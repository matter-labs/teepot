// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification, both continuous and one-shot

mod args;
mod client;
mod proof;
mod verification;

use crate::verification::{
    log_quote_verification_summary, verify_attestation_quote, verify_batch_proof,
};
use anyhow::Result;
use args::{Arguments, AttestationPolicyArgs};
use clap::Parser;
use client::MainNodeClient;
use proof::get_proofs;
use reqwest::Client;
use teepot::log::setup_logging;
use tokio::{signal, sync::watch};
use tracing::{debug, error, info, trace, warn};
use url::Url;
use zksync_basic_types::L1BatchNumber;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    setup_logging(&args.log_level)?;
    validate_arguments(&args)?;
    let (stop_sender, stop_receiver) = watch::channel(false);
    let mut process_handle = tokio::spawn(verify_batches_proofs(stop_receiver, args));
    tokio::select! {
        ret = &mut process_handle => { return ret?; },
        _ = signal::ctrl_c() => {
            tracing::info!("Stop signal received, shutting down");
            stop_sender.send(true).ok();
            // Wait for process_batches to complete gracefully
            process_handle.await??;
        }
    }

    Ok(())
}

fn validate_arguments(args: &Arguments) -> Result<()> {
    if args.attestation_policy.sgx_mrsigners.is_none()
        && args.attestation_policy.sgx_mrenclaves.is_none()
    {
        error!("Neither `--sgx-mrenclaves` nor `--sgx-mrsigners` specified. Any code could have produced the proof.");
    }

    Ok(())
}

/// Verify all TEE proofs for all batches starting from the given batch number up to the specified
/// batch number, if a range is provided. Otherwise, continue verifying batches until the stop
/// signal is received.
async fn verify_batches_proofs(
    mut stop_receiver: watch::Receiver<bool>,
    args: Arguments,
) -> Result<()> {
    let node_client = MainNodeClient::new(args.rpc_url.clone(), args.chain_id)?;
    let http_client = Client::new();
    let first_batch_number = match args.batch_range {
        Some((first_batch_number, _)) => first_batch_number,
        None => args
            .continuous
            .expect("clap::ArgGroup should guarantee batch range or continuous option is set"),
    };
    let end_batch_number = args
        .batch_range
        .map_or(u32::MAX, |(_, end_batch_number)| end_batch_number.0);
    let mut unverified_batches_count: u32 = 0;
    let mut last_processed_batch_number = first_batch_number.0;

    for current_batch_number in first_batch_number.0..=end_batch_number {
        if *stop_receiver.borrow() {
            tracing::warn!("Stop signal received, shutting down");
            break;
        }

        trace!("Verifying TEE proofs for batch #{}", current_batch_number);

        let all_verified = verify_batch_proofs(
            &mut stop_receiver,
            current_batch_number.into(),
            &args.rpc_url,
            &http_client,
            &node_client,
            &args.attestation_policy,
        )
        .await?;

        if !all_verified {
            unverified_batches_count += 1;
        }

        if current_batch_number < end_batch_number {
            tokio::time::timeout(args.rate_limit, stop_receiver.changed())
                .await
                .ok();
        }

        last_processed_batch_number = current_batch_number;
    }

    let verified_batches_count =
        last_processed_batch_number + 1 - first_batch_number.0 - unverified_batches_count;

    if unverified_batches_count > 0 {
        if verified_batches_count == 0 {
            error!(
                "All {} batches failed verification!",
                unverified_batches_count
            );
        } else {
            error!(
                "Some batches failed verification! Unverified batches: {}. Verified batches: {}.",
                unverified_batches_count, verified_batches_count
            );
        }
    } else {
        info!(
            "All {} batches verified successfully!",
            verified_batches_count
        );
    }

    Ok(())
}

/// Verify all TEE proofs for the given batch number. Note that each batch number can potentially
/// have multiple proofs of the same TEE type.
async fn verify_batch_proofs(
    stop_receiver: &mut watch::Receiver<bool>,
    batch_number: L1BatchNumber,
    rpc_url: &Url,
    http_client: &Client,
    node_client: &MainNodeClient,
    attestation_policy: &AttestationPolicyArgs,
) -> Result<bool> {
    let proofs = get_proofs(stop_receiver, batch_number, http_client, rpc_url).await?;
    let batch_no = batch_number.0;
    let mut total_proofs_count: u32 = 0;
    let mut unverified_proofs_count: u32 = 0;

    for proof in proofs
        .into_iter()
        // only support SGX proofs for now
        .filter(|proof| proof.tee_type.eq_ignore_ascii_case("sgx"))
    {
        let batch_no = proof.l1_batch_number;

        total_proofs_count += 1;
        let tee_type = proof.tee_type.to_uppercase();

        if proof
            .status
            .map_or(false, |s| s.eq_ignore_ascii_case("permanently_ignored"))
        {
            trace!(
                batch_no,
                tee_type,
                "Proof is marked as permanently ignored. Skipping."
            );
            continue;
        }
        trace!(batch_no, tee_type, proof.proved_at, "Verifying proof.");

        let attestation = proof.attestation.unwrap_or_default();
        debug!(batch_no, "Verifying quote ({} bytes)...", attestation.len());
        let quote_verification_result = verify_attestation_quote(&attestation)?;
        let verified_successfully = verify_batch_proof(
            &quote_verification_result,
            attestation_policy,
            node_client,
            &proof.signature.unwrap_or_default(),
            L1BatchNumber(proof.l1_batch_number),
        )
        .await?;

        log_quote_verification_summary(&quote_verification_result);

        if verified_successfully {
            info!(
                batch_no,
                proof.proved_at, tee_type, "Verification succeeded.",
            );
        } else {
            unverified_proofs_count += 1;
            warn!(batch_no, proof.proved_at, tee_type, "Verification failed!",);
        }
    }

    let verified_proofs_count = total_proofs_count - unverified_proofs_count;
    if unverified_proofs_count > 0 {
        if verified_proofs_count == 0 {
            error!(
                batch_no,
                "All {} proofs failed verification!", unverified_proofs_count
            );
        } else {
            warn!(
                batch_no,
                "Some proofs failed verification. Unverified proofs: {}. Verified proofs: {}.",
                unverified_proofs_count,
                verified_proofs_count
            );
        }
    }

    // if at least one proof is verified, consider the batch verified
    let is_batch_verified = verified_proofs_count > 0;

    Ok(is_batch_verified)
}

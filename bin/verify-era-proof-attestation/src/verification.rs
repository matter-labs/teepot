// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use crate::{args::AttestationPolicyArgs, client::JsonRpcClient};
use anyhow::{Context, Result};
use hex::encode;
use secp256k1::{constants::PUBLIC_KEY_SIZE, ecdsa::Signature, Message, PublicKey};
use teepot::{
    client::TcbLevel,
    ethereum::recover_signer,
    quote::{
        error::QuoteContext, tee_qv_get_collateral, verify_quote_with_collateral, Quote,
        QuoteVerificationResult, Report,
    },
};
use tracing::{debug, info, warn};
use zksync_basic_types::{L1BatchNumber, H256};

fn verify_batch_proof_new_format(quote: &Quote, root_hash: H256, signature: &[u8]) -> Result<bool> {
    let ethereum_address_from_quote = &quote.get_report_data()[..20];
    let signature_bytes: &[u8; 65] = signature.try_into()?;
    let root_hash_bytes = root_hash.as_bytes();
    let root_hash_msg = Message::from_digest_slice(root_hash_bytes)?;
    let ethereum_address_from_signature = recover_signer(signature_bytes, &root_hash_msg)?;
    debug!(
        "Root hash: {}. Ethereum address from the attestation quote: {}. Ethereum address from the signature: {}.",
        root_hash,
        encode(ethereum_address_from_quote),
        encode(ethereum_address_from_signature),
    );
    Ok(ethereum_address_from_signature == ethereum_address_from_quote)
}

fn verify_batch_proof_old_format(quote: &Quote, root_hash: H256, signature: &[u8]) -> Result<bool> {
    let public_key = PublicKey::from_slice(&quote.get_report_data()[..PUBLIC_KEY_SIZE])?;
    let signature = Signature::from_compact(signature)?;
    let root_hash_msg = Message::from_digest_slice(&root_hash.0)?;
    Ok(signature.verify(&root_hash_msg, &public_key).is_ok())
}

pub async fn verify_batch_proof(
    quote_verification_result: &QuoteVerificationResult,
    attestation_policy: &AttestationPolicyArgs,
    node_client: &impl JsonRpcClient,
    signature: &[u8],
    batch_number: L1BatchNumber,
) -> Result<bool> {
    if !is_quote_matching_policy(attestation_policy, quote_verification_result) {
        return Ok(false);
    }

    let root_hash = node_client.get_root_hash(batch_number).await?;
    let quote = &quote_verification_result.quote;
    let verification_successful = verify_batch_proof_old_format(&quote, root_hash, signature)?
        || verify_batch_proof_new_format(&quote, root_hash, signature)?;

    Ok(verification_successful)
}

pub fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    let collateral = QuoteContext::context(
        tee_qv_get_collateral(attestation_quote_bytes),
        "Failed to get collateral!",
    )?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(attestation_quote_bytes, Some(&collateral), unix_time)
        .context("Failed to verify quote with collateral!")
}

pub fn log_quote_verification_summary(quote_verification_result: &QuoteVerificationResult) {
    let QuoteVerificationResult {
        collateral_expired,
        result,
        quote,
        advisories,
        ..
    } = quote_verification_result;
    if *collateral_expired {
        warn!("Freshly fetched collateral expired!");
    }
    let tcblevel = TcbLevel::from(*result);
    let advisories = if advisories.is_empty() {
        "None".to_string()
    } else {
        advisories
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    info!(
        "Quote verification result: {tcblevel}. {report}. Advisory IDs: {advisories}.",
        report = &quote.report
    );
}

fn is_quote_matching_policy(
    attestation_policy: &AttestationPolicyArgs,
    quote_verification_result: &QuoteVerificationResult,
) -> bool {
    let quote = &quote_verification_result.quote;
    let tcblevel = TcbLevel::from(quote_verification_result.result);

    if !attestation_policy.sgx_allowed_tcb_levels.contains(tcblevel) {
        warn!(
            "Quote verification failed: TCB level mismatch (expected one of: {:?}, actual: {})",
            attestation_policy.sgx_allowed_tcb_levels, tcblevel
        );
        return false;
    }
    match &quote.report {
        Report::SgxEnclave(report_body) => {
            check_policy(
                attestation_policy.sgx_mrsigners.as_deref(),
                &report_body.mr_signer,
                "mrsigner",
            ) && check_policy(
                attestation_policy.sgx_mrenclaves.as_deref(),
                &report_body.mr_enclave,
                "mrenclave",
            )
        }
        _ => false,
    }
}

fn check_policy(policy: Option<&str>, actual_value: &[u8], field_name: &str) -> bool {
    if let Some(valid_values) = policy {
        let valid_values: Vec<&str> = valid_values.split(',').collect();
        let actual_value = hex::encode(actual_value);
        if !valid_values.contains(&actual_value.as_str()) {
            warn!(
                "Quote verification failed: {} mismatch (expected one of: {:?}, actual: {})",
                field_name, valid_values, actual_value
            );
            return false;
        }
        debug!(field_name, actual_value, "Attestation policy check passed");
    }
    true
}

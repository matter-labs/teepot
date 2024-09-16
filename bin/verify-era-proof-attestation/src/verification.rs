// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use anyhow::{Context, Result};
use hex::encode;
use secp256k1::{constants::PUBLIC_KEY_SIZE, ecdsa::Signature, Message, PublicKey};
use teepot::{
    client::TcbLevel,
    sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
};
use tracing::{debug, info, warn};
use zksync_basic_types::{L1BatchNumber, H256};

use crate::args::AttestationPolicyArgs;
use crate::client::JsonRpcClient;

pub async fn verify_batch_proof(
    quote_verification_result: &QuoteVerificationResult<'_>,
    attestation_policy: &AttestationPolicyArgs,
    node_client: &impl JsonRpcClient,
    signature: &[u8],
    batch_number: L1BatchNumber,
) -> Result<bool> {
    if !is_quote_matching_policy(attestation_policy, quote_verification_result) {
        return Ok(false);
    }

    let batch_no = batch_number.0;

    let public_key = PublicKey::from_slice(
        &quote_verification_result.quote.report_body.reportdata[..PUBLIC_KEY_SIZE],
    )?;
    debug!(batch_no, "public key: {}", public_key);

    let root_hash = node_client.get_root_hash(batch_number).await?;
    debug!(batch_no, "root hash: {}", root_hash);

    let is_verified = verify_signature(signature, public_key, root_hash)?;
    if is_verified {
        info!(batch_no, signature = %encode(signature), "Signature verified successfully.");
    } else {
        warn!(batch_no, signature = %encode(signature), "Failed to verify signature!");
    }
    Ok(is_verified)
}

pub fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    let collateral =
        tee_qv_get_collateral(attestation_quote_bytes).context("Failed to get collateral!")?;
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
    info!(
        "Quote verification result: {}. mrsigner: {}, mrenclave: {}, reportdata: {}. Advisory IDs: {}.",
        tcblevel,
        hex::encode(quote.report_body.mrsigner),
        hex::encode(quote.report_body.mrenclave),
        hex::encode(quote.report_body.reportdata),
        if advisories.is_empty() {
            "None".to_string()
        } else {
            advisories.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        }
    );
}

fn verify_signature(signature: &[u8], public_key: PublicKey, root_hash: H256) -> Result<bool> {
    let signature = Signature::from_compact(signature)?;
    let root_hash_msg = Message::from_digest_slice(&root_hash.0)?;
    Ok(signature.verify(&root_hash_msg, &public_key).is_ok())
}

fn is_quote_matching_policy(
    attestation_policy: &AttestationPolicyArgs,
    quote_verification_result: &QuoteVerificationResult<'_>,
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

    check_policy(
        attestation_policy.sgx_mrsigners.as_deref(),
        &quote.report_body.mrsigner,
        "mrsigner",
    ) && check_policy(
        attestation_policy.sgx_mrenclaves.as_deref(),
        &quote.report_body.mrenclave,
        "mrenclave",
    )
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

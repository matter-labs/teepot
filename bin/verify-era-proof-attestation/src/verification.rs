// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use crate::{args::AttestationPolicyArgs, client::JsonRpcClient};
use anyhow::{anyhow, Context, Result};
use hex::encode;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, SECP256K1,
};
use teepot::{
    client::TcbLevel,
    ethereum::{public_key_to_ethereum_address, recover_signer},
    prover::reportdata::ReportData,
    quote::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult, Report},
};
use tracing::{debug, info, trace, warn};
use zksync_basic_types::{L1BatchNumber, H256};

struct TeeProof {
    report: ReportData,
    root_hash: H256,
    signature: Vec<u8>,
}

impl TeeProof {
    pub fn new(report: ReportData, root_hash: H256, signature: Vec<u8>) -> Self {
        Self {
            report,
            root_hash,
            signature,
        }
    }

    pub fn verify(&self) -> Result<bool> {
        match &self.report {
            ReportData::V0(report) => {
                debug!("ReportData::V0");
                let signature = Signature::from_compact(&self.signature)?;
                let root_hash_msg = Message::from_digest_slice(&self.root_hash.0)?;
                Ok(signature.verify(&root_hash_msg, &report.pubkey).is_ok())
            }
            ReportData::V1(report) => {
                debug!("ReportData::V1");
                let ethereum_address_from_report = report.ethereum_address;
                let root_hash_msg = Message::from_digest_slice(self.root_hash.as_bytes())?;

                trace!("sig len = {}", self.signature.len());

                let sig_vec = self.signature.clone();

                if self.signature.len() == 64 {
                    info!("Signature is missing RecoveryId!");
                    // Fallback for missing RecoveryId
                    for rec_id in [
                        RecoveryId::Zero,
                        RecoveryId::One,
                        RecoveryId::Two,
                        RecoveryId::Three,
                    ] {
                        let Ok(sig) = RecoverableSignature::from_compact(&sig_vec, rec_id) else {
                            continue;
                        };
                        let Ok(public) = SECP256K1.recover_ecdsa(&root_hash_msg, &sig) else {
                            continue;
                        };
                        let ethereum_address_from_signature =
                            public_key_to_ethereum_address(&public);

                        debug!(
                            "Root hash: {}. Ethereum address from the attestation quote: {}. Ethereum address from the signature: {}.",
                            self.root_hash,
                            encode(ethereum_address_from_report),
                            encode(ethereum_address_from_signature),
                        );
                        if ethereum_address_from_signature == ethereum_address_from_report {
                            info!("Had to use RecoveryId::{rec_id:?}");
                            return Ok(true);
                        }
                    }
                    return Ok(false);
                }

                let signature_bytes: [u8; 65] = sig_vec
                    .try_into()
                    .map_err(|e| anyhow!("{:?}", e))
                    .context("invalid length of signature bytes")?;
                let ethereum_address_from_signature =
                    recover_signer(&signature_bytes, &root_hash_msg)?;
                debug!(
                    "Root hash: {}. Ethereum address from the attestation quote: {}. Ethereum address from the signature: {}.",
                    self.root_hash,
                    encode(ethereum_address_from_report),
                    encode(ethereum_address_from_signature),
                );
                Ok(ethereum_address_from_signature == ethereum_address_from_report)
            }
            ReportData::Unknown(_) => Ok(false),
        }
    }
}

pub async fn verify_batch_proof(
    attestation_quote_bytes: &[u8],
    attestation_policy: &AttestationPolicyArgs,
    node_client: &impl JsonRpcClient,
    signature: &[u8],
    batch_number: L1BatchNumber,
) -> Result<bool> {
    use std::fs;

    let quote_verification_result = verify_attestation_quote(attestation_quote_bytes)?;

    log_quote_verification_summary(&quote_verification_result);

    if !is_quote_matching_policy(attestation_policy, &quote_verification_result) {
        return Ok(false);
    }

    let root_hash = node_client.get_root_hash(batch_number).await?;
    let report_data_bytes = quote_verification_result.quote.get_report_data();
    let report_data = ReportData::try_from(report_data_bytes)?;
    let tee_proof = TeeProof::new(report_data, root_hash, signature.to_vec());
    tee_proof.verify()
}

pub fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    let collateral = teepot::quote::error::QuoteContext::context(
        tee_qv_get_collateral(attestation_quote_bytes),
        "Failed to get collateral!",
    )?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(attestation_quote_bytes, Some(collateral), unix_time)
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

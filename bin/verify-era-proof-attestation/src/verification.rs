// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use crate::{args::AttestationPolicyArgs, client::JsonRpcClient};
use anyhow::{anyhow, Context, Result};
use hex::encode;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, SECP256K1,
};
use std::fs;
use teepot::{
    client::TcbLevel,
    ethereum::{public_key_to_ethereum_address, recover_signer},
    prover::reportdata::ReportData,
    quote::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult, Report},
    sgx::Collateral,
};
use tracing::{debug, info, trace, warn};
use x509_cert::der::Encode;
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

    pub fn verify(&mut self) -> Result<bool> {
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
                            self.signature.push(
                                u8::try_from(i32::from(rec_id)).context("recovery id to u8")? + 27,
                            );
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

fn save_verification_artifacts(
    batch_number: L1BatchNumber,
    signature: &[u8],
    root_hash: &H256,
    attestation_quote_bytes: &[u8],
    collateral: &Collateral,
) -> Result<()> {
    fs::write(
        format!("{}_signature.hex", batch_number),
        hex::encode(signature),
    )?;
    fs::write(
        format!("{}_root_hash.hex", batch_number),
        format!("{:x}", root_hash),
    )?;
    fs::write(
        format!("{}_quote.bin", batch_number),
        attestation_quote_bytes,
    )?;
    fs::write(
        format!("{}_quote.bin.hex", batch_number),
        hex::encode(attestation_quote_bytes),
    )?;

    let certs = x509_cert::certificate::CertificateInner::<
        x509_cert::certificate::Rfc5280
    >::load_pem_chain(collateral.pck_crl_issuer_chain.split_last().unwrap().1)?;

    let cert = certs
        .into_iter()
        .find(|cert| {
            cert.tbs_certificate
                .subject
                .to_string()
                .contains("PCK Platform CA")
        })
        .ok_or(anyhow!("PCK Platform CA cert not found"))?;

    fs::write(
        format!("{}_platformDer.hex", batch_number),
        hex::encode(&cert.to_der()?),
    )
    .context("Failed to write PCK Platform CA to platformDer.hex")?;

    debug!(
        "Platform CA serial {}",
        cert.tbs_certificate.serial_number.to_string()
    );

    fs::write(
        format!("{}_rootCrlDer.hex", batch_number),
        collateral.root_ca_crl.split_last().unwrap().1,
    )
    .context("Failed to write root_ca_crl to rootCrlDer.hex")?;

    fs::write(
        format!("{}_platformCrlDer.hex", batch_number),
        hex::encode(collateral.pck_crl.split_last().unwrap().1),
    )
    .context("Failed to write pck_crl to platformCrlDer.hex")?;

    let certs = x509_cert::certificate::CertificateInner::<
        x509_cert::certificate::Rfc5280
    >::load_pem_chain(collateral.tcb_info_issuer_chain.split_last().unwrap().1)?;

    let cert = certs
        .into_iter()
        .find(|cert| {
            cert.tbs_certificate
                .subject
                .to_string()
                .contains("TCB Signing")
        })
        .ok_or(anyhow!("TCB Signing cert not found"))?;

    debug!("TCB cert {}", cert.tbs_certificate.subject.to_string());
    debug!(
        "TCB serial {}",
        cert.tbs_certificate.serial_number.to_string()
    );

    fs::write(
        format!("{}_tcbDer.hex", batch_number),
        hex::encode(&cert.to_der()?),
    )
    .context("Failed to write TCB Signing CA to tcbDer.hex")?;

    fs::write(
        format!("{}_tcb_info.json", batch_number),
        collateral.tcb_info.split_last().unwrap().1,
    )
    .context("Failed to write tcb_info to tcb_info.json")?;

    let certs = x509_cert::certificate::CertificateInner::<
        x509_cert::certificate::Rfc5280
    >::load_pem_chain(collateral.qe_identity_issuer_chain.split_last().unwrap().1)?;

    let _ = certs
        .into_iter()
        .find(|qe_cert| {
            qe_cert
                .tbs_certificate
                .serial_number
                .eq(&cert.tbs_certificate.serial_number)
        })
        .ok_or(anyhow!("QE identity cert != TCB cert"))?;

    fs::write(
        format!("{}_qe_identity.json", batch_number),
        collateral.qe_identity.split_last().unwrap().1,
    )
    .context("Failed to write qe_identity to qe_identity.json")?;

    Ok(())
}

pub async fn verify_batch_proof(
    attestation_quote_bytes: &[u8],
    attestation_policy: &AttestationPolicyArgs,
    node_client: &impl JsonRpcClient,
    signature: &[u8],
    batch_number: L1BatchNumber,
    save: bool,
) -> Result<bool> {
    let quote_verification_result = verify_attestation_quote(attestation_quote_bytes)?;

    log_quote_verification_summary(&quote_verification_result);

    if !is_quote_matching_policy(attestation_policy, &quote_verification_result) {
        return Ok(false);
    }
    let QuoteVerificationResult {
        quote, collateral, ..
    } = quote_verification_result;
    let root_hash = node_client.get_root_hash(batch_number).await?;
    let report_data_bytes = quote.get_report_data();

    let report_data = ReportData::try_from(report_data_bytes)?;

    let mut tee_proof = TeeProof::new(report_data, root_hash, signature.to_vec());

    let res = tee_proof.verify();

    if save {
        save_verification_artifacts(
            batch_number,
            tee_proof.signature.as_slice(),
            &root_hash,
            attestation_quote_bytes,
            &collateral,
        )?;
    }

    res
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

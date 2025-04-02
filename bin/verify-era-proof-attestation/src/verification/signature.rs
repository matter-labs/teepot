// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, SECP256K1,
};
use teepot::{
    ethereum::{public_key_to_ethereum_address, recover_signer},
    prover::reportdata::ReportData,
    quote::QuoteVerificationResult,
};
use zksync_basic_types::H256;

use crate::error;

const SIGNATURE_LENGTH_WITH_RECOVERY_ID: usize = 65;
const SIGNATURE_LENGTH_WITHOUT_RECOVERY_ID: usize = 64;

/// Handles verification of signatures in proofs
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verify a batch proof signature
    pub fn verify_batch_proof(
        quote_verification_result: &QuoteVerificationResult,
        root_hash: H256,
        signature: &[u8],
    ) -> error::Result<bool> {
        let report_data_bytes = quote_verification_result.quote.get_report_data();
        tracing::trace!(?report_data_bytes);

        let report_data = ReportData::try_from(report_data_bytes).map_err(|e| {
            error::Error::internal(format!("Could not convert to ReportData: {}", e))
        })?;

        Self::verify(&report_data, &root_hash, signature)
    }

    /// Verify signature against report data and root hash
    pub fn verify(
        report_data: &ReportData,
        root_hash: &H256,
        signature: &[u8],
    ) -> error::Result<bool> {
        match report_data {
            ReportData::V0(report) => Self::verify_v0(report, root_hash, signature),
            ReportData::V1(report) => Self::verify_v1(report, root_hash, signature),
            ReportData::Unknown(_) => Ok(false),
        }
    }

    /// Verify a V0 report
    fn verify_v0(
        report: &teepot::prover::reportdata::ReportDataV0,
        root_hash: &H256,
        signature: &[u8],
    ) -> error::Result<bool> {
        tracing::debug!("ReportData::V0");
        let signature = Signature::from_compact(signature)
            .map_err(|e| error::Error::signature_verification(e.to_string()))?;
        let root_hash_msg = Message::from_digest(root_hash.0);
        Ok(signature.verify(&root_hash_msg, &report.pubkey).is_ok())
    }

    /// Verify a V1 report
    fn verify_v1(
        report: &teepot::prover::reportdata::ReportDataV1,
        root_hash: &H256,
        signature: &[u8],
    ) -> error::Result<bool> {
        tracing::debug!("ReportData::V1");
        let ethereum_address_from_report = report.ethereum_address;

        let root_hash_msg = Message::from_digest(
            root_hash
                .as_bytes()
                .try_into()
                .map_err(|_| error::Error::signature_verification("root hash not 32 bytes"))?,
        );

        tracing::trace!("sig len = {}", signature.len());

        // Try to recover Ethereum address from signature
        let ethereum_address_from_signature = match signature.len() {
            // Handle 64-byte signature case (missing recovery ID)
            SIGNATURE_LENGTH_WITHOUT_RECOVERY_ID => {
                SignatureVerifier::recover_address_with_missing_recovery_id(
                    signature,
                    &root_hash_msg,
                )?
            }
            // Standard 65-byte signature case
            SIGNATURE_LENGTH_WITH_RECOVERY_ID => {
                let signature_bytes: [u8; SIGNATURE_LENGTH_WITH_RECOVERY_ID] =
                    signature.try_into().map_err(|_| {
                        error::Error::signature_verification(
                            "Expected 65-byte signature but got a different length",
                        )
                    })?;

                recover_signer(&signature_bytes, &root_hash_msg).map_err(|e| {
                    error::Error::signature_verification(format!("Failed to recover signer: {}", e))
                })?
            }
            // Any other length is invalid
            len => {
                return Err(error::Error::signature_verification(format!(
                    "Invalid signature length: {len} bytes"
                )))
            }
        };

        // Log verification details
        tracing::debug!(
            "Root hash: {}. Ethereum address from the attestation quote: {}. Ethereum address from the signature: {}.",
            root_hash,
            hex::encode(ethereum_address_from_report),
            hex::encode(ethereum_address_from_signature),
        );

        Ok(ethereum_address_from_signature == ethereum_address_from_report)
    }

    /// Helper function to recover Ethereum address when recovery ID is missing
    fn recover_address_with_missing_recovery_id(
        signature: &[u8],
        message: &Message,
    ) -> error::Result<[u8; 20]> {
        tracing::info!("Signature is missing RecoveryId!");

        // Try all possible recovery IDs
        for rec_id in [
            RecoveryId::Zero,
            RecoveryId::One,
            RecoveryId::Two,
            RecoveryId::Three,
        ] {
            let Ok(rec_sig) = RecoverableSignature::from_compact(signature, rec_id) else {
                continue;
            };

            let Ok(public) = SECP256K1.recover_ecdsa(message, &rec_sig) else {
                continue;
            };

            let ethereum_address = public_key_to_ethereum_address(&public);
            tracing::info!("Had to use RecoveryId::{rec_id:?}");
            return Ok(ethereum_address);
        }

        // No valid recovery ID found
        Err(error::Error::signature_verification(
            "Could not find valid recovery ID",
        ))
    }
}

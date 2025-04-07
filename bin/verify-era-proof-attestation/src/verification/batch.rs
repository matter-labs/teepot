// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use crate::{
    client::JsonRpcClient,
    core::AttestationPolicy,
    error,
    proof::Proof,
    verification::{AttestationVerifier, PolicyEnforcer, SignatureVerifier, VerificationReporter},
};
use tokio_util::sync::CancellationToken;
use zksync_basic_types::L1BatchNumber;

/// Result of a batch verification
#[derive(Debug, Clone, Copy)]
pub struct BatchVerificationResult {
    /// Total number of proofs processed
    pub total_count: u32,
    /// Number of proofs that were verified successfully
    pub verified_count: u32,
    /// Number of proofs that failed verification
    pub unverified_count: u32,
}

/// Handles the batch verification process
pub struct BatchVerifier<C: JsonRpcClient> {
    node_client: C,
    attestation_policy: AttestationPolicy,
}

impl<C: JsonRpcClient> BatchVerifier<C> {
    /// Create a new batch verifier
    pub fn new(node_client: C, attestation_policy: AttestationPolicy) -> Self {
        Self {
            node_client,
            attestation_policy,
        }
    }

    /// Verify proofs for a batch
    pub async fn verify_batch_proofs(
        &self,
        token: &CancellationToken,
        batch_number: L1BatchNumber,
        proofs: Vec<Proof>,
    ) -> error::Result<BatchVerificationResult> {
        let batch_no = batch_number.0;
        let mut total_proofs_count: u32 = 0;
        let mut verified_proofs_count: u32 = 0;

        for proof in proofs.into_iter() {
            if token.is_cancelled() {
                tracing::warn!("Stop signal received during batch verification");
                return Ok(BatchVerificationResult {
                    total_count: total_proofs_count,
                    verified_count: verified_proofs_count,
                    unverified_count: total_proofs_count - verified_proofs_count,
                });
            }

            total_proofs_count += 1;
            let tee_type = proof.tee_type.to_uppercase();

            if proof.is_permanently_ignored() {
                tracing::debug!(
                    batch_no,
                    tee_type,
                    "Proof is marked as permanently ignored. Skipping."
                );
                continue;
            }

            tracing::debug!(batch_no, tee_type, proof.proved_at, "Verifying proof.");

            let attestation_bytes = proof.attestation_bytes();
            let signature_bytes = proof.signature_bytes();

            tracing::debug!(
                batch_no,
                "Verifying quote ({} bytes)...",
                attestation_bytes.len()
            );

            // Verify attestation
            let quote_verification_result = AttestationVerifier::verify_quote(&attestation_bytes)?;

            // Log verification results
            VerificationReporter::log_quote_verification_summary(&quote_verification_result);

            // Check if attestation matches policy
            let policy_matches = PolicyEnforcer::validate_policy(
                &self.attestation_policy,
                &quote_verification_result,
            );

            if let Err(e) = policy_matches {
                tracing::error!(batch_no, tee_type, "Attestation policy check failed: {e}");
                continue;
            }

            // Verify signature
            let root_hash = self
                .node_client
                .get_root_hash(L1BatchNumber(proof.l1_batch_number))
                .await?;

            let signature_verified = SignatureVerifier::verify_batch_proof(
                &quote_verification_result,
                root_hash,
                &signature_bytes,
            )?;

            if signature_verified {
                tracing::info!(
                    batch_no,
                    proof.proved_at,
                    tee_type,
                    "Verification succeeded.",
                );
                verified_proofs_count += 1;
            } else {
                tracing::warn!(batch_no, proof.proved_at, tee_type, "Verification failed!",);
            }
        }

        let unverified_proofs_count = total_proofs_count.saturating_sub(verified_proofs_count);

        // Log batch verification results
        VerificationReporter::log_batch_verification_results(
            batch_no,
            verified_proofs_count,
            unverified_proofs_count,
        );

        Ok(BatchVerificationResult {
            total_count: total_proofs_count,
            verified_count: verified_proofs_count,
            unverified_count: unverified_proofs_count,
        })
    }
}

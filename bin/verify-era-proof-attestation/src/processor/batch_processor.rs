// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Core functionality for processing individual batches

use crate::error;
use tokio_util::sync::CancellationToken;
use zksync_basic_types::L1BatchNumber;

use crate::{
    client::{HttpClient, MainNodeClient, RetryConfig},
    core::{VerificationResult, VerifierConfig},
    proof::ProofFetcher,
    verification::{BatchVerifier, VerificationReporter},
};

/// Responsible for processing individual batches
pub struct BatchProcessor {
    config: VerifierConfig,
    proof_fetcher: ProofFetcher,
    batch_verifier: BatchVerifier<MainNodeClient>,
}

impl BatchProcessor {
    /// Create a new batch processor with the given configuration
    pub fn new(config: VerifierConfig) -> error::Result<Self> {
        // Initialize clients and fetchers
        let node_client = MainNodeClient::new(config.args.rpc_url.clone(), config.args.chain_id)?;
        let http_client = HttpClient::new();
        let retry_config = RetryConfig::default();
        let proof_fetcher =
            ProofFetcher::new(http_client, config.args.rpc_url.clone(), retry_config);
        let batch_verifier = BatchVerifier::new(node_client, config.policy.clone());
        Ok(Self {
            config,
            proof_fetcher,
            batch_verifier,
        })
    }

    /// Process a single batch and return the verification result
    pub async fn process_batch(
        &self,
        token: &CancellationToken,
        batch_number: L1BatchNumber,
    ) -> error::Result<VerificationResult> {
        if token.is_cancelled() {
            tracing::info!("Stop signal received, shutting down");
            return Ok(VerificationResult::Interrupted);
        }

        tracing::trace!("Verifying TEE proofs for batch #{}", batch_number.0);

        // Fetch proofs for the current batch across different TEE types
        let mut proofs = Vec::new();
        for tee_type in self.config.args.tee_types.iter().copied() {
            match self
                .proof_fetcher
                .get_proofs(token, batch_number, tee_type)
                .await
            {
                Ok(batch_proofs) => proofs.extend(batch_proofs),
                Err(error::Error::Interrupted) => return Err(error::Error::Interrupted),
                Err(e) => {
                    tracing::error!(
                        "Failed to fetch proofs for TEE type {:?} at batch {}: {:#}",
                        tee_type,
                        batch_number.0,
                        e
                    );
                    continue;
                }
            }
        }

        if proofs.is_empty() {
            tracing::warn!("No proofs found for batch #{}", batch_number.0);
            return Ok(VerificationResult::NoProofsFound);
        }

        // Verify proofs for the current batch
        let verification_result = self
            .batch_verifier
            .verify_batch_proofs(token, batch_number, proofs)
            .await?;

        let result = if verification_result.total_count == 0 {
            VerificationResult::NoProofsFound
        } else if verification_result.verified_count == verification_result.total_count {
            VerificationResult::Success
        } else if verification_result.verified_count > 0 {
            VerificationResult::PartialSuccess {
                verified_count: verification_result.verified_count,
                unverified_count: verification_result.unverified_count,
            }
        } else {
            VerificationResult::Failure
        };

        tracing::debug!("Batch #{} verification result: {}", batch_number.0, result);

        // Apply rate limiting between batches if needed
        if !matches!(result, VerificationResult::Interrupted)
            && self.config.args.rate_limit.as_millis() > 0
        {
            tokio::time::timeout(self.config.args.rate_limit, token.cancelled())
                .await
                .ok();
        }

        Ok(result)
    }

    /// Log the overall verification results
    pub fn log_overall_results(success_count: u32, failure_count: u32) {
        VerificationReporter::log_overall_verification_results(success_count, failure_count);
    }
}

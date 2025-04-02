// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Continuous batch processor for ongoing verification of new batches

use tokio::sync::watch;
use zksync_basic_types::L1BatchNumber;

use crate::{
    core::{VerificationResult, VerifierConfig},
    error,
    processor::BatchProcessor,
};

/// Processes batches continuously until stopped
pub struct ContinuousProcessor {
    batch_processor: BatchProcessor,
    start_batch: L1BatchNumber,
}

impl ContinuousProcessor {
    /// Create a new continuous processor that starts from the given batch
    pub fn new(config: VerifierConfig, start_batch: L1BatchNumber) -> error::Result<Self> {
        let batch_processor = BatchProcessor::new(config)?;

        Ok(Self {
            batch_processor,
            start_batch,
        })
    }

    /// Run the processor until stopped
    pub async fn run(
        &self,
        mut stop_receiver: watch::Receiver<bool>,
    ) -> error::Result<Vec<(u32, VerificationResult)>> {
        tracing::info!(
            "Starting continuous verification from batch {}",
            self.start_batch.0
        );

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut current_batch = self.start_batch.0;

        // Continue processing batches until stopped or reaching maximum batch number
        while !*stop_receiver.borrow() {
            let batch = L1BatchNumber(current_batch);
            match self
                .batch_processor
                .process_batch(&mut stop_receiver, batch)
                .await
            {
                Ok(result) => {
                    match result {
                        VerificationResult::Success => success_count += 1,
                        VerificationResult::PartialSuccess { .. } => success_count += 1,
                        VerificationResult::Failure => failure_count += 1,
                        VerificationResult::Interrupted => {
                            results.push((current_batch, result));
                            break;
                        }
                        VerificationResult::NoProofsFound => {
                            // In continuous mode, we might hit batches that don't have proofs yet
                            // Wait a bit longer before retrying
                            if !*stop_receiver.borrow() {
                                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                                // Don't increment batch number, try again
                                continue;
                            }
                        }
                    }

                    results.push((current_batch, result));
                }
                Err(e) => {
                    tracing::error!("Error processing batch {}: {}", current_batch, e);
                    results.push((current_batch, VerificationResult::Failure));
                    failure_count += 1;
                }
            }

            // Move to the next batch
            current_batch = current_batch
                .checked_add(1)
                .ok_or(error::Error::internal("Maximum batch number reached"))?;
        }

        // Log overall results
        BatchProcessor::log_overall_results(success_count, failure_count);

        Ok(results)
    }
}

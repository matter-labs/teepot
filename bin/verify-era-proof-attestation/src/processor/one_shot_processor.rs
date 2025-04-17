// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! One-shot batch processor for verifying a single batch or a range of batches

use crate::error;
use tokio_util::sync::CancellationToken;
use zksync_basic_types::L1BatchNumber;

use crate::{
    core::{VerificationResult, VerifierConfig},
    processor::BatchProcessor,
};

/// Processes a specific range of batches and then exits
pub struct OneShotProcessor {
    batch_processor: BatchProcessor,
    start_batch: L1BatchNumber,
    end_batch: L1BatchNumber,
}

impl OneShotProcessor {
    /// Create a new one-shot processor for the given batch range
    pub fn new(
        config: VerifierConfig,
        start_batch: L1BatchNumber,
        end_batch: L1BatchNumber,
    ) -> error::Result<Self> {
        let batch_processor = BatchProcessor::new(config)?;

        Ok(Self {
            batch_processor,
            start_batch,
            end_batch,
        })
    }

    /// Run the processor until completion or interruption
    pub async fn run(
        &self,
        token: &CancellationToken,
    ) -> error::Result<Vec<(u32, VerificationResult)>> {
        tracing::info!(
            "Starting one-shot verification of batches {} to {}",
            self.start_batch.0,
            self.end_batch.0
        );

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;

        for batch_number in self.start_batch.0..=self.end_batch.0 {
            let batch = L1BatchNumber(batch_number);
            let result = self.batch_processor.process_batch(token, batch).await?;

            match result {
                VerificationResult::Success | VerificationResult::PartialSuccess { .. } => {
                    success_count += 1;
                }
                VerificationResult::Failure => failure_count += 1,
                VerificationResult::Interrupted => {
                    results.push((batch_number, result));
                    break;
                }
                VerificationResult::NoProofsFound => {}
            }

            results.push((batch_number, result));
        }

        // Log overall results
        BatchProcessor::log_overall_results(success_count, failure_count);

        Ok(results)
    }
}

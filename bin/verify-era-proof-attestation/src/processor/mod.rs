// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Processing logic for batch verification

mod batch_processor;
mod continuous_processor;
mod one_shot_processor;

pub use batch_processor::BatchProcessor;
pub use continuous_processor::ContinuousProcessor;
pub use one_shot_processor::OneShotProcessor;

use crate::{
    core::{VerificationResult, VerifierConfig, VerifierMode},
    error::Result,
};
use tokio::sync::watch;

// Using an enum instead of a trait because async functions in traits can't be used in trait objects
/// Processor variants for different verification modes
pub enum ProcessorType {
    /// One-shot processor for processing a specific range of batches
    OneShot(OneShotProcessor),
    /// Continuous processor for monitoring new batches
    Continuous(ContinuousProcessor),
}

impl ProcessorType {
    /// Run the processor until completion or interruption
    pub async fn run(
        &self,
        stop_receiver: watch::Receiver<bool>,
    ) -> Result<Vec<(u32, VerificationResult)>> {
        match self {
            ProcessorType::OneShot(processor) => processor.run(stop_receiver).await,
            ProcessorType::Continuous(processor) => processor.run(stop_receiver).await,
        }
    }
}

/// Factory for creating the appropriate processor based on configuration
pub struct ProcessorFactory;

impl ProcessorFactory {
    /// Create a new processor based on the provided configuration
    pub fn create(config: VerifierConfig) -> Result<(ProcessorType, VerifierMode)> {
        let mode = if let Some((start, end)) = config.args.batch_range {
            let processor = OneShotProcessor::new(config.clone(), start, end)?;
            let mode = VerifierMode::OneShot {
                start_batch: start,
                end_batch: end,
            };
            (ProcessorType::OneShot(processor), mode)
        } else if let Some(start) = config.args.continuous {
            let processor = ContinuousProcessor::new(config.clone(), start)?;
            let mode = VerifierMode::Continuous { start_batch: start };
            (ProcessorType::Continuous(processor), mode)
        } else {
            unreachable!("Clap ArgGroup should ensure either batch_range or continuous is set")
        };

        Ok(mode)
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Tool for SGX attestation and batch signature verification, both continuous and one-shot

mod client;
mod core;
mod error;
mod processor;
mod proof;
mod verification;

use crate::{
    core::{VerifierConfig, VerifierConfigArgs},
    error::Error,
    processor::ProcessorFactory,
};
use clap::Parser;
use error::Result;
use tokio::signal;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let config = VerifierConfig::new(VerifierConfigArgs::parse())?;

    // Initialize logging
    tracing::subscriber::set_global_default(
        teepot::log::setup_logging(env!("CARGO_CRATE_NAME"), &config.args.log_level)
            .map_err(|e| Error::internal(e.to_string()))?,
    )
    .map_err(|e| Error::internal(e.to_string()))?;

    // Create processor based on config
    let (processor, mode) = ProcessorFactory::create(config.clone())?;

    // Set up a cancellation Token
    let token = CancellationToken::new();

    // Log startup information
    tracing::info!("Starting verification in {}", mode);

    // Spawn processing task
    let mut process_handle = {
        let token = token.clone();
        tokio::spawn(async move { processor.run(token).await })
    };

    // Wait for processing to complete or for stop signal
    tokio::select! {
        result = &mut process_handle => {
            match result {
                Ok(Ok(verification_results)) => {
                    tracing::info!("Verification completed successfully");

                    let total_batches = verification_results.len();
                    let successful_batches = verification_results.iter()
                        .filter(|(_, result)| result.is_successful())
                        .count();

                    tracing::info!(
                        "Verified {} batches: {} succeeded, {} failed",
                        total_batches,
                        successful_batches,
                        total_batches - successful_batches
                    );

                    Ok(())
                },
                Ok(Err(e)) => {
                    tracing::error!("Verification failed: {}", e);
                    Err(e)
                },
                Err(e) => {
                    tracing::error!("Task panicked: {}", e);
                    Err(Error::internal(format!("Task panicked: {}", e)))
                }
            }
        },
        _ = signal::ctrl_c() => {
            tracing::info!("Stop signal received, shutting down gracefully...");
            token.cancel();

            // Wait for processor to complete gracefully
            match process_handle.await {
                Ok(_) => tracing::info!("Processor stopped gracefully"),
                Err(e) => tracing::error!("Error stopping processor: {}", e),
            }

            Ok(())
        }
    }
}

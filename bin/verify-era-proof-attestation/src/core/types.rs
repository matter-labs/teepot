// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Common type definitions used throughout the application

use std::fmt;
use zksync_basic_types::L1BatchNumber;

/// Represents the operating mode of the verifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierMode {
    /// Run on a single batch or range of batches and then exit
    OneShot {
        /// Starting batch number
        start_batch: L1BatchNumber,
        /// Ending batch number
        end_batch: L1BatchNumber,
    },
    /// Run continuously starting from a specific batch, until interrupted
    Continuous {
        /// Starting batch number
        start_batch: L1BatchNumber,
    },
}

impl fmt::Display for VerifierMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierMode::OneShot {
                start_batch,
                end_batch,
            } => {
                if start_batch == end_batch {
                    write!(f, "one-shot mode (batch {})", start_batch)
                } else {
                    write!(f, "one-shot mode (batches {}-{})", start_batch, end_batch)
                }
            }
            VerifierMode::Continuous { start_batch } => {
                write!(f, "continuous mode (starting from batch {})", start_batch)
            }
        }
    }
}

/// Result of proof verification for a single batch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// All proofs for the batch were verified successfully
    Success,
    /// Some proofs for the batch failed verification
    PartialSuccess {
        /// Number of successfully verified proofs
        verified_count: u32,
        /// Number of proofs that failed verification
        unverified_count: u32,
    },
    /// No proofs for the batch were verified successfully
    Failure,
    /// Verification was interrupted before completion
    Interrupted,
    /// No proofs were found for the batch
    NoProofsFound,
}

impl VerificationResult {
    /// Check if the majority of the proofs was verified successfully
    pub fn is_successful(&self) -> bool {
        match self {
            VerificationResult::Success => true,
            VerificationResult::PartialSuccess {
                verified_count,
                unverified_count,
            } => verified_count > unverified_count,
            VerificationResult::Failure => false,
            VerificationResult::Interrupted => false,
            VerificationResult::NoProofsFound => false,
        }
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationResult::Success => write!(f, "Success"),
            VerificationResult::PartialSuccess {
                verified_count,
                unverified_count,
            } => {
                write!(
                    f,
                    "Partial Success ({} verified, {} failed)",
                    verified_count, unverified_count
                )
            }
            VerificationResult::Failure => write!(f, "Failure"),
            VerificationResult::Interrupted => write!(f, "Interrupted"),
            VerificationResult::NoProofsFound => write!(f, "No Proofs Found"),
        }
    }
}

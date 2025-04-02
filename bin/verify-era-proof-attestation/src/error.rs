// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Error types for the verification process

use teepot::sgx::QuoteError;
use thiserror::Error;
use zksync_basic_types::L1BatchNumber;

/// Result type used throughout the application
pub type Result<T> = std::result::Result<T, Error>;

/// Error types that can occur during verification
#[derive(Error, Debug)]
pub enum Error {
    /// Error fetching proof
    #[error("Failed to fetch proof for batch {batch_number}: {reason}")]
    ProofFetch {
        /// Batch number that caused the error
        batch_number: L1BatchNumber,
        /// Reason for the error
        reason: String,
    },

    /// Error communicating with the HTTP server
    #[error("HTTP request failed with status {status_code}: {message}")]
    Http {
        /// HTTP status code
        status_code: u16,
        /// Error message
        message: String,
    },

    /// Error communicating with the JSON-RPC server
    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),

    /// JSON-RPC response has an invalid format
    #[error("JSON-RPC response has an invalid format")]
    JsonRpcInvalidResponse(String),

    /// Invalid batch range
    #[error("Invalid batch range: {0}")]
    InvalidBatchRange(String),

    /// Error verifying attestation
    #[error(transparent)]
    AttestationVerification(#[from] QuoteError),

    /// Error verifying signature
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    /// Attestation policy violation
    #[error("Attestation policy violation: {0}")]
    PolicyViolation(String),

    /// Operation interrupted
    #[error("Operation interrupted")]
    Interrupted,

    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Utility functions for working with errors
impl Error {
    /// Create a new proof fetch error
    pub fn proof_fetch(batch_number: L1BatchNumber, reason: impl Into<String>) -> Self {
        Self::ProofFetch {
            batch_number,
            reason: reason.into(),
        }
    }

    /// Create a new policy violation error
    pub fn policy_violation(reason: impl Into<String>) -> Self {
        Self::PolicyViolation(reason.into())
    }

    /// Create a new signature verification error
    pub fn signature_verification(reason: impl Into<String>) -> Self {
        Self::SignatureVerification(reason.into())
    }

    /// Create a new internal error
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::Internal(reason.into())
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Self::Http {
            status_code: value.status().map(|v| v.as_u16()).unwrap_or(0),
            message: value.to_string(),
        }
    }
}

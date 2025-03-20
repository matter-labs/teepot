// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use teepot::quote::{get_collateral, verify_quote_with_collateral, QuoteVerificationResult};

use crate::error;

/// Handles verification of attestation quotes
pub struct AttestationVerifier;

impl AttestationVerifier {
    /// Verify an attestation quote
    pub fn verify_quote(attestation_quote_bytes: &[u8]) -> error::Result<QuoteVerificationResult> {
        // Get collateral for the quote
        let collateral = get_collateral(attestation_quote_bytes)?;

        // Get current time for verification
        let unix_time: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| error::Error::internal(format!("Failed to get system time: {}", e)))?
            .as_secs() as _;

        // Verify the quote with the collateral
        let res =
            verify_quote_with_collateral(attestation_quote_bytes, Some(&collateral), unix_time)?;

        Ok(res)
    }
}

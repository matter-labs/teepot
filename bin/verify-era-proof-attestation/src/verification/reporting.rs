// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use teepot::quote::{tcblevel::TcbLevel, QuoteVerificationResult};

/// Handles reporting and logging of verification results
pub struct VerificationReporter;

impl VerificationReporter {
    /// Log summary of a quote verification
    pub fn log_quote_verification_summary(quote_verification_result: &QuoteVerificationResult) {
        let QuoteVerificationResult {
            collateral_expired,
            result,
            quote,
            advisories,
            ..
        } = quote_verification_result;

        if *collateral_expired {
            tracing::warn!("Freshly fetched collateral expired!");
        }

        let tcblevel = TcbLevel::from(*result);
        let advisories = if advisories.is_empty() {
            "None".to_string()
        } else {
            advisories
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        tracing::debug!(
            "Quote verification result: {tcblevel}. {report}. Advisory IDs: {advisories}.",
            report = &quote.report
        );
    }

    /// Log the results of batch verification
    pub fn log_batch_verification_results(
        batch_no: u32,
        verified_proofs_count: u32,
        unverified_proofs_count: u32,
    ) {
        if unverified_proofs_count > 0 {
            if verified_proofs_count == 0 {
                tracing::error!(
                    batch_no,
                    "All {} proofs failed verification!",
                    unverified_proofs_count
                );
            } else {
                tracing::warn!(
                    batch_no,
                    "Some proofs failed verification. Unverified proofs: {}. Verified proofs: {}.",
                    unverified_proofs_count,
                    verified_proofs_count
                );
            }
        } else if verified_proofs_count > 0 {
            tracing::info!(
                batch_no,
                "All {} proofs verified successfully!",
                verified_proofs_count
            );
        }
    }

    /// Log overall verification results for multiple batches
    pub fn log_overall_verification_results(
        verified_batches_count: u32,
        unverified_batches_count: u32,
    ) {
        if unverified_batches_count > 0 {
            if verified_batches_count == 0 {
                tracing::error!(
                    "All {} batches failed verification!",
                    unverified_batches_count
                );
            } else {
                tracing::error!(
                    "Some batches failed verification! Unverified batches: {}. Verified batches: {}.",
                    unverified_batches_count,
                    verified_batches_count
                );
            }
        } else {
            tracing::info!("{} batches verified successfully!", verified_batches_count);
        }
    }
}

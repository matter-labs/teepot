// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use crate::{
    core::AttestationPolicy,
    error::{Error, Result},
};
use bytes::Bytes;
use enumset::EnumSet;
use teepot::quote::{tcblevel::TcbLevel, QuoteVerificationResult, Report};

/// Enforces policy requirements on attestation quotes
pub struct PolicyEnforcer;

impl PolicyEnforcer {
    /// Check if a quote matches the attestation policy
    pub fn validate_policy(
        attestation_policy: &AttestationPolicy,
        quote_verification_result: &QuoteVerificationResult,
    ) -> Result<()> {
        let quote = &quote_verification_result.quote;
        let tcblevel = TcbLevel::from(quote_verification_result.result);

        match &quote.report {
            Report::SgxEnclave(report_body) => {
                // Validate TCB level
                Self::validate_tcb_level(&attestation_policy.sgx_allowed_tcb_levels, tcblevel)?;

                // Validate SGX Advisories
                for advisory in &quote_verification_result.advisories {
                    Self::check_policy(
                        attestation_policy.sgx_allowed_advisory_ids.as_deref(),
                        advisory,
                        "advisories",
                    )?;
                }

                // Validate SGX policies
                Self::check_policy_hash(
                    attestation_policy.sgx_mrsigners.as_deref(),
                    &report_body.mr_signer,
                    "mrsigner",
                )?;

                Self::check_policy_hash(
                    attestation_policy.sgx_mrenclaves.as_deref(),
                    &report_body.mr_enclave,
                    "mrenclave",
                )
            }
            Report::TD10(report_body) => {
                // Validate TCB level
                Self::validate_tcb_level(&attestation_policy.tdx_allowed_tcb_levels, tcblevel)?;

                // Validate TDX Advisories
                for advisory in &quote_verification_result.advisories {
                    Self::check_policy(
                        attestation_policy.tdx_allowed_advisory_ids.as_deref(),
                        advisory,
                        "mrsigner",
                    )?;
                }

                // Build combined TDX MR and validate
                let tdx_mr = Self::build_tdx_mr([
                    &report_body.mr_td,
                    &report_body.rt_mr0,
                    &report_body.rt_mr1,
                    &report_body.rt_mr2,
                    &report_body.rt_mr3,
                ]);

                Self::check_policy_hash(attestation_policy.tdx_mrs.as_deref(), &tdx_mr, "tdxmr")
            }
            Report::TD15(report_body) => {
                // Validate TCB level
                Self::validate_tcb_level(&attestation_policy.tdx_allowed_tcb_levels, tcblevel)?;

                // Validate TDX Advisories
                for advisory in &quote_verification_result.advisories {
                    Self::check_policy(
                        attestation_policy.tdx_allowed_advisory_ids.as_deref(),
                        advisory,
                        "advisories",
                    )?;
                }

                // Build combined TDX MR and validate
                let tdx_mr = Self::build_tdx_mr([
                    &report_body.base.mr_td,
                    &report_body.base.rt_mr0,
                    &report_body.base.rt_mr1,
                    &report_body.base.rt_mr2,
                    &report_body.base.rt_mr3,
                ]);

                Self::check_policy_hash(attestation_policy.tdx_mrs.as_deref(), &tdx_mr, "tdxmr")
            }
            _ => Err(Error::policy_violation("Unknown quote report format")),
        }
    }

    /// Helper method to validate TCB levels
    fn validate_tcb_level(
        allowed_levels: &EnumSet<TcbLevel>,
        actual_level: TcbLevel,
    ) -> Result<()> {
        if !allowed_levels.contains(actual_level) {
            let error_msg = format!(
                "Quote verification failed: TCB level mismatch (expected one of: {:?}, actual: {})",
                allowed_levels, actual_level
            );
            return Err(Error::policy_violation(error_msg));
        }
        Ok(())
    }

    /// Helper method to build combined TDX measurement register
    fn build_tdx_mr<const N: usize>(parts: [&[u8]; N]) -> Vec<u8> {
        parts.into_iter().flatten().cloned().collect()
    }

    /// Check if a policy value matches the actual value
    fn check_policy(policy: Option<&[String]>, actual_value: &str, field_name: &str) -> Result<()> {
        if let Some(valid_values) = policy {
            if !valid_values.iter().any(|value| value == actual_value) {
                let error_msg =
                    format!(
                    "Quote verification failed: {} mismatch (expected one of: [ {} ], actual: {})",
                    field_name, valid_values.join(", "), actual_value
                );
                return Err(Error::policy_violation(error_msg));
            }

            tracing::debug!(field_name, actual_value, "Attestation policy check passed");
        }

        Ok(())
    }

    fn check_policy_hash(
        policy: Option<&[Bytes]>,
        actual_value: &[u8],
        field_name: &str,
    ) -> Result<()> {
        if let Some(valid_values) = policy {
            let actual_value = Bytes::copy_from_slice(actual_value);
            if !valid_values.contains(&actual_value) {
                let valid_values = valid_values
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(", ");
                let error_msg = format!(
                    "Quote verification failed: {} mismatch (expected one of: [ {} ], actual: {:x})",
                    field_name, valid_values, actual_value
                );
                return Err(Error::policy_violation(error_msg));
            }

            tracing::debug!(
                field_name,
                actual_value = format!("{actual_value:x}"),
                "Attestation policy check passed"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_policy() {
        // Test with no policy (should pass)
        PolicyEnforcer::check_policy_hash(None, &[1, 2, 3], "test").unwrap();

        // Test with matching policy
        let actual_value: Bytes = hex::decode("01020304").unwrap().into();
        PolicyEnforcer::check_policy_hash(
            Some(vec![actual_value.clone()]).as_deref(),
            &actual_value,
            "test",
        )
        .unwrap();

        //.clone() Test with matching policy (multiple values)
        PolicyEnforcer::check_policy_hash(
            Some(vec![
                "aabbcc".into(),
                "01020304".into(),
                "ddeeff".into(),
                actual_value.clone(),
            ])
            .as_deref(),
            &actual_value,
            "test",
        )
        .unwrap();

        // Test with non-matching policy
        PolicyEnforcer::check_policy_hash(
            Some(vec!["aabbcc".into(), "ddeeff".into()]).as_deref(),
            &actual_value,
            "test",
        )
        .unwrap_err();
    }
}

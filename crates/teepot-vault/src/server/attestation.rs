// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Common attestation API for all TEEs

use crate::client::AttestationArgs;
use clap::Args;
use serde::{Deserialize, Serialize};

pub use teepot::{
    quote::{
        attestation::get_quote_and_collateral, error::QuoteContext, get_quote,
        verify_quote_with_collateral, QuoteVerificationResult,
    },
    sgx::{parse_tcb_levels, Collateral, EnumSet, TcbLevel},
};

/// Options and arguments needed to attest a TEE
#[derive(Args, Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultAttestationArgs {
    /// hex encoded SGX mrsigner of the enclave to attest
    #[arg(long, env = "VAULT_SGX_MRSIGNER")]
    pub vault_sgx_mrsigner: Option<String>,
    /// hex encoded SGX mrenclave of the enclave to attest
    #[arg(long, env = "VAULT_SGX_MRENCLAVE")]
    pub vault_sgx_mrenclave: Option<String>,
    /// URL of the server
    #[arg(long, required = true, env = "VAULT_ADDR")]
    pub vault_addr: String,
    /// allowed TCB levels, comma separated:
    /// Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded, OutOfDate, OutOfDateConfigNeeded
    #[arg(long, value_parser = parse_tcb_levels, env = "VAULT_SGX_ALLOWED_TCB_LEVELS")]
    pub vault_sgx_allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
}

impl From<VaultAttestationArgs> for AttestationArgs {
    fn from(value: VaultAttestationArgs) -> Self {
        AttestationArgs {
            sgx_mrsigner: value.vault_sgx_mrsigner,
            sgx_mrenclave: value.vault_sgx_mrenclave,
            server: value.vault_addr,
            sgx_allowed_tcb_levels: value.vault_sgx_allowed_tcb_levels,
        }
    }
}

impl From<&VaultAttestationArgs> for AttestationArgs {
    fn from(value: &VaultAttestationArgs) -> Self {
        AttestationArgs {
            sgx_mrsigner: value.vault_sgx_mrsigner.clone(),
            sgx_mrenclave: value.vault_sgx_mrenclave.clone(),
            server: value.vault_addr.clone(),
            sgx_allowed_tcb_levels: value.vault_sgx_allowed_tcb_levels,
        }
    }
}

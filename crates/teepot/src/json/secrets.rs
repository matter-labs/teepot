// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Common types for the teepot secrets JSON API

use crate::server::signatures::MultiSigPolicy;
use crate::sgx::sign::Zeroizing;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Configuration for the admin tee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// admin signature policy
    pub policy: MultiSigPolicy,
}

impl AdminConfig {
    /// validate the configuration
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()
    }
}

/// Configuration for the admin tee
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdminState {
    /// last digest of executed commands
    pub last_digest: String,
}

/// Configuration for the admin tee
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SGXSigningKey {
    /// private key in PEM format
    pub pem_pk: Zeroizing<String>,
}

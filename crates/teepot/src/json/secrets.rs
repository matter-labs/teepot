// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Common types for the teepot secrets JSON API

use crate::sgx::sign::Zeroizing;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;

/// Configuration for the admin tee
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminConfig {
    /// PGP keys to sign commands for the admin tee
    #[serde_as(as = "Box<[Base64]>")]
    pub admin_pgp_keys: Box<[Box<[u8]>]>,
    /// admin threshold
    pub admin_threshold: usize,
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

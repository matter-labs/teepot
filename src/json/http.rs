// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Common types for the teepot http JSON API

use crate::sgx::Collateral;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::fmt::Display;
use std::sync::Arc;

/// The unseal request data
#[derive(Debug, Serialize, Deserialize)]
pub struct Unseal {
    /// The unseal key
    pub key: String,
}

impl Unseal {
    /// The unseal URL
    pub const URL: &'static str = "/v1/sys/unseal";
}

/// The attestation URL
pub const ATTESTATION_URL: &str = "/v1/sys/attestation";

/// The attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// The quote
    pub quote: Arc<[u8]>,
    /// The collateral
    pub collateral: Arc<Collateral>,
}

/// The init request data
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Init {
    /// PGP keys to encrypt the unseal keys with
    pub pgp_keys: Vec<String>,
    /// number of secret shares
    pub secret_shares: usize,
    /// secret threshold
    pub secret_threshold: usize,
    /// PGP keys to sign commands for the admin tee
    #[serde_as(as = "Box<[Base64]>")]
    pub admin_pgp_keys: Box<[Box<[u8]>]>,
    /// admin threshold
    pub admin_threshold: usize,
    /// admin TEE mrenclave
    pub admin_tee_mrenclave: String,
}

impl Init {
    /// The init URL
    pub const URL: &'static str = "/v1/sys/init";
}

/// The init request data
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultInitRequest {
    /// PGP keys to encrypt the unseal keys with
    pub pgp_keys: Vec<String>,
    /// number of secret shares
    pub secret_shares: usize,
    /// secret threshold
    pub secret_threshold: usize,
}

/// The init response data
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    /// The unseal keys (gpg encrypted)
    pub unseal_keys: Vec<String>,
}

/// The Vault TEE auth request data
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    /// The name of the TEE
    pub name: String,
    /// The type of the TEE
    #[serde(rename = "type")]
    pub tee_type: String,
    /// The attestation report data base64 encoded
    #[serde_as(as = "Base64")]
    pub quote: Box<[u8]>,
    /// The attestation collateral json encoded
    pub collateral: String,
    /// The vault attestation challenge (hex encoded)
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    #[serde(skip_serializing_if = "Option::is_none", default = "Option::default")]
    pub challenge: Option<[u8; 32]>,
}

impl AuthRequest {
    /// The auth URL
    pub const URL: &'static str = "/v1/auth/tee/login";
}

/// Vault auth metadata
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthMetadataField {
    collateral_expiration_date: String,
    tee_name: String,
}

/// Vault auth data
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthDataField {
    /// The attestation report data base64 encoded
    #[serde_as(as = "Base64")]
    #[serde(default)]
    pub quote: Box<[u8]>,
    /// The attestation collateral json encoded
    #[serde(default)]
    pub collateral: String,
}

/// Vault auth
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthField {
    /// TODO
    pub renewable: bool,
    /// TODO
    pub lease_duration: isize,
    /// TODO
    pub policies: Vec<String>,
    /// TODO
    pub accessor: String,
    /// TODO
    pub client_token: String,
    /// TODO
    pub metadata: AuthMetadataField,
}

/// The Vault TEE auth response data
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuthResponse {
    /// vault auth
    pub auth: AuthField,
    ///
    pub data: AuthDataField,
}

/// One command datum
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct VaultCommand {
    /// The command to execute
    pub url: String,
    /// The command to execute
    pub data: Value,
}

impl Display for VaultCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str(
                serde_json::to_string_pretty(self)
                    .unwrap_or("{}".into())
                    .as_str(),
            )
        } else {
            f.write_str(serde_json::to_string(self).unwrap_or("{}".into()).as_str())
        }
    }
}

/// Multiple command data
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct VaultCommands {
    /// The sha-256 hash of the last command hex encoded
    pub last_digest: String,
    /// The actual commands
    pub commands: Vec<VaultCommand>,
}

/// The command request data
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultCommandRequest {
    /// The commands to execute
    ///
    /// The commands are json serialized `VaultCommands`,
    /// because they are signed with multiple signatures.
    ///
    /// The commands are executed in order.
    pub commands: String,
    /// The signatures of the commands
    pub signatures: Vec<String>,
}

impl VaultCommandRequest {
    /// The command request URL
    pub const URL: &'static str = "/v1/command";
}

/// The command response
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultCommandResponse {
    /// The status code
    pub status_code: u16,
    /// The response body
    pub value: Option<Value>,
}

/// The command response
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultCommandsResponse {
    /// The stored digest for the execution
    pub digest: String,
    /// The results of the individual commands
    pub results: Vec<VaultCommandResponse>,
}

impl Display for VaultCommandResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str(
                serde_json::to_string_pretty(self)
                    .unwrap_or("{}".into())
                    .as_str(),
            )
        } else {
            f.write_str(serde_json::to_string(self).unwrap_or("{}".into()).as_str())
        }
    }
}

/// The command request URL
pub const DIGEST_URL: &str = "/v1/digest";

/// The signing request
#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    /// json serialized `SignRequestData`, because it is signed with multiple signatures.
    pub sign_request_data: String,
    /// The signatures of the SignRequestData
    pub signatures: Vec<String>,
}

impl SignRequest {
    /// The sign request URL
    pub const URL: &'static str = "/v1/sign";
}

/// The signing request data
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignRequestData {
    /// The sha-256 hash of the last command hex encoded
    pub last_digest: String,
    /// The name of the TEE
    pub tee_name: String,
    /// The type of the TEE
    #[serde(rename = "type")]
    pub tee_type: String,
    /// The TEE security version number
    pub tee_svn: u16,
    /// The data to be signed.
    ///
    /// In case of `tee_type == "sgx"`, it's the SGX Sigstruct Body
    #[serde_as(as = "Base64")]
    pub data: Vec<u8>,
}

/// The signing request
#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    /// The stored digest for the execution
    pub digest: String,
    /// The signed data for the tee.
    ///
    /// In case of `tee_type == "sgx"`, it's the SGX Sigstruct
    pub signed_data: Vec<u8>,
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

//! Intel API Client
//!
//! This module provides an API client for interacting with the Intel API for Trusted Services.
//! The API follows the documentation found at [Intel API Documentation](https://api.portal.trustedservices.intel.com/content/documentation.html).
//!
//! Create an [`ApiClient`] to interface with the Intel API.
//!
//! Example
//! ```rust,no_run
//! use intel_dcap_api::{ApiClient, IntelApiError, TcbInfoResponse};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), IntelApiError> {
//!    let client = ApiClient::new()?;
//!
//!    // Example: Get SGX TCB Info
//!    let fmspc_example = "00606A000000"; // Example FMSPC from docs
//!    match client.get_sgx_tcb_info(fmspc_example, None, None).await {
//!        Ok(TcbInfoResponse {
//!               tcb_info_json,
//!               issuer_chain,
//!           }) => println!(
//!            "SGX TCB Info for {}:\n{}\nIssuer Chain: {}",
//!           fmspc_example, tcb_info_json, issuer_chain
//!        ),
//!        Err(e) => eprintln!("Error getting SGX TCB info: {}", e),
//!    }
//!
//!    Ok(())
//! }
//! ```

#![deny(missing_docs)]
#![deny(clippy::all)]

mod client;
mod error;
mod requests;
mod responses;
mod types;

// Re-export public items
pub use client::ApiClient;
pub use error::IntelApiError;
pub use responses::{
    AddPackageResponse, EnclaveIdentityJson, EnclaveIdentityResponse, FmspcJsonResponse,
    PckCertificateResponse, PckCertificatesResponse, PckCrlResponse, TcbEvaluationDataNumbersJson,
    TcbEvaluationDataNumbersResponse, TcbInfoJson, TcbInfoResponse,
};
pub use types::{ApiVersion, CaType, CrlEncoding, PlatformFilter, UpdateType};

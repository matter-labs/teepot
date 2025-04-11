// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

mod enclave_identity;
mod fmspc;
mod helpers;
mod pck_cert;
mod pck_crl;
mod registration;
mod tcb_info;

use crate::{
    error::IntelApiError,
    types::ApiVersion, // Import ApiVersion
};
use reqwest::Client;
use url::Url;

// Base URL for the Intel Trusted Services API
const BASE_URL: &str = "https://api.trustedservices.intel.com";

/// Client for interacting with Intel Trusted Services API.
///
/// Provides methods to access both SGX and TDX certification services,
/// supporting API versions V3 and V4. This client offers functionality
/// to register platforms, retrieve PCK certificates and CRLs, fetch TCB
/// information, enclave identities, as well as TCB evaluation data numbers.
///
/// # Examples
///
/// ```rust,no_run
/// use intel_dcap_api::ApiClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Create a client with default settings (V4 API)
///     let client = ApiClient::new()?;
///
///     // Retrieve TCB info for a specific FMSPC
///     let tcb_info = client.get_sgx_tcb_info("00606A000000", None, None).await?;
///     println!("TCB Info: {}", tcb_info.tcb_info_json);
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: Url,
    api_version: ApiVersion,
}

impl ApiClient {
    /// Creates a new client targeting the latest supported API version (V4).
    ///
    /// # Returns
    ///
    /// A result containing the newly created `ApiClient` or an `IntelApiError` if there
    /// was an issue building the underlying HTTP client.
    ///
    /// # Errors
    ///
    /// This function may fail if the provided TLS version or base URL
    /// cannot be used to build a `reqwest` client.
    pub fn new() -> Result<Self, IntelApiError> {
        Self::new_with_options(BASE_URL, ApiVersion::V4) // Default to V4
    }

    /// Creates a new client targeting a specific API version.
    ///
    /// # Arguments
    ///
    /// * `api_version` - The desired API version to use (V3 or V4).
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the `reqwest` client cannot be built
    /// with the specified options.
    pub fn new_with_version(api_version: ApiVersion) -> Result<Self, IntelApiError> {
        Self::new_with_options(BASE_URL, api_version)
    }

    /// Creates a new client with a custom base URL, targeting the latest supported API version (V4).
    ///
    /// # Arguments
    ///
    /// * `base_url` - The custom base URL for the Intel Trusted Services API.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the `reqwest` client cannot be built
    /// or if the provided base URL is invalid.
    pub fn new_with_base_url(base_url: impl reqwest::IntoUrl) -> Result<Self, IntelApiError> {
        Self::new_with_options(base_url, ApiVersion::V4) // Default to V4
    }

    /// Creates a new client with a custom base URL and specific API version.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The custom base URL for the Intel Trusted Services API.
    /// * `api_version` - The desired API version (V3 or V4).
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the `reqwest` client cannot be built
    /// or if the provided base URL is invalid.
    pub fn new_with_options(
        base_url: impl reqwest::IntoUrl,
        api_version: ApiVersion,
    ) -> Result<Self, IntelApiError> {
        Ok(ApiClient {
            client: Client::builder()
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .build()?,
            base_url: base_url.into_url()?,
            api_version, // Store the version
        })
    }
}

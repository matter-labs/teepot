// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use super::ApiClient; // Import from parent module
use crate::{
    error::{check_status, IntelApiError},
    responses::AddPackageResponse,
};
use reqwest::{header, StatusCode};
use std::num::ParseIntError;

impl ApiClient {
    /// POST /sgx/registration/v1/platform
    /// Registers a multi-package SGX platform with the Intel Trusted Services API.
    ///
    /// # Arguments
    ///
    /// * `platform_manifest` - Binary data representing the platform manifest.
    ///
    /// # Returns
    ///
    /// Request body is binary Platform Manifest
    /// Returns the hex-encoded PPID as a `String` upon success.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or if the response status
    /// is not HTTP `201 CREATED`.
    pub async fn register_platform(
        &self,
        platform_manifest: Vec<u8>,
    ) -> Result<String, IntelApiError> {
        // Registration paths are fixed, use the helper with "registration" service
        let path = self.build_api_path("sgx", "registration", "platform")?;
        let url = self.base_url.join(&path)?;

        let response = self
            .client
            .post(url)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(platform_manifest)
            .send()
            .await?;

        let response = check_status(response, &[StatusCode::CREATED]).await?;

        // Response body is hex-encoded PPID
        let ppid_hex = response.text().await?;
        Ok(ppid_hex)
    }

    /// POST /sgx/registration/v1/package
    /// Adds new package(s) to an already registered SGX platform instance.
    ///
    /// # Arguments
    ///
    /// * `add_package_request` - Binary data for the "Add Package" request body.
    /// * `subscription_key` - The subscription key required by the Intel API.
    ///
    /// # Returns
    ///
    /// A [`AddPackageResponse`] containing the Platform Membership Certificates and
    /// the count of them extracted from the response header.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails, if the subscription key is invalid,
    /// or if the response status is not HTTP `200 OK`.
    pub async fn add_package(
        &self,
        add_package_request: Vec<u8>,
        subscription_key: &str,
    ) -> Result<AddPackageResponse, IntelApiError> {
        if subscription_key.is_empty() {
            return Err(IntelApiError::InvalidSubscriptionKey);
        }

        // Registration paths are fixed
        let path = self.build_api_path("sgx", "registration", "package")?;
        let url = self.base_url.join(&path)?;

        let response = self
            .client
            .post(url)
            .header("Ocp-Apim-Subscription-Key", subscription_key)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(add_package_request)
            .send()
            .await?;

        let response = check_status(response, &[StatusCode::OK]).await?;

        // Use the generic header helper, assuming header name is stable across reg versions
        let cert_count_str = self.get_required_header(&response, "Certificate-Count", None)?;
        let pck_cert_count: usize = cert_count_str.parse().map_err(|e: ParseIntError| {
            IntelApiError::HeaderValueParse("Certificate-Count", e.to_string())
        })?;

        // Response body is a binary array of certificates
        let pck_certs = response.bytes().await?.to_vec();
        Ok(AddPackageResponse {
            pck_certs,
            pck_cert_count,
        })
    }
}

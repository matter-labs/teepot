// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use super::ApiClient; // Import from parent module
use crate::{
    error::IntelApiError,
    requests::{PckCertRequest, PckCertsConfigRequest, PckCertsRequest},
    responses::{PckCertificateResponse, PckCertificatesResponse},
    types::ApiVersion,
};
use reqwest::header;

impl ApiClient {
    // === Provisioning Certification Service ===

    /// GET /sgx/certification/{v3,v4}/pckcert
    /// Retrieves a single SGX PCK certificate using encrypted PPID and SVNs.
    ///
    /// Optionally requires a subscription key. The `ppid_encryption_key_type` parameter
    /// is only valid for API v4 and allows specifying the PPID encryption key type (e.g. "RSA-3072").
    ///
    /// # Arguments
    ///
    /// * `encrypted_ppid` - Hex-encoded encrypted PPID.
    /// * `cpusvn` - Hex-encoded CPUSVN value.
    /// * `pcesvn` - Hex-encoded PCESVN value.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `subscription_key` - Optional subscription key if the Intel API requires it.
    /// * `ppid_encryption_key_type` - Optional PPID encryption key type (V4 only).
    ///
    /// # Returns
    ///
    /// A [`PckCertificateResponse`] containing the PEM-encoded certificate, issuer chain,
    /// TCBm, and FMSPC.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the API call fails or the response contains an invalid status.
    /// Returns PEM Cert, Issuer Chain, TCBm, FMSPC.
    pub async fn get_pck_certificate_by_ppid(
        &self,
        encrypted_ppid: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        subscription_key: Option<&str>,
        ppid_encryption_key_type: Option<&str>,
    ) -> Result<PckCertificateResponse, IntelApiError> {
        // Check V4-only parameter
        self.check_v4_only_param(ppid_encryption_key_type, "PPID-Encryption-Key")?;

        let path = self.build_api_path("sgx", "", "pckcert")?; // service is empty
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut()
            .append_pair("encrypted_ppid", encrypted_ppid)
            .append_pair("cpusvn", cpusvn)
            .append_pair("pcesvn", pcesvn)
            .append_pair("pceid", pceid);

        let mut request_builder = self.client.get(url);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        // Only add for V4
        if self.api_version == ApiVersion::V4 {
            request_builder = Self::maybe_add_header(
                request_builder,
                "PPID-Encryption-Key",
                ppid_encryption_key_type,
            );
        }

        self.fetch_pck_certificate(request_builder).await
    }

    /// POST /sgx/certification/{v3,v4}/pckcert
    /// Retrieves a single SGX PCK certificate using a platform manifest and SVNs.
    ///
    /// Optionally requires a subscription key.
    ///
    /// # Arguments
    ///
    /// * `platform_manifest` - Hex-encoded platform manifest.
    /// * `cpusvn` - Hex-encoded CPUSVN value.
    /// * `pcesvn` - Hex-encoded PCESVN value.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `subscription_key` - Optional subscription key if the Intel API requires it.
    ///
    /// # Returns
    ///
    /// A [`PckCertificateResponse`] containing the PEM-encoded certificate, issuer chain,
    /// TCBm, and FMSPC.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or if the response is invalid.
    /// Returns PEM Cert, Issuer Chain, TCBm, FMSPC.
    pub async fn get_pck_certificate_by_manifest(
        &self,
        platform_manifest: &str,
        cpusvn: &str,
        pcesvn: &str,
        pceid: &str,
        subscription_key: Option<&str>,
    ) -> Result<PckCertificateResponse, IntelApiError> {
        let path = self.build_api_path("sgx", "", "pckcert")?;
        let url = self.base_url.join(&path)?;
        let request_body = PckCertRequest {
            platform_manifest,
            cpusvn,
            pcesvn,
            pceid,
        };

        let mut request_builder = self
            .client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request_body);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        self.fetch_pck_certificate(request_builder).await
    }

    /// GET /sgx/certification/{v3,v4}/pckcerts
    /// Retrieves all SGX PCK certificates for a platform using encrypted PPID.
    ///
    /// Optionally requires a subscription key. The `ppid_encryption_key_type` parameter
    /// is only valid for API v4.
    ///
    /// # Arguments
    ///
    /// * `encrypted_ppid` - Hex-encoded encrypted PPID.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `subscription_key` - Optional subscription key if the Intel API requires it.
    /// * `ppid_encryption_key_type` - Optional PPID encryption key type (V4 only).
    ///
    /// # Returns
    ///
    /// A [`PckCertificatesResponse`] containing JSON with `{tcb, tcbm, cert}` entries,
    /// as well as the issuer chain and FMSPC headers.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the API call fails or the response status is invalid.
    pub async fn get_pck_certificates_by_ppid(
        &self,
        encrypted_ppid: &str,
        pceid: &str,
        subscription_key: Option<&str>,
        ppid_encryption_key_type: Option<&str>,
    ) -> Result<PckCertificatesResponse, IntelApiError> {
        // Check V4-only parameter
        self.check_v4_only_param(ppid_encryption_key_type, "PPID-Encryption-Key")?;

        let path = self.build_api_path("sgx", "", "pckcerts")?;
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut()
            .append_pair("encrypted_ppid", encrypted_ppid)
            .append_pair("pceid", pceid);

        let mut request_builder = self.client.get(url);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        // Only add for V4
        if self.api_version == ApiVersion::V4 {
            request_builder = Self::maybe_add_header(
                request_builder,
                "PPID-Encryption-Key",
                ppid_encryption_key_type,
            );
        }

        self.fetch_pck_certificates(request_builder).await
    }

    /// POST /sgx/certification/{v3,v4}/pckcerts
    /// Retrieves all SGX PCK certificates for a platform using a platform manifest.
    ///
    /// Optionally requires a subscription key.
    ///
    /// # Arguments
    ///
    /// * `platform_manifest` - Hex-encoded platform manifest.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `subscription_key` - Optional subscription key if the Intel API requires it.
    ///
    /// # Returns
    ///
    /// A [`PckCertificatesResponse`] containing JSON with `{tcb, tcbm, cert}` entries,
    /// as well as the issuer chain and FMSPC headers.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the API call fails or the response status is invalid.
    pub async fn get_pck_certificates_by_manifest(
        &self,
        platform_manifest: &str,
        pceid: &str,
        subscription_key: Option<&str>,
    ) -> Result<PckCertificatesResponse, IntelApiError> {
        let path = self.build_api_path("sgx", "", "pckcerts")?;
        let url = self.base_url.join(&path)?;
        let request_body = PckCertsRequest {
            platform_manifest,
            pceid,
        };

        let mut request_builder = self
            .client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request_body);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        self.fetch_pck_certificates(request_builder).await
    }

    /// GET /sgx/certification/{v3,v4}/pckcerts/config (using PPID)
    /// Retrieves SGX PCK certificates for a specific configuration (CPUSVN) using encrypted PPID.
    ///
    /// Optionally requires a subscription key. The `ppid_encryption_key_type` parameter
    /// is only valid for API v4. Returns JSON with `{tcb, tcbm, cert}` entries,
    /// as well as the issuer chain and FMSPC headers.
    ///
    /// # Arguments
    ///
    /// * `encrypted_ppid` - Hex-encoded encrypted PPID.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `cpusvn` - Hex-encoded CPUSVN value for the requested configuration.
    /// * `subscription_key` - Optional subscription key if the Intel API requires it.
    /// * `ppid_encryption_key_type` - Optional PPID encryption key type (V4 only).
    ///
    /// # Returns
    ///
    /// A [`PckCertificatesResponse`] with the requested config's certificate data.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or if the response status
    /// is not `200 OK`.
    pub async fn get_pck_certificates_config_by_ppid(
        &self,
        encrypted_ppid: &str,
        pceid: &str,
        cpusvn: &str,
        subscription_key: Option<&str>,
        ppid_encryption_key_type: Option<&str>,
    ) -> Result<PckCertificatesResponse, IntelApiError> {
        // V3 does not support PPID-Encryption-Key header/type
        if self.api_version == ApiVersion::V3 && ppid_encryption_key_type.is_some() {
            return Err(IntelApiError::UnsupportedApiVersion(
                "PPID-Encryption-Key header is only supported in API v4".to_string(),
            ));
        }

        let path = self.build_api_path("sgx", "", "pckcerts/config")?;
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut()
            .append_pair("encrypted_ppid", encrypted_ppid)
            .append_pair("pceid", pceid)
            .append_pair("cpusvn", cpusvn);

        let mut request_builder = self.client.get(url);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        // Only add for V4
        if self.api_version == ApiVersion::V4 {
            request_builder = Self::maybe_add_header(
                request_builder,
                "PPID-Encryption-Key",
                ppid_encryption_key_type,
            );
        }

        self.fetch_pck_certificates(request_builder).await
    }

    /// POST /sgx/certification/{v3,v4}/pckcerts/config (using Manifest)
    /// Retrieves SGX PCK certificates for a specific configuration (CPUSVN) using a platform manifest.
    ///
    /// Optionally requires a subscription key. Returns JSON with `{tcb, tcbm, cert}` entries,
    /// as well as the issuer chain and FMSPC headers.
    ///
    /// # Arguments
    ///
    /// * `platform_manifest` - Hex-encoded platform manifest.
    /// * `pceid` - Hex-encoded PCEID value.
    /// * `cpusvn` - Hex-encoded CPUSVN value for the requested configuration.
    /// * `subscription_key` - Optional subscription key if needed by the Intel API.
    ///
    /// # Returns
    ///
    /// A [`PckCertificatesResponse`] with the requested config's certificate data.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or if the response status
    /// is not `200 OK`.
    pub async fn get_pck_certificates_config_by_manifest(
        &self,
        platform_manifest: &str,
        pceid: &str,
        cpusvn: &str,
        subscription_key: Option<&str>,
    ) -> Result<PckCertificatesResponse, IntelApiError> {
        let path = self.build_api_path("sgx", "", "pckcerts/config")?;
        let url = self.base_url.join(&path)?;
        let request_body = PckCertsConfigRequest {
            platform_manifest,
            pceid,
            cpusvn,
        };

        let mut request_builder = self
            .client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request_body);

        request_builder = Self::maybe_add_header(
            request_builder,
            "Ocp-Apim-Subscription-Key",
            subscription_key,
        );

        self.fetch_pck_certificates(request_builder).await
    }
}

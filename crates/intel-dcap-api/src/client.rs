// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use crate::responses::AddPackageResponse;
use crate::{
    error::{check_status, extract_api_error_details, IntelApiError},
    requests::{PckCertRequest, PckCertsConfigRequest, PckCertsRequest},
    responses::{
        EnclaveIdentityResponse, PckCertificateResponse, PckCertificatesResponse, PckCrlResponse,
        TcbEvaluationDataNumbersResponse, TcbInfoResponse,
    },
    types::{ApiVersion, CaType, CrlEncoding, PlatformFilter, UpdateType}, // Import ApiVersion
    FmspcJsonResponse,
};
use percent_encoding::percent_decode_str;
use reqwest::{header, Client, IntoUrl, RequestBuilder, Response, StatusCode};
use std::num::ParseIntError;
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
    pub fn new_with_base_url(base_url: impl IntoUrl) -> Result<Self, IntelApiError> {
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
        base_url: impl IntoUrl,
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

    /// GET /sgx/certification/{v3,v4}/pckcrl
    /// Retrieves the PCK Certificate Revocation List (CRL) for a specified CA type.
    ///
    /// Optionally takes an `encoding` parameter indicating whether the CRL should be
    /// returned as PEM or DER. Defaults to PEM if not specified.
    ///
    /// # Arguments
    ///
    /// * `ca_type` - The type of CA to retrieve the CRL for (e.g., "processor" or "platform").
    /// * `encoding` - An optional [`CrlEncoding`] (PEM or DER).
    ///
    /// # Returns
    ///
    /// A [`PckCrlResponse`] containing the CRL data and the issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or if the response status
    /// is not `200 OK`.
    /// Optional 'encoding' parameter ("pem" or "der").
    /// Returns CRL data (PEM or DER) and Issuer Chain header.
    pub async fn get_pck_crl(
        &self,
        ca_type: CaType,
        encoding: Option<CrlEncoding>,
    ) -> Result<PckCrlResponse, IntelApiError> {
        let path = self.build_api_path("sgx", "", "pckcrl")?;
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut()
            .append_pair("ca", &ca_type.to_string());

        if let Some(enc) = encoding {
            url.query_pairs_mut()
                .append_pair("encoding", &enc.to_string());
        }

        let request_builder = self.client.get(url);
        let response = request_builder.send().await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let issuer_chain = self.get_required_header(
            &response,
            "SGX-PCK-CRL-Issuer-Chain",       // v4 name
            Some("SGX-PCK-CRL-Issuer-Chain"), // v3 name
        )?;

        // Response body is PEM or DER CRL
        let crl_data = response.bytes().await?.to_vec();

        Ok(PckCrlResponse {
            crl_data,
            issuer_chain,
        })
    }

    // --- TCB Info ---

    /// GET /sgx/certification/{v3,v4}/tcb
    /// Retrieves SGX TCB information for a given FMSPC.
    ///
    /// Returns TCB Info JSON string (Appendix A) and Issuer Chain header.
    /// This function supports both API v3 and v4. The `update` and `tcbEvaluationDataNumber`
    /// parameters are only supported by API v4. If both are provided at the same time (for v4),
    /// a conflict error is returned.
    ///
    /// # Arguments
    ///
    /// * `fmspc` - Hex-encoded FMSPC value.
    /// * `update` - Optional [`UpdateType`] for API v4.
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// A [`TcbInfoResponse`] containing the TCB info JSON and the issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the API request fails, if conflicting parameters are used,
    /// or if the requested TCB data is not found.
    pub async fn get_sgx_tcb_info(
        &self,
        fmspc: &str,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<TcbInfoResponse, IntelApiError> {
        // V3 does not support 'update' or 'tcbEvaluationDataNumber'
        if self.api_version == ApiVersion::V3 && update.is_some() {
            return Err(IntelApiError::UnsupportedApiVersion(
                "'update' parameter requires API v4".to_string(),
            ));
        }
        if self.api_version == ApiVersion::V3 && tcb_evaluation_data_number.is_some() {
            return Err(IntelApiError::UnsupportedApiVersion(
                "'tcbEvaluationDataNumber' parameter requires API v4".to_string(),
            ));
        }
        if self.api_version == ApiVersion::V4
            && update.is_some()
            && tcb_evaluation_data_number.is_some()
        {
            return Err(IntelApiError::ConflictingParameters(
                "'update' and 'tcbEvaluationDataNumber'",
            ));
        }

        let path = self.build_api_path("sgx", "", "tcb")?;
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut().append_pair("fmspc", fmspc);

        // Add V4-specific parameters
        if self.api_version == ApiVersion::V4 {
            if let Some(upd) = update {
                url.query_pairs_mut()
                    .append_pair("update", &upd.to_string());
            }
            if let Some(tedn) = tcb_evaluation_data_number {
                url.query_pairs_mut()
                    .append_pair("tcbEvaluationDataNumber", &tedn.to_string());
            }
        }

        let request_builder = self.client.get(url);

        // Special handling for 404/410 when tcbEvaluationDataNumber is specified (V4 only)
        if self.api_version == ApiVersion::V4 {
            if let Some(tedn_val) = tcb_evaluation_data_number {
                // Use the helper function to check status before proceeding
                self.check_tcb_evaluation_status(&request_builder, tedn_val, "SGX TCB Info")
                    .await?;
                // If the check passes (doesn't return Err), continue to fetch_json_with_issuer_chain
            }
        }

        // Fetch JSON and header (header name seems same for v3/v4)
        let (tcb_info_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(
                request_builder,
                "TCB-Info-Issuer-Chain",           // v4 name
                Some("SGX-TCB-Info-Issuer-Chain"), // v3 name
            )
            .await?;

        Ok(TcbInfoResponse {
            tcb_info_json,
            issuer_chain,
        })
    }

    /// GET /tdx/certification/v4/tcb
    /// Retrieves TDX TCB information for a given FMSPC (API v4 only).
    ///
    /// # Arguments
    ///
    /// * `fmspc` - Hex-encoded FMSPC value.
    /// * `update` - An optional [`UpdateType`] (v4 only).
    /// * `tcb_evaluation_data_number` - An optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// A [`TcbInfoResponse`] containing TDX TCB info JSON and the issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used,
    /// if there are conflicting parameters, or if the TDX TCB data is not found.
    /// Returns TCB Info JSON string (Appendix A) and Issuer Chain header.
    pub async fn get_tdx_tcb_info(
        &self,
        fmspc: &str,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<TcbInfoResponse, IntelApiError> {
        // Ensure V4 API
        self.ensure_v4_api("get_tdx_tcb_info")?;
        // Check conflicting parameters (only relevant for V4, checked inside helper)
        self.check_conflicting_update_params(update, tcb_evaluation_data_number)?;

        let path = self.build_api_path("tdx", "", "tcb")?;
        let mut url = self.base_url.join(&path)?;
        url.query_pairs_mut().append_pair("fmspc", fmspc);

        if let Some(upd) = update {
            url.query_pairs_mut()
                .append_pair("update", &upd.to_string());
        }
        if let Some(tedn) = tcb_evaluation_data_number {
            url.query_pairs_mut()
                .append_pair("tcbEvaluationDataNumber", &tedn.to_string());
        }

        let request_builder = self.client.get(url);

        // Special handling for 404/410 when tcbEvaluationDataNumber is specified
        if let Some(tedn_val) = tcb_evaluation_data_number {
            // Use the helper function to check status before proceeding
            self.check_tcb_evaluation_status(&request_builder, tedn_val, "TDX TCB Info")
                .await?;
            // If the check passes (doesn't return Err), continue to fetch_json_with_issuer_chain
        }

        // Fetch JSON and header (TDX only exists in V4)
        let (tcb_info_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(request_builder, "TCB-Info-Issuer-Chain", None)
            .await?;

        Ok(TcbInfoResponse {
            tcb_info_json,
            issuer_chain,
        })
    }

    // --- Enclave Identity ---

    /// Retrieves the SGX QE Identity from the Intel API.
    ///
    /// Returns Enclave Identity JSON string (Appendix B) and Issuer Chain header.
    /// Supports both v3 and v4. The `update` and `tcb_evaluation_data_number`
    /// parameters are only valid in API v4. Returns the enclave identity JSON
    /// and an issuer chain header.
    ///
    /// # Arguments
    ///
    /// * `update` - Optional [`UpdateType`] (v4 only).
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// An [`EnclaveIdentityResponse`] containing the JSON identity and issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails, if conflicting v4 parameters are used,
    /// or if the desired identity resource is not found.
    pub async fn get_sgx_qe_identity(
        &self,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<EnclaveIdentityResponse, IntelApiError> {
        self.get_sgx_enclave_identity("qe", update, tcb_evaluation_data_number)
            .await
    }

    /// Retrieves the TDX QE Identity from the Intel API (API v4 only).
    ///
    /// # Arguments
    ///
    /// * `update` - Optional [`UpdateType`] (v4 only).
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// An [`EnclaveIdentityResponse`] containing the JSON identity and issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used,
    /// if conflicting parameters are provided, or if the identity resource is not found.
    /// GET /tdx/certification/v4/qe/identity - V4 ONLY
    pub async fn get_tdx_qe_identity(
        &self,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<EnclaveIdentityResponse, IntelApiError> {
        // Ensure V4 API
        self.ensure_v4_api("get_tdx_qe_identity")?;
        // Check conflicting parameters (only relevant for V4, checked inside helper)
        self.check_conflicting_update_params(update, tcb_evaluation_data_number)?;

        let path = self.build_api_path("tdx", "qe", "identity")?;
        let mut url = self.base_url.join(&path)?;

        if let Some(upd) = update {
            url.query_pairs_mut()
                .append_pair("update", &upd.to_string());
        }
        if let Some(tedn) = tcb_evaluation_data_number {
            url.query_pairs_mut()
                .append_pair("tcbEvaluationDataNumber", &tedn.to_string());
        }

        let request_builder = self.client.get(url);

        // Special handling for 404/410 when tcbEvaluationDataNumber is specified
        if let Some(tedn_val) = tcb_evaluation_data_number {
            // Use the helper function to check status before proceeding
            self.check_tcb_evaluation_status(&request_builder, tedn_val, "TDX QE Identity")
                .await?;
            // If the check passes (doesn't return Err), continue to fetch_json_with_issuer_chain
        }

        // Fetch JSON and header (TDX only exists in V4)
        let (enclave_identity_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(
                request_builder,
                "SGX-Enclave-Identity-Issuer-Chain",
                None,
            )
            .await?;

        Ok(EnclaveIdentityResponse {
            enclave_identity_json,
            issuer_chain,
        })
    }

    /// Retrieves the SGX QVE Identity from the Intel API.
    ///
    /// Supports API v3 and v4. The `update` and `tcb_evaluation_data_number` parameters
    /// are v4 only. Returns the QVE identity JSON and issuer chain.
    ///
    /// # Arguments
    ///
    /// * `update` - Optional [`UpdateType`] (v4 only).
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// An [`EnclaveIdentityResponse`] containing the QVE identity JSON and issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails, if conflicting parameters are used,
    /// or if the identity resource is not found.
    /// GET /sgx/certification/{v3,v4}/qve/identity
    pub async fn get_sgx_qve_identity(
        &self,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<EnclaveIdentityResponse, IntelApiError> {
        self.get_sgx_enclave_identity("qve", update, tcb_evaluation_data_number)
            .await
    }

    /// Retrieves the SGX QAE Identity from the Intel API (API v4 only).
    ///
    /// # Arguments
    ///
    /// * `update` - Optional [`UpdateType`] (v4 only).
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number (v4 only).
    ///
    /// # Returns
    ///
    /// An [`EnclaveIdentityResponse`] containing the QAE identity JSON and issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used,
    /// if conflicting parameters are provided, or if the QAE identity is not found.
    /// GET /sgx/certification/v4/qae/identity - V4 ONLY
    pub async fn get_sgx_qae_identity(
        &self,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<EnclaveIdentityResponse, IntelApiError> {
        // QAE endpoint requires V4
        if self.api_version != ApiVersion::V4 {
            return Err(IntelApiError::UnsupportedApiVersion(
                "QAE Identity endpoint requires API v4".to_string(),
            ));
        }
        // Call the generic helper, it will handle V4 params and 404/410 checks
        self.get_sgx_enclave_identity("qae", update, tcb_evaluation_data_number)
            .await
    }

    // --- FMSPCs & TCB Evaluation Data Numbers ---

    /// GET /sgx/certification/{v3,v4}/fmspcs
    /// Retrieves a list of FMSPC values for SGX and TDX platforms (API v4 only).
    ///
    /// # Arguments
    ///
    /// * `platform_filter` - An optional filter specifying SGX or TDX platforms.
    ///
    /// # Returns
    ///
    /// Optional 'platform' filter.
    /// A `String` containing the JSON array of objects, each containing `fmspc` and `platform`.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used or if the request fails.
    pub async fn get_fmspcs(
        &self,
        platform_filter: Option<PlatformFilter>,
    ) -> Result<FmspcJsonResponse, IntelApiError> {
        if self.api_version == ApiVersion::V3 {
            return Err(IntelApiError::UnsupportedApiVersion(
                "API v4 only function".to_string(),
            ));
        }
        let path = self.build_api_path("sgx", "", "fmspcs")?;
        let mut url = self.base_url.join(&path)?;

        if let Some(pf) = platform_filter {
            url.query_pairs_mut()
                .append_pair("platform", &pf.to_string());
        }

        let request_builder = self.client.get(url);
        let response = request_builder.send().await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let fmspcs_json = response.text().await?;

        Ok(fmspcs_json)
    }

    /// GET /sgx/certification/v4/tcbevaluationdatanumbers - V4 ONLY
    /// Retrieves the currently supported SGX TCB Evaluation Data Numbers (API v4 only).
    ///
    /// # Returns
    ///
    /// A [`TcbEvaluationDataNumbersResponse`] containing the JSON structure of TCB Evaluation
    /// Data Numbers and an issuer chain header.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used or if the request fails.
    pub async fn get_sgx_tcb_evaluation_data_numbers(
        &self,
    ) -> Result<TcbEvaluationDataNumbersResponse, IntelApiError> {
        // Endpoint requires V4
        if self.api_version != ApiVersion::V4 {
            return Err(IntelApiError::UnsupportedApiVersion(
                "SGX TCB Evaluation Data Numbers endpoint requires API v4".to_string(),
            ));
        }

        let path = self.build_api_path("sgx", "", "tcbevaluationdatanumbers")?;
        let url = self.base_url.join(&path)?;
        let request_builder = self.client.get(url);

        let (tcb_evaluation_data_numbers_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(
                request_builder,
                "TCB-Evaluation-Data-Numbers-Issuer-Chain",
                None,
            )
            .await?;

        Ok(TcbEvaluationDataNumbersResponse {
            tcb_evaluation_data_numbers_json,
            issuer_chain,
        })
    }

    /// GET /tdx/certification/v4/tcbevaluationdatanumbers - V4 ONLY
    /// Retrieves the currently supported TDX TCB Evaluation Data Numbers (API v4 only).
    ///
    /// # Returns
    ///
    /// A [`TcbEvaluationDataNumbersResponse`] containing the JSON structure of TCB Evaluation
    /// Data Numbers and an issuer chain header.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if an unsupported API version is used or if the request fails.
    pub async fn get_tdx_tcb_evaluation_data_numbers(
        &self,
    ) -> Result<TcbEvaluationDataNumbersResponse, IntelApiError> {
        // Endpoint requires V4
        if self.api_version != ApiVersion::V4 {
            return Err(IntelApiError::UnsupportedApiVersion(
                "TDX TCB Evaluation Data Numbers endpoint requires API v4".to_string(),
            ));
        }

        let path = self.build_api_path("tdx", "", "tcbevaluationdatanumbers")?;
        let url = self.base_url.join(&path)?;
        let request_builder = self.client.get(url);

        let (tcb_evaluation_data_numbers_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(
                request_builder,
                "TCB-Evaluation-Data-Numbers-Issuer-Chain",
                None,
            )
            .await?;

        Ok(TcbEvaluationDataNumbersResponse {
            tcb_evaluation_data_numbers_json,
            issuer_chain,
        })
    }

    // ------------------------
    // Internal helper methods
    // ------------------------

    /// Helper to construct API paths dynamically based on version and technology (SGX/TDX).
    fn build_api_path(
        &self,
        technology: &str,
        service: &str,
        endpoint: &str,
    ) -> Result<String, IntelApiError> {
        let api_segment = self.api_version.path_segment();

        if technology == "tdx" && self.api_version == ApiVersion::V3 {
            return Err(IntelApiError::UnsupportedApiVersion(format!(
                "TDX endpoint /{}/{}/{} requires API v4",
                service, endpoint, technology
            )));
        }
        if technology == "sgx" && service == "registration" {
            return Ok(format!("/sgx/registration/v1/{}", endpoint).replace("//", "/"));
        }

        Ok(format!(
            "/{}/certification/{}/{}/{}",
            technology, api_segment, service, endpoint
        )
        .replace("//", "/"))
    }

    /// Helper to add an optional header if the string is non-empty.
    fn maybe_add_header(
        builder: RequestBuilder,
        header_name: &'static str,
        header_value: Option<&str>,
    ) -> RequestBuilder {
        match header_value {
            Some(value) if !value.is_empty() => builder.header(header_name, value),
            _ => builder,
        }
    }

    /// Helper to extract a required header string value, handling potential v3/v4 differences.
    fn get_required_header(
        &self,
        response: &Response,
        v4_header_name: &'static str,
        v3_header_name: Option<&'static str>,
    ) -> Result<String, IntelApiError> {
        let header_name = match self.api_version {
            ApiVersion::V4 => v4_header_name,
            ApiVersion::V3 => v3_header_name.unwrap_or(v4_header_name),
        };
        let value = response
            .headers()
            .get(header_name)
            .ok_or(IntelApiError::MissingOrInvalidHeader(header_name))?
            .to_str()
            .map_err(|e| IntelApiError::HeaderValueParse(header_name, e.to_string()))?;

        if value.contains('%') {
            percent_decode_str(value)
                .decode_utf8()
                .map_err(|e| IntelApiError::HeaderValueParse(header_name, e.to_string()))
                .map(|s| s.to_string())
        } else {
            Ok(value.to_string())
        }
    }

    /// Helper to execute a request that returns a single PCK certificate and associated headers.
    async fn fetch_pck_certificate(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<PckCertificateResponse, IntelApiError> {
        let response = request_builder.send().await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let issuer_chain = self.get_required_header(
            &response,
            "SGX-PCK-Certificate-Issuer-Chain",
            Some("SGX-PCK-Certificate-Issuer-Chain"),
        )?;
        let tcbm = self.get_required_header(&response, "SGX-TCBm", Some("SGX-TCBm"))?;
        let fmspc = self.get_required_header(&response, "SGX-FMSPC", Some("SGX-FMSPC"))?;
        let pck_cert_pem = response.text().await?;

        Ok(PckCertificateResponse {
            pck_cert_pem,
            issuer_chain,
            tcbm,
            fmspc,
        })
    }

    /// Helper to execute a request that returns a PCK certificates JSON array and associated headers.
    async fn fetch_pck_certificates(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<PckCertificatesResponse, IntelApiError> {
        let response = request_builder.send().await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let issuer_chain = self.get_required_header(
            &response,
            "SGX-PCK-Certificate-Issuer-Chain",
            Some("SGX-PCK-Certificate-Issuer-Chain"),
        )?;
        let fmspc = self.get_required_header(&response, "SGX-FMSPC", Some("SGX-FMSPC"))?;
        let pck_certs_json = response.text().await?;

        Ok(PckCertificatesResponse {
            pck_certs_json,
            issuer_chain,
            fmspc,
        })
    }

    /// Helper to execute a request expected to return JSON plus an Issuer-Chain header.
    async fn fetch_json_with_issuer_chain(
        &self,
        request_builder: RequestBuilder,
        v4_issuer_chain_header: &'static str,
        v3_issuer_chain_header: Option<&'static str>,
    ) -> Result<(String, String), IntelApiError> {
        let response = request_builder.send().await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let issuer_chain =
            self.get_required_header(&response, v4_issuer_chain_header, v3_issuer_chain_header)?;
        let json_body = response.text().await?;

        Ok((json_body, issuer_chain))
    }

    /// Checks for HTTP 404 or 410 status when querying TCB Evaluation Data Number based resources.
    async fn check_tcb_evaluation_status(
        &self,
        request_builder: &RequestBuilder,
        tcb_evaluation_data_number_val: u64,
        resource_description: &str,
    ) -> Result<(), IntelApiError> {
        let builder_clone = request_builder.try_clone().ok_or_else(|| {
            IntelApiError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to clone request builder for status check",
            ))
        })?;

        let response = builder_clone.send().await?;
        let status = response.status();

        if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            let (request_id, _, _) = extract_api_error_details(&response);
            return Err(IntelApiError::ApiError {
                status,
                request_id,
                error_code: None,
                error_message: Some(format!(
                    "{} for TCB Evaluation Data Number {} {}",
                    resource_description,
                    tcb_evaluation_data_number_val,
                    if status == StatusCode::NOT_FOUND {
                        "not found"
                    } else {
                        "is no longer available"
                    }
                )),
            });
        }
        Ok(())
    }

    /// Ensures the client is configured for API v4, otherwise returns an error.
    fn ensure_v4_api(&self, function_name: &str) -> Result<(), IntelApiError> {
        if self.api_version != ApiVersion::V4 {
            Err(IntelApiError::UnsupportedApiVersion(format!(
                "{} requires API v4",
                function_name
            )))
        } else {
            Ok(())
        }
    }

    /// Checks if a V4-only parameter is provided with a V3 API version.
    fn check_v4_only_param<T>(
        &self,
        param_value: Option<T>,
        param_name: &str,
    ) -> Result<(), IntelApiError> {
        if self.api_version == ApiVersion::V3 && param_value.is_some() {
            Err(IntelApiError::UnsupportedApiVersion(format!(
                "'{}' parameter requires API v4",
                param_name
            )))
        } else {
            Ok(())
        }
    }

    /// Checks for conflicting `update` and `tcb_evaluation_data_number` parameters when using V4.
    fn check_conflicting_update_params(
        &self,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<(), IntelApiError> {
        if self.api_version == ApiVersion::V4
            && update.is_some()
            && tcb_evaluation_data_number.is_some()
        {
            Err(IntelApiError::ConflictingParameters(
                "'update' and 'tcbEvaluationDataNumber'",
            ))
        } else {
            Ok(())
        }
    }

    /// Retrieves generic SGX enclave identity (QE, QVE, QAE) data.
    ///
    /// # Arguments
    ///
    /// * `identity_path_segment` - String slice representing the identity path segment (e.g., "qe", "qve", "qae").
    /// * `update` - Optional [`UpdateType`] for API v4.
    /// * `tcb_evaluation_data_number` - Optional TCB Evaluation Data Number for API v4.
    ///
    /// # Returns
    ///
    /// An [`EnclaveIdentityResponse`] containing the JSON identity data and issuer chain.
    ///
    /// # Errors
    ///
    /// Returns an `IntelApiError` if the request fails or the specified resource
    /// is unavailable.
    async fn get_sgx_enclave_identity(
        &self,
        identity_path_segment: &str,
        update: Option<UpdateType>,
        tcb_evaluation_data_number: Option<u64>,
    ) -> Result<EnclaveIdentityResponse, IntelApiError> {
        self.check_v4_only_param(update, "update")?;
        self.check_v4_only_param(tcb_evaluation_data_number, "tcbEvaluationDataNumber")?;
        self.check_conflicting_update_params(update, tcb_evaluation_data_number)?;

        let path = self.build_api_path("sgx", identity_path_segment, "identity")?;
        let mut url = self.base_url.join(&path)?;

        if self.api_version == ApiVersion::V4 {
            if let Some(upd) = update {
                url.query_pairs_mut()
                    .append_pair("update", &upd.to_string());
            }
            if let Some(tedn) = tcb_evaluation_data_number {
                url.query_pairs_mut()
                    .append_pair("tcbEvaluationDataNumber", &tedn.to_string());
            }
        }

        let request_builder = self.client.get(url);

        if self.api_version == ApiVersion::V4 {
            if let Some(tedn_val) = tcb_evaluation_data_number {
                let description = format!("SGX {} Identity", identity_path_segment.to_uppercase());
                self.check_tcb_evaluation_status(&request_builder, tedn_val, &description)
                    .await?;
            }
        }

        let (enclave_identity_json, issuer_chain) = self
            .fetch_json_with_issuer_chain(
                request_builder,
                "SGX-Enclave-Identity-Issuer-Chain",
                Some("SGX-Enclave-Identity-Issuer-Chain"),
            )
            .await?;

        Ok(EnclaveIdentityResponse {
            enclave_identity_json,
            issuer_chain,
        })
    }
}

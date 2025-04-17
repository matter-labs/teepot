// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

//! Internal helper methods

use super::ApiClient; // Import from parent module
use crate::{
    error::{check_status, extract_api_error_details, IntelApiError},
    responses::{PckCertificateResponse, PckCertificatesResponse},
    types::{ApiVersion, UpdateType},
};
use percent_encoding::percent_decode_str;
use reqwest::{RequestBuilder, Response, StatusCode};
use std::io;

impl ApiClient {
    /// Helper to construct API paths dynamically based on version and technology (SGX/TDX).
    pub(super) fn build_api_path(
        &self,
        technology: &str,
        service: &str,
        endpoint: &str,
    ) -> Result<String, IntelApiError> {
        let api_segment = self.api_version.path_segment();

        if technology == "tdx" && self.api_version == ApiVersion::V3 {
            return Err(IntelApiError::UnsupportedApiVersion(format!(
                "TDX endpoint /{service}/{endpoint}/{technology} requires API v4",
            )));
        }
        if technology == "sgx" && service == "registration" {
            // Registration paths are fixed at v1 regardless of client's api_version
            return Ok(format!("/sgx/registration/v1/{endpoint}").replace("//", "/"));
        }

        Ok(
            format!("/{technology}/certification/{api_segment}/{service}/{endpoint}")
                .replace("//", "/"),
        )
    }

    /// Helper to add an optional header if the string is non-empty.
    pub(super) fn maybe_add_header(
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
    pub(super) fn get_required_header(
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
    pub(super) async fn fetch_pck_certificate(
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
    pub(super) async fn fetch_pck_certificates(
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
    pub(super) async fn fetch_json_with_issuer_chain(
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
    pub(super) async fn check_tcb_evaluation_status(
        &self,
        request_builder: &RequestBuilder,
        tcb_evaluation_data_number_val: u64,
        resource_description: &str,
    ) -> Result<(), IntelApiError> {
        let builder_clone = request_builder.try_clone().ok_or_else(|| {
            IntelApiError::Io(io::Error::new(
                io::ErrorKind::Other,
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
    pub(super) fn ensure_v4_api(&self, function_name: &str) -> Result<(), IntelApiError> {
        if self.api_version != ApiVersion::V4 {
            return Err(IntelApiError::UnsupportedApiVersion(format!(
                "{function_name} requires API v4",
            )));
        }
        Ok(())
    }

    /// Checks if a V4-only parameter is provided with a V3 API version.
    pub(super) fn check_v4_only_param<T>(
        &self,
        param_value: Option<T>,
        param_name: &str,
    ) -> Result<(), IntelApiError> {
        if self.api_version == ApiVersion::V3 && param_value.is_some() {
            Err(IntelApiError::UnsupportedApiVersion(format!(
                "'{param_name}' parameter requires API v4",
            )))
        } else {
            Ok(())
        }
    }

    /// Checks for conflicting `update` and `tcb_evaluation_data_number` parameters when using V4.
    pub(super) fn check_conflicting_update_params(
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
}

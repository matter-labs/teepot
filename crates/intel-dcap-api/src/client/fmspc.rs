// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use super::ApiClient; // Import from parent module
use crate::{
    error::{check_status, IntelApiError},
    responses::TcbEvaluationDataNumbersResponse,
    types::{ApiVersion, PlatformFilter},
    FmspcJsonResponse,
};
use reqwest::StatusCode;

impl ApiClient {
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
}

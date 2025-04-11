// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use super::ApiClient; // Import from parent module
use crate::{
    error::IntelApiError,
    responses::TcbInfoResponse,
    types::{ApiVersion, UpdateType},
};

impl ApiClient {
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
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use super::ApiClient; // Import from parent module
use crate::{
    error::IntelApiError,
    responses::EnclaveIdentityResponse,
    types::{ApiVersion, UpdateType},
};

impl ApiClient {
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
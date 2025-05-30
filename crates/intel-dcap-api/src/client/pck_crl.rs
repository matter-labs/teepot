// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

//! PCK Certificate Revocation List

use super::ApiClient; // Import from parent module
use crate::{
    error::{check_status, IntelApiError},
    responses::PckCrlResponse,
    types::{CaType, CrlEncoding},
};
use reqwest::StatusCode;

impl ApiClient {
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
        let response = self.execute_with_retry(request_builder).await?;
        let response = check_status(response, &[StatusCode::OK]).await?;

        let issuer_chain = self.get_required_header(
            &response,
            "SGX-PCK-CRL-Issuer-Chain",
            Some("SGX-PCK-CRL-Issuer-Chain"),
        )?;

        // Response body is PEM or DER CRL
        let crl_data = response.bytes().await?.to_vec();

        Ok(PckCrlResponse {
            crl_data,
            issuer_chain,
        })
    }
}

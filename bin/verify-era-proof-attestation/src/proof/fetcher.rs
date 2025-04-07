// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use crate::{
    client::{HttpClient, RetryConfig, RetryHelper},
    error::{Error, Result},
    proof::{
        parsing::ProofResponseParser,
        types::{GetProofsRequest, GetProofsResponse, Proof},
    },
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;
use zksync_basic_types::{tee_types::TeeType, L1BatchNumber};

/// Handles fetching proofs from the server with retry logic
pub struct ProofFetcher {
    http_client: HttpClient,
    rpc_url: Url,
    retry_config: RetryConfig,
}

impl ProofFetcher {
    /// Create a new proof fetcher
    pub fn new(http_client: HttpClient, rpc_url: Url, retry_config: RetryConfig) -> Self {
        Self {
            http_client,
            rpc_url,
            retry_config,
        }
    }

    /// Get proofs for a batch number with retry logic
    pub async fn get_proofs(
        &self,
        token: &CancellationToken,
        batch_number: L1BatchNumber,
        tee_type: &TeeType,
    ) -> Result<Vec<Proof>> {
        let mut proofs_request = GetProofsRequest::new(batch_number, tee_type);
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(128);
        let retry_backoff_multiplier: f32 = 2.0;

        while !token.is_cancelled() {
            match self.send_request(&proofs_request, token).await {
                Ok(response) => {
                    // Parse the response using the ProofResponseParser
                    match ProofResponseParser::parse_response(response) {
                        Ok(proofs) => {
                            // Filter valid proofs
                            let valid_proofs = ProofResponseParser::filter_valid_proofs(&proofs);

                            if !valid_proofs.is_empty() {
                                return Ok(valid_proofs);
                            }

                            // No valid proofs found, retry
                            let error_msg = format!(
                                "No valid TEE proofs found for batch #{}. They may not be ready yet. Retrying in {} milliseconds.",
                                batch_number.0,
                                backoff.as_millis()
                            );
                            tracing::warn!(batch_no = batch_number.0, "{}", error_msg);
                            // Here we could use the ProofFetching error if we needed to return immediately
                            // return Err(Error::ProofFetching(error_msg));
                        }
                        Err(e) => {
                            // Handle specific error for Sgx variant
                            if let Error::JsonRpc(msg) = &e {
                                if msg.contains("RPC requires 'Sgx' variant") {
                                    tracing::debug!("Switching to 'Sgx' variant for RPC");
                                    proofs_request.params.1 = "Sgx".to_string();
                                    continue;
                                }
                            }
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }

            tokio::time::timeout(backoff, token.cancelled()).await.ok();

            backoff = std::cmp::min(
                Duration::from_millis(
                    (backoff.as_millis() as f32 * retry_backoff_multiplier) as u64,
                ),
                max_backoff,
            );

            if token.is_cancelled() {
                break;
            }
        }

        // If we've reached this point, we've either been stopped or exhausted retries
        if token.is_cancelled() {
            // Return empty vector if stopped
            Ok(vec![])
        } else {
            // Use the ProofFetching error variant if we've exhausted retries
            Err(Error::proof_fetch(batch_number, "exhausted retries"))
        }
    }

    /// Send a request to the server with retry logic
    async fn send_request(
        &self,
        request: &GetProofsRequest,
        token: &CancellationToken,
    ) -> Result<GetProofsResponse> {
        let retry_helper = RetryHelper::new(self.retry_config.clone());
        let request_clone = request.clone();
        let http_client = self.http_client.clone();
        let rpc_url = self.rpc_url.clone();

        retry_helper
            .execute(&format!("get_proofs_{}", request.params.0), || async {
                let result = http_client
                    .send_json::<_, GetProofsResponse>(&rpc_url, &request_clone)
                    .await;

                // Check if we need to abort due to stop signal
                if token.is_cancelled() {
                    return Err(Error::Interrupted);
                }

                result
            })
            .await
    }
}

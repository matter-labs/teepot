// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use anyhow::{bail, Result};
use jsonrpsee_types::error::ErrorObject;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, warn};
use url::Url;
use zksync_basic_types::L1BatchNumber;

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProofsRequest {
    pub jsonrpc: String,
    pub id: u32,
    pub method: String,
    pub params: (L1BatchNumber, String),
}

pub async fn get_proofs(
    stop_receiver: &mut watch::Receiver<bool>,
    batch_number: L1BatchNumber,
    http_client: &Client,
    rpc_url: &Url,
) -> Result<Vec<Proof>> {
    let mut proofs_request = GetProofsRequest::new(batch_number);
    let mut retries = 0;
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(128);
    let retry_backoff_multiplier: f32 = 2.0;

    while !*stop_receiver.borrow() {
        let proofs = proofs_request
            .send(stop_receiver, http_client, rpc_url)
            .await?;

        if !proofs.is_empty()
            && proofs.iter().all(|proof| {
                !proof.status.eq_ignore_ascii_case("failed")
                    && !proof.status.eq_ignore_ascii_case("picked_by_prover")
            })
        {
            return Ok(proofs);
        }

        retries += 1;
        warn!(
            batch_no = batch_number.0, retries,
            "No TEE proofs found for batch #{}. They may not be ready yet. Retrying in {} milliseconds.",
            batch_number, backoff.as_millis(),
        );

        tokio::time::timeout(backoff, stop_receiver.changed())
            .await
            .ok();

        backoff = std::cmp::min(backoff.mul_f32(retry_backoff_multiplier), max_backoff);
    }

    Ok(vec![])
}

impl GetProofsRequest {
    pub fn new(batch_number: L1BatchNumber) -> Self {
        GetProofsRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "unstable_getTeeProofs".to_string(),
            params: (batch_number, "sgx".to_string()),
        }
    }

    pub async fn send(
        &mut self,
        stop_receiver: &mut watch::Receiver<bool>,
        http_client: &Client,
        rpc_url: &Url,
    ) -> Result<Vec<Proof>> {
        let mut retries = 0;
        let max_retries = 5;
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(128);
        let retry_backoff_multiplier: f32 = 2.0;
        let mut response = None;

        while !*stop_receiver.borrow() {
            let result = http_client
                .post(rpc_url.clone())
                .json(self)
                .send()
                .await?
                .error_for_status()?
                .json::<GetProofsResponse>()
                .await;

            match result {
                Ok(res) => match res.error {
                    None => {
                        response = Some(res);
                        break;
                    }
                    Some(error) => {
                        // Handle corner case, where the old RPC interface expects 'Sgx'
                        if let Some(data) = error.data() {
                            if data.get().contains("unknown variant `sgx`, expected `Sgx`") {
                                self.params.1 = "Sgx".to_string();
                                continue;
                            }
                        }
                        error!(?error, "received JSONRPC error {error:?}");
                        bail!("JSONRPC error {error:?}");
                    }
                },
                Err(err) => {
                    retries += 1;
                    if retries >= max_retries {
                        return Err(anyhow::anyhow!(
                            "Failed to send request to {} after {} retries: {}. Request details: {:?}",
                            rpc_url,
                            max_retries,
                            err,
                            self
                        ));
                    }
                    warn!(
                        %err,
                        "Failed to send request to {rpc_url}. {retries}/{max_retries}, retrying in {} milliseconds. Request details: {:?}",
                        backoff.as_millis(),
                        self
                    );
                    tokio::time::timeout(backoff, stop_receiver.changed())
                        .await
                        .ok();
                    backoff = std::cmp::min(backoff.mul_f32(retry_backoff_multiplier), max_backoff);
                }
            };
        }

        Ok(response.map_or_else(Vec::new, |res| res.result.unwrap_or_default()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProofsResponse {
    pub jsonrpc: String,
    pub result: Option<Vec<Proof>>,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject<'static>>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub l1_batch_number: u32,
    pub tee_type: String,
    #[serde_as(as = "Option<Hex>")]
    pub pubkey: Option<Vec<u8>>,
    #[serde_as(as = "Option<Hex>")]
    pub signature: Option<Vec<u8>>,
    #[serde_as(as = "Option<Hex>")]
    pub proof: Option<Vec<u8>>,
    pub proved_at: String,
    pub status: String,
    #[serde_as(as = "Option<Hex>")]
    pub attestation: Option<Vec<u8>>,
}

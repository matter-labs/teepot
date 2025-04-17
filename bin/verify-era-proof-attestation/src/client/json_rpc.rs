// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_types::L2ChainId;
use zksync_web3_decl::{
    client::{Client as NodeClient, L2},
    error::ClientRpcContext,
    namespaces::ZksNamespaceClient,
};

use crate::error;

/// Trait for interacting with the JSON-RPC API
pub trait JsonRpcClient {
    /// Get the root hash for a specific batch
    async fn get_root_hash(&self, batch_number: L1BatchNumber) -> error::Result<H256>;
    // TODO implement get_tee_proofs(batch_number, tee_type) once https://crates.io/crates/zksync_web3_decl crate is updated
}

/// Client for interacting with the main node
pub struct MainNodeClient(NodeClient<L2>);

impl MainNodeClient {
    /// Create a new client for the main node
    pub fn new(rpc_url: Url, chain_id: u64) -> error::Result<Self> {
        let chain_id = L2ChainId::try_from(chain_id)
            .map_err(|e| error::Error::Internal(format!("Invalid chain ID: {e}")))?;

        let node_client = NodeClient::http(rpc_url.into())
            .map_err(|e| error::Error::Internal(format!("Failed to create JSON-RPC client: {e}")))?
            .for_network(chain_id.into())
            .build();

        Ok(MainNodeClient(node_client))
    }
}

impl JsonRpcClient for MainNodeClient {
    async fn get_root_hash(&self, batch_number: L1BatchNumber) -> error::Result<H256> {
        let batch_details = self
            .0
            .get_l1_batch_details(batch_number)
            .rpc_context("get_l1_batch_details")
            .await
            .map_err(|e| error::Error::JsonRpc(format!("Failed to get batch details: {e}")))?
            .ok_or_else(|| {
                error::Error::JsonRpc(format!("No details found for batch #{batch_number}"))
            })?;

        batch_details.base.root_hash.ok_or_else(|| {
            error::Error::JsonRpc(format!("No root hash found for batch #{batch_number}"))
        })
    }
}

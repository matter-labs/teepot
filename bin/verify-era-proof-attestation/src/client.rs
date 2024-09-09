// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use anyhow::{anyhow, Context, Result};
use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_types::L2ChainId;
use zksync_web3_decl::{
    client::{Client as NodeClient, L2},
    error::ClientRpcContext,
    namespaces::ZksNamespaceClient,
};

pub trait JsonRpcClient {
    async fn get_root_hash(&self, batch_number: L1BatchNumber) -> Result<H256>;
    // TODO implement get_tee_proofs(batch_number, tee_type) once https://crates.io/crates/zksync_web3_decl crate is updated
}

pub struct MainNodeClient(NodeClient<L2>);

impl MainNodeClient {
    pub fn new(rpc_url: Url, chain_id: u64) -> Result<Self> {
        let node_client = NodeClient::http(rpc_url.into())
            .context("failed creating JSON-RPC client for main node")?
            .for_network(
                L2ChainId::try_from(chain_id)
                    .map_err(anyhow::Error::msg)?
                    .into(),
            )
            .build();

        Ok(MainNodeClient(node_client))
    }
}

impl JsonRpcClient for MainNodeClient {
    async fn get_root_hash(&self, batch_number: L1BatchNumber) -> Result<H256> {
        self.0
            .get_l1_batch_details(batch_number)
            .rpc_context("get_l1_batch_details")
            .await?
            .and_then(|res| res.base.root_hash)
            .ok_or_else(|| anyhow!("No root hash found for batch #{}", batch_number))
    }
}

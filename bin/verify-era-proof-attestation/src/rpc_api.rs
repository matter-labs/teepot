use anyhow::{anyhow, Context, Result};
use clap::Parser;
use reqwest::Client;
use secp256k1::{constants::PUBLIC_KEY_SIZE, ecdsa::Signature, Message, PublicKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use teepot::{
    client::TcbLevel,
    sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
};
use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_types::L2ChainId;
use zksync_web3_decl::{
    client::{Client as NodeClient, L2},
    error::ClientRpcContext,
    namespaces::ZksNamespaceClient,
};

trait JsonRpcClient {
    async fn get_root_hash(&self, batch_number: L1BatchNumber) -> Result<H256>;
    // TODO implement get_tee_proofs(batch_number, tee_type) once https://crates.io/crates/zksync_web3_decl crate is updated
}

struct MainNodeClient(NodeClient<L2>);

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

// JSON-RPC request and response structures for fetching TEE proofs

#[derive(Debug, Serialize, Deserialize)]
struct GetProofsRequest {
    jsonrpc: String,
    id: u32,
    method: String,
    params: (L1BatchNumber, String),
}

#[derive(Debug, Serialize, Deserialize)]
struct GetProofsResponse {
    jsonrpc: String,
    result: Vec<Proof>,
    id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    #[serde(rename = "l1BatchNumber")]
    l1_batch_number: u32,
    #[serde(rename = "teeType")]
    tee_type: String,
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    proof: Vec<u8>,
    #[serde(rename = "provedAt")]
    proved_at: String,
    attestation: Vec<u8>,
}

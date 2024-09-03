// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

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
use tokio::time::sleep;
use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_types::L2ChainId;
use zksync_web3_decl::{
    client::{Client as NodeClient, L2},
    error::ClientRpcContext,
    namespaces::ZksNamespaceClient,
};

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// The batch number or range of batch numbers to verify the attestation and signature (e.g., "42" or "42-45").
    #[clap(short = 'n', long = "batch-number", value_parser = parse_batch_range)]
    batch_range: (L1BatchNumber, L1BatchNumber),
    /// URL of the RPC server to query for the batch attestation and signature.
    #[clap(short = 'u', long)]
    rpc_url: Url,
    /// Chain ID of the network to query.
    #[clap(short = 'c', long, default_value_t = L2ChainId::default().as_u64())]
    chain_id: u64,
    /// Rate limit between requests in milliseconds.
    #[clap(short = 'r', long, default_value_t = Duration::from_millis(0), value_parser = parse_duration)]
    rate_limit: Duration,
}

fn parse_batch_range(s: &str) -> Result<(L1BatchNumber, L1BatchNumber)> {
    let parse = |s: &str| {
        s.parse::<u32>()
            .map(L1BatchNumber::from)
            .map_err(|e| anyhow!(e))
    };
    match s.split_once('-') {
        Some((start, end)) => {
            let (start, end) = (parse(start)?, parse(end)?);
            if start > end {
                Err(anyhow!(
                    "Start batch number ({}) must be less than or equal to end batch number ({})",
                    start,
                    end
                ))
            } else {
                Ok((start, end))
            }
        }
        None => {
            let batch_number = parse(s)?;
            Ok((batch_number, batch_number))
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    let millis = s.parse()?;
    Ok(Duration::from_millis(millis))
}

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arguments::parse();
    let node_client = NodeClient::http(args.rpc_url.clone().into())
        .context("failed creating JSON-RPC client for main node")?
        .for_network(
            L2ChainId::try_from(args.chain_id)
                .map_err(anyhow::Error::msg)?
                .into(),
        )
        .build();
    let node_client = MainNodeClient(node_client);
    let http_client = Client::new();
    let (start_batch_number, end_batch_number) = args.batch_range;

    for batch_number in start_batch_number.0..=end_batch_number.0 {
        let proofs_request = GetProofsRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "unstable_getTeeProofs".to_string(),
            params: (L1BatchNumber(batch_number), "Sgx".to_string()),
        };
        let proofs_response = http_client
            .post(args.rpc_url.clone())
            .json(&proofs_request)
            .send()
            .await?
            .error_for_status()?
            .json::<GetProofsResponse>()
            .await?;

        for proof in proofs_response
            .result
            .into_iter()
            .filter(|proof| proof.tee_type.to_lowercase() == "sgx")
        {
            println!(
                "Verifying batch #{} proved at {}",
                proof.l1_batch_number, proof.proved_at
            );
            let quote_verification_result = verify_attestation_quote(&proof.attestation)?;
            print_quote_verification_summary(&quote_verification_result);
            let public_key = PublicKey::from_slice(
                &quote_verification_result.quote.report_body.reportdata[..PUBLIC_KEY_SIZE],
            )?;
            println!("Public key from attestation quote: {}", public_key);
            let root_hash = node_client
                .get_root_hash(L1BatchNumber(proof.l1_batch_number))
                .await?;
            println!("Root hash: {}", root_hash);
            verify_signature(&proof.signature, public_key, root_hash)?;
            println!();
        }

        sleep(args.rate_limit).await;
    }

    Ok(())
}

fn verify_signature(signature: &[u8], public_key: PublicKey, root_hash: H256) -> Result<()> {
    let signature = Signature::from_compact(signature)?;
    let root_hash_msg = Message::from_digest_slice(&root_hash.0)?;
    if signature.verify(&root_hash_msg, &public_key).is_ok() {
        println!("Signature verified successfully");
    } else {
        println!("Failed to verify signature");
    }
    Ok(())
}

fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    println!(
        "Verifying quote ({} bytes)...",
        attestation_quote_bytes.len()
    );
    let collateral =
        tee_qv_get_collateral(attestation_quote_bytes).context("Failed to get collateral")?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(attestation_quote_bytes, Some(&collateral), unix_time)
        .context("Failed to verify quote with collateral")
}

fn print_quote_verification_summary(quote_verification_result: &QuoteVerificationResult) {
    let QuoteVerificationResult {
        collateral_expired,
        result,
        quote,
        advisories,
        ..
    } = quote_verification_result;
    if *collateral_expired {
        println!("Freshly fetched collateral expired");
    }
    let tcblevel = TcbLevel::from(*result);
    for advisory in advisories {
        println!("\tInfo: Advisory ID: {advisory}");
    }
    println!("Quote verification result: {}", tcblevel);
    println!("mrsigner: {}", hex::encode(quote.report_body.mrsigner));
    println!("mrenclave: {}", hex::encode(quote.report_body.mrenclave));
    println!("reportdata: {}", hex::encode(quote.report_body.reportdata));
}

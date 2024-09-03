// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

mod rpc_api;
mod verifier;

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

use rpc_api::MainNodeClient;
use verifier::verify_proof;

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// The batch number or range of batch numbers to verify the attestation and signature (e.g., "42" or "42-45").
    #[clap(short = 'n', long = "batch-number", value_parser = parse_batch_range)]
    batch_range: (L1BatchNumber, L1BatchNumber),
    /// URL of the RPC server to query for the batch attestation and signature.
    #[clap(short, long)]
    rpc_url: Url,
    /// Chain ID of the network to query.
    #[clap(short, long, default_value_t = L2ChainId::default().as_u64())]
    chain_id: u64,
    /// Run continuously, polling for new batch ranges from the RPC server.
    #[clap(short, long)]
    continuous: bool,
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

    if args.continuous {
        run_continuous_mode(&http_client, &node_client, &args.rpc_url).await?;
    } else {
        run_once(&http_client, &node_client, &args.rpc_url, args.batch_range).await?;
    }

    Ok(())
}

async fn run_continuous_mode(
    http_client: &Client,
    node_client: &MainNodeClient,
    rpc_url: &Url,
) -> Result<()> {
    loop {
        let batch_range = poll_latest_batch_range(http_client, rpc_url).await?;
        run_once(http_client, node_client, batch_range, rpc_url).await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn run_once(
    http_client: &Client,
    node_client: &MainNodeClient,
    rpc_url: &Url,
    batch_range: (L1BatchNumber, L1BatchNumber),
) -> Result<()> {
    let (start_batch_number, end_batch_number) = batch_range;

    for batch_number in start_batch_number.0..=end_batch_number.0 {
        println!("Verifying batch #{}", proof.l1_batch_number);

        let proofs_response = get_tee_proofs(batch_number, http_client, rpc_url).await?;
        let mut batch_proof_instance = 1;

        for proof in proofs_response
            .result
            .into_iter()
            .filter(|proof| proof.tee_type.eq_ignore_ascii_case("Sgx"))
        {
            println!(
                "  Verifying proof instance {} of the batch, proved at {}"
                proof.l1_batch_number, proof.proved_at
            );
            let verification_result = verify_proof(proof, node_client).await?;
            batch_proof_instance += 1;
        }

        println!();
    }

    Ok(())
}

async fn get_tee_proofs(
    batch_number: u32,
    http_client: &Client,
    rpc_url: &Url,
) -> Result<Vec<Proof>> {
    let proofs_request = GetProofsRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: "unstable_getTeeProofs".to_string(),
        params: (L1BatchNumber(batch_number), "Sgx".to_string()),
    };
    let proofs_response = http_client
        .post(rpc_url.clone())
        .json(&proofs_request)
        .send()
        .await?
        .error_for_status()?
        .json::<GetProofsResponse>()
        .await;
    // TODO return 404 if no proofs found

    Ok(proofs_response)
}

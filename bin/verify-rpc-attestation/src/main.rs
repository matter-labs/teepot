// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

use anyhow::{Context, Result};
use clap::{Args, Parser};
// use secp256k1::{ecdsa::Signature, Message, PublicKey};
// use std::{fs, io::Read, path::PathBuf, str::FromStr, time::UNIX_EPOCH};
// use teepot::{
//     client::TcbLevel,
//     sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
// };
use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// The batch number for which we want to verify the attestation and signature.
    #[clap(short = 'n', long)]
    batch_number: L1BatchNumber,
    /// URL of the RPC server to query for the batch attestation and signature.
    #[clap(short, long)]
    rpc_url: Url,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetProofsRequest {
    l1_batch_number: L1BatchNumber,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetProofsResponse {
    jsonrpc: String,
    result: Vec<Proof>,
    id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    l1BatchNumber: u32,
    teeType: String,
    pubkey: Vec<u8>,
    signature: Vec<u8>,
    proof: Vec<u8>,
    provedAt: String,
    attestation: Vec<u8>,
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    println!(args.batch_number);
    let http_client = Client::new();
    let request = GetProofsRequest {
        l1_batch_number: args.batch_number,
    };
    let response = http_client
        .post(args.rpc_url)
        .json(&request)
        .send()
        .error_for_status()?
        .json::<GetProofsResponse>()
        .await;
    println!("{:?}", response);

    Ok(())
}

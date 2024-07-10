// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

use alloy_primitives::B256;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use secp256k1::{ecdsa::Signature, Message, PublicKey};
use std::fs;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use teepot::{
    client::TcbLevel,
    sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
};

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// File with attestation quote proving signature originated from a TEE enclave.
    #[clap()]
    attestation_file: PathBuf,
    /// An optional subcommand, for instance, for optional signature verification.
    #[clap(subcommand)]
    command: Option<SubCommands>,
}

#[derive(Args, Debug)]
struct SignatureArgs {
    /// File containing a batch signature signed within a TEE enclave.
    #[arg(long)]
    signature_file: PathBuf,
    /// Batch root hash for signature verification.
    #[arg(long)]
    root_hash: B256,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    /// Provide both signature_file and root_hash
    SignVerify(SignatureArgs),
}

fn main() -> Result<()> {
    let args = Arguments::parse();

    let attestation_quote_bytes = fs::read(&args.attestation_file)?;
    let quote_verification_result = verify_attestation_quote(&attestation_quote_bytes)?;
    print_quote_verification_summary(&quote_verification_result);

    match &args.command {
        Some(SubCommands::SignVerify(signature_args)) => {
            verify_signature(&quote_verification_result, signature_args)?;
        }
        None => {}
    }
    Ok(())
}

fn verify_signature(
    quote_verification_result: &QuoteVerificationResult,
    signature_args: &SignatureArgs,
) -> Result<()> {
    let reportdata = &quote_verification_result.quote.report_body.reportdata;
    let public_key = PublicKey::from_slice(reportdata)?;
    println!("Public key from attestation quote: {}", public_key);
    let signature_bytes = fs::read(&signature_args.signature_file)?;
    let signature = Signature::from_compact(&signature_bytes)?;
    let root_hash_msg = Message::from_digest_slice(&signature_args.root_hash.0)?;
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
        tee_qv_get_collateral(&attestation_quote_bytes).context("Failed to get collateral")?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(&attestation_quote_bytes, Some(&collateral), unix_time)
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

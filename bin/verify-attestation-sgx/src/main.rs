// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

use anyhow::{bail, Context, Result};
use clap::Parser;
use secp256k1::{ecdsa::Signature, Message, PublicKey};
use std::fs;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;
use teepot::client::TcbLevel;
use teepot::sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult};

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "TEE attestation verifier", long_about = None)]
struct Arguments {
    /// File containing a batch signature signed within a TEE enclave.
    #[clap(long)]
    signature_file: Option<PathBuf>,
    /// File with attestation quote proving signature originated from a TEE enclave.
    #[clap(long)]
    attestation_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    let attestation_quote_bytes = fs::read(&args.attestation_file)?;
    let quote_verification_result = verify_attestation_quote(&attestation_quote_bytes)?;
    print_quote_verification_summary(&quote_verification_result);
    if let Some(signature_file) = args.signature_file {
        let reportdata = &quote_verification_result.quote.report_body.reportdata;
        let verifying_key = PublicKey::from_slice(reportdata)?;
        // let signature_bytes = fs::read(&args.signature_file)?;
        // let signature = Signature::from_compact(&signature_bytes)?;
        let signature = fs::read(&args.signature_file)?.map(Signature::from_compact)?;
        let message = Message::from_slice(reportdata)?; // TODO
        if signature.verify(&message, &verifying_key).is_ok() {
            println!("Signature verified successfully");
        } else {
            println!("Failed to verify signature");
        }
    }
    Ok(())
}

fn verify_attestation_quote<'a>(
    attestation_quote_bytes: &'a Vec<u8>,
) -> Result<QuoteVerificationResult<'a>> {
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

fn print_quote_verification_summary<'a>(quote_verification_result: &QuoteVerificationResult<'a>) {
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

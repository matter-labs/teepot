// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Tool for SGX attestation and batch signature verification

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use core::convert::TryInto;
use hex::encode;
use secp256k1::Message;
use std::{fs, io::Read, path::PathBuf, str::FromStr, time::UNIX_EPOCH};
use teepot::{
    client::TcbLevel,
    ethereum::recover_signer,
    prover::reportdata::ReportData,
    quote::{error, tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
};
use zksync_basic_types::H256;

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// Attestation quote proving the signature originated from a TEE enclave.
    #[clap(name = "attestation_file", value_parser)]
    attestation: ArgSource,
    /// An optional subcommand, for instance, for optional signature verification.
    #[clap(subcommand)]
    command: Option<SubCommands>,
}

#[derive(Debug, Clone)]
enum ArgSource {
    File(PathBuf),
    Stdin,
}

impl FromStr for ArgSource {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "-" => Ok(ArgSource::Stdin),
            _ => Ok(ArgSource::File(PathBuf::from(s))),
        }
    }
}

#[derive(Args, Debug)]
struct SignatureArgs {
    /// File containing a batch signature signed within a TEE enclave.
    #[arg(long)]
    signature_file: PathBuf,
    /// Batch root hash for signature verification.
    #[arg(long)]
    root_hash: H256,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    /// Verify a batch signature signed within a TEE enclave.
    SignVerify(SignatureArgs),
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    let attestation_quote_bytes = match args.attestation {
        ArgSource::File(path) => fs::read(path)?,
        ArgSource::Stdin => {
            let mut quote = Vec::new();
            std::io::stdin()
                .read_to_end(&mut quote)
                .context("Failed to read attestation quote from stdin")?;
            quote
        }
    };
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
    let report_data = ReportData::try_from(quote_verification_result.quote.get_report_data())?;
    let ethereum_address_from_quote = match report_data {
        ReportData::V1(report_data_v1) => report_data_v1.ethereum_address,
        _ => return Err(anyhow!("Unsupported report data version")),
    };
    let signature_bytes: &[u8] = &fs::read(&signature_args.signature_file)?;
    let root_hash = Message::from_digest_slice(signature_args.root_hash.as_bytes())?;
    let ethereum_address_from_signature = recover_signer(&signature_bytes.try_into()?, &root_hash)?;
    let verification_successful = ethereum_address_from_signature == ethereum_address_from_quote;

    println!(
        "Signature '{}' {}. Ethereum address from attestation quote: {}. Ethereum address from signature: {}.",
        encode(signature_bytes),
        if verification_successful {
            "verified successfully"
        } else {
            "verification failed"
        },
        encode(ethereum_address_from_quote),
        encode(ethereum_address_from_signature)
    );
    Ok(())
}

fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    println!(
        "Verifying quote ({} bytes)...",
        attestation_quote_bytes.len()
    );
    let collateral = error::QuoteContext::context(
        tee_qv_get_collateral(attestation_quote_bytes),
        "Failed to get collateral",
    )?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)?
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

    println!("{:#}", &quote.report);
}

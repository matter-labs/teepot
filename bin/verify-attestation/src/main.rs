// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Tool for SGX attestation and batch signature verification

use anyhow::{bail, Context, Result};
use clap::Parser;

use std::{fs, io::Read, path::PathBuf, str::FromStr, time::UNIX_EPOCH};
use teepot::quote::{get_collateral, verify_quote_with_collateral, QuoteVerificationResult};

#[derive(Parser, Debug)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
struct Arguments {
    /// Attestation quote proving the signature originated from a TEE enclave.
    #[clap(name = "attestation_file", value_parser)]
    attestation: ArgSource,
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
    Ok(())
}

fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    if attestation_quote_bytes.is_empty() {
        bail!("Empty quote provided!");
    }
    println!(
        "Verifying quote ({} bytes)...",
        attestation_quote_bytes.len()
    );
    let collateral = get_collateral(attestation_quote_bytes)?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(attestation_quote_bytes, Some(&collateral), unix_time)
        .context("Failed to verify quote with collateral")
}

fn print_quote_verification_summary(quote_verification_result: &QuoteVerificationResult) {
    let QuoteVerificationResult {
        collateral_expired,
        result: tcblevel,
        quote,
        advisories,
        ..
    } = quote_verification_result;
    if *collateral_expired {
        println!("Freshly fetched collateral expired");
    }
    for advisory in advisories {
        println!("\tInfo: Advisory ID: {advisory}");
    }
    println!("Quote verification result: {tcblevel}");

    println!("{:#}", &quote.report);
}

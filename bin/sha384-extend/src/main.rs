// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Extend the TDX measurement

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use sha2::Digest;

/// Calculate a TDX rtmr or TPM pcr sha384 value by extending it
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// digest in hex to extend with
    #[arg(long)]
    extend: String,
    /// initial digest in hex
    #[arg(long)]
    digest: String,
}

fn main() -> Result<()> {
    let args = Arguments::parse();

    // Parse the digest string as a hex array
    let extend_bytes = hex::decode(&args.extend).context("Invalid digest format")?;
    let mut digest_bytes = hex::decode(&args.digest).context("Invalid digest format")?;

    digest_bytes.extend(extend_bytes);

    let bytes = sha2::Sha384::digest(&digest_bytes);
    let hex = hex::encode(bytes);

    println!("{hex}");
    Ok(())
}

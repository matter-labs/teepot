// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Simple TEE attestation verification test

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::time::UNIX_EPOCH;
use teepot::client::TcbLevel;
use teepot::sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult};

fn main() -> Result<()> {
    // read myquote from stdin
    let mut myquote = Vec::new();
    std::io::stdin()
        .read_to_end(&mut myquote)
        .context("Failed to read quote from stdin")?;

    let collateral = tee_qv_get_collateral(&myquote).context("Failed to get collateral")?;

    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as _;

    let QuoteVerificationResult {
        collateral_expired,
        result,

        quote,
        advisories,
        ..
    } = verify_quote_with_collateral(&myquote, Some(&collateral), unix_time.saturating_add(60))
        .context("Failed to verify quote with collateral")?;

    if collateral_expired {
        bail!("Freshly fetched collateral expired");
    }

    let tcblevel = TcbLevel::from(result);
    if tcblevel != TcbLevel::Ok {
        println!("Quote verification result: {}", tcblevel);
    }

    for advisory in advisories {
        println!("\tInfo: Advisory ID: {advisory}");
    }

    println!("Quote verified successfully: {}", tcblevel);
    println!("mrsigner: {}", hex::encode(quote.report_body.mrsigner));
    println!("mrenclave: {}", hex::encode(quote.report_body.mrenclave));
    println!("reportdata: {}", hex::encode(quote.report_body.reportdata));

    Ok(())
}

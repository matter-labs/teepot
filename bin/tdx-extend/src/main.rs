// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! Extend the TDX measurement

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use teepot::{
    log::{setup_logging, LogLevelParser},
    tdx::rtmr::TdxRtmrEvent,
    util::pad,
};
use tracing::{error, level_filters::LevelFilter};

/// Extend a TDX rtmr with a hash digest for measured boot.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// digest in hex to extend the rtmr with
    #[arg(long)]
    digest: String,
    /// the number or the rtmr
    #[arg(long, default_value = "2")]
    rtmr: u64,
    /// Log level for the log output.
    /// Valid values are: `off`, `error`, `warn`, `info`, `debug`, `trace`
    #[clap(long, default_value_t = LevelFilter::WARN, value_parser = LogLevelParser)]
    pub log_level: LevelFilter,
}

fn main_with_error() -> Result<()> {
    let args = Arguments::parse();
    tracing::subscriber::set_global_default(setup_logging(
        env!("CARGO_CRATE_NAME"),
        &args.log_level,
    )?)?;

    // Parse the digest string as a hex array
    let digest_bytes = hex::decode(&args.digest).context("Invalid digest format")?;
    let extend_data: [u8; 48] = pad(&digest_bytes).context("Invalid digest length")?;

    // Extend the TDX measurement with the extend data
    TdxRtmrEvent::default()
        .with_extend_data(extend_data)
        .with_rtmr_index(args.rtmr)
        .extend()?;

    Ok(())
}

fn main() -> Result<()> {
    let ret = main_with_error();
    if let Err(e) = &ret {
        error!(error = %e, "Execution failed");
    }
    ret
}

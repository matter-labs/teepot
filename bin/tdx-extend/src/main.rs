// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Extend the TDX measurement

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use teepot::{
    log::{setup_logging, LogLevelParser},
    pad,
    tdx::rtmr::TdxRtmrEvent,
};
use tracing::{error, level_filters::LevelFilter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// digest in hex
    #[arg(long)]
    digest: String,
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
    let extend_data: [u8; 48] = pad(&digest_bytes);

    // Extend the TDX measurement with the extend data
    TdxRtmrEvent::default()
        .with_extend_data(extend_data)
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

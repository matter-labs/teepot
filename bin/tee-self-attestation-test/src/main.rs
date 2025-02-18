// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Simple TEE self-attestation test

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use teepot::quote::attestation::get_quote_and_collateral;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let report_data = [0u8; 64];
    let report = get_quote_and_collateral(None, &report_data)
        .context("failed to get quote and collateral")?;

    let base64_string = general_purpose::STANDARD.encode(report.quote.as_ref());
    print!("{}", base64_string);

    Ok(())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Simple TEE self-attestation test

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use teepot::server::attestation::get_quote_and_collateral;
use tracing::error;
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
    if let Err(e) = get_quote_and_collateral(None, &report_data) {
        error!("failed to get quote and collateral: {e:?}");
        return Err(e);
    }
    Ok(())
}

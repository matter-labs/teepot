// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Write secrets to a Vault TEE from environment variables

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use teepot::client::vault::VaultConnection;
use teepot::server::attestation::VaultAttestationArgs;
use tracing::{debug, info, warn};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// turn on test mode
    #[arg(long, hide = true)]
    pub test: bool,
    /// vault token
    #[arg(long, env = "VAULT_TOKEN", hide = true)]
    pub vault_token: String,
    #[clap(flatten)]
    pub attestation: VaultAttestationArgs,
    /// name of this TEE to login to vault
    #[arg(long, required = true)]
    pub name: String,
    /// name of this TEE to login to vault
    #[arg(long)]
    pub store_name: Option<String>,
    /// secrets to write to vault with the value of the environment variables
    #[arg(long, required = true)]
    pub secrets: Vec<String>,
}

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Arguments::parse();

    // Split every string with a ',' into a vector of strings, flatten them and collect them.
    let secrets = args
        .secrets
        .iter()
        .flat_map(|s| s.split(','))
        .collect::<Vec<_>>();

    info!("args: {:?}", args);

    let conn = if args.test {
        warn!("TEST MODE");
        let client = awc::Client::builder()
            .add_default_header((actix_web::http::header::USER_AGENT, "teepot/1.0"))
            .finish();
        // SAFETY: TEST MODE
        unsafe {
            VaultConnection::new_from_client_without_attestation(
                args.attestation.vault_addr.clone(),
                client,
                args.name.clone(),
                args.vault_token.clone(),
            )
        }
    } else {
        VaultConnection::new(&args.attestation.clone().into(), args.name.clone())
            .await
            .expect("connecting to vault")
    };

    let tee_name = args.store_name.unwrap_or(args.name.clone());

    let env = env::vars()
        .filter(|(k, _)| secrets.contains(&k.as_str()))
        .collect::<HashMap<_, _>>();

    for (secret_name, secret_val) in env {
        debug!("storing secret {secret_name}: {secret_val}");
        let secret_val = Value::String(secret_val);
        conn.store_secret_for_tee(&tee_name, &secret_val, &secret_name)
            .await
            .expect("storing secret");
        info!("stored secret {secret_name}");
    }

    Ok(())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Get the secrets from a Vault TEE and pass them as environment variables to a command

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;
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
    /// secrets to get from vault and pass as environment variables
    #[arg(long, required = true)]
    pub secrets: Vec<String>,
    /// command to run
    pub command: Vec<String>,
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

    let mut env: HashMap<String, String> = HashMap::new();

    for secret_name in secrets {
        debug!("getting secret {secret_name}");
        let secret_val: serde_json::Value = match conn.load_secret(secret_name).await? {
            Some(val) => val,
            None => {
                debug!("secret {secret_name} not found");
                continue;
            }
        };

        debug!("got secret {secret_name}: {secret_val}");

        // Plain strings can be converted to strings.
        let env_val = match secret_val {
            Value::String(s) => s,
            _ => secret_val.to_string(),
        };

        env.insert(secret_name.to_string(), env_val);
    }

    let err = Command::new(&args.command[0])
        .args(&args.command[1..])
        .envs(env)
        .exec();

    Err(err).context("exec failed")
}

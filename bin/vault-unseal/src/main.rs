// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use teepot::client::{AttestationArgs, TeeConnection};
use teepot::json::http::{Init, InitResponse, Unseal, ATTESTATION_URL};
use tracing::{error, info, trace, warn};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// admin threshold
    #[arg(long)]
    admin_threshold: usize,
    /// PGP keys to sign commands for the admin tee
    #[arg(short, long)]
    admin_pgp_key_file: Vec<String>,
    /// admin TEE mrenclave
    #[arg(long)]
    admin_tee_mrenclave: String,
    /// secret threshold
    #[arg(long)]
    unseal_threshold: usize,
    /// PGP keys to encrypt the unseal keys with
    #[arg(short, long)]
    unseal_pgp_key_file: Vec<String>,
}

/// subcommands and their options/arguments.
#[derive(Subcommand, Debug)]
enum SubCommands {
    Init(InitArgs),
    Unseal,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    #[clap(flatten)]
    pub attestation: AttestationArgs,
    /// Subcommands (with their own options)
    #[clap(subcommand)]
    cmd: SubCommands,
}

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Arguments::parse();

    match args.cmd {
        SubCommands::Init(_) => init(args).await?,
        SubCommands::Unseal => unseal(args).await?,
    }

    Ok(())
}

async fn init(args: Arguments) -> Result<()> {
    let conn = TeeConnection::new(&args.attestation, ATTESTATION_URL).await?;

    info!("Quote verified! Connection secure!");

    let SubCommands::Init(init_args) = args.cmd else {
        unreachable!()
    };

    if init_args.admin_threshold == 0 {
        bail!("admin threshold must be greater than 0");
    }

    if init_args.unseal_threshold == 0 {
        bail!("unseal threshold must be greater than 0");
    }

    if init_args.admin_threshold > init_args.admin_pgp_key_file.len() {
        bail!("admin threshold must be less than or equal to the number of admin pgp keys");
    }

    if init_args.unseal_threshold > init_args.unseal_pgp_key_file.len() {
        bail!("unseal threshold must be less than or equal to the number of unseal pgp keys");
    }

    let mut pgp_keys = Vec::new();

    for filename in init_args.unseal_pgp_key_file {
        let mut file =
            File::open(&filename).context(format!("Failed to open pgp key file {}", &filename))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let key = std::str::from_utf8(&buf)?.trim().to_string();
        pgp_keys.push(key);
    }

    let mut admin_pgp_keys = Vec::new();

    for filename in init_args.admin_pgp_key_file {
        let mut file =
            File::open(&filename).context(format!("Failed to open pgp key file {}", &filename))?;
        // read all lines from file and concatenate them
        let mut key = String::new();
        file.read_to_string(&mut key)
            .context(format!("Failed to read pgp key file {}", &filename))?;
        key.retain(|c| !c.is_ascii_whitespace());

        let bytes = general_purpose::STANDARD.decode(key).context(format!(
            "Failed to base64 decode pgp key file {}",
            &filename
        ))?;
        admin_pgp_keys.push(bytes.into_boxed_slice());
    }

    let init = Init {
        secret_shares: pgp_keys.len() as _,
        secret_threshold: init_args.unseal_threshold,
        admin_threshold: init_args.admin_threshold,
        admin_tee_mrenclave: init_args.admin_tee_mrenclave,
        admin_pgp_keys: admin_pgp_keys.into_boxed_slice(),
        pgp_keys,
    };

    info!("Inititalizing vault");

    let mut response = conn
        .client()
        .post(&format!(
            "{server}{url}",
            server = conn.server(),
            url = Init::URL
        ))
        .send_json(&init)
        .await
        .map_err(|e| anyhow!("Error sending init request: {}", e))?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("Failed to init vault: {}", status_code);
        if let Ok(r) = response.json::<Value>().await {
            eprintln!("Failed to init vault: {}", r);
        }
        bail!("failed to init vault: {}", status_code);
    }

    let init_response: Value = response.json().await.context("failed to init vault")?;

    info!("Got Response: {}", init_response.to_string());

    let resp: InitResponse =
        serde_json::from_value(init_response).context("Failed to parse init response")?;
    println!("{}", serde_json::to_string(&resp).unwrap());
    Ok(())
}

async fn unseal(args: Arguments) -> Result<()> {
    info!("Reading unencrypted key from stdin");

    // read all bytes from stdin
    let mut stdin = std::io::stdin();
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf)?;
    let key = std::str::from_utf8(&buf)?.trim().to_string();

    if key.is_empty() {
        bail!("Error reading key from stdin");
    }

    let conn = TeeConnection::new(&args.attestation, ATTESTATION_URL).await?;

    info!("Quote verified! Connection secure!");

    info!("Unsealing vault");

    let unseal_data = Unseal { key };

    let mut response = conn
        .client()
        .post(&format!(
            "{server}{url}",
            server = conn.server(),
            url = Unseal::URL
        ))
        .send_json(&unseal_data)
        .await
        .map_err(|e| anyhow!("Error sending unseal request: {}", e))?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("Failed to unseal vault: {}", status_code);
        if let Ok(r) = response.json::<Value>().await {
            eprintln!("Failed to unseal vault: {}", r);
        }
        bail!("failed to unseal vault: {}", status_code);
    }

    let unseal_response: Value = response.json().await.context("failed to unseal vault")?;

    trace!("Got Response: {}", unseal_response.to_string());

    if matches!(unseal_response["sealed"].as_bool(), Some(true)) {
        warn!("Vault is still sealed!");
        println!("Vault is still sealed!");
    } else {
        info!("Vault is unsealed!");
        println!("Vault is unsealed!");
    }
    Ok(())
}

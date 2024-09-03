// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Pre-exec for binary running in a TEE needing attestation of a secret signing key

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use secp256k1::{rand, Keypair, PublicKey, Secp256k1, SecretKey};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;
use teepot::quote::get_quote;
use tracing::error;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

const TEE_QUOTE_FILE: &str = "/tmp/tee_quote";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// environment variable prefix to use
    #[arg(long, default_value = "")]
    env_prefix: String,
    /// program to exec [args...] (required)
    #[arg(required = true, allow_hyphen_values = true, last = true)]
    cmd_args: Vec<OsString>,
}

fn main_with_error() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;

    let args = Args::parse();

    let mut rng = rand::thread_rng();
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rng);
    let signing_key = SecretKey::from_keypair(&keypair);
    let verifying_key = PublicKey::from_keypair(&keypair);
    let verifying_key_bytes = verifying_key.serialize();
    let tee_type = match get_quote(verifying_key_bytes.as_ref()) {
        Ok(quote) => {
            // save quote to file
            std::fs::write(TEE_QUOTE_FILE, quote)?;
            "sgx"
        }
        Err(e) => {
            error!("Failed to get quote: {}", e);
            std::fs::write(TEE_QUOTE_FILE, [])?;
            "none"
        }
    };

    let err = Command::new(&args.cmd_args[0])
        .args(&args.cmd_args[1..])
        .env(
            format!("{}SIGNING_KEY", args.env_prefix),
            signing_key.display_secret().to_string(),
        )
        .env(
            format!("{}ATTESTATION_QUOTE_FILE_PATH", args.env_prefix),
            TEE_QUOTE_FILE,
        )
        .env(format!("{}TEE_TYPE", args.env_prefix), tee_type)
        .exec();

    Err(err).with_context(|| {
        format!(
            "exec of `{cmd}` failed",
            cmd = args.cmd_args[0].to_string_lossy()
        )
    })
}

fn main() -> Result<()> {
    let ret = main_with_error();
    if let Err(e) = &ret {
        error!("Error: {}", e);
    }
    ret
}

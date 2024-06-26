// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Pre-exec for binary running in a TEE needing attestation of a secret signing key

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use secp256k1::{rand, Keypair, PublicKey, Secp256k1, SecretKey};

use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;
use teepot::quote::get_quote;
use tracing::error;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

const TEE_QUOTE_FILE: &str = "/tmp/tee_quote";

fn main_with_error() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;

    let args = env::args_os().collect::<Box<_>>();

    if args.len() < 2 {
        return Err(anyhow::anyhow!(
            "Usage: {} <command> [args...]",
            args[0].to_string_lossy()
        ));
    }

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

    let err = Command::new(&args[1])
        .args(&args[2..])
        .env("TEE_SIGNING_KEY", signing_key.display_secret().to_string())
        .env("TEE_QUOTE_FILE", TEE_QUOTE_FILE)
        .env("TEE_TYPE", tee_type)
        .exec();

    Err(err).with_context(|| format!("exec of `{cmd}` failed", cmd = args[1].to_string_lossy()))
}

fn main() -> Result<()> {
    let ret = main_with_error();
    if let Err(e) = &ret {
        error!("Error: {}", e);
    }
    ret
}

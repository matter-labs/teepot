// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Pre-exec for binary running in a TEE needing attestation of a secret signing key

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::{ffi::OsString, os::unix::process::CommandExt, process::Command};
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

/// Converts a public key into an Ethereum address by hashing the encoded public key with Keccak256.
pub fn public_key_to_address(public: &PublicKey) -> [u8; 20] {
    let public_key_bytes = public.serialize_uncompressed();

    // Skip the first byte (0x04) which indicates uncompressed key
    let hash: [u8; 32] = Keccak256::digest(&public_key_bytes[1..]).into();

    // Take the last 20 bytes of the hash to get the Ethereum address
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
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
    let (signing_key, verifying_key) = secp.generate_keypair(&mut rng);
    let ethereum_address = public_key_to_address(&verifying_key);
    let tee_type = match get_quote(ethereum_address.as_ref()) {
        Ok((tee_type, quote)) => {
            // save quote to file
            std::fs::write(TEE_QUOTE_FILE, quote)?;
            tee_type.to_string()
        }
        Err(e) => {
            error!("Failed to get quote: {}", e);
            std::fs::write(TEE_QUOTE_FILE, [])?;
            "none".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_to_address() {
        let secp = Secp256k1::new();
        let secret_key_bytes =
            hex::decode("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3")
                .unwrap();
        let secret_key = SecretKey::from_slice(&secret_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_address = hex::decode("627306090abaB3A6e1400e9345bC60c78a8BEf57").unwrap();
        let address = public_key_to_address(&public_key);

        assert_eq!(address, expected_address.as_slice());
    }
}

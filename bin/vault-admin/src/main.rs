// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use pgp::types::KeyTrait;
use pgp::{Deserializable, SignedPublicKey};
use serde_json::Value;
use std::default::Default;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use teepot::client::{AttestationArgs, TeeConnection};
use teepot::json::http::{
    SignRequest, SignRequestData, SignResponse, VaultCommandRequest, VaultCommands,
    VaultCommandsResponse, DIGEST_URL,
};
use teepot::server::signatures::verify_sig;
use teepot::sgx::sign::Signature;
use tracing::{error, info};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Args, Debug)]
struct SendArgs {
    #[clap(flatten)]
    pub attestation: AttestationArgs,
    /// Vault command file
    #[arg(required = true)]
    pub command_file: PathBuf,
    /// GPG signature files
    #[arg(required = true)]
    pub sigs: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct SignTeeArgs {
    #[clap(flatten)]
    pub attestation: AttestationArgs,
    /// output file
    #[arg(short, long, required = true)]
    pub out: PathBuf,
    /// signature request file
    #[arg(required = true)]
    pub sig_request_file: PathBuf,
    /// GPG signature files
    #[arg(required = true)]
    pub sigs: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct DigestArgs {
    #[clap(flatten)]
    pub attestation: AttestationArgs,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// GPG identity files
    #[arg(short, long, required = true)]
    pub idents: Vec<PathBuf>,
    /// Vault command file
    #[arg(required = true)]
    pub command_file: PathBuf,
    /// GPG signature files
    #[arg(required = true)]
    pub sigs: Vec<PathBuf>,
}

#[derive(Args, Debug)]
struct CreateSignRequestArgs {
    /// Last digest
    #[arg(long)]
    pub last_digest: Option<String>,
    /// TEE name
    #[arg(long)]
    pub tee_name: Option<String>,
    /// Vault command file
    #[arg(required = true)]
    pub sig_file: PathBuf,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    /// Send the signed commands to execute to the vault
    Command(SendArgs),
    /// Verify the signature(s) for the commands to send
    Verify(VerifyArgs),
    /// Get the digest of the last executed commands
    Digest(DigestArgs),
    /// Send the signed commands to execute to the vault
    SignTee(SignTeeArgs),
    /// Create a sign request
    CreateSignRequest(CreateSignRequestArgs),
}

/// Admin tool for the vault
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
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
    info!("Quote verified! Connection secure!");

    match args.cmd {
        SubCommands::Command(args) => send_commands(args).await?,
        SubCommands::SignTee(args) => send_sig_request(args).await?,
        SubCommands::Verify(args) => {
            verify(args.command_file, args.idents.iter(), args.sigs.iter())?
        }
        SubCommands::Digest(args) => digest(args).await?,
        SubCommands::CreateSignRequest(args) => create_sign_request(args)?,
    }

    Ok(())
}

fn create_sign_request(args: CreateSignRequestArgs) -> Result<()> {
    let mut sigstruct_file = File::open(&args.sig_file)?;
    let mut sigstruct_bytes = Vec::new();
    sigstruct_file.read_to_end(&mut sigstruct_bytes)?;

    let sigstruct = bytemuck::try_from_bytes::<Signature>(&sigstruct_bytes)
        .context(format!("parsing signature file {:?}", &args.sig_file))?;

    let body = sigstruct.body();
    let data = bytemuck::bytes_of(&body).to_vec();

    let sign_request_data = SignRequestData {
        data,
        last_digest: args.last_digest.unwrap_or_default(),
        tee_name: args.tee_name.unwrap_or_default(),
        tee_type: "sgx".to_string(),
        ..Default::default()
    };

    println!("{}", serde_json::to_string_pretty(&sign_request_data)?);
    Ok(())
}

fn verify(
    msg: impl AsRef<Path>,
    idents_file_paths: impl Iterator<Item = impl AsRef<Path>>,
    sig_paths: impl Iterator<Item = impl AsRef<Path>>,
) -> Result<()> {
    let mut cmd_file = File::open(msg.as_ref())?;
    let mut cmd_buf = Vec::new();
    cmd_file
        .read_to_end(&mut cmd_buf)
        .context(format!("reading command file {:?}", &cmd_file))?;

    let mut idents = Vec::new();
    for ident_file_path in idents_file_paths {
        let ident_file = File::open(ident_file_path.as_ref()).context(format!(
            "reading identity file {:?}",
            ident_file_path.as_ref()
        ))?;
        idents.push(
            SignedPublicKey::from_armor_single(ident_file)
                .context(format!(
                    "reading identity file {:?}",
                    ident_file_path.as_ref()
                ))?
                .0,
        );
    }

    for sig_path in sig_paths {
        let mut sig_file = File::open(&sig_path)
            .context(format!("reading signature file {:?}", sig_path.as_ref()))?;
        let mut sig = String::new();
        sig_file
            .read_to_string(&mut sig)
            .context(format!("reading signature file {:?}", sig_path.as_ref()))?;
        let ident_pos = verify_sig(&sig, &cmd_buf, &idents)?;
        println!(
            "Verified signature for `{}`",
            hex::encode_upper(idents.get(ident_pos).unwrap().fingerprint())
        );
        // Remove the identity from the list of identities to verify
        idents.remove(ident_pos);
    }

    Ok(())
}

async fn send_commands(args: SendArgs) -> Result<()> {
    // Read the command file into a string
    let mut cmd_file = File::open(&args.command_file)?;
    let mut commands = String::new();
    cmd_file.read_to_string(&mut commands)?;

    // Check that the command file is valid JSON
    let vault_commands: VaultCommands = serde_json::from_str(&commands)
        .context(format!("parsing command file {:?}", &args.command_file))?;

    let mut signatures = Vec::new();

    for sig in args.sigs {
        let mut sig_file = File::open(sig)?;
        let mut sig = String::new();
        sig_file.read_to_string(&mut sig)?;
        signatures.push(sig);
    }

    let send_req = VaultCommandRequest {
        commands,
        signatures,
    };

    let conn = TeeConnection::new(&args.attestation);

    let mut response = conn
        .client()
        .post(&format!(
            "{server}{url}",
            server = conn.server(),
            url = VaultCommandRequest::URL
        ))
        .send_json(&send_req)
        .await
        .map_err(|e| anyhow!("sending command request: {}", e))?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("sending command request: {}", status_code);
        if let Ok(r) = response.json::<Value>().await {
            eprintln!(
                "Error sending command request: {}",
                serde_json::to_string(&r).unwrap_or_default()
            );
        }
        bail!("sending command request: {}", status_code);
    }

    let cmd_responses: VaultCommandsResponse = response
        .json()
        .await
        .context("failed parsing command response")?;

    println!("digest: {}", &cmd_responses.digest);

    let pairs = cmd_responses
        .results
        .iter()
        .zip(vault_commands.commands.iter())
        .map(|(resp, cmd)| {
            let mut pair = serde_json::Map::new();
            pair.insert("request".to_string(), serde_json::to_value(cmd).unwrap());
            pair.insert("response".to_string(), serde_json::to_value(resp).unwrap());
            pair
        })
        .collect::<Vec<_>>();

    println!("{}", serde_json::to_string_pretty(&pairs)?);
    Ok(())
}

async fn send_sig_request(args: SignTeeArgs) -> Result<()> {
    // Read the command file into a string
    let mut cmd_file = File::open(&args.sig_request_file)?;
    let mut sign_request_data_str = String::new();
    cmd_file.read_to_string(&mut sign_request_data_str)?;

    // Check that the command file is valid JSON
    let _sign_request_data: SignRequestData = serde_json::from_str(&sign_request_data_str)
        .context(format!("parsing command file {:?}", &args.sig_request_file))?;

    let mut signatures = Vec::new();

    for sig in args.sigs {
        let mut sig_file = File::open(sig)?;
        let mut sig = String::new();
        sig_file.read_to_string(&mut sig)?;
        signatures.push(sig);
    }

    // open out_file early to fail fast if it is not writable
    let mut out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&args.out)?;

    let send_req = SignRequest {
        sign_request_data: sign_request_data_str,
        signatures,
    };

    let conn = TeeConnection::new(&args.attestation);

    let mut response = conn
        .client()
        .post(&format!(
            "{server}{url}",
            server = conn.server(),
            url = SignRequest::URL
        ))
        .send_json(&send_req)
        .await
        .map_err(|e| anyhow!("sending sign request: {}", e))?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("sending sign request: {}", status_code);
        if let Ok(r) = response.json::<Value>().await {
            eprintln!(
                "Error sending sign request: {}",
                serde_json::to_string(&r).unwrap_or_default()
            );
        }
        bail!("sending sign request: {}", status_code);
    }

    let sign_response: SignResponse = response
        .json()
        .await
        .context("failed parsing sign response")?;

    println!("digest: {}", &sign_response.digest);

    out_file.write_all(&sign_response.signed_data)?;

    println!("{{ \"digest\": \"{}\" }}", sign_response.digest);
    Ok(())
}

async fn digest(args: DigestArgs) -> Result<()> {
    let conn = TeeConnection::new(&args.attestation);

    let mut response = conn
        .client()
        .get(&format!("{server}{DIGEST_URL}", server = conn.server()))
        .send()
        .await
        .map_err(|e| anyhow!("sending digest request: {}", e))?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("sending digest request: {}", status_code);
        if let Ok(r) = response.json::<Value>().await {
            eprintln!("Error sending digest request: {}", r);
        }
        bail!("sending digest request: {}", status_code);
    }

    let digest_response: Value = response
        .json()
        .await
        .context("failed parsing digest response")?;

    println!("{}", serde_json::to_string_pretty(&digest_response)?);
    Ok(())
}

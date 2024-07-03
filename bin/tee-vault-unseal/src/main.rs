// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Server to initialize and unseal the Vault TEE.

#![deny(missing_docs)]
#![deny(clippy::all)]

mod init;
mod unseal;

use actix_web::rt::time::sleep;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use anyhow::{Context, Result};
use awc::Client;
use clap::Parser;
use init::post_init;
use rustls::ServerConfig;
use std::fmt::Debug;
use std::io::Read;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use teepot::client::{AttestationArgs, TeeConnection};
use teepot::json::http::{Init, Unseal};
use teepot::json::secrets::AdminConfig;
use teepot::server::attestation::{get_quote_and_collateral, VaultAttestationArgs};
use teepot::server::new_json_cfg;
use teepot::server::pki::make_self_signed_cert;
use teepot::sgx::{parse_tcb_levels, EnumSet, TcbLevel};
use tracing::{error, info};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use unseal::post_unseal;

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Worker thread state and data
#[derive(Debug, Clone)]
pub struct Worker {
    /// TLS config for the HTTPS client
    pub vault_attestation: Arc<AttestationArgs>,
    /// Server config
    pub config: Arc<UnsealServerConfig>,
    /// Server state
    pub state: Arc<RwLock<UnsealServerState>>,
}

/// Global Server config
#[derive(Debug, Default)]
pub struct UnsealServerConfig {
    /// Vault URL
    pub vault_url: String,
    /// The expected report_data for the Vault TEE
    pub report_data: Box<[u8]>,
    /// allowed TCB levels
    pub allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
    /// SHA256 of the vault_auth_tee plugin binary
    pub vault_auth_tee_sha: String,
    /// version string of the vault_auth_tee plugin
    pub vault_auth_tee_version: String,
    /// the common cacert file for the vault cluster
    pub ca_cert_file: PathBuf,
}

/// Server state
#[derive(Debug, Clone)]
pub enum UnsealServerState {
    /// Undefined
    Undefined,
    /// Vault is not yet initialized
    VaultUninitialized,
    /// Vault is initialized but not unsealed
    VaultInitialized {
        /// config for the admin TEE
        admin_config: AdminConfig,
        /// initial admin TEE mrenclave
        admin_tee_mrenclave: String,
        /// Vault root token
        root_token: String,
    },
    /// Vault is already initialized but not unsealed
    /// and should already be configured
    VaultInitializedAndConfigured,
    /// Vault is unsealed
    VaultUnsealed,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// allowed TCB levels, comma separated
    #[arg(long, value_parser = parse_tcb_levels, env = "ALLOWED_TCB_LEVELS", default_value = "Ok")]
    allowed_tcb_levels: EnumSet<TcbLevel>,
    /// port to listen on
    #[arg(long, env = "PORT", default_value = "8443")]
    port: u16,
    #[arg(long, env = "VAULT_AUTH_TEE_SHA256")]
    vault_auth_tee_sha: String,
    #[arg(long, env = "VAULT_AUTH_TEE_SHA256_FILE")]
    vault_auth_tee_sha_file: Option<PathBuf>,
    #[arg(long, env = "VAULT_AUTH_TEE_VERSION")]
    vault_auth_tee_version: String,
    /// ca cert file
    #[arg(long, env = "CA_CERT_FILE", default_value = "/opt/vault/cacert.pem")]
    ca_cert_file: PathBuf,
    #[clap(flatten)]
    pub attestation: VaultAttestationArgs,
}

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(
            fmt::layer()
                .with_span_events(fmt::format::FmtSpan::NEW)
                .with_writer(std::io::stderr),
        );
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut args = Args::parse();

    info!("Starting up");

    if let Err(e) = get_quote_and_collateral(Some(args.allowed_tcb_levels), &[0u8; 64]) {
        error!("failed to get quote and collateral: {e:?}");
        // don't return for now, we can still serve requests but we won't be able to attest
    }

    let (report_data, cert_chain, priv_key) = make_self_signed_cert("CN=localhost", None)?;

    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert([cert_chain].into(), priv_key)
        .context("Failed to load TLS key/cert files")?;

    let attestation_args: AttestationArgs = args.attestation.clone().into();

    let conn = TeeConnection::new(&attestation_args);

    let server_state = get_vault_status(&args.attestation.vault_addr, conn.client()).await;

    // If sha file given, override env variable with contents
    if let Some(sha_file) = args.vault_auth_tee_sha_file {
        let mut file = std::fs::File::open(sha_file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        args.vault_auth_tee_sha = contents.trim_end().into();
    }

    info!("Starting HTTPS server at port {}", args.port);
    let server_config = Arc::new(UnsealServerConfig {
        vault_url: args.attestation.vault_addr,
        report_data: Box::from(report_data),
        allowed_tcb_levels: Some(args.allowed_tcb_levels),
        vault_auth_tee_sha: args.vault_auth_tee_sha,
        vault_auth_tee_version: args.vault_auth_tee_version,
        ca_cert_file: args.ca_cert_file,
    });

    let server_state = Arc::new(RwLock::new(server_state));

    let worker = Worker {
        vault_attestation: Arc::new(attestation_args),
        config: server_config,
        state: server_state,
    };

    let server = match HttpServer::new(move || {
        App::new()
            // enable logger
            //.wrap(TracingLogger::default())
            .app_data(new_json_cfg())
            .app_data(Data::new(worker.clone()))
            .service(web::resource(Init::URL).route(web::post().to(post_init)))
            .service(web::resource(Unseal::URL).route(web::post().to(post_unseal)))
    })
    .bind_rustls_0_22((Ipv6Addr::UNSPECIFIED, args.port), config)
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to bind to port {}: {e:?}", args.port);
            return Err(e).context(format!("Failed to bind to port {}", args.port));
        }
    };

    if let Err(e) = server.worker_max_blocking_threads(2).workers(8).run().await {
        error!("failed to start HTTPS server: {e:?}");
        return Err(e).context("Failed to start HTTPS server");
    }

    Ok(())
}

async fn get_vault_status(vault_url: &str, client: &Client) -> UnsealServerState {
    loop {
        let r = client
            .get(format!("{}/v1/sys/health", vault_url))
            .send()
            .await;

        if let Ok(r) = r {
            // https://developer.hashicorp.com/vault/api-docs/system/health
            match r.status().as_u16() {
                200 | 429 | 472 | 473 => {
                    info!("Vault is initialized and unsealed");
                    break UnsealServerState::VaultUnsealed;
                }
                501 => {
                    info!("Vault is not initialized");
                    break UnsealServerState::VaultUninitialized;
                }
                503 => {
                    info!("Vault is initialized but not unsealed");
                    break UnsealServerState::VaultInitializedAndConfigured;
                }
                s => {
                    error!("Vault is not ready: status code {s}");
                }
            }
        }
        info!("Waiting for vault to be ready");
        sleep(Duration::from_secs(1)).await;
    }
}

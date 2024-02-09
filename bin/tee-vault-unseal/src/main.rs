// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Server to initialize and unseal the Vault TEE.

#![deny(missing_docs)]
#![deny(clippy::all)]

mod attestation;
mod init;
mod unseal;

use actix_web::http::header;
use actix_web::rt::time::sleep;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use anyhow::{Context, Result};
use attestation::get_attestation;
use awc::{Client, Connector};
use clap::Parser;
use init::post_init;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use rustls_pemfile::{certs, read_one};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use std::net::Ipv6Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{fs::File, io::BufReader};
use teepot::json::http::{Init, Unseal, ATTESTATION_URL};
use teepot::json::secrets::AdminConfig;
use teepot::server::attestation::get_quote_and_collateral;
use teepot::server::new_json_cfg;
use teepot::sgx::{parse_tcb_levels, EnumSet, TcbLevel};
use tracing::{error, info, trace};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use unseal::post_unseal;
use x509_cert::der::Decode as _;
use x509_cert::der::Encode as _;
use x509_cert::Certificate;

const VAULT_AUTH_TEE_SHA256: &str = include_str!("../../../assets/vault-auth-tee.sha256");
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Worker thread state and data
pub struct Worker {
    /// TLS config for the HTTPS client
    pub client_tls_config: Arc<ClientConfig>,
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
    pub report_data: Vec<u8>,
    /// allowed TCB levels
    pub allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
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

impl UnsealServerConfig {
    /// Create a new ServerState
    pub fn new(
        vault_url: String,
        report_data: [u8; 64],
        allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
    ) -> Self {
        Self {
            report_data: report_data.to_vec(),
            vault_url,
            allowed_tcb_levels,
        }
    }
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
    /// vault url
    #[arg(long, env = "VAULT_ADDR", default_value = "https://vault:8210")]
    vault_url: String,
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

    let args = Args::parse();

    let tls_ok = std::path::Path::new("/opt/vault/tls/tls.ok");
    loop {
        info!("Waiting for TLS key/cert files to be generated");

        // Wait for the file `data/tls.key` to exist
        if tls_ok.exists() {
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    info!("Starting up");

    let (config, client_tls_config, report_data) = load_rustls_config().or_else(|e| {
        error!("failed to load rustls config: {e:?}");
        Err(e).context("Failed to load rustls config")
    })?;

    if let Err(e) = get_quote_and_collateral(Some(args.allowed_tcb_levels), &report_data) {
        error!("failed to get quote and collateral: {e:?}");
        // don't return for now, we can still serve requests but we won't be able to attest
    }

    let client = create_https_client(client_tls_config.clone());

    let server_state = get_vault_status(&args.vault_url, client).await;

    info!("Starting HTTPS server at port {}", args.port);
    let server_config = Arc::new(UnsealServerConfig::new(
        args.vault_url,
        report_data,
        Some(args.allowed_tcb_levels),
    ));

    let server_state = Arc::new(RwLock::new(server_state));

    let server = match HttpServer::new(move || {
        let worker = Worker {
            client_tls_config: client_tls_config.clone(),
            config: server_config.clone(),
            state: server_state.clone(),
        };

        App::new()
            // enable logger
            //.wrap(TracingLogger::default())
            .app_data(new_json_cfg())
            .app_data(Data::new(worker))
            .service(web::resource(ATTESTATION_URL).route(web::get().to(get_attestation)))
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

async fn get_vault_status(vault_url: &str, client: Client) -> UnsealServerState {
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

// Save the hash of the public server key to `REPORT_DATA` to check
// the attestations against it and it does not change on reconnect.
fn make_verifier(server_cert: Box<[u8]>) -> impl ServerCertVerifier {
    #[derive(Debug)]
    struct V {
        server_cert: Box<[u8]>,
        server_verifier: Arc<WebPkiServerVerifier>,
    }
    impl ServerCertVerifier for V {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, Error> {
            let data = &self.server_cert;

            if data.as_ref() == end_entity.as_ref() {
                info!("Server certificate matches expected certificate");
                Ok(ServerCertVerified::assertion())
            } else {
                error!("Server certificate does not match expected certificate");
                Err(rustls::Error::General(
                    "Server certificate does not match expected certificate".to_string(),
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            self.server_verifier
                .verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            self.server_verifier
                .verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.server_verifier.supported_verify_schemes()
        }
    }
    let root_store = Arc::new(rustls::RootCertStore::empty());
    let server_verifier = WebPkiServerVerifier::builder(root_store).build().unwrap();
    V {
        server_cert,
        server_verifier,
    }
}

/// Load TLS key/cert files
pub fn load_rustls_config() -> Result<(ServerConfig, Arc<ClientConfig>, [u8; 64])> {
    // init server config builder with safe defaults
    let config = ServerConfig::builder().with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(
        File::open("/opt/vault/tls/tls.crt").context("Failed to open TLS cert file")?,
    );
    let key_file = &mut BufReader::new(
        File::open("/opt/vault/tls/tls.key").context("Failed to open TLS key file")?,
    );

    // convert files to key/cert objects
    let cert_chain: Vec<_> = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let priv_key: rustls::pki_types::PrivateKeyDer = match read_one(key_file).unwrap() {
        Some(rustls_pemfile::Item::RSAKey(key)) => {
            rustls::pki_types::PrivatePkcs1KeyDer::from(key).into()
        }
        Some(rustls_pemfile::Item::PKCS8Key(key)) => {
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into()
        }
        _ => panic!("no keys found"),
    };

    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(make_verifier(
                cert_chain[0].as_ref().into(),
            )))
            .with_no_client_auth(),
    );

    let cert = Certificate::from_der(cert_chain[0].as_ref()).unwrap();
    let pub_key = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();

    let hash = Sha256::digest(pub_key);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&hash[..32]);

    let report_data_hex = hex::encode(report_data);
    trace!(report_data_hex);

    let config = config
        .with_single_cert(cert_chain, priv_key)
        .context("Failed to load TLS key/cert files")?;

    Ok((config, tls_config, report_data))
}

/// Create an HTTPS client with the default headers and config
pub fn create_https_client(client_tls_config: Arc<ClientConfig>) -> Client {
    Client::builder()
        .add_default_header((header::USER_AGENT, "teepot/1.0"))
        // a "connector" wraps the stream into an encrypted connection
        .connector(Connector::new().rustls_0_22(client_tls_config))
        .timeout(Duration::from_secs(12000))
        .finish()
}

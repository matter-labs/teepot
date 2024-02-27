// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Server to handle requests to the Vault TEE

#![deny(missing_docs)]
#![deny(clippy::all)]
mod command;
mod digest;
mod sign;

use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use anyhow::{Context, Result};
use clap::Parser;
use command::post_command;
use digest::get_digest;
use rustls::ServerConfig;
use sign::post_sign;
use std::net::Ipv6Addr;
use std::sync::Arc;
use teepot::json::http::{SignRequest, VaultCommandRequest, DIGEST_URL};
use teepot::server::attestation::{get_quote_and_collateral, VaultAttestationArgs};
use teepot::server::new_json_cfg;
use teepot::server::pki::make_self_signed_cert;
use teepot::sgx::{parse_tcb_levels, EnumSet, TcbLevel};
use tracing::{error, info};
use tracing_actix_web::TracingLogger;
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Server state
pub struct ServerState {
    /// Server TLS public key hash
    pub report_data: [u8; 64],
    /// Vault attestation args
    pub vault_attestation: VaultAttestationArgs,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// allowed TCB levels, comma separated
    #[arg(long, value_parser = parse_tcb_levels, env = "ALLOWED_TCB_LEVELS", default_value = "Ok")]
    server_sgx_allowed_tcb_levels: EnumSet<TcbLevel>,
    /// port to listen on
    #[arg(long, env = "PORT", default_value = "8444")]
    port: u16,
    #[clap(flatten)]
    pub attestation: VaultAttestationArgs,
}

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Arguments::parse();

    let (report_data, cert_chain, priv_key) = make_self_signed_cert("CN=localhost", None)?;

    if let Err(e) = get_quote_and_collateral(Some(args.server_sgx_allowed_tcb_levels), &report_data)
    {
        error!("failed to get quote and collateral: {e:?}");
        // don't return for now, we can still serve requests but we won't be able to attest
    }

    // init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert([cert_chain].into(), priv_key)
        .context("Failed to load TLS key/cert files")?;

    info!("Starting HTTPS server at port {}", args.port);

    info!("Quote verified! Connection secure!");

    let server_state = Arc::new(ServerState {
        report_data,
        vault_attestation: args.attestation,
    });

    let server = match HttpServer::new(move || {
        App::new()
            // enable logger
            .wrap(TracingLogger::default())
            .app_data(new_json_cfg())
            .app_data(Data::new(server_state.clone()))
            .service(web::resource(VaultCommandRequest::URL).route(web::post().to(post_command)))
            .service(web::resource(SignRequest::URL).route(web::post().to(post_sign)))
            .service(web::resource(DIGEST_URL).route(web::get().to(get_digest)))
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use teepot::json::http::{VaultCommand, VaultCommands};

    const TEST_DATA: &str = include_str!("../../../tests/data/test.json");

    #[test]
    fn test_vault_commands() {
        let cmd = VaultCommand {
            url: "/v1/auth/tee/tees/test".to_string(),
            data: json!({
                "lease": "1000",
                "name": "test",
                "types": "sgx",
                "sgx_allowed_tcb_levels": "Ok,SwHardeningNeeded",
                "sgx_mrsigner": "c5591a72b8b86e0d8814d6e8750e3efe66aea2d102b8ba2405365559b858697d",
                "token_policies": "test"
            }),
        };
        let cmds = VaultCommands {
            commands: vec![cmd],
            last_digest: "".into(),
        };

        let test_data_cmds: VaultCommands = serde_json::from_str(TEST_DATA).unwrap();

        assert_eq!(cmds, test_data_cmds);
    }
}

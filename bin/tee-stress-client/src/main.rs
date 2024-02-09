// SPDX-License-Identifier: Apache-2.0

//! Server to handle requests to the Vault TEE

#![deny(missing_docs)]
#![deny(clippy::all)]

use actix_web::rt::time::sleep;
use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use teepot::client::vault::VaultConnection;
use teepot::server::attestation::{get_quote_and_collateral, VaultAttestationArgs};
use teepot::server::pki::make_self_signed_cert;
use teepot::sgx::{parse_tcb_levels, EnumSet, TcbLevel};
use tracing::{error, trace};
use tracing_log::LogTracer;
use tracing_subscriber::Registry;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// allowed TCB levels, comma separated
    #[arg(long, value_parser = parse_tcb_levels, env = "ALLOWED_TCB_LEVELS", default_value = "Ok")]
    my_sgx_allowed_tcb_levels: EnumSet<TcbLevel>,
    #[clap(flatten)]
    pub attestation: VaultAttestationArgs,
}

#[derive(Debug, Serialize, Deserialize)]
struct MySecret {
    val: usize,
}

#[actix_web::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Arguments::parse();

    let (report_data, _cert_chain, _priv_key) = make_self_signed_cert()?;
    if let Err(e) = get_quote_and_collateral(Some(args.my_sgx_allowed_tcb_levels), &report_data) {
        error!("failed to get quote and collateral: {e:?}");
        // don't return for now, we can still serve requests but we won't be able to attest
    }

    let mut vault_1 = args.attestation.clone();
    let mut vault_2 = args.attestation.clone();
    let mut vault_3 = args.attestation.clone();

    vault_1.vault_addr = "https://vault-1:8210".to_string();
    vault_2.vault_addr = "https://vault-2:8210".to_string();
    vault_3.vault_addr = "https://vault-3:8210".to_string();

    let servers = vec![vault_1.clone(), vault_2.clone(), vault_3.clone()];

    let mut val: usize = 1;

    loop {
        let mut conns = Vec::new();
        for server in &servers {
            match VaultConnection::new(&server.into(), "stress".to_string()).await {
                Ok(conn) => conns.push(conn),
                Err(e) => {
                    error!("connecting to {}: {}", server.vault_addr, e);
                    continue;
                }
            }
        }

        if conns.is_empty() {
            error!("no connections");
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let i = val % conns.len();
        trace!("storing secret");
        conns[i]
            .store_secret(MySecret { val }, "val")
            .await
            .context("storing secret")?;
        for conn in conns {
            let got: MySecret = conn
                .load_secret("val")
                .await
                .context("loading secret")?
                .context("loading secret")?;
            assert_eq!(got.val, val,);
        }
        val += 1;
        sleep(Duration::from_secs(1)).await;
    }
}

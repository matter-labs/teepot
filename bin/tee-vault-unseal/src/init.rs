// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use crate::{get_vault_status, UnsealServerState, Worker};
use actix_web::error::ErrorBadRequest;
use actix_web::{web, HttpResponse};
use anyhow::{anyhow, Context, Result};
use awc::http::StatusCode;
use serde_json::json;
use teepot::client::TeeConnection;
use teepot::json::http::{Init, InitResponse, VaultInitRequest};
use teepot::json::secrets::AdminConfig;
use teepot::server::{HttpResponseError, Status};
use tracing::{debug, error, info, instrument, trace};

#[instrument(level = "info", name = "/v1/sys/init", skip_all)]
pub async fn post_init(
    worker: web::Data<Worker>,
    init: web::Json<Init>,
) -> Result<HttpResponse, HttpResponseError> {
    let Init {
        pgp_keys,
        secret_shares,
        secret_threshold,
        admin_pgp_keys,
        admin_threshold,
        admin_tee_mrenclave,
    } = init.into_inner();
    let conn = TeeConnection::new(&worker.vault_attestation);
    let client = conn.client();
    let vault_url = &worker.config.vault_url;

    let vault_init = VaultInitRequest {
        pgp_keys,
        secret_shares,
        secret_threshold,
    };

    if admin_threshold < 1 {
        return Ok(HttpResponse::from_error(ErrorBadRequest(
            json!({"error": "admin_threshold must be at least 1"}),
        )));
    }

    if admin_threshold > admin_pgp_keys.len() {
        return Ok(HttpResponse::from_error(ErrorBadRequest(
            json!({"error": "admin_threshold must be less than or equal to the number of admin_pgp_keys"}),
        )));
    }

    loop {
        let current_state = worker.state.read().unwrap().clone();
        match current_state {
            UnsealServerState::VaultUninitialized => {
                break;
            }
            UnsealServerState::VaultUnsealed => {
                return Err(anyhow!("Vault already unsealed")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultInitialized { .. } => {
                return Err(anyhow!("Vault already initialized")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultInitializedAndConfigured => {
                return Err(anyhow!("Vault already initialized")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::Undefined => {
                let state = get_vault_status(vault_url, client).await;
                *worker.state.write().unwrap() = state;
                continue;
            }
        }
    }

    trace!(
        "Sending init request to Vault {}",
        serde_json::to_string(&vault_init).unwrap()
    );
    let mut response = client
        .post(format!("{}/v1/sys/init", vault_url))
        .send_json(&vault_init)
        .await?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("Vault returned server error: {}", status_code);
        return Err(HttpResponseError::from_proxy(response).await);
    }

    let response = response
        .json::<serde_json::Value>()
        .await
        .context("Failed to convert to json")
        .status(StatusCode::INTERNAL_SERVER_ERROR)?;

    info!("Vault initialized");
    trace!("response {}", response);

    let root_token = response["root_token"]
        .as_str()
        .ok_or(anyhow!("No `root_token` field"))
        .status(StatusCode::BAD_GATEWAY)?
        .to_string();

    debug!("Root token: {root_token}");

    let unseal_keys = response["keys_base64"]
        .as_array()
        .ok_or(anyhow!("No `keys_base64` field"))
        .status(StatusCode::BAD_GATEWAY)?
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    debug!("Unseal keys: {}", unseal_keys.join(", "));

    /*
    FIXME: use unseal keys to create new token
        let mut output = File::create("/opt/vault/data/root_token")
            .context("Failed to create `/opt/vault/data/root_token`")?;
        output
            .write_all(root_token.as_bytes())
            .context("Failed to write root_token")?;
    */

    *worker.state.write().unwrap() = UnsealServerState::VaultInitialized {
        admin_config: AdminConfig {
            admin_pgp_keys,
            admin_threshold,
        },
        admin_tee_mrenclave,
        root_token,
    };

    let response = InitResponse { unseal_keys };

    Ok(HttpResponse::Ok().json(response)) // <- send response
}

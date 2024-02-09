// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! post commands

use crate::ServerState;
use actix_web::web;
use anyhow::{anyhow, Context, Result};
use awc::http::StatusCode;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use teepot::client::vault::VaultConnection;
use teepot::json::http::{
    VaultCommandRequest, VaultCommandResponse, VaultCommands, VaultCommandsResponse,
};
use teepot::json::secrets::{AdminConfig, AdminState};
use teepot::server::{signatures::VerifySig, HttpResponseError, Status};
use tracing::instrument;

/// Post command
#[instrument(level = "info", name = "/v1/command", skip_all)]
pub async fn post_command(
    state: web::Data<Arc<ServerState>>,
    item: web::Json<VaultCommandRequest>,
) -> Result<web::Json<VaultCommandsResponse>, HttpResponseError> {
    let conn = VaultConnection::new(&state.vault_attestation.clone().into(), "admin".to_string())
        .await
        .context("connecting to vault")
        .status(StatusCode::BAD_GATEWAY)?;

    let mut admin_state: AdminState = conn
        .load_secret("state")
        .await?
        .context("empty admin state")
        .status(StatusCode::BAD_GATEWAY)?;

    let commands: VaultCommands = serde_json::from_str(&item.commands)
        .context("parsing commands")
        .status(StatusCode::BAD_REQUEST)?;

    if admin_state.last_digest.to_ascii_lowercase() != commands.last_digest {
        return Err(anyhow!(
            "last digest does not match {} != {}",
            admin_state.last_digest.to_ascii_lowercase(),
            commands.last_digest
        ))
        .status(StatusCode::BAD_REQUEST);
    }

    let admin_config: AdminConfig = conn
        .load_secret("config")
        .await?
        .context("empty admin config")
        .status(StatusCode::BAD_GATEWAY)?;
    admin_config.check_sigs(&item.signatures, item.commands.as_bytes())?;

    let mut hasher = Sha256::new();
    hasher.update(item.commands.as_bytes());
    let hash = hasher.finalize();
    let digest = hex::encode(hash);
    admin_state.last_digest = digest.clone();
    conn.store_secret(admin_state, "state").await?;

    let mut responds = VaultCommandsResponse {
        digest,
        results: vec![],
    };

    for (pos, command) in commands.commands.iter().enumerate() {
        let resp = conn
            .vault_put(
                &format!("Executing command {pos}"),
                &command.url,
                &command.data,
            )
            .await?;

        let vcr = VaultCommandResponse {
            status_code: resp.0.as_u16(),
            value: resp.1,
        };

        responds.results.push(vcr);
    }

    let _ = conn.revoke_token().await;

    Ok(web::Json(responds))
}

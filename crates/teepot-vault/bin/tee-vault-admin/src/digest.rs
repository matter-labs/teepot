// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! digest

use crate::ServerState;
use actix_web::{web, HttpResponse};
use anyhow::{Context, Result};
use awc::http::StatusCode;
use serde_json::json;
use std::sync::Arc;
use teepot_vault::client::vault::VaultConnection;
use teepot_vault::json::secrets::AdminState;
use teepot_vault::server::{HttpResponseError, Status};
use tracing::instrument;

/// Get last digest
#[instrument(level = "info", name = "/v1/digest", skip_all)]
pub async fn get_digest(
    state: web::Data<Arc<ServerState>>,
) -> Result<HttpResponse, HttpResponseError> {
    let conn = VaultConnection::new(&state.vault_attestation.clone().into(), "admin".to_string())
        .await
        .context("connecting to vault")
        .status(StatusCode::BAD_GATEWAY)?;

    let admin_state: AdminState = conn
        .load_secret("state")
        .await?
        .context("empty admin state")
        .status(StatusCode::BAD_GATEWAY)?;

    Ok(HttpResponse::Ok().json(json!({"last_digest": admin_state.last_digest })))
}

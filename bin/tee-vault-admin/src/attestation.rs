// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! attestation

use crate::ServerState;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use anyhow::{Context, Result};
use std::sync::Arc;
use teepot::json::http::AttestationResponse;
use teepot::server::attestation::get_quote_and_collateral;
use teepot::server::{HttpResponseError, Status};
use tracing::instrument;

/// Get attestation
#[instrument(level = "info", name = "/v1/sys/attestation", skip_all)]
pub async fn get_attestation(
    worker: Data<Arc<ServerState>>,
) -> Result<Json<AttestationResponse>, HttpResponseError> {
    get_quote_and_collateral(None, &worker.report_data)
        .context("Error getting attestation")
        .map(Json)
        .status(StatusCode::INTERNAL_SERVER_ERROR)
}

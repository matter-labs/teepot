// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

use crate::Worker;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use anyhow::{Context, Result};
use teepot::json::http::AttestationResponse;
use teepot::server::attestation::get_quote_and_collateral;
use teepot::server::{HttpResponseError, Status};
use tracing::instrument;

#[instrument(level = "info", name = "/v1/sys/attestation", skip_all)]
pub async fn get_attestation(
    worker: Data<Worker>,
) -> Result<Json<AttestationResponse>, HttpResponseError> {
    let report_data: [u8; 64] = worker
        .config
        .report_data
        .clone()
        .try_into()
        .map_err(|_| "Error getting attestation")?;
    get_quote_and_collateral(None, &report_data)
        .context("Error getting attestation")
        .map(Json)
        .status(StatusCode::INTERNAL_SERVER_ERROR)
}

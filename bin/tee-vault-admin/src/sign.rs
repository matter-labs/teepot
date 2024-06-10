// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! post signing request

use crate::ServerState;
use actix_web::http::StatusCode;
use actix_web::web;
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use teepot::client::vault::VaultConnection;
use teepot::json::http::{SignRequest, SignRequestData, SignResponse};
use teepot::json::secrets::{AdminConfig, AdminState, SGXSigningKey};
use teepot::server::signatures::VerifySig as _;
use teepot::server::{HttpResponseError, Status};
use teepot::sgx::sign::PrivateKey as _;
use teepot::sgx::sign::{Author, Signature};
use teepot::sgx::sign::{Body, RS256PrivateKey};
use tracing::instrument;

/// Sign command
#[instrument(level = "info", name = "/v1/sign", skip_all)]
pub async fn post_sign(
    state: web::Data<Arc<ServerState>>,
    item: web::Json<SignRequest>,
) -> Result<web::Json<SignResponse>, HttpResponseError> {
    let conn = VaultConnection::new(&state.vault_attestation.clone().into(), "admin".to_string())
        .await
        .context("connecting to vault")
        .status(StatusCode::BAD_GATEWAY)?;

    let mut admin_state: AdminState = conn
        .load_secret("state")
        .await?
        .context("empty admin state")
        .status(StatusCode::BAD_GATEWAY)?;

    let sign_request: SignRequestData = serde_json::from_str(&item.sign_request_data)
        .context("parsing sign request data")
        .status(StatusCode::BAD_REQUEST)?;

    // Sanity checks
    if sign_request.tee_type != "sgx" {
        return Err(anyhow!("tee_type not supported")).status(StatusCode::BAD_REQUEST);
    }

    let tee_name = sign_request.tee_name;

    if !tee_name.is_ascii() {
        return Err(anyhow!("tee_name is not ascii")).status(StatusCode::BAD_REQUEST);
    }

    // check if tee_name is alphanumeric
    if !tee_name.chars().all(|c| c.is_alphanumeric()) {
        return Err(anyhow!("tee_name is not alphanumeric")).status(StatusCode::BAD_REQUEST);
    }

    // check if tee_name starts with an alphabetic char
    if !tee_name.chars().next().unwrap().is_alphabetic() {
        return Err(anyhow!("tee_name does not start with an alphabetic char"))
            .status(StatusCode::BAD_REQUEST);
    }

    if admin_state.last_digest != sign_request.last_digest {
        return Err(anyhow!(
            "last digest does not match {} != {}",
            admin_state.last_digest.to_ascii_lowercase(),
            sign_request.last_digest
        ))
        .status(StatusCode::BAD_REQUEST);
    }

    let admin_config: AdminConfig = conn
        .load_secret("config")
        .await?
        .context("empty admin config")
        .status(StatusCode::BAD_GATEWAY)?;
    admin_config.check_sigs(&item.signatures, item.sign_request_data.as_bytes())?;

    let mut hasher = Sha256::new();
    hasher.update(item.sign_request_data.as_bytes());
    let hash = hasher.finalize();
    let digest = hex::encode(hash);
    admin_state.last_digest.clone_from(&digest);
    conn.store_secret(admin_state, "state").await?;

    // Sign SGX enclave
    let key_path = format!("signing_keys/{}", tee_name);

    let sgx_key = match conn
        .load_secret::<SGXSigningKey>(&key_path)
        .await
        .context("Error loading signing key")
        .status(StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(key) => RS256PrivateKey::from_pem(&key.pem_pk)
            .context("Failed to parse private key")
            .status(StatusCode::INTERNAL_SERVER_ERROR)?,
        None => {
            let private_key = RS256PrivateKey::generate(3)
                .context("Failed to generate private key")
                .status(StatusCode::INTERNAL_SERVER_ERROR)?;

            let pem_pk = private_key
                .to_pem()
                .context("Failed to convert private key to pem")
                .status(StatusCode::INTERNAL_SERVER_ERROR)?;

            let key = SGXSigningKey { pem_pk };

            conn.store_secret(key.clone(), &key_path)
                .await
                .context("Error storing generated private key")
                .status(StatusCode::INTERNAL_SERVER_ERROR)?;

            private_key
        }
    };

    let signed_data = sign_sgx(&sign_request.data, &sgx_key)?;
    let respond = SignResponse {
        digest,
        signed_data,
    };

    let _ = conn.revoke_token().await;

    Ok(web::Json(respond))
}

fn sign_sgx(body_bytes: &[u8], sgx_key: &RS256PrivateKey) -> Result<Vec<u8>, HttpResponseError> {
    let body: Body = bytemuck::try_pod_read_unaligned(body_bytes)
        .context("Invalid SGX input data")
        .status(StatusCode::INTERNAL_SERVER_ERROR)?;

    if body.can_set_debug() {
        return Err(anyhow!("Not signing SGX enclave with debug flag"))
            .status(StatusCode::BAD_REQUEST);
    }

    // FIXME: do we need the date and sw defined value?
    let author = Author::new(0, 0);
    let sig = Signature::new(sgx_key, author, body)
        .context("Failed to create RSA signature")
        .status(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(bytemuck::bytes_of(&sig).to_vec())
}

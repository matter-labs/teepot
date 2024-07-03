// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use crate::{get_vault_status, UnsealServerConfig, UnsealServerState, Worker, VAULT_TOKEN_HEADER};
use actix_web::http::StatusCode;
use actix_web::rt::time::sleep;
use actix_web::{web, HttpResponse};
use anyhow::{anyhow, Context, Result};
use awc::{Client, ClientRequest, SendClientRequest};
use serde_json::{json, Value};
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::time::Duration;
use teepot::client::vault::VaultConnection;
use teepot::client::TeeConnection;
use teepot::json::http::Unseal;
use teepot::json::secrets::{AdminConfig, AdminState};
use teepot::server::{HttpResponseError, Status};
use tracing::{debug, error, info, instrument, trace};

#[instrument(level = "info", name = "/v1/sys/unseal", skip_all)]
pub async fn post_unseal(
    worker: web::Data<Worker>,
    item: web::Json<Unseal>,
) -> Result<HttpResponse, HttpResponseError> {
    let conn = TeeConnection::new(&worker.vault_attestation);
    let client = conn.client();
    let app = &worker.config;
    let vault_url = &app.vault_url;

    loop {
        let current_state = worker.state.read().unwrap().clone();
        match current_state {
            UnsealServerState::VaultUninitialized => {
                return Err(anyhow!("Vault not yet initialized")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultUnsealed => {
                return Err(anyhow!("Vault already unsealed")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultInitialized { .. } => {
                break;
            }
            UnsealServerState::VaultInitializedAndConfigured => {
                break;
            }
            UnsealServerState::Undefined => {
                let state = get_vault_status(vault_url, client).await;
                *worker.state.write().unwrap() = state;
                continue;
            }
        }
    }

    let mut response = client
        .post(format!("{}/v1/sys/unseal", vault_url))
        .send_json(&item.0)
        .await?;

    let status_code = response.status();
    if !status_code.is_success() {
        error!("Vault returned server error: {}", status_code);
        let mut client_resp = HttpResponse::build(status_code);
        for (header_name, header_value) in response.headers().iter() {
            client_resp.insert_header((header_name.clone(), header_value.clone()));
        }
        return Ok(client_resp.streaming(response));
    }

    let response: Value = response
        .json()
        .await
        .context("parsing unseal response")
        .status(StatusCode::INTERNAL_SERVER_ERROR)?;

    debug!("unseal: {:?}", response);

    if response.get("errors").is_some() {
        return Ok(HttpResponse::Ok().json(response));
    }

    let sealed = response
        .get("sealed")
        .map(|v| v.as_bool().unwrap_or(true))
        .unwrap_or(true);

    debug!(sealed);

    // if unsealed
    if !sealed {
        let mut state = UnsealServerState::VaultUnsealed;
        std::mem::swap(&mut *worker.state.write().unwrap(), &mut state);

        match state {
            UnsealServerState::VaultUninitialized => {
                return Err(anyhow!("Invalid internal state")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultUnsealed => {
                return Err(anyhow!("Invalid internal state")).status(StatusCode::BAD_REQUEST);
            }
            UnsealServerState::VaultInitialized {
                admin_config,
                admin_tee_mrenclave,
                root_token,
            } => {
                debug!(root_token);
                info!("Vault is unsealed");

                vault_configure_unsealed(
                    app,
                    &admin_config,
                    &root_token,
                    &admin_tee_mrenclave,
                    client,
                )
                .await
                .context("Failed to configure unsealed vault")
                .status(StatusCode::BAD_GATEWAY)?;

                // destroy root token
                let _response = client
                    .post(format!("{}/v1/auth/token/revoke-self", app.vault_url))
                    .insert_header((VAULT_TOKEN_HEADER, root_token.to_string()))
                    .send()
                    .await;

                info!("Vault unsealed and configured!");
            }
            UnsealServerState::VaultInitializedAndConfigured => {
                info!("Vault is unsealed and hopefully configured!");
                info!("Initiating raft join");
                // load TLS cert chain
                let mut cert_file = File::open(&app.ca_cert_file)
                    .context("Failed to open TLS cert chain")
                    .status(StatusCode::INTERNAL_SERVER_ERROR)?;

                let mut cert_buf = Vec::new();
                cert_file
                    .read_to_end(&mut cert_buf)
                    .context("Failed to read TLS cert chain")
                    .status(StatusCode::INTERNAL_SERVER_ERROR)?;

                let cert_chain = std::str::from_utf8(&cert_buf)
                    .context("Failed to parse TLS cert chain as UTF-8")
                    .status(StatusCode::INTERNAL_SERVER_ERROR)?
                    .to_string();

                let payload = json!({"leader_ca_cert": cert_chain, "retry": true });

                let mut response = client
                    .post(format!("{}/v1/sys/storage/raft/join", vault_url))
                    .send_json(&payload)
                    .await?;

                let status_code = response.status();
                if !status_code.is_success() {
                    error!("Vault returned server error: {}", status_code);
                    let mut client_resp = HttpResponse::build(status_code);
                    for (header_name, header_value) in response.headers().iter() {
                        client_resp.insert_header((header_name.clone(), header_value.clone()));
                    }
                    return Ok(client_resp.streaming(response));
                }

                let response: Value = response
                    .json()
                    .await
                    .context("parsing raft join response")
                    .status(StatusCode::INTERNAL_SERVER_ERROR)?;

                debug!("raft join: {:?}", response);

                if response.get("errors").is_some() {
                    return Ok(HttpResponse::Ok().json(response));
                }
            }
            UnsealServerState::Undefined => {
                unreachable!("Invalid internal state");
            }
        }
    }

    Ok(HttpResponse::Accepted().json(response)) // <- send response
}

pub async fn vault_configure_unsealed(
    app: &UnsealServerConfig,
    admin_config: &AdminConfig,
    root_token: &str,
    admin_tee_mrenclave: &str,
    c: &Client,
) -> Result<(), HttpResponseError> {
    wait_for_plugins_catalog(app, root_token, c).await;

    if !plugin_is_already_running(app, root_token, c).await? {
        let r = vault(
            "Installing vault-auth-tee plugin",
            c.put(format!(
                "{}/v1/sys/plugins/catalog/auth/vault-auth-tee",
                app.vault_url
            )),
            root_token,
            json!({
                "sha256": app.vault_auth_tee_sha,
                "command": "vault-auth-tee",
                "version": app.vault_auth_tee_version
            }),
        )
        .await
        .map_err(|e| anyhow!("{:?}", e))
        .status(StatusCode::BAD_GATEWAY)?;
        if !r.status().is_success() {
            let err = HttpResponseError::from_proxy(r).await;
            return Err(err);
        }
    } else {
        info!("vault-auth-tee plugin already installed");
    }

    if !plugin_is_already_running(app, root_token, c).await? {
        let r = vault(
            "Activating vault-auth-tee plugin",
            c.post(format!("{}/v1/sys/auth/tee", app.vault_url)),
            root_token,
            json!({"type": "vault-auth-tee"}),
        )
        .await
        .map_err(|e| anyhow!("{:?}", e))
        .status(StatusCode::BAD_GATEWAY)?;
        if !r.status().is_success() {
            let err = HttpResponseError::from_proxy(r).await;
            return Err(err);
        }
    } else {
        info!("vault-auth-tee plugin already activated");
    }

    if let Ok(mut r) = c
        .get(format!("{}/v1/auth/tee/tees?list=true", app.vault_url))
        .insert_header((VAULT_TOKEN_HEADER, root_token))
        .send()
        .await
    {
        let r: Value = r
            .json()
            .await
            .map_err(|e| anyhow!("{:?}", e))
            .status(StatusCode::BAD_GATEWAY)?;
        trace!("{:?}", r);
        if let Some(tees) = r.get("data").and_then(|v| v.get("keys")) {
            if let Some(tees) = tees.as_array() {
                if tees.contains(&json!("root")) {
                    info!("root TEE already installed");
                    return Ok(());
                }
            }
        }
    }

    vault(
        "Installing root TEE",
        c.put(format!("{}/v1/auth/tee/tees/admin", app.vault_url)),
        root_token,
        json!({
            "lease": "1000",
            "name": "admin",
            "types": "sgx",
            "sgx_allowed_tcb_levels": "Ok,SwHardeningNeeded",
            "sgx_mrenclave": &admin_tee_mrenclave,
            "token_policies": "admin"
        }),
    )
    .await
    .map_err(|e| anyhow!("{:?}", e))
    .status(StatusCode::BAD_GATEWAY)?;

    // Install admin policies
    let admin_policy = include_str!("admin-policy.hcl");
    vault(
        "Installing admin policy",
        c.put(format!("{}/v1/sys/policies/acl/admin", app.vault_url)),
        root_token,
        json!({ "policy": admin_policy }),
    )
    .await
    .map_err(|e| anyhow!("{:?}", e))
    .status(StatusCode::BAD_GATEWAY)?;

    vault(
        "Enable the key/value secrets engine v1 at secret/.",
        c.put(format!("{}/v1/sys/mounts/secret", app.vault_url)),
        root_token,
        json!({ "type": "kv", "description": "K/V v1" } ),
    )
    .await
    .map_err(|e| anyhow!("{:?}", e))
    .status(StatusCode::BAD_GATEWAY)?;

    // Create a `VaultConnection` for the `admin` tee to initialize the secrets for it.
    // Safety: the connection was already attested
    let admin_vcon = unsafe {
        VaultConnection::new_from_client_without_attestation(
            app.vault_url.clone(),
            c.clone(),
            "admin".into(),
            root_token.to_string(),
        )
    };

    // initialize the admin config
    admin_vcon.store_secret(admin_config, "config").await?;
    admin_vcon
        .store_secret(AdminState::default(), "state")
        .await?;

    Ok(())
}

async fn wait_for_plugins_catalog(app: &UnsealServerConfig, root_token: &str, c: &Client) {
    info!("Waiting for plugins to be loaded");
    loop {
        let r = c
            .get(format!("{}/v1/sys/plugins/catalog", app.vault_url))
            .insert_header((VAULT_TOKEN_HEADER, root_token))
            .send()
            .await;

        match r {
            Ok(r) => {
                if r.status().is_success() {
                    break;
                } else {
                    debug!("/v1/sys/plugins/catalog status: {:#?}", r)
                }
            }
            Err(e) => {
                debug!("/v1/sys/plugins/catalog error: {}", e)
            }
        }

        info!("Waiting for plugins to be loaded");
        sleep(Duration::from_secs(1)).await;
    }
}

async fn plugin_is_already_running(
    app: &UnsealServerConfig,
    root_token: &str,
    c: &Client,
) -> std::result::Result<bool, HttpResponseError> {
    if let Ok(mut r) = c
        .get(format!("{}/v1/sys/auth", app.vault_url))
        .insert_header((VAULT_TOKEN_HEADER, root_token))
        .send()
        .await
    {
        if !r.status().is_success() {
            return Ok(false);
        }
        let r: Value = r
            .json()
            .await
            .map_err(|e| anyhow!("{:?}", e))
            .status(StatusCode::BAD_GATEWAY)?;
        trace!("{}", r.to_string());

        let is_running = r
            .get("data")
            .and_then(|v| v.get("tee/"))
            .and_then(|v| v.get("running_sha256"))
            .and_then(|v| v.as_str())
            .and_then(|v| if v.is_empty() { None } else { Some(v) })
            .and_then(|v| {
                if v == app.vault_auth_tee_sha {
                    Some(v)
                } else {
                    None
                }
            })
            .is_some();
        Ok(is_running)
    } else {
        Ok(false)
    }
}

async fn vault(
    action: &str,
    req: ClientRequest,
    token: &str,
    json: Value,
) -> <SendClientRequest as Future>::Output {
    info!("{}", action);
    debug!("json: {:?}", json);
    match req
        .insert_header((VAULT_TOKEN_HEADER, token))
        .send_json(&json)
        .await
    {
        Ok(r) => {
            debug!("response {:?}", r);
            Ok(r)
        }
        Err(e) => {
            error!("{}: {}", action, e);
            Err(e)
        }
    }
}

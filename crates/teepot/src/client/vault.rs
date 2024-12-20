// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Helper functions for CLI clients to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

use super::{AttestationArgs, TeeConnection};
use crate::{
    json::http::{AuthRequest, AuthResponse},
    quote::error::QuoteContext,
    server::{pki::make_self_signed_cert, AnyHowResponseError, HttpResponseError, Status},
};
pub use crate::{
    quote::{verify_quote_with_collateral, QuoteVerificationResult},
    sgx::{
        parse_tcb_levels, sgx_gramine_get_quote, sgx_ql_qv_result_t, Collateral, EnumSet, TcbLevel,
    },
};
use actix_http::error::PayloadError;
use actix_web::{http::header, ResponseError};
use anyhow::{anyhow, bail, Context, Result};
use awc::{
    error::{SendRequestError, StatusCode},
    Client, ClientResponse, Connector,
};
use bytes::Bytes;
use futures_core::Stream;
use intel_tee_quote_verification_rs::tee_qv_get_collateral;
use rustls::ClientConfig;
use serde_json::{json, Value};
use std::{
    fmt::{Display, Formatter},
    sync::Arc,
    time,
};
use tracing::{debug, error, info, trace};

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Error returned when sending a request to Vault
#[derive(Debug, thiserror::Error)]
pub enum VaultSendError {
    /// Error sending the request
    SendRequest(String),
    /// Error returned by the Vault API
    #[error(transparent)]
    Vault(#[from] HttpResponseError),
}

impl Display for VaultSendError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultSendError::SendRequest(e) => write!(f, "VaultSendError: {}", e),
            VaultSendError::Vault(e) => write!(f, "VaultSendError: {}", e),
        }
    }
}

const _: () = {
    fn assert_send<T: Send>() {}
    let _ = assert_send::<VaultSendError>;
};

impl From<VaultSendError> for HttpResponseError {
    fn from(value: VaultSendError) -> Self {
        match value {
            VaultSendError::SendRequest(e) => HttpResponseError::Anyhow(AnyHowResponseError {
                status_code: StatusCode::BAD_GATEWAY,
                error: anyhow!(e),
            }),
            VaultSendError::Vault(e) => e,
        }
    }
}

/// A connection to a Vault TEE, which implements the `teepot` attestation API
/// called by a TEE itself. This authenticates the TEE to Vault and gets a token,
/// which can be used to access the Vault API.
pub struct VaultConnection {
    /// Options and arguments needed to attest Vault
    pub conn: TeeConnection,
    key_hash: [u8; 64],
    client_token: String,
    name: String,
}

impl VaultConnection {
    /// Create a new connection to Vault
    ///
    /// This will verify the attestation report and check that the enclave
    /// is running the expected code.
    pub async fn new(args: &AttestationArgs, name: String) -> Result<Self> {
        let (key_hash, rustls_certificate, rustls_pk) =
            make_self_signed_cert("CN=localhost", None)?;

        let tls_config = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TeeConnection::make_verifier(
                    args.clone(),
                )))
                .with_client_auth_cert(vec![rustls_certificate], rustls_pk)?,
        );

        let client = Client::builder()
            .add_default_header((header::USER_AGENT, "teepot/1.0"))
            // a "connector" wraps the stream into an encrypted connection
            .connector(Connector::new().rustls_0_23(tls_config))
            .timeout(time::Duration::from_secs(12000))
            .finish();

        let mut this = Self {
            name,
            key_hash,
            conn: unsafe {
                TeeConnection::new_from_client_without_attestation(args.server.clone(), client)
            },
            client_token: Default::default(),
        };

        this.client_token = this.auth().await?.auth.client_token;

        trace!("Got Token: {:#?}", &this.client_token);

        Ok(this)
    }

    /// create a new [`VaultConnection`] to Vault from an existing connection
    ///
    /// # Safety
    /// This function is unsafe, because it does not verify the attestation report.
    pub unsafe fn new_from_client_without_attestation(
        server: String,
        client: Client,
        name: String,
        client_token: String,
    ) -> Self {
        Self {
            name,
            client_token,
            conn: unsafe { TeeConnection::new_from_client_without_attestation(server, client) },
            key_hash: [0u8; 64],
        }
    }

    /// Get a reference to the agent, which can be used to make requests to the TEE
    ///
    /// Note, that it will refuse to connect to any other TLS server than the one
    /// specified in the `AttestationArgs` of the `Self::new` function.
    pub fn agent(&self) -> &Client {
        self.conn.client()
    }

    async fn auth(&self) -> Result<AuthResponse> {
        info!("Getting attestation report");
        let attestation_url = AuthRequest::URL;
        let quote = sgx_gramine_get_quote(&self.key_hash).context("Failed to get own quote")?;
        let collateral = tee_qv_get_collateral(&quote).context("Failed to get own collateral")?;

        let auth_req = AuthRequest {
            name: self.name.clone(),
            tee_type: "sgx".to_string(),
            quote,
            collateral: serde_json::to_string(&collateral)?,
            challenge: None,
        };

        let mut response = self
            .agent()
            .post(&format!(
                "{server}{attestation_url}",
                server = self.conn.server,
            ))
            .send_json(&auth_req)
            .await
            .map_err(|e| anyhow!("Error sending attestation request: {}", e))?;

        let status_code = response.status();
        if !status_code.is_success() {
            error!("Failed to login to vault: {}", status_code);
            if let Ok(r) = response.json::<Value>().await {
                eprintln!("Failed to login to vault: {}", r);
            }
            bail!("failed to login to vault: {}", status_code);
        }

        let auth_response: Value = response.json().await.context("failed to login to vault")?;
        trace!(
            "Got AuthResponse: {:?}",
            serde_json::to_string(&auth_response)
        );

        let auth_response: AuthResponse =
            serde_json::from_value(auth_response).context("Failed to parse AuthResponse")?;

        trace!("Got AuthResponse: {:#?}", &auth_response);

        Ok(auth_response)
    }

    /// Send a put request to the vault
    pub async fn vault_put(
        &self,
        action: &str,
        url: &str,
        json: &Value,
    ) -> std::result::Result<(StatusCode, Option<Value>), VaultSendError> {
        let full_url = format!("{}{url}", self.conn.server);
        info!("{action} via put {full_url}");
        debug!(
            "sending json: {:?}",
            serde_json::to_string(json).unwrap_or_default()
        );
        let res = self
            .agent()
            .put(full_url)
            .insert_header((VAULT_TOKEN_HEADER, self.client_token.clone()))
            .send_json(json)
            .await;
        Self::handle_client_response(action, res).await
    }

    /// Send a get request to the vault
    pub async fn vault_get(
        &self,
        action: &str,
        url: &str,
    ) -> std::result::Result<(StatusCode, Option<Value>), VaultSendError> {
        let full_url = format!("{}{url}", self.conn.server);
        info!("{action} via get {full_url}");
        let res = self
            .agent()
            .get(full_url)
            .insert_header((VAULT_TOKEN_HEADER, self.client_token.clone()))
            .send()
            .await;
        Self::handle_client_response(action, res).await
    }

    async fn handle_client_response<S>(
        action: &str,
        res: std::result::Result<ClientResponse<S>, SendRequestError>,
    ) -> std::result::Result<(StatusCode, Option<Value>), VaultSendError>
    where
        S: Stream<Item = Result<Bytes, PayloadError>>,
    {
        match res {
            Ok(mut r) => {
                let status_code = r.status();
                if status_code.is_success() {
                    let msg = r.json().await.ok();
                    debug!(
                        "{action}: status code: {status_code} {:?}",
                        serde_json::to_string(&msg)
                    );
                    Ok((status_code, msg))
                } else {
                    let err = HttpResponseError::from_proxy(r).await;
                    error!("{action}: {err:?}");
                    Err(err.into())
                }
            }
            Err(e) => {
                error!("{}: {}", action, e);
                Err(VaultSendError::SendRequest(e.to_string()))
            }
        }
    }

    /// Revoke the token
    pub async fn revoke_token(&self) -> std::result::Result<(), VaultSendError> {
        self.vault_put(
            "Revoke the token",
            "/v1/auth/token/revoke-self",
            &Value::default(),
        )
        .await?;
        Ok(())
    }

    fn check_rel_path(rel_path: &str) -> Result<(), HttpResponseError> {
        if !rel_path.is_ascii() {
            return Err(anyhow!("path is not ascii")).status(StatusCode::BAD_REQUEST);
        }

        // check if rel_path is alphanumeric
        if !rel_path
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '/')
        {
            return Err(anyhow!("path is not alphanumeric")).status(StatusCode::BAD_REQUEST);
        }

        Ok(())
    }

    /// set a secret in the vault
    pub async fn store_secret<'de, T: serde::Serialize>(
        &self,
        val: T,
        rel_path: &str,
    ) -> Result<(), HttpResponseError> {
        self.store_secret_for_tee(&self.name, val, rel_path).await
    }

    /// set a secret in the vault for a different TEE
    pub async fn store_secret_for_tee<'de, T: serde::Serialize>(
        &self,
        tee_name: &str,
        val: T,
        rel_path: &str,
    ) -> Result<(), HttpResponseError> {
        Self::check_rel_path(rel_path)?;

        let value = serde_json::to_value(val)
            .context("converting value to json")
            .status(StatusCode::INTERNAL_SERVER_ERROR)?;

        let value = json!({ "data" : { "_" : value } });

        self.vault_put(
            "Setting secret",
            &format!("/v1/secret/data/tee/{}/{}", tee_name, rel_path),
            &value,
        )
        .await?;
        Ok(())
    }

    /// get a secret from the vault
    pub async fn load_secret<'de, T: serde::de::DeserializeOwned>(
        &self,
        rel_path: &str,
    ) -> Result<Option<T>, HttpResponseError> {
        self.load_secret_for_tee(&self.name, rel_path).await
    }

    /// get a secret from the vault for a specific TEE
    pub async fn load_secret_for_tee<'de, T: serde::de::DeserializeOwned>(
        &self,
        tee_name: &str,
        rel_path: &str,
    ) -> Result<Option<T>, HttpResponseError> {
        Self::check_rel_path(rel_path)?;
        let v = self
            .vault_get(
                "Getting secret",
                &format!("/v1/secret/data/tee/{}/{}", tee_name, rel_path),
            )
            .await
            .or_else(|e| match e {
                VaultSendError::Vault(ref se) => {
                    if se.status_code() == StatusCode::NOT_FOUND {
                        debug!("Secret not found: {}", rel_path);
                        Ok((StatusCode::OK, None))
                    } else {
                        Err(e)
                    }
                }
                VaultSendError::SendRequest(_) => Err(e),
            })?
            .1
            .as_ref()
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("_"))
            .and_then(|v| serde_json::from_value(v.clone()).transpose())
            .transpose()
            .context("Error getting value from vault")
            .status(StatusCode::INTERNAL_SERVER_ERROR)?
            .flatten();
        Ok(v)
    }
}

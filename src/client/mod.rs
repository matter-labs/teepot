// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Helper functions for CLI clients to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod vault;

use crate::json::http::AttestationResponse;
use crate::sgx::Collateral;
pub use crate::sgx::{
    parse_tcb_levels, sgx_ql_qv_result_t, verify_quote_with_collateral, EnumSet,
    QuoteVerificationResult, TcbLevel,
};
use actix_web::http::header;
use anyhow::{anyhow, bail, Context, Result};
use awc::{Client, Connector};
use clap::Args;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time;
use std::time::Duration;
use tracing::{error, info, warn};
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::Certificate;

/// Options and arguments needed to attest a TEE
#[derive(Args, Debug, Clone)]
pub struct AttestationArgs {
    /// hex encoded SGX mrsigner of the enclave to attest
    #[arg(long)]
    pub sgx_mrsigner: Option<String>,
    /// hex encoded SGX mrenclave of the enclave to attest
    #[arg(long)]
    pub sgx_mrenclave: Option<String>,
    /// URL of the server
    #[arg(long, required = true)]
    pub server: String,
    /// allowed TCB levels, comma separated:
    /// Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded, OutOfDate, OutOfDateConfigNeeded
    #[arg(long, value_parser = parse_tcb_levels)]
    pub sgx_allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
}

/// A connection to a TEE, which implements the `teepot` attestation API
pub struct TeeConnection {
    /// Options and arguments needed to attest a TEE
    server: String,
    client: Client,
}

impl TeeConnection {
    /// Create a new connection to a TEE
    ///
    /// This will verify the attestation report and check that the enclave
    /// is running the expected code.
    pub async fn new(args: &AttestationArgs, attestation_url: &str) -> Result<Self> {
        let pk_hash = Arc::new(OnceLock::new());

        let tls_config = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Self::make_verifier(pk_hash.clone())))
                .with_no_client_auth(),
        );

        let agent = Client::builder()
            .add_default_header((header::USER_AGENT, "teepot/1.0"))
            // a "connector" wraps the stream into an encrypted connection
            .connector(Connector::new().rustls_0_22(tls_config))
            .timeout(Duration::from_secs(12000))
            .finish();

        let this = Self {
            server: args.server.clone(),
            client: agent,
        };

        this.check_attestation(args, attestation_url, pk_hash)
            .await?;

        Ok(this)
    }

    /// Create a new connection to a TEE
    ///
    /// # Safety
    /// This function is unsafe, because it does not verify the attestation report.
    pub unsafe fn new_from_client_without_attestation(server: String, client: Client) -> Self {
        Self { server, client }
    }

    /// Get a reference to the agent, which can be used to make requests to the TEE
    ///
    /// Note, that it will refuse to connect to any other TLS server than the one
    /// specified in the `AttestationArgs` of the `Self::new` function.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get a reference to the server URL
    pub fn server(&self) -> &str {
        &self.server
    }

    async fn check_attestation(
        &self,
        args: &AttestationArgs,
        attestation_url: &str,
        pk_hash: Arc<OnceLock<[u8; 32]>>,
    ) -> Result<()> {
        info!("Getting attestation report");

        let mut response = self
            .client
            .get(&format!("{}{attestation_url}", args.server))
            .send()
            .await
            .map_err(|e| anyhow!("Error sending attestation request: {}", e))?;

        let status_code = response.status();
        if !status_code.is_success() {
            error!("Failed to get attestation: {}", status_code);
            if let Ok(r) = response.json::<Value>().await {
                eprintln!("Failed to get attestation: {}", r);
            }
            bail!("failed to get attestation: {}", status_code);
        }

        let attestation: AttestationResponse =
            response.json().await.context("failed to get attestation")?;

        let current_time: i64 = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as _;

        info!("Verifying attestation report");

        let quote: &[u8] = &attestation.quote;
        let collateral: Option<&Collateral> = Some(&attestation.collateral);
        let pk_hash = pk_hash.get().unwrap();

        Self::check_attestation_args(args, current_time, quote, collateral, pk_hash)?;

        Ok(())
    }

    /// Check the attestation report against `AttestationArgs`
    pub fn check_attestation_args(
        args: &AttestationArgs,
        current_time: i64,
        quote: &[u8],
        collateral: Option<&Collateral>,
        pk_hash: &[u8; 32],
    ) -> Result<()> {
        let QuoteVerificationResult {
            collateral_expired,
            result,
            quote,
            advisories,
            ..
        } = verify_quote_with_collateral(quote, collateral, current_time).unwrap();

        if collateral_expired || !matches!(result, sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK) {
            if collateral_expired {
                error!("Collateral is out of date!");
                bail!("Collateral is out of date!");
            }

            let tcblevel = TcbLevel::from(result);
            if args
                .sgx_allowed_tcb_levels
                .map_or(true, |levels| !levels.contains(tcblevel))
            {
                error!("Quote verification result: {}", tcblevel);
                bail!("Quote verification result: {}", tcblevel);
            }

            info!("TcbLevel is allowed: {}", tcblevel);
        }

        for advisory in advisories {
            warn!("Info: Advisory ID: {advisory}");
        }

        if &quote.report_body.reportdata[..32] != pk_hash {
            error!("Report data mismatch");
            bail!("Report data mismatch");
        } else {
            info!(
                "Report data matches `{}`",
                hex::encode(&quote.report_body.reportdata[..32])
            );
        }

        if let Some(mrsigner) = &args.sgx_mrsigner {
            let mrsigner_bytes = hex::decode(mrsigner).context("Failed to decode mrsigner")?;
            if quote.report_body.mrsigner[..] != mrsigner_bytes {
                bail!(
                    "mrsigner mismatch: got {}, expected {}",
                    hex::encode(quote.report_body.mrsigner),
                    &mrsigner
                );
            } else {
                info!("mrsigner `{mrsigner}` matches");
            }
        }

        if let Some(mrenclave) = &args.sgx_mrenclave {
            let mrenclave_bytes = hex::decode(mrenclave).context("Failed to decode mrenclave")?;
            if quote.report_body.mrenclave[..] != mrenclave_bytes {
                bail!(
                    "mrenclave mismatch: got {}, expected {}",
                    hex::encode(quote.report_body.mrenclave),
                    &mrenclave
                );
            } else {
                info!("mrenclave `{mrenclave}` matches");
            }
        }
        Ok(())
    }

    /// Save the hash of the public server key to `REPORT_DATA` to check
    /// the attestations against it and it does not change on reconnect.
    pub fn make_verifier(pk_hash: Arc<OnceLock<[u8; 32]>>) -> impl ServerCertVerifier {
        #[derive(Debug)]
        struct V {
            pk_hash: Arc<OnceLock<[u8; 32]>>,
            server_verifier: Arc<WebPkiServerVerifier>,
        }
        impl ServerCertVerifier for V {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer,
                _intermediates: &[CertificateDer],
                _server_name: &ServerName,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                let cert = Certificate::from_der(end_entity.as_ref())
                    .map_err(|e| Error::General(format!("Failed get certificate {e:?}")))?;
                let pub_key = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .unwrap();

                let hash = Sha256::digest(pub_key);
                let data = self.pk_hash.get_or_init(|| hash[..32].try_into().unwrap());

                if data == &hash[..32] {
                    info!(
                        "Checked or set server certificate public key hash `{}`",
                        hex::encode(&hash[..32])
                    );
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    error!("Server certificate does not match expected certificate");
                    Err(rustls::Error::General(
                        "Server certificate does not match expected certificate".to_string(),
                    ))
                }
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, Error> {
                self.server_verifier
                    .verify_tls12_signature(message, cert, dss)
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, Error> {
                self.server_verifier
                    .verify_tls13_signature(message, cert, dss)
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.server_verifier.supported_verify_schemes()
            }
        }
        let root_store = Arc::new(rustls::RootCertStore::empty());
        let server_verifier = WebPkiServerVerifier::builder(root_store).build().unwrap();
        V {
            pk_hash,
            server_verifier,
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Helper functions for CLI clients to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod vault;

pub use crate::quote::verify_quote_with_collateral;
pub use crate::quote::QuoteVerificationResult;
use crate::quote::Report;
use crate::server::pki::{RaTlsCollateralExtension, RaTlsQuoteExtension};
use crate::sgx::Quote;
pub use crate::sgx::{parse_tcb_levels, sgx_ql_qv_result_t, EnumSet, TcbLevel};
use actix_web::http::header;
use anyhow::Result;
use awc::{Client, Connector};
use clap::Args;
use const_oid::AssociatedOid;
use intel_tee_quote_verification_rs::Collateral;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};
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
    pub fn new(args: &AttestationArgs) -> Self {
        let tls_config = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Self::make_verifier(args.clone())))
                .with_no_client_auth(),
        );

        let agent = Client::builder()
            .add_default_header((header::USER_AGENT, "teepot/1.0"))
            // a "connector" wraps the stream into an encrypted connection
            .connector(Connector::new().rustls_0_22(tls_config))
            .timeout(Duration::from_secs(12000))
            .finish();

        Self {
            server: args.server.clone(),
            client: agent,
        }
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

    /// Save the hash of the public server key to `REPORT_DATA` to check
    /// the attestations against it and it does not change on reconnect.
    pub fn make_verifier(args: AttestationArgs) -> impl ServerCertVerifier {
        #[derive(Debug)]
        struct V {
            args: AttestationArgs,
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

                let exts = cert
                    .tbs_certificate
                    .extensions
                    .ok_or_else(|| Error::General("Failed get quote in certificate".into()))?;

                trace!("Get quote bytes!");

                let quote_bytes = exts
                    .iter()
                    .find(|ext| ext.extn_id == RaTlsQuoteExtension::OID)
                    .ok_or_else(|| Error::General("Failed get quote in certificate".into()))?
                    .extn_value
                    .as_bytes();

                trace!("Get collateral bytes!");

                let collateral = exts
                    .iter()
                    .find(|ext| ext.extn_id == RaTlsCollateralExtension::OID)
                    .and_then(|ext| {
                        serde_json::from_slice::<Collateral>(ext.extn_value.as_bytes())
                            .map_err(|e| {
                                debug!("Failed to get collateral in certificate {e:?}");
                                trace!(
                                    "Failed to get collateral in certificate {:?}",
                                    String::from_utf8_lossy(ext.extn_value.as_bytes())
                                );
                            })
                            .ok()
                    });

                if collateral.is_none() {
                    debug!("Failed to get collateral in certificate");
                }

                let quote = Quote::try_from_bytes(quote_bytes).map_err(|e| {
                    Error::General(format!("Failed get quote in certificate {e:?}"))
                })?;

                if &quote.report_body.reportdata[..32] != hash.as_slice() {
                    error!("Report data mismatch");
                    return Err(Error::General("Report data mismatch".to_string()));
                } else {
                    info!(
                        "Report data matches `{}`",
                        hex::encode(&quote.report_body.reportdata[..32])
                    );
                }

                let current_time: i64 = time::SystemTime::now()
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as _;

                let QuoteVerificationResult {
                    collateral_expired,
                    result,
                    quote,
                    advisories,
                    earliest_expiration_date,
                    ..
                } = verify_quote_with_collateral(quote_bytes, collateral.as_ref(), current_time)
                    .unwrap();

                let Report::SgxEnclave(report_body) = quote.report else {
                    return Err(Error::General("TDX quote and not SGX quote".into()));
                };

                if collateral_expired || result != sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK {
                    if collateral_expired {
                        error!(
                            "Collateral is out of date! Expired {}",
                            earliest_expiration_date
                        );
                        return Err(Error::General(format!(
                            "Collateral is out of date! Expired {}",
                            earliest_expiration_date
                        )));
                    }

                    let tcblevel = TcbLevel::from(result);
                    if self
                        .args
                        .sgx_allowed_tcb_levels
                        .map_or(true, |levels| !levels.contains(tcblevel))
                    {
                        error!("Quote verification result: {}", tcblevel);
                        return Err(Error::General(format!(
                            "Quote verification result: {}",
                            tcblevel
                        )));
                    }

                    info!("TcbLevel is allowed: {}", tcblevel);
                }

                for advisory in advisories {
                    warn!("Info: Advisory ID: {advisory}");
                }

                if let Some(mrsigner) = &self.args.sgx_mrsigner {
                    let mrsigner_bytes = hex::decode(mrsigner)
                        .map_err(|e| Error::General(format!("Failed to decode mrsigner: {}", e)))?;
                    if report_body.mr_signer[..] != mrsigner_bytes {
                        return Err(Error::General(format!(
                            "mrsigner mismatch: got {}, expected {}",
                            hex::encode(report_body.mr_signer),
                            &mrsigner
                        )));
                    } else {
                        info!("mrsigner `{mrsigner}` matches");
                    }
                }

                if let Some(mrenclave) = &self.args.sgx_mrenclave {
                    let mrenclave_bytes = hex::decode(mrenclave).map_err(|e| {
                        Error::General(format!("Failed to decode mrenclave: {}", e))
                    })?;
                    if report_body.mr_enclave[..] != mrenclave_bytes {
                        return Err(Error::General(format!(
                            "mrenclave mismatch: got {}, expected {}",
                            hex::encode(report_body.mr_enclave),
                            &mrenclave
                        )));
                    } else {
                        info!("mrenclave `{mrenclave}` matches");
                    }
                }

                Ok(rustls::client::danger::ServerCertVerified::assertion())
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
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let server_verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .unwrap();

        V {
            args,
            server_verifier,
        }
    }
}

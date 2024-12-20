// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Common attestation API for all TEEs

use crate::{
    client::AttestationArgs,
    json::http::AttestationResponse,
    quote::{
        error::QuoteContext, get_quote, verify_quote_with_collateral, QuoteVerificationResult,
    },
    sgx::{parse_tcb_levels, Collateral, EnumSet, TcbLevel},
};
use anyhow::{bail, Context, Result};
use clap::Args;
use intel_tee_quote_verification_rs::tee_qv_get_collateral;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, UNIX_EPOCH},
};
use tracing::{debug, error, info, trace, warn};

struct Attestation {
    quote: Arc<[u8]>,
    collateral: Arc<Collateral>,
    report_data: [u8; 64],
    earliest_expiration_date: i64,
}

/// Returns the quote and collateral for the current TEE.
///
/// if `allowed_tcb_levels` is `None`, then any TCB level is accepted.
/// Otherwise, the quote must be verified and the collateral must be
/// within the allowed TCB levels.
pub fn get_quote_and_collateral(
    allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
    report_data: &[u8; 64],
) -> Result<AttestationResponse> {
    static ATTESTATION: RwLock<Option<Attestation>> = RwLock::new(None);

    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as _;

    if let Some(attestation) = ATTESTATION.read().unwrap().as_ref() {
        trace!(attestation.earliest_expiration_date);

        if attestation.earliest_expiration_date > unix_time.saturating_add(60)
            && report_data.eq(&attestation.report_data)
        {
            debug!("return cache attestation quote and collateral");
            return Ok(AttestationResponse {
                quote: attestation.quote.clone(),
                collateral: attestation.collateral.clone(),
            });
        }
    }

    let (_tee_type, myquote) = get_quote(report_data).context("Failed to get own quote")?;
    let collateral = tee_qv_get_collateral(&myquote).context("Failed to get own collateral")?;

    let QuoteVerificationResult {
        collateral_expired,
        result,
        earliest_expiration_date,
        tcb_level_date_tag,
        quote,
        advisories,
    } = verify_quote_with_collateral(&myquote, Some(&collateral), unix_time.saturating_add(60))
        .context("Failed to verify own quote with collateral")?;

    debug!(tcb_level_date_tag);

    if collateral_expired {
        bail!("Freshly fetched collateral expired");
    }

    let tcblevel = TcbLevel::from(result);
    if tcblevel != TcbLevel::Ok
        && allowed_tcb_levels.map_or(false, |levels| !levels.contains(tcblevel))
    {
        error!("Quote verification result: {}", tcblevel);
        bail!("Quote verification result: {}", tcblevel);
    }

    for advisory in advisories {
        warn!("\tInfo: Advisory ID: {advisory}");
    }

    info!("Own quote verified successfully: {}", tcblevel);
    info!(
        "Earliest expiration in {:?}",
        Duration::from_secs((earliest_expiration_date - unix_time) as _)
    );

    info!("{:#}", quote.report);

    let quote: Arc<[u8]> = Arc::from(myquote);
    let collateral = Arc::from(collateral);

    let mut attestation = ATTESTATION.write().unwrap();
    *attestation = Some(Attestation {
        quote: quote.clone(),
        collateral: collateral.clone(),
        report_data: *report_data,
        earliest_expiration_date,
    });

    Ok(AttestationResponse { quote, collateral })
}

/// Options and arguments needed to attest a TEE
#[derive(Args, Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultAttestationArgs {
    /// hex encoded SGX mrsigner of the enclave to attest
    #[arg(long, env = "VAULT_SGX_MRSIGNER")]
    pub vault_sgx_mrsigner: Option<String>,
    /// hex encoded SGX mrenclave of the enclave to attest
    #[arg(long, env = "VAULT_SGX_MRENCLAVE")]
    pub vault_sgx_mrenclave: Option<String>,
    /// URL of the server
    #[arg(long, required = true, env = "VAULT_ADDR")]
    pub vault_addr: String,
    /// allowed TCB levels, comma separated:
    /// Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded, OutOfDate, OutOfDateConfigNeeded
    #[arg(long, value_parser = parse_tcb_levels, env = "VAULT_SGX_ALLOWED_TCB_LEVELS")]
    pub vault_sgx_allowed_tcb_levels: Option<EnumSet<TcbLevel>>,
}

impl From<VaultAttestationArgs> for AttestationArgs {
    fn from(value: VaultAttestationArgs) -> Self {
        AttestationArgs {
            sgx_mrsigner: value.vault_sgx_mrsigner,
            sgx_mrenclave: value.vault_sgx_mrenclave,
            server: value.vault_addr,
            sgx_allowed_tcb_levels: value.vault_sgx_allowed_tcb_levels,
        }
    }
}

impl From<&VaultAttestationArgs> for AttestationArgs {
    fn from(value: &VaultAttestationArgs) -> Self {
        AttestationArgs {
            sgx_mrsigner: value.vault_sgx_mrsigner.clone(),
            sgx_mrenclave: value.vault_sgx_mrenclave.clone(),
            server: value.vault_addr.clone(),
            sgx_allowed_tcb_levels: value.vault_sgx_allowed_tcb_levels,
        }
    }
}

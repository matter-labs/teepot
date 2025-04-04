// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Common attestation API for all TEEs

use crate::quote::{
    error::QuoteContext,
    get_quote,
    tcblevel::{EnumSet, TcbLevel},
    verify_quote_with_collateral, Collateral, QuoteVerificationResult,
};
use anyhow::{bail, Context, Result};
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

/// The attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// The quote
    pub quote: Arc<[u8]>,
    /// The collateral
    pub collateral: Arc<Collateral>,
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

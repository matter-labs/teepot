// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Emulate Intel DCAP library collateral and verification
//!
use crate::quote::error::{QuoteContext, QuoteContextErr, QuoteError};
use crate::quote::tcblevel::TcbLevel;
use crate::quote::{Collateral, Quote, QuoteVerificationResult, TEEType};
use bytes::Bytes;
use dcap_qvl::verify::VerifiedReport;
use dcap_qvl::QuoteCollateralV3;
use std::str::FromStr;

async fn get_collateral_from_pcs(
    quote: &[u8],
) -> Result<(QuoteCollateralV3, String, Bytes), QuoteError> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform")
        .send()
        .await
        .map_err(|e| QuoteError::Unexpected(format!("Failed to fetch collateral: {e}")))?;

    let issuer_chain = response
        .headers()
        .get("SGX-PCK-CRL-Issuer-Chain")
        .ok_or(QuoteError::Unexpected(
            "Missing SGX-PCK-CRL-Issuer-Chain header".into(),
        ))?
        .to_str()
        .map_err(|e| QuoteError::Unexpected(format!("Invalid header value: {e}")))?
        .to_string();

    let pck_crl = response
        .bytes()
        .await
        .map_err(|e| QuoteError::Unexpected(format!("Failed to fetch collateral: {e}")))?;

    dcap_qvl::collateral::get_collateral_from_pcs(quote, std::time::Duration::from_secs(1000))
        .await
        .map(|res| (res, issuer_chain, pck_crl))
        .str_context("get_collateral")
}

pub(crate) fn get_collateral(quote: &[u8]) -> Result<Collateral, QuoteError> {
    let quote_owned = quote.to_vec();

    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("get_collateral")?;

        // Call the asynchronous connect method using the runtime.
        let collateral = rt.block_on(get_collateral_from_pcs(&quote_owned))?;
        Ok::<_, QuoteError>(collateral)
    });

    let (collateral, pck_crl, pck_issuer_chain) = match join.join() {
        Ok(res) => res?,
        Err(e) => {
            if let Some(e) = e.downcast_ref::<&str>() {
                return Err(QuoteError::Unexpected(e.to_string()));
            }
            return Err(QuoteError::Unexpected("get_collateral panic".into()));
        }
    };

    let QuoteCollateralV3 {
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
    } = collateral;

    let tcb_info_signature = hex::encode(tcb_info_signature);
    let qe_identity_signature = hex::encode(qe_identity_signature);

    // best effort
    Ok(Collateral {
        // unhandled
        major_version: 0,
        // unhandled
        minor_version: 0,
        // unhandled
        tee_type: 0,
        // unhandled
        pck_crl_issuer_chain: pck_issuer_chain.as_ref().into(),
        // unhandled
        root_ca_crl: Box::new([]),
        // unhandled
        pck_crl: pck_crl.as_bytes().into(),
        tcb_info_issuer_chain: tcb_info_issuer_chain.as_bytes().into(),
        tcb_info: format!(
            "{{ \"tcbInfo\": {tcb_info}, \"signature\": \"{tcb_info_signature}\" }} "
        )
        .as_bytes()
        .into(),
        qe_identity_issuer_chain: qe_identity_issuer_chain.as_bytes().into(),
        qe_identity: format!(
            "{{ \"enclaveIdentity\": {qe_identity}, \"signature\": \"{qe_identity_signature}\" }} "
        )
        .as_bytes()
        .into(),
    })
}

fn convert_collateral(collateral: &Collateral) -> Result<QuoteCollateralV3, QuoteError> {
    let tcb_info_json: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(
        collateral.tcb_info.as_ref().split_last().unwrap().1,
    ))
    .str_context("convert_collateral: tcb_info_json")?;

    let tcb_info = tcb_info_json["tcbInfo"].to_string();

    let tcb_info_signature = tcb_info_json
        .get("signature")
        .context("convert_collateral: TCB Info missing 'signature' field")?
        .as_str()
        .context("convert_collateral: TCB Info signature must be a string")?;
    let tcb_info_signature = hex::decode(tcb_info_signature)
        .ok()
        .context("convert_collateral: TCB Info signature must be valid hex")?;

    let qe_identity_json: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(
        collateral.qe_identity.as_ref().split_last().unwrap().1,
    ))
    .str_context("convert_collateral: QE Identity should be valid JSON")?;

    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .context("convert_collateral: QE Identity missing 'enclaveIdentity' field")?
        .to_string();

    let qe_identity_signature = qe_identity_json
        .get("signature")
        .context("convert_collateral: QE Identity missing 'signature' field")?
        .as_str()
        .context("convert_collateral: QE Identity signature must be a string")?;
    let qe_identity_signature = hex::decode(qe_identity_signature)
        .ok()
        .context("convert_collateral: QE Identity signature must be valid hex")?;

    Ok(QuoteCollateralV3 {
        tcb_info_issuer_chain: String::from_utf8_lossy(collateral.tcb_info_issuer_chain.as_ref())
            .to_string(),
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain: String::from_utf8_lossy(
            collateral.tcb_info_issuer_chain.as_ref(),
        )
        .to_string(),
        qe_identity: qe_identity.to_string(),
        qe_identity_signature,
    })
}
pub(crate) fn verify_quote_with_collateral(
    quote: &[u8],
    collateral: Option<&Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult, QuoteError> {
    let collateral = collateral
        .ok_or(QuoteError::Unexpected("No".into()))
        .and_then(convert_collateral)?;

    let verified_report = dcap_qvl::verify::verify(
        quote,
        &collateral,
        current_time
            .try_into()
            .str_context("verify_quote_with_collateral: verify")?,
    )
    .expect("verify_quote_with_collateral: failed to verify quote");

    let VerifiedReport {
        status,
        advisory_ids,
        report: _,
    } = verified_report;

    let result =
        TcbLevel::from_str(&status).str_context("verify_quote_with_collateral: TcbLevel")?;

    let quote = Quote::parse(quote)?;

    let tcb_info_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(collateral.tcb_info.as_ref()))
            .str_context("verify_quote_with_collateral tcb_info_json")?;

    let next_update = tcb_info_json
        .get("nextUpdate")
        .context("verify_quote_with_collateral: TCB Info missing 'nextUpdate' field")?
        .as_str()
        .context("verify_quote_with_collateral: TCB Info nextUpdate must be a string")?;

    let next_update = chrono::DateTime::parse_from_rfc3339(next_update)
        .ok()
        .context("verify_quote_with_collateral: Failed to parse next update")?;

    Ok(QuoteVerificationResult {
        result,
        collateral_expired: result == TcbLevel::OutOfDate,
        earliest_expiration_date: next_update
            .signed_duration_since(chrono::DateTime::UNIX_EPOCH)
            .num_seconds(),
        tcb_level_date_tag: 0,
        advisories: advisory_ids,
        quote,
    })
}

/// Get the attestation quote from a TEE
pub fn get_quote(_report_data: &[u8]) -> Result<(TEEType, Box<[u8]>), QuoteError> {
    Err(QuoteError::UnknownTee)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Emulate Intel DCAP library collateral and verification

use crate::quote::{
    error::{QuoteContext, QuoteContextErr, QuoteError},
    tcblevel::TcbLevel,
    Collateral, Quote, QuoteVerificationResult, TEEType,
};
use bytes::Bytes;
use dcap_qvl::{verify::VerifiedReport, QuoteCollateralV3};
use std::ffi::{CStr, CString};
use std::str::FromStr;

/// Helper function to extract a required header value from a response
fn extract_header_value(
    response: &reqwest::Response,
    header_name: &str,
) -> Result<String, QuoteError> {
    response
        .headers()
        .get(header_name)
        .ok_or_else(|| QuoteError::Unexpected(format!("Missing required header: {header_name}")))?
        .to_str()
        .map_err(|e| QuoteError::Unexpected(format!("Invalid header value: {e}")))
        .map(str::to_string)
}

/// Fetch collateral data from Intel's Provisioning Certification Service
async fn fetch_pcs_collateral(
    quote: &[u8],
) -> Result<(QuoteCollateralV3, String, Bytes), QuoteError> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform")
        .send()
        .await
        .map_err(|e| QuoteError::Unexpected(format!("Failed to fetch collateral: {e}")))?;

    // Extract required fields
    let issuer_chain = extract_header_value(&response, "SGX-PCK-CRL-Issuer-Chain")?;
    let pck_crl_data = response
        .bytes()
        .await
        .map_err(|e| QuoteError::Unexpected(format!("Failed to fetch collateral data: {e}")))?;

    // Fetch the full collateral
    dcap_qvl::collateral::get_collateral_from_pcs(quote, std::time::Duration::from_secs(1000))
        .await
        .map(|collateral| (collateral, issuer_chain, pck_crl_data))
        .str_context("Fetching PCS collateral with `get_collateral_from_pcs`")
}

/// Get collateral for a quote, handling the async operations
pub(crate) fn get_collateral(quote: &[u8]) -> Result<Collateral, QuoteError> {
    // Execute the async operation in a separate thread
    let result = std::thread::scope(|s| {
        s.spawn(|| {
            // Create a minimal runtime for this thread only
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to build tokio runtime")?;

            // Run the async function
            rt.block_on(fetch_pcs_collateral(quote))
        })
        .join()
        .map_err(|_| QuoteError::Unexpected("Thread panic in get_collateral".into()))
    })??;

    // Destructure the result
    let (collateral, pck_crl, pck_issuer_chain) = result;

    // Convert QuoteCollateralV3 to Collateral
    convert_to_collateral(collateral, &pck_crl, &pck_issuer_chain)
}

// Helper function to convert QuoteCollateralV3 to Collateral
fn convert_to_collateral(
    collateral: QuoteCollateralV3,
    pck_crl: &str,
    pck_issuer_chain: &[u8],
) -> Result<Collateral, QuoteError> {
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

    // Create strings with proper formatting
    let tcb_info_json =
        format!("{{ \"tcbInfo\": {tcb_info}, \"signature\": \"{tcb_info_signature}\" }}");

    let qe_identity_json = format!(
        "{{ \"enclaveIdentity\": {qe_identity}, \"signature\": \"{qe_identity_signature}\" }}"
    );

    // Helper to create CString and convert to Box<[u8]>
    let to_bytes_with_nul = |s: String, context: &str| -> Result<Box<[u8]>, QuoteError> {
        Ok(CString::new(s)
            .str_context(context)?
            .as_bytes_with_nul()
            .into())
    };

    Ok(Collateral {
        // Default/unhandled values
        major_version: 0,
        minor_version: 0,
        tee_type: 0,
        root_ca_crl: Box::new([]),

        // Converted values
        pck_crl_issuer_chain: pck_issuer_chain.into(),
        pck_crl: pck_crl.as_bytes().into(),
        tcb_info_issuer_chain: to_bytes_with_nul(tcb_info_issuer_chain, "tcb_info_issuer_chain")?,
        tcb_info: to_bytes_with_nul(tcb_info_json, "tcb_info")?,
        qe_identity_issuer_chain: to_bytes_with_nul(
            qe_identity_issuer_chain,
            "qe_identity_issuer_chain",
        )?,
        qe_identity: to_bytes_with_nul(qe_identity_json, "qe_identity")?,
    })
}

/// Split the last zero byte
fn get_str_from_bytes(bytes: &[u8], context: &str) -> Result<String, QuoteError> {
    let c_str = CStr::from_bytes_until_nul(bytes)
        .str_context(format!("Failed to extract CString: {context}"))?;
    Ok(c_str.to_string_lossy().into_owned())
}

/// Parse JSON field from collateral data
fn parse_json_field(data: &[u8], context: &str) -> Result<serde_json::Value, QuoteError> {
    serde_json::from_str(&get_str_from_bytes(data, context)?)
        .str_context(format!("Failed to parse JSON: {context}"))
}

/// Convert Collateral to QuoteCollateralV3
fn convert_collateral(collateral: &Collateral) -> Result<QuoteCollateralV3, QuoteError> {
    // Parse TCB info
    let tcb_info_json = parse_json_field(collateral.tcb_info.as_ref(), "tcb_info_json")?;

    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json
        .get("signature")
        .context("TCB Info missing 'signature' field")?
        .as_str()
        .context("TCB Info signature must be a string")?;

    let tcb_info_signature = hex::decode(tcb_info_signature)
        .ok()
        .context("TCB Info signature must be valid hex")?;

    // Parse QE identity
    let qe_identity_json = parse_json_field(collateral.qe_identity.as_ref(), "qe_identity_json")?;

    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .context("QE Identity missing 'enclaveIdentity' field")?
        .to_string();

    let qe_identity_signature = qe_identity_json
        .get("signature")
        .context("QE Identity missing 'signature' field")?
        .as_str()
        .context("QE Identity signature must be a string")?;

    let qe_identity_signature = hex::decode(qe_identity_signature)
        .ok()
        .context("QE Identity signature must be valid hex")?;

    Ok(QuoteCollateralV3 {
        tcb_info_issuer_chain: get_str_from_bytes(
            collateral.tcb_info_issuer_chain.as_ref(),
            "convert_collateral: tcb_info_issuer_chain",
        )?,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain: get_str_from_bytes(
            collateral.qe_identity_issuer_chain.as_ref(),
            "convert_collateral: qe_identity_issuer_chain",
        )?,
        qe_identity,
        qe_identity_signature,
    })
}

/// Verify a quote with the provided collateral
pub(crate) fn verify_quote_with_collateral(
    quote: &[u8],
    collateral: Option<&Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult, QuoteError> {
    // Convert collateral or return error if not provided
    let collateral = collateral
        .ok_or_else(|| QuoteError::Unexpected("No collateral provided".into()))
        .and_then(convert_collateral)?;

    // Convert current time to u64
    let current_time_u64 = current_time
        .try_into()
        .str_context("Failed to convert current_time to u64")?;

    // Verify the quote
    let verified_report = dcap_qvl::verify::verify(quote, &collateral, current_time_u64)
        .expect("Failed to verify quote");

    let VerifiedReport {
        status,
        advisory_ids,
        report: _,
    } = verified_report;

    // Parse TCB level from status
    let result =
        TcbLevel::from_str(&status).str_context("Failed to parse TCB level from status")?;

    // Parse quote
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

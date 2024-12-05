// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Get a quote from a TEE

use crate::sgx::{sgx_gramine_get_quote, Quote3Error};
use crate::tdx::tgx_get_quote;
use bytemuck::cast_slice;
pub use dcap_qvl::quote::Report;
use intel_tee_quote_verification_rs::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t,
    tee_get_supplemental_data_version_and_size, tee_supp_data_descriptor_t, tee_verify_quote,
    Collateral,
};
use std::ffi::CStr;
use std::{io, mem};
use tracing::{error, trace, warn};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[error("{msg}")]
pub struct GetQuoteError {
    pub(crate) msg: Box<str>,
    #[source] // optional if field name is `source`
    pub(crate) source: io::Error,
}

/// Helper trait to get the report data from TEE quotes
pub trait GetReportData {
    /// Get the report data from TEE quotes
    fn get_report_data(&self) -> &[u8];
}

impl GetReportData for dcap_qvl::quote::Quote {
    fn get_report_data(&self) -> &[u8] {
        match &self.report {
            Report::SgxEnclave(r) => r.report_data.as_slice(),
            Report::TD10(r) => r.report_data.as_slice(),
            Report::TD15(r) => r.base.report_data.as_slice(),
        }
    }
}

/// Get the attestation quote from a TEE
pub fn get_quote(report_data: &[u8]) -> Result<Box<[u8]>, GetQuoteError> {
    // check, if we are running in a TEE
    if std::fs::metadata("/dev/attestation").is_ok() {
        if report_data.len() > 64 {
            return Err(GetQuoteError {
                msg: "Report data too long".into(),
                source: io::Error::new(io::ErrorKind::Other, "Report data too long"),
            });
        }

        let mut report_data_fixed = [0u8; 64];
        report_data_fixed[..report_data.len()].copy_from_slice(report_data);

        sgx_gramine_get_quote(&report_data_fixed)
    } else if std::fs::metadata("/dev/tdx_guest").is_ok() {
        if report_data.len() > 64 {
            return Err(GetQuoteError {
                msg: "Report data too long".into(),
                source: io::Error::new(io::ErrorKind::Other, "Report data too long"),
            });
        }

        let mut report_data_fixed = [0u8; 64];
        report_data_fixed[..report_data.len()].copy_from_slice(report_data);

        tgx_get_quote(&report_data_fixed)
    } else {
        // if not, return an error
        Err(GetQuoteError {
            msg: "Not running in a TEE".into(),
            source: io::Error::new(io::ErrorKind::Other, "Not running in a TEE"),
        })
    }
}

/// Wrapper func for error
/// TODO: move to intel_tee_quote_verification_rs
pub fn tee_qv_get_collateral(quote: &[u8]) -> Result<Collateral, Quote3Error> {
    intel_tee_quote_verification_rs::tee_qv_get_collateral(quote).map_err(Into::into)
}

/// The result of the quote verification
pub struct QuoteVerificationResult {
    /// the raw result
    pub result: sgx_ql_qv_result_t,
    /// indicates if the collateral is expired
    pub collateral_expired: bool,
    /// the earliest expiration date of the collateral
    pub earliest_expiration_date: i64,
    /// Date of the TCB level
    pub tcb_level_date_tag: i64,
    /// the advisory string
    pub advisories: Vec<String>,
    /// the quote
    pub quote: dcap_qvl::quote::Quote,
}

/// Verifies a quote with optional collateral material
pub fn verify_quote_with_collateral(
    quote: &[u8],
    collateral: Option<&Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult, Quote3Error> {
    let mut supp_data: mem::MaybeUninit<sgx_ql_qv_supplemental_t> = mem::MaybeUninit::zeroed();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: supp_data.as_mut_ptr() as *mut u8,
    };
    trace!("tee_get_supplemental_data_version_and_size");
    let (_, supp_size) =
        tee_get_supplemental_data_version_and_size(quote).map_err(|e| Quote3Error {
            msg: "tee_get_supplemental_data_version_and_size".into(),
            inner: e,
        })?;

    trace!(
        "tee_get_supplemental_data_version_and_size supp_size: {}",
        supp_size
    );

    if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
        supp_data_desc.data_size = supp_size;
    } else {
        supp_data_desc.data_size = 0;
        trace!(
            "tee_get_supplemental_data_version_and_size supp_size: {}",
            supp_size
        );
        trace!(
            "mem::size_of::<sgx_ql_qv_supplemental_t>(): {}",
            mem::size_of::<sgx_ql_qv_supplemental_t>()
        );
        warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
    }

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    let has_sup = p_supplemental_data.is_some();

    trace!("tee_verify_quote");

    let (collateral_expiration_status, result) =
        tee_verify_quote(quote, collateral, current_time, None, p_supplemental_data).map_err(
            |e| Quote3Error {
                msg: "tee_verify_quote".into(),
                inner: e,
            },
        )?;

    trace!("check adv");

    // check supplemental data if necessary
    let (advisories, earliest_expiration_date, tcb_level_date_tag) = if has_sup {
        unsafe {
            let supp_data = supp_data.assume_init();
            // convert to valid UTF-8 string
            let ads = CStr::from_bytes_until_nul(cast_slice(&supp_data.sa_list[..]))
                .ok()
                .and_then(|s| CStr::to_str(s).ok())
                .into_iter()
                .flat_map(|s| s.split(',').map(str::trim).map(String::from))
                .filter(|s| !s.is_empty())
                .collect();
            (
                ads,
                supp_data.earliest_expiration_date,
                supp_data.tcb_level_date_tag,
            )
        }
    } else {
        (vec![], 0, 0)
    };

    trace!("quote");
    let quote = dcap_qvl::quote::Quote::parse(quote).map_err(|e| Quote3Error {
        msg: format!("dcap_qvl::quote::Quote::parse: {e:?}"),
        inner: quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED,
    })?;

    let res = QuoteVerificationResult {
        collateral_expired: collateral_expiration_status != 0,
        earliest_expiration_date,
        tcb_level_date_tag,
        result,
        quote,
        advisories,
    };

    Ok(res)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

/// Drive Intel DCAP verification crate, which is using the C library
use crate::quote::{
    error::QuoteError, tcblevel::TcbLevel, Collateral, Quote, QuoteVerificationResult, TEEType,
};
use crate::sgx::sgx_gramine_get_quote;
use bytemuck::cast_slice;
use std::{ffi::CStr, mem};
use tdx_attest_rs::{tdx_att_get_quote, tdx_attest_error_t, tdx_report_data_t};
use teepot_tee_quote_verification_rs::{
    quote3_error_t as _quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t,
    tee_get_supplemental_data_version_and_size, tee_qv_get_collateral, tee_supp_data_descriptor_t,
    tee_verify_quote,
};
use tracing::{trace, warn};

fn sgx_ql_qv_result_t_conv(value: sgx_ql_qv_result_t) -> TcbLevel {
    match value {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => TcbLevel::Ok,
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => TcbLevel::OutOfDate,
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
            TcbLevel::OutOfDateConfigNeeded
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => TcbLevel::SwHardeningNeeded,
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            TcbLevel::ConfigAndSwHardeningNeeded
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => TcbLevel::ConfigNeeded,
        _ => TcbLevel::Invalid,
    }
}

fn quote3_error_t_conv(e: _quote3_error_t, context: impl Into<String>) -> QuoteError {
    let context = context.into();
    match e {
        _quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => QuoteError::InvalidParameter(context),
        _quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => QuoteError::PckCertChainError(context),
        _quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => {
            QuoteError::PckCertUnsupportedFormat(context)
        }
        _quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => {
            QuoteError::QuoteFormatUnsupported(context)
        }
        _quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => QuoteError::OutOfMemory(context),
        _quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => {
            QuoteError::NoQuoteCollateralData(context)
        }
        _quote3_error_t::SGX_QL_ERROR_UNEXPECTED => QuoteError::Unexpected(context),
        _quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => {
            QuoteError::QuoteCertificationDataUnsupported(context)
        }
        _quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => {
            QuoteError::UnableToGenerateReport(context)
        }
        _quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => QuoteError::CrlUnsupportedFormat(context),
        _ => QuoteError::Unexpected(context),
    }
}

pub fn get_collateral(quote: &[u8]) -> Result<crate::quote::Collateral, QuoteError> {
    let collateral = tee_qv_get_collateral(quote)
        .map_err(|e| quote3_error_t_conv(e, "tee_qv_get_collateral"))?;
    Ok(Collateral {
        major_version: collateral.major_version,
        minor_version: collateral.minor_version,
        tee_type: collateral.tee_type,
        pck_crl_issuer_chain: collateral.pck_crl_issuer_chain,
        root_ca_crl: collateral.root_ca_crl,
        pck_crl: collateral.pck_crl,
        tcb_info_issuer_chain: collateral.tcb_info_issuer_chain,
        tcb_info: collateral.tcb_info,
        qe_identity_issuer_chain: collateral.qe_identity_issuer_chain,
        qe_identity: collateral.qe_identity,
    })
}

/// Verifies a quote with optional collateral material
pub(crate) fn verify_quote_with_collateral(
    quote: &[u8],
    collateral: Option<&crate::quote::Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult, QuoteError> {
    let collateral = collateral.map(|c| {
        let c = c.clone();
        teepot_tee_quote_verification_rs::Collateral {
            major_version: c.major_version,
            minor_version: c.minor_version,
            tee_type: c.tee_type,
            pck_crl_issuer_chain: c.pck_crl_issuer_chain,
            root_ca_crl: c.root_ca_crl,
            pck_crl: c.pck_crl,
            tcb_info_issuer_chain: c.tcb_info_issuer_chain,
            tcb_info: c.tcb_info,
            qe_identity_issuer_chain: c.qe_identity_issuer_chain,
            qe_identity: c.qe_identity,
        }
    });

    let mut supp_data: mem::MaybeUninit<sgx_ql_qv_supplemental_t> = mem::MaybeUninit::zeroed();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: supp_data.as_mut_ptr() as *mut u8,
    };
    trace!("tee_get_supplemental_data_version_and_size");
    let (_, supp_size) = tee_get_supplemental_data_version_and_size(quote)
        .map_err(|e| quote3_error_t_conv(e, "tee_get_supplemental_data_version_and_size"))?;

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

    let (collateral_expiration_status, result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        p_supplemental_data,
    )
    .map_err(|e| quote3_error_t_conv(e, "tee_verify_quote"))?;

    trace!("tee_verify_quote end");

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

    trace!("Quote::parse");
    let quote = Quote::parse(quote)?;

    let res = QuoteVerificationResult {
        collateral_expired: collateral_expiration_status != 0,
        earliest_expiration_date,
        tcb_level_date_tag,
        result: sgx_ql_qv_result_t_conv(result),
        quote,
        advisories,
    };

    Ok(res)
}

/// Get a TDX quote
fn tgx_get_quote(report_data_bytes: &[u8; 64]) -> Result<Box<[u8]>, QuoteError> {
    let mut tdx_report_data = tdx_report_data_t { d: [0; 64usize] };
    tdx_report_data.d.copy_from_slice(report_data_bytes);

    let (error, quote) = tdx_att_get_quote(Some(&tdx_report_data), None, None, 0);

    if error == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        if let Some(quote) = quote {
            Ok(quote.into())
        } else {
            Err(QuoteError::TdxAttGetQuote {
                msg: "tdx_att_get_quote: No quote returned".into(),
                inner: error,
            })
        }
    } else {
        Err(error.into())
    }
}

/// Get the attestation quote from a TEE
pub(crate) fn get_quote(report_data: &[u8]) -> Result<(TEEType, Box<[u8]>), QuoteError> {
    // check, if we are running in a TEE
    if std::fs::metadata("/dev/attestation").is_ok() {
        // SGX Gramine environment
        if report_data.len() > 64 {
            return Err(QuoteError::ReportDataSize);
        }

        let mut report_data_fixed = [0u8; 64];
        report_data_fixed[..report_data.len()].copy_from_slice(report_data);

        Ok((TEEType::SGX, sgx_gramine_get_quote(&report_data_fixed)?))
    } else if std::fs::metadata("/dev/tdx_guest").is_ok() {
        // native TDX environment
        if report_data.len() > 64 {
            return Err(QuoteError::ReportDataSize);
        }

        let mut report_data_fixed = [0u8; 64];
        report_data_fixed[..report_data.len()].copy_from_slice(report_data);

        Ok((TEEType::TDX, tgx_get_quote(&report_data_fixed)?))
    } else {
        // if not, return an error
        Err(QuoteError::UnknownTee)
    }
}

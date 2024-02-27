// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

// Copyright (c) The Enarx Project Developers https://github.com/enarx/sgx

//! Intel SGX Enclave report structures.

pub mod error;
pub mod sign;
pub mod tcblevel;

use bytemuck::{cast_slice, try_from_bytes, AnyBitPattern, PodCastError};
use intel_tee_quote_verification_rs::{
    quote3_error_t, sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_supp_data_descriptor_t, tee_verify_quote,
};
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::mem;
use tracing::{trace, warn};

use crate::quote::GetQuoteError;
pub use error::{Quote3Error, QuoteFromError};
pub use intel_tee_quote_verification_rs::{sgx_ql_qv_result_t, Collateral};
pub use tcblevel::{parse_tcb_levels, EnumSet, TcbLevel};

/// Structure of a quote
#[derive(Copy, Clone, Debug, AnyBitPattern)]
#[repr(C)]
pub struct Quote {
    version: [u8; 2],
    key_type: [u8; 2],
    reserved: [u8; 4],
    qe_svn: [u8; 2],
    pce_svn: [u8; 2],
    qe_vendor_id: [u8; 16],
    /// The user data that was passed, when creating the enclave
    pub user_data: [u8; 20],
    /// The report body
    pub report_body: ReportBody,
}

impl Quote {
    /// Creates a quote from a byte slice
    pub fn try_from_bytes(bytes: &[u8]) -> Result<&Self, QuoteFromError> {
        if bytes.len() < mem::size_of::<Self>() {
            return Err(PodCastError::SizeMismatch.into());
        }
        let this: &Self = try_from_bytes(&bytes[..mem::size_of::<Self>()])?;
        if this.version() != 3 {
            return Err(QuoteFromError::InvalidVersion);
        }
        Ok(this)
    }

    /// Version of the `Quote` structure
    pub fn version(&self) -> u16 {
        u16::from_le_bytes(self.version)
    }
}

/// The enclave report body.
///
/// For more information see the following documents:
///
/// [Intel® Software Guard Extensions (Intel® SGX) Data Center Attestation Primitives: ECDSA Quote Library API](https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf)
///
/// Table 5, A.4. Quote Format
///
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3 (3A, 3B, 3C & 3D): System Programming Guide](https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.html)
///
/// Table 38-21. Layout of REPORT
#[derive(Copy, Clone, Debug, AnyBitPattern)]
#[repr(C)]
pub struct ReportBody {
    /// The security version number of the enclave.
    pub cpusvn: [u8; 16],
    /// The Misc section of the StateSaveArea of the enclave
    pub miscselect: [u8; 4],
    reserved1: [u8; 28],
    /// The allowed Features of the enclave.
    pub features: [u8; 8],
    /// The allowed XCr0Flags of the enclave.
    pub xfrm: [u8; 8],
    /// The measurement of the enclave
    pub mrenclave: [u8; 32],
    reserved2: [u8; 32],
    /// The hash of the public key, that signed the enclave
    pub mrsigner: [u8; 32],
    reserved3: [u8; 96],
    /// ISV assigned Product ID of the enclave.
    pub isv_prodid: [u8; 2],
    /// ISV assigned SVN (security version number) of the enclave.
    pub isv_svn: [u8; 2],
    reserved4: [u8; 60],
    /// The enclave report data, injected when requesting the quote, that is used for attestation.
    pub reportdata: [u8; 64],
}

/// The result of the quote verification
pub struct QuoteVerificationResult<'a> {
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
    pub quote: &'a Quote,
}

/// Verifies a quote with optional collateral material
pub fn verify_quote_with_collateral<'a>(
    quote: &'a [u8],
    collateral: Option<&Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult<'a>, Quote3Error> {
    let mut supp_data: mem::MaybeUninit<sgx_ql_qv_supplemental_t> = mem::MaybeUninit::zeroed();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: supp_data.as_mut_ptr() as *mut u8,
    };
    trace!("tee_get_supplemental_data_version_and_size");
    let (_, supp_size) =
        tee_get_supplemental_data_version_and_size(quote).map_err(|e| Quote3Error {
            msg: "tee_get_supplemental_data_version_and_size",
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
                msg: "tee_verify_quote",
                inner: e,
            },
        )?;

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

    let quote = Quote::try_from_bytes(quote).map_err(|_| Quote3Error {
        msg: "Quote::try_from_bytes",
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

/// Get the attestation report in a Gramine enclave
pub fn sgx_gramine_get_quote(report_data: &[u8; 64]) -> Result<Box<[u8]>, GetQuoteError> {
    let mut file = OpenOptions::new()
        .write(true)
        .open("/dev/attestation/user_report_data")
        .map_err(|e| GetQuoteError {
            msg: "Failed to open `/dev/attestation/user_report_data`".into(),
            source: e,
        })?;

    file.write(report_data).map_err(|e| GetQuoteError {
        msg: "Failed to write `/dev/attestation/user_report_data`".into(),
        source: e,
    })?;

    drop(file);

    let mut file = OpenOptions::new()
        .read(true)
        .open("/dev/attestation/quote")
        .map_err(|e| GetQuoteError {
            msg: "Failed to open `/dev/attestation/quote`".into(),
            source: e,
        })?;

    let mut quote = Vec::new();
    file.read_to_end(&mut quote).map_err(|e| GetQuoteError {
        msg: "Failed to read `/dev/attestation/quote`".into(),
        source: e,
    })?;
    Ok(quote.into_boxed_slice())
}

/// Wrapper func for error
/// TODO: move to intel_tee_quote_verification_rs
pub fn tee_qv_get_collateral(quote: &[u8]) -> Result<Collateral, Quote3Error> {
    intel_tee_quote_verification_rs::tee_qv_get_collateral(quote).map_err(Into::into)
}

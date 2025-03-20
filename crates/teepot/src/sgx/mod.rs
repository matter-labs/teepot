// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

// Copyright (c) The Enarx Project Developers https://github.com/enarx/sgx

//! Intel SGX Enclave report structures.

pub mod sign;

use crate::quote::error::QuoteContext;
pub use crate::quote::{error::QuoteError, Collateral};
use bytemuck::{try_from_bytes, AnyBitPattern, PodCastError};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    mem,
};

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
    pub fn try_from_bytes(bytes: &[u8]) -> Result<&Self, QuoteError> {
        if bytes.len() < mem::size_of::<Self>() {
            return Err(PodCastError::SizeMismatch.into());
        }
        let this: &Self = try_from_bytes(&bytes[..mem::size_of::<Self>()])?;
        if this.version() != 3 {
            return Err(QuoteError::InvalidVersion);
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

/// Get the attestation report in a Gramine enclave
pub fn sgx_gramine_get_quote(report_data: &[u8; 64]) -> Result<Box<[u8]>, QuoteError> {
    let mut file = OpenOptions::new()
        .write(true)
        .open("/dev/attestation/user_report_data")
        .context("opening `/dev/attestation/user_report_data`")?;

    file.write(report_data)
        .context("writing `/dev/attestation/user_report_data`")?;

    drop(file);

    let mut file = OpenOptions::new()
        .read(true)
        .open("/dev/attestation/quote")
        .context("opening `/dev/attestation/quote`")?;

    let mut quote = Vec::new();
    file.read_to_end(&mut quote)
        .context("reading `/dev/attestation/quote`")?;

    Ok(quote.into_boxed_slice())
}

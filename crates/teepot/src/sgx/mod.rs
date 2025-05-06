// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

// Copyright (c) The Enarx Project Developers https://github.com/enarx/sgx

//! Intel SGX Enclave report structures.

pub mod sign;

use crate::quote::error::QuoteContext;
pub use crate::quote::{error::QuoteError, Collateral};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

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

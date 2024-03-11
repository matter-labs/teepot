// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Get a quote from a TEE

use crate::sgx::sgx_gramine_get_quote;
use std::io;

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[error("{msg}")]
pub struct GetQuoteError {
    pub(crate) msg: Box<str>,
    #[source] // optional if field name is `source`
    pub(crate) source: io::Error,
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
    } else {
        // if not, return an error
        Err(GetQuoteError {
            msg: "Not running in a TEE".into(),
            source: io::Error::new(io::ErrorKind::Other, "Not running in a TEE"),
        })
    }
}

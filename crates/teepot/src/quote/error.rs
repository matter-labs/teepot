// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! Quote Error type

use std::io;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use tdx_attest_rs::tdx_attest_error_t;
use thiserror::Error;

/// Quote parsing error
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum QuoteError {
    #[error("I/O Error")]
    IoError { context: String, source: io::Error },
    #[error("parsing bytes")]
    ConvertError(#[from] bytemuck::PodCastError),
    #[error("unsupported quote version")]
    QuoteVersion,
    #[error("invalid tee type")]
    InvalidTeeType,
    #[error("unsupported body type")]
    UnsupportedBodyType,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[error("tdx_att_get_quote error {msg}: {inner:?}")]
    TdxAttGetQuote {
        inner: tdx_attest_error_t,
        msg: String,
    },
    #[error("invalid version")]
    InvalidVersion,
    #[error("report data too long")]
    ReportDataSize,
    #[error("can't get a quote: unknown TEE")]
    UnknownTee,
    #[error("{0}: invalid parameter")]
    InvalidParameter(String),
    #[error("{0}: platform lib unavailable")]
    PlatformLibUnavailable(String),
    #[error("{0}: pck cert chain error")]
    PckCertChainError(String),
    #[error("{0}: pck cert unsupported format")]
    PckCertUnsupportedFormat(String),
    #[error("{0}: quote format unsupported")]
    QuoteFormatUnsupported(String),
    #[error("{0}: out of memory")]
    OutOfMemory(String),
    #[error("{0}: no quote collateral data")]
    NoQuoteCollateralData(String),
    #[error("{0}: unexpected error")]
    Unexpected(String),
    #[error("{0}: quote certification data unsupported")]
    QuoteCertificationDataUnsupported(String),
    #[error("{0}: unable to generate report")]
    UnableToGenerateReport(String),
    #[error("{0}: CRL unsupported format")]
    CrlUnsupportedFormat(String),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl From<tdx_attest_error_t> for QuoteError {
    fn from(code: tdx_attest_error_t) -> Self {
        Self::TdxAttGetQuote {
            inner: code,
            msg: "code".to_string(),
        }
    }
}

/// Usability trait for easy QuoteError annotation
pub trait QuoteContext {
    /// The Ok Type
    type Ok;
    /// The Context
    fn context<I: Into<String>>(self, msg: I) -> Result<Self::Ok, QuoteError>;
}

impl<T> QuoteContext for Result<T, std::io::Error> {
    type Ok = T;
    fn context<I: Into<String>>(self, msg: I) -> Result<T, QuoteError> {
        self.map_err(|e| QuoteError::IoError {
            context: msg.into(),
            source: e,
        })
    }
}

impl<T> QuoteContext for Option<T> {
    type Ok = T;
    fn context<I: Into<String>>(self, msg: I) -> Result<T, QuoteError> {
        self.ok_or(QuoteError::Unexpected(msg.into()))
    }
}

/// Usability trait for easy QuoteError annotation
pub trait QuoteContextErr {
    /// The Ok Type
    type Ok;
    /// The Context
    fn str_context<I: std::fmt::Display>(self, msg: I) -> Result<Self::Ok, QuoteError>;
}

impl<T, E: std::fmt::Display> QuoteContextErr for Result<T, E> {
    type Ok = T;
    fn str_context<I: std::fmt::Display>(self, msg: I) -> Result<T, QuoteError> {
        self.map_err(|e| QuoteError::Unexpected(format!("{}: {}", msg, e)))
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<T> QuoteContext for Result<T, tdx_attest_error_t> {
    type Ok = T;
    fn context<I: Into<String>>(self, msg: I) -> Result<T, QuoteError> {
        self.map_err(|e| QuoteError::TdxAttGetQuote {
            msg: msg.into(),
            inner: e,
        })
    }
}

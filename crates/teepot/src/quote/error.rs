// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Quote Error type

use intel_tee_quote_verification_rs::quote3_error_t;
use std::io;
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
    #[error("quote verification error {msg}: {inner:?}")]
    Quote3Error { inner: quote3_error_t, msg: String },
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
}

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

impl<T> QuoteContext for Result<T, quote3_error_t> {
    type Ok = T;
    fn context<I: Into<String>>(self, msg: I) -> Result<T, QuoteError> {
        self.map_err(|e| QuoteError::Quote3Error {
            msg: msg.into(),
            inner: e,
        })
    }
}

impl<T> QuoteContext for Result<T, tdx_attest_error_t> {
    type Ok = T;
    fn context<I: Into<String>>(self, msg: I) -> Result<T, QuoteError> {
        self.map_err(|e| QuoteError::TdxAttGetQuote {
            msg: msg.into(),
            inner: e,
        })
    }
}

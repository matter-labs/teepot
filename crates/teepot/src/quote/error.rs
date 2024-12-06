// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Quote Error type

use intel_tee_quote_verification_rs::quote3_error_t;
use std::io;
use thiserror::Error;

/// Quote parsing error
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum QuoteError {
    #[error("reading bytes")]
    ReadError(#[from] io::Error),
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
    #[error("invalid version")]
    InvalidVersion,
}

impl From<quote3_error_t> for QuoteError {
    fn from(code: quote3_error_t) -> Self {
        Self::Quote3Error {
            inner: code,
            msg: "code".to_string(),
        }
    }
}

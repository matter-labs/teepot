// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Intel SGX Enclave error wrapper

use bytemuck::PodCastError;
use intel_tee_quote_verification_rs::quote3_error_t;
use std::fmt::Formatter;

/// Wrapper for the quote verification Error
#[derive(Copy, Clone)]
pub struct Quote3Error {
    /// error message
    pub msg: &'static str,
    /// raw error code
    pub inner: quote3_error_t,
}

impl std::fmt::Display for Quote3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.msg, self.inner)
    }
}

impl std::fmt::Debug for Quote3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.msg, self.inner)
    }
}

impl std::error::Error for Quote3Error {}

impl From<quote3_error_t> for Quote3Error {
    fn from(inner: quote3_error_t) -> Self {
        Self {
            msg: "Generic",
            inner,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum QuoteFromError {
    #[error(transparent)]
    PodCastError(#[from] PodCastError),

    #[error("Quote version is invalid")]
    InvalidVersion,
}

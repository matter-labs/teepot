// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Quote Error type

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
    #[error("unknown error")]
    Unknown,
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Helper functions to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod client;
pub mod config;
pub mod ethereum;
pub mod json;
pub mod log;
pub mod prover;
pub mod quote;
pub mod server;
pub mod sgx;
pub mod tdx;
pub mod util;

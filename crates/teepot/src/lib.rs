// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Helper functions to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod client;
pub mod json;
pub mod server;
pub mod sgx;

pub mod quote;

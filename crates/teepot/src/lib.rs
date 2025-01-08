// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Helper functions to verify Intel SGX enclaves and other TEEs.

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod client;
pub mod ethereum;
pub mod json;
pub mod log;
pub mod prover;
pub mod quote;
pub mod server;
pub mod sgx;
pub mod tdx;

/// pad a byte slice to a fixed sized array
pub fn pad<const T: usize>(input: &[u8]) -> [u8; T] {
    let mut output = [0; T];
    let len = input.len();
    if len > T {
        output.copy_from_slice(&input[..T]);
    } else {
        output[..len].copy_from_slice(input);
    }
    output
}

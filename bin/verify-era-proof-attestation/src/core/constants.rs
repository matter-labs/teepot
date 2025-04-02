// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Constants used throughout the application

/// Maximum number of retry attempts for fetching proofs
pub const MAX_PROOF_FETCH_RETRIES: u32 = 3;

/// Default delay between retries (in milliseconds)
pub const DEFAULT_RETRY_DELAY_MS: u64 = 1000;

/// Default timeout for HTTP requests (in seconds)
pub const DEFAULT_HTTP_REQUEST_TIMEOUT: u64 = 30;

/// SGX hash size in bytes
pub const SGX_HASH_SIZE: usize = 32;

/// TDX hash size in bytes
pub const TDX_HASH_SIZE: usize = 48;

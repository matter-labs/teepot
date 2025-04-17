// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! A tool for extending SHA384 digests, commonly used in TPM and TDX operations
//!
//! # Overview
//! This utility implements the extend operation used in Trusted Platform Module (TPM)
//! Platform Configuration Registers (PCRs) and Intel Trust Domain Extensions (TDX)
//! Runtime Measurement Registers (RTMRs). The extend operation combines two SHA384
//! digests by concatenating and then hashing them.
//!
//! # Usage
//! ```shell
//! sha384-extend <extend-value> [--base <initial-value>]
//! ```
//! Where:
//! - `extend-value`: SHA384 digest in hex format to extend with
//! - `initial-value`: Optional initial SHA384 digest in hex format (defaults to "00")
//!
//! # Example
//! ```shell
//! sha384-extend --base 01 26bb0c
//! ```

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use sha2::Digest;
use teepot::util::pad;

/// Calculate e.g. a TDX RTMR or TPM PCR SHA384 digest by extending it with another
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// The SHA384 digest (in hex format) to extend the base value with.
    /// Must be a valid hex string that can be padded to 48 bytes (384 bits).
    extend: String,

    /// The initial SHA384 digest (in hex format) to extend from.
    /// Must be a valid hex string that can be padded to 48 bytes (384 bits).
    #[arg(long, default_value = "00", required = false)]
    base: String,
}

/// Extends a base SHA384 digest with another digest
///
/// # Arguments
/// * `base` - Base hex string to extend from
/// * `extend` - Hex string to extend with
///
/// # Returns
/// * `Result<String>` - The resulting SHA384 digest as a hex string
///
/// # Examples
/// ```
/// let result = extend_sha384("00", "aa").unwrap();
/// ```
pub fn extend_sha384(base: &str, extend: &str) -> Result<String> {
    let mut hasher = sha2::Sha384::new();

    hasher.update(pad::<48>(&hex::decode(base).context(format!(
        "Failed to decode base digest '{base}' - expected hex string",
    ))?)?);

    hasher.update(pad::<48>(&hex::decode(extend).context(format!(
        "Failed to decode extend digest '{extend}' - expected hex string",
    ))?)?);

    Ok(hex::encode(hasher.finalize()))
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    let hex = extend_sha384(&args.base, &args.extend)?;
    println!("{hex}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BASE: &str = "00";
    const TEST_EXTEND: &str = "d3a665eb2bf8a6c4e6cee0ccfa663ee4098fc4903725b1823d8d0316126bb0cb";
    const EXPECTED_RESULT: &str = "971fb52f90ec98a234301ca9b8fc30b613c33e3dd9c0cc42dcb8003d4a95d8fb218b75baf028b70a3cabcb947e1ca453";

    const EXPECTED_RESULT_00: &str = "f57bb7ed82c6ae4a29e6c9879338c592c7d42a39135583e8ccbe3940f2344b0eb6eb8503db0ffd6a39ddd00cd07d8317";

    #[test]
    fn test_extend_sha384_with_test_vectors() {
        let result = extend_sha384(TEST_BASE, TEST_EXTEND).unwrap();
        assert_eq!(
            result, EXPECTED_RESULT,
            "SHA384 extend result didn't match expected value"
        );

        // Test with empty base
        let result = extend_sha384("", TEST_EXTEND).unwrap();
        assert_eq!(
            result, EXPECTED_RESULT,
            "SHA384 extend result didn't match expected value"
        );

        // Test with empty base
        let result = extend_sha384("", "").unwrap();
        assert_eq!(
            result, EXPECTED_RESULT_00,
            "SHA384 extend result didn't match expected value"
        );
    }

    #[test]
    fn test_extend_sha384_with_invalid_base() {
        // Test with invalid hex in base
        let result = extend_sha384("not_hex", TEST_EXTEND);
        assert!(result.is_err(), "Should fail with invalid base hex");

        // Test with odd length hex string
        let result = extend_sha384("0", TEST_EXTEND);
        assert!(result.is_err(), "Should fail with odd-length hex string");
    }

    #[test]
    fn test_extend_sha384_with_invalid_extend() {
        // Test with invalid hex in extend
        let result = extend_sha384(TEST_BASE, "not_hex");
        assert!(result.is_err(), "Should fail with invalid extend hex");

        // Test with odd length hex string
        let result = extend_sha384(TEST_BASE, "0");
        assert!(result.is_err(), "Should fail with odd-length hex string");
    }

    #[test]
    fn test_extend_sha384_with_oversized_input() {
        // Create a hex string that's too long (more than 48 bytes when decoded)
        let oversized = "00".repeat(49); // 49 bytes when decoded

        let result = extend_sha384(TEST_BASE, &oversized);
        assert!(result.is_err(), "Should fail with oversized extend value");

        let result = extend_sha384(&oversized, TEST_EXTEND);
        assert!(result.is_err(), "Should fail with oversized base value");
    }

    #[test]
    fn test_extend_sha384_idempotent() {
        // Test that extending with the same values produces the same result
        let result1 = extend_sha384(TEST_BASE, TEST_EXTEND).unwrap();
        let result2 = extend_sha384(TEST_BASE, TEST_EXTEND).unwrap();
        assert_eq!(result1, result2, "Same inputs should produce same output");
    }

    #[test]
    fn test_extend_sha384_case_sensitivity() {
        // Test that upper and lower case hex strings produce the same result
        let upper_extend = TEST_EXTEND.to_uppercase();
        let result1 = extend_sha384(TEST_BASE, TEST_EXTEND).unwrap();
        let result2 = extend_sha384(TEST_BASE, &upper_extend).unwrap();
        assert_eq!(result1, result2, "Case should not affect the result");
    }
}

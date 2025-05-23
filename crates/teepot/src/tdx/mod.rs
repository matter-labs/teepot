// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Intel TDX helper functions.

#[cfg(all(feature = "quote_op", target_os = "linux", target_arch = "x86_64"))]
pub mod rtmr;

/// The sha384 digest of 0u32, which is used in the UEFI TPM protocol
/// as a marker. Used to advance the PCR.
/// ```shell
/// $ echo -n -e "\000\000\000\000" | sha384sum -b
/// 394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0 *-
/// ```
pub const UEFI_MARKER_DIGEST_BYTES: [u8; 48] = [
    0x39, 0x43, 0x41, 0xb7, 0x18, 0x2c, 0xd2, 0x27, 0xc5, 0xc6, 0xb0, 0x7e, 0xf8, 0x00, 0x0c, 0xdf,
    0xd8, 0x61, 0x36, 0xc4, 0x29, 0x2b, 0x8e, 0x57, 0x65, 0x73, 0xad, 0x7e, 0xd9, 0xae, 0x41, 0x01,
    0x9f, 0x58, 0x18, 0xb4, 0xb9, 0x71, 0xc9, 0xef, 0xfc, 0x60, 0xe1, 0xad, 0x9f, 0x12, 0x89, 0xf0,
];

# teepot

TEE (Trusted Execution Environment) utilities for Intel SGX and TDX attestation.

## Overview

Teepot provides comprehensive support for generating and verifying attestation quotes from Intel SGX enclaves and TDX trust domains. It handles the complete attestation workflow including quote generation, collateral fetching, and verification with detailed TCB (Trusted Computing Base) status reporting.

## Features

- **Multi-TEE Support**: Works with both Intel SGX and Intel TDX
- **Attestation Quote Generation**: Generate quotes with custom report data
- **Quote Verification**: Verify quotes with automatic collateral fetching
- **TCB Level Management**: Filter quotes by security level
- **Cross-Platform**: Native support for Linux x86_64, fallback implementation for other platforms
- **Gramine SGX Support**: Special support for Gramine-based SGX enclaves
- **Comprehensive Error Handling**: Detailed error context for debugging

## Usage

### Basic Quote Generation and Verification

```rust
use teepot::quote::{get_quote, get_collateral, verify_quote_with_collateral};

// Generate a quote with custom data
let report_data = [0u8; 64]; // Your custom data here
let quote = get_quote(&report_data)?;

// Fetch collateral for verification
let collateral = get_collateral(&quote)?;

// Verify the quote
let result = verify_quote_with_collateral(&quote, collateral.as_ref(), None)?;
println!("TCB Level: {:?}", result.tcb_level);
```

### High-Level Attestation API

```rust
use teepot::quote::attestation::get_quote_and_collateral;

// Generate quote and fetch collateral in one call
let (quote, collateral, result) = get_quote_and_collateral(&report_data)?;
```

### TCB Level Filtering

```rust
use teepot::quote::{TcbLevel, verify_quote_with_collateral};

// Only accept quotes with up-to-date TCB
let accepted_levels = vec![TcbLevel::Ok];
let result = verify_quote_with_collateral(&quote, collateral.as_ref(), Some(&accepted_levels))?;
```

## Supported Platforms

- **Full support**: Linux x86_64 with Intel SGX/TDX drivers
- **Verification only**: All other platforms via `dcap-qvl`

## Dependencies

On Linux x86_64, the crate uses Intel's DCAP libraries for quote generation. Make sure you have:
- Intel SGX DCAP Quote Generation Library
- Intel SGX DCAP Quote Verification Library

## License

This project is licensed under the Apache License, Version 2.0 - see the LICENSE file for details.

Note: Some code is derived from the [Enarx project](https://github.com/enarx/).
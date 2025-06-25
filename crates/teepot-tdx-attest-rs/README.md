# teepot-tdx-attest-rs

[![Crates.io](https://img.shields.io/crates/v/teepot-tdx-attest-rs.svg)](https://crates.io/crates/teepot-tdx-attest-rs)
[![Documentation](https://docs.rs/teepot-tdx-attest-rs/badge.svg)](https://docs.rs/teepot-tdx-attest-rs)
[![License](https://img.shields.io/crates/l/teepot-tdx-attest-rs.svg)](LICENSE)

Rust bindings for Intel TDX (Trust Domain Extensions) attestation functionality. This crate provides a safe Rust interface to the Intel TDX attestation library, enabling trusted execution environments to generate attestation quotes and reports.

This is a fork of the original [tdx-attest-rs](https://github.com/intel/SGXDataCenterAttestationPrimitives) crate, maintained as part of the [Teepot](https://github.com/matter-labs/teepot) project.

## Features

- Request TDX attestation quotes
- Generate TDX reports
- Extend runtime measurement registers (RTMRs)
- Query supported attestation key IDs
- Safe Rust wrappers around the Intel TDX attestation C library

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
teepot-tdx-attest-rs = "0.1.2"
```

## Usage

### Generate a TDX Quote

```rust
use teepot_tdx_attest_rs::*;

// Prepare report data (typically a hash you want to bind to the quote)
let tdx_report_data = tdx_report_data_t {
    d: [0; 64], // Your data here
};

// List of supported attestation key IDs
let att_key_id_list = [tdx_uuid_t {
    d: [0; 16], // Your key ID
}];

let mut att_key_id = tdx_uuid_t {
    d: [0; 16],
};

// Request the quote
let (result, quote) = tdx_att_get_quote(
    Some(&tdx_report_data),
    Some(&att_key_id_list),
    Some(&mut att_key_id),
    0
);

match result {
    tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
        // Process the quote
        if let Some(quote_data) = quote {
            println!("Quote generated successfully, size: {}", quote_data.len());
        }
    }
    _ => {
        println!("Failed to generate quote: {:?}", result);
    }
}
```

### Generate a TDX Report

```rust
use teepot_tdx_attest_rs::*;

let tdx_report_data = tdx_report_data_t {
    d: [0; 64], // Your report data
};

let mut tdx_report = tdx_report_t {
    d: [0; 1024],
};

let result = tdx_att_get_report(Some(&tdx_report_data), &mut tdx_report);

if result == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
    println!("Report generated successfully");
}
```

### Extend RTMR

```rust
use teepot_tdx_attest_rs::*;

// Prepare RTMR event data
let rtmr_event = vec![0u8; 68]; // Your event data

let result = tdx_att_extend(&rtmr_event);

if result == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
    println!("RTMR extended successfully");
}
```

### Get Supported Attestation Key IDs

```rust
use teepot_tdx_attest_rs::*;

let (result, att_key_ids) = tdx_att_get_supported_att_key_ids();

if result == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
    if let Some(ids) = att_key_ids {
        println!("Found {} supported attestation key IDs", ids.len());
    }
}
```

## Error Handling

The crate uses the `tdx_attest_error_t` enum for error reporting. Common error values include:

- `TDX_ATTEST_SUCCESS` - Operation completed successfully
- `TDX_ATTEST_ERROR_INVALID_PARAMETER` - Invalid parameter provided
- `TDX_ATTEST_ERROR_DEVICE_FAILURE` - Failed to access TDX attestation device
- `TDX_ATTEST_ERROR_OUT_OF_MEMORY` - Memory allocation failure
- `TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID` - Unsupported attestation key ID

## Requirements

- Intel TDX-enabled hardware
- TDX attestation runtime environment
- The `teepot-tdx-attest-sys` crate (automatically included as a dependency)

## Safety

This crate provides safe Rust wrappers around unsafe FFI calls to the Intel TDX attestation library. All pointer operations are handled internally, and the API uses Rust's type system to ensure safety.

## License

This project is licensed under the BSD-3-Clause License - see the [License.txt](License.txt) file for details.

## Contributing

This is a fork maintained as part of the Teepot project. For contributions, please visit the [Teepot repository](https://github.com/matter-labs/teepot).

## Original Work

This crate is based on Intel's SGX Data Center Attestation Primitives. The original source can be found at [Intel's repository](https://github.com/intel/SGXDataCenterAttestationPrimitives).
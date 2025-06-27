# teepot-tee-quote-verification-rs

[![Crates.io](https://img.shields.io/crates/v/teepot-tee-quote-verification-rs.svg)](https://crates.io/crates/teepot-tee-quote-verification-rs)
[![Documentation](https://docs.rs/teepot-tee-quote-verification-rs/badge.svg)](https://docs.rs/teepot-tee-quote-verification-rs)
[![License](https://img.shields.io/crates/l/teepot-tee-quote-verification-rs.svg)](https://github.com/matter-labs/teepot/blob/main/LICENSE)

A Rust wrapper for Intel® Software Guard Extensions (SGX) and Trust Domain Extensions (TDX) quote verification.

This crate is a fork of the original [intel-tee-quote-verification-rs](https://github.com/intel/SGXDataCenterAttestationPrimitives) crate, providing safe Rust bindings for the Intel Quote Verification Library (QVL).

## Features

- Safe Rust wrappers for SGX and TDX quote verification APIs
- Support for both SGX ECDSA and TDX ECDSA quote verification
- Collateral management for quote verification
- Supplemental data handling
- Cross-platform support (Linux x86_64)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
teepot-tee-quote-verification-rs = "0.6.0"
```

### Example: Verify an SGX Quote

```rust
use teepot_tee_quote_verification_rs::*;

fn verify_sgx_quote(quote: &[u8]) -> Result<(), quote3_error_t> {
    // Get collateral for the quote
    let collateral = tee_qv_get_collateral(quote)?;
    
    // Get supplemental data size
    let supp_data_size = sgx_qv_get_quote_supplemental_data_size()?;
    let mut supp_data = sgx_ql_qv_supplemental_t::default();
    
    // Verify the quote
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
        
    let (expiration_status, verification_result) = sgx_qv_verify_quote(
        quote,
        Some(&collateral),
        current_time,
        None, // QvE report info (None for host-based verification)
        supp_data_size,
        Some(&mut supp_data),
    )?;
    
    match verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            println!("Quote verification passed!");
            Ok(())
        }
        _ => {
            println!("Quote verification failed: {:?}", verification_result);
            Err(quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER)
        }
    }
}
```

### Example: Verify a TDX Quote

```rust
use teepot_tee_quote_verification_rs::*;

fn verify_tdx_quote(quote: &[u8]) -> Result<(), quote3_error_t> {
    // Get collateral for the quote
    let collateral = tee_qv_get_collateral(quote)?;
    
    // Get supplemental data size
    let supp_data_size = tdx_qv_get_quote_supplemental_data_size()?;
    let mut supp_data = sgx_ql_qv_supplemental_t::default();
    
    // Verify the quote
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
        
    let (expiration_status, verification_result) = tdx_qv_verify_quote(
        quote,
        Some(&collateral),
        current_time,
        None, // QvE report info
        supp_data_size,
        Some(&mut supp_data),
    )?;
    
    match verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            println!("TDX quote verification passed!");
            Ok(())
        }
        _ => {
            println!("TDX quote verification failed: {:?}", verification_result);
            Err(quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER)
        }
    }
}
```

### Unified TEE Quote Verification

For a unified interface that works with both SGX and TDX quotes:

```rust
use teepot_tee_quote_verification_rs::*;

fn verify_tee_quote(quote: &[u8]) -> Result<(), quote3_error_t> {
    // Get collateral
    let collateral = tee_qv_get_collateral(quote)?;
    
    // Get supplemental data version and size
    let (version, data_size) = tee_get_supplemental_data_version_and_size(quote)?;
    
    // Prepare supplemental data descriptor
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: version,
        data_size,
        p_data: std::ptr::null_mut(),
    };
    
    // Allocate buffer for supplemental data if needed
    let mut supp_data_buffer = vec![0u8; data_size as usize];
    if data_size > 0 {
        supp_data_desc.p_data = supp_data_buffer.as_mut_ptr();
    }
    
    // Verify quote
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
        
    let (expiration_status, verification_result) = tee_verify_quote(
        quote,
        Some(&collateral),
        current_time,
        None,
        Some(&mut supp_data_desc),
    )?;
    
    println!("Verification result: {:?}", verification_result);
    println!("Collateral expiration status: {}", expiration_status);
    
    Ok(())
}
```

## Platform Support

This crate is currently supported on:
- Linux x86_64

On other platforms, the crate will compile but provide stub implementations.

## Dependencies

On Linux x86_64, this crate depends on:
- `intel-tee-quote-verification-sys`: System bindings for Intel QVL
- `teepot-tdx-attest-rs`: TDX attestation support

## License

This project is licensed under the BSD-3-Clause License. See the [LICENSE](https://github.com/matter-labs/teepot/blob/main/LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to the [Teepot repository](https://github.com/matter-labs/teepot).

## Related Crates

- [intel-tee-quote-verification-rs](https://github.com/intel/SGXDataCenterAttestationPrimitives) - The original Intel crate
- [teepot-tdx-attest-rs](https://crates.io/crates/teepot-tdx-attest-rs) - TDX attestation support
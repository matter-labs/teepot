# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This crate (`intel-dcap-api`) is a Rust client library for Intel's Data Center Attestation Primitives (DCAP) API. It
provides access to Intel's Trusted Services API for SGX and TDX attestation, including TCB info, PCK certificates, CRLs,
and enclave identity verification.

## Features

- Support for both API v3 and v4
- Async/await API using tokio
- Comprehensive error handling with Intel-specific error codes
- Type-safe request/response structures
- Support for SGX and TDX platforms
- Real data integration tests
- **Automatic rate limit handling with configurable retries**

## Development Commands

```bash
# Build
cargo build
cargo build --no-default-features --features rustls  # Use rustls instead of default TLS

# Test
cargo test

# Lint
cargo clippy

# Examples
cargo run --example example            # Basic usage example
cargo run --example get_pck_crl       # Fetch certificate revocation lists
cargo run --example common_usage      # Common attestation verification patterns
cargo run --example integration_test  # Comprehensive test of most API endpoints
cargo run --example fetch_test_data   # Fetch real data from Intel API for tests
cargo run --example handle_rate_limit # Demonstrate automatic rate limiting handling
```

## Architecture

### Client Structure

- **ApiClient** (`src/client/mod.rs`): Main entry point supporting API v3/v4
    - Base URL: https://api.trustedservices.intel.com
    - Manages HTTP client and API version selection
    - Automatic retry logic for 429 (Too Many Requests) responses
    - Default: 3 retries, configurable via `set_max_retries()`

### Key Modules

- **client/**: API endpoint implementations
    - `tcb_info`: SGX/TDX TCB information retrieval
        - `get_sgx_tcb_info()`, `get_tdx_tcb_info()`
    - `pck_cert`: PCK certificate operations
        - `get_pck_certificate_by_ppid()`, `get_pck_certificate_by_manifest()`
        - `get_pck_certificates_by_ppid()`, `get_pck_certificates_by_manifest()`
        - `get_pck_certificates_config_by_ppid()`, `get_pck_certificates_config_by_manifest()`
    - `pck_crl`: Certificate revocation lists
        - `get_pck_crl()` - supports PEM and DER encoding
    - `enclave_identity`: SGX QE/QVE/QAE/TDQE identity
        - `get_sgx_qe_identity()`, `get_sgx_qve_identity()`, `get_sgx_qae_identity()`, `get_tdx_qe_identity()`
    - `fmspc`: FMSPC-related operations (V4 only)
        - `get_fmspcs()` - with optional platform filter
        - `get_sgx_tcb_evaluation_data_numbers()`, `get_tdx_tcb_evaluation_data_numbers()`
    - `registration`: Platform registration
        - `register_platform()`, `add_package()`

### Core Types

- **error.rs**: `IntelApiError` for comprehensive error handling
    - Extracts error details from Error-Code and Error-Message headers
    - **`TooManyRequests` variant for rate limiting (429) after retry exhaustion**
- **types.rs**: Enums (CaType, ApiVersion, UpdateType, etc.)
- **requests.rs**: Request structures
- **responses.rs**: Response structures with JSON and certificate data

### API Pattern

All client methods follow this pattern:

1. Build request with query parameters
2. Send HTTP request with proper headers (with automatic retry on 429)
3. Parse response (JSON + certificate chains)
4. Return typed response or error

### Rate Limiting & Retry Logic

- **Automatic Retries**: All HTTP requests automatically retry on 429 (Too Many Requests) responses
- **Retry Configuration**: Default 3 retries, configurable via `ApiClient::set_max_retries()`
- **Retry-After Handling**: Waits for duration specified in Retry-After header before retrying
- **Error Handling**: `IntelApiError::TooManyRequests` returned only after all retries exhausted
- **Implementation**: `execute_with_retry()` in `src/client/helpers.rs` handles retry logic

### Testing Strategy

- **Mock Tests**: Two test suites using mockito for HTTP mocking
    - `tests/mock_api_tests.rs`: Basic API functionality tests with simple data (11 tests)
    - `tests/real_data_mock_tests.rs`: Tests using real Intel API responses (25 tests)
- **Test Data**: Real responses stored in `tests/test_data/` (JSON format)
    - Fetched using `cargo run --example fetch_test_data`
    - Includes TCB info, CRLs, enclave identities for both SGX and TDX
    - Covers V3 and V4 API variations, different update types, and evaluation data numbers
- **Key Testing Considerations**:
    - Headers with newlines must be URL-encoded for mockito (use `percent_encode` with `NON_ALPHANUMERIC`)
    - V3 vs V4 API use different header names:
        - V3: `SGX-TCB-Info-Issuer-Chain`
        - V4: `TCB-Info-Issuer-Chain`
    - Error responses include Error-Code and Error-Message headers
    - Examples use real Intel API endpoints
    - Test data (FMSPC, PPID) from Intel documentation
    - Async tests require tokio runtime

## API Version Differences

### V4-Only Features

- FMSPC listing (`get_fmspcs()`)
- TCB Evaluation Data Numbers endpoints
- PPID encryption key type parameter
- TDX QE identity endpoint

## Common Pitfalls

1. **Mockito Header Encoding**: Always URL-encode headers containing newlines/special characters
2. **API Version Selection**: Some endpoints are V4-only and will return errors on V3
3. **Rate Limiting**: Client automatically retries 429 responses; disable with `set_max_retries(0)` if manual handling
   needed
4. **Platform Filters**: Only certain values are valid (All, Client, E3, E5)
5. **Test Data**: PCK certificate endpoints require valid platform data and often need subscription keys
6. **Issuer Chain Validation**: Always check that `issuer_chain` is non-empty - it's critical for signature verification

## Security Considerations

- **Certificate Chain Verification**: The `issuer_chain` field contains the certificates needed to verify the signature
  of the response data
- **Signature Validation**: All JSON responses (TCB info, enclave identities) should have their signatures verified
  using the issuer chain
- **CRL Verification**: PCK CRLs must be signature-verified before being used for certificate revocation checking
- **Empty Issuer Chains**: Always validate that issuer chains are present and non-empty before trusting response data

# teepot-tdx-attest-sys

[![Crates.io](https://img.shields.io/crates/v/teepot-tdx-attest-sys.svg)](https://crates.io/crates/teepot-tdx-attest-sys)
[![Documentation](https://docs.rs/teepot-tdx-attest-sys/badge.svg)](https://docs.rs/teepot-tdx-attest-sys)
[![License](https://img.shields.io/crates/l/teepot-tdx-attest-sys.svg)](https://github.com/matter-labs/teepot/blob/main/crates/teepot-tdx-attest-sys/License.txt)

Raw FFI bindings to Intel TDX Attestation Library (`libtdx_attest`).

This crate provides low-level FFI bindings for Intel Trust Domain Extensions (TDX) attestation functionality. It is a fork of the original [tdx-attest-sys](https://github.com/intel/SGXDataCenterAttestationPrimitives) crate from Intel's SGX Data Center Attestation Primitives.

## Prerequisites

Before using this crate, you need to install:

- Intel® SGX DCAP Driver
- Intel® SGX SDK
- Intel® SGX DCAP Packages
- Intel® SGX DCAP PCCS (Provisioning Certificate Caching Service)

Please refer to the [SGX DCAP Linux installation guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) for detailed installation instructions.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
teepot-tdx-attest-sys = "0.1.0"
```

This crate provides raw FFI bindings. For a more ergonomic Rust API, consider using a higher-level wrapper crate.

## Building

The crate uses `bindgen` to generate Rust bindings from the C headers during build time. Make sure you have:

- The TDX attestation library (`libtdx_attest`) installed on your system
- If using Intel SGX SDK, set the `SGX_SDK` environment variable to point to your SDK installation

## License

This project is licensed under the BSD-3-Clause License. See the [License.txt](License.txt) file for details.

## Repository

This crate is part of the [Teepot](https://github.com/matter-labs/teepot) project.
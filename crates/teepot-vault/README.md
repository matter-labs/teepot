# teepot-vault

[![Crates.io](https://img.shields.io/crates/v/teepot-vault.svg)](https://crates.io/crates/teepot-vault)
[![Documentation](https://docs.rs/teepot-vault/badge.svg)](https://docs.rs/teepot-vault)
[![License](https://img.shields.io/crates/l/teepot-vault.svg)](LICENSE)

A TEE (Trusted Execution Environment) secret manager that provides secure storage and retrieval of secrets for TEE applications, with a focus on Intel SGX enclaves.

## Features

- **Remote Attestation**: Verify Intel SGX enclaves and other TEEs using attestation reports
- **Secure Communication**: Establish TLS connections with custom certificate verification based on TEE attestation
- **HashiCorp Vault Integration**: Store and retrieve secrets with TEE-specific access controls
- **Multi-signature Support**: PGP-based multi-signature verification for administrative commands
- **Configurable TCB Levels**: Support for different Trusted Computing Base security levels

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
teepot-vault = "0.6.0"
```

## Usage

### Creating a Vault Connection

```rust
use teepot_vault::client::{AttestationArgs, VaultConnection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = AttestationArgs {
        sgx_mrsigner: Some("your_mrsigner_hex".to_string()),
        sgx_mrenclave: Some("your_mrenclave_hex".to_string()),
        server: "https://vault.example.com".to_string(),
        sgx_allowed_tcb_levels: Some(vec!["Ok".to_string(), "ConfigNeeded".to_string()]),
    };

    let vault_conn = VaultConnection::new(&args, "my-tee-app".to_string()).await?;
    
    Ok(())
}
```

### Storing and Retrieving Secrets

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct MySecret {
    api_key: String,
    private_key: Vec<u8>,
}

// Store a secret
let my_secret = MySecret {
    api_key: "secret-key".to_string(),
    private_key: vec![1, 2, 3, 4],
};
vault_conn.store_secret(my_secret, "secrets/my-app/config").await?;

// Retrieve a secret
let secret: MySecret = vault_conn.load_secret("secrets/my-app/config").await?.unwrap();
```

### Custom TEE Connections

For more control over the connection and custom operations:

```rust
use teepot_vault::client::TeeConnection;

let tee_conn = TeeConnection::new(&args);
let client = tee_conn.client(); // Get the HTTP client for custom requests

// Perform custom authenticated requests
let response = client
    .get("https://vault.example.com/custom/endpoint")
    .send()
    .await?;
```

## Server Components

The crate also provides server-side utilities for building TEE-aware services:

```rust
use teepot_vault::server::{HttpResponseError, Status};
use actix_web::{web, App, HttpServer, Result};

async fn handler() -> Result<String, HttpResponseError> {
    // Your TEE service logic here
    Ok("Secure response".to_string())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/api/secure", web::get().to(handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Requirements

- Rust 1.70 or later
- For SGX support: Intel SGX SDK and PSW (Platform Software)
- HashiCorp Vault instance (for vault operations)
- TEE environment (Intel SGX, Intel TDX, or compatible)

## Security Considerations

This crate is designed for use in high-security environments. When using it:

1. Always verify attestation reports before trusting a TEE
2. Use appropriate TCB levels for your security requirements
3. Ensure proper key management for PGP signatures
4. Follow HashiCorp Vault best practices for secret management

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
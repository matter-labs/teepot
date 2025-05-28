// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{ApiClient, CaType, IntelApiError, UpdateType};

/// Common usage patterns for the Intel DCAP API client
///
/// This example demonstrates typical use cases for attestation verification.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client (defaults to V4 API)
    let client = ApiClient::new()?;

    // Example 1: Get TCB info for quote verification
    println!("Example 1: Getting TCB info for SGX quote verification");
    println!("======================================================");

    let fmspc = "00906ED50000"; // From SGX quote

    match client.get_sgx_tcb_info(fmspc, None, None).await {
        Ok(response) => {
            // Critical: Check that issuer chain is present for signature verification
            if response.issuer_chain.is_empty() {
                println!("✗ Error: Empty issuer chain - cannot verify TCB info signature!");
                return Ok(());
            }

            println!("✓ Retrieved TCB info for FMSPC: {}", fmspc);

            // Parse the TCB info
            let tcb_info: serde_json::Value = serde_json::from_str(&response.tcb_info_json)?;

            // Extract useful information
            if let Some(tcb_levels) = tcb_info["tcbInfo"]["tcbLevels"].as_array() {
                println!("  Found {} TCB levels", tcb_levels.len());

                // Show the latest TCB level
                if let Some(latest) = tcb_levels.first() {
                    println!("  Latest TCB level:");
                    if let Some(status) = latest["tcbStatus"].as_str() {
                        println!("    Status: {}", status);
                    }
                    if let Some(date) = latest["tcbDate"].as_str() {
                        println!("    Date: {}", date);
                    }
                }
            }

            // The issuer chain is needed to verify the signature
            println!(
                "  Issuer chain length: {} bytes",
                response.issuer_chain.len()
            );
            // Verify we have certificate chain for signature verification
            let cert_count = response.issuer_chain.matches("BEGIN CERTIFICATE").count();
            println!("  Certificate chain contains {} certificates", cert_count);
        }
        Err(IntelApiError::ApiError {
            status,
            error_message,
            ..
        }) => {
            println!(
                "✗ API Error {}: {}",
                status,
                error_message.unwrap_or_default()
            );
        }
        Err(e) => {
            println!("✗ Error: {:?}", e);
        }
    }

    println!();

    // Example 2: Get QE identity for enclave verification
    println!("Example 2: Getting QE identity for enclave verification");
    println!("======================================================");

    match client.get_sgx_qe_identity(None, None).await {
        Ok(response) => {
            // Critical: Check that issuer chain is present for signature verification
            if response.issuer_chain.is_empty() {
                println!("✗ Error: Empty issuer chain - cannot verify QE identity signature!");
                return Ok(());
            }

            println!("✓ Retrieved QE identity");
            println!(
                "  Issuer chain length: {} bytes",
                response.issuer_chain.len()
            );

            let identity: serde_json::Value =
                serde_json::from_str(&response.enclave_identity_json)?;

            if let Some(enclave_id) = identity["enclaveIdentity"]["id"].as_str() {
                println!("  Enclave ID: {}", enclave_id);
            }

            if let Some(version) = identity["enclaveIdentity"]["version"].as_u64() {
                println!("  Version: {}", version);
            }

            if let Some(mrsigner) = identity["enclaveIdentity"]["mrsigner"].as_str() {
                println!("  MRSIGNER: {}...", &mrsigner[..16]);
            }
        }
        Err(e) => {
            println!("✗ Failed to get QE identity: {:?}", e);
        }
    }

    println!();

    // Example 3: Check certificate revocation
    println!("Example 3: Checking certificate revocation status");
    println!("================================================");

    match client.get_pck_crl(CaType::Processor, None).await {
        Ok(response) => {
            // Critical: Check that issuer chain is present for CRL verification
            if response.issuer_chain.is_empty() {
                println!("✗ Error: Empty issuer chain - cannot verify CRL signature!");
                return Ok(());
            }

            println!("✓ Retrieved PCK CRL");
            println!(
                "  Issuer chain length: {} bytes",
                response.issuer_chain.len()
            );

            let crl_pem = String::from_utf8_lossy(&response.crl_data);

            // In real usage, you would parse this CRL and check if a certificate is revoked
            if crl_pem.contains("BEGIN X509 CRL") {
                println!("  CRL format: PEM");
                println!("  CRL size: {} bytes", crl_pem.len());

                // Count the revoked certificates (naive approach)
                let revoked_count = crl_pem.matches("Serial Number:").count();
                println!("  Approximate revoked certificates: {}", revoked_count);
            }
        }
        Err(e) => {
            println!("✗ Failed to get CRL: {:?}", e);
        }
    }

    println!();

    // Example 4: Early update for testing
    println!("Example 4: Getting early TCB update (for testing)");
    println!("================================================");

    match client
        .get_sgx_tcb_info(fmspc, Some(UpdateType::Early), None)
        .await
    {
        Ok(response) => {
            println!("✓ Retrieved early TCB update");

            let tcb_info: serde_json::Value = serde_json::from_str(&response.tcb_info_json)?;

            if let Some(next_update) = tcb_info["tcbInfo"]["nextUpdate"].as_str() {
                println!("  Next update: {}", next_update);
            }
        }
        Err(IntelApiError::ApiError { status, .. }) if status.as_u16() == 404 => {
            println!("  No early update available (this is normal)");
        }
        Err(e) => {
            println!("✗ Error: {:?}", e);
        }
    }

    println!();
    println!("Done! These examples show common patterns for attestation verification.");

    Ok(())
}

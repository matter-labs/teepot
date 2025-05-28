// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{
    ApiClient, ApiVersion, CaType, CrlEncoding, IntelApiError, PlatformFilter, UpdateType,
};
use std::time::Duration;
use tokio::time::sleep;

/// Comprehensive integration test example demonstrating most Intel DCAP API client functions
///
/// This example shows how to use various endpoints of the Intel Trusted Services API.
/// Note: Some operations may fail with 404 or 400 errors if the data doesn't exist on Intel's servers.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Intel DCAP API Integration Test Example ===\n");

    // Create clients for both V3 and V4 APIs
    let v4_client = ApiClient::new()?;
    let v3_client =
        ApiClient::new_with_options("https://api.trustedservices.intel.com", ApiVersion::V3)?;

    // Track successes and failures
    let mut results = Vec::new();

    // Test FMSPC - commonly used for TCB lookups
    let test_fmspc = "00906ED50000";
    let test_fmspc_tdx = "00806F050000";

    println!("1. Testing TCB Info Endpoints...");
    println!("================================");

    // 1.1 SGX TCB Info (V4)
    print!("  - SGX TCB Info (V4): ");
    match v4_client.get_sgx_tcb_info(test_fmspc, None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX TCB Info (V4)", false));
            } else {
                println!("✓ Success");
                println!("    FMSPC: {}", test_fmspc);
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let tcb_info: serde_json::Value = serde_json::from_str(&response.tcb_info_json)?;
                if let Some(version) = tcb_info["tcbInfo"]["version"].as_u64() {
                    println!("    TCB Info Version: {}", version);
                }
                results.push(("SGX TCB Info (V4)", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX TCB Info (V4)", false));
        }
    }

    // Add small delay between requests to be nice to the API
    sleep(Duration::from_millis(100)).await;

    // 1.2 SGX TCB Info (V3)
    print!("  - SGX TCB Info (V3): ");
    match v3_client.get_sgx_tcb_info(test_fmspc, None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX TCB Info (V3)", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                results.push(("SGX TCB Info (V3)", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX TCB Info (V3)", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 1.3 TDX TCB Info
    print!("  - TDX TCB Info: ");
    match v4_client.get_tdx_tcb_info(test_fmspc_tdx, None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("TDX TCB Info", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let tcb_info: serde_json::Value = serde_json::from_str(&response.tcb_info_json)?;
                if let Some(id) = tcb_info["tcbInfo"]["id"].as_str() {
                    println!("    Platform: {}", id);
                }
                results.push(("TDX TCB Info", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("TDX TCB Info", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 1.4 SGX TCB Info with Early Update
    print!("  - SGX TCB Info (Early Update): ");
    match v4_client
        .get_sgx_tcb_info(test_fmspc, Some(UpdateType::Early), None)
        .await
    {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX TCB Info (Early)", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                results.push(("SGX TCB Info (Early)", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX TCB Info (Early)", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    println!("\n2. Testing Enclave Identity Endpoints...");
    println!("========================================");

    // 2.1 SGX QE Identity
    print!("  - SGX QE Identity: ");
    match v4_client.get_sgx_qe_identity(None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX QE Identity", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let identity: serde_json::Value =
                    serde_json::from_str(&response.enclave_identity_json)?;
                if let Some(id) = identity["enclaveIdentity"]["id"].as_str() {
                    println!("    Enclave ID: {}", id);
                }
                results.push(("SGX QE Identity", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX QE Identity", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 2.2 SGX QVE Identity
    print!("  - SGX QVE Identity: ");
    match v4_client.get_sgx_qve_identity(None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX QVE Identity", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                results.push(("SGX QVE Identity", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX QVE Identity", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 2.3 SGX QAE Identity
    print!("  - SGX QAE Identity: ");
    match v4_client.get_sgx_qae_identity(None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX QAE Identity", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                results.push(("SGX QAE Identity", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX QAE Identity", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 2.4 TDX QE Identity (V4 only)
    print!("  - TDX QE Identity: ");
    match v4_client.get_tdx_qe_identity(None, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("TDX QE Identity", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                results.push(("TDX QE Identity", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("TDX QE Identity", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    println!("\n3. Testing PCK CRL Endpoints...");
    println!("================================");

    // 3.1 PCK CRL - Processor (PEM)
    print!("  - PCK CRL (Processor, PEM): ");
    match v4_client.get_pck_crl(CaType::Processor, None).await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("PCK CRL (Processor)", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let crl_str = String::from_utf8_lossy(&response.crl_data);
                if crl_str.contains("BEGIN X509 CRL") {
                    println!("    Format: PEM");
                }
                results.push(("PCK CRL (Processor)", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("PCK CRL (Processor)", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 3.2 PCK CRL - Platform (DER)
    print!("  - PCK CRL (Platform, DER): ");
    match v4_client
        .get_pck_crl(CaType::Platform, Some(CrlEncoding::Der))
        .await
    {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("PCK CRL (Platform, DER)", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                println!("    CRL size: {} bytes", response.crl_data.len());
                results.push(("PCK CRL (Platform, DER)", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("PCK CRL (Platform, DER)", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    println!("\n4. Testing FMSPC Endpoints (V4 only)...");
    println!("=======================================");

    // 4.1 Get FMSPCs (no filter)
    print!("  - Get FMSPCs (no filter): ");
    match v4_client.get_fmspcs(None).await {
        Ok(fmspcs_json) => {
            println!("✓ Success");
            let fmspcs: serde_json::Value = serde_json::from_str(&fmspcs_json)?;
            if let Some(arr) = fmspcs.as_array() {
                println!("    Total FMSPCs: {}", arr.len());
                // Show first few FMSPCs
                for (i, fmspc) in arr.iter().take(3).enumerate() {
                    if let (Some(fmspc_val), Some(platform)) =
                        (fmspc["fmspc"].as_str(), fmspc["platform"].as_str())
                    {
                        println!("    [{}] {} - {}", i + 1, fmspc_val, platform);
                    }
                }
                if arr.len() > 3 {
                    println!("    ... and {} more", arr.len() - 3);
                }
            }
            results.push(("Get FMSPCs", true));
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("Get FMSPCs", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 4.2 Get FMSPCs with platform filter
    print!("  - Get FMSPCs (All platforms): ");
    match v4_client.get_fmspcs(Some(PlatformFilter::All)).await {
        Ok(_) => {
            println!("✓ Success");
            results.push(("Get FMSPCs (filtered)", true));
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("Get FMSPCs (filtered)", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    println!("\n5. Testing TCB Evaluation Data Numbers (V4 only)...");
    println!("===================================================");

    // 5.1 SGX TCB Evaluation Data Numbers
    print!("  - SGX TCB Evaluation Data Numbers: ");
    match v4_client.get_sgx_tcb_evaluation_data_numbers().await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("SGX TCB Eval Numbers", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let data: serde_json::Value =
                    serde_json::from_str(&response.tcb_evaluation_data_numbers_json)?;
                if let Some(sgx_data) = data.get("sgx") {
                    println!(
                        "    SGX entries: {}",
                        sgx_data.as_array().map(|a| a.len()).unwrap_or(0)
                    );
                }
                results.push(("SGX TCB Eval Numbers", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("SGX TCB Eval Numbers", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    // 5.2 TDX TCB Evaluation Data Numbers
    print!("  - TDX TCB Evaluation Data Numbers: ");
    match v4_client.get_tdx_tcb_evaluation_data_numbers().await {
        Ok(response) => {
            if response.issuer_chain.is_empty() {
                println!("✗ Failed: Empty issuer chain");
                results.push(("TDX TCB Eval Numbers", false));
            } else {
                println!("✓ Success");
                println!("    Issuer chain: {} bytes", response.issuer_chain.len());
                let data: serde_json::Value =
                    serde_json::from_str(&response.tcb_evaluation_data_numbers_json)?;
                if let Some(tdx_data) = data.get("tdx") {
                    println!(
                        "    TDX entries: {}",
                        tdx_data.as_array().map(|a| a.len()).unwrap_or(0)
                    );
                }
                results.push(("TDX TCB Eval Numbers", true));
            }
        }
        Err(e) => {
            println!("✗ Failed: {:?}", e);
            results.push(("TDX TCB Eval Numbers", false));
        }
    }

    sleep(Duration::from_millis(100)).await;

    println!("\n6. Testing PCK Certificate Endpoints...");
    println!("=======================================");

    /*    // 6.1 PCK Certificate by PPID (usually requires valid data)
        print!("  - PCK Certificate by PPID: ");
        let test_ppid = "0000000000000000000000000000000000000000000000000000000000000000";
        let test_cpusvn = "00000000000000000000000000000000";
        let test_pcesvn = "0000";
        let test_pceid = "0000";

        match v4_client
            .get_pck_certificate_by_ppid(test_ppid, test_cpusvn, test_pcesvn, test_pceid, None, None)
            .await
        {
            Ok(_) => {
                println!("✓ Success");
                results.push(("PCK Certificate", true));
            }
            Err(e) => {
                // Expected to fail with test data
                match &e {
                    IntelApiError::ApiError { status, .. } => {
                        println!("✗ Failed (Expected): HTTP {}", status);
                    }
                    _ => println!("✗ Failed: {:?}", e),
                }
                results.push(("PCK Certificate", false));
            }
        }

        sleep(Duration::from_millis(100)).await;
    */
    println!("\n7. Testing API Version Compatibility...");
    println!("=======================================");

    // 7.1 Try V4-only endpoint on V3
    print!("  - V4-only endpoint on V3 (should fail): ");
    match v3_client.get_fmspcs(None).await {
        Ok(_) => {
            println!("✗ Unexpected success!");
            results.push(("V3/V4 compatibility check", false));
        }
        Err(IntelApiError::UnsupportedApiVersion(_)) => {
            println!("✓ Correctly rejected");
            results.push(("V3/V4 compatibility check", true));
        }
        Err(e) => {
            println!("✗ Wrong error: {:?}", e);
            results.push(("V3/V4 compatibility check", false));
        }
    }

    println!("\n8. Testing Error Handling...");
    println!("============================");

    // 8.1 Invalid FMSPC
    print!("  - Invalid FMSPC format: ");
    match v4_client.get_sgx_tcb_info("invalid", None, None).await {
        Ok(_) => {
            println!("✗ Unexpected success!");
            results.push(("Error handling", false));
        }
        Err(IntelApiError::ApiError {
            status,
            error_code,
            error_message,
            ..
        }) => {
            println!("✓ Correctly handled");
            println!("    Status: {}", status);
            if let Some(code) = error_code {
                println!("    Error Code: {}", code);
            }
            if let Some(msg) = error_message {
                println!("    Error Message: {}", msg);
            }
            results.push(("Error handling", true));
        }
        Err(e) => {
            println!("✗ Unexpected error: {:?}", e);
            results.push(("Error handling", false));
        }
    }

    // Summary
    println!("\n\n=== Summary ===");
    println!("===============");

    let total = results.len();
    let successful = results.iter().filter(|(_, success)| *success).count();
    let failed = total - successful;

    println!("Total tests: {}", total);
    println!(
        "Successful:  {} ({}%)",
        successful,
        (successful * 100) / total
    );
    println!("Failed:      {} ({}%)", failed, (failed * 100) / total);

    println!("\nDetailed Results:");
    for (test, success) in &results {
        println!("  {} {}", if *success { "✓" } else { "✗" }, test);
    }

    println!("\nNote: Some failures are expected due to:");
    println!("- Test data not existing on Intel servers");
    println!("- PCK operations requiring valid platform data");
    println!("- Subscription key requirements for certain endpoints");

    Ok(())
}

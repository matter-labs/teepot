// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use base64::{engine::general_purpose, Engine as _};
use intel_dcap_api::{ApiClient, ApiVersion, CaType, CrlEncoding, PlatformFilter, UpdateType};
use std::{fs, path::Path};

/// Fetch real data from Intel API and save it as JSON files
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create test data directory
    let test_data_dir = Path::new("tests/test_data");
    fs::create_dir_all(test_data_dir)?;

    let client = ApiClient::new()?;

    println!("Fetching real test data from Intel API...");

    // Keep track of successful fetches
    let mut successes: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    // 1. Fetch SGX TCB info
    println!("\n1. Fetching SGX TCB info...");
    match client
        .get_sgx_tcb_info("00606A6A0000", Some(UpdateType::Standard), None)
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_tcb_info.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX TCB info".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX TCB info: {}", e));
        }
    }

    // 2. Fetch TDX TCB info
    println!("\n2. Fetching TDX TCB info...");
    match client
        .get_tdx_tcb_info("00806F050000", Some(UpdateType::Standard), None)
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("tdx_tcb_info.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("TDX TCB info".to_string());
        }
        Err(e) => {
            failures.push(format!("TDX TCB info: {}", e));
        }
    }

    // 3. Fetch PCK CRL for processor
    println!("\n3. Fetching PCK CRL (processor)...");
    match client.get_pck_crl(CaType::Processor, None).await {
        Ok(response) => {
            let crl_string = String::from_utf8_lossy(&response.crl_data);
            let data = serde_json::json!({
                "crl_data": crl_string,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("pck_crl_processor.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("PCK CRL (processor)".to_string());
        }
        Err(e) => {
            failures.push(format!("PCK CRL (processor): {}", e));
        }
    }

    // 4. Fetch PCK CRL for platform
    println!("\n4. Fetching PCK CRL (platform)...");
    match client.get_pck_crl(CaType::Platform, None).await {
        Ok(response) => {
            let crl_string = String::from_utf8_lossy(&response.crl_data);
            let data = serde_json::json!({
                "crl_data": crl_string,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("pck_crl_platform.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("PCK CRL (platform)".to_string());
        }
        Err(e) => {
            failures.push(format!("PCK CRL (platform): {}", e));
        }
    }

    // 5. Fetch SGX QE identity
    println!("\n5. Fetching SGX QE identity...");
    match client.get_sgx_qe_identity(None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "enclave_identity_json": response.enclave_identity_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_qe_identity.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX QE identity".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX QE identity: {}", e));
        }
    }

    // 6. Fetch SGX QVE identity
    println!("\n6. Fetching SGX QVE identity...");
    match client.get_sgx_qve_identity(None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "enclave_identity_json": response.enclave_identity_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_qve_identity.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX QVE identity".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX QVE identity: {}", e));
        }
    }

    // 7. Fetch TDX QE identity
    println!("\n7. Fetching TDX QE identity...");
    match client.get_tdx_qe_identity(None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "enclave_identity_json": response.enclave_identity_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("tdx_qe_identity.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("TDX QE identity".to_string());
        }
        Err(e) => {
            failures.push(format!("TDX QE identity: {}", e));
        }
    }

    // 8. Try an alternative FMSPC
    println!("\n8. Fetching alternative SGX TCB info...");
    match client.get_sgx_tcb_info("00906ED50000", None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_tcb_info_alt.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("Alternative SGX TCB info".to_string());
        }
        Err(e) => {
            failures.push(format!("Alternative SGX TCB info: {}", e));
        }
    }

    // 9. Fetch PCK certificate
    println!("\n9. Attempting to fetch PCK certificate...");
    let ppid = "3d6dd97e96f84536a2267e727dd860e4fdd3ffa3e319db41e8f69c9a43399e7b7ce97d7eb3bd05b0a58bdb5b90a0e218";
    let cpusvn = "0606060606060606060606060606060606060606060606060606060606060606";
    let pcesvn = "0a00";
    let pceid = "0000";

    match client
        .get_pck_certificate_by_ppid(ppid, cpusvn, pcesvn, pceid, None, None)
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "pck_cert_pem": response.pck_cert_pem,
                "issuer_chain": response.issuer_chain,
                "tcbm": response.tcbm,
                "fmspc": response.fmspc,
            });
            fs::write(
                test_data_dir.join("pck_cert.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("PCK certificate".to_string());
        }
        Err(e) => {
            failures.push(format!("PCK certificate: {}", e));
        }
    }

    // 10. Fetch SGX QAE identity
    println!("\n10. Fetching SGX QAE identity...");
    match client.get_sgx_qae_identity(None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "enclave_identity_json": response.enclave_identity_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_qae_identity.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX QAE identity".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX QAE identity: {}", e));
        }
    }

    // 11. Fetch FMSPCs
    println!("\n11. Fetching FMSPCs...");
    match client.get_fmspcs(Some(PlatformFilter::All)).await {
        Ok(fmspcs_json) => {
            let data = serde_json::json!({
                "fmspcs_json": fmspcs_json,
            });
            fs::write(
                test_data_dir.join("fmspcs.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("FMSPCs".to_string());
        }
        Err(e) => {
            failures.push(format!("FMSPCs: {}", e));
        }
    }

    // 12. Fetch SGX TCB evaluation data numbers
    println!("\n12. Fetching SGX TCB evaluation data numbers...");
    match client.get_sgx_tcb_evaluation_data_numbers().await {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_evaluation_data_numbers_json": response.tcb_evaluation_data_numbers_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_tcb_eval_nums.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX TCB evaluation data numbers".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX TCB evaluation data numbers: {}", e));
        }
    }

    // 13. Fetch TDX TCB evaluation data numbers
    println!("\n13. Fetching TDX TCB evaluation data numbers...");
    match client.get_tdx_tcb_evaluation_data_numbers().await {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_evaluation_data_numbers_json": response.tcb_evaluation_data_numbers_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("tdx_tcb_eval_nums.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("TDX TCB evaluation data numbers".to_string());
        }
        Err(e) => {
            failures.push(format!("TDX TCB evaluation data numbers: {}", e));
        }
    }

    // 14. Fetch PCK CRL with DER encoding
    println!("\n14. Fetching PCK CRL (processor, DER encoding)...");
    match client
        .get_pck_crl(CaType::Processor, Some(CrlEncoding::Der))
        .await
    {
        Ok(response) => {
            // For DER, save as base64
            let crl_base64 = general_purpose::STANDARD.encode(&response.crl_data);
            let data = serde_json::json!({
                "crl_data_base64": crl_base64,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("pck_crl_processor_der.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("PCK CRL (processor, DER)".to_string());
        }
        Err(e) => {
            failures.push(format!("PCK CRL (processor, DER): {}", e));
        }
    }

    // 15. Try different update types
    println!("\n15. Fetching SGX TCB info with Early update...");
    match client
        .get_sgx_tcb_info("00906ED50000", Some(UpdateType::Early), None)
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_tcb_info_early.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX TCB info (Early update)".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX TCB info (Early update): {}", e));
        }
    }

    // 16. Try with specific TCB evaluation data number
    println!("\n16. Fetching TDX TCB info with specific evaluation number...");
    match client
        .get_tdx_tcb_info("00806F050000", None, Some(17))
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("tdx_tcb_info_eval17.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("TDX TCB info (eval number 17)".to_string());
        }
        Err(e) => {
            failures.push(format!("TDX TCB info (eval number 17): {}", e));
        }
    }

    // 17. Try different FMSPCs
    println!("\n17. Fetching more SGX TCB info variations...");
    let test_fmspcs = vec!["00906ED50000", "00906C0F0000", "00A06F050000"];
    for fmspc in test_fmspcs {
        match client.get_sgx_tcb_info(fmspc, None, None).await {
            Ok(response) => {
                let data = serde_json::json!({
                    "tcb_info_json": response.tcb_info_json,
                    "issuer_chain": response.issuer_chain,
                });
                fs::write(
                    test_data_dir.join(format!("sgx_tcb_info_{}.json", fmspc)),
                    serde_json::to_string_pretty(&data)?,
                )?;
                successes.push(format!("SGX TCB info (FMSPC: {})", fmspc));
            }
            Err(e) => {
                failures.push(format!("SGX TCB info (FMSPC: {}): {}", fmspc, e));
            }
        }
    }

    // 18. Try FMSPCs with different platform filters
    println!("\n18. Fetching FMSPCs with different platform filters...");
    match client.get_fmspcs(None).await {
        Ok(fmspcs_json) => {
            let data = serde_json::json!({
                "fmspcs_json": fmspcs_json,
            });
            fs::write(
                test_data_dir.join("fmspcs_no_filter.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("FMSPCs (no filter)".to_string());
        }
        Err(e) => {
            failures.push(format!("FMSPCs (no filter): {}", e));
        }
    }

    match client.get_fmspcs(Some(PlatformFilter::All)).await {
        Ok(fmspcs_json) => {
            let data = serde_json::json!({
                "fmspcs_json": fmspcs_json,
            });
            fs::write(
                test_data_dir.join("fmspcs_all_platforms.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("FMSPCs (all platforms)".to_string());
        }
        Err(e) => {
            failures.push(format!("FMSPCs (all platforms): {}", e));
        }
    }

    // 19. Try PCK certificates with different parameters (encrypted PPID)
    println!("\n19. Attempting to fetch PCK certificates with different params...");
    // Try with a different encrypted PPID format
    let encrypted_ppid = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let pceid = "0000";

    match client
        .get_pck_certificates_by_ppid(encrypted_ppid, pceid, None, None)
        .await
    {
        Ok(response) => {
            let data = serde_json::json!({
                "pck_certificates_json": response.pck_certs_json,
                "issuer_chain": response.issuer_chain,
                "fmspc": response.fmspc,
            });
            fs::write(
                test_data_dir.join("pck_certificates.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("PCK certificates (by PPID)".to_string());
        }
        Err(e) => {
            failures.push(format!("PCK certificates (by PPID): {}", e));
        }
    }

    // 20. Try TDX TCB info with different FMSPCs
    println!("\n20. Fetching TDX TCB info variations...");
    let tdx_fmspcs = vec!["00806F050000", "00A06F050000", "00606A0000000"];
    for fmspc in tdx_fmspcs {
        match client.get_tdx_tcb_info(fmspc, None, None).await {
            Ok(response) => {
                let data = serde_json::json!({
                    "tcb_info_json": response.tcb_info_json,
                    "issuer_chain": response.issuer_chain,
                });
                fs::write(
                    test_data_dir.join(format!("tdx_tcb_info_{}.json", fmspc)),
                    serde_json::to_string_pretty(&data)?,
                )?;
                successes.push(format!("TDX TCB info (FMSPC: {})", fmspc));
            }
            Err(e) => {
                failures.push(format!("TDX TCB info (FMSPC: {}): {}", fmspc, e));
            }
        }
    }

    // 21. Try with V3 API for some endpoints
    println!("\n21. Testing V3 API endpoints...");
    let v3_client =
        ApiClient::new_with_options("https://api.trustedservices.intel.com", ApiVersion::V3)?;

    match v3_client.get_sgx_tcb_info("00906ED50000", None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "tcb_info_json": response.tcb_info_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_tcb_info_v3.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX TCB info (V3 API)".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX TCB info (V3 API): {}", e));
        }
    }

    match v3_client.get_sgx_qe_identity(None, None).await {
        Ok(response) => {
            let data = serde_json::json!({
                "enclave_identity_json": response.enclave_identity_json,
                "issuer_chain": response.issuer_chain,
            });
            fs::write(
                test_data_dir.join("sgx_qe_identity_v3.json"),
                serde_json::to_string_pretty(&data)?,
            )?;
            successes.push("SGX QE identity (V3 API)".to_string());
        }
        Err(e) => {
            failures.push(format!("SGX QE identity (V3 API): {}", e));
        }
    }

    println!("\n\nTest data fetching complete!");
    println!("\nSuccessful fetches:");
    for s in &successes {
        println!("  ✓ {}", s);
    }

    if !failures.is_empty() {
        println!("\nFailed fetches:");
        for f in &failures {
            println!("  ✗ {}", f);
        }
    }

    println!("\nData saved in: {}", test_data_dir.display());

    Ok(())
}

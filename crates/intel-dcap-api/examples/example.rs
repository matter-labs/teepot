// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{
    ApiClient, ApiVersion, CaType, CrlEncoding, EnclaveIdentityResponse, IntelApiError,
    PckCrlResponse, PlatformFilter, TcbInfoResponse,
};

#[tokio::main]
async fn main() -> Result<(), IntelApiError> {
    for api_version in [ApiVersion::V3, ApiVersion::V4] {
        println!("Using API version: {}", api_version);

        let client = ApiClient::new_with_version(api_version)?;

        // Example: Get SGX TCB Info
        let fmspc_example = "00606A000000"; // Example FMSPC from docs
        match client.get_sgx_tcb_info(fmspc_example, None, None).await {
            Ok(TcbInfoResponse {
                tcb_info_json,
                issuer_chain,
            }) => println!(
                "SGX TCB Info for {}:\n{}\nIssuer Chain: {}",
                fmspc_example, tcb_info_json, issuer_chain
            ),
            Err(e) => eprintln!("Error getting SGX TCB info: {}", e),
        }

        // Example: Get FMSPCs
        match client.get_fmspcs(Some(PlatformFilter::E3)).await {
            // Filter for E3 platform type [cite: 230]
            Ok(fmspc_list) => println!("\nE3 FMSPCs:\n{}", fmspc_list),
            Err(e) => eprintln!("Error getting FMSPCs: {}", e),
        }

        // Example: Get SGX QE Identity
        match client.get_sgx_qe_identity(None, None).await {
            Ok(EnclaveIdentityResponse {
                enclave_identity_json,
                issuer_chain,
            }) => {
                println!(
                    "\nSGX QE Identity:\n{}\nIssuer Chain: {}",
                    enclave_identity_json, issuer_chain
                )
            }
            Err(e) => eprintln!("Error getting SGX QE Identity: {}", e),
        }

        // Example: Get PCK CRL (Platform CA, PEM encoding)
        match client
            .get_pck_crl(CaType::Platform, Some(CrlEncoding::Pem))
            .await
        {
            // [cite: 118, 119]
            Ok(PckCrlResponse {
                crl_data,
                issuer_chain,
            }) => {
                // Attempt to decode PEM for display, otherwise show byte count
                match String::from_utf8(crl_data.clone()) {
                    Ok(pem_string) => println!(
                        "\nPlatform PCK CRL (PEM):\n{}\nIssuer Chain: {}",
                        pem_string, issuer_chain
                    ),
                    Err(_) => println!(
                        "\nPlatform PCK CRL ({} bytes, likely DER):\nIssuer Chain: {}",
                        crl_data.len(),
                        issuer_chain
                    ),
                }
            }
            Err(e) => eprintln!("Error getting PCK CRL: {}", e),
        }
    }

    Ok(())
}

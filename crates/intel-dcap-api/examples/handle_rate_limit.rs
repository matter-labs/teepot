// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

//! Example demonstrating automatic rate limit handling
//!
//! The Intel DCAP API client now automatically handles 429 Too Many Requests responses
//! by retrying up to 3 times by default. This example shows how to configure the retry
//! behavior and handle cases where all retries are exhausted.

use intel_dcap_api::{ApiClient, IntelApiError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create API client with default settings (3 retries)
    let mut client = ApiClient::new()?;

    println!("Example 1: Default behavior (automatic retries)");
    println!("================================================");

    // Example FMSPC value
    let fmspc = "00606A000000";

    // The client will automatically retry up to 3 times if rate limited
    match client.get_sgx_tcb_info(fmspc, None, None).await {
        Ok(tcb_info) => {
            println!("✓ Successfully retrieved TCB info");
            println!(
                "  TCB Info JSON length: {} bytes",
                tcb_info.tcb_info_json.len()
            );
            println!(
                "  Issuer Chain length: {} bytes",
                tcb_info.issuer_chain.len()
            );
        }
        Err(IntelApiError::TooManyRequests {
            request_id,
            retry_after,
        }) => {
            println!("✗ Rate limited even after 3 automatic retries");
            println!("  Request ID: {}", request_id);
            println!("  Last retry-after was: {} seconds", retry_after);
        }
        Err(e) => {
            eprintln!("✗ Other error: {}", e);
        }
    }

    println!("\nExample 2: Custom retry configuration");
    println!("=====================================");

    // Configure client to retry up to 5 times
    client.set_max_retries(5);
    println!("Set max retries to 5");

    match client.get_sgx_tcb_info(fmspc, None, None).await {
        Ok(_) => println!("✓ Request succeeded"),
        Err(IntelApiError::TooManyRequests { .. }) => {
            println!("✗ Still rate limited after 5 retries")
        }
        Err(e) => eprintln!("✗ Error: {}", e),
    }

    println!("\nExample 3: Disable automatic retries");
    println!("====================================");

    // Disable automatic retries
    client.set_max_retries(0);
    println!("Disabled automatic retries");

    match client.get_sgx_tcb_info(fmspc, None, None).await {
        Ok(_) => println!("✓ Request succeeded on first attempt"),
        Err(IntelApiError::TooManyRequests {
            request_id,
            retry_after,
        }) => {
            println!("✗ Rate limited (no automatic retry)");
            println!("  Request ID: {}", request_id);
            println!("  Retry after: {} seconds", retry_after);
            println!("  You would need to implement manual retry logic here");
        }
        Err(e) => eprintln!("✗ Error: {}", e),
    }

    println!("\nNote: The client handles rate limiting automatically!");
    println!("You only need to handle TooManyRequests errors if:");
    println!("- You disable automatic retries (set_max_retries(0))");
    println!("- All automatic retries are exhausted");

    Ok(())
}

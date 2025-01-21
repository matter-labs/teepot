// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use anyhow::{bail, Result};
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, Jitter, RetryTransientMiddleware};
use serde_json::Value;
use std::time::Duration;

const DEFAULT_INSTANCE_METADATA_BASE_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes";

async fn fetch_gcp_metadata(
    http_client: &ClientWithMiddleware,
    metadata_key: &str,
) -> Result<Value> {
    // Validate the metadata key:
    if metadata_key.is_empty() {
        bail!("Empty metadata_key");
    }

    let url = format!("{DEFAULT_INSTANCE_METADATA_BASE_URL}/{metadata_key}");

    // Make an HTTP GET request:
    let response = http_client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await?;

    // Handle response:
    if response.status().is_success() {
        let metadata_text = response.text().await?;
        serde_json::from_str(&metadata_text)
            .map_err(|e| anyhow::format_err!("Failed to parse metadata JSON: {}", e))
    } else {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "<empty>".to_string());
        bail!(
            "Failed to fetch metadata: {}, Response body: {}",
            status,
            error_body
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Build the client with retry middleware and exponential backoff:
    let retry_policy = ExponentialBackoff::builder()
        .retry_bounds(Duration::from_secs(1), Duration::from_secs(32))
        .jitter(Jitter::Bounded)
        .base(2)
        .build_with_total_retry_duration(Duration::from_secs(60));
    let client = ClientBuilder::new(Client::builder().build()?) // Underlying reqwest client
        .with(RetryTransientMiddleware::new_with_policy(retry_policy)) // Add retry middleware
        .build();

    // Fetch and display metadata:
    match fetch_gcp_metadata(&client, "container_config").await {
        Ok(container_config) => {
            println!("Container config:\n{:#?}", container_config);
        }
        Err(e) => {
            eprintln!("Error fetching container config: {}", e);
        }
    }

    Ok(())
}

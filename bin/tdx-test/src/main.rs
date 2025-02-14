// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use teepot::config::{load_config_with_telemetry, TelemetryConfig};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// Configuration struct
#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    server: ServerConfig,
    telemetry: TelemetryConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            telemetry: TelemetryConfig::new(
                env!("CARGO_CRATE_NAME").into(),
                env!("CARGO_PKG_VERSION").into(),
            ),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerConfig {
    port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { port: 8080 }
    }
}

// Error handling
#[derive(Error, Debug)]
enum AppError {
    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config =
        load_config_with_telemetry("APP".into(), |config: &AppConfig| &config.telemetry).await?;

    loop {
        error!(?config, "error test!");
        warn!(?config, "warn test!");
        info!(?config, "info test!");
        debug!(?config, "debug test!");
        trace!(?config, "trace test!");
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

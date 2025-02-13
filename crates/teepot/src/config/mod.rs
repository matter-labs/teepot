// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

//! Configuration handling

use async_trait::async_trait;
use config::{
    builder::AsyncState, AsyncSource, Config, ConfigBuilder, ConfigError, File, FileFormat, Format,
    Map,
};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{logs::LoggerProvider, runtime, Resource};
use opentelemetry_semantic_conventions::{
    attribute::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tracing::trace;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

const DEFAULT_INSTANCE_METADATA_BASE_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/container_config";

/// Get the configuration via HTTP
#[derive(Debug)]
pub struct HttpSource<F: Format> {
    /// the URI
    pub uri: String,
    /// the expected format
    pub format: F,
    /// if this is required, it will error, if not available
    pub required: bool,
}

#[async_trait]
impl<F: Format + Send + Sync + Debug> AsyncSource for HttpSource<F> {
    async fn collect(&self) -> Result<Map<String, config::Value>, ConfigError> {
        let response = match reqwest::get(&self.uri)
            .await
            .map_err(|e| ConfigError::Foreign(Box::new(e)))
        {
            Ok(response) => response,
            Err(e) => {
                if self.required {
                    return Err(e);
                } else {
                    return Ok(Map::new());
                }
            }
        };

        // error conversion is possible from custom AsyncSource impls
        response
            .text()
            .await
            .map_err(|e| ConfigError::Foreign(Box::new(e)))
            .and_then(|text| {
                self.format
                    .parse(Some(&self.uri), &text)
                    .map_err(ConfigError::Foreign)
            })
            .or_else(|res| {
                if self.required {
                    Err(res)
                } else {
                    Ok(Map::new())
                }
            })
    }
}

/// Main telemetry configuration container
#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// The crate name `env!("CARGO_CRATE_NAME")`
    pub crate_name: String,
    /// The package version `env!("CARGO_PKG_VERSION")`
    pub pkg_version: String,
    /// OpenTelemetry Protocol (OTLP) specific settings
    pub otlp: TelemetryOtlpConfig,
    /// Logging-specific configuration
    pub logging: TelemetryLoggingConfig,
}

impl TelemetryConfig {
    /// Create a new TelemetryConfig, usually with
    /// ```rust,
    /// # use teepot::config::TelemetryConfig;
    /// let telemetry_config = TelemetryConfig::new(
    ///                 env!("CARGO_CRATE_NAME").into(),
    ///                 env!("CARGO_PKG_VERSION").into(),
    ///             );
    /// ```
    pub fn new(crate_name: String, pkg_version: String) -> Self {
        Self {
            crate_name,
            pkg_version,
            otlp: TelemetryOtlpConfig::default(),
            logging: TelemetryLoggingConfig::default(),
        }
    }
}

/// Configuration for logging behavior
#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryLoggingConfig {
    /// The logging level (e.g., "debug", "info", "warn", "error")
    pub level: String,
    /// Whether to output logs in JSON format
    pub json: bool,
    /// Whether to output logs to console
    pub console: bool,
}

impl Default for TelemetryLoggingConfig {
    fn default() -> Self {
        Self {
            level: "warn".into(),
            json: false,
            console: true,
        }
    }
}

/// OpenTelemetry Protocol specific configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryOtlpConfig {
    /// Controls whether OpenTelemetry Protocol (OTLP) export is enabled.
    /// FIXME: has no effect right now
    pub enable: bool,
    /// The endpoint URL for the OpenTelemetry collector
    pub endpoint: String,
    /// The protocol to use for OTLP communication (e.g., "grpc", "http/protobuf")
    pub protocol: String,
}

impl Default for TelemetryOtlpConfig {
    fn default() -> Self {
        Self {
            enable: true,
            endpoint: "127.0.0.1:4317".to_string(),
            protocol: "grpc".to_string(),
        }
    }
}

fn protocol_from_string(protocol: &str) -> Result<opentelemetry_otlp::Protocol, anyhow::Error> {
    match protocol.to_lowercase().as_str() {
        "http/protobuf" => Ok(opentelemetry_otlp::Protocol::HttpBinary),
        "http/json" => Ok(opentelemetry_otlp::Protocol::HttpJson),
        "grpc" => Ok(opentelemetry_otlp::Protocol::Grpc),
        _ => Err(anyhow::anyhow!("Invalid protocol")),
    }
}

/// Loads configuration and sets up logging based on the provided configuration accessor
///
/// # Type Parameters
/// * `S` - Configuration type that implements Default, Serialize, Deserialize, and Send
///
/// # Arguments
/// * `get_telemetry_config` - Function to extract `TelemetryConfig` from type `S`
///
/// # Returns
/// * `Result<S>` - The loaded configuration or error
pub async fn load_config_with_telemetry<
    S: Default + Serialize + for<'a> Deserialize<'a> + Send + 'static,
>(
    get_telemetry_config: fn(&S) -> &TelemetryConfig,
) -> Result<S, Box<dyn std::error::Error + Send + Sync>> {
    with_console_logging(async move {
        trace!("Loading config");
        // Load configuration
        let config = ConfigBuilder::<AsyncState>::default()
            .add_source(Config::try_from(&S::default())?)
            .add_source(File::with_name("config/default").required(false))
            .add_source(
                config::Environment::with_prefix("APP")
                    .try_parsing(true)
                    .separator("_"),
            )
            .add_async_source(HttpSource {
                uri: DEFAULT_INSTANCE_METADATA_BASE_URL.into(),
                format: FileFormat::Json,
                required: false,
            })
            .build()
            .await?
            .try_deserialize::<S>()?;

        // Initialize telemetry
        init_telemetry(get_telemetry_config(&config))?;
        Ok::<S, Box<dyn std::error::Error + Send + Sync>>(config)
    })
    .await
}

fn create_console_format_layer<S>() -> tracing_subscriber::fmt::Layer<S>
where
    S: for<'a> tracing::Subscriber + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_ansi(true)
        .with_thread_names(true)
}

async fn with_console_logging<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Configure console logging
    let fmt_layer = create_console_format_layer();

    let subs = tracing_subscriber::registry()
        .with(EnvFilter::new("trace"))
        .with(fmt_layer.pretty());

    let _default = tracing::subscriber::set_default(subs);

    tracing_futures::WithSubscriber::with_current_subscriber(fut).await
}

fn init_telemetry(
    config: &TelemetryConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::env::set_var(
        "RUST_LOG",
        std::env::var("RUST_LOG").unwrap_or_else(|_| {
            format!(
                // `otel::tracing` should be a level info to emit opentelemetry trace & span
                // `otel::setup` set to debug to log detected resources, configuration read and infered
                "warn,{crate_name}={log_level},teepot={log_level},otel::tracing=error,otel=error",
                log_level = config.logging.level,
                crate_name = config.crate_name
            )
        }),
    );
    // Configure OpenTelemetry resource
    let resource = Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, config.crate_name.clone()),
            KeyValue::new(SERVICE_VERSION, config.pkg_version.clone()),
        ],
        SCHEMA_URL,
    );

    // Configure the OTLP exporter
    let logging_provider = LoggerProvider::builder()
        .with_batch_exporter(
            opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(&config.otlp.endpoint)
                .with_protocol(protocol_from_string(&config.otlp.protocol)?)
                .build()?,
            runtime::Tokio,
        )
        .with_resource(resource)
        .build();

    let logging_layer =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&logging_provider);

    // Configure console logging
    let fmt_layer = create_console_format_layer();

    // Combine layers based on configuration
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(logging_layer);

    // Add console logging if enabled
    if config.logging.console {
        // Optionally configure JSON logging
        if config.logging.json {
            subscriber.with(fmt_layer.json()).init()
        } else {
            subscriber.with(fmt_layer.pretty()).init()
        }
    } else {
        subscriber.init()
    };

    Ok(())
}

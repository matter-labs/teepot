// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Retry mechanism for handling transient failures

use std::time::Duration;
use tokio::time::sleep;

use crate::{
    core::{DEFAULT_RETRY_DELAY_MS, MAX_PROOF_FETCH_RETRIES},
    error::{Error, Result},
};

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Delay between retry attempts
    pub delay: Duration,
    /// Whether to use exponential backoff
    pub use_exponential_backoff: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: MAX_PROOF_FETCH_RETRIES,
            delay: Duration::from_millis(DEFAULT_RETRY_DELAY_MS),
            use_exponential_backoff: true,
        }
    }
}

/// Helper for executing operations with retries
pub struct RetryHelper {
    config: RetryConfig,
}

impl RetryHelper {
    /// Create a new retry helper with the given configuration
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Execute an operation with retries
    pub async fn execute<T, F, Fut>(&self, operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        let mut last_error;

        loop {
            attempt += 1;
            tracing::debug!(
                "Executing operation '{}' (attempt {}/{})",
                operation_name,
                attempt,
                self.config.max_attempts
            );

            match operation().await {
                Ok(result) => {
                    tracing::debug!(
                        "Operation '{}' succeeded on attempt {}",
                        operation_name,
                        attempt
                    );
                    return Ok(result);
                }
                Err(Error::Interrupted) => return Err(Error::Interrupted),
                Err(e) => {
                    last_error = e;

                    if attempt >= self.config.max_attempts {
                        tracing::warn!(
                            "Operation '{}' failed after {} attempts. Giving up.",
                            operation_name,
                            attempt
                        );
                        break;
                    }

                    let delay = if self.config.use_exponential_backoff {
                        self.config.delay.mul_f32(2.0_f32.powi(attempt as i32 - 1))
                    } else {
                        self.config.delay
                    };

                    tracing::warn!(
                        "Operation '{}' failed on attempt {}: {}. Retrying in {:?}...",
                        operation_name,
                        attempt,
                        last_error,
                        delay
                    );

                    sleep(delay).await;
                }
            }
        }

        Err(last_error)
    }
}

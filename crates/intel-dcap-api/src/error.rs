// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use reqwest::{Response, StatusCode};
use thiserror::Error;

/// Represents all possible errors that can occur when interacting with Intel's DCAP API.
#[derive(Error, Debug)]
pub enum IntelApiError {
    /// Indicates that the requested API version or feature is unsupported.
    #[error("Unsupported API version or feature: {0}")]
    UnsupportedApiVersion(String),

    /// Wraps an underlying reqwest error.
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    /// Wraps a URL parsing error.
    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Wraps a Serde JSON error.
    #[error("Serde JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Represents a general API error, capturing the HTTP status and optional error details.
    #[error("API Error: Status={status}, Request-ID={request_id}, Code={error_code:?}, Message={error_message:?}")]
    ApiError {
        /// HTTP status code returned by the API.
        status: StatusCode,
        /// The unique request identifier for tracing errors.
        request_id: String,
        /// An optional server-provided error code.
        error_code: Option<String>,
        /// An optional server-provided error message.
        error_message: Option<String>,
    },

    /// Indicates that a header is missing or invalid.
    #[error("Header missing or invalid: {0}")]
    MissingOrInvalidHeader(&'static str),

    /// Represents an invalid subscription key.
    #[error("Invalid Subscription Key format")]
    InvalidSubscriptionKey,

    /// Indicates that conflicting parameters were supplied.
    #[error("Cannot provide conflicting parameters: {0}")]
    ConflictingParameters(&'static str),

    /// Wraps a standard I/O error.
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),

    /// Represents an error while parsing a header's value.
    #[error("Header value parse error for '{0}': {1}")]
    HeaderValueParse(&'static str, String),

    /// Indicates an invalid parameter was provided.
    #[error("Invalid parameter value: {0}")]
    InvalidParameter(&'static str),
}

/// Extracts common API error details from response headers.
pub(crate) fn extract_api_error_details(
    response: &Response,
) -> (String, Option<String>, Option<String>) {
    let request_id = response
        .headers()
        .get("Request-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let error_code = response
        .headers()
        .get("Error-Code")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let error_message = response
        .headers()
        .get("Error-Message")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (request_id, error_code, error_message)
}

/// Checks the response status and returns an ApiError if it's not one of the expected statuses.
pub(crate) async fn check_status(
    response: Response,
    expected_statuses: &[StatusCode],
) -> Result<Response, IntelApiError> {
    let status = response.status();
    if expected_statuses.contains(&status) {
        Ok(response)
    } else {
        let (request_id, error_code, error_message) = extract_api_error_details(&response);
        Err(IntelApiError::ApiError {
            status,
            request_id,
            error_code,
            error_message,
        })
    }
}

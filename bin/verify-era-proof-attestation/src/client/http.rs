// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! HTTP client for making requests to external services

use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use url::Url;

use crate::{
    core::DEFAULT_HTTP_REQUEST_TIMEOUT,
    error::{Error, Result},
};

/// Client for making HTTP requests
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    /// Create a new HTTP client with default configuration
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_REQUEST_TIMEOUT))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Make a POST request to the specified URL with the provided body
    pub async fn post<T: Serialize>(&self, url: &Url, body: T) -> Result<String> {
        let response = self.client.post(url.clone()).json(&body).send().await?;
        self.handle_response(response).await
    }

    /// Send a JSON request and parse the response
    pub async fn send_json<T: Serialize, R: DeserializeOwned>(
        &self,
        url: &Url,
        body: T,
    ) -> Result<R> {
        let response_text = self.post(url, body).await?;
        let response: R = serde_json::from_str(&response_text)
            .map_err(|e| Error::JsonRpcInvalidResponse(e.to_string()))?;

        Ok(response)
    }

    /// Handle the HTTP response
    async fn handle_response(&self, response: reqwest::Response) -> Result<String> {
        let status = response.status();
        let body = response.text().await?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(Error::Http {
                status_code: status.as_u16(),
                message: body,
            })
        }
    }
}

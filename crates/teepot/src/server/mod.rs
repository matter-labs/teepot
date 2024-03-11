// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! # tee-server

#![deny(missing_docs)]
#![deny(clippy::all)]

pub mod attestation;
pub mod pki;
pub mod signatures;

use actix_web::http::StatusCode;
use actix_web::web::Bytes;
use actix_web::{error, HttpRequest, HttpResponse};
use actix_web::{HttpMessage, ResponseError};
use anyhow::anyhow;
use awc::error::{PayloadError, SendRequestError};
use awc::ClientResponse;
use futures_core::Stream;
use std::fmt::{Debug, Display, Formatter};
use tracing::error;

/// Anyhow error with an HTTP status code
pub struct AnyHowResponseError {
    /// error message
    pub error: anyhow::Error,
    /// HTTP status code
    pub status_code: StatusCode,
}

/// Proxy response error
pub struct ProxyResponseError {
    /// HTTP status code
    pub status_code: StatusCode,
    /// HTTP body
    pub body: Option<Bytes>,
    /// HTTP content type
    pub content_type: String,
}

/// custom HTTP response error
pub enum HttpResponseError {
    /// Anyhow error
    Anyhow(AnyHowResponseError),
    /// Proxy error
    Proxy(ProxyResponseError),
}

impl std::error::Error for HttpResponseError {}

/// Attach an HTTP status code to an anyhow error turning it into an HttpResponseError
pub trait Status {
    /// The Ok type
    type Ok;
    /// Attach an HTTP status code to an anyhow error turning it into an HttpResponseError
    fn status(self, status: StatusCode) -> Result<Self::Ok, HttpResponseError>;
}

impl<T> Status for Result<T, anyhow::Error> {
    type Ok = T;
    fn status(self, status: StatusCode) -> Result<T, HttpResponseError> {
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(HttpResponseError::new(error, status)),
        }
    }
}

impl HttpResponseError {
    fn new(error: anyhow::Error, status_code: StatusCode) -> Self {
        Self::Anyhow(AnyHowResponseError { error, status_code })
    }

    /// Create a new HTTP response error from a proxy response
    pub async fn from_proxy<S>(mut response: ClientResponse<S>) -> Self
    where
        S: Stream<Item = Result<Bytes, PayloadError>>,
    {
        let status_code = response.status();
        let body = response.body().await.ok();
        let content_type = response.content_type().to_string();

        error!(
            "Vault returned server error: {status_code} {}",
            body.as_ref()
                .map_or("", |b| std::str::from_utf8(b).unwrap_or(""))
        );

        Self::Proxy(ProxyResponseError {
            status_code,
            body,
            content_type,
        })
    }
}

impl From<&str> for HttpResponseError {
    fn from(value: &str) -> Self {
        error!("{}", value);
        HttpResponseError::new(
            anyhow!(value.to_string()),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

impl From<SendRequestError> for HttpResponseError {
    fn from(error: SendRequestError) -> Self {
        error!("Error sending request: {:?}", error);
        HttpResponseError::new(
            anyhow!(error.to_string()),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

impl Debug for HttpResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Self::Anyhow(e) = self {
            if f.alternate() {
                write!(f, "{:#?}", e.error)
            } else {
                write!(f, "{:?}", e.error)
            }
        } else {
            write!(f, "HttpResponseError")
        }
    }
}

impl Display for HttpResponseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Self::Anyhow(e) = self {
            if f.alternate() {
                write!(f, "{:#}", e.error)
            } else {
                write!(f, "{}", e.error)
            }
        } else {
            write!(f, "HttpResponseError")
        }
    }
}

impl ResponseError for HttpResponseError {
    fn status_code(&self) -> StatusCode {
        match self {
            HttpResponseError::Anyhow(e) => e.status_code,
            HttpResponseError::Proxy(e) => e.status_code,
        }
    }

    fn error_response(&self) -> HttpResponse {
        match self {
            HttpResponseError::Anyhow(e) => HttpResponse::build(self.status_code())
                .content_type("application/json")
                .body(format!(r#"{{"error":"{}"}}"#, e.error)),
            HttpResponseError::Proxy(e) => {
                if let Some(ref body) = e.body {
                    HttpResponse::build(self.status_code())
                        .content_type(e.content_type.clone())
                        .body(body.clone())
                } else {
                    HttpResponse::new(self.status_code())
                }
            }
        }
    }
}

/// Create a new json config
pub fn new_json_cfg() -> actix_web::web::JsonConfig {
    actix_web::web::JsonConfig::default()
        .limit(1024 * 1024)
        .error_handler(json_error_handler)
}

fn json_error_handler(err: error::JsonPayloadError, _: &HttpRequest) -> actix_web::Error {
    error::InternalError::from_response(
        "",
        HttpResponse::BadRequest()
            .content_type("application/json")
            .body(format!(r#"{{"error":"json error: {}"}}"#, err)),
    )
    .into()
}

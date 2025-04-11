// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct PckCertRequest<'a> {
    #[serde(rename = "platformManifest")]
    pub(crate) platform_manifest: &'a str,
    pub(crate) cpusvn: &'a str,
    pub(crate) pcesvn: &'a str,
    pub(crate) pceid: &'a str,
}

#[derive(Serialize)]
pub(crate) struct PckCertsRequest<'a> {
    #[serde(rename = "platformManifest")]
    pub(crate) platform_manifest: &'a str,
    pub(crate) pceid: &'a str,
}

#[derive(Serialize)]
pub(crate) struct PckCertsConfigRequest<'a> {
    #[serde(rename = "platformManifest")]
    pub(crate) platform_manifest: &'a str,
    pub(crate) cpusvn: &'a str,
    pub(crate) pceid: &'a str,
}

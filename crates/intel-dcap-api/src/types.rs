// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use std::fmt;

/// Represents the type of Certificate Authority (CA) for Intel Trusted Services.
///
/// This enum defines the different types of Certificate Authorities used in the Intel DCAP API,
/// specifically distinguishing between processor and platform CAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaType {
    /// Represents a processor-specific Certificate Authority.
    Processor,
    /// Represents a platform-wide Certificate Authority.
    Platform,
}

impl fmt::Display for CaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaType::Processor => write!(f, "processor"),
            CaType::Platform => write!(f, "platform"),
        }
    }
}

/// Represents the encoding format for Certificate Revocation Lists (CRLs).
///
/// This enum defines the supported encoding formats for CRLs in the Intel DCAP API,
/// distinguishing between PEM (Privacy Enhanced Mail) and DER (Distinguished Encoding Rules) formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlEncoding {
    /// Represents the PEM (Privacy Enhanced Mail) encoding format.
    Pem,
    /// Represents the DER (Distinguished Encoding Rules) encoding format.
    Der,
}

impl fmt::Display for CrlEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrlEncoding::Pem => write!(f, "pem"),
            CrlEncoding::Der => write!(f, "der"),
        }
    }
}

/// Represents the type of update for Intel Trusted Services.
///
/// This enum defines different update types, distinguishing between early and standard updates
/// in the Intel DCAP (Data Center Attestation Primitives) API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    /// Represents early updates, typically used for preview or beta releases.
    Early,
    /// Represents standard updates, which are the regular release cycle.
    Standard,
}

impl fmt::Display for UpdateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateType::Early => write!(f, "early"),
            UpdateType::Standard => write!(f, "standard"),
        }
    }
}

/// Represents the platform filter options for Intel DCAP (Data Center Attestation Primitives) API.
///
/// This enum allows filtering platforms based on different criteria,
/// such as selecting all platforms, client-specific platforms, or specific Intel processor generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFilter {
    /// Represents a selection of all available platforms.
    All,
    /// Represents a selection of client-specific platforms.
    Client,
    /// Represents platforms with Intel E3 processors.
    E3,
    /// Represents platforms with Intel E5 processors.
    E5,
}

impl fmt::Display for PlatformFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformFilter::All => write!(f, "all"),
            PlatformFilter::Client => write!(f, "client"),
            PlatformFilter::E3 => write!(f, "E3"),
            PlatformFilter::E5 => write!(f, "E5"),
        }
    }
}

/// Represents the version of the Intel Trusted Services API to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiVersion {
    /// Represents version 3 of the Intel Trusted Services API.
    V3,
    /// Represents version 4 of the Intel Trusted Services API.
    V4,
}

impl ApiVersion {
    /// Returns the string representation of the version for URL paths.
    pub fn path_segment(&self) -> &'static str {
        match self {
            ApiVersion::V3 => "v3",
            ApiVersion::V4 => "v4",
        }
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiVersion::V3 => write!(f, "v3"),
            ApiVersion::V4 => write!(f, "v4"),
        }
    }
}

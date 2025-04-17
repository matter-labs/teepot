// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Intel SGX Enclave TCB level wrapper

use enumset::EnumSetType;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

pub use enumset::EnumSet;

/// TCB level
#[derive(EnumSetType, Debug, Serialize, Deserialize)]
#[enumset(serialize_repr = "list")]
#[non_exhaustive]
pub enum TcbLevel {
    /// TCB is up to date
    Ok,
    /// TCB is up to date, but the configuration is not
    ConfigNeeded,
    /// TCB is up to date, but the configuration and software hardening is not
    ConfigAndSwHardeningNeeded,
    /// TCB is up to date, but the software hardening is not
    SwHardeningNeeded,
    /// TCB is out of date
    OutOfDate,
    /// TCB is out of date and the configuration is also out of date
    OutOfDateConfigNeeded,
    /// TCB level is invalid
    Invalid,
}

impl FromStr for TcbLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ok" | "uptodate" => Ok(TcbLevel::Ok),
            "configneeded" => Ok(TcbLevel::ConfigNeeded),
            "configandswhardeningneeded" => Ok(TcbLevel::ConfigAndSwHardeningNeeded),
            "swhardeningneeded" => Ok(TcbLevel::SwHardeningNeeded),
            "outofdate" => Ok(TcbLevel::OutOfDate),
            "outofdateconfigneeded" => Ok(TcbLevel::OutOfDateConfigNeeded),
            "invalid" => Ok(TcbLevel::Invalid),
            _ => Err(format!("Invalid TCB level: {s}")),
        }
    }
}

impl Display for TcbLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TcbLevel::Ok => write!(f, "Ok"),
            TcbLevel::ConfigNeeded => write!(f, "ConfigNeeded: Firmware needs to be updated"),
            TcbLevel::ConfigAndSwHardeningNeeded => write!(f, "ConfigAndSwHardeningNeeded: Firmware configuration needs to be updated and software hardening is needed"),
            TcbLevel::SwHardeningNeeded => write!(f, "SwHardeningNeeded: Software hardening is needed"),
            TcbLevel::OutOfDate => write!(f, "OutOfDate: Firmware needs to be updated"),
            TcbLevel::OutOfDateConfigNeeded => write!(f, "OutOfDateConfigNeeded: Firmware needs to be updated and configuration needs to be updated."),
            TcbLevel::Invalid => write!(f, "Invalid TCB level"),
        }
    }
}

/// Parse a comma-separated list of TCB levels
pub fn parse_tcb_levels(
    s: &str,
) -> Result<EnumSet<TcbLevel>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut set = EnumSet::new();
    for level_str in s.split(',') {
        let level_str = level_str.trim();
        let level =
            TcbLevel::from_str(level_str).map_err(|_| format!("Invalid TCB level: {level_str}"))?;
        set.insert(level);
    }
    Ok(set)
}

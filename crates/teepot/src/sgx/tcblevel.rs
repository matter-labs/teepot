// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Intel SGX Enclave TCB level wrapper

use enumset::EnumSetType;
use intel_tee_quote_verification_rs::sgx_ql_qv_result_t;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub use enumset::EnumSet;

/// TCB level
#[derive(EnumSetType, Debug)]
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

impl From<sgx_ql_qv_result_t> for TcbLevel {
    fn from(value: sgx_ql_qv_result_t) -> Self {
        match value {
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => TcbLevel::Ok,
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => TcbLevel::OutOfDate,
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
                TcbLevel::OutOfDateConfigNeeded
            }
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => TcbLevel::SwHardeningNeeded,
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
                TcbLevel::ConfigAndSwHardeningNeeded
            }
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => TcbLevel::ConfigNeeded,
            _ => TcbLevel::Invalid,
        }
    }
}

impl FromStr for TcbLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ok" => Ok(TcbLevel::Ok),
            "ConfigNeeded" => Ok(TcbLevel::ConfigNeeded),
            "ConfigAndSwHardeningNeeded" => Ok(TcbLevel::ConfigAndSwHardeningNeeded),
            "SwHardeningNeeded" => Ok(TcbLevel::SwHardeningNeeded),
            "OutOfDate" => Ok(TcbLevel::OutOfDate),
            "OutOfDateConfigNeeded" => Ok(TcbLevel::OutOfDateConfigNeeded),
            "Invalid" => Ok(TcbLevel::Invalid),
            _ => Err(()),
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
        let level = TcbLevel::from_str(level_str)
            .map_err(|_| format!("Invalid TCB level: {}", level_str))?;
        set.insert(level);
    }
    Ok(set)
}

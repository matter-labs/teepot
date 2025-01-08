// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Versioning of Intel SGX/TDX quote's report data for TEE prover and verifier.

use core::convert::Into;

use anyhow::{anyhow, Result};
use secp256k1::{constants::PUBLIC_KEY_SIZE, PublicKey};

/// Report data length for Intel SGX/TDX.
const REPORT_DATA_LENGTH: usize = 64;

/// Ethereum address length.
const ETHEREUM_ADDR_LENGTH: usize = 20;

/// Report data version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportData {
    /// Legacy version of report data that was initially not intended to be versioned.
    /// The report_data was on-chain incompatible and consisted of a compressed ECDSA public key.
    ///
    /// +-------------------------------------+--------------------------------+------------------+
    /// | compressed ECDSA pubkey (33 bytes)  | zeroes (30 bytes)              | version (1 byte) |
    /// +-------------------------------------+--------------------------------+------------------+
    V0(ReportDataV0),
    /// Latest version of report data compatible with on-chain verification.
    ///
    /// +--------------------------+-------------------------------------------+------------------+
    /// | Ethereum addr (20 bytes) | zeros (43 bytes)                          | version (1 byte) |
    /// +--------------------------+-------------------------------------------+------------------+
    V1(ReportDataV1),
    /// Unknown version of report data.
    Unknown(Vec<u8>),
}

impl TryFrom<&[u8]> for ReportData {
    type Error = anyhow::Error;

    fn try_from(report_data_bytes: &[u8]) -> Result<Self> {
        if report_data_bytes.len() != REPORT_DATA_LENGTH {
            return Err(anyhow!("Invalid byte slice length"));
        }
        let version = report_data_bytes[REPORT_DATA_LENGTH - 1];
        match version {
            0 => Ok(Self::V0(ReportDataV0::try_from(report_data_bytes)?)),
            1 => Ok(Self::V1(ReportDataV1::try_from(report_data_bytes)?)),
            _ => Ok(Self::Unknown(report_data_bytes.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ReportDataV0 {
    pub pubkey: PublicKey,
}

impl TryFrom<&[u8]> for ReportDataV0 {
    type Error = anyhow::Error;

    fn try_from(report_data_bytes: &[u8]) -> Result<Self> {
        if report_data_bytes.len() != REPORT_DATA_LENGTH {
            return Err(anyhow!("Invalid byte slice length"));
        }
        let pubkey = PublicKey::from_slice(&report_data_bytes[..PUBLIC_KEY_SIZE])?;
        Ok(Self { pubkey })
    }
}

impl Into<[u8; REPORT_DATA_LENGTH]> for ReportDataV0 {
    fn into(self) -> [u8; REPORT_DATA_LENGTH] {
        let mut bytes = [0u8; REPORT_DATA_LENGTH];
        bytes[..PUBLIC_KEY_SIZE].copy_from_slice(&self.pubkey.serialize());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ReportDataV1 {
    pub ethereum_addr: [u8; ETHEREUM_ADDR_LENGTH],
}

impl TryFrom<&[u8]> for ReportDataV1 {
    type Error = anyhow::Error;

    fn try_from(report_data_bytes: &[u8]) -> Result<Self> {
        if report_data_bytes.len() != REPORT_DATA_LENGTH {
            return Err(anyhow!("Invalid byte slice length"));
        }
        let mut ethereum_addr = [0u8; ETHEREUM_ADDR_LENGTH];
        ethereum_addr.copy_from_slice(&report_data_bytes[..ETHEREUM_ADDR_LENGTH]);
        Ok(Self { ethereum_addr })
    }
}

impl Into<[u8; REPORT_DATA_LENGTH]> for ReportDataV1 {
    fn into(self) -> [u8; REPORT_DATA_LENGTH] {
        let mut bytes = [0u8; REPORT_DATA_LENGTH];
        bytes[..ETHEREUM_ADDR_LENGTH].copy_from_slice(&self.ethereum_addr);
        bytes[REPORT_DATA_LENGTH - 1] = 1;
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use secp256k1::{Secp256k1, SecretKey};

    const ETHEREUM_ADDR: [u8; ETHEREUM_ADDR_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ];

    fn generate_test_report_data(version_byte: u8) -> [u8; REPORT_DATA_LENGTH] {
        let mut data = [0u8; REPORT_DATA_LENGTH];
        data[..ETHEREUM_ADDR.len()].copy_from_slice(&ETHEREUM_ADDR);
        data[REPORT_DATA_LENGTH - 1] = version_byte;
        data
    }

    fn generate_test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let secret_key_bytes =
            hex::decode("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3")
                .unwrap();
        let secret_key = SecretKey::from_slice(&secret_key_bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret_key)
    }

    fn generate_test_report_data_v0(pubkey: PublicKey) -> [u8; REPORT_DATA_LENGTH] {
        let pubkey_bytes = pubkey.serialize();
        let mut report_data_bytes = [0u8; REPORT_DATA_LENGTH];
        report_data_bytes[..PUBLIC_KEY_SIZE].copy_from_slice(&pubkey_bytes);
        report_data_bytes
    }

    #[test]
    fn test_from_bytes_v0() {
        let pubkey = generate_test_pubkey();
        let report_data_bytes = generate_test_report_data_v0(pubkey);
        let report_data = ReportData::try_from(report_data_bytes.as_ref()).unwrap();
        assert_eq!(report_data, ReportData::V0(ReportDataV0 { pubkey }));
    }

    #[test]
    fn report_data_from_bytes_v1() {
        let data = generate_test_report_data(1);
        let report_data = ReportData::try_from(data.as_ref()).unwrap();
        assert_eq!(
            report_data,
            ReportData::V1(ReportDataV1 {
                ethereum_addr: ETHEREUM_ADDR
            })
        );
    }

    #[test]
    fn report_data_from_bytes_unknown() {
        let report_data_bytes = generate_test_report_data(99);
        let report_data = ReportData::try_from(report_data_bytes.as_ref()).unwrap();
        assert_eq!(report_data, ReportData::Unknown(report_data_bytes.into()));
    }

    #[test]
    fn report_data_to_bytes_v0() {
        let pubkey = generate_test_pubkey();
        let report_data = ReportDataV0 { pubkey };
        let report_data: [u8; REPORT_DATA_LENGTH] = report_data.into();
        assert_eq!(&report_data[..PUBLIC_KEY_SIZE], pubkey.serialize().as_ref());
        assert_eq!(report_data[REPORT_DATA_LENGTH - 1], 0);
        assert!(report_data[PUBLIC_KEY_SIZE..REPORT_DATA_LENGTH - 1]
            .iter()
            .all(|&byte| byte == 0));
    }

    #[test]
    fn report_data_to_bytes_v1() {
        let report_data = ReportDataV1 {
            ethereum_addr: ETHEREUM_ADDR,
        };
        let report_data: [u8; REPORT_DATA_LENGTH] = report_data.into();
        assert_eq!(&report_data[..ETHEREUM_ADDR_LENGTH], &ETHEREUM_ADDR);
        assert_eq!(report_data[REPORT_DATA_LENGTH - 1], 1);
        assert!(report_data[ETHEREUM_ADDR_LENGTH..REPORT_DATA_LENGTH - 1]
            .iter()
            .all(|&byte| byte == 0));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

// Parts of it are Copyright (c) 2024 Phala Network
// and copied from https://github.com/Phala-Network/dcap-qvl

//! Get a quote from a TEE

pub mod attestation;
pub mod error;
pub mod tcblevel;

#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "intel.rs")]
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    path = "phala.rs"
)]
mod os;
mod utils;

use crate::quote::{
    error::{QuoteContext as _, QuoteError},
    tcblevel::TcbLevel,
};
use bytemuck::AnyBitPattern;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    io::Read,
    str::FromStr,
};
use tracing::trace;

#[allow(missing_docs)]
pub const TEE_TYPE_SGX: u32 = 0x0000_0000;
#[allow(missing_docs)]
pub const TEE_TYPE_TDX: u32 = 0x0000_0081;

#[allow(missing_docs)]
pub const BODY_SGX_ENCLAVE_REPORT_TYPE: u16 = 1;
#[allow(missing_docs)]
pub const BODY_TD_REPORT10_TYPE: u16 = 2;
#[allow(missing_docs)]
pub const BODY_TD_REPORT15_TYPE: u16 = 3;
#[allow(missing_docs)]
pub const ENCLAVE_REPORT_BYTE_LEN: usize = 384;

#[allow(missing_docs)]
pub const ECDSA_SIGNATURE_BYTE_LEN: usize = 64;
#[allow(missing_docs)]
pub const ECDSA_PUBKEY_BYTE_LEN: usize = 64;
#[allow(missing_docs)]
pub const QE_REPORT_SIG_BYTE_LEN: usize = ECDSA_SIGNATURE_BYTE_LEN;

mod serde_bytes {
    use serde::Deserialize;

    pub(crate) trait FromBytes {
        fn from_bytes(bytes: Vec<u8>) -> Option<Self>
        where
            Self: Sized;
    }
    impl FromBytes for Vec<u8> {
        fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
            Some(bytes)
        }
    }
    impl<const N: usize> FromBytes for [u8; N] {
        fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
            bytes.try_into().ok()
        }
    }

    pub(crate) fn serialize<S: serde::Serializer>(
        data: impl AsRef<[u8]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let hex_str = hex::encode(data);
        serializer.serialize_str(&hex_str)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>, T: FromBytes>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        T::from_bytes(bytes).ok_or_else(|| serde::de::Error::custom("invalid bytes"))
    }
}

/// Trait that allows zero-copy read of value-references from slices in LE format.
pub trait Decode: Sized {
    /// Attempt to deserialise the value from input.
    fn decode<I: Read>(input: &mut I) -> Result<Self, error::QuoteError>;
}

impl<T: AnyBitPattern> Decode for T {
    fn decode<I: Read>(input: &mut I) -> Result<Self, error::QuoteError> {
        let mut bytes = vec![0u8; size_of::<T>()];
        input.read(&mut bytes).context("parsing bytes")?;
        bytemuck::try_pod_read_unaligned(&bytes).map_err(Into::into)
    }
}

#[derive(Debug, Clone)]
#[allow(missing_docs)]
#[repr(C)]
pub struct Data<T> {
    pub data: Vec<u8>,
    _marker: core::marker::PhantomData<T>,
}

impl<T> Serialize for Data<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(&self.data, serializer)
    }
}

impl<'de, T> Deserialize<'de> for Data<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = serde_bytes::deserialize(deserializer)?;
        Ok(Data {
            data,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T: Decode + Into<u64>> Decode for Data<T> {
    fn decode<I: Read>(input: &mut I) -> Result<Self, QuoteError> {
        let len = T::decode(input)?;
        let mut data = vec![0u8; len.into() as usize];
        input.read(&mut data).context("reading bytes")?;
        Ok(Data {
            data,
            _marker: core::marker::PhantomData,
        })
    }
}

#[allow(missing_docs)]
#[derive(AnyBitPattern, Debug, Serialize, Deserialize, Copy, Clone)]
#[repr(C, packed)]
pub struct Header {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    #[serde(with = "serde_bytes")]
    pub qe_vendor_id: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub user_data: [u8; 20],
}

#[derive(AnyBitPattern, Debug, Copy, Clone)]
#[allow(missing_docs)]
#[repr(C, packed)]
pub struct Body {
    pub body_type: u16,
    pub size: u32,
}

#[derive(Serialize, Deserialize, AnyBitPattern, Debug, Clone, Copy)]
#[allow(missing_docs)]
#[repr(C, packed)]
pub struct EnclaveReport {
    #[serde(with = "serde_bytes")]
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    #[serde(with = "serde_bytes")]
    pub reserved1: [u8; 28],
    #[serde(with = "serde_bytes")]
    pub attributes: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_enclave: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved2: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub mr_signer: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub reserved3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    #[serde(with = "serde_bytes")]
    pub reserved4: [u8; 60],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

#[derive(AnyBitPattern, Debug, Copy, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C, packed)]
pub struct TDReport10 {
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_signer_seam: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub seam_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub td_attributes: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub xfam: [u8; 8],
    #[serde(with = "serde_bytes")]
    pub mr_td: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_config_id: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub mr_owner_config: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr0: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr1: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr2: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub rt_mr3: [u8; 48],
    #[serde(with = "serde_bytes")]
    pub report_data: [u8; 64],
}

#[derive(AnyBitPattern, Debug, Copy, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C, packed)]
pub struct TDReport15 {
    pub base: TDReport10,
    #[serde(with = "serde_bytes")]
    pub tee_tcb_svn2: [u8; 16],
    #[serde(with = "serde_bytes")]
    pub mr_service_td: [u8; 48],
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Clone)]
#[repr(C)]
pub struct CertificationData {
    pub cert_type: u16,
    pub body: Data<u32>,
}

impl Decode for CertificationData {
    fn decode<I: Read>(input: &mut I) -> Result<Self, QuoteError> {
        Ok(Self {
            cert_type: Decode::decode(input)?,
            body: Decode::decode(input)?,
        })
    }
}

impl core::fmt::Debug for CertificationData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let body_str = String::from_utf8_lossy(&self.body.data);
        f.debug_struct("CertificationData")
            .field("cert_type", &self.cert_type)
            .field("body", &body_str)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
pub struct QEReportCertificationData {
    #[serde(with = "serde_bytes")]
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

impl Decode for QEReportCertificationData {
    fn decode<I: Read>(input: &mut I) -> Result<Self, QuoteError> {
        Ok(Self {
            qe_report: Decode::decode(input)?,
            qe_report_signature: Decode::decode(input)?,
            qe_auth_data: Decode::decode(input)?,
            certification_data: Decode::decode(input)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
pub struct AuthDataV3 {
    #[serde(with = "serde_bytes")]
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report: [u8; ENCLAVE_REPORT_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub qe_report_signature: [u8; QE_REPORT_SIG_BYTE_LEN],
    pub qe_auth_data: Data<u16>,
    pub certification_data: CertificationData,
}

impl Decode for AuthDataV3 {
    fn decode<I: Read>(input: &mut I) -> Result<Self, QuoteError> {
        Ok(Self {
            ecdsa_signature: Decode::decode(input)?,
            ecdsa_attestation_key: Decode::decode(input)?,
            qe_report: Decode::decode(input)?,
            qe_report_signature: Decode::decode(input)?,
            qe_auth_data: Decode::decode(input)?,
            certification_data: Decode::decode(input)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
pub struct AuthDataV4 {
    #[serde(with = "serde_bytes")]
    pub ecdsa_signature: [u8; ECDSA_SIGNATURE_BYTE_LEN],
    #[serde(with = "serde_bytes")]
    pub ecdsa_attestation_key: [u8; ECDSA_PUBKEY_BYTE_LEN],
    pub certification_data: CertificationData,
    pub qe_report_data: QEReportCertificationData,
}

impl AuthDataV4 {
    #[allow(missing_docs)]
    pub fn into_v3(self) -> AuthDataV3 {
        AuthDataV3 {
            ecdsa_signature: self.ecdsa_signature,
            ecdsa_attestation_key: self.ecdsa_attestation_key,
            qe_report: self.qe_report_data.qe_report,
            qe_report_signature: self.qe_report_data.qe_report_signature,
            qe_auth_data: self.qe_report_data.qe_auth_data,
            certification_data: self.qe_report_data.certification_data,
        }
    }
}

impl Decode for AuthDataV4 {
    fn decode<I: Read>(input: &mut I) -> Result<Self, error::QuoteError> {
        let ecdsa_signature = Decode::decode(input)?;
        let ecdsa_attestation_key = Decode::decode(input)?;
        let certification_data: CertificationData = Decode::decode(input)?;
        let qe_report_data =
            QEReportCertificationData::decode(&mut &certification_data.body.data[..])?;
        Ok(AuthDataV4 {
            ecdsa_signature,
            ecdsa_attestation_key,
            certification_data,
            qe_report_data,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
pub enum AuthData {
    V3(AuthDataV3),
    V4(AuthDataV4),
}

impl AuthData {
    #[allow(missing_docs)]
    pub fn into_v3(self) -> AuthDataV3 {
        match self {
            AuthData::V3(data) => data,
            AuthData::V4(data) => data.into_v3(),
        }
    }
}

fn decode_auth_data(ver: u16, input: &mut &[u8]) -> Result<AuthData, error::QuoteError> {
    match ver {
        3 => {
            let auth_data = AuthDataV3::decode(input)?;
            Ok(AuthData::V3(auth_data))
        }
        4 => {
            let auth_data = AuthDataV4::decode(input)?;
            Ok(AuthData::V4(auth_data))
        }
        _ => Err(error::QuoteError::QuoteVersion),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
#[non_exhaustive]
pub enum Report {
    SgxEnclave(EnclaveReport),
    TD10(TDReport10),
    TD15(TDReport15),
}

impl Report {
    #[allow(missing_docs)]
    pub fn is_sgx(&self) -> bool {
        matches!(self, Report::SgxEnclave(_))
    }

    #[allow(missing_docs)]
    pub fn as_td10(&self) -> Option<&TDReport10> {
        match self {
            Report::TD10(report) => Some(report),
            Report::TD15(report) => Some(&report.base),
            _ => None,
        }
    }

    #[allow(missing_docs)]
    pub fn as_td15(&self) -> Option<&TDReport15> {
        match self {
            Report::TD15(report) => Some(report),
            _ => None,
        }
    }

    #[allow(missing_docs)]
    pub fn as_sgx(&self) -> Option<&EnclaveReport> {
        match self {
            Report::SgxEnclave(report) => Some(report),
            _ => None,
        }
    }
}

impl Display for Report {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn space_or_newline(f: &mut Formatter<'_>) -> std::fmt::Result {
            if f.alternate() {
                writeln!(f)
            } else {
                write!(f, " ")
            }
        }
        match self {
            Report::SgxEnclave(report_body) => {
                write!(f, "mrsigner: {}", hex::encode(report_body.mr_signer))?;
                space_or_newline(f)?;
                write!(f, "mrenclave: {}", hex::encode(report_body.mr_enclave))?;
                space_or_newline(f)?;
                write!(
                    f,
                    "reportdata: {}",
                    hex::encode(report_body.report_data.as_slice())
                )?;
            }
            Report::TD10(report_body) => {
                write!(f, "mrtd: {}", hex::encode(report_body.mr_td))?;
                space_or_newline(f)?;
                write!(f, "rtmr0: {}", hex::encode(report_body.rt_mr0))?;
                space_or_newline(f)?;
                write!(f, "rtmr1: {}", hex::encode(report_body.rt_mr1))?;
                space_or_newline(f)?;
                write!(f, "rtmr2: {}", hex::encode(report_body.rt_mr2))?;
                space_or_newline(f)?;
                write!(f, "rtmr3: {}", hex::encode(report_body.rt_mr3))?;
                space_or_newline(f)?;
                write!(
                    f,
                    "reportdata: {}",
                    hex::encode(report_body.report_data.as_slice())
                )?;
            }
            Report::TD15(report_body) => {
                let report_body = &report_body.base;
                write!(f, "mrtd: {}", hex::encode(report_body.mr_td))?;
                space_or_newline(f)?;
                write!(f, "rtmr0: {}", hex::encode(report_body.rt_mr0))?;
                space_or_newline(f)?;
                write!(f, "rtmr1: {}", hex::encode(report_body.rt_mr1))?;
                space_or_newline(f)?;
                write!(f, "rtmr2: {}", hex::encode(report_body.rt_mr2))?;
                space_or_newline(f)?;
                write!(f, "rtmr3: {}", hex::encode(report_body.rt_mr3))?;
                space_or_newline(f)?;
                write!(
                    f,
                    "reportdata: {}",
                    hex::encode(report_body.report_data.as_slice())
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[repr(C)]
pub struct Quote {
    pub header: Header,
    pub report: Report,
    pub auth_data: AuthData,
}

impl Decode for Quote {
    fn decode<I: Read>(input: &mut I) -> Result<Self, error::QuoteError> {
        let header = Header::decode(input)?;
        trace!(?header);
        let report;
        match header.version {
            3 => {
                if header.tee_type != TEE_TYPE_SGX {
                    return Err(error::QuoteError::InvalidTeeType);
                }
                report = Report::SgxEnclave(EnclaveReport::decode(input)?);
            }
            4 => match header.tee_type {
                TEE_TYPE_SGX => {
                    report = Report::SgxEnclave(EnclaveReport::decode(input)?);
                }
                TEE_TYPE_TDX => {
                    report = Report::TD10(TDReport10::decode(input)?);
                }
                _ => return Err(error::QuoteError::InvalidTeeType),
            },
            5 => {
                let body = Body::decode(input)?;
                match body.body_type {
                    BODY_SGX_ENCLAVE_REPORT_TYPE => {
                        report = Report::SgxEnclave(EnclaveReport::decode(input)?);
                    }
                    BODY_TD_REPORT10_TYPE => {
                        report = Report::TD10(TDReport10::decode(input)?);
                    }
                    BODY_TD_REPORT15_TYPE => {
                        report = Report::TD15(TDReport15::decode(input)?);
                    }
                    _ => return Err(error::QuoteError::UnsupportedBodyType),
                }
            }
            _ => return Err(error::QuoteError::QuoteVersion),
        }
        let data = Data::<u32>::decode(input)?;
        let auth_data = decode_auth_data(header.version, &mut &data.data[..])?;
        Ok(Quote {
            header,
            report,
            auth_data,
        })
    }
}

/// FMSPC (Family-Model-Stepping-Platform-CustomSKU) is a 6-byte identifier
/// that uniquely identifies a platform's SGX TCB level.
/// It is extracted from the PCK certificate in the SGX quote and is used to
/// fetch TCB information from Intel's Provisioning Certification Service.
pub type Fmspc = [u8; 6];

/// CPU Security Version Number (CPUSVN) is a 16-byte value representing
/// the security version of the CPU microcode and firmware.
/// It is used in SGX attestation to determine the security patch level
/// of the platform.
pub type CpuSvn = [u8; 16];

/// Security Version Number (SVN) is a 16-bit value representing the
/// security version of a component (like PCE or QE).
/// Higher values indicate newer security patches have been applied.
pub type Svn = u16;

impl Quote {
    /// Parse a TEE quote from a byte slice.
    pub fn parse(quote: &[u8]) -> Result<Self, QuoteError> {
        let mut input = quote;
        let quote = Quote::decode(&mut input)?;
        Ok(quote)
    }

    /// Get the raw certificate chain from the quote.
    pub fn raw_cert_chain(&self) -> Result<&[u8], QuoteError> {
        let cert_data = match &self.auth_data {
            AuthData::V3(data) => &data.certification_data,
            AuthData::V4(data) => &data.qe_report_data.certification_data,
        };
        if cert_data.cert_type != 5 {
            QuoteError::QuoteCertificationDataUnsupported(format!(
                "Unsupported cert type: {}",
                cert_data.cert_type
            ));
        }
        Ok(&cert_data.body.data)
    }

    /// Get the FMSPC from the quote.
    pub fn fmspc(&self) -> Result<Fmspc, QuoteError> {
        let raw_cert_chain = self.raw_cert_chain()?;
        let certs = utils::extract_certs(raw_cert_chain)?;
        let cert = certs
            .first()
            .ok_or(QuoteError::Unexpected("Invalid certificate".into()))?;
        let extension_section = utils::get_intel_extension(cert)?;
        utils::get_fmspc(&extension_section)
    }

    /// Get the report data
    pub fn get_report_data(&self) -> &[u8] {
        match &self.report {
            Report::SgxEnclave(r) => r.report_data.as_slice(),
            Report::TD10(r) => r.report_data.as_slice(),
            Report::TD15(r) => r.base.report_data.as_slice(),
        }
    }
}

/// TEE type
#[non_exhaustive]
pub enum TEEType {
    /// Intel SGX
    SGX,
    /// Intel TDX
    TDX,
    /// AMD SEV-SNP
    SNP,
}

impl Display for TEEType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            TEEType::SGX => "sgx",
            TEEType::TDX => "tdx",
            TEEType::SNP => "snp",
        };
        write!(f, "{str}")
    }
}

impl FromStr for TEEType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "sgx" => Ok(TEEType::SGX),
            "tdx" => Ok(TEEType::TDX),
            "snp" => Ok(TEEType::SNP),
            _ => Err("Invalid TEE type".to_string()),
        }
    }
}

/// Get the attestation quote from a TEE
pub fn get_quote(report_data: &[u8]) -> Result<(TEEType, Box<[u8]>), QuoteError> {
    os::get_quote(report_data)
}

/// The result of the quote verification
pub struct QuoteVerificationResult {
    /// the raw result
    pub result: TcbLevel,
    /// indicates if the collateral is expired
    pub collateral_expired: bool,
    /// the earliest expiration date of the collateral
    pub earliest_expiration_date: i64,
    /// Date of the TCB level
    pub tcb_level_date_tag: i64,
    /// the advisory string
    pub advisories: Vec<String>,
    /// the quote
    pub quote: Quote,
}

/// The collateral data needed to do remote attestation for SGX and TDX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collateral {
    /// Major version of the collateral data
    pub major_version: u16,
    /// Minor version of the collateral data
    pub minor_version: u16,
    /// Type of TEE (SGX=0, TDX=0x81)
    pub tee_type: u32,
    /// The PCK CRL issuer chain used for validating the PCK CRL
    pub pck_crl_issuer_chain: Box<[u8]>,
    /// The root CA CRL used for validating the PCK CRL issuer chain
    pub root_ca_crl: Box<[u8]>,
    /// The PCK CRL used for validating the PCK certificate
    pub pck_crl: Box<[u8]>,
    /// The TCB info issuer chain used for validating the TCB info
    pub tcb_info_issuer_chain: Box<[u8]>,
    /// The TCB info used for determining the TCB level
    pub tcb_info: Box<[u8]>,
    /// The QE identity issuer chain used for validating the QE identity
    pub qe_identity_issuer_chain: Box<[u8]>,
    /// The QE identity used for validating the QE
    pub qe_identity: Box<[u8]>,
}

/// Get the collateral data from an SGX or TDX quote
pub fn get_collateral(quote: &[u8]) -> Result<Collateral, QuoteError> {
    os::get_collateral(quote)
}

/// Verifies a quote with optional collateral material
pub fn verify_quote_with_collateral(
    quote: &[u8],
    collateral: Option<&Collateral>,
    current_time: i64,
) -> Result<QuoteVerificationResult, QuoteError> {
    os::verify_quote_with_collateral(quote, collateral, current_time)
}

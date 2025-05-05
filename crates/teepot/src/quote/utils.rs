// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

// Parts of it are Copyright (c) 2024 Phala Network
// and copied from https://github.com/Phala-Network/dcap-qvl

use crate::quote::{error::QuoteError, Fmspc};
use asn1_der::{
    typed::{DerDecodable, Sequence},
    DerObject,
};
use x509_cert::certificate::CertificateInner;

pub mod oids {
    use const_oid::ObjectIdentifier as OID;

    const fn oid(s: &str) -> OID {
        OID::new_unwrap(s)
    }

    pub const SGX_EXTENSION: OID = oid("1.2.840.113741.1.13.1");
    pub const FMSPC: OID = oid("1.2.840.113741.1.13.1.4");

    #[test]
    fn const_oid_works() {
        assert_eq!(
            SGX_EXTENSION.as_bytes(),
            oid("1.2.840.113741.1.13.1").as_bytes()
        );
    }
}
pub fn get_intel_extension(cert: &CertificateInner) -> Result<Vec<u8>, QuoteError> {
    let mut extension_iter = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|e| e.extn_id == oids::SGX_EXTENSION)
        .map(|e| e.extn_value.clone());

    let extension = extension_iter
        .next()
        .ok_or_else(|| QuoteError::Unexpected("Intel extension not found".into()))?;
    if extension_iter.next().is_some() {
        //"There should only be one section containing Intel extensions"
        return Err(QuoteError::Unexpected("Intel extension ambiguity".into()));
    }
    Ok(extension.into_bytes())
}

pub fn find_extension(path: &[&[u8]], raw: &[u8]) -> Result<Vec<u8>, QuoteError> {
    let obj = DerObject::decode(raw)
        .map_err(|_| QuoteError::Unexpected("Failed to decode DER object".into()))?;
    let subobj =
        get_obj(path, obj).map_err(|_| QuoteError::Unexpected("Failed to get subobject".into()))?;
    Ok(subobj.value().to_vec())
}

fn get_obj<'a>(path: &[&[u8]], mut obj: DerObject<'a>) -> Result<DerObject<'a>, QuoteError> {
    for oid in path {
        let seq = Sequence::load(obj)
            .map_err(|_| QuoteError::Unexpected("Failed to load sequence".into()))?;
        obj = sub_obj(oid, seq)
            .map_err(|_| QuoteError::Unexpected("Failed to get subobject".into()))?;
    }
    Ok(obj)
}

fn sub_obj<'a>(oid: &[u8], seq: Sequence<'a>) -> Result<DerObject<'a>, QuoteError> {
    for i in 0..seq.len() {
        let entry = seq
            .get(i)
            .map_err(|_| QuoteError::Unexpected("Failed to get entry".into()))?;
        let entry = Sequence::load(entry)
            .map_err(|_| QuoteError::Unexpected("Failed to load sequence".into()))?;
        let name = entry
            .get(0)
            .map_err(|_| QuoteError::Unexpected("Failed to get name".into()))?;
        let value = entry
            .get(1)
            .map_err(|_| QuoteError::Unexpected("Failed to get value".into()))?;
        if name.value() == oid {
            return Ok(value);
        }
    }
    Err(QuoteError::Unexpected("Oid is missing".into()))
}

pub fn get_fmspc(extension_section: &[u8]) -> Result<Fmspc, QuoteError> {
    let data = find_extension(&[oids::FMSPC.as_bytes()], extension_section)
        .map_err(|_| QuoteError::Unexpected("Failed to find Fmspc".into()))?;
    if data.len() != 6 {
        return Err(QuoteError::Unexpected("Fmspc length mismatch".into()));
    }

    data.try_into()
        .map_err(|_| QuoteError::Unexpected("Failed to decode Fmspc".into()))
}

pub fn extract_certs(cert_chain: &[u8]) -> Result<Vec<CertificateInner>, QuoteError> {
    let cert_chain = cert_chain.strip_suffix(&[0]).unwrap_or(cert_chain);

    CertificateInner::<x509_cert::certificate::Rfc5280>::load_pem_chain(cert_chain)
        .map_err(|e| QuoteError::Unexpected(format!("Could not load a PEM chain: {}", e)))
}

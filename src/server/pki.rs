// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Some cryptographic utilities

pub use crate::sgx::{
    parse_tcb_levels, sgx_ql_qv_result_t, verify_quote_with_collateral, EnumSet,
    QuoteVerificationResult, TcbLevel,
};
use anyhow::{anyhow, Context, Result};
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_CLIENT_AUTH,
    ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::SECP_256_R_1;
use getrandom::getrandom;
use pkcs8::der::asn1::OctetString;
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::referenced::RefToOwned;
use pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo,
    SubjectPublicKeyInfoRef,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sec1::EcPrivateKey;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::der::asn1::BitString;
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate};
use zeroize::Zeroizing;

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY as ECPK, SECP_256_R_1 as P256,
    SECP_384_R_1 as P384,
};
use pkcs8::der::asn1::BitStringRef;

const ES256: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
    oid: ECDSA_WITH_SHA_256,
    parameters: None,
};

const ES384: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
    oid: ECDSA_WITH_SHA_384,
    parameters: None,
};

/// Utility trait for signing with a private key
pub trait PrivateKeyInfoExt {
    /// Generates a keypair
    ///
    /// Returns the DER encoding of the `PrivateKeyInfo` type.
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>>;

    /// Get the public key
    ///
    /// This function creates a `SubjectPublicKeyInfo` which corresponds with
    /// this private key. Note that this function does not do any cryptographic
    /// calculations. It expects that the `PrivateKeyInfo` already contains the
    /// public key.
    fn public_key(&self) -> Result<SubjectPublicKeyInfoRef<'_>>;

    /// Get the default signing algorithm for this `SubjectPublicKeyInfo`
    fn signs_with(&self) -> Result<AlgorithmIdentifierRef<'_>>;

    /// Signs the body with the specified algorithm
    ///
    /// Note that the signature is returned in its encoded form as it will
    /// appear in an X.509 certificate or PKCS#10 certification request.
    fn sign(&self, body: &[u8], algo: AlgorithmIdentifierRef<'_>) -> Result<Vec<u8>>;
}

impl<'a> PrivateKeyInfoExt for PrivateKeyInfo<'a> {
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>> {
        let rand = ring::rand::SystemRandom::new();

        let doc = match oid {
            P256 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            P384 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            _ => return Err(anyhow!("unsupported")),
        };

        Ok(doc.as_ref().to_vec().into())
    }

    fn public_key(&self) -> Result<SubjectPublicKeyInfoRef<'_>> {
        match self.algorithm.oids()? {
            (ECPK, ..) => {
                let ec = EcPrivateKey::from_der(self.private_key)?;
                let pk = ec.public_key.ok_or_else(|| anyhow!("missing public key"))?;
                Ok(SubjectPublicKeyInfo {
                    algorithm: self.algorithm,
                    subject_public_key: BitStringRef::new(0, pk)?,
                })
            }
            _ => Err(anyhow!("unsupported")),
        }
    }

    fn signs_with(&self) -> Result<AlgorithmIdentifierRef<'_>> {
        match self.algorithm.oids()? {
            (ECPK, Some(P256)) => Ok(ES256),
            (ECPK, Some(P384)) => Ok(ES384),
            _ => Err(anyhow!("unsupported")),
        }
    }

    fn sign(&self, body: &[u8], algo: AlgorithmIdentifierRef<'_>) -> Result<Vec<u8>> {
        let rng = ring::rand::SystemRandom::new();
        match (self.algorithm.oids()?, algo) {
            ((ECPK, Some(P256)), ES256) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_der()?, &rng)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            ((ECPK, Some(P384)), ES384) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_der()?, &rng)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            _ => Err(anyhow!("unsupported")),
        }
    }
}

/// Create a private key and a self-signed certificate
pub fn make_self_signed_cert() -> Result<(
    [u8; 64],
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    // Generate a keypair.
    let raw = PrivateKeyInfo::generate(SECP_256_R_1).context("failed to generate a private key")?;
    let pki = PrivateKeyInfo::from_der(raw.as_ref())
        .context("failed to parse DER-encoded private key")?;
    let der = pki.public_key().unwrap().to_der().unwrap();

    let mut key_hash = [0u8; 64];
    let hash = Sha256::digest(der);
    key_hash[..32].copy_from_slice(&hash);

    // Create a relative distinguished name.
    let rdns = RdnSequence::from_str("CN=localhost")?;

    // Create the extensions.
    let ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment).to_der()?;
    let eu = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH]).to_der()?;
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    }
    .to_der()?;

    let mut serial = [0u8; 16];
    getrandom(&mut serial)?;

    // Create the certificate body.
    let tbs = TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: SerialNumber::new(&serial)?,
        signature: pki.signs_with()?.ref_to_owned(),
        issuer: rdns.clone(),
        validity: Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365))?,
        subject: rdns,
        subject_public_key_info: pki.public_key()?.ref_to_owned(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            x509_cert::ext::Extension {
                extn_id: ID_CE_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new(ku)?,
            },
            x509_cert::ext::Extension {
                extn_id: ID_CE_BASIC_CONSTRAINTS,
                critical: true,
                extn_value: OctetString::new(bc)?,
            },
            x509_cert::ext::Extension {
                extn_id: ID_CE_EXT_KEY_USAGE,
                critical: false,
                extn_value: OctetString::new(eu)?,
            },
        ]),
    };

    // Self-sign the certificate.
    let alg = tbs.signature.clone();
    let sig = pki.sign(&tbs.to_der()?, alg.owned_to_ref())?;
    let crt = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(&sig)?,
    };

    let rustls_certificate = rustls::pki_types::CertificateDer::from(crt.to_der()?);
    let rustls_pk = rustls::pki_types::PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pki.to_der()?));
    Ok((key_hash, rustls_certificate, rustls_pk))
}

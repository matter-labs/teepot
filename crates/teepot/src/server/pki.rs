// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Create a private key and a signed and self-signed certificates

use crate::quote::{error::QuoteContext, get_quote};
pub use crate::sgx::{parse_tcb_levels, sgx_ql_qv_result_t, EnumSet, TcbLevel};
use anyhow::{Context, Result};
use const_oid::{
    db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH},
    AssociatedOid,
};
use intel_tee_quote_verification_rs::tee_qv_get_collateral;
use p256::{ecdsa::DerSignature, pkcs8::EncodePrivateKey};
use pkcs8::der;
use rand::rngs::OsRng;
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use signature::Signer;
use std::{str::FromStr, time::Duration};
use tracing::debug;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{asn1::OctetString, pem::LineEnding, Encode as _, EncodePem as _, Length},
    ext::{
        pkix::{name::GeneralNames, ExtendedKeyUsage, SubjectAltName},
        AsExtension, Extension,
    },
    name::{Name, RdnSequence},
    serial_number::SerialNumber,
    spki::{
        DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier,
        SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
    },
    time::Validity,
    Certificate,
};
use zeroize::Zeroizing;

/// The OID for the `gramine-ra-tls` quote extension
pub const ID_GRAMINE_RA_TLS_QUOTE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1337.6");

/// The OID for the `enarx-ra-tls` collateral extension
/// TODO: this OID is just made up in `enarx` OID namespace, reserve it somehow
pub const ID_GRAMINE_RA_TLS_COLLATERAL: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.99");

/// The `gramine-ra-tls` x509 extension
pub struct RaTlsQuoteExtension {
    /// The hash of the certificate's public key
    pub quote: Vec<u8>,
}

impl AssociatedOid for RaTlsQuoteExtension {
    const OID: ObjectIdentifier = ID_GRAMINE_RA_TLS_QUOTE;
}

impl x509_cert::der::Encode for RaTlsQuoteExtension {
    fn encoded_len(&self) -> pkcs8::der::Result<Length> {
        unimplemented!()
    }

    fn encode(
        &self,
        _writer: &mut impl x509_cert::der::Writer,
    ) -> Result<(), x509_cert::der::Error> {
        unimplemented!()
    }
}

impl AsExtension for RaTlsQuoteExtension {
    fn critical(&self, _: &x509_cert::name::Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
    fn to_extension(
        &self,
        _subject: &Name,
        _extensions: &[Extension],
    ) -> std::result::Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: false,
            extn_value: OctetString::new(self.quote.as_slice())?,
        })
    }
}

/// The `gramine-ra-tls` x509 extension
pub struct RaTlsCollateralExtension {
    /// The hash of the certificate's public key
    pub collateral: Vec<u8>,
}

impl AssociatedOid for RaTlsCollateralExtension {
    const OID: ObjectIdentifier = ID_GRAMINE_RA_TLS_COLLATERAL;
}

impl x509_cert::der::Encode for RaTlsCollateralExtension {
    fn encoded_len(&self) -> pkcs8::der::Result<Length> {
        unimplemented!()
    }

    fn encode(
        &self,
        _writer: &mut impl x509_cert::der::Writer,
    ) -> Result<(), x509_cert::der::Error> {
        unimplemented!()
    }
}

impl AsExtension for RaTlsCollateralExtension {
    fn critical(&self, _: &x509_cert::name::Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
    fn to_extension(
        &self,
        _subject: &Name,
        _extensions: &[Extension],
    ) -> std::result::Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: false,
            extn_value: OctetString::new(self.collateral.as_slice())?,
        })
    }
}

/// Create a private key and a self-signed certificate
pub fn make_self_signed_cert(
    dn: &str,
    an: Option<GeneralNames>,
) -> Result<(
    [u8; 64],
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    // Generate a keypair.
    let mut rng = OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let verifying_key_der = verifying_key
        .to_public_key_der()
        .context("failed to create public key der")?;

    let mut key_hash = [0u8; 64];
    let hash = Sha256::digest(verifying_key_der.as_bytes());
    key_hash[..32].copy_from_slice(&hash);

    let (_tee_type, quote) = get_quote(&key_hash)?;
    debug!("quote.len: {:?}", quote.len());
    // Create a relative distinguished name.
    let rdns = RdnSequence::from_str(dn)?;
    let collateral = tee_qv_get_collateral(&quote).context("Failed to get own collateral")?;

    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial)?;

    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: rdns.clone(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        },
        SerialNumber::new(&serial)?,
        Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365 * 10))?,
        rdns,
        SubjectPublicKeyInfoOwned::try_from(verifying_key_der.as_bytes())
            .context("failed to create SubjectPublicKeyInfo")?,
        &signing_key,
    )
    .context("failed to create CertificateBuilder")?;

    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ID_KP_SERVER_AUTH,
            ID_KP_CLIENT_AUTH,
        ]))
        .context("failed to add ExtendedKeyUsage")?;

    if let Some(an) = an {
        builder
            .add_extension(&SubjectAltName(an))
            .context("failed to add SubjectAltName")?;
    }

    // FIXME: OID for tee_type
    builder
        .add_extension(&RaTlsQuoteExtension {
            quote: quote.to_vec(),
        })
        .context("failed to add GRAMINE_RA_TLS")?;

    builder
        .add_extension(&RaTlsCollateralExtension {
            collateral: serde_json::to_vec(&collateral).context("failed to add GRAMINE_RA_TLS")?,
        })
        .context("failed to add GRAMINE_RA_TLS")?;

    let crt = builder.build::<DerSignature>().unwrap();
    let rustls_certificate = rustls::pki_types::CertificateDer::from(crt.to_der()?);
    let signing_key_der = signing_key
        .to_pkcs8_der()
        .context("failed to encode PKCS#8")?;

    let rustls_pk = rustls::pki_types::PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        signing_key_der.as_bytes(),
    ))
    .clone_key();
    Ok((key_hash, rustls_certificate, rustls_pk))
}

/// Create a private key and a self-signed certificate
pub fn make_signed_cert<S, Signature>(
    dn: &str,
    an: Option<GeneralNames>,
    issuer_cert: &Certificate,
    issuer_key: &S,
) -> Result<([u8; 64], String, Zeroizing<String>)>
where
    Signature: SignatureBitStringEncoding,
    S: signature::Keypair + DynSignatureAlgorithmIdentifier + Signer<Signature>,
    S::VerifyingKey: EncodePublicKey,
{
    // Generate a keypair.
    let mut rng = rand::rngs::OsRng;
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let verifying_key_der = verifying_key
        .to_public_key_der()
        .context("failed to create public key der")?;

    let mut key_hash = [0u8; 64];
    let hash = Sha256::digest(verifying_key_der.as_bytes());
    key_hash[..32].copy_from_slice(&hash);

    let (_tee_type, quote) = get_quote(&key_hash).context("Failed to get own quote")?;

    // Create a relative distinguished name.
    let subject = Name::from_str(dn)?;

    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial)?;

    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        },
        SerialNumber::new(&serial)?,
        Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365 * 10))?,
        subject,
        SubjectPublicKeyInfoOwned::try_from(verifying_key_der.as_bytes())
            .context("failed to create SubjectPublicKeyInfo")?,
        issuer_key,
    )
    .context("failed to create CertificateBuilder")?;
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ID_KP_SERVER_AUTH,
            ID_KP_CLIENT_AUTH,
        ]))
        .context("failed to add ExtendedKeyUsage")?;

    if let Some(an) = an {
        builder
            .add_extension(&SubjectAltName(an))
            .context("failed to add SubjectAltName")?;
    }

    // FIXME: oid according to tee_type
    builder
        .add_extension(&RaTlsQuoteExtension {
            quote: quote.to_vec(),
        })
        .context("failed to add GRAMINE_RA_TLS")?;

    let crt = builder.build::<Signature>().unwrap();
    let cert_pem = crt.to_pem(LineEnding::LF)?;
    let key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;

    Ok((key_hash, cert_pem, key_pem))
}

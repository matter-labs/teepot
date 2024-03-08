// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Matter Labs

//! Signature checking utilities

use crate::json::secrets::AdminConfig;
use crate::server::{HttpResponseError, Status as _};
use actix_web::http::StatusCode;
use anyhow::{anyhow, bail, Context, Result};
use pgp::types::KeyTrait;
use pgp::{Deserializable, SignedPublicKey, StandaloneSignature};
use tracing::debug;

/// Verify a pgp signature for some message given some public keys
pub fn verify_sig(sig: &str, msg: &[u8], keys: &[SignedPublicKey]) -> anyhow::Result<usize> {
    let (signatures, _) =
        StandaloneSignature::from_string_many(sig).context(format!("reading signature {}", sig))?;

    for signature in signatures {
        let signature = match signature {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to parse signature: {}", e);
                continue;
            }
        };

        for (pos, key) in keys.iter().enumerate() {
            let actual_key = &key.primary_key;
            if actual_key.is_signing_key() && signature.verify(&actual_key, msg).is_ok() {
                return Ok(pos);
            }
            for sub_key in &key.public_subkeys {
                if sub_key.is_signing_key() && signature.verify(sub_key, msg).is_ok() {
                    return Ok(pos);
                }
            }
        }
    }
    eprintln!("Failed to verify signature for `{sig}`");
    bail!("Failed to verify signature for `{sig}`");
}

/// Verify pgp signatures for a message with some threshold
pub fn check_sigs(
    pgp_keys: &[Box<[u8]>],
    threshold: usize,
    signatures: &[String],
    msg: &[u8],
) -> Result<(), HttpResponseError> {
    let mut keys = Vec::new();

    for bytes in pgp_keys {
        let key = SignedPublicKey::from_bytes(bytes.as_ref())
            .context("parsing public key")
            .status(StatusCode::INTERNAL_SERVER_ERROR)?;
        keys.push(key);
    }

    let mut verified: usize = 0;

    for sig in signatures {
        if let Ok(pos) = verify_sig(sig, msg, &keys) {
            keys.remove(pos);
            verified += 1;
        }
        if verified >= threshold {
            break;
        }
    }

    if verified < threshold {
        return Err(anyhow!("not enough valid signatures")).status(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

/// Verify pgp signatures for a message
pub trait VerifySig {
    /// Verify pgp signatures for a message
    fn check_sigs(&self, signatures: &[String], msg: &[u8]) -> Result<(), HttpResponseError>;
}

impl VerifySig for AdminConfig {
    fn check_sigs(&self, signatures: &[String], msg: &[u8]) -> Result<(), HttpResponseError> {
        check_sigs(&self.admin_pgp_keys, self.admin_threshold, signatures, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::verify_sig;
    use base64::{engine::general_purpose, Engine as _};
    use pgp::{Deserializable, SignedPublicKey};

    const TEST_DATA: &str = include_str!("../../tests/data/test.json");

    // gpg --armor --local-user test@example.com --detach-sign bin/tee-vault-admin/tests/data/test.json
    const TEST_SIG: &str = include_str!("../../tests/data/test.json.asc");

    // gpg --armor --export 81A312C59D679D930FA9E8B06D728F29A2DBABF8  > bin/tee-vault-admin/tests/data/pub-81A312C59D679D930FA9E8B06D728F29A2DBABF8.asc
    const TEST_KEY: &str =
        include_str!("../../tests/data/pub-81A312C59D679D930FA9E8B06D728F29A2DBABF8.asc");

    const TEST_KEY_BASE64: &str =
        include_str!("../../tests/data/pub-81A312C59D679D930FA9E8B06D728F29A2DBABF8.b64");

    #[test]
    fn test_sig() {
        let test_key = SignedPublicKey::from_string(TEST_KEY).unwrap().0;
        verify_sig(TEST_SIG, TEST_DATA.as_bytes(), &[test_key]).unwrap();
    }

    #[test]
    fn test_key_import() {
        let str = TEST_KEY_BASE64.lines().collect::<String>();
        let bytes = general_purpose::STANDARD.decode(str).unwrap();
        let _ = SignedPublicKey::from_bytes(bytes.as_slice()).unwrap();
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

//! Signature checking utilities

use crate::server::{HttpResponseError, Status as _};
use actix_web::http::StatusCode;
use anyhow::{anyhow, bail, Context, Result};
use pgp::types::KeyTrait;
use pgp::{Deserializable, SignedPublicKey, StandaloneSignature};
use serde::{Deserialize, Serialize};
use tracing::{error, trace};

impl MultiSigPolicy {
    /// validate the policy
    pub fn validate(&self) -> Result<()> {
        if self.threshold == 0 {
            bail!("admin_threshold must be greater than 0");
        }
        if self.members.is_empty() {
            bail!("validation elements must not be empty");
        }
        if self.threshold > self.members.len() {
            bail!("threshold must be smaller than number of elements");
        }
        for ele in self.members.iter() {
            match ele {
                KeyOrChilds::Key(key) => {
                    SignedPublicKey::from_string(key)?;
                }
                KeyOrChilds::Child(child) => {
                    child.validate()?;
                }
            }
        }
        Ok(())
    }
}

/// M of N Signature Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigPolicy {
    /// Name of this level
    pub name: String,
    /// Array of PGP key for validation or Self
    pub members: Box<[KeyOrChilds]>,
    /// Threshold for validation
    pub threshold: usize,
}

/// A m of n child can be a m of n KeyOrChilds or a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOrChilds {
    /// a key
    Key(String),
    /// a sub m of n
    Child(MultiSigPolicy),
}

/// Verify a pgp signature for some message given some public keys
pub fn verify_sig(sig: &str, msg: &[u8], keys: &[SignedPublicKey]) -> anyhow::Result<usize> {
    let (signatures, _) =
        StandaloneSignature::from_string_many(sig).context(format!("reading signature {}", sig))?;

    for signature in signatures {
        let signature = match signature {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to parse signature: {}", e);
                continue;
            }
        };

        for (pos, key) in keys.iter().enumerate() {
            let actual_key = &key.primary_key;
            if actual_key.is_signing_key() {
                trace!(
                    "Checking with key {}",
                    hex::encode(actual_key.fingerprint())
                );
                if signature.verify(&actual_key, msg).is_ok() {
                    trace!(
                        "Verified with key {}",
                        hex::encode(actual_key.fingerprint())
                    );
                    return Ok(pos);
                }
            }
            for actual_key in &key.public_subkeys {
                if actual_key.is_signing_key() {
                    trace!(
                        "Checking with subkey {}",
                        hex::encode(actual_key.fingerprint())
                    );
                    if signature.verify(actual_key, msg).is_ok() {
                        trace!(
                            "Verified with key {}",
                            hex::encode(actual_key.fingerprint())
                        );
                        return Ok(pos);
                    }
                }
            }
        }
    }
    trace!("Failed to verify signature for `{sig}`");
    bail!("Failed to verify signature for `{sig}`");
}

impl MultiSigPolicy {
    /// Verify pgp signatures for a message with the current policy
    pub fn check_sigs(&self, signatures: &[String], msg: &[u8]) -> Result<(), HttpResponseError> {
        fn inner_check_sigs(
            admin_config: &MultiSigPolicy,
            signatures: &[String],
            msg: &[u8],
        ) -> Result<(), HttpResponseError> {
            let mut keys = Vec::new();
            let mut verified: usize = 0;

            for key_or_child in admin_config.members.as_ref() {
                match key_or_child {
                    KeyOrChilds::Key(key) => {
                        // This is not a performance critical path, so we can import from bytes every time
                        let (key, _) = SignedPublicKey::from_string(key)
                            .context("parsing public key")
                            .status(StatusCode::INTERNAL_SERVER_ERROR)?;
                        keys.push(key);
                    }
                    KeyOrChilds::Child(child) => {
                        if inner_check_sigs(child, signatures, msg).is_ok() {
                            verified += 1;
                        }
                    }
                }
            }

            if verified < admin_config.threshold {
                for sig in signatures {
                    if let Ok(pos) = verify_sig(sig, msg, &keys) {
                        keys.remove(pos);
                        verified += 1;
                    }
                    if verified >= admin_config.threshold {
                        break;
                    }
                }
            }

            if verified < admin_config.threshold {
                return Err(anyhow!("not enough valid signatures")).status(StatusCode::BAD_REQUEST);
            }
            Ok(())
        }

        inner_check_sigs(self, signatures, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::{Deserializable, SignedPublicKey};
    use test_log::test;

    const TEST_DATA: &str = include_str!("../../tests/data/test.json");

    // gpg --armor --local-user test@example.com --detach-sign bin/tee-vault-admin/tests/data/test.json
    const TEST_SIG: &str = include_str!("../../tests/data/test.json.asc");

    const TEST_SIG_2: &str = include_str!("../../tests/data/test.json_2.asc");

    // gpg --armor --export 81A312C59D679D930FA9E8B06D728F29A2DBABF8  > bin/tee-vault-admin/tests/data/pub-81A312C59D679D930FA9E8B06D728F29A2DBABF8.asc
    const TEST_KEY: &str =
        include_str!("../../tests/data/pub-81A312C59D679D930FA9E8B06D728F29A2DBABF8.asc");

    const TEST_KEY_2: &str =
        include_str!("../../tests/data/pub-7F3D64824AC0B6B8009E50504BC0896FB5693595.asc");

    #[test]
    fn test_sig() {
        let test_key = SignedPublicKey::from_string(TEST_KEY).unwrap().0;
        verify_sig(TEST_SIG, TEST_DATA.as_bytes(), &[test_key]).unwrap();
    }

    #[test]
    fn test_multisig() {
        assert!(MultiSigPolicy {
            name: "test".to_string(),
            members: vec![KeyOrChilds::Key("test".into())].into_boxed_slice(),
            threshold: 0,
        }
        .validate()
        .is_err());

        assert!(MultiSigPolicy {
            name: "test".to_string(),
            members: vec![KeyOrChilds::Key("test".into())].into_boxed_slice(),
            threshold: 2,
        }
        .validate()
        .is_err());

        assert!(MultiSigPolicy {
            name: "test".to_string(),
            members: vec![KeyOrChilds::Key("test".into()),].into_boxed_slice(),
            threshold: 1,
        }
        .validate()
        .is_err());

        let policy = MultiSigPolicy {
            name: "test".to_string(),
            members: vec![
                KeyOrChilds::Key(TEST_KEY_2.into()),
                KeyOrChilds::Key(TEST_KEY.into()),
            ]
            .into_boxed_slice(),
            threshold: 1,
        };

        assert!(policy.validate().is_ok());

        policy
            .check_sigs(&[TEST_SIG.into()], TEST_DATA.as_bytes())
            .unwrap();

        policy
            .check_sigs(&[TEST_SIG_2.into()], TEST_DATA.as_bytes())
            .unwrap();

        policy
            .check_sigs(&[TEST_SIG.into(), TEST_SIG_2.into()], TEST_DATA.as_bytes())
            .unwrap();

        let policy = MultiSigPolicy {
            name: "test".to_string(),
            members: vec![
                KeyOrChilds::Key(TEST_KEY_2.into()),
                KeyOrChilds::Key(TEST_KEY.into()),
            ]
            .into_boxed_slice(),
            threshold: 2,
        };

        assert!(policy.validate().is_ok());

        assert!(policy
            .check_sigs(&[TEST_SIG.into()], TEST_DATA.as_bytes())
            .is_err());

        assert!(policy
            .check_sigs(&[TEST_SIG_2.into()], TEST_DATA.as_bytes())
            .is_err());

        policy
            .check_sigs(&[TEST_SIG.into(), TEST_SIG_2.into()], TEST_DATA.as_bytes())
            .unwrap();

        let policy = MultiSigPolicy {
            name: "test".to_string(),
            members: vec![
                KeyOrChilds::Child(MultiSigPolicy {
                    name: "teamA".to_string(),
                    members: vec![KeyOrChilds::Key(TEST_KEY.into())].into_boxed_slice(),
                    threshold: 1,
                }),
                KeyOrChilds::Child(MultiSigPolicy {
                    name: "teamB".to_string(),
                    members: vec![KeyOrChilds::Key(TEST_KEY_2.into())].into_boxed_slice(),
                    threshold: 1,
                }),
            ]
            .into_boxed_slice(),
            threshold: 2,
        };

        assert!(policy.validate().is_ok());

        assert!(policy
            .check_sigs(&[TEST_SIG.into()], TEST_DATA.as_bytes())
            .is_err());

        policy
            .check_sigs(&[TEST_SIG.into(), TEST_SIG_2.into()], TEST_DATA.as_bytes())
            .unwrap();

        assert!(policy.validate().is_ok());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Ethereum-specific helper functions for on-chain verification of Intel SGX attestation.

use anyhow::Result;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, SECP256K1,
};
use sha3::{Digest, Keccak256};

/// Equivalent to the ecrecover precompile, ensuring that the signatures we produce off-chain
/// can be recovered on-chain.
pub fn recover_signer(sig: &[u8; 65], root_hash: &Message) -> Result<[u8; 20]> {
    let sig = RecoverableSignature::from_compact(
        &sig[0..64],
        RecoveryId::try_from(i32::from(sig[64]) - 27)?,
    )?;
    let public = SECP256K1.recover_ecdsa(*root_hash, &sig)?;
    Ok(public_key_to_ethereum_address(&public))
}

/// Converts a public key into an Ethereum address by hashing the encoded public key with Keccak256.
pub fn public_key_to_ethereum_address(public: &PublicKey) -> [u8; 20] {
    let public_key_bytes = public.serialize_uncompressed();

    // Skip the first byte (0x04) which indicates uncompressed key
    let hash: [u8; 32] = Keccak256::digest(&public_key_bytes[1..]).into();

    // Take the last 20 bytes of the hash to get the Ethereum address
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
mod tests {
    use secp256k1::{Secp256k1, SecretKey};

    use super::*;

    /// Signs the message in Ethereum-compatible format for on-chain verification.
    fn sign_message(sec: &SecretKey, message: Message) -> Result<[u8; 65]> {
        let s = SECP256K1.sign_ecdsa_recoverable(message, sec);
        let (rec_id, data) = s.serialize_compact();

        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&data);
        // as defined in the Ethereum Yellow Paper (Appendix F)
        // https://ethereum.github.io/yellowpaper/paper.pdf
        signature[64] = 27 + i32::from(rec_id) as u8;

        Ok(signature)
    }

    #[test]
    fn recover() {
        // Decode the sample secret key, generate the public key, and derive the Ethereum address
        // from the public key
        let secp = Secp256k1::new();
        let secret_key_bytes =
            hex::decode("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3")
                .unwrap();
        let secret_key =
            SecretKey::from_byte_array(secret_key_bytes.as_slice().try_into().unwrap()).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_address = hex::decode("627306090abaB3A6e1400e9345bC60c78a8BEf57").unwrap();
        let address = public_key_to_ethereum_address(&public_key);

        assert_eq!(address, expected_address.as_slice());

        // Take a root hash, create a message from the hash, and sign the message using
        // the secret key
        let root_hash = b"12345678901234567890123456789012";
        let root_hash_bytes = root_hash.as_slice();
        let msg_to_sign = Message::from_digest(root_hash_bytes.try_into().unwrap());
        let signature = sign_message(&secret_key, msg_to_sign).unwrap();

        // Recover the signer's Ethereum address from the signature and the message, and verify it
        // matches the expected address
        let proof_addr = recover_signer(&signature, &msg_to_sign).unwrap();

        assert_eq!(proof_addr, expected_address.as_slice());
    }
}

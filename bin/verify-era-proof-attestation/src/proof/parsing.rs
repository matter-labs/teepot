// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use super::types::{GetProofsResponse, Proof};
use crate::error;

/// Handles parsing of proof responses and error handling
pub struct ProofResponseParser;

impl ProofResponseParser {
    /// Parse a response and extract the proofs
    pub fn parse_response(response: GetProofsResponse) -> error::Result<Vec<Proof>> {
        // Handle JSON-RPC errors
        if let Some(error) = response.error {
            // Special case for handling the old RPC interface
            if let Some(data) = error.data() {
                if data.get().contains("unknown variant `sgx`, expected `Sgx`") {
                    return Err(error::Error::JsonRpc(
                        "RPC requires 'Sgx' variant instead of 'sgx'".to_string(),
                    ));
                }
            }

            return Err(error::Error::JsonRpc(format!("JSONRPC error: {error:?}")));
        }

        // Extract proofs from the result
        Ok(response.result.unwrap_or_default())
    }

    /// Filter proofs to find valid ones
    pub fn filter_valid_proofs(proofs: &[Proof]) -> Vec<Proof> {
        proofs
            .iter()
            .filter(|proof| !proof.is_failed_or_picked())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee_types::error::ErrorObject;

    #[test]
    fn test_proof_is_permanently_ignored() {
        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("permanently_ignored".to_string()),
            attestation: None,
        };

        assert!(proof.is_permanently_ignored());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("PERMANENTLY_IGNORED".to_string()),
            attestation: None,
        };

        assert!(proof.is_permanently_ignored());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("other".to_string()),
            attestation: None,
        };

        assert!(!proof.is_permanently_ignored());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: None,
            attestation: None,
        };

        assert!(!proof.is_permanently_ignored());
    }

    #[test]
    fn test_proof_is_failed_or_picked() {
        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("failed".to_string()),
            attestation: None,
        };

        assert!(proof.is_failed_or_picked());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("picked_by_prover".to_string()),
            attestation: None,
        };

        assert!(proof.is_failed_or_picked());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("FAILED".to_string()),
            attestation: None,
        };

        assert!(proof.is_failed_or_picked());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: Some("other".to_string()),
            attestation: None,
        };

        assert!(!proof.is_failed_or_picked());

        let proof = Proof {
            l1_batch_number: 123,
            tee_type: "TDX".to_string(),
            pubkey: None,
            signature: None,
            proof: None,
            proved_at: "2023-01-01T00:00:00Z".to_string(),
            status: None,
            attestation: None,
        };

        assert!(!proof.is_failed_or_picked());
    }

    #[test]
    fn test_parse_response_success() {
        let response = GetProofsResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(vec![Proof {
                l1_batch_number: 123,
                tee_type: "TDX".to_string(),
                pubkey: None,
                signature: None,
                proof: None,
                proved_at: "2023-01-01T00:00:00Z".to_string(),
                status: None,
                attestation: None,
            }]),
            id: 1,
            error: None,
        };

        let proofs = ProofResponseParser::parse_response(response).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].l1_batch_number, 123);
    }

    #[test]
    fn test_parse_response_error() {
        let response = GetProofsResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            id: 1,
            error: Some(ErrorObject::owned(1, "Error", None::<()>)),
        };

        let error = ProofResponseParser::parse_response(response).unwrap_err();
        match error {
            error::Error::JsonRpc(msg) => {
                assert!(msg.contains("JSONRPC error"));
            }
            _ => panic!("Expected JsonRpc error"),
        }
    }

    #[test]
    fn test_parse_response_sgx_variant_error() {
        let error_obj = ErrorObject::owned(
            1,
            "Error",
            Some(
                serde_json::to_value("unknown variant `sgx`, expected `Sgx`")
                    .unwrap()
                    .to_string(),
            ),
        );

        let response = GetProofsResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            id: 1,
            error: Some(error_obj),
        };

        let error = ProofResponseParser::parse_response(response).unwrap_err();
        match error {
            error::Error::JsonRpc(msg) => {
                assert!(msg.contains("RPC requires 'Sgx' variant"));
            }
            _ => panic!("Expected JsonRpc error about Sgx variant"),
        }
    }

    #[test]
    fn test_filter_valid_proofs() {
        let proofs = vec![
            Proof {
                l1_batch_number: 123,
                tee_type: "TDX".to_string(),
                pubkey: None,
                signature: None,
                proof: None,
                proved_at: "2023-01-01T00:00:00Z".to_string(),
                status: None,
                attestation: None,
            },
            Proof {
                l1_batch_number: 124,
                tee_type: "TDX".to_string(),
                pubkey: None,
                signature: None,
                proof: None,
                proved_at: "2023-01-01T00:00:00Z".to_string(),
                status: Some("failed".to_string()),
                attestation: None,
            },
            Proof {
                l1_batch_number: 125,
                tee_type: "TDX".to_string(),
                pubkey: None,
                signature: None,
                proof: None,
                proved_at: "2023-01-01T00:00:00Z".to_string(),
                status: Some("picked_by_prover".to_string()),
                attestation: None,
            },
        ];

        let valid_proofs = ProofResponseParser::filter_valid_proofs(&proofs);
        assert_eq!(valid_proofs.len(), 1);
        assert_eq!(valid_proofs[0].l1_batch_number, 123);
    }
}

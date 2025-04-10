// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

use jsonrpsee_types::error::ErrorObject;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use zksync_basic_types::{tee_types::TeeType, L1BatchNumber};

/// Request structure for fetching proofs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetProofsRequest {
    pub jsonrpc: String,
    pub id: u32,
    pub method: String,
    pub params: (L1BatchNumber, String),
}

impl GetProofsRequest {
    /// Create a new request for the given batch number
    pub fn new(batch_number: L1BatchNumber, tee_type: &TeeType) -> Self {
        GetProofsRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "unstable_getTeeProofs".to_string(),
            params: (batch_number, tee_type.to_string()),
        }
    }
}

/// Response structure for proof requests
#[derive(Debug, Serialize, Deserialize)]
pub struct GetProofsResponse {
    pub jsonrpc: String,
    pub result: Option<Vec<Proof>>,
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject<'static>>,
}

/// Proof structure containing attestation and signature data
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub l1_batch_number: u32,
    pub tee_type: String,
    #[serde_as(as = "Option<Hex>")]
    pub pubkey: Option<Vec<u8>>,
    #[serde_as(as = "Option<Hex>")]
    pub signature: Option<Vec<u8>>,
    #[serde_as(as = "Option<Hex>")]
    pub proof: Option<Vec<u8>>,
    pub proved_at: String,
    pub status: Option<String>,
    #[serde_as(as = "Option<Hex>")]
    pub attestation: Option<Vec<u8>>,
}

impl Proof {
    /// Check if the proof is marked as permanently ignored
    pub fn is_permanently_ignored(&self) -> bool {
        self.status
            .as_ref()
            .is_some_and(|s| s.eq_ignore_ascii_case("permanently_ignored"))
    }

    /// Check if the proof is failed or picked by a prover
    pub fn is_failed_or_picked(&self) -> bool {
        self.status.as_ref().is_some_and(|s| {
            s.eq_ignore_ascii_case("failed") || s.eq_ignore_ascii_case("picked_by_prover")
        })
    }

    /// Get the attestation bytes or an empty vector if not present
    pub fn attestation_bytes(&self) -> Vec<u8> {
        self.attestation.clone().unwrap_or_default()
    }

    /// Get the signature bytes or an empty vector if not present
    pub fn signature_bytes(&self) -> Vec<u8> {
        self.signature.clone().unwrap_or_default()
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

/// JSON structure as defined in Appendix A of the API spec.
/// Content may vary slightly between API v3 and v4.
pub type TcbInfoJson = String;

/// JSON structure as defined in Appendix B of the API spec.
/// Content may vary slightly between API v3 and v4.
pub type EnclaveIdentityJson = String;

/// JSON Array of {tcb, tcbm, cert}.
/// Content structure expected to be consistent between v3 and v4.
pub type PckCertsJsonResponse = String;

/// JSON Array of {fmspc, platform}.
/// Content structure expected to be consistent between v3 and v4.
pub type FmspcJsonResponse = String;

/// JSON structure as defined in Appendix C of the API spec (V4 ONLY).
pub type TcbEvaluationDataNumbersJson = String;

/// Response structure for a PCK (Platform Configuration Key) Certificate.
///
/// Contains the PCK certificate, its issuer chain, TCB measurement, and FMSPC value.
#[derive(Debug, Clone)]
pub struct PckCertificateResponse {
    /// PEM-encoded PCK certificate.
    pub pck_cert_pem: String,
    /// PEM-encoded certificate chain for the PCK certificate issuer.
    /// Header name differs between v3 ("PCS-Certificate-Issuer-Chain") and v4 ("SGX-PCK-Certificate-Issuer-Chain").
    pub issuer_chain: String,
    /// TCBm value associated with the certificate (Hex-encoded).
    pub tcbm: String,
    /// FMSPC value associated with the certificate (Hex-encoded).
    pub fmspc: String,
}

/// Response structure for multiple PCK (Platform Configuration Key) Certificates.
///
/// Contains a JSON array of PCK certificates, their issuer chain, and the associated FMSPC value.
/// This struct represents the response for retrieving multiple PCK certificates from the Intel SGX API.
#[derive(Debug, Clone)]
pub struct PckCertificatesResponse {
    /// JSON array containing PCK certificates and their associated TCB levels.
    pub pck_certs_json: PckCertsJsonResponse, // String alias for now
    /// PEM-encoded certificate chain for the PCK certificate issuer.
    /// Header name differs between v3 ("PCS-Certificate-Issuer-Chain") and v4 ("SGX-PCK-Certificate-Issuer-Chain").
    pub issuer_chain: String,
    /// FMSPC value associated with the certificates (Hex-encoded).
    pub fmspc: String,
}

/// Response structure for TCB (Trusted Computing Base) Information.
///
/// Contains the JSON representation of TCB information for a specific platform,
/// along with the certificate chain of the TCB Info signer.
#[derive(Debug, Clone)]
pub struct TcbInfoResponse {
    /// JSON containing TCB information for a specific platform (FMSPC).
    pub tcb_info_json: TcbInfoJson, // String alias for now
    /// PEM-encoded certificate chain for the TCB Info signer.
    /// Header name differs slightly between v3 ("SGX-TCB-Info-Issuer-Chain") and v4 ("TCB-Info-Issuer-Chain" - check spec).
    pub issuer_chain: String,
}

/// Response structure for Enclave Identity Information.
///
/// Contains the JSON representation of enclave identity details for QE, QvE, or QAE,
/// along with its issuer chain.
#[derive(Debug, Clone)]
pub struct EnclaveIdentityResponse {
    /// JSON containing information about the QE, QvE, or QAE.
    pub enclave_identity_json: EnclaveIdentityJson, // String alias for now
    /// PEM-encoded certificate chain for the Enclave Identity signer.
    /// Header name seems consistent ("SGX-Enclave-Identity-Issuer-Chain").
    pub issuer_chain: String,
}

/// Response structure for TCB Evaluation Data Numbers (V4 ONLY).
///
/// Contains the JSON representation of supported TCB Evaluation Data Numbers
/// and its corresponding issuer chain.
#[derive(Debug, Clone)]
pub struct TcbEvaluationDataNumbersResponse {
    /// JSON containing the list of supported TCB Evaluation Data Numbers (V4 ONLY).
    pub tcb_evaluation_data_numbers_json: TcbEvaluationDataNumbersJson, // String alias for now
    /// PEM-encoded certificate chain for the TCB Evaluation Data Numbers signer (V4 ONLY).
    /// Header: "TCB-Evaluation-Data-Numbers-Issuer-Chain".
    pub issuer_chain: String,
}

/// Response structure for Platform Configuration Key Certificate Revocation List (PCK CRL).
///
/// Contains the CRL data and its issuer chain for validating platform configuration keys.
#[derive(Debug, Clone)]
pub struct PckCrlResponse {
    /// CRL data (PEM or DER encoded).
    pub crl_data: Vec<u8>,
    /// PEM-encoded certificate chain for the CRL issuer.
    /// Header name differs between v3 ("PCS-CRL-Issuer-Chain") and v4 ("SGX-PCK-CRL-Issuer-Chain").
    pub issuer_chain: String,
}

/// Response structure for the request to add a package.
pub struct AddPackageResponse {
    /// Platform Membership Certificates
    pub pck_certs: Vec<u8>,
    /// The certificate count extracted from the response header.
    pub pck_cert_count: usize,
}

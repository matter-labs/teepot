// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{
    ApiClient, ApiVersion, CaType, CrlEncoding, IntelApiError, PlatformFilter, UpdateType,
};
use mockito::Server;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use serde_json::Value;

// Include real test data
const TDX_TCB_INFO_DATA: &[u8] = include_bytes!("test_data/tdx_tcb_info.json");
const PCK_CRL_PROCESSOR_DATA: &[u8] = include_bytes!("test_data/pck_crl_processor.json");
const PCK_CRL_PLATFORM_DATA: &[u8] = include_bytes!("test_data/pck_crl_platform.json");
const SGX_QE_IDENTITY_DATA: &[u8] = include_bytes!("test_data/sgx_qe_identity.json");
const SGX_QVE_IDENTITY_DATA: &[u8] = include_bytes!("test_data/sgx_qve_identity.json");
const TDX_QE_IDENTITY_DATA: &[u8] = include_bytes!("test_data/tdx_qe_identity.json");
const SGX_TCB_INFO_ALT_DATA: &[u8] = include_bytes!("test_data/sgx_tcb_info_alt.json");
const SGX_QAE_IDENTITY_DATA: &[u8] = include_bytes!("test_data/sgx_qae_identity.json");
const FMSPCS_DATA: &[u8] = include_bytes!("test_data/fmspcs.json");
const SGX_TCB_EVAL_NUMS_DATA: &[u8] = include_bytes!("test_data/sgx_tcb_eval_nums.json");
const TDX_TCB_EVAL_NUMS_DATA: &[u8] = include_bytes!("test_data/tdx_tcb_eval_nums.json");
const PCK_CRL_PROCESSOR_DER_DATA: &[u8] = include_bytes!("test_data/pck_crl_processor_der.json");
const SGX_TCB_INFO_EARLY_DATA: &[u8] = include_bytes!("test_data/sgx_tcb_info_early.json");
const TDX_TCB_INFO_EVAL17_DATA: &[u8] = include_bytes!("test_data/tdx_tcb_info_eval17.json");
const FMSPCS_NO_FILTER_DATA: &[u8] = include_bytes!("test_data/fmspcs_no_filter.json");
// const FMSPCS_ALL_PLATFORMS_DATA: &[u8] = include_bytes!("test_data/fmspcs_all_platforms.json"); // Reserved for future use
const SGX_QE_IDENTITY_V3_DATA: &[u8] = include_bytes!("test_data/sgx_qe_identity_v3.json");
const SGX_TCB_INFO_V3_DATA: &[u8] = include_bytes!("test_data/sgx_tcb_info_v3.json");
const TDX_TCB_INFO_ALT_DATA: &[u8] = include_bytes!("test_data/tdx_tcb_info_00806F050000.json");

fn parse_test_data(data: &[u8]) -> Value {
    serde_json::from_slice(data).expect("Failed to parse test data")
}

#[tokio::test]
async fn test_tdx_tcb_info_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_TCB_INFO_DATA);

    // URL encode the issuer chain header value
    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "00806F050000".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_tdx_tcb_info("00806F050000", None, None).await;

    if let Err(e) = &result {
        eprintln!("Error: {:?}", e);
        eprintln!("Server URL: {}", server.url());
    }

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.tcb_info_json,
        test_data["tcb_info_json"].as_str().unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );

    // Verify the JSON can be parsed
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00806F050000");
    assert_eq!(tcb_info["tcbInfo"]["id"], "TDX");
}

#[tokio::test]
async fn test_sgx_qe_identity_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_QE_IDENTITY_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/qe/identity")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-Enclave-Identity-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["enclave_identity_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_qe_identity(None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.enclave_identity_json,
        test_data["enclave_identity_json"].as_str().unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );

    // Verify the JSON structure
    let identity: Value = serde_json::from_str(&response.enclave_identity_json).unwrap();
    assert_eq!(identity["enclaveIdentity"]["id"], "QE");
}

#[tokio::test]
async fn test_sgx_qve_identity_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_QVE_IDENTITY_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/qve/identity")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-Enclave-Identity-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["enclave_identity_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_qve_identity(None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify the JSON structure
    let identity: Value = serde_json::from_str(&response.enclave_identity_json).unwrap();
    assert_eq!(identity["enclaveIdentity"]["id"], "QVE");
}

#[tokio::test]
async fn test_tdx_qe_identity_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_QE_IDENTITY_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/tdx/certification/v4/qe/identity")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-Enclave-Identity-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["enclave_identity_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_tdx_qe_identity(None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify the JSON structure
    let identity: Value = serde_json::from_str(&response.enclave_identity_json).unwrap();
    assert_eq!(identity["enclaveIdentity"]["id"], "TD_QE");
}

#[tokio::test]
async fn test_pck_crl_processor_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(PCK_CRL_PROCESSOR_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/pckcrl")
        .match_query(mockito::Matcher::UrlEncoded(
            "ca".into(),
            "processor".into(),
        ))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["crl_data"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_pck_crl(CaType::Processor, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&response.crl_data),
        test_data["crl_data"].as_str().unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );

    // Verify it's a valid CRL format
    let crl_str = String::from_utf8_lossy(&response.crl_data);
    assert!(crl_str.contains("BEGIN X509 CRL"));
    assert!(crl_str.contains("END X509 CRL"));
}

#[tokio::test]
async fn test_pck_crl_platform_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(PCK_CRL_PLATFORM_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/pckcrl")
        .match_query(mockito::Matcher::UrlEncoded("ca".into(), "platform".into()))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["crl_data"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_pck_crl(CaType::Platform, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify issuer chain contains multiple certificates
    assert!(response.issuer_chain.contains("BEGIN CERTIFICATE"));
    assert!(response.issuer_chain.contains("END CERTIFICATE"));
}

#[tokio::test]
async fn test_sgx_tcb_info_alt_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_TCB_INFO_ALT_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "00906ED50000".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_tcb_info("00906ED50000", None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify the JSON structure
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00906ED50000");
    assert_eq!(tcb_info["tcbInfo"]["id"], "SGX");
}

#[tokio::test]
async fn test_tdx_tcb_with_update_type() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_TCB_INFO_DATA);

    // Test with Early update type
    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m1 = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("fmspc".into(), "00806F050000".into()),
            mockito::Matcher::UrlEncoded("update".into(), "early".into()),
        ]))
        .with_status(200)
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client
        .get_tdx_tcb_info("00806F050000", Some(UpdateType::Early), None)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_error_handling_with_intel_headers() {
    let mut server = Server::new_async().await;

    // Real error response from Intel API
    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "invalid".into(),
        ))
        .with_status(404)
        .with_header("Request-ID", "abc123def456")
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_tcb_info("invalid", None, None).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IntelApiError::ApiError {
            status, request_id, ..
        } => {
            assert_eq!(status.as_u16(), 404);
            assert_eq!(request_id, "abc123def456");
        }
        _ => panic!("Expected ApiError"),
    }
}

#[tokio::test]
async fn test_v3_api_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(PCK_CRL_PROCESSOR_DATA);

    // V3 uses different header names
    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v3/pckcrl")
        .match_query(mockito::Matcher::UrlEncoded(
            "ca".into(),
            "processor".into(),
        ))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["crl_data"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();
    let result = client.get_pck_crl(CaType::Processor, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&response.crl_data),
        test_data["crl_data"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_sgx_qae_identity_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_QAE_IDENTITY_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/qae/identity")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-Enclave-Identity-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["enclave_identity_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_qae_identity(None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.enclave_identity_json,
        test_data["enclave_identity_json"].as_str().unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );

    // Verify the JSON structure
    let identity: Value = serde_json::from_str(&response.enclave_identity_json).unwrap();
    assert_eq!(identity["enclaveIdentity"]["id"], "QAE");
}

#[tokio::test]
async fn test_get_fmspcs_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(FMSPCS_DATA);

    let _m = server
        .mock("GET", "/sgx/certification/v4/fmspcs")
        .match_query(mockito::Matcher::UrlEncoded(
            "platform".into(),
            "all".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(test_data["fmspcs_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_fmspcs(Some(PlatformFilter::All)).await;

    assert!(result.is_ok());
    let fmspcs_json = result.unwrap();
    assert_eq!(fmspcs_json, test_data["fmspcs_json"].as_str().unwrap());

    // Verify the JSON structure
    let fmspcs: Value = serde_json::from_str(&fmspcs_json).unwrap();
    assert!(fmspcs.is_array());
    assert!(!fmspcs.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_sgx_tcb_evaluation_data_numbers_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_TCB_EVAL_NUMS_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/tcbevaluationdatanumbers")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header(
            "TCB-Evaluation-Data-Numbers-Issuer-Chain",
            &encoded_issuer_chain,
        )
        .with_body(
            test_data["tcb_evaluation_data_numbers_json"]
                .as_str()
                .unwrap(),
        )
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_tcb_evaluation_data_numbers().await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.tcb_evaluation_data_numbers_json,
        test_data["tcb_evaluation_data_numbers_json"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );

    // Verify the JSON structure
    let eval_nums: Value =
        serde_json::from_str(&response.tcb_evaluation_data_numbers_json).unwrap();
    assert!(eval_nums.is_object());
}

#[tokio::test]
async fn test_tdx_tcb_evaluation_data_numbers_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_TCB_EVAL_NUMS_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/tdx/certification/v4/tcbevaluationdatanumbers")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header(
            "TCB-Evaluation-Data-Numbers-Issuer-Chain",
            &encoded_issuer_chain,
        )
        .with_body(
            test_data["tcb_evaluation_data_numbers_json"]
                .as_str()
                .unwrap(),
        )
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_tdx_tcb_evaluation_data_numbers().await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.tcb_evaluation_data_numbers_json,
        test_data["tcb_evaluation_data_numbers_json"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_pck_crl_der_encoding_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(PCK_CRL_PROCESSOR_DER_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    // The DER data is stored as base64 in our test data
    let crl_base64 = test_data["crl_data_base64"].as_str().unwrap();
    use base64::{engine::general_purpose, Engine as _};
    let crl_der = general_purpose::STANDARD.decode(crl_base64).unwrap();

    let _m = server
        .mock("GET", "/sgx/certification/v4/pckcrl")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("ca".into(), "processor".into()),
            mockito::Matcher::UrlEncoded("encoding".into(), "der".into()),
        ]))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", &encoded_issuer_chain)
        .with_body(crl_der)
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client
        .get_pck_crl(CaType::Processor, Some(CrlEncoding::Der))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify the response data matches
    let response_base64 = general_purpose::STANDARD.encode(&response.crl_data);
    assert_eq!(response_base64, crl_base64);
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_sgx_tcb_info_early_update_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_TCB_INFO_EARLY_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("fmspc".into(), "00906ED50000".into()),
            mockito::Matcher::UrlEncoded("update".into(), "early".into()),
        ]))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client
        .get_sgx_tcb_info("00906ED50000", Some(UpdateType::Early), None)
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.tcb_info_json,
        test_data["tcb_info_json"].as_str().unwrap()
    );

    // Verify the JSON structure
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00906ED50000");
}

#[tokio::test]
async fn test_tdx_tcb_info_with_eval_number_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_TCB_INFO_EVAL17_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("fmspc".into(), "00806F050000".into()),
            mockito::Matcher::UrlEncoded("tcbEvaluationDataNumber".into(), "17".into()),
        ]))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client
        .get_tdx_tcb_info("00806F050000", None, Some(17))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify the response
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00806F050000");
    assert_eq!(tcb_info["tcbInfo"]["id"], "TDX");
}

#[tokio::test]
async fn test_get_fmspcs_v3_should_fail() {
    let server = Server::new_async().await;

    // FMSPCs is V4 only
    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();
    let result = client.get_fmspcs(None).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IntelApiError::UnsupportedApiVersion(msg) => {
            assert!(msg.contains("API v4 only"));
        }
        _ => panic!("Expected UnsupportedApiVersion error"),
    }
}

#[tokio::test]
async fn test_tcb_evaluation_data_numbers_v3_should_fail() {
    let server = Server::new_async().await;

    // TCB evaluation data numbers is V4 only
    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();

    let sgx_result = client.get_sgx_tcb_evaluation_data_numbers().await;
    assert!(sgx_result.is_err());
    match sgx_result.unwrap_err() {
        IntelApiError::UnsupportedApiVersion(msg) => {
            assert!(msg.contains("requires API v4"));
        }
        _ => panic!("Expected UnsupportedApiVersion error"),
    }

    let tdx_result = client.get_tdx_tcb_evaluation_data_numbers().await;
    assert!(tdx_result.is_err());
    match tdx_result.unwrap_err() {
        IntelApiError::UnsupportedApiVersion(msg) => {
            assert!(msg.contains("requires API v4"));
        }
        _ => panic!("Expected UnsupportedApiVersion error"),
    }
}

#[tokio::test]
async fn test_get_fmspcs_no_filter_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(FMSPCS_NO_FILTER_DATA);

    let _m = server
        .mock("GET", "/sgx/certification/v4/fmspcs")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(test_data["fmspcs_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_fmspcs(None).await;

    assert!(result.is_ok());
    let fmspcs_json = result.unwrap();
    assert_eq!(fmspcs_json, test_data["fmspcs_json"].as_str().unwrap());
}

#[tokio::test]
async fn test_sgx_qe_identity_v3_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_QE_IDENTITY_V3_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    // V3 uses different header names
    let _m = server
        .mock("GET", "/sgx/certification/v3/qe/identity")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-Enclave-Identity-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["enclave_identity_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();
    let result = client.get_sgx_qe_identity(None, None).await;

    if let Err(e) = &result {
        eprintln!("Error in V3 test: {:?}", e);
    }

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.enclave_identity_json,
        test_data["enclave_identity_json"].as_str().unwrap()
    );
    assert_eq!(
        response.issuer_chain,
        test_data["issuer_chain"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_sgx_tcb_info_v3_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(SGX_TCB_INFO_V3_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    // V3 uses different header names
    let _m = server
        .mock("GET", "/sgx/certification/v3/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "00906ED50000".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("SGX-TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();
    let result = client.get_sgx_tcb_info("00906ED50000", None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(
        response.tcb_info_json,
        test_data["tcb_info_json"].as_str().unwrap()
    );

    // Verify the JSON structure
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00906ED50000");
}

#[tokio::test]
async fn test_tdx_tcb_info_alternate_fmspc_with_real_data() {
    let mut server = Server::new_async().await;
    let test_data = parse_test_data(TDX_TCB_INFO_ALT_DATA);

    let issuer_chain = test_data["issuer_chain"].as_str().unwrap();
    let encoded_issuer_chain =
        percent_encode(issuer_chain.as_bytes(), NON_ALPHANUMERIC).to_string();

    let _m = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "00806F050000".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_header("TCB-Info-Issuer-Chain", &encoded_issuer_chain)
        .with_body(test_data["tcb_info_json"].as_str().unwrap())
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_tdx_tcb_info("00806F050000", None, None).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Verify we got the same data as the first TDX TCB info test
    let tcb_info: Value = serde_json::from_str(&response.tcb_info_json).unwrap();
    assert_eq!(tcb_info["tcbInfo"]["fmspc"], "00806F050000");
    assert_eq!(tcb_info["tcbInfo"]["id"], "TDX");
}

#[tokio::test]
async fn test_platform_filter_combinations() {
    let mut server = Server::new_async().await;

    // Test with different platform filters
    let filters = vec![
        (Some(PlatformFilter::All), "all"),
        (Some(PlatformFilter::Client), "client"),
        (Some(PlatformFilter::E3), "E3"),
        (Some(PlatformFilter::E5), "E5"),
        (None, ""),
    ];

    for (filter, query_value) in filters {
        let mock_response = r#"[{"fmspc": "00906ED50000", "platform": "SGX"}]"#;

        let mut mock = server.mock("GET", "/sgx/certification/v4/fmspcs");

        if !query_value.is_empty() {
            mock = mock.match_query(mockito::Matcher::UrlEncoded(
                "platform".into(),
                query_value.into(),
            ));
        }

        let _m = mock
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(mock_response)
            .create_async()
            .await;

        let client = ApiClient::new_with_base_url(server.url()).unwrap();
        let result = client.get_fmspcs(filter).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.contains("00906ED50000"));
    }
}

#[tokio::test]
async fn test_error_scenarios() {
    let mut server = Server::new_async().await;

    // Test 404 with Error headers
    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "invalid".into(),
        ))
        .with_status(404)
        .with_header("Request-ID", "test123")
        .with_header("Error-Code", "InvalidParameter")
        .with_header("Error-Message", "Invalid FMSPC format")
        .create_async()
        .await;

    let client = ApiClient::new_with_base_url(server.url()).unwrap();
    let result = client.get_sgx_tcb_info("invalid", None, None).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IntelApiError::ApiError {
            status,
            request_id,
            error_code,
            error_message,
        } => {
            assert_eq!(status.as_u16(), 404);
            assert_eq!(request_id, "test123");
            assert_eq!(error_code.as_deref(), Some("InvalidParameter"));
            assert_eq!(error_message.as_deref(), Some("Invalid FMSPC format"));
        }
        _ => panic!("Expected ApiError"),
    }
}

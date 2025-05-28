// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{ApiClient, ApiVersion, CaType, IntelApiError, UpdateType};
use mockito::Server;
use reqwest::Client;

// Create a test client without TLS requirements
async fn create_test_client(base_url: &str) -> ApiClient {
    // Create a custom client without TLS requirements for testing
    ApiClient::new_with_base_url(base_url).expect("Failed to create client")
}

#[tokio::test]
async fn test_simple_request() {
    let mut server = Server::new_async().await;

    // First, test with plain reqwest to ensure mock works
    let _m = server
        .mock("GET", "/test")
        .with_status(200)
        .with_body("test")
        .create_async()
        .await;

    let client = Client::new();
    let resp = client
        .get(format!("{}/test", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "test");
}

#[tokio::test]
async fn test_tdx_tcb_minimal() {
    let mut server = Server::new_async().await;

    // Use minimal response
    let _m = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "test123".into(),
        ))
        .with_status(200)
        .with_header("TCB-Info-Issuer-Chain", "test-cert")
        .with_body("{}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_tdx_tcb_info("test123", None, None).await;

    match &result {
        Ok(resp) => {
            assert_eq!(resp.tcb_info_json, "{}");
            assert_eq!(resp.issuer_chain, "test-cert");
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
            panic!("Request failed");
        }
    }
}

#[tokio::test]
async fn test_sgx_qe_identity_minimal() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/qe/identity")
        .with_status(200)
        .with_header("SGX-Enclave-Identity-Issuer-Chain", "test-cert")
        .with_body("{}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_sgx_qe_identity(None, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.enclave_identity_json, "{}");
    assert_eq!(resp.issuer_chain, "test-cert");
}

#[tokio::test]
async fn test_pck_crl_minimal() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/pckcrl")
        .match_query(mockito::Matcher::UrlEncoded(
            "ca".into(),
            "processor".into(),
        ))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", "test-cert")
        .with_body("test-crl")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_pck_crl(CaType::Processor, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(String::from_utf8_lossy(&resp.crl_data), "test-crl");
    assert_eq!(resp.issuer_chain, "test-cert");
}

#[tokio::test]
async fn test_error_handling() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded("fmspc".into(), "bad".into()))
        .with_status(404)
        .with_header("Request-ID", "test-123")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_sgx_tcb_info("bad", None, None).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IntelApiError::ApiError {
            status, request_id, ..
        } => {
            assert_eq!(status.as_u16(), 404);
            assert_eq!(request_id, "test-123");
        }
        _ => panic!("Wrong error type"),
    }
}

#[tokio::test]
async fn test_update_types() {
    let mut server = Server::new_async().await;

    // Test Early update type
    let _m1 = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("fmspc".into(), "test".into()),
            mockito::Matcher::UrlEncoded("update".into(), "early".into()),
        ]))
        .with_status(200)
        .with_header("TCB-Info-Issuer-Chain", "cert")
        .with_body("{\"early\":true}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client
        .get_tdx_tcb_info("test", Some(UpdateType::Early), None)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().tcb_info_json, "{\"early\":true}");

    // Test Standard update type
    let _m2 = server
        .mock("GET", "/tdx/certification/v4/tcb")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("fmspc".into(), "test".into()),
            mockito::Matcher::UrlEncoded("update".into(), "standard".into()),
        ]))
        .with_status(200)
        .with_header("TCB-Info-Issuer-Chain", "cert")
        .with_body("{\"standard\":true}")
        .create_async()
        .await;

    let result2 = client
        .get_tdx_tcb_info("test", Some(UpdateType::Standard), None)
        .await;
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap().tcb_info_json, "{\"standard\":true}");
}

#[tokio::test]
async fn test_v3_api_headers() {
    let mut server = Server::new_async().await;

    // V3 uses different header names for CRL
    let _m = server
        .mock("GET", "/sgx/certification/v3/pckcrl")
        .match_query(mockito::Matcher::UrlEncoded("ca".into(), "platform".into()))
        .with_status(200)
        .with_header("SGX-PCK-CRL-Issuer-Chain", "v3-cert")
        .with_body("v3-crl-data")
        .create_async()
        .await;

    let client = ApiClient::new_with_options(server.url(), ApiVersion::V3).unwrap();
    let result = client.get_pck_crl(CaType::Platform, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(String::from_utf8_lossy(&resp.crl_data), "v3-crl-data");
    assert_eq!(resp.issuer_chain, "v3-cert");
}

#[tokio::test]
async fn test_sgx_qve_identity() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/qve/identity")
        .with_status(200)
        .with_header("SGX-Enclave-Identity-Issuer-Chain", "qve-cert")
        .with_body("{\"id\":\"QVE\"}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_sgx_qve_identity(None, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.enclave_identity_json, "{\"id\":\"QVE\"}");
    assert_eq!(resp.issuer_chain, "qve-cert");
}

#[tokio::test]
async fn test_tdx_qe_identity() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/tdx/certification/v4/qe/identity")
        .with_status(200)
        .with_header("SGX-Enclave-Identity-Issuer-Chain", "tdx-qe-cert")
        .with_body("{\"id\":\"TDX-QE\"}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_tdx_qe_identity(None, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.enclave_identity_json, "{\"id\":\"TDX-QE\"}");
    assert_eq!(resp.issuer_chain, "tdx-qe-cert");
}

#[tokio::test]
async fn test_error_with_details() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/pckcert")
        .match_query(mockito::Matcher::Any)
        .with_status(400)
        .with_header("Request-ID", "error-req-123")
        .with_header("Error-Code", "InvalidParameter")
        .with_header("Error-Message", "PPID format is invalid")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client
        .get_pck_certificate_by_ppid("bad", "bad", "bad", "bad", None, None)
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IntelApiError::ApiError {
            status,
            request_id,
            error_code,
            error_message,
        } => {
            assert_eq!(status.as_u16(), 400);
            assert_eq!(request_id, "error-req-123");
            assert_eq!(error_code.as_deref(), Some("InvalidParameter"));
            assert_eq!(error_message.as_deref(), Some("PPID format is invalid"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[tokio::test]
async fn test_sgx_tcb_info() {
    let mut server = Server::new_async().await;

    let _m = server
        .mock("GET", "/sgx/certification/v4/tcb")
        .match_query(mockito::Matcher::UrlEncoded(
            "fmspc".into(),
            "00606A6A0000".into(),
        ))
        .with_status(200)
        .with_header("TCB-Info-Issuer-Chain", "sgx-tcb-cert")
        .with_body("{\"tcbInfo\":{\"fmspc\":\"00606A6A0000\"}}")
        .create_async()
        .await;

    let client = create_test_client(&server.url()).await;
    let result = client.get_sgx_tcb_info("00606A6A0000", None, None).await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(
        resp.tcb_info_json,
        "{\"tcbInfo\":{\"fmspc\":\"00606A6A0000\"}}"
    );
    assert_eq!(resp.issuer_chain, "sgx-tcb-cert");
}

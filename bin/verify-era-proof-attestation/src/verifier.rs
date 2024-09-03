use anyhow::{anyhow, Context, Result};
use clap::Parser;
use reqwest::Client;
use secp256k1::{constants::PUBLIC_KEY_SIZE, ecdsa::Signature, Message, PublicKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use teepot::{
    client::TcbLevel,
    sgx::{tee_qv_get_collateral, verify_quote_with_collateral, QuoteVerificationResult},
};
use url::Url;
use zksync_basic_types::{L1BatchNumber, H256};
use zksync_types::L2ChainId;
use zksync_web3_decl::{
    client::{Client as NodeClient, L2},
    error::ClientRpcContext,
    namespaces::ZksNamespaceClient,
};

fn verify_signature(signature: &[u8], public_key: PublicKey, root_hash: H256) -> Result<()> {
    let signature = Signature::from_compact(signature)?;
    let root_hash_msg = Message::from_digest_slice(&root_hash.0)?;
    if signature.verify(&root_hash_msg, &public_key).is_ok() {
        println!("  Signature verified successfully");
    } else {
        println!("  Failed to verify signature");
    }
    Ok(())
}

async fn verify_proof(proof: Proof, node_client: &MainNodeClient) -> Result<(), anyhow::Error> {
    let quote_verification_result = verify_attestation_quote(&proof.attestation)?;
    print_quote_verification_summary(&quote_verification_result);
    let public_key = PublicKey::from_slice(
        &quote_verification_result.quote.report_body.reportdata[..PUBLIC_KEY_SIZE],
    )?;
    println!("  Public key from attestation quote: {}", public_key);
    let root_hash = node_client
        .get_root_hash(L1BatchNumber(proof.l1_batch_number))
        .await?;
    println!("  Root hash: {}", root_hash);
    verify_signature(&proof.signature, public_key, root_hash)?;
    Ok(())
}

fn print_quote_verification_summary(quote_verification_result: &QuoteVerificationResult) {
    let QuoteVerificationResult {
        collateral_expired,
        result,
        quote,
        advisories,
        ..
    } = quote_verification_result;
    if *collateral_expired {
        println!("  Freshly fetched collateral expired");
    }
    let tcblevel = TcbLevel::from(*result);
    for advisory in advisories {
        println!("  \tInfo: Advisory ID: {advisory}");
    }
    println!("  Quote verification result: {}", tcblevel);
    println!("  mrsigner: {}", hex::encode(quote.report_body.mrsigner));
    println!("  mrenclave: {}", hex::encode(quote.report_body.mrenclave));
    println!(
        "  reportdata: {}",
        hex::encode(quote.report_body.reportdata)
    );
}

fn verify_attestation_quote(attestation_quote_bytes: &[u8]) -> Result<QuoteVerificationResult> {
    println!(
        "Verifying quote ({} bytes)...",
        attestation_quote_bytes.len()
    );
    let collateral =
        tee_qv_get_collateral(attestation_quote_bytes).context("Failed to get collateral")?;
    let unix_time: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as _;
    verify_quote_with_collateral(attestation_quote_bytes, Some(&collateral), unix_time)
        .context("Failed to verify quote with collateral")
}

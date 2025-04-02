// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! Pre-exec for binary running in a TEE needing attestation of a secret signing key

#![deny(missing_docs)]
#![deny(clippy::all)]

use anyhow::{Context, Result};
use clap::Parser;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::RsaPrivateKey;
use std::fs::File;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use teepot::pki::make_signed_cert;
use tracing::error;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::DecodePem;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::Certificate;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// ca cert file
    #[arg(long, env = "CA_CERT_FILE", default_value = "/opt/vault/cacert.pem")]
    ca_cert_file: PathBuf,
    /// ca key file
    #[arg(long, env = "CA_KEY_FILE", default_value = "/opt/vault/cakey.pem")]
    ca_key_file: PathBuf,
    /// out cert file
    #[arg(long, env = "TLS_CERT_FILE", default_value = "/opt/vault/tls/tls.crt")]
    tls_cert_file: PathBuf,
    /// out key file
    #[arg(long, env = "TLS_KEY_FILE", default_value = "/opt/vault/tls/tls.key")]
    tls_key_file: PathBuf,
    /// DNS names, comma separated
    #[arg(long, env = "DNS_NAMES", required = true)]
    dns_names: String,
    /// program to exec [args...] (required)
    #[arg(required = true, allow_hyphen_values = true, last = true)]
    cmd_args: Vec<String>,
}

fn main_with_error() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;

    let args = Args::parse();

    // read `issuer_cert_bytes` from file
    let ca_cert = std::fs::read(args.ca_cert_file).context("Failed to read ca_cert")?;

    let issuer_cert = Certificate::from_pem(&ca_cert)?;
    let issuer_key =
        RsaPrivateKey::read_pkcs8_pem_file(args.ca_key_file).context("Failed to read ca_key")?;
    let issuer_key_pair = SigningKey::<Sha256>::new(issuer_key);

    // TODO: read values from config file or env or args
    let dn = "O=system:nodes,CN=system:node";
    let mut an = vec![std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST).into()];
    an.extend(
        args.dns_names
            .split(',')
            .map(|s| GeneralName::DnsName(Ia5String::try_from(s.to_string()).unwrap())),
    );

    let (_report_data, cert, priv_key) =
        make_signed_cert(dn, Some(an), &issuer_cert, &issuer_key_pair)?;

    // open args.tls_cert_file and write cert and ca_cert
    let mut file = File::create(&args.tls_cert_file).context("Failed to create tls_cert")?;
    file.write_all(cert.as_bytes())
        .context("Failed to write tls_cert")?;
    file.write_all(&ca_cert)
        .context("Failed to write tls_cert")?;

    std::fs::write(args.tls_key_file, priv_key).context("Failed to write tls_cert")?;

    let err = Command::new(&args.cmd_args[0])
        .args(&args.cmd_args[1..])
        .exec();

    Err(err).with_context(|| format!("exec of `{cmd}` failed", cmd = args.cmd_args.join(" ")))
}

fn main() -> Result<()> {
    let ret = main_with_error();
    if let Err(e) = &ret {
        error!("Error: {}", e);
    }
    ret
}

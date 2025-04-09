// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Matter Labs

use intel_dcap_api::{ApiClient, CaType, CrlEncoding, IntelApiError, PckCrlResponse};
use x509_cert::{
    der::{oid::AssociatedOid, Decode, SliceReader},
    ext::pkix::{
        crl::dp::DistributionPoint,
        name::{DistributionPointName, GeneralName},
        CrlDistributionPoints,
    },
};

#[tokio::main]
async fn main() -> Result<(), IntelApiError> {
    let client = ApiClient::new()?;

    let PckCrlResponse {
        crl_data,
        issuer_chain,
    } = client
        .get_pck_crl(CaType::Platform, Some(CrlEncoding::Der))
        .await?;

    let certs = x509_cert::certificate::CertificateInner::<
        x509_cert::certificate::Rfc5280
    >::load_pem_chain(issuer_chain.as_bytes()).map_err(
        |_| IntelApiError::InvalidParameter("Could not load a PEM chain")
    )?;

    for cert in certs {
        println!("Issuer: {}", cert.tbs_certificate.issuer);
        println!("Subject: {}", cert.tbs_certificate.subject);
        println!("Serial Number: {}", cert.tbs_certificate.serial_number);
        println!("Not Before: {}", cert.tbs_certificate.validity.not_before);
        println!("Not After: {}", cert.tbs_certificate.validity.not_after);

        // Extract and print CRL distribution points
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == CrlDistributionPoints::OID {
                    // Create a SliceReader from the byte slice
                    let mut reader = SliceReader::new(ext.extn_value.as_bytes()).map_err(|_| {
                        IntelApiError::InvalidParameter(
                            "Could not create reader from extension value",
                        )
                    })?;

                    // Now pass the reader to decode_value
                    if let Ok(dist_points) = Vec::<DistributionPoint>::decode(&mut reader) {
                        for point in dist_points {
                            if let Some(DistributionPointName::FullName(names)) =
                                point.distribution_point
                            {
                                for name in names {
                                    if let GeneralName::UniformResourceIdentifier(uri) = name {
                                        let uri = uri.as_str();
                                        let crl_bytes = reqwest::get(uri).await?.bytes().await?;
                                        println!("CRL bytes (hex): {}", hex::encode(&crl_bytes));
                                    }
                                }
                            }
                        }
                    } else {
                        println!("Could not decode CRL distribution points");
                    }
                }
            }
        }
    }

    println!("CRL bytes (hex): {}", hex::encode(&crl_data));

    Ok(())
}

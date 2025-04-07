// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Configuration settings for the verification process

use crate::{
    core::{SGX_HASH_SIZE, TDX_HASH_SIZE},
    error,
};
use bytes::{Bytes, BytesMut};
use clap::{ArgGroup, Parser};
use enumset::EnumSet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, ops::Deref, path::PathBuf, str::FromStr, time::Duration};
use teepot::{log::LogLevelParser, quote::tcblevel::TcbLevel};
use tracing_subscriber::filter::LevelFilter;
use url::Url;
use zksync_basic_types::{tee_types::TeeType, L1BatchNumber};
use zksync_types::L2ChainId;

/// Primary configuration for the verification process
#[derive(Parser, Debug, Clone)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None
)]
#[clap(group(
    ArgGroup::new("mode")
        .required(true)
        .args(&["batch_range", "continuous"]),
))]
pub struct VerifierConfigArgs {
    /// Log level for the log output.
    /// Valid values are: `off`, `error`, `warn`, `info`, `debug`, `trace`
    #[clap(long, default_value_t = LevelFilter::WARN, value_parser = LogLevelParser)]
    pub log_level: LevelFilter,

    /// The batch number or range of batch numbers to verify the attestation and signature (e.g.,
    /// "42" or "42-45"). This option is mutually exclusive with the `--continuous` mode.
    #[clap(short = 'n', long = "batch", value_parser = parse_batch_range)]
    pub batch_range: Option<(L1BatchNumber, L1BatchNumber)>,

    /// Continuous mode: keep verifying new batches until interrupted. This option is mutually
    /// exclusive with the `--batch` option.
    #[clap(long, value_name = "FIRST_BATCH")]
    pub continuous: Option<L1BatchNumber>,

    /// URL of the RPC server to query for the batch attestation and signature.
    #[clap(long = "rpc")]
    pub rpc_url: Url,

    /// Chain ID of the network to query.
    #[clap(long = "chain", default_value_t = L2ChainId::default().as_u64())]
    pub chain_id: u64,

    /// Rate limit between requests in milliseconds.
    #[clap(long, default_value = "0", value_parser = parse_duration)]
    pub rate_limit: Duration,

    /// Path to a YAML file containing attestation policy configuration.
    /// This overrides any attestation policy settings provided via command line options.
    #[clap(long = "attestation-policy-file")]
    pub attestation_policy_file: Option<PathBuf>,

    /// Comma separated list of Tee types to process
    #[clap(long)]
    pub tee_types: TeeTypes,
}

/// Attestation policy implemented as a set of criteria that must be met by SGX attestation.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SgxAttestationPolicyConfig {
    /// List of allowed hex-encoded SGX mrsigners. Batch attestation must consist of
    /// one of these mrsigners. If the list is empty, the mrsigner check is skipped.
    #[serde(default)]
    pub mrsigners: Option<Vec<String>>,

    /// List of allowed hex-encoded SGX mrenclaves. Batch attestation must consist
    /// of one of these mrenclaves. If the list is empty, the mrenclave check is skipped.
    #[serde(default)]
    pub mrenclaves: Option<Vec<String>>,

    /// List of allowed SGX TCB levels. If the list is empty, the TCB level check is
    /// skipped. Allowed values: Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded,
    /// OutOfDate, OutOfDateConfigNeeded.
    #[serde(default = "default_tcb_levels")]
    pub allowed_tcb_levels: EnumSet<TcbLevel>,

    /// List of allowed SGX Advisories. If the list is empty, theAdvisories check is skipped.
    #[serde(default)]
    pub allowed_advisory_ids: Option<Vec<String>>,
}

/// Attestation policy implemented as a set of criteria that must be met by TDX attestation.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TdxAttestationPolicyConfig {
    /// List of allowed hex-encoded TDX mrs. Batch attestation must consist
    /// of one of these mrs. If the list is empty, the mrs check is skipped.
    #[serde(default)]
    pub mrs: Option<Vec<[String; 5]>>,

    /// List of allowed SGX TCB levels. If the list is empty, the TCB level check is
    /// skipped. Allowed values: Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded,
    /// OutOfDate, OutOfDateConfigNeeded.
    #[serde(default = "default_tcb_levels")]
    pub allowed_tcb_levels: EnumSet<TcbLevel>,

    /// List of allowed TDX Advisories. If the list is empty, theAdvisories check is skipped.
    #[serde(default)]
    pub allowed_advisory_ids: Option<Vec<String>>,
}

/// Attestation policy implemented as a set of criteria that must be met by SGX or TDX attestation.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicyConfig {
    /// SGX attestation policy
    pub sgx: SgxAttestationPolicyConfig,
    /// TDX attestation policy
    pub tdx: TdxAttestationPolicyConfig,
}

#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    pub sgx_mrsigners: Option<Vec<Bytes>>,
    pub sgx_mrenclaves: Option<Vec<Bytes>>,
    pub sgx_allowed_tcb_levels: EnumSet<TcbLevel>,
    pub sgx_allowed_advisory_ids: Option<Vec<String>>,
    pub tdx_allowed_tcb_levels: EnumSet<TcbLevel>,
    pub tdx_mrs: Option<Vec<Bytes>>,
    pub tdx_allowed_advisory_ids: Option<Vec<String>>,
}

/// Default TCB levels used for Serde deserialization
fn default_tcb_levels() -> EnumSet<TcbLevel> {
    let mut set = EnumSet::new();
    set.insert(TcbLevel::Ok);
    set
}

// TODO:
// When moving this binary to the `zksync-era` repo, we
// should be using `EnumSet<TeeType>` but this requires
// #[derive(EnumSetType, Debug, Serialize, Deserialize)]
// #[enumset(serialize_repr = "list")]
// for `TeeType`
#[derive(Clone, Debug)]
pub struct TeeTypes(HashSet<TeeType>);

impl FromStr for TeeTypes {
    type Err = error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut hs = HashSet::new();
        let tee_strs: Vec<&str> = s.split(',').collect();
        for tee_str in tee_strs {
            match tee_str.to_ascii_lowercase().as_str() {
                "sgx" => {
                    hs.insert(TeeType::Sgx);
                }
                "tdx" => {
                    hs.insert(TeeType::Tdx);
                }
                _ => {
                    return Err(error::Error::internal("Unknown TEE type"));
                }
            }
        }
        Ok(Self(hs))
    }
}
impl Default for TeeTypes {
    fn default() -> Self {
        Self(HashSet::from([TeeType::Sgx, TeeType::Tdx]))
    }
}

impl Deref for TeeTypes {
    type Target = HashSet<TeeType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub args: VerifierConfigArgs,
    pub policy: AttestationPolicy,
}

impl VerifierConfig {
    pub fn new(args: VerifierConfigArgs) -> error::Result<Self> {
        let policy = if let Some(path) = &args.attestation_policy_file {
            let policy_content = fs::read_to_string(path).map_err(|e| {
                error::Error::internal(format!("Failed to read attestation policy file: {}", e))
            })?;

            let policy_config: AttestationPolicyConfig = serde_yaml::from_str(&policy_content)
                .map_err(|e| {
                    error::Error::internal(format!(
                        "Failed to parse attestation policy file: {}",
                        e
                    ))
                })?;

            tracing::info!("Loaded attestation policy from file: {:?}", path);
            policy_config
        } else {
            AttestationPolicyConfig::default()
        };

        let policy = AttestationPolicy {
            sgx_mrsigners: decode_hex_vec_option(policy.sgx.mrsigners, SGX_HASH_SIZE)?,
            sgx_mrenclaves: decode_hex_vec_option(policy.sgx.mrenclaves, SGX_HASH_SIZE)?,
            sgx_allowed_tcb_levels: policy.sgx.allowed_tcb_levels,
            sgx_allowed_advisory_ids: policy.sgx.allowed_advisory_ids,
            tdx_allowed_tcb_levels: policy.tdx.allowed_tcb_levels,
            tdx_mrs: decode_tdx_mrs(policy.tdx.mrs, TDX_HASH_SIZE)?,
            tdx_allowed_advisory_ids: policy.tdx.allowed_advisory_ids,
        };

        if policy.sgx_mrsigners.is_none() && policy.sgx_mrenclaves.is_none() {
            tracing::error!(
                "Neither `--sgx-mrenclaves` nor `--sgx-mrsigners` specified. Any code could have produced the SGX proof."
            );
        }

        if policy.tdx_mrs.is_none() {
            tracing::error!(
                "`--tdxmrs` not specified. Any code could have produced the TDX proof."
            );
        }

        Ok(Self { args, policy })
    }
}

// Helper function to decode a vector of hex strings
fn decode_hex_vec_option(
    hex_strings: Option<Vec<String>>,
    bytes_length: usize,
) -> Result<Option<Vec<Bytes>>, hex::FromHexError> {
    hex_strings
        .map(|strings| {
            strings
                .into_iter()
                .map(|s| {
                    if s.len() > (bytes_length * 2) {
                        return Err(hex::FromHexError::InvalidStringLength);
                    }
                    hex::decode(s).map(Bytes::from)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
}

// Improved decode_tdx_mrs function
fn decode_tdx_mrs(
    tdx_mrs_opt: Option<Vec<[String; 5]>>,
    bytes_length: usize,
) -> Result<Option<Vec<Bytes>>, hex::FromHexError> {
    match tdx_mrs_opt {
        None => Ok(None),
        Some(mrs_array) => {
            let result = mrs_array
                .into_iter()
                .map(|strings| decode_and_combine_mrs(strings, bytes_length))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(result))
        }
    }
}

// Helper function to decode and combine MRs
fn decode_and_combine_mrs(
    strings: [String; 5],
    bytes_length: usize,
) -> Result<Bytes, hex::FromHexError> {
    let mut buffer = BytesMut::with_capacity(bytes_length * 5);

    for s in &strings {
        if s.len() > (bytes_length * 2) {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let decoded = hex::decode(s)?;
        buffer.extend(decoded);
    }

    Ok(buffer.freeze())
}

/// Parse a batch range from a string like "42" or "42-45"
fn parse_batch_range(s: &str) -> error::Result<(L1BatchNumber, L1BatchNumber)> {
    let parse = |s: &str| {
        s.parse::<u32>()
            .map(L1BatchNumber::from)
            .map_err(|e| error::Error::internal(format!("Can't convert batch {s} to number: {e}")))
    };
    match s.split_once('-') {
        Some((start, end)) => {
            let (start, end) = (parse(start)?, parse(end)?);
            if start > end {
                Err(error::Error::InvalidBatchRange(s.into()))
            } else {
                Ok((start, end))
            }
        }
        None => {
            let batch_number = parse(s)?;
            Ok((batch_number, batch_number))
        }
    }
}

/// Parse a duration from a millisecond string
fn parse_duration(s: &str) -> error::Result<Duration> {
    let millis = s
        .parse()
        .map_err(|e| error::Error::internal(format!("Can't convert {s} to duration: {e}")))?;
    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{env, fs, path::PathBuf};
    use teepot::quote::tcblevel::TcbLevel;

    #[test]
    fn test_load_attestation_policy_from_yaml() {
        // Create a temporary directory for the test
        let temp_dir = env::temp_dir().join("test_attestation_policy");
        fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        // Create a temporary YAML file
        let yaml_path = temp_dir.join("policy.yaml");
        let yaml_content = r#"
sgx:
    mrenclaves:
      - a2caa7055e333f69c3e46ca7ba65b135a86c90adfde2afb356e05075b7818b3c
      - 36eeb64cc816f80a1cf5818b26710f360714b987d3799e757cbefba7697b9589
    allowed_tcb_levels:
      - Ok
      - SwHardeningNeeded
tdx:
    mrs:
      - - 2a90c8fa38672cafd791d994beb6836b99383b2563736858632284f0f760a6446efd1e7ec457cf08b629ea630f7b4525
        - 3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f
        - c08ab64725566bcc8a6fb1c79e2e64744fcff1594b8f1f02d716fb66592ecd5de94933b2bc54ffbbc43a52aab7eb1146
        - 092a4866a9e6a1672d7439a5d106fbc6eb57b738d5bfea5276d41afa2551824365fdd66700c1ce9c0b20542b9f9d5945
        - 971fb52f90ec98a234301ca9b8fc30b613c33e3dd9c0cc42dcb8003d4a95d8fb218b75baf028b70a3cabcb947e1ca453
"#;
        fs::write(&yaml_path, yaml_content).expect("Failed to write YAML file");

        // Create a minimal config
        let config = VerifierConfig::new(VerifierConfigArgs {
            log_level: LevelFilter::INFO,
            batch_range: Some((L1BatchNumber(1), L1BatchNumber(10))),
            continuous: None,
            rpc_url: Url::parse("http://localhost:8545").unwrap(),
            chain_id: 270,
            rate_limit: Duration::from_millis(0),
            attestation_policy_file: Some(yaml_path.clone()),
            tee_types: Default::default(),
        })
        .expect("Failed to load attestation policy");

        // Verify that the attestation policy was loaded correctly
        assert_eq!(config.policy.sgx_mrsigners, None);
        assert_eq!(
            config.policy.sgx_mrenclaves,
            Some(vec![
                Bytes::from(
                    hex::decode("a2caa7055e333f69c3e46ca7ba65b135a86c90adfde2afb356e05075b7818b3c")
                        .unwrap(),
                ),
                Bytes::from(
                    hex::decode("36eeb64cc816f80a1cf5818b26710f360714b987d3799e757cbefba7697b9589")
                        .unwrap(),
                ),
            ])
        );
        assert!(config.policy.sgx_allowed_tcb_levels.contains(TcbLevel::Ok));
        assert!(config
            .policy
            .sgx_allowed_tcb_levels
            .contains(TcbLevel::SwHardeningNeeded));
        assert_eq!(
            config.policy.tdx_mrs,
            Some(vec![Bytes::from(
                hex::decode(concat!(
                "2a90c8fa38672cafd791d994beb6836b99383b2563736858632284f0f760a6446efd1e7ec457cf08b629ea630f7b4525",
                "3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f",
                "c08ab64725566bcc8a6fb1c79e2e64744fcff1594b8f1f02d716fb66592ecd5de94933b2bc54ffbbc43a52aab7eb1146",
                "092a4866a9e6a1672d7439a5d106fbc6eb57b738d5bfea5276d41afa2551824365fdd66700c1ce9c0b20542b9f9d5945",
                "971fb52f90ec98a234301ca9b8fc30b613c33e3dd9c0cc42dcb8003d4a95d8fb218b75baf028b70a3cabcb947e1ca453"
                )).unwrap()),
            ])
        );

        // Clean up
        fs::remove_file(yaml_path).expect("Failed to remove temp YAML file");
        fs::remove_dir_all(temp_dir).expect("Failed to remove temp directory");
    }

    #[test]
    fn test_invalid_yaml_file_path() {
        // Create a minimal config with a non-existent YAML file path
        let result = VerifierConfig::new(VerifierConfigArgs {
            log_level: LevelFilter::INFO,
            batch_range: Some((L1BatchNumber(1), L1BatchNumber(10))),
            continuous: None,
            rpc_url: Url::parse("http://localhost:8545").unwrap(),
            chain_id: 270,
            rate_limit: Duration::from_millis(0),
            attestation_policy_file: Some(PathBuf::from("/non/existent/path.yaml")),
            tee_types: Default::default(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_yaml_content() {
        // Create a temporary directory for the test
        let temp_dir = env::temp_dir().join("test_invalid_yaml");
        fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        // Create a temporary YAML file with invalid content
        let yaml_path = temp_dir.join("invalid_policy.yaml");
        let yaml_content = r#"
sgx_mrsigners: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
invalid_key: "some value"
allowed_tcb_levels:
  - Invalid
  - ConfigNeeded
"#;
        fs::write(&yaml_path, yaml_content).expect("Failed to write YAML file");

        // Create a minimal config
        let result = VerifierConfig::new(VerifierConfigArgs {
            log_level: LevelFilter::INFO,
            batch_range: Some((L1BatchNumber(1), L1BatchNumber(10))),
            continuous: None,
            rpc_url: Url::parse("http://localhost:8545").unwrap(),
            chain_id: 270,
            rate_limit: Duration::from_millis(0),
            attestation_policy_file: Some(yaml_path.clone()),
            tee_types: Default::default(),
        });
        assert!(result.is_err());

        // Clean up
        fs::remove_file(yaml_path).expect("Failed to remove temp YAML file");
        fs::remove_dir_all(temp_dir).expect("Failed to remove temp directory");
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

use anyhow::{anyhow, Result};
use clap::{ArgGroup, Args, Parser};
use std::time::Duration;
use teepot::log::LogLevelParser;
use teepot::sgx::{parse_tcb_levels, EnumSet, TcbLevel};
use tracing_subscriber::filter::LevelFilter;
use url::Url;
use zksync_basic_types::L1BatchNumber;
use zksync_types::L2ChainId;

#[derive(Parser, Debug, Clone)]
#[command(author = "Matter Labs", version, about = "SGX attestation and batch signature verifier", long_about = None)]
#[clap(group(
    ArgGroup::new("mode")
        .required(true)
        .args(&["batch_range", "continuous"]),
))]
pub struct Arguments {
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
    /// Criteria for valid attestation policy. Invalid proofs will be rejected.
    #[clap(flatten)]
    pub attestation_policy: AttestationPolicyArgs,
}

/// Attestation policy implemented as a set of criteria that must be met by SGX attestation.
#[derive(Args, Debug, Clone)]
pub struct AttestationPolicyArgs {
    /// Comma-separated list of allowed hex-encoded SGX mrsigners. Batch attestation must consist of
    /// one of these mrsigners. If the list is empty, the mrsigner check is skipped.
    #[arg(long = "mrsigners")]
    pub sgx_mrsigners: Option<String>,
    /// Comma-separated list of allowed hex-encoded SGX mrenclaves. Batch attestation must consist
    /// of one of these mrenclaves. If the list is empty, the mrenclave check is skipped.
    #[arg(long = "mrenclaves")]
    pub sgx_mrenclaves: Option<String>,
    /// Comma-separated list of allowed TCB levels. If the list is empty, the TCB level check is
    /// skipped. Allowed values: Ok, ConfigNeeded, ConfigAndSwHardeningNeeded, SwHardeningNeeded,
    /// OutOfDate, OutOfDateConfigNeeded.
    #[arg(long, value_parser = parse_tcb_levels, default_value = "Ok")]
    pub sgx_allowed_tcb_levels: EnumSet<TcbLevel>,
}

fn parse_batch_range(s: &str) -> Result<(L1BatchNumber, L1BatchNumber)> {
    let parse = |s: &str| {
        s.parse::<u32>()
            .map(L1BatchNumber::from)
            .map_err(|e| anyhow!(e))
    };
    match s.split_once('-') {
        Some((start, end)) => {
            let (start, end) = (parse(start)?, parse(end)?);
            if start > end {
                Err(anyhow!(
                    "Start batch number ({}) must be less than or equal to end batch number ({})",
                    start,
                    end
                ))
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

fn parse_duration(s: &str) -> Result<Duration> {
    let millis = s.parse()?;
    Ok(Duration::from_millis(millis))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Matter Labs

//! Logging related stuff

use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing::Subscriber;
use tracing_log::LogTracer;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::Registry;
use tracing_subscriber::{prelude::*, EnvFilter};

/// A log level parser for clap, with "off", "error", "warn", "info", "debug", "trace" as valid values
#[derive(Clone)]
pub struct LogLevelParser;

impl clap::builder::TypedValueParser for LogLevelParser {
    type Value = LevelFilter;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> anyhow::Result<Self::Value, clap::Error> {
        clap::builder::TypedValueParser::parse(self, cmd, arg, value.to_owned())
    }

    fn parse(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: std::ffi::OsString,
    ) -> std::result::Result<Self::Value, clap::Error> {
        use std::str::FromStr;
        let p = clap::builder::PossibleValuesParser::new([
            "off", "error", "warn", "info", "debug", "trace",
        ]);
        let v = p.parse(cmd, arg, value)?;

        Ok(LevelFilter::from_str(&v).unwrap())
    }
}

/// Setup standard logging and loglevel for the current crate and the `teepot` crate.
pub fn setup_logging(
    crate_name: &str,
    log_level: &LevelFilter,
) -> anyhow::Result<impl Subscriber + Send + Sync + 'static> {
    LogTracer::init().context("Failed to set logger")?;
    let filter = EnvFilter::builder()
        .try_from_env()
        .unwrap_or(match *log_level {
            LevelFilter::OFF => EnvFilter::new("off"),
            _ => EnvFilter::new(format!(
                "warn,{crate_name}={log_level},teepot={log_level}",
                log_level = log_level
            )),
        });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_file(false)
        .with_line_number(false)
        .with_writer(std::io::stderr);

    let subscriber = Registry::default().with(filter).with(fmt_layer);

    Ok(subscriber)
}

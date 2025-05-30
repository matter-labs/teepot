// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

use anyhow::{anyhow, Result};
use clap::Parser;
use pesign::PE;
use sha2::{Digest, Sha384};
use std::{
    fmt::{Display, Formatter},
    io::{Error, Read, Seek, SeekFrom},
    path::PathBuf,
};
use teepot::{
    log::{setup_logging, LogLevelParser},
    tdx::UEFI_MARKER_DIGEST_BYTES,
};
use tracing::{debug, info, level_filters::LevelFilter};

/// Precalculate rtmr1 and rtmr2 values.
///
/// Currently tested with the Google confidential compute engines.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// disk image to measure the GPT table from
    #[arg(long)]
    image: PathBuf,
    /// path to the used UKI EFI binary
    #[arg(long)]
    bootefi: PathBuf,
    /// path to the used linux kernel EFI binary (contained in the UKI)
    #[arg(long)]
    kernel: PathBuf,
    /// Log level for the log output.
    /// Valid values are: `off`, `error`, `warn`, `info`, `debug`, `trace`
    #[clap(long, default_value_t = LevelFilter::WARN, value_parser = LogLevelParser)]
    pub log_level: LevelFilter,
}

struct Rtmr {
    state: Vec<u8>,
}

impl Rtmr {
    pub fn extend(&mut self, hash: &[u8]) -> &[u8] {
        self.state.extend(hash);
        let bytes = Sha384::digest(&self.state);
        self.state.resize(48, 0);
        self.state.copy_from_slice(&bytes);
        &self.state
    }
}

impl Default for Rtmr {
    fn default() -> Self {
        Self {
            state: [0u8; 48].to_vec(),
        }
    }
}

impl Display for Rtmr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.state))
    }
}

const CHUNK_SIZE: u64 = 1024 * 128;

fn main() -> Result<()> {
    let args = Arguments::parse();
    tracing::subscriber::set_global_default(setup_logging(
        env!("CARGO_CRATE_NAME"),
        &args.log_level,
    )?)?;

    let mut rtmr1 = Rtmr::default();
    let mut rtmr2 = Rtmr::default();

    /*
    - pcr_index: 1
      event: efiaction
      digests:
        - method: sha384
          digest: 77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71
      digest_verification_status: verified
      data: Q2FsbGluZyBFRkkgQXBwbGljYXRpb24gZnJvbSBCb290IE9wdGlvbg==
      parsed_data:
        Ok:
          text: Calling EFI Application from Boot Option
       */
    rtmr1.extend(&hex::decode("77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71")?);

    /*
    - pcr_index: 1
      event: separator
      digests:
        - method: sha384
          digest: 394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0
      digest_verification_status: verified
      data: AAAAAA==
      parsed_data:
        Ok:
          validseparator: UEFI
       */
    rtmr1.extend(&UEFI_MARKER_DIGEST_BYTES);

    // Open disk image.
    let cfg = gpt::GptConfig::new().writable(false);
    let disk = cfg.open(args.image)?;

    // Print GPT layout.
    info!("Disk (primary) header: {:#?}", disk.primary_header());
    info!("Partition layout: {:#?}", disk.partitions());

    let header = disk.primary_header()?;
    let mut msr = Vec::<u8>::new();
    let lb_size = disk.logical_block_size();
    let mut device = disk.device_ref();
    device.seek(SeekFrom::Start(lb_size.as_u64()))?;
    let mut buf = [0u8; 92];
    device.read_exact(&mut buf)?;
    msr.extend_from_slice(&buf);

    let pstart = header
        .part_start
        .checked_mul(lb_size.as_u64())
        .ok_or_else(|| Error::other("partition overflow - start offset"))?;
    let _ = device.seek(SeekFrom::Start(pstart))?;

    assert_eq!(header.part_size, 128);
    assert!(header.num_parts < u32::from(u8::MAX));

    let empty_bytes = [0u8; 128];

    msr.extend_from_slice(&disk.partitions().len().to_le_bytes());

    for _ in 0..header.num_parts {
        let mut bytes = empty_bytes;

        device.read_exact(&mut bytes)?;
        if bytes.eq(&empty_bytes) {
            continue;
        }
        msr.extend_from_slice(&bytes);
    }

    let mut hasher = Sha384::new();
    hasher.update(&msr);
    let result = hasher.finalize();
    info!("GPT hash: {:x}", result);

    rtmr1.extend(&result);

    let mut pe = PE::from_path(&args.bootefi)?;

    let hash = pe.calc_authenticode(pesign::cert::Algorithm::Sha384)?;
    info!("hash of {:?}: {hash}", args.bootefi);
    rtmr1.extend(&hex::decode(&hash)?);

    let section_table = pe.get_section_table()?;

    for section in &section_table {
        debug!(section_name = ?section.name()?);
    }

    for sect in [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"] {
        let mut hasher = Sha384::new();
        hasher.update(sect.as_bytes());
        hasher.update([0u8]);
        let out = hasher.finalize();
        debug!(sect, "name: {out:x}");
        rtmr2.extend(&out);

        let s = section_table
            .iter()
            .find(|s| s.name().unwrap().eq(sect))
            .ok_or(anyhow!("Failed to find section `{sect}`"))?;

        let mut start = u64::from(s.pointer_to_raw_data);
        let end = start + u64::from(s.virtual_size);

        debug!(sect, start, end, len = (s.virtual_size));

        let mut hasher = Sha384::new();

        loop {
            if start >= end {
                break;
            }

            let mut buf = vec![0; CHUNK_SIZE.min(end - start) as _];
            pe.read_exact_at(start, buf.as_mut_slice())?;
            hasher.update(buf.as_slice());

            start += CHUNK_SIZE;
        }
        let digest = hasher.finalize();
        debug!(sect, "binary: {digest:x}");
        rtmr2.extend(&digest);
    }

    let hash = PE::from_path(&args.kernel)?.calc_authenticode(pesign::cert::Algorithm::Sha384)?;
    info!("hash of {:?}: {hash}", args.kernel);
    rtmr1.extend(&hex::decode(&hash)?);

    /*
    - pcr_index: 1
      event: efiaction
      digests:
        - method: sha384
          digest: 214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0
      digest_verification_status: verified
      data: RXhpdCBCb290IFNlcnZpY2VzIEludm9jYXRpb24=
      parsed_data:
        Ok:
          text: Exit Boot Services Invocation
       */
    rtmr1.extend(&hex::decode("214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0")?);

    /*
    - pcr_index: 1
      event: efiaction
      digests:
        - method: sha384
          digest: 0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74
      digest_verification_status: verified
      data: RXhpdCBCb290IFNlcnZpY2VzIFJldHVybmVkIHdpdGggU3VjY2Vzcw==
      parsed_data:
        Ok:
          text: Exit Boot Services Returned with Success
      */
    rtmr1.extend(&hex::decode("0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74")?);

    println!("{{");
    println!("\t\"rtmr1\": \"{rtmr1}\",");
    println!("\t\"rtmr2\": \"{rtmr2}\"");
    println!("}}");

    Ok(())
}

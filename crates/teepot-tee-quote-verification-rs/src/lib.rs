// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "intel.rs")]
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    path = "empty.rs"
)]
mod os;

pub use os::*;

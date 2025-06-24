// SPDX-License-Identifier: BSD-3-Clause

#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "intel.rs")]
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    path = "empty.rs"
)]
mod os;

pub use os::*;

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! rtmr event data

use crate::sgx::QuoteError;

/// The sha384 digest of 0u32, which is used in the UEFI TPM protocol
/// as a marker. Used to advance the PCR.
/// ```shell
/// $ echo -n -e "\000\000\000\000" | sha384sum -b
/// 394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0 *-
/// ```
pub const UEFI_MARKER_DIGEST_BYTES: [u8; 48] = [
    0x39, 0x43, 0x41, 0xb7, 0x18, 0x2c, 0xd2, 0x27, 0xc5, 0xc6, 0xb0, 0x7e, 0xf8, 0x00, 0x0c, 0xdf,
    0xd8, 0x61, 0x36, 0xc4, 0x29, 0x2b, 0x8e, 0x57, 0x65, 0x73, 0xad, 0x7e, 0xd9, 0xae, 0x41, 0x01,
    0x9f, 0x58, 0x18, 0xb4, 0xb9, 0x71, 0xc9, 0xef, 0xfc, 0x60, 0xe1, 0xad, 0x9f, 0x12, 0x89, 0xf0,
];

/// The actual rtmr event data handled in DCAP
#[repr(C, packed)]
pub struct TdxRtmrEvent {
    /// Always 1
    version: u32,

    /// The RTMR that will be extended. As defined in
    /// https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-measurement
    /// we will use RTMR 3 for guest application code and configuration.
    rtmr_index: u64,

    /// Data that will be used to extend RTMR
    extend_data: [u8; 48usize],

    /// Not used in DCAP
    event_type: u32,

    /// Always 0
    event_data_size: u32,

    /// Not used in DCAP
    event_data: Vec<u8>,
}

impl Default for TdxRtmrEvent {
    fn default() -> Self {
        Self {
            extend_data: [0; 48],
            version: 1,
            rtmr_index: 3,
            event_type: 0,
            event_data_size: 0,
            event_data: Vec::new(),
        }
    }
}

impl TdxRtmrEvent {
    /// use the extend data
    pub fn with_extend_data(mut self, extend_data: [u8; 48]) -> Self {
        self.extend_data = extend_data;
        self
    }

    /// extend the rtmr index
    pub fn with_rtmr_index(mut self, rtmr_index: u64) -> Self {
        self.rtmr_index = rtmr_index;
        self
    }

    /// extending the index, consuming self
    pub fn extend(self) -> Result<(), QuoteError> {
        let event: Vec<u8> = self.into();

        match tdx_attest_rs::tdx_att_extend(&event) {
            tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => Ok(()),
            error_code => Err(error_code.into()),
        }
    }
}

impl From<TdxRtmrEvent> for Vec<u8> {
    fn from(val: TdxRtmrEvent) -> Self {
        let event_ptr = &val as *const TdxRtmrEvent as *const u8;
        let event_data_size = std::mem::size_of::<u8>() * val.event_data_size as usize;
        let res_size = std::mem::size_of::<u32>() * 3
            + std::mem::size_of::<u64>()
            + std::mem::size_of::<[u8; 48]>()
            + event_data_size;
        let mut res = vec![0; res_size];
        unsafe {
            for (i, chunk) in res.iter_mut().enumerate().take(res_size - event_data_size) {
                *chunk = *event_ptr.add(i);
            }
        }
        let event_data = val.event_data;
        for i in 0..event_data_size {
            res[i + res_size - event_data_size] = event_data[i];
        }

        res
    }
}

#[cfg(test)]
mod test {
    use super::UEFI_MARKER_DIGEST_BYTES;

    #[test]
    fn test_uefi_marker_digest() {
        assert_eq!(
            UEFI_MARKER_DIGEST_BYTES.to_vec(),
            hex::decode("394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0").unwrap()
        );
    }
}

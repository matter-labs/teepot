// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 Matter Labs

//! rtmr event data

use teepot::sgx::QuoteError;

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

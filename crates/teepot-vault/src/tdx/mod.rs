// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! Intel TDX helper functions.

pub mod rtmr;

pub use intel_tee_quote_verification_rs::Collateral;
use tdx_attest_rs::{tdx_att_get_quote, tdx_attest_error_t, tdx_report_data_t};
pub use teepot::sgx::tcblevel::{parse_tcb_levels, EnumSet, TcbLevel};
use teepot::sgx::QuoteError;

/// Get a TDX quote
pub fn tgx_get_quote(report_data_bytes: &[u8; 64]) -> Result<Box<[u8]>, QuoteError> {
    let mut tdx_report_data = tdx_report_data_t { d: [0; 64usize] };
    tdx_report_data.d.copy_from_slice(report_data_bytes);

    let (error, quote) = tdx_att_get_quote(Some(&tdx_report_data), None, None, 0);

    if error == tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        if let Some(quote) = quote {
            Ok(quote.into())
        } else {
            Err(QuoteError::TdxAttGetQuote {
                msg: "tdx_att_get_quote: No quote returned".into(),
                inner: error,
            })
        }
    } else {
        Err(error.into())
    }
}

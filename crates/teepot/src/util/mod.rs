// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Matter Labs

//! utility functions.

use thiserror::Error;

/// Errors that can occur when padding byte vectors to fixed-size arrays.
#[derive(Error, Debug)]
pub enum PadError {
    /// Indicates that the input vector's length exceeds the target array size.
    ///
    /// # Fields
    /// * `expected` - The target size of the array in bytes
    /// * `actual` - The actual length of the input vector in bytes
    ///
    /// # Example
    /// ```rust
    /// # use teepot::util::{pad, PadError};
    /// let long_input = vec![1, 2, 3, 4];
    /// let result = pad::<2>(&long_input);
    /// assert!(matches!(
    ///     result,
    ///     Err(PadError::InputTooLong { expected: 2, actual: 4 })
    /// ));
    /// ```
    #[error("Input vector is too long - expected {expected} bytes, got {actual}")]
    InputTooLong {
        /// The expected length (target array size)
        expected: usize,
        /// The actual length of the provided input
        actual: usize,
    },
}

/// Pad a byte vector to a fixed-size array by appending zeros. If the input is longer
/// than the target size, returns an error.
///
/// # Arguments
/// * `input` - Input byte vector to be padded with zeros
///
/// # Returns
/// * `Result<[u8; T], PadError>` - A fixed-size array of length T, or a PadError if input is too long
///
/// # Errors
/// Returns `PadError::InputTooLong` if the input vector length exceeds the target array size T,
/// containing both the expected and actual sizes
///
/// # Examples
/// ```rust
/// # use teepot::util::{pad, PadError};
/// let input = vec![1, 2, 3];
/// let padded: [u8; 5] = pad(&input)?;
/// assert_eq!(padded, [1, 2, 3, 0, 0]);
///
/// // Error case: input too long
/// let long_input = vec![1, 2, 3, 4, 5, 6];
/// assert!(matches!(
///     pad::<5>(&long_input),
///     Err(PadError::InputTooLong { expected: 5, actual: 6 })
/// ));
/// # Ok::<(), PadError>(())
/// ```
///
/// # Type Parameters
/// * `T` - The fixed size of the output array in bytes
pub fn pad<const T: usize>(input: &[u8]) -> Result<[u8; T], PadError> {
    let mut output = [0u8; T];
    match input.len().cmp(&T) {
        std::cmp::Ordering::Greater => Err(PadError::InputTooLong {
            expected: T,
            actual: input.len(),
        }),
        std::cmp::Ordering::Equal => {
            output.copy_from_slice(input);
            Ok(output)
        }
        std::cmp::Ordering::Less => {
            output[..input.len()].copy_from_slice(input);
            Ok(output)
        }
    }
}

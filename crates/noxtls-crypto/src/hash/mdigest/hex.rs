// Copyright (c) 2019-2026, Argenox Technologies LLC
// All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only OR LicenseRef-Argenox-Commercial-License
//
// This file is part of the NoxTLS Library.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by the
// Free Software Foundation; version 2 of the License.
//
// Alternatively, this file may be used under the terms of a commercial
// license from Argenox Technologies LLC.
//
// See `noxtls/LICENSE` and `noxtls/LICENSE.md` in this repository for full details.
// CONTACT: info@argenox.com

use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

/// Decodes a hexadecimal string into raw bytes.
///
/// # Arguments
/// * `hex`: ASCII hexadecimal string with even length.
///
/// # Returns
/// Decoded binary bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidEncoding`] when the string length is odd or a character is not hexadecimal ASCII.
///
/// # Panics
///
/// This function does not panic.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding("hex length must be even"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// Converts one ASCII hexadecimal digit into a 4-bit numeric value.
///
/// # Arguments
///
/// * `value` — Single ASCII byte from a hex string (`0-9`, `a-f`, or `A-F`).
///
/// # Returns
///
/// `Ok` nibble in `0..16` on success.
///
/// # Errors
///
/// Returns [`Error::InvalidEncoding`] when `value` is not a hex digit.
///
/// # Panics
///
/// This function does not panic.
fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Error::InvalidEncoding("invalid hex character")),
    }
}

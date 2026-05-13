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

use noxtls_core::{Error, Result};

/// Represents a parsed DER TLV node body with its ASN.1 tag.
#[derive(Debug, Clone)]
pub struct DerNode<'a> {
    pub tag: u8,
    pub body: &'a [u8],
}

/// Parses one DER node from input and returns the node plus remaining bytes.
///
/// # Arguments
///
/// * `input` — DER-encoded byte stream starting at a TLV node.
///
/// # Returns
///
/// Tuple of parsed [`DerNode`] and remaining unconsumed bytes.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when the input is too short for tag/length, length is invalid, or the declared length exceeds the buffer.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_parse_der_node(input: &[u8]) -> Result<(DerNode<'_>, &[u8])> {
    if input.len() < 2 {
        return Err(Error::ParseFailure("DER node too short"));
    }
    let tag = input[0];
    let (len, len_len) = noxtls_parse_der_length(&input[1..])?;
    let start = 1_usize
        .checked_add(len_len)
        .ok_or(Error::ParseFailure("DER length arithmetic overflow"))?;
    let end = start
        .checked_add(len)
        .ok_or(Error::ParseFailure("DER length arithmetic overflow"))?;
    if input.len() < end {
        return Err(Error::ParseFailure("DER length exceeds input"));
    }
    Ok((
        DerNode {
            tag,
            body: &input[start..end],
        },
        &input[end..],
    ))
}

/// Parses DER length octets and returns `(content_length, length_octet_count)`.
///
/// # Arguments
///
/// * `input` — Byte slice beginning at DER length octets (immediately after the tag byte in a TLV).
///
/// # Returns
///
/// `(content_length, length_octet_count)` for the parsed DER length.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when length octets are missing, indefinite form is used, or the long-form width is unsupported for this parser.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        return Err(Error::ParseFailure("missing DER length"));
    }
    let first = input[0];
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > 4 || input.len() < 1 + octets {
        return Err(Error::ParseFailure("unsupported DER length"));
    }
    if input[1] == 0 {
        return Err(Error::ParseFailure("non-canonical DER length"));
    }
    if octets == 1 && input[1] < 0x80 {
        return Err(Error::ParseFailure("non-canonical DER length"));
    }
    let mut len = 0_usize;
    for b in &input[1..1 + octets] {
        len = (len << 8) | usize::from(*b);
    }
    Ok((len, 1 + octets))
}

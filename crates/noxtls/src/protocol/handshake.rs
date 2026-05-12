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

/// Encodes one TLS handshake message with a 1-byte type, 3-byte big-endian length, and payload body.
///
/// # Arguments
///
/// * `handshake_type` — TLS `HandshakeType` wire value for this message.
/// * `body` — Handshake message body bytes; length must fit in 24 bits.
///
/// # Returns
///
/// Owned buffer containing `handshake_type || len[3] || body`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn encode_handshake_message(handshake_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(handshake_type);
    let len_bytes = (body.len() as u32).to_be_bytes();
    out.extend_from_slice(&len_bytes[1..4]);
    out.extend_from_slice(body);
    out
}

/// Parses a TLS handshake message prefix and returns the type and body slice.
///
/// # Arguments
///
/// * `input` — Full handshake message bytes including the 4-byte header and body.
///
/// # Returns
///
/// On success, `(handshake_type, body)` where `body` borrows from `input`.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when the buffer is shorter than four bytes or the declared length does not match the buffer size.
///
/// # Panics
///
/// This function does not panic.
pub fn parse_handshake_message(input: &[u8]) -> Result<(u8, &[u8])> {
    if input.len() < 4 {
        return Err(Error::ParseFailure("handshake message too short"));
    }
    let handshake_type = input[0];
    let body_len = u32::from_be_bytes([0x00, input[1], input[2], input[3]]) as usize;
    if input.len() != body_len + 4 {
        return Err(Error::ParseFailure("handshake length mismatch"));
    }
    Ok((handshake_type, &input[4..]))
}

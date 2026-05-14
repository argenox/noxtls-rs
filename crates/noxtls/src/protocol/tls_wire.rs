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

//! TLS wire helpers: record deframing and handshake payload splitting for interoperable transports.

use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

/// Length of a TLS 1.x `TLSPlaintext` outer header (`type || version || length`).
pub const TLS_RECORD_HEADER_LEN: usize = 5;

/// Maximum TLS record payload length permitted by RFC 5246 / RFC 8446 outer length field.
pub const TLS_MAX_RECORD_PAYLOAD_LEN: usize = 1 << 14;

/// Splits one TLS `Handshake` inner payload into individual handshake messages.
///
/// Each message has the form `type(1) || length(3) || body(length)`.
///
/// # Arguments
///
/// * `payload` — Decrypted inner handshake bytes (for example from TLS 1.3 `Handshake` inner content).
///
/// # Returns
///
/// On success, a vector of complete handshake message byte vectors in wire order.
///
/// # Errors
///
/// Returns [`noxtls_core::Error::ParseFailure`] when the payload is truncated or malformed.
///
/// # Panics
///
/// This function does not panic.
pub fn split_tls13_handshake_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    const HANDSHAKE_HEADER_LEN: usize = 4;
    let mut cursor = 0_usize;
    let mut messages = Vec::new();
    while cursor < payload.len() {
        if payload.len().saturating_sub(cursor) < HANDSHAKE_HEADER_LEN {
            return Err(Error::ParseFailure(
                "truncated tls handshake header in inner handshake payload",
            ));
        }
        let message_len = ((payload[cursor + 1] as usize) << 16)
            | ((payload[cursor + 2] as usize) << 8)
            | payload[cursor + 3] as usize;
        let full_len = HANDSHAKE_HEADER_LEN.saturating_add(message_len);
        if payload.len().saturating_sub(cursor) < full_len {
            return Err(Error::ParseFailure(
                "truncated tls handshake message body in inner handshake payload",
            ));
        }
        messages.push(payload[cursor..cursor + full_len].to_vec());
        cursor = cursor.saturating_add(full_len);
    }
    Ok(messages)
}

/// Buffers incoming TLS octets and yields complete record packets (`header + payload`).
///
/// This type supports partial reads from blocking or non-blocking transports.
#[derive(Debug, Default, Clone)]
pub struct TlsRecordDeframer {
    buf: Vec<u8>,
}

impl TlsRecordDeframer {
    /// Creates an empty deframer buffer.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — No parameters.
    ///
    /// # Returns
    ///
    /// An empty [`TlsRecordDeframer`] ready to accept bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends newly read transport bytes to the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `chunk` — Non-empty slice of TLS octets read from the peer.
    ///
    /// # Returns
    ///
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Returns one complete TLS record packet if the buffer holds at least `5 + length` bytes.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — Uses internal buffer only.
    ///
    /// # Returns
    ///
    /// `Ok(Some(packet))` when a full record is available, `Ok(None)` when more bytes are needed,
    /// or an error when the header advertises an illegal length.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error::InvalidLength`] when the length field exceeds [`TLS_MAX_RECORD_PAYLOAD_LEN`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn pop_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < TLS_RECORD_HEADER_LEN {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        if payload_len > TLS_MAX_RECORD_PAYLOAD_LEN {
            return Err(Error::InvalidLength(
                "tls record payload exceeds maximum allowed length",
            ));
        }
        let total = TLS_RECORD_HEADER_LEN.saturating_add(payload_len);
        if self.buf.len() < total {
            return Ok(None);
        }
        let packet = self.buf[..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(packet))
    }

    /// Returns the number of bytes currently buffered.
    ///
    /// # Arguments
    ///
    /// * `&self` — Deframer whose buffered length is queried.
    ///
    /// # Returns
    ///
    /// Buffered byte count.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

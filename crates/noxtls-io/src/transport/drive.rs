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

//! Helpers that combine the TLS state machine with a [`super::blocking::BlockingStream`].

use super::blocking::BlockingStream;
use super::TransportError;

/// Reads exactly `len` bytes from `stream` into `out`, resizing `out` as needed.
///
/// # Arguments
///
/// * `stream` — Blocking transport carrying TLS record bytes.
/// * `len` — Exact number of bytes to read before returning `Ok`.
/// * `out` — Growable buffer cleared then resized to `len` and filled from the stream.
///
/// # Returns
///
/// `Ok(())` when `out.len() == len` and all bytes were read successfully.
///
/// # Errors
///
/// Returns [`TransportError::UnexpectedEof`] when the stream returns zero bytes before `len` is satisfied,
/// or any error propagated from [`BlockingStream::read`].
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_read_exact_blocking<S: BlockingStream>(
    stream: &mut S,
    len: usize,
    out: &mut crate::internal_alloc::Vec<u8>,
) -> Result<(), TransportError> {
    out.clear();
    out.resize(len, 0);
    let mut read_total = 0usize;
    while read_total < len {
        let n = stream.read(&mut out[read_total..len])?;
        if n == 0 {
            return Err(TransportError::UnexpectedEof);
        }
        read_total = read_total.saturating_add(n);
    }
    Ok(())
}

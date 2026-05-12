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

//! Blocking byte-stream trait for synchronous TLS record transport.

use super::TransportError;

/// Blocking byte stream used to move TLS records without async runtimes.
pub trait BlockingStream {
    /// Reads up to `buf.len()` bytes into the start of `buf`.
    ///
    /// # Arguments
    ///
    /// * `self` — Blocking transport endpoint.
    /// * `buf` — Destination buffer; only the first returned count of bytes are defined.
    ///
    /// # Returns
    ///
    /// On success, the number of bytes read into `buf` (may be less than `buf.len()` except at EOF semantics).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnexpectedEof`] or [`TransportError::IoFailed`] when the underlying stream fails.
    ///
    /// # Panics
    ///
    /// Implementations should not panic; callers treat panics as a defect in the adapter.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Writes every byte in `data` using one or more underlying writes.
    ///
    /// # Arguments
    ///
    /// * `self` — Blocking transport endpoint.
    /// * `data` — Slice whose entire contents must be transmitted before returning `Ok`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all bytes are accepted by the transport.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when a partial write makes no progress or flush/write fails.
    ///
    /// # Panics
    ///
    /// Implementations should not panic; callers treat panics as a defect in the adapter.
    fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError>;
}

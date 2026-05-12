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

//! Blocking [`super::blocking::BlockingStream`] adapter for types implementing the `embedded-io` `Read` and `Write` traits.
//!
//! Enabled with the `adapter-embedded-io` Cargo feature.

use embedded_io::{ErrorType, Read, Write};

use super::blocking::BlockingStream;
use super::TransportError;

/// Wraps an `embedded-io` reader/writer pair for [`BlockingStream`] consumers.
pub struct EmbeddedIoTransport<I> {
    inner: I,
}

impl<I> EmbeddedIoTransport<I> {
    /// Constructs a transport adapter around `inner`.
    ///
    /// # Arguments
    ///
    /// * `inner` — `embedded-io` reader/writer value wrapped by this adapter.
    ///
    /// # Returns
    ///
    /// A new [`EmbeddedIoTransport`] ready for blocking TLS I/O.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn new(inner: I) -> Self {
        Self { inner }
    }

    /// Consumes the adapter and returns the wrapped `embedded-io` object.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter to destructure.
    ///
    /// # Returns
    ///
    /// The original `inner` value passed to [`Self::new`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn into_inner(self) -> I {
        self.inner
    }
}

impl<I: Read + Write + ErrorType> BlockingStream for EmbeddedIoTransport<I> {
    /// Reads up to `buf.len()` bytes using the `embedded-io` `Read` trait semantics.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the read.
    /// * `buf` — Destination buffer for received bytes.
    ///
    /// # Returns
    ///
    /// The byte count stored in `buf` on success.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when the underlying `read` reports failure.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.inner
            .read(buf)
            .map_err(|_| TransportError::IoFailed("embedded-io read failed"))
    }

    /// Writes all bytes in `data` using repeated `embedded-io` `Write` calls and flushes once.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the writes.
    /// * `data` — Bytes to transmit in order.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the full slice is written and flushed.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when a write returns zero progress, a write fails, or flush fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let n = self
                .inner
                .write(&data[offset..])
                .map_err(|_| TransportError::IoFailed("embedded-io write failed"))?;
            if n == 0 {
                return Err(TransportError::IoFailed("embedded-io wrote zero bytes"));
            }
            offset = offset.saturating_add(n);
        }
        self.inner
            .flush()
            .map_err(|_| TransportError::IoFailed("embedded-io flush failed"))?;
        Ok(())
    }
}

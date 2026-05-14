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

//! Async [`super::stream_async::AsyncByteStream`] adapter for `embedded-io-async` reader/writer types.
//!
//! Enabled with the `adapter-embedded-io-async` Cargo feature.

use async_trait::async_trait;
use embedded_io_async::{ErrorType, Read, Write};

use super::stream_async::AsyncByteStream;
use super::TransportError;

/// Wraps an `embedded-io-async` reader/writer pair for [`AsyncByteStream`] consumers.
pub struct EmbeddedIoAsyncTransport<I> {
    inner: I,
}

impl<I> EmbeddedIoAsyncTransport<I> {
    /// Constructs an async transport adapter around `inner`.
    ///
    /// # Arguments
    ///
    /// * `inner` — Async `embedded-io-async` reader/writer value wrapped by this adapter.
    ///
    /// # Returns
    ///
    /// A noxtls_new [`EmbeddedIoAsyncTransport`] ready for async TLS I/O.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_new(inner: I) -> Self {
        Self { inner }
    }

    /// Consumes the adapter and returns the wrapped async I/O object.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter to destructure.
    ///
    /// # Returns
    ///
    /// The original `inner` value passed to [`Self::noxtls_new`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn into_inner(self) -> I {
        self.inner
    }
}

#[async_trait(?Send)]
impl<I> AsyncByteStream for EmbeddedIoAsyncTransport<I>
where
    I: Read + Write + ErrorType,
{
    /// Reads up to `buf.len()` bytes asynchronously using `embedded-io-async` read semantics.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the async read.
    /// * `buf` — Destination buffer for received bytes.
    ///
    /// # Returns
    ///
    /// The byte count stored in `buf` on success.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when the underlying async `read` reports failure.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    async fn read_async(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.inner
            .read(buf)
            .await
            .map_err(|_| TransportError::IoFailed("embedded-io-async read failed"))
    }

    /// Writes all bytes in `data` using repeated async writes followed by flush.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the async writes.
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
    async fn write_all_async(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let n = self
                .inner
                .write(&data[offset..])
                .await
                .map_err(|_| TransportError::IoFailed("embedded-io-async write failed"))?;
            if n == 0 {
                return Err(TransportError::IoFailed(
                    "embedded-io-async wrote zero bytes",
                ));
            }
            offset = offset.saturating_add(n);
        }
        self.inner
            .flush()
            .await
            .map_err(|_| TransportError::IoFailed("embedded-io-async flush failed"))?;
        Ok(())
    }
}

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

//! Tokio-backed [`super::stream_async::AsyncByteStream`] adapter for types implementing Tokio
//! `AsyncReadExt` and `AsyncWriteExt`.
//!
//! Enabled with the `adapter-tokio` Cargo feature.

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::stream_async::AsyncByteStream;
use super::TransportError;

/// Wraps a Tokio stream that implements `AsyncReadExt` and `AsyncWriteExt`.
pub struct TokioAsyncTransport<T> {
    inner: T,
}

impl<T> TokioAsyncTransport<T> {
    /// Constructs a Tokio-backed async transport around `inner`.
    ///
    /// # Arguments
    ///
    /// * `inner` — Tokio stream used for async TLS record I/O.
    ///
    /// # Returns
    ///
    /// A new [`TokioAsyncTransport`] ready for use as an [`AsyncByteStream`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Consumes the adapter and returns the wrapped Tokio stream.
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
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[async_trait(?Send)]
impl<T> AsyncByteStream for TokioAsyncTransport<T>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    /// Reads up to `buf.len()` bytes using Tokio `AsyncReadExt::read`.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the Tokio read.
    /// * `buf` — Destination buffer for received bytes.
    ///
    /// # Returns
    ///
    /// The byte count stored in `buf` on success.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when the Tokio read reports failure.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    async fn read_async(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.inner
            .read(buf)
            .await
            .map_err(|_| TransportError::IoFailed("tokio read failed"))
    }

    /// Writes all bytes in `data` using Tokio `AsyncWriteExt::write_all` then flushes.
    ///
    /// # Arguments
    ///
    /// * `self` — Adapter whose `inner` performs the Tokio writes.
    /// * `data` — Bytes to transmit in order.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the full slice is written and flushed.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::IoFailed`] when Tokio `write_all` or `flush` fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    async fn write_all_async(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.inner
            .write_all(data)
            .await
            .map_err(|_| TransportError::IoFailed("tokio write_all failed"))?;
        self.inner
            .flush()
            .await
            .map_err(|_| TransportError::IoFailed("tokio flush failed"))?;
        Ok(())
    }
}

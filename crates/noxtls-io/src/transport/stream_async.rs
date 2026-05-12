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

//! Async byte stream trait used by TLS record drivers without tying callers to a specific runtime.
//!
//! Available when `adapter-embedded-io-async` or `adapter-tokio` is enabled alongside this module.

use async_trait::async_trait;

use super::TransportError;

/// Async byte stream for TLS record framing without assuming a specific runtime.
///
/// Uses `?Send` so `embedded-io-async` transports that are not `Send` remain usable.
#[async_trait(?Send)]
pub trait AsyncByteStream {
    /// Reads up to `buf.len()` bytes asynchronously into `buf`.
    ///
    /// # Arguments
    ///
    /// * `self` — Async transport endpoint.
    /// * `buf` — Destination buffer; only the first returned count of bytes are defined.
    ///
    /// # Returns
    ///
    /// On success, the number of bytes read into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] variants when the underlying async read fails.
    ///
    /// # Panics
    ///
    /// Implementations should not panic; callers treat panics as a defect in the adapter.
    async fn read_async(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Writes every byte in `data` asynchronously before returning `Ok`.
    ///
    /// # Arguments
    ///
    /// * `self` — Async transport endpoint.
    /// * `data` — Slice whose entire contents must be transmitted.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all bytes are accepted and any required flushing completes successfully.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] variants when the underlying async write or flush fails.
    ///
    /// # Panics
    ///
    /// Implementations should not panic; callers treat panics as a defect in the adapter.
    async fn write_all_async(&mut self, data: &[u8]) -> Result<(), TransportError>;
}

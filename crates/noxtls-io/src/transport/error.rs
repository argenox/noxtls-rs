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

use core::fmt::{Display, Formatter};

/// Describes transport-level read/write failures independent of TLS alert encoding.
///
/// Variants are intentionally minimal so adapters map diverse backends to stable diagnostics.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TransportError {
    /// Underlying stream returned EOF before enough bytes were available.
    UnexpectedEof,
    /// Byte I/O failed with an implementation-specific condition.
    IoFailed(&'static str),
}

impl Display for TransportError {
    /// Writes the stable human-readable message for this transport error.
    ///
    /// # Arguments
    ///
    /// * `self` — Transport error to render.
    /// * `f` — Formatter receiving the UTF-8 message text.
    ///
    /// # Returns
    ///
    /// `Ok(())` when formatting succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`core::fmt::Error`] when the formatter rejects output.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of stream"),
            Self::IoFailed(msg) => f.write_str(msg),
        }
    }
}

#[cfg(feature = "std")]
/// Bridges [`TransportError`] into [`std::error::Error`] when the `std` feature is enabled.
impl std::error::Error for TransportError {}

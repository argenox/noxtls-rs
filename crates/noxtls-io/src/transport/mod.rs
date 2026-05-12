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

//! Transport abstractions for blocking and async byte I/O.
//!
//! [`TransportError`] classifies failures shared across adapters. Submodules provide concrete
//! [`blocking::BlockingStream`] helpers, optional async traits, and integration with embedded and Tokio stacks.

mod error;

pub mod blocking;
#[cfg(any(feature = "adapter-embedded-io-async", feature = "adapter-tokio"))]
pub mod stream_async;

#[cfg(feature = "adapter-embedded-io")]
pub mod embedded_io_adapter;
#[cfg(feature = "adapter-embedded-io-async")]
pub mod embedded_io_async_adapter;
#[cfg(feature = "adapter-tokio")]
pub mod tokio_adapter;

pub mod drive;

pub use error::TransportError;

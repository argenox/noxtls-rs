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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! Blocking and async byte transport adapters for moving TLS records on the wire.
//!
//! The [`transport`] module exposes [`transport::blocking::BlockingStream`] and, when async adapter features are
//! enabled, async stream traits plus optional Tokio and `embedded-io` shims.

#[cfg(not(feature = "std"))]
extern crate alloc;

mod internal_alloc;

pub mod transport;

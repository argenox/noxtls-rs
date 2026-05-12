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

//! Re-exports heap types for `no_std` + `alloc` builds.
//!
//! When `std` is enabled, the same names resolve to the standard library `String` and `Vec` types so
//! call sites in `noxtls-pem` stay identical across feature sets.

/// Borrowed-to-owned conversion trait from the `alloc` crate (re-exported for `no_std` builds).
#[cfg(not(feature = "std"))]
pub(crate) use alloc::borrow::ToOwned;
/// Growable UTF-8 string type from `alloc` (re-exported for `no_std` builds).
#[cfg(not(feature = "std"))]
pub(crate) use alloc::string::String;
/// Growable byte vector type from `alloc` (re-exported for `no_std` builds).
#[cfg(not(feature = "std"))]
pub(crate) use alloc::vec::Vec;
/// Growable UTF-8 string type from the standard library when `std` is enabled.
#[cfg(feature = "std")]
pub(crate) use std::string::String;
/// Growable byte vector type from the standard library when `std` is enabled.
#[cfg(feature = "std")]
pub(crate) use std::vec::Vec;

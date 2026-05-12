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
//! Call sites use [`Vec`] uniformly whether the crate is built with `std` or `alloc` only.

/// Growable byte vector from `alloc` when `std` is disabled.
#[cfg(not(feature = "std"))]
pub(crate) use alloc::vec::Vec;
/// Growable byte vector from the standard library when `std` is enabled.
#[cfg(feature = "std")]
pub(crate) use std::vec::Vec;

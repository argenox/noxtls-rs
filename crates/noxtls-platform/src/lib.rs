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

//! Portable hooks for wall time, monotonic timers, and entropy suitable for embedded TLS stacks.

/// Millisecond-resolution opaque timestamp used by DTLS flight and retransmit timers.
///
/// Values are produced by platform-specific monotonic sources; callers should only compare or
/// subtract deltas within the same clock domain.
pub type MonotonicMillis = u64;

/// Reads whole seconds since the Unix epoch using the system clock when `std` is enabled.
///
/// # Arguments
///
/// This function takes no parameters.
///
/// # Returns
///
/// Elapsed whole seconds since 1970-01-01 UTC, or `0` when the system clock is unavailable or yields a pre-epoch time.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
#[must_use]
pub fn unix_timestamp_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}


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

use crate::internal_alloc::Vec;

/// Defines the streaming digest contract used by hash implementations.
pub trait Digest {
    /// Feeds additional bytes into the digest state.
    ///
    /// # Arguments
    /// * `data`: Additional message bytes to absorb into the hash state.
    ///
    /// # Panics
    ///
    /// This function does not panic for conforming implementations in this crate.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the digest and returns the resulting hash bytes.
    ///
    /// # Returns
    /// Final digest bytes for all input provided through `update`.
    ///
    /// # Panics
    ///
    /// This function does not panic for conforming implementations in this crate.
    fn finalize(self) -> Vec<u8>;
}

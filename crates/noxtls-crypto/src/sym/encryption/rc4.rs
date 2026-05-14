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

use noxtls_core::{Error, Result};

/// Implements RC4 stream cipher state for compatibility testing.
#[derive(Debug, Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Initializes RC4 by running key-scheduling over a non-empty key.
    ///
    /// # Arguments
    /// * `key`: Secret RC4 key bytes.
    ///
    /// # Returns
    /// Initialized `Rc4` state after key scheduling.
    pub fn noxtls_new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::InvalidLength("rc4 key must not be empty"));
        }
        let mut s = [0_u8; 256];
        for (idx, entry) in s.iter_mut().enumerate() {
            *entry = idx as u8;
        }
        let mut j = 0_u8;
        for i in 0..256_u16 {
            let idx = i as usize;
            j = j.wrapping_add(s[idx]).wrapping_add(key[idx % key.len()]);
            s.swap(idx, usize::from(j));
        }
        Ok(Self { s, i: 0, j: 0 })
    }

    /// Generates the next RC4 keystream byte using the PRGA.
    ///
    /// # Arguments
    ///
    /// * `self` — RC4 permutation state advanced in place.
    ///
    /// # Returns
    ///
    /// Next pseudorandom keystream byte.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
        self.s.swap(usize::from(self.i), usize::from(self.j));
        let t = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
        self.s[usize::from(t)]
    }

    /// XORs RC4 keystream with `input` and writes the ciphertext/plaintext to `output`.
    ///
    /// # Arguments
    /// * `input`: Input bytes to transform.
    /// * `output`: Output buffer with same length as `input`.
    ///
    /// # Returns
    /// `Ok(())` when transformation completes.
    pub fn apply_keystream(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if input.len() != output.len() {
            return Err(Error::InvalidLength("input and output length mismatch"));
        }
        for (in_byte, out_byte) in input.iter().zip(output.iter_mut()) {
            *out_byte = *in_byte ^ self.next_byte();
        }
        Ok(())
    }
}

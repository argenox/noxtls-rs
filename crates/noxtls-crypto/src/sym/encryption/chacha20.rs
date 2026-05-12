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

/// Implements the ChaCha20 stream cipher state and block operations.
#[derive(Debug, Clone)]
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// Initializes ChaCha20 with a 256-bit key, 96-bit nonce, and block counter.
    ///
    /// # Arguments
    ///
    /// * `key` — 32-byte ChaCha20 key.
    /// * `nonce` — 12-byte nonce.
    /// * `counter` — Initial 32-bit block counter.
    ///
    /// # Returns
    ///
    /// Initialized [`ChaCha20`] state.
    ///
    /// # Panics
    ///
    /// This function does not panic for fixed key and nonce sizes as typed.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let constants: [u8; 16] = *b"expand 32-byte k";
        let mut state = [0_u32; 16];
        state[0] = u32::from_le_bytes(constants[0..4].try_into().expect("len"));
        state[1] = u32::from_le_bytes(constants[4..8].try_into().expect("len"));
        state[2] = u32::from_le_bytes(constants[8..12].try_into().expect("len"));
        state[3] = u32::from_le_bytes(constants[12..16].try_into().expect("len"));
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("len"));
        }
        state[12] = counter;
        state[13] = u32::from_le_bytes(nonce[0..4].try_into().expect("len"));
        state[14] = u32::from_le_bytes(nonce[4..8].try_into().expect("len"));
        state[15] = u32::from_le_bytes(nonce[8..12].try_into().expect("len"));
        Self { state }
    }

    /// Applies one ChaCha quarter round to four state words.
    ///
    /// # Arguments
    ///
    /// * `state` — Working ChaCha20 state array.
    /// * `a`, `b`, `c`, `d` — Indices of the four words participating in the round.
    ///
    /// # Returns
    ///
    /// `()`; mutates `state` in place.
    ///
    /// # Panics
    ///
    /// This function does not panic when indices are valid for the fixed ChaCha20 schedule (as used by this module).
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Returns the 64-byte ChaCha20 block function output for the current counter and nonce.
    ///
    /// # Arguments
    ///
    /// * `self` — Cipher state whose current block should be serialized.
    ///
    /// # Returns
    ///
    /// Serialized block words after 20 double rounds; the counter is not advanced.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn block_output(&self) -> [u8; 64] {
        self.block()
    }

    /// Produces a 64-byte keystream block from the current internal state without advancing the counter.
    ///
    /// # Arguments
    ///
    /// * `self` — ChaCha20 state prior to counter increment (counter increment happens in [`Self::apply_keystream`]).
    ///
    /// # Returns
    ///
    /// One serialized 64-byte keystream block.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn block(&self) -> [u8; 64] {
        let mut working = self.state;
        for _ in 0..10 {
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }
        for (w, s) in working.iter_mut().zip(self.state) {
            *w = w.wrapping_add(s);
        }
        let mut out = [0_u8; 64];
        for (i, word) in working.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// XORs the generated keystream with `input` and writes the result to `output`.
    ///
    /// # Arguments
    ///
    /// * `input` — Input bytes to transform.
    /// * `output` — Output buffer with the same length as `input`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transformation completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `input` and `output` lengths differ.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn apply_keystream(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        if output.len() != input.len() {
            return Err(Error::InvalidLength("input and output length mismatch"));
        }
        let mut offset = 0;
        while offset < input.len() {
            let block = self.block();
            self.state[12] = self.state[12].wrapping_add(1);
            let chunk_len = (input.len() - offset).min(64);
            for idx in 0..chunk_len {
                output[offset + idx] = input[offset + idx] ^ block[idx];
            }
            offset += chunk_len;
        }
        Ok(())
    }
}

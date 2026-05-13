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

use super::Digest;
use crate::internal_alloc::Vec;

/// Implements SHA-512 compression and streaming digest state.
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    bit_len: u128,
}

impl Default for Sha512 {
    /// Builds a SHA-512 hasher with standard IV constants and an empty buffer.
    ///
    /// # Returns
    ///
    /// Fresh [`Sha512`] in the initial state.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn default() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0_u8; 128],
            buffer_len: 0,
            bit_len: 0,
        }
    }
}

impl Sha512 {
    /// Creates a new SHA-512 hasher initialized with standard IV constants.
    ///
    /// # Returns
    /// A fresh `Sha512` instance with empty input state.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds internal SHA-512 machinery initialized for the SHA-384 IV set.
    ///
    /// # Returns
    ///
    /// [`Sha512`] configured for SHA-384 digests (48-byte truncation at the API boundary).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn new_sha384() -> Self {
        Self {
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            ..Self::default()
        }
    }

    /// Compresses one 1024-bit SHA-512 message block into the eight working words.
    ///
    /// # Arguments
    ///
    /// * `self` — Running hasher whose `state` is updated.
    /// * `block` — One fully prepared 128-byte big-endian message block.
    ///
    /// # Returns
    ///
    /// `()`; folds the round function output into `self.state`.
    ///
    /// # Panics
    ///
    /// Panics only if internal word parsing fails; callers pass full blocks produced by this type.
    fn compress(&mut self, block: &[u8; 128]) {
        const K: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];
        let mut w = [0_u64; 80];
        for (i, chunk) in block.chunks_exact(8).enumerate().take(16) {
            w[i] = u64::from_be_bytes(
                chunk
                    .try_into()
                    .expect("sha512 block chunk length must be 8"),
            );
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Digest for Sha512 {
    /// Absorbs `data` into the running digest, compressing whenever 128 bytes accumulate.
    ///
    /// # Arguments
    ///
    /// * `self` — Running SHA-512 hasher.
    /// * `data` — Next message bytes to append.
    ///
    /// # Returns
    ///
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn update(&mut self, mut data: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((data.len() as u128) * 8);
        while !data.is_empty() {
            let to_copy = (128 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];
            if self.buffer_len == 128 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalizes SHA-512 padding and returns the 64-byte digest in a newly allocated vector.
    ///
    /// # Arguments
    ///
    /// * `self` — Consumed hasher holding buffered tail bytes and the 128-bit length counter.
    ///
    /// # Returns
    ///
    /// [`Vec`] containing exactly 64 digest bytes (big-endian words from internal state).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn finalize(mut self) -> Vec<u8> {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..112].fill(0);
        self.buffer[112..128].copy_from_slice(&self.bit_len.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        let mut out = Vec::with_capacity(64);
        for word in self.state {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Computes SHA-512 of `data` and returns 64 digest bytes.
///
/// # Arguments
/// * `data`: Input bytes to hash.
///
/// # Returns
/// A 64-byte SHA-512 digest.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Computes SHA-384 of `data` and returns 48 digest bytes.
///
/// # Arguments
/// * `data`: Input bytes to hash.
///
/// # Returns
/// A 48-byte SHA-384 digest.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha512::new_sha384();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0_u8; 48];
    out.copy_from_slice(&digest[..48]);
    out
}

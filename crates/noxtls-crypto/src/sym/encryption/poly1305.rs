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

use crate::sym::encryption::ChaCha20;

/// Derives the 32-byte Poly1305 one-time key from ChaCha20 block counter zero (RFC 8439 section 2.6).
///
/// # Arguments
/// * `key`: 32-byte ChaCha20 key.
/// * `nonce`: 12-byte nonce.
///
/// # Returns
/// First 32 bytes of the ChaCha20 block at counter 0.
pub fn noxtls_poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let cipher = ChaCha20::new(key, nonce, 0);
    let block = cipher.block_output();
    let mut otk = [0_u8; 32];
    otk.copy_from_slice(&block[..32]);
    otk
}

/// Computes RFC 8439 Poly1305 on a variable-length message (unpadded block encoding).
///
/// # Arguments
/// * `otk`: 32-byte one-time key (first half forms clamped `r`, second half is `s`).
/// * `msg`: Message bytes to authenticate.
///
/// # Returns
/// 16-byte authentication tag in little-endian form.
pub fn noxtls_poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut state = Poly1305State::new(otk);
    let mut offset = 0;
    while offset < msg.len() {
        let remaining = msg.len() - offset;
        if remaining >= 16 {
            let block: [u8; 16] = msg[offset..offset + 16].try_into().expect("len");
            state.compute_block(&block, false);
            offset += 16;
        } else {
            let mut block = [0_u8; 16];
            block[..remaining].copy_from_slice(&msg[offset..]);
            block[remaining] = 1;
            state.compute_block(&block, true);
            offset += remaining;
        }
    }
    state.finalize()
}

/// Runs Poly1305 when the input length is a multiple of 16 (RFC 8439 AEAD `mac_data`).
///
/// # Arguments
/// * `otk`: 32-byte one-time key.
/// * `data`: Byte string whose length is divisible by 16.
///
/// # Returns
/// 16-byte tag, or zero tag if `data` is empty (caller should avoid empty input for AEAD).
pub fn noxtls_poly1305_mac_padded16(otk: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut state = Poly1305State::new(otk);
    debug_assert!(data.len() % 16 == 0);
    let mut offset = 0;
    while offset < data.len() {
        let block: [u8; 16] = data[offset..offset + 16].try_into().expect("len");
        state.compute_block(&block, false);
        offset += 16;
    }
    state.finalize()
}

/// Compares two 16-byte Poly1305 tags in constant time.
///
/// # Arguments
/// * `a`, `b`: Tags to compare.
///
/// # Returns
/// `true` when all octets match.
pub fn noxtls_poly1305_tags_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0_u8;
    for idx in 0..16 {
        diff |= a[idx] ^ b[idx];
    }
    diff == 0
}

/// Holds Poly1305 `r`, accumulator `h`, and `s` pad words for finalization.
#[derive(Clone, Default)]
struct Poly1305State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305State {
    /// Builds Poly1305 state from a 32-byte one-time key (clamped `r` limbs and `s` pad words).
    ///
    /// # Arguments
    ///
    /// * `key` — 32-byte Poly1305 key; the first 16 bytes define `r` after clamping, the last 16 define `s`.
    ///
    /// # Returns
    ///
    /// Initialized internal state ready to absorb message blocks.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn new(key: &[u8; 32]) -> Self {
        let mut poly = Poly1305State::default();
        poly.r[0] = u32::from_le_bytes(key[0..4].try_into().expect("len")) & 0x3ff_ffff;
        poly.r[1] = (u32::from_le_bytes(key[3..7].try_into().expect("len")) >> 2) & 0x3ff_ff03;
        poly.r[2] = (u32::from_le_bytes(key[6..10].try_into().expect("len")) >> 4) & 0x3ff_c0ff;
        poly.r[3] = (u32::from_le_bytes(key[9..13].try_into().expect("len")) >> 6) & 0x3f0_3fff;
        poly.r[4] = (u32::from_le_bytes(key[12..16].try_into().expect("len")) >> 8) & 0x00f_ffff;

        poly.pad[0] = u32::from_le_bytes(key[16..20].try_into().expect("len"));
        poly.pad[1] = u32::from_le_bytes(key[20..24].try_into().expect("len"));
        poly.pad[2] = u32::from_le_bytes(key[24..28].try_into().expect("len"));
        poly.pad[3] = u32::from_le_bytes(key[28..32].try_into().expect("len"));

        poly
    }

    /// Absorbs one 16-byte block into the polynomial hash accumulator.
    ///
    /// # Arguments
    ///
    /// * `self` — Running Poly1305 state.
    /// * `block` — Next 16 message bytes as little-endian 32-bit limbs.
    /// * `partial` — When `true`, sets the high bit encoding for the final partial-block path.
    ///
    /// # Returns
    ///
    /// `()`; updates `self.h` in place.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn compute_block(&mut self, block: &[u8; 16], partial: bool) {
        let hibit = if partial { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        h0 += u32::from_le_bytes(block[0..4].try_into().expect("len")) & 0x3ff_ffff;
        h1 += (u32::from_le_bytes(block[3..7].try_into().expect("len")) >> 2) & 0x3ff_ffff;
        h2 += (u32::from_le_bytes(block[6..10].try_into().expect("len")) >> 4) & 0x3ff_ffff;
        h3 += (u32::from_le_bytes(block[9..13].try_into().expect("len")) >> 6) & 0x3ff_ffff;
        h4 += (u32::from_le_bytes(block[12..16].try_into().expect("len")) >> 8) | hibit;

        let d0 = (u64::from(h0) * u64::from(r0))
            + (u64::from(h1) * u64::from(s4))
            + (u64::from(h2) * u64::from(s3))
            + (u64::from(h3) * u64::from(s2))
            + (u64::from(h4) * u64::from(s1));

        let mut d1 = (u64::from(h0) * u64::from(r1))
            + (u64::from(h1) * u64::from(r0))
            + (u64::from(h2) * u64::from(s4))
            + (u64::from(h3) * u64::from(s3))
            + (u64::from(h4) * u64::from(s2));

        let mut d2 = (u64::from(h0) * u64::from(r2))
            + (u64::from(h1) * u64::from(r1))
            + (u64::from(h2) * u64::from(r0))
            + (u64::from(h3) * u64::from(s4))
            + (u64::from(h4) * u64::from(s3));

        let mut d3 = (u64::from(h0) * u64::from(r3))
            + (u64::from(h1) * u64::from(r2))
            + (u64::from(h2) * u64::from(r1))
            + (u64::from(h3) * u64::from(r0))
            + (u64::from(h4) * u64::from(s4));

        let mut d4 = (u64::from(h0) * u64::from(r4))
            + (u64::from(h1) * u64::from(r3))
            + (u64::from(h2) * u64::from(r2))
            + (u64::from(h3) * u64::from(r1))
            + (u64::from(h4) * u64::from(r0));

        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(c);

        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(c);

        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(c);

        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(c);

        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    /// Finalizes Poly1305 and returns the 128-bit authenticator in little-endian byte order.
    ///
    /// # Arguments
    ///
    /// * `self` — Consumed Poly1305 state after message absorption.
    ///
    /// # Returns
    ///
    /// 16-byte Poly1305 tag.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn finalize(self) -> [u8; 16] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;

        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;

        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;

        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;

        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;

        let mut tag = [0_u8; 16];
        tag[0..4].copy_from_slice(&h0.to_le_bytes());
        tag[4..8].copy_from_slice(&h1.to_le_bytes());
        tag[8..12].copy_from_slice(&h2.to_le_bytes());
        tag[12..16].copy_from_slice(&h3.to_le_bytes());

        tag
    }
}

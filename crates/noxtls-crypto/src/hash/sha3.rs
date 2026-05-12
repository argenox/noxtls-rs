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

//! SHA-3 family digests (FIPS 202) using an in-house Keccak-f[1600] sponge.

use crate::internal_alloc::Vec;

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROTATION_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Applies one full Keccak-f\[1600] permutation in place.
///
/// # Arguments
///
/// * `state` — 25 lanes (5×5) of the sponge state in row-major order; updated by the round function.
///
/// # Returns
///
/// `()`; permutes `state` in place.
///
/// # Panics
///
/// This function does not panic.
fn keccak_f1600(state: &mut [u64; 25]) {
    for &round_constant in &KECCAK_ROUND_CONSTANTS {
        let mut c = [0_u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0_u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0_u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let index = x + 5 * y;
                let rotated = state[index].rotate_left(KECCAK_ROTATION_OFFSETS[index]);
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                b[new_x + 5 * new_y] = rotated;
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        state[0] ^= round_constant;
    }
}

/// XOR-absorbs one full rate-sized block into the sponge state and permutes once.
///
/// # Arguments
///
/// * `state` — Keccak state to update.
/// * `rate_bytes` — Sponge rate in bytes (must be a multiple of 8 and match `block` length).
/// * `block` — Exactly `rate_bytes` input octets interpreted as little-endian 64-bit lanes.
///
/// # Returns
///
/// `()`; updates `state` then calls [`keccak_f1600`].
///
/// # Panics
///
/// This function does not panic when `block.len() == rate_bytes` as produced by this module.
fn absorb_block(state: &mut [u64; 25], rate_bytes: usize, block: &[u8]) {
    for (lane, lane_state) in state.iter_mut().take(rate_bytes / 8).enumerate() {
        let start = lane * 8;
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&block[start..start + 8]);
        *lane_state ^= u64::from_le_bytes(bytes);
    }
    keccak_f1600(state);
}

/// Runs a Keccak sponge with the given rate, domain byte, and squeeze length.
///
/// # Arguments
///
/// * `rate_bytes` — Sponge rate in bytes (SHA3-256/SHAKE256 use 136; SHA3-384 uses 104; SHA3-512 uses 72 in this implementation).
/// * `output_len` — Number of output bytes to squeeze (truncate if the last lane is partial).
/// * `data` — Message bytes absorbed before padding.
/// * `domain` — Domain-separation suffix XORed into the padded tail (`0x06` for SHA3, `0x1F` for SHAKE256 here).
///
/// # Returns
///
/// Allocated digest or XOF bytes of length `output_len`.
///
/// # Panics
///
/// This function does not panic for valid `rate_bytes` values used by the public SHA3/SHAKE entry points.
fn keccak_sponge(rate_bytes: usize, output_len: usize, data: &[u8], domain: u8) -> Vec<u8> {
    let mut state = [0_u64; 25];
    let mut cursor = 0_usize;
    while cursor + rate_bytes <= data.len() {
        absorb_block(&mut state, rate_bytes, &data[cursor..cursor + rate_bytes]);
        cursor += rate_bytes;
    }

    let mut tail = [0_u8; 200];
    let tail_len = data.len() - cursor;
    tail[..tail_len].copy_from_slice(&data[cursor..]);
    tail[tail_len] ^= domain;
    tail[rate_bytes - 1] ^= 0x80;
    absorb_block(&mut state, rate_bytes, &tail[..rate_bytes]);

    let mut out = Vec::with_capacity(output_len);
    while out.len() < output_len {
        let mut lane = 0_usize;
        while lane < (rate_bytes / 8) && out.len() < output_len {
            out.extend_from_slice(&state[lane].to_le_bytes());
            lane += 1;
        }
        if out.len() >= output_len {
            break;
        }
        keccak_f1600(&mut state);
    }
    out.truncate(output_len);
    out
}

/// Computes the SHA3-256 digest of `data`.
///
/// # Arguments
/// * `data`: Input octets.
///
/// # Returns
/// 32-byte digest.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let digest = keccak_sponge(136, 32, data, 0x06);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the SHA3-384 digest of `data`.
///
/// # Arguments
/// * `data`: Input octets.
///
/// # Returns
/// 48-byte digest.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let digest = keccak_sponge(104, 48, data, 0x06);
    let mut out = [0_u8; 48];
    out.copy_from_slice(&digest);
    out
}

/// Computes the SHA3-512 digest of `data`.
///
/// # Arguments
/// * `data`: Input octets.
///
/// # Returns
/// 64-byte digest.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let digest = keccak_sponge(72, 64, data, 0x06);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Computes SHAKE256 extendable-output bytes for `data`.
///
/// # Arguments
/// * `data`: Input octets.
/// * `output_len`: Number of bytes to squeeze from the XOF stream.
///
/// # Returns
/// Variable-length SHAKE256 output.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    // SHAKE functions use domain-separation suffix 0x1F (FIPS 202).
    keccak_sponge(136, output_len, data, 0x1F)
}


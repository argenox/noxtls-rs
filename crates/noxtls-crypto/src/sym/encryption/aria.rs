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
use noxtls_core::{Error, Result};

const ARIA_S1: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const ARIA_S2: [u8; 256] = [
    0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
    0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
    0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
    0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
    0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
    0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
    0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
    0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
    0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
    0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
    0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
    0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
    0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
    0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
    0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
    0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
];

const C1: [u8; 16] = [
    0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0,
];
const C2: [u8; 16] = [
    0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0,
];
const C3: [u8; 16] = [
    0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e,
];

/// Implements ARIA block cipher with key schedule and block operations.
#[derive(Debug, Clone)]
pub struct AriaCipher {
    round_keys: [[u8; 16]; 17],
    rounds: usize,
}

impl AriaCipher {
    /// Constructs ARIA key schedule for 128/192/256-bit keys.
    ///
    /// # Arguments
    /// * `key`: ARIA key bytes (16, 24, or 32 bytes).
    ///
    /// # Returns
    /// Initialized `AriaCipher` with round keys.
    pub fn noxtls_new(key: &[u8]) -> Result<Self> {
        let (rounds, ck1, ck2, ck3) = match key.len() {
            16 => (12, &C1, &C2, &C3),
            24 => (14, &C2, &C3, &C1),
            32 => (16, &C3, &C1, &C2),
            _ => {
                return Err(Error::InvalidLength(
                    "aria key length must be 16, 24, or 32 bytes",
                ));
            }
        };

        let mut kl = [0_u8; 16];
        kl.copy_from_slice(&key[..16]);
        let mut kr = [0_u8; 16];
        match key.len() {
            16 => {}
            24 => {
                kr[..8].copy_from_slice(&key[16..24]);
            }
            32 => {
                kr.copy_from_slice(&key[16..32]);
            }
            _ => unreachable!(),
        }

        let w0 = kl;
        let mut w1 = fo(&w0, ck1);
        xor_block_in_place(&mut w1, &kr);
        let mut w2 = fe(&w1, ck2);
        xor_block_in_place(&mut w2, &w0);
        let mut w3 = fo(&w2, ck3);
        xor_block_in_place(&mut w3, &w1);

        let mut ek = [[0_u8; 16]; 17];
        let mut rot = [0_u8; 16];

        rotate_right_128(&w1, &mut rot, 19);
        ek[0] = xor_block(&w0, &rot);
        rotate_right_128(&w2, &mut rot, 19);
        ek[1] = xor_block(&w1, &rot);
        rotate_right_128(&w3, &mut rot, 19);
        ek[2] = xor_block(&w2, &rot);
        rotate_right_128(&w0, &mut rot, 19);
        ek[3] = xor_block(&rot, &w3);

        rotate_right_128(&w1, &mut rot, 31);
        ek[4] = xor_block(&w0, &rot);
        rotate_right_128(&w2, &mut rot, 31);
        ek[5] = xor_block(&w1, &rot);
        rotate_right_128(&w3, &mut rot, 31);
        ek[6] = xor_block(&w2, &rot);
        rotate_right_128(&w0, &mut rot, 31);
        ek[7] = xor_block(&rot, &w3);

        rotate_left_128(&w1, &mut rot, 61);
        ek[8] = xor_block(&w0, &rot);
        rotate_left_128(&w2, &mut rot, 61);
        ek[9] = xor_block(&w1, &rot);
        rotate_left_128(&w3, &mut rot, 61);
        ek[10] = xor_block(&w2, &rot);
        rotate_left_128(&w0, &mut rot, 61);
        ek[11] = xor_block(&rot, &w3);

        rotate_left_128(&w1, &mut rot, 31);
        ek[12] = xor_block(&w0, &rot);
        rotate_left_128(&w2, &mut rot, 31);
        ek[13] = xor_block(&w1, &rot);
        rotate_left_128(&w3, &mut rot, 31);
        ek[14] = xor_block(&w2, &rot);
        rotate_left_128(&w0, &mut rot, 31);
        ek[15] = xor_block(&rot, &w3);

        rotate_left_128(&w1, &mut rot, 19);
        ek[16] = xor_block(&w0, &rot);

        let mut enc = Self {
            round_keys: [[0_u8; 16]; 17],
            rounds,
        };
        enc.round_keys[..=rounds].copy_from_slice(&ek[..=rounds]);
        Ok(enc)
    }

    /// Encrypts one 16-byte ARIA block in place.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to encrypt in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<()> {
        let mut state = *block;
        for round in 1..self.rounds {
            if (round & 1) != 0 {
                state = fo(&state, &self.round_keys[round - 1]);
            } else {
                state = fe(&state, &self.round_keys[round - 1]);
            }
        }
        xor_block_in_place(&mut state, &self.round_keys[self.rounds - 1]);
        sl2(&mut state);
        xor_block_in_place(&mut state, &self.round_keys[self.rounds]);
        *block = state;
        Ok(())
    }

    /// Decrypts one 16-byte ARIA block in place.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to decrypt in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<()> {
        let mut temp = self.round_keys;
        let rounds = self.rounds;

        let mut dec_keys = [[0_u8; 16]; 17];
        dec_keys[0] = temp[rounds];
        for i in 1..rounds {
            dec_keys[i] = temp[rounds - i];
            diffusion_layer(&mut dec_keys[i]);
        }
        dec_keys[rounds] = temp[0];

        temp = dec_keys;
        let mut state = *block;
        for round in 1..rounds {
            if (round & 1) != 0 {
                state = fo(&state, &temp[round - 1]);
            } else {
                state = fe(&state, &temp[round - 1]);
            }
        }
        xor_block_in_place(&mut state, &temp[rounds - 1]);
        sl2(&mut state);
        xor_block_in_place(&mut state, &temp[rounds]);
        *block = state;
        Ok(())
    }
}

/// Encrypts ARIA-ECB over full blocks; input length must be multiple of 16.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_aria_ecb_encrypt(cipher: &AriaCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aria ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Decrypts ARIA-ECB over full blocks; input length must be multiple of 16.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_aria_ecb_decrypt(cipher: &AriaCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aria ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Encrypts ARIA-CBC with a 16-byte IV and block-aligned plaintext.
pub fn noxtls_aria_cbc_encrypt(
    cipher: &AriaCipher,
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aria cbc input must be block-aligned"));
    }
    let mut out = plaintext.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(16) {
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= prev[i];
        }
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

/// Decrypts ARIA-CBC with a 16-byte IV and block-aligned ciphertext.
pub fn noxtls_aria_cbc_decrypt(
    cipher: &AriaCipher,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aria cbc input must be block-aligned"));
    }
    let mut out = ciphertext.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(16) {
        let mut cur = [0_u8; 16];
        cur.copy_from_slice(chunk);
        let mut block = cur;
        cipher.decrypt_block(&mut block)?;
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        chunk.copy_from_slice(&block);
        prev = cur;
    }
    Ok(out)
}

/// Applies ARIA-CTR transformation using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_aria_ctr_apply(
    cipher: &AriaCipher,
    nonce_counter: &[u8; 16],
    input: &[u8],
) -> Vec<u8> {
    noxtls_aria_ctr_encrypt(cipher, nonce_counter, input)
}

/// Encrypts bytes with ARIA-CTR using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_aria_ctr_encrypt(
    cipher: &AriaCipher,
    nonce_counter: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    aria_ctr_process(cipher, nonce_counter, plaintext)
}

/// Decrypts bytes with ARIA-CTR using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_aria_ctr_decrypt(
    cipher: &AriaCipher,
    nonce_counter: &[u8; 16],
    ciphertext: &[u8],
) -> Vec<u8> {
    aria_ctr_process(cipher, nonce_counter, ciphertext)
}

/// Applies CTR keystream XOR (same operation for encrypt/decrypt).
///
/// # Arguments
///
/// * `cipher` — `&AriaCipher`.
/// * `nonce_counter` — `&[u8; 16]`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `aria_ctr_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn aria_ctr_process(cipher: &AriaCipher, nonce_counter: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut counter = *nonce_counter;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = counter;
        cipher
            .encrypt_block(&mut stream)
            .expect("aria block encryption should not fail");
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        increment_be(&mut counter);
        offset += chunk_len;
    }
    out
}

/// Applies ARIA-CFB-128 transformation with a 16-byte IV.
#[must_use]
pub fn noxtls_aria_cfb_apply(cipher: &AriaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    noxtls_aria_cfb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with ARIA-CFB-128 using a 16-byte IV/register.
#[must_use]
pub fn noxtls_aria_cfb_encrypt(cipher: &AriaCipher, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    aria_cfb_process(cipher, iv, plaintext, true)
}

/// Decrypts bytes with ARIA-CFB-128 using a 16-byte IV/register.
#[must_use]
pub fn noxtls_aria_cfb_decrypt(cipher: &AriaCipher, iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    aria_cfb_process(cipher, iv, ciphertext, false)
}

/// Applies CFB keystream XOR with direction-specific register updates.
///
/// # Arguments
///
/// * `cipher` — `&AriaCipher`.
/// * `iv` — `&[u8; 16]`.
/// * `input` — `&[u8]`.
/// * `encrypt` — `bool`.
///
/// # Returns
///
/// `Vec<u8>` produced by `aria_cfb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn aria_cfb_process(cipher: &AriaCipher, iv: &[u8; 16], input: &[u8], encrypt: bool) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut reg = *iv;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = reg;
        cipher
            .encrypt_block(&mut stream)
            .expect("aria block encryption should not fail");
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        if encrypt {
            shift_register_append(&mut reg, &out[offset..offset + chunk_len]);
        } else {
            shift_register_append(&mut reg, &input[offset..offset + chunk_len]);
        }
        offset += chunk_len;
    }
    out
}

/// Applies ARIA-OFB transformation with a 16-byte IV.
#[must_use]
pub fn noxtls_aria_ofb_apply(cipher: &AriaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    noxtls_aria_ofb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with ARIA-OFB using a 16-byte IV.
#[must_use]
pub fn noxtls_aria_ofb_encrypt(cipher: &AriaCipher, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    aria_ofb_process(cipher, iv, plaintext)
}

/// Decrypts bytes with ARIA-OFB using a 16-byte IV.
#[must_use]
pub fn noxtls_aria_ofb_decrypt(cipher: &AriaCipher, iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    aria_ofb_process(cipher, iv, ciphertext)
}

/// Applies OFB keystream XOR (same operation for encrypt/decrypt).
///
/// # Arguments
///
/// * `cipher` — `&AriaCipher`.
/// * `iv` — `&[u8; 16]`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `aria_ofb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn aria_ofb_process(cipher: &AriaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut stream = *iv;
    let mut offset = 0;
    while offset < input.len() {
        cipher
            .encrypt_block(&mut stream)
            .expect("aria block encryption should not fail");
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        offset += chunk_len;
    }
    out
}

/// Increments a big-endian 128-bit counter in place.
///
/// # Arguments
///
/// * `counter` — `&mut [u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn increment_be(counter: &mut [u8; 16]) {
    for b in counter.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// Applies ARIA FO layer.
///
/// # Arguments
///
/// * `input` — `&[u8; 16]`.
/// * `rk` — `&[u8; 16]`.
///
/// # Returns
///
/// `[u8` produced by `fo` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fo(input: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    let mut out = *input;
    xor_block_in_place(&mut out, rk);
    sl1(&mut out);
    diffusion_layer(&mut out);
    out
}

/// Applies ARIA FE layer.
///
/// # Arguments
///
/// * `input` — `&[u8; 16]`.
/// * `rk` — `&[u8; 16]`.
///
/// # Returns
///
/// `[u8` produced by `fe` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fe(input: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    let mut out = *input;
    xor_block_in_place(&mut out, rk);
    sl2(&mut out);
    diffusion_layer(&mut out);
    out
}

/// Applies ARIA substitution layer type 1.
///
/// # Arguments
///
/// * `state` — `&mut [u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sl1(state: &mut [u8; 16]) {
    let (inv_s1, inv_s2) = inverse_sboxes();
    state[0] = ARIA_S1[state[0] as usize];
    state[1] = ARIA_S2[state[1] as usize];
    state[2] = inv_s1[state[2] as usize];
    state[3] = inv_s2[state[3] as usize];
    state[4] = ARIA_S1[state[4] as usize];
    state[5] = ARIA_S2[state[5] as usize];
    state[6] = inv_s1[state[6] as usize];
    state[7] = inv_s2[state[7] as usize];
    state[8] = ARIA_S1[state[8] as usize];
    state[9] = ARIA_S2[state[9] as usize];
    state[10] = inv_s1[state[10] as usize];
    state[11] = inv_s2[state[11] as usize];
    state[12] = ARIA_S1[state[12] as usize];
    state[13] = ARIA_S2[state[13] as usize];
    state[14] = inv_s1[state[14] as usize];
    state[15] = inv_s2[state[15] as usize];
}

/// Applies ARIA substitution layer type 2.
///
/// # Arguments
///
/// * `state` — `&mut [u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sl2(state: &mut [u8; 16]) {
    let (inv_s1, inv_s2) = inverse_sboxes();
    state[0] = inv_s1[state[0] as usize];
    state[1] = inv_s2[state[1] as usize];
    state[2] = ARIA_S1[state[2] as usize];
    state[3] = ARIA_S2[state[3] as usize];
    state[4] = inv_s1[state[4] as usize];
    state[5] = inv_s2[state[5] as usize];
    state[6] = ARIA_S1[state[6] as usize];
    state[7] = ARIA_S2[state[7] as usize];
    state[8] = inv_s1[state[8] as usize];
    state[9] = inv_s2[state[9] as usize];
    state[10] = ARIA_S1[state[10] as usize];
    state[11] = ARIA_S2[state[11] as usize];
    state[12] = inv_s1[state[12] as usize];
    state[13] = inv_s2[state[13] as usize];
    state[14] = ARIA_S1[state[14] as usize];
    state[15] = ARIA_S2[state[15] as usize];
}

/// Applies ARIA diffusion layer matrix multiplication.
///
/// # Arguments
///
/// * `state` — `&mut [u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn diffusion_layer(state: &mut [u8; 16]) {
    let mut temp = [0_u8; 16];
    temp[0] = state[3] ^ state[4] ^ state[6] ^ state[8] ^ state[9] ^ state[13] ^ state[14];
    temp[1] = state[2] ^ state[5] ^ state[7] ^ state[8] ^ state[9] ^ state[12] ^ state[15];
    temp[2] = state[1] ^ state[4] ^ state[6] ^ state[10] ^ state[11] ^ state[12] ^ state[15];
    temp[3] = state[0] ^ state[5] ^ state[7] ^ state[10] ^ state[11] ^ state[13] ^ state[14];
    temp[4] = state[0] ^ state[2] ^ state[5] ^ state[8] ^ state[11] ^ state[14] ^ state[15];
    temp[5] = state[1] ^ state[3] ^ state[4] ^ state[9] ^ state[10] ^ state[14] ^ state[15];
    temp[6] = state[0] ^ state[2] ^ state[7] ^ state[9] ^ state[10] ^ state[12] ^ state[13];
    temp[7] = state[1] ^ state[3] ^ state[6] ^ state[8] ^ state[11] ^ state[12] ^ state[13];
    temp[8] = state[0] ^ state[1] ^ state[4] ^ state[7] ^ state[10] ^ state[13] ^ state[15];
    temp[9] = state[0] ^ state[1] ^ state[5] ^ state[6] ^ state[11] ^ state[12] ^ state[14];
    temp[10] = state[2] ^ state[3] ^ state[5] ^ state[6] ^ state[8] ^ state[13] ^ state[15];
    temp[11] = state[2] ^ state[3] ^ state[4] ^ state[7] ^ state[9] ^ state[12] ^ state[14];
    temp[12] = state[1] ^ state[2] ^ state[6] ^ state[7] ^ state[9] ^ state[11] ^ state[12];
    temp[13] = state[0] ^ state[3] ^ state[6] ^ state[7] ^ state[8] ^ state[10] ^ state[13];
    temp[14] = state[0] ^ state[3] ^ state[4] ^ state[5] ^ state[9] ^ state[11] ^ state[14];
    temp[15] = state[1] ^ state[2] ^ state[4] ^ state[5] ^ state[8] ^ state[10] ^ state[15];
    *state = temp;
}

/// Builds inverse S-box tables from forward S-box constants.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `([u8` produced by `inverse_sboxes` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn inverse_sboxes() -> ([u8; 256], [u8; 256]) {
    let mut inv_s1 = [0_u8; 256];
    let mut inv_s2 = [0_u8; 256];
    for (idx, val) in ARIA_S1.iter().enumerate() {
        inv_s1[*val as usize] = idx as u8;
    }
    for (idx, val) in ARIA_S2.iter().enumerate() {
        inv_s2[*val as usize] = idx as u8;
    }
    (inv_s1, inv_s2)
}

/// XORs two 128-bit blocks.
///
/// # Arguments
///
/// * `a` — `&[u8; 16]`.
/// * `b` — `&[u8; 16]`.
///
/// # Returns
///
/// `[u8` produced by `xor_block` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0_u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// XORs `rhs` into `lhs` block in place.
///
/// # Arguments
///
/// * `lhs` — `&mut [u8; 16]`.
/// * `rhs` — `&[u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn xor_block_in_place(lhs: &mut [u8; 16], rhs: &[u8; 16]) {
    for i in 0..16 {
        lhs[i] ^= rhs[i];
    }
}

/// Shifts CFB register left by segment length and appends segment bytes.
///
/// # Arguments
///
/// * `reg` — `&mut [u8; 16]`.
/// * `segment` — `&[u8]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn shift_register_append(reg: &mut [u8; 16], segment: &[u8]) {
    debug_assert!(segment.len() <= 16);
    if segment.len() == 16 {
        reg.copy_from_slice(segment);
        return;
    }
    let keep = 16 - segment.len();
    reg.copy_within(segment.len().., 0);
    reg[keep..].copy_from_slice(segment);
}

/// Rotates a 128-bit block right by `bits`.
///
/// # Arguments
///
/// * `input` — `&[u8; 16]`.
/// * `out` — `&mut [u8; 16]`.
/// * `bits` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn rotate_right_128(input: &[u8; 16], out: &mut [u8; 16], bits: usize) {
    let b = bits & 127;
    if b == 0 {
        *out = *input;
        return;
    }
    let hi = u64::from_be_bytes(input[..8].try_into().expect("slice is 8 bytes"));
    let lo = u64::from_be_bytes(input[8..].try_into().expect("slice is 8 bytes"));
    let (new_hi, new_lo) = if b < 64 {
        ((hi >> b) | (lo << (64 - b)), (lo >> b) | (hi << (64 - b)))
    } else if b == 64 {
        (lo, hi)
    } else {
        let s = b - 64;
        ((lo >> s) | (hi << (64 - s)), (hi >> s) | (lo << (64 - s)))
    };
    out[..8].copy_from_slice(&new_hi.to_be_bytes());
    out[8..].copy_from_slice(&new_lo.to_be_bytes());
}

/// Rotates a 128-bit block left by `bits`.
///
/// # Arguments
///
/// * `input` — `&[u8; 16]`.
/// * `out` — `&mut [u8; 16]`.
/// * `bits` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn rotate_left_128(input: &[u8; 16], out: &mut [u8; 16], bits: usize) {
    rotate_right_128(input, out, 128 - (bits & 127));
}

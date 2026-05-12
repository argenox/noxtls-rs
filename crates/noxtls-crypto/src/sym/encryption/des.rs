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

/// Holds DES 16-round subkeys for block encryption and decryption.
#[derive(Debug, Clone)]
pub struct DesCipher {
    subkeys: [u64; 16],
}

impl DesCipher {
    /// Constructs DES key schedule from an 8-byte key (including parity bits).
    ///
    /// # Arguments
    /// * `key`: 8-byte DES key including parity bits.
    ///
    /// # Returns
    /// Initialized `DesCipher` with derived round subkeys.
    pub fn new(key: &[u8; 8]) -> Result<Self> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidLength("des key must not be all zeros"));
        }
        let mut subkeys = [0_u64; 16];
        let key_u64 = u64::from_be_bytes(*key);
        let permuted = permute(key_u64, &PC1, 64);
        let mut c = ((permuted >> 28) & 0x0FFF_FFFF) as u32;
        let mut d = (permuted & 0x0FFF_FFFF) as u32;
        for (i, shift) in SHIFTS.iter().enumerate() {
            c = rotate_left_28(c, *shift);
            d = rotate_left_28(d, *shift);
            let cd = (u64::from(c) << 28) | u64::from(d);
            subkeys[i] = permute(cd, &PC2, 56);
        }
        Ok(Self { subkeys })
    }

    /// Encrypts one 8-byte block using DES Feistel rounds.
    ///
    /// # Arguments
    /// * `block`: Mutable 8-byte block to encrypt in place.
    pub fn encrypt_block(&self, block: &mut [u8; 8]) -> Result<()> {
        let data = u64::from_be_bytes(*block);
        let out = crypt_block(data, &self.subkeys, false);
        *block = out.to_be_bytes();
        Ok(())
    }

    /// Decrypts one 8-byte block using DES Feistel rounds.
    ///
    /// # Arguments
    /// * `block`: Mutable 8-byte block to decrypt in place.
    pub fn decrypt_block(&self, block: &mut [u8; 8]) -> Result<()> {
        let data = u64::from_be_bytes(*block);
        let out = crypt_block(data, &self.subkeys, true);
        *block = out.to_be_bytes();
        Ok(())
    }
}

/// Encrypts DES-ECB over full 8-byte blocks.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `input`: Block-aligned plaintext bytes.
///
/// # Returns
/// ECB ciphertext bytes with same length as `input`.
pub fn des_ecb_encrypt(cipher: &DesCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(8) {
        return Err(Error::InvalidLength("des ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(8) {
        let mut block = [0_u8; 8];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Decrypts DES-ECB over full 8-byte blocks.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `input`: Block-aligned ciphertext bytes.
///
/// # Returns
/// ECB plaintext bytes with same length as `input`.
pub fn des_ecb_decrypt(cipher: &DesCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(8) {
        return Err(Error::InvalidLength("des ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(8) {
        let mut block = [0_u8; 8];
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Encrypts DES-CBC over full 8-byte blocks with caller-supplied IV.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector.
/// * `input`: Block-aligned plaintext bytes.
///
/// # Returns
/// CBC ciphertext bytes with same length as `input`.
pub fn des_cbc_encrypt(cipher: &DesCipher, iv: &[u8; 8], input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(8) {
        return Err(Error::InvalidLength("des cbc input must be block-aligned"));
    }
    let mut out = input.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(8) {
        for (idx, byte) in chunk.iter_mut().enumerate() {
            *byte ^= prev[idx];
        }
        let mut block = [0_u8; 8];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block)?;
        chunk.copy_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

/// Decrypts DES-CBC over full 8-byte blocks with caller-supplied IV.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector.
/// * `input`: Block-aligned ciphertext bytes.
///
/// # Returns
/// CBC plaintext bytes with same length as `input`.
pub fn des_cbc_decrypt(cipher: &DesCipher, iv: &[u8; 8], input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(8) {
        return Err(Error::InvalidLength("des cbc input must be block-aligned"));
    }
    let mut out = input.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(8) {
        let mut cur = [0_u8; 8];
        cur.copy_from_slice(chunk);
        let mut block = cur;
        cipher.decrypt_block(&mut block)?;
        for idx in 0..8 {
            block[idx] ^= prev[idx];
        }
        chunk.copy_from_slice(&block);
        prev = cur;
    }
    Ok(out)
}

/// Applies DES-CTR transformation using an 8-byte initial counter block.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `nonce_counter`: Initial 8-byte counter block.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes (encryption/decryption are identical in CTR).
pub fn des_ctr_apply(cipher: &DesCipher, nonce_counter: &[u8; 8], input: &[u8]) -> Vec<u8> {
    des_ctr_encrypt(cipher, nonce_counter, input)
}

/// Encrypts bytes with DES-CTR using an 8-byte initial counter block.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `nonce_counter`: Initial 8-byte counter block.
/// * `plaintext`: Plaintext bytes to encrypt.
///
/// # Returns
/// Ciphertext bytes with same length as `plaintext`.
pub fn des_ctr_encrypt(cipher: &DesCipher, nonce_counter: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    des_ctr_process(cipher, nonce_counter, plaintext)
}

/// Decrypts bytes with DES-CTR using an 8-byte initial counter block.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `nonce_counter`: Initial 8-byte counter block.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Plaintext bytes with same length as `ciphertext`.
pub fn des_ctr_decrypt(cipher: &DesCipher, nonce_counter: &[u8; 8], ciphertext: &[u8]) -> Vec<u8> {
    des_ctr_process(cipher, nonce_counter, ciphertext)
}

/// Applies CTR keystream XOR (same operation for encrypt/decrypt).
///
/// # Arguments
///
/// * `cipher` — `&DesCipher`.
/// * `nonce_counter` — `&[u8; 8]`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `des_ctr_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn des_ctr_process(cipher: &DesCipher, nonce_counter: &[u8; 8], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut counter = *nonce_counter;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = counter;
        cipher
            .encrypt_block(&mut stream)
            .expect("des block encryption should not fail");
        let chunk_len = (input.len() - offset).min(8);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        increment_be_64(&mut counter);
        offset += chunk_len;
    }
    out
}

/// Applies DES-CFB-64 transformation with an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes for CFB mode.
pub fn des_cfb_apply(cipher: &DesCipher, iv: &[u8; 8], input: &[u8]) -> Vec<u8> {
    des_cfb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with DES-CFB-64 using an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `plaintext`: Plaintext bytes to encrypt.
///
/// # Returns
/// Ciphertext bytes with same length as `plaintext`.
pub fn des_cfb_encrypt(cipher: &DesCipher, iv: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    des_cfb_process(cipher, iv, plaintext, true)
}

/// Decrypts bytes with DES-CFB-64 using an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Plaintext bytes with same length as `ciphertext`.
pub fn des_cfb_decrypt(cipher: &DesCipher, iv: &[u8; 8], ciphertext: &[u8]) -> Vec<u8> {
    des_cfb_process(cipher, iv, ciphertext, false)
}

/// Applies CFB keystream XOR with direction-specific register updates.
///
/// # Arguments
///
/// * `cipher` — `&DesCipher`.
/// * `iv` — `&[u8; 8]`.
/// * `input` — `&[u8]`.
/// * `encrypt` — `bool`.
///
/// # Returns
///
/// `Vec<u8>` produced by `des_cfb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn des_cfb_process(cipher: &DesCipher, iv: &[u8; 8], input: &[u8], encrypt: bool) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut reg = *iv;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = reg;
        cipher
            .encrypt_block(&mut stream)
            .expect("des block encryption should not fail");
        let chunk_len = (input.len() - offset).min(8);
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

/// Applies DES-OFB transformation with an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes for OFB mode.
pub fn des_ofb_apply(cipher: &DesCipher, iv: &[u8; 8], input: &[u8]) -> Vec<u8> {
    des_ofb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with DES-OFB using an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `plaintext`: Plaintext bytes to encrypt.
///
/// # Returns
/// Ciphertext bytes with same length as `plaintext`.
pub fn des_ofb_encrypt(cipher: &DesCipher, iv: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    des_ofb_process(cipher, iv, plaintext)
}

/// Decrypts bytes with DES-OFB using an 8-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured DES cipher instance.
/// * `iv`: 8-byte initialization vector/register.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Plaintext bytes with same length as `ciphertext`.
pub fn des_ofb_decrypt(cipher: &DesCipher, iv: &[u8; 8], ciphertext: &[u8]) -> Vec<u8> {
    des_ofb_process(cipher, iv, ciphertext)
}

/// Applies OFB keystream XOR (same operation for encrypt/decrypt).
///
/// # Arguments
///
/// * `cipher` — `&DesCipher`.
/// * `iv` — `&[u8; 8]`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `des_ofb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn des_ofb_process(cipher: &DesCipher, iv: &[u8; 8], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut stream = *iv;
    let mut offset = 0;
    while offset < input.len() {
        cipher
            .encrypt_block(&mut stream)
            .expect("des block encryption should not fail");
        let chunk_len = (input.len() - offset).min(8);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        offset += chunk_len;
    }
    out
}

/// Runs DES block encryption/decryption with subkeys in selected order.
///
/// # Arguments
///
/// * `data` — `u64`.
/// * `subkeys` — `&[u64; 16]`.
/// * `decrypt` — `bool`.
///
/// # Returns
///
/// `u64` produced by `crypt_block` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn crypt_block(data: u64, subkeys: &[u64; 16], decrypt: bool) -> u64 {
    let permuted = permute(data, &IP, 64);
    let mut l = ((permuted >> 32) & 0xFFFF_FFFF) as u32;
    let mut r = (permuted & 0xFFFF_FFFF) as u32;
    for round in 0..16 {
        let key_idx = if decrypt { 15 - round } else { round };
        let new_l = r;
        let f = feistel(r, subkeys[key_idx]);
        r = l ^ f;
        l = new_l;
    }
    let pre_output = (u64::from(r) << 32) | u64::from(l);
    permute(pre_output, &FP, 64)
}

/// Applies DES Feistel F-function: expansion, XOR, S-box substitution, permutation.
///
/// # Arguments
///
/// * `r` — `u32`.
/// * `subkey` — `u64`.
///
/// # Returns
///
/// `u32` produced by `feistel` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn feistel(r: u32, subkey: u64) -> u32 {
    let expanded = permute(u64::from(r), &E, 32);
    let mixed = expanded ^ subkey;
    let mut sbox_out = 0_u32;
    for (i, sbox) in SBOXES.iter().enumerate() {
        let shift = 42 - (i * 6);
        let chunk = ((mixed >> shift) & 0x3f) as u8;
        let row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        let col = (chunk >> 1) & 0x0f;
        let val = sbox[usize::from(row)][usize::from(col)];
        sbox_out = (sbox_out << 4) | u32::from(val);
    }
    permute(u64::from(sbox_out), &P, 32) as u32
}

/// Applies bit-permutation table where entries are 1-indexed from MSB.
///
/// # Arguments
///
/// * `input` — `u64`.
/// * `table` — `&[u8]`.
/// * `input_bits` — `u8`.
///
/// # Returns
///
/// `u64` produced by `permute` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn permute(input: u64, table: &[u8], input_bits: u8) -> u64 {
    let mut out = 0_u64;
    for &pos in table {
        out <<= 1;
        let shift = usize::from(input_bits - pos);
        out |= (input >> shift) & 1;
    }
    out
}

/// Rotates 28-bit key half left by round-defined amount.
///
/// # Arguments
///
/// * `value` — `u32`.
/// * `shift` — `u8`.
///
/// # Returns
///
/// `u32` produced by `rotate_left_28` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn rotate_left_28(value: u32, shift: u8) -> u32 {
    let mask = 0x0FFF_FFFF;
    ((value << shift) | (value >> (28 - u32::from(shift)))) & mask
}

/// Increments an 8-byte big-endian counter in place.
///
/// # Arguments
///
/// * `counter` — `&mut [u8; 8]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn increment_be_64(counter: &mut [u8; 8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Shifts CFB register left by segment length and appends segment bytes.
///
/// # Arguments
///
/// * `reg` — `&mut [u8; 8]`.
/// * `segment` — `&[u8]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn shift_register_append(reg: &mut [u8; 8], segment: &[u8]) {
    debug_assert!(segment.len() <= 8);
    if segment.len() == 8 {
        reg.copy_from_slice(segment);
        return;
    }
    let keep = 8 - segment.len();
    reg.copy_within(segment.len().., 0);
    reg[keep..].copy_from_slice(segment);
}

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SBOXES: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

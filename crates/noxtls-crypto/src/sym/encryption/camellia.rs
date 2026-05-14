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

const CAMELLIA_SBOX1: [u8; 256] = [
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e,
];

const SIGMA1: u64 = 0xA09E_667F_3BCC_908B;
const SIGMA2: u64 = 0xB67A_E858_4CAA_73B2;
const SIGMA3: u64 = 0xC6EF_372F_E94F_82BE;
const SIGMA4: u64 = 0x54FF_53A5_F1D3_6F1C;
const SIGMA5: u64 = 0x10E5_27FA_DE68_2D1D;
const SIGMA6: u64 = 0xB056_88C2_B3E6_C1FD;

/// Implements Camellia block cipher key schedule and block operations.
#[derive(Debug, Clone)]
pub struct CamelliaCipher {
    key_type: CamelliaType,
    kw: [u64; 4],
    ke: [u64; 6],
    k: [u64; 24],
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CamelliaType {
    Bits128,
    Bits192,
    Bits256,
}

impl CamelliaCipher {
    /// Constructs Camellia key schedule for 128/192/256-bit keys.
    ///
    /// # Arguments
    /// * `key`: Camellia key bytes (16, 24, or 32 bytes).
    ///
    /// # Returns
    /// Initialized `CamelliaCipher` with round-key material.
    pub fn noxtls_new(key: &[u8]) -> Result<Self> {
        let key_type = match key.len() {
            16 => CamelliaType::Bits128,
            24 => CamelliaType::Bits192,
            32 => CamelliaType::Bits256,
            _ => {
                return Err(Error::InvalidLength(
                    "camellia key length must be 16, 24, or 32 bytes",
                ));
            }
        };

        let kl_hi = load_u64_be(&key[..8]);
        let kl_lo = load_u64_be(&key[8..16]);
        let (kr_hi, kr_lo) = match key_type {
            CamelliaType::Bits128 => (0, 0),
            CamelliaType::Bits192 => {
                let hi = load_u64_be(&key[16..24]);
                (hi, !hi)
            }
            CamelliaType::Bits256 => (load_u64_be(&key[16..24]), load_u64_be(&key[24..32])),
        };

        let mut d1 = kl_hi ^ kr_hi;
        let mut d2 = kl_lo ^ kr_lo;
        d2 ^= f64(d1, SIGMA1);
        d1 ^= f64(d2, SIGMA2);
        d1 ^= kl_hi;
        d2 ^= kl_lo;
        d2 ^= f64(d1, SIGMA3);
        d1 ^= f64(d2, SIGMA4);
        let ka_hi = d1;
        let ka_lo = d2;

        let (kb_hi, kb_lo) = if key_type == CamelliaType::Bits128 {
            (0, 0)
        } else {
            let mut bd1 = ka_hi ^ kr_hi;
            let mut bd2 = ka_lo ^ kr_lo;
            bd2 ^= f64(bd1, SIGMA5);
            bd1 ^= f64(bd2, SIGMA6);
            (bd1, bd2)
        };

        let mut kw = [0_u64; 4];
        let mut ke = [0_u64; 6];
        let mut k = [0_u64; 24];

        if key_type == CamelliaType::Bits128 {
            (kw[0], kw[1]) = rotl128(kl_hi, kl_lo, 0);
            (k[0], k[1]) = rotl128(ka_hi, ka_lo, 0);
            (k[2], k[3]) = rotl128(kl_hi, kl_lo, 15);
            (k[4], k[5]) = rotl128(ka_hi, ka_lo, 15);
            (ke[0], ke[1]) = rotl128(ka_hi, ka_lo, 30);
            (k[6], k[7]) = rotl128(kl_hi, kl_lo, 45);
            (k[8], _) = rotl128(ka_hi, ka_lo, 45);
            (_, k[9]) = rotl128(kl_hi, kl_lo, 60);
            (k[10], k[11]) = rotl128(ka_hi, ka_lo, 60);
            (ke[2], ke[3]) = rotl128(kl_hi, kl_lo, 77);
            (k[12], k[13]) = rotl128(kl_hi, kl_lo, 94);
            (k[14], k[15]) = rotl128(ka_hi, ka_lo, 94);
            (k[16], k[17]) = rotl128(kl_hi, kl_lo, 111);
            (kw[2], kw[3]) = rotl128(ka_hi, ka_lo, 111);
        } else {
            (kw[0], kw[1]) = rotl128(kl_hi, kl_lo, 0);
            (k[0], k[1]) = rotl128(kb_hi, kb_lo, 0);
            (k[2], k[3]) = rotl128(kr_hi, kr_lo, 15);
            (k[4], k[5]) = rotl128(ka_hi, ka_lo, 15);
            (ke[0], ke[1]) = rotl128(kr_hi, kr_lo, 30);
            (k[6], k[7]) = rotl128(kb_hi, kb_lo, 30);
            (k[8], k[9]) = rotl128(kl_hi, kl_lo, 45);
            (k[10], k[11]) = rotl128(ka_hi, ka_lo, 45);
            (ke[2], ke[3]) = rotl128(kl_hi, kl_lo, 60);
            (k[12], k[13]) = rotl128(kr_hi, kr_lo, 60);
            (k[14], k[15]) = rotl128(kb_hi, kb_lo, 60);
            (k[16], k[17]) = rotl128(kl_hi, kl_lo, 77);
            (ke[4], ke[5]) = rotl128(ka_hi, ka_lo, 77);
            (k[18], k[19]) = rotl128(kr_hi, kr_lo, 94);
            (k[20], k[21]) = rotl128(ka_hi, ka_lo, 94);
            (k[22], k[23]) = rotl128(kl_hi, kl_lo, 111);
            (kw[2], kw[3]) = rotl128(kb_hi, kb_lo, 111);
        }

        Ok(Self {
            key_type,
            kw,
            ke,
            k,
        })
    }

    /// Encrypts one 16-byte Camellia block in place.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to encrypt in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) -> Result<()> {
        let (mut d1, mut d2) = load_block_be(block);
        d1 ^= self.kw[0];
        d2 ^= self.kw[1];

        if self.key_type == CamelliaType::Bits128 {
            d2 ^= f64(d1, self.k[0]);
            d1 ^= f64(d2, self.k[1]);
            d2 ^= f64(d1, self.k[2]);
            d1 ^= f64(d2, self.k[3]);
            d2 ^= f64(d1, self.k[4]);
            d1 ^= f64(d2, self.k[5]);
            d1 = fl(d1, self.ke[0]);
            d2 = flinv(d2, self.ke[1]);
            d2 ^= f64(d1, self.k[6]);
            d1 ^= f64(d2, self.k[7]);
            d2 ^= f64(d1, self.k[8]);
            d1 ^= f64(d2, self.k[9]);
            d2 ^= f64(d1, self.k[10]);
            d1 ^= f64(d2, self.k[11]);
            d1 = fl(d1, self.ke[2]);
            d2 = flinv(d2, self.ke[3]);
            d2 ^= f64(d1, self.k[12]);
            d1 ^= f64(d2, self.k[13]);
            d2 ^= f64(d1, self.k[14]);
            d1 ^= f64(d2, self.k[15]);
            d2 ^= f64(d1, self.k[16]);
            d1 ^= f64(d2, self.k[17]);
        } else {
            d2 ^= f64(d1, self.k[0]);
            d1 ^= f64(d2, self.k[1]);
            d2 ^= f64(d1, self.k[2]);
            d1 ^= f64(d2, self.k[3]);
            d2 ^= f64(d1, self.k[4]);
            d1 ^= f64(d2, self.k[5]);
            d1 = fl(d1, self.ke[0]);
            d2 = flinv(d2, self.ke[1]);
            d2 ^= f64(d1, self.k[6]);
            d1 ^= f64(d2, self.k[7]);
            d2 ^= f64(d1, self.k[8]);
            d1 ^= f64(d2, self.k[9]);
            d2 ^= f64(d1, self.k[10]);
            d1 ^= f64(d2, self.k[11]);
            d1 = fl(d1, self.ke[2]);
            d2 = flinv(d2, self.ke[3]);
            d2 ^= f64(d1, self.k[12]);
            d1 ^= f64(d2, self.k[13]);
            d2 ^= f64(d1, self.k[14]);
            d1 ^= f64(d2, self.k[15]);
            d2 ^= f64(d1, self.k[16]);
            d1 ^= f64(d2, self.k[17]);
            d1 = fl(d1, self.ke[4]);
            d2 = flinv(d2, self.ke[5]);
            d2 ^= f64(d1, self.k[18]);
            d1 ^= f64(d2, self.k[19]);
            d2 ^= f64(d1, self.k[20]);
            d1 ^= f64(d2, self.k[21]);
            d2 ^= f64(d1, self.k[22]);
            d1 ^= f64(d2, self.k[23]);
        }

        d2 ^= self.kw[2];
        d1 ^= self.kw[3];
        store_block_be(block, d1, d2);
        Ok(())
    }

    /// Decrypts one 16-byte Camellia block in place.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to decrypt in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) -> Result<()> {
        let mut kw_dec = [0_u64; 4];
        kw_dec[0] = self.kw[2];
        kw_dec[1] = self.kw[3];
        kw_dec[2] = self.kw[0];
        kw_dec[3] = self.kw[1];

        let mut ke_dec = [0_u64; 6];
        let mut k_dec = [0_u64; 24];

        if self.key_type == CamelliaType::Bits128 {
            ke_dec[0] = self.ke[3];
            ke_dec[1] = self.ke[2];
            ke_dec[2] = self.ke[1];
            ke_dec[3] = self.ke[0];
            for (i, item) in k_dec.iter_mut().enumerate().take(18) {
                *item = self.k[17 - i];
            }
        } else {
            ke_dec[0] = self.ke[5];
            ke_dec[1] = self.ke[4];
            ke_dec[2] = self.ke[3];
            ke_dec[3] = self.ke[2];
            ke_dec[4] = self.ke[1];
            ke_dec[5] = self.ke[0];
            for (i, item) in k_dec.iter_mut().enumerate().take(24) {
                *item = self.k[23 - i];
            }
        }

        let (mut d1, mut d2) = load_block_be(block);
        d1 ^= kw_dec[0];
        d2 ^= kw_dec[1];

        if self.key_type == CamelliaType::Bits128 {
            d2 ^= f64(d1, k_dec[0]);
            d1 ^= f64(d2, k_dec[1]);
            d2 ^= f64(d1, k_dec[2]);
            d1 ^= f64(d2, k_dec[3]);
            d2 ^= f64(d1, k_dec[4]);
            d1 ^= f64(d2, k_dec[5]);
            d1 = fl(d1, ke_dec[0]);
            d2 = flinv(d2, ke_dec[1]);
            d2 ^= f64(d1, k_dec[6]);
            d1 ^= f64(d2, k_dec[7]);
            d2 ^= f64(d1, k_dec[8]);
            d1 ^= f64(d2, k_dec[9]);
            d2 ^= f64(d1, k_dec[10]);
            d1 ^= f64(d2, k_dec[11]);
            d1 = fl(d1, ke_dec[2]);
            d2 = flinv(d2, ke_dec[3]);
            d2 ^= f64(d1, k_dec[12]);
            d1 ^= f64(d2, k_dec[13]);
            d2 ^= f64(d1, k_dec[14]);
            d1 ^= f64(d2, k_dec[15]);
            d2 ^= f64(d1, k_dec[16]);
            d1 ^= f64(d2, k_dec[17]);
        } else {
            d2 ^= f64(d1, k_dec[0]);
            d1 ^= f64(d2, k_dec[1]);
            d2 ^= f64(d1, k_dec[2]);
            d1 ^= f64(d2, k_dec[3]);
            d2 ^= f64(d1, k_dec[4]);
            d1 ^= f64(d2, k_dec[5]);
            d1 = fl(d1, ke_dec[0]);
            d2 = flinv(d2, ke_dec[1]);
            d2 ^= f64(d1, k_dec[6]);
            d1 ^= f64(d2, k_dec[7]);
            d2 ^= f64(d1, k_dec[8]);
            d1 ^= f64(d2, k_dec[9]);
            d2 ^= f64(d1, k_dec[10]);
            d1 ^= f64(d2, k_dec[11]);
            d1 = fl(d1, ke_dec[2]);
            d2 = flinv(d2, ke_dec[3]);
            d2 ^= f64(d1, k_dec[12]);
            d1 ^= f64(d2, k_dec[13]);
            d2 ^= f64(d1, k_dec[14]);
            d1 ^= f64(d2, k_dec[15]);
            d2 ^= f64(d1, k_dec[16]);
            d1 ^= f64(d2, k_dec[17]);
            d1 = fl(d1, ke_dec[4]);
            d2 = flinv(d2, ke_dec[5]);
            d2 ^= f64(d1, k_dec[18]);
            d1 ^= f64(d2, k_dec[19]);
            d2 ^= f64(d1, k_dec[20]);
            d1 ^= f64(d2, k_dec[21]);
            d2 ^= f64(d1, k_dec[22]);
            d1 ^= f64(d2, k_dec[23]);
        }

        d2 ^= kw_dec[2];
        d1 ^= kw_dec[3];
        store_block_be(block, d1, d2);
        Ok(())
    }
}

/// Encrypts Camellia-ECB over full blocks; input length must be multiple of 16.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_camellia_ecb_encrypt(cipher: &CamelliaCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength(
            "camellia ecb input must be block-aligned",
        ));
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

/// Decrypts Camellia-ECB over full blocks; input length must be multiple of 16.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_camellia_ecb_decrypt(cipher: &CamelliaCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength(
            "camellia ecb input must be block-aligned",
        ));
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

/// Encrypts Camellia-CBC with a 16-byte IV and block-aligned plaintext.
pub fn noxtls_camellia_cbc_encrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength(
            "camellia cbc input must be block-aligned",
        ));
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

/// Decrypts Camellia-CBC with a 16-byte IV and block-aligned ciphertext.
pub fn noxtls_camellia_cbc_decrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength(
            "camellia cbc input must be block-aligned",
        ));
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

/// Applies Camellia-CTR transformation using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_camellia_ctr_apply(
    cipher: &CamelliaCipher,
    nonce_counter: &[u8; 16],
    input: &[u8],
) -> Vec<u8> {
    noxtls_camellia_ctr_encrypt(cipher, nonce_counter, input)
}

/// Encrypts bytes with Camellia-CTR using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_camellia_ctr_encrypt(
    cipher: &CamelliaCipher,
    nonce_counter: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    camellia_ctr_process(cipher, nonce_counter, plaintext)
}

/// Decrypts bytes with Camellia-CTR using a 16-byte initial counter block.
#[must_use]
pub fn noxtls_camellia_ctr_decrypt(
    cipher: &CamelliaCipher,
    nonce_counter: &[u8; 16],
    ciphertext: &[u8],
) -> Vec<u8> {
    camellia_ctr_process(cipher, nonce_counter, ciphertext)
}

/// Applies Camellia-CTR keystream XOR (encrypt and decrypt share this path).
///
/// # Arguments
///
/// * `cipher` — Camellia instance used to derive successive keystream blocks.
/// * `nonce_counter` — 16-byte initial counter block advanced big-endian per RFC.
/// * `input` — Data to XOR with the keystream.
///
/// # Returns
///
/// Output buffer matching `input` length.
///
/// # Panics
///
/// Panics only if an internal block encrypt call fails (should not occur for valid `cipher`).
fn camellia_ctr_process(
    cipher: &CamelliaCipher,
    nonce_counter: &[u8; 16],
    input: &[u8],
) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut counter = *nonce_counter;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = counter;
        cipher
            .encrypt_block(&mut stream)
            .expect("camellia block encryption should not fail");
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        increment_be(&mut counter);
        offset += chunk_len;
    }
    out
}

/// Applies Camellia-CFB-128 transformation with a 16-byte IV.
#[must_use]
pub fn noxtls_camellia_cfb_apply(cipher: &CamelliaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    noxtls_camellia_cfb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with Camellia-CFB-128 using a 16-byte IV/register.
#[must_use]
pub fn noxtls_camellia_cfb_encrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    camellia_cfb_process(cipher, iv, plaintext, true)
}

/// Decrypts bytes with Camellia-CFB-128 using a 16-byte IV/register.
#[must_use]
pub fn noxtls_camellia_cfb_decrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Vec<u8> {
    camellia_cfb_process(cipher, iv, ciphertext, false)
}

/// Applies Camellia-CFB-128 keystream XOR with encrypt/decrypt-specific shift-register updates.
///
/// # Arguments
///
/// * `cipher` — Camellia instance for generating keystream blocks.
/// * `iv` — 16-byte IV/register state.
/// * `input` — Plaintext for encrypt (`encrypt == true`) or ciphertext for decrypt.
/// * `encrypt` — Selects which segment is fed back into the CFB register.
///
/// # Returns
///
/// Transformed bytes matching `input` length.
///
/// # Panics
///
/// Panics only if an internal block encrypt call fails (should not occur for valid `cipher`).
fn camellia_cfb_process(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    input: &[u8],
    encrypt: bool,
) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut reg = *iv;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = reg;
        cipher
            .encrypt_block(&mut stream)
            .expect("camellia block encryption should not fail");
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

/// Applies Camellia-OFB transformation with a 16-byte IV.
#[must_use]
pub fn noxtls_camellia_ofb_apply(cipher: &CamelliaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    noxtls_camellia_ofb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with Camellia-OFB using a 16-byte IV.
#[must_use]
pub fn noxtls_camellia_ofb_encrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    camellia_ofb_process(cipher, iv, plaintext)
}

/// Decrypts bytes with Camellia-OFB using a 16-byte IV.
#[must_use]
pub fn noxtls_camellia_ofb_decrypt(
    cipher: &CamelliaCipher,
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Vec<u8> {
    camellia_ofb_process(cipher, iv, ciphertext)
}

/// Applies OFB keystream XOR (same operation for encrypt/decrypt).
///
/// # Arguments
///
/// * `cipher` — `&CamelliaCipher`.
/// * `iv` — `&[u8; 16]`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `camellia_ofb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn camellia_ofb_process(cipher: &CamelliaCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut stream = *iv;
    let mut offset = 0;
    while offset < input.len() {
        cipher
            .encrypt_block(&mut stream)
            .expect("camellia block encryption should not fail");
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

/// Applies Camellia F-function to 64-bit input and subkey.
///
/// # Arguments
///
/// * `input` — `u64`.
/// * `key` — `u64`.
///
/// # Returns
///
/// `u64` produced by `f64` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn f64(input: u64, key: u64) -> u64 {
    let x = input ^ key;
    let mut t = [0_u8; 8];
    t[0] = (x >> 56) as u8;
    t[1] = (x >> 48) as u8;
    t[2] = (x >> 40) as u8;
    t[3] = (x >> 32) as u8;
    t[4] = (x >> 24) as u8;
    t[5] = (x >> 16) as u8;
    t[6] = (x >> 8) as u8;
    t[7] = x as u8;

    let s2 = |v: u8| (v << 1) | (v >> 7);
    let s3 = |v: u8| (v << 7) | (v >> 1);
    let s4 = |v: u8| CAMELLIA_SBOX1[((v << 1) | (v >> 7)) as usize];

    t[0] = CAMELLIA_SBOX1[t[0] as usize];
    t[1] = s2(CAMELLIA_SBOX1[t[1] as usize]);
    t[2] = s3(CAMELLIA_SBOX1[t[2] as usize]);
    t[3] = s4(t[3]);
    t[4] = s2(CAMELLIA_SBOX1[t[4] as usize]);
    t[5] = s3(CAMELLIA_SBOX1[t[5] as usize]);
    t[6] = s4(t[6]);
    t[7] = CAMELLIA_SBOX1[t[7] as usize];

    let y1 = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
    let y2 = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
    let y3 = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
    let y4 = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    let y5 = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
    let y6 = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
    let y7 = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
    let y8 = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

    ((y1 as u64) << 56)
        | ((y2 as u64) << 48)
        | ((y3 as u64) << 40)
        | ((y4 as u64) << 32)
        | ((y5 as u64) << 24)
        | ((y6 as u64) << 16)
        | ((y7 as u64) << 8)
        | (y8 as u64)
}

/// Applies Camellia FL function to 64-bit half-block.
///
/// # Arguments
///
/// * `input` — `u64`.
/// * `key` — `u64`.
///
/// # Returns
///
/// `u64` produced by `fl` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fl(input: u64, key: u64) -> u64 {
    let mut x1 = (input >> 32) as u32;
    let mut x2 = input as u32;
    let k1 = (key >> 32) as u32;
    let k2 = key as u32;
    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;
    ((x1 as u64) << 32) | (x2 as u64)
}

/// Applies Camellia FLINV inverse function to 64-bit half-block.
///
/// # Arguments
///
/// * `input` — `u64`.
/// * `key` — `u64`.
///
/// # Returns
///
/// `u64` produced by `flinv` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn flinv(input: u64, key: u64) -> u64 {
    let mut y1 = (input >> 32) as u32;
    let mut y2 = input as u32;
    let k1 = (key >> 32) as u32;
    let k2 = key as u32;
    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);
    ((y1 as u64) << 32) | (y2 as u64)
}

/// Rotates 128-bit value represented as (hi, lo) left by r bits.
///
/// # Arguments
///
/// * `hi` — `u64`.
/// * `lo` — `u64`.
/// * `r` — `usize`.
///
/// # Returns
///
/// `(u64, u64)` produced by `rotl128` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn rotl128(hi: u64, lo: u64, r: usize) -> (u64, u64) {
    if r == 0 {
        return (hi, lo);
    }
    if r >= 64 {
        return rotl128(lo, hi, r - 64);
    }
    ((hi << r) | (lo >> (64 - r)), (lo << r) | (hi >> (64 - r)))
}

/// Loads u64 from big-endian byte slice of length 8.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// `u64` produced by `load_u64_be` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn load_u64_be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("slice is 8 bytes"))
}

/// Loads 128-bit block into (high, low) big-endian u64 words.
///
/// # Arguments
///
/// * `block` — `&[u8; 16]`.
///
/// # Returns
///
/// `(u64, u64)` produced by `load_block_be` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn load_block_be(block: &[u8; 16]) -> (u64, u64) {
    (load_u64_be(&block[..8]), load_u64_be(&block[8..]))
}

/// Stores block with swapped halves according to Camellia final permutation.
///
/// # Arguments
///
/// * `out` — `&mut [u8; 16]`.
/// * `d1` — `u64`.
/// * `d2` — `u64`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn store_block_be(out: &mut [u8; 16], d1: u64, d2: u64) {
    out[..8].copy_from_slice(&d2.to_be_bytes());
    out[8..].copy_from_slice(&d1.to_be_bytes());
}

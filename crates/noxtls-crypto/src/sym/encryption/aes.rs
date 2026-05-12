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

/// Stores expanded AES round keys for block encryption/decryption.
#[derive(Debug, Clone)]
pub struct AesCipher {
    round_keys: Vec<[u8; 16]>,
    rounds: usize,
}

impl AesCipher {
    /// Builds an AES cipher for 128/192/256-bit keys.
    ///
    /// # Arguments
    /// * `key`: AES key bytes (16, 24, or 32 bytes).
    ///
    /// # Returns
    /// Initialized `AesCipher` with expanded round keys.
    pub fn new(key: &[u8]) -> Result<Self> {
        let (nk, rounds) = match key.len() {
            16 => (4, 10),
            24 => (6, 12),
            32 => (8, 14),
            _ => {
                return Err(Error::InvalidLength(
                    "aes key length must be 16, 24, or 32 bytes",
                ))
            }
        };
        let expanded = key_expansion(key, nk, rounds);
        Ok(Self {
            round_keys: expanded,
            rounds,
        })
    }

    /// Encrypts one 16-byte block in place using AES.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to encrypt in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0]);
        for round in 1..self.rounds {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round]);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, &self.round_keys[self.rounds]);
    }

    /// Decrypts one 16-byte block in place using AES inverse rounds.
    ///
    /// # Arguments
    /// * `block`: Mutable 16-byte block to decrypt in place.
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[self.rounds]);
        for round in (1..self.rounds).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, &self.round_keys[round]);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &self.round_keys[0]);
    }
}

/// Encrypts AES-ECB over full blocks; input length must be multiple of 16.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `input`: Block-aligned plaintext bytes.
///
/// # Returns
/// ECB ciphertext bytes with same length as `input`.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn aes_ecb_encrypt(cipher: &AesCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aes ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Decrypts AES-ECB over full blocks; input length must be multiple of 16.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `input`: Block-aligned ciphertext bytes.
///
/// # Returns
/// ECB plaintext bytes with same length as `input`.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn aes_ecb_decrypt(cipher: &AesCipher, input: &[u8]) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aes ecb input must be block-aligned"));
    }
    let mut out = input.to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    Ok(out)
}

/// Encrypts AES-CBC with a 16-byte IV and block-aligned plaintext.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector.
/// * `plaintext`: Block-aligned plaintext bytes.
///
/// # Returns
/// CBC ciphertext bytes with same length as `plaintext`.
pub fn aes_cbc_encrypt(cipher: &AesCipher, iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aes cbc input must be block-aligned"));
    }
    let mut out = plaintext.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(16) {
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= prev[i];
        }
        let mut block = [0_u8; 16];
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev = block;
    }
    Ok(out)
}

/// Decrypts AES-CBC with a 16-byte IV and block-aligned ciphertext.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector.
/// * `ciphertext`: Block-aligned ciphertext bytes.
///
/// # Returns
/// CBC plaintext bytes with same length as `ciphertext`.
pub fn aes_cbc_decrypt(cipher: &AesCipher, iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(Error::InvalidLength("aes cbc input must be block-aligned"));
    }
    let mut out = ciphertext.to_vec();
    let mut prev = *iv;
    for chunk in out.chunks_exact_mut(16) {
        let mut cur = [0_u8; 16];
        cur.copy_from_slice(chunk);
        let mut block = cur;
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        chunk.copy_from_slice(&block);
        prev = cur;
    }
    Ok(out)
}

/// Applies AES-CTR transformation using a 16-byte initial counter block.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `nonce_counter`: Initial 16-byte counter block.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes (encryption/decryption are identical in CTR).
pub fn aes_ctr_apply(cipher: &AesCipher, nonce_counter: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut counter = *nonce_counter;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = counter;
        cipher.encrypt_block(&mut stream);
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        increment_be(&mut counter);
        offset += chunk_len;
    }
    out
}

/// Applies AES-CFB-128 transformation with a 16-byte IV.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector/register.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes for CFB mode.
pub fn aes_cfb_apply(cipher: &AesCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    aes_cfb_encrypt(cipher, iv, input)
}

/// Encrypts bytes with AES-CFB-128 using a 16-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector/register.
/// * `plaintext`: Plaintext bytes to encrypt.
///
/// # Returns
/// Ciphertext bytes with same length as `plaintext`.
pub fn aes_cfb_encrypt(cipher: &AesCipher, iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    aes_cfb_process(cipher, iv, plaintext, true)
}

/// Decrypts bytes with AES-CFB-128 using a 16-byte IV/register.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector/register.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Plaintext bytes with same length as `ciphertext`.
pub fn aes_cfb_decrypt(cipher: &AesCipher, iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    aes_cfb_process(cipher, iv, ciphertext, false)
}

/// Processes AES-CFB-128 encryption/decryption while tracking register updates.
///
/// # Arguments
///
/// * `cipher` — `&AesCipher`.
/// * `iv` — `&[u8; 16]`.
/// * `input` — `&[u8]`.
/// * `encrypt` — `bool`.
///
/// # Returns
///
/// `Vec<u8>` produced by `aes_cfb_process` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn aes_cfb_process(cipher: &AesCipher, iv: &[u8; 16], input: &[u8], encrypt: bool) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut reg = *iv;
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = reg;
        cipher.encrypt_block(&mut stream);
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

/// Applies AES-OFB transformation with a 16-byte IV.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `iv`: 16-byte initialization vector.
/// * `input`: Input bytes to transform.
///
/// # Returns
/// Transformed bytes for OFB mode.
pub fn aes_ofb_apply(cipher: &AesCipher, iv: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8; input.len()];
    let mut stream = *iv;
    let mut offset = 0;
    while offset < input.len() {
        cipher.encrypt_block(&mut stream);
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        offset += chunk_len;
    }
    out
}

/// Placeholder API for AES-GCM during ongoing porting work.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `nonce`: GCM nonce bytes.
/// * `aad`: Additional authenticated data bytes.
/// * `plaintext`: Plaintext bytes to encrypt.
///
/// # Returns
/// `(ciphertext, tag)` pair with 16-byte authentication tag.
pub fn aes_gcm_encrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let h = {
        let mut zero = [0_u8; 16];
        cipher.encrypt_block(&mut zero);
        u128::from_be_bytes(zero)
    };
    let j0 = gcm_j0(h, nonce);
    let mut ctr = j0;
    inc32_u128(&mut ctr);
    let ciphertext = gcm_ctr_xor(cipher, ctr, plaintext);
    let s = ghash(h, aad, &ciphertext);
    let mut e_j0 = j0.to_be_bytes();
    cipher.encrypt_block(&mut e_j0);
    let tag = (u128::from_be_bytes(e_j0) ^ s).to_be_bytes();
    Ok((ciphertext, tag))
}

/// Decrypts and authenticates AES-GCM ciphertext/tag with associated data.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `nonce`: GCM nonce bytes.
/// * `aad`: Additional authenticated data bytes.
/// * `ciphertext`: Ciphertext bytes to decrypt.
/// * `tag`: 16-byte authentication tag to verify.
///
/// # Returns
/// Decrypted plaintext bytes when tag verification succeeds.
pub fn aes_gcm_decrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    let h = {
        let mut zero = [0_u8; 16];
        cipher.encrypt_block(&mut zero);
        u128::from_be_bytes(zero)
    };
    let j0 = gcm_j0(h, nonce);
    let mut ctr = j0;
    inc32_u128(&mut ctr);
    let s = ghash(h, aad, ciphertext);
    let mut e_j0 = j0.to_be_bytes();
    cipher.encrypt_block(&mut e_j0);
    let expected_tag = (u128::from_be_bytes(e_j0) ^ s).to_be_bytes();
    if !constant_time_tag_eq(&expected_tag, tag) {
        return Err(Error::CryptoFailure("aes-gcm authentication failed"));
    }
    Ok(gcm_ctr_xor(cipher, ctr, ciphertext))
}

/// Placeholder API for AES-CCM during ongoing porting work.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `nonce`: CCM nonce bytes (7..13 bytes).
/// * `aad`: Additional authenticated data bytes.
/// * `plaintext`: Plaintext bytes to encrypt/authenticate.
///
/// # Returns
/// `(ciphertext, tag)` pair with 16-byte authentication tag.
pub fn aes_ccm_encrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(Error::InvalidLength("aes-ccm nonce must be 7..13 bytes"));
    }
    let q = 15 - nonce.len();
    if plaintext.len() >= (1_usize << (8 * q.min(8))) {
        return Err(Error::InvalidLength(
            "aes-ccm plaintext too large for nonce",
        ));
    }
    let t_len = 16_usize;
    let mut b0 = [0_u8; 16];
    let aadata_flag = if aad.is_empty() { 0_u8 } else { 0x40 };
    let m_prime = (((t_len - 2) / 2) as u8) << 3;
    let l_prime = (q as u8) - 1;
    b0[0] = aadata_flag | m_prime | l_prime;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    encode_len_q(plaintext.len() as u64, q, &mut b0[16 - q..]);

    let mut mac_state = [0_u8; 16];
    xor_block_in_place(&mut mac_state, &b0);
    cipher.encrypt_block(&mut mac_state);

    if !aad.is_empty() {
        let mut aad_blocked = Vec::new();
        if aad.len() < 0xFF00 {
            aad_blocked.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else {
            aad_blocked.extend_from_slice(&[0xFF, 0xFE]);
            aad_blocked.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        }
        aad_blocked.extend_from_slice(aad);
        pad16(&mut aad_blocked);
        for chunk in aad_blocked.chunks_exact(16) {
            let mut blk = [0_u8; 16];
            blk.copy_from_slice(chunk);
            xor_block_in_place(&mut mac_state, &blk);
            cipher.encrypt_block(&mut mac_state);
        }
    }

    let mut payload = plaintext.to_vec();
    pad16(&mut payload);
    for chunk in payload.chunks_exact(16) {
        let mut blk = [0_u8; 16];
        blk.copy_from_slice(chunk);
        xor_block_in_place(&mut mac_state, &blk);
        cipher.encrypt_block(&mut mac_state);
    }
    let mut tag = mac_state;

    let mut ctr0 = [0_u8; 16];
    ctr0[0] = l_prime;
    ctr0[1..1 + nonce.len()].copy_from_slice(nonce);
    let mut s0 = ctr0;
    cipher.encrypt_block(&mut s0);
    for (t, s) in tag.iter_mut().zip(s0) {
        *t ^= s;
    }

    let mut ciphertext = vec![0_u8; plaintext.len()];
    let mut counter = ctr0;
    for block_idx in 0..plaintext.len().div_ceil(16) {
        increment_q_counter(&mut counter, q);
        let mut stream = counter;
        cipher.encrypt_block(&mut stream);
        let start = block_idx * 16;
        let end = (start + 16).min(plaintext.len());
        for i in start..end {
            ciphertext[i] = plaintext[i] ^ stream[i - start];
        }
    }

    Ok((ciphertext, tag))
}

/// Decrypts and authenticates AES-CCM ciphertext/tag with associated data.
///
/// # Arguments
/// * `cipher`: Configured AES cipher instance.
/// * `nonce`: CCM nonce bytes (7..13 bytes).
/// * `aad`: Additional authenticated data bytes.
/// * `ciphertext`: Ciphertext bytes to decrypt/authenticate.
/// * `tag`: 16-byte authentication tag to verify.
///
/// # Returns
/// Decrypted plaintext bytes when tag verification succeeds.
pub fn aes_ccm_decrypt(
    cipher: &AesCipher,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    if !(7..=13).contains(&nonce.len()) {
        return Err(Error::InvalidLength("aes-ccm nonce must be 7..13 bytes"));
    }
    let q = 15 - nonce.len();
    if ciphertext.len() >= (1_usize << (8 * q.min(8))) {
        return Err(Error::InvalidLength(
            "aes-ccm ciphertext too large for nonce",
        ));
    }
    let t_len = 16_usize;
    let l_prime = (q as u8) - 1;

    let mut ctr0 = [0_u8; 16];
    ctr0[0] = l_prime;
    ctr0[1..1 + nonce.len()].copy_from_slice(nonce);

    let mut plaintext = vec![0_u8; ciphertext.len()];
    let mut counter = ctr0;
    for block_idx in 0..ciphertext.len().div_ceil(16) {
        increment_q_counter(&mut counter, q);
        let mut stream = counter;
        cipher.encrypt_block(&mut stream);
        let start = block_idx * 16;
        let end = (start + 16).min(ciphertext.len());
        for i in start..end {
            plaintext[i] = ciphertext[i] ^ stream[i - start];
        }
    }

    let mut b0 = [0_u8; 16];
    let aadata_flag = if aad.is_empty() { 0_u8 } else { 0x40 };
    let m_prime = (((t_len - 2) / 2) as u8) << 3;
    b0[0] = aadata_flag | m_prime | l_prime;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    encode_len_q(plaintext.len() as u64, q, &mut b0[16 - q..]);

    let mut mac_state = [0_u8; 16];
    xor_block_in_place(&mut mac_state, &b0);
    cipher.encrypt_block(&mut mac_state);

    if !aad.is_empty() {
        let mut aad_blocked = Vec::new();
        if aad.len() < 0xFF00 {
            aad_blocked.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else {
            aad_blocked.extend_from_slice(&[0xFF, 0xFE]);
            aad_blocked.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        }
        aad_blocked.extend_from_slice(aad);
        pad16(&mut aad_blocked);
        for chunk in aad_blocked.chunks_exact(16) {
            let mut blk = [0_u8; 16];
            blk.copy_from_slice(chunk);
            xor_block_in_place(&mut mac_state, &blk);
            cipher.encrypt_block(&mut mac_state);
        }
    }

    let mut payload = plaintext.clone();
    pad16(&mut payload);
    for chunk in payload.chunks_exact(16) {
        let mut blk = [0_u8; 16];
        blk.copy_from_slice(chunk);
        xor_block_in_place(&mut mac_state, &blk);
        cipher.encrypt_block(&mut mac_state);
    }
    let mut expected_tag = mac_state;
    let mut s0 = ctr0;
    cipher.encrypt_block(&mut s0);
    for (t, s) in expected_tag.iter_mut().zip(s0) {
        *t ^= s;
    }
    if !constant_time_tag_eq(&expected_tag, tag) {
        return Err(Error::CryptoFailure("aes-ccm authentication failed"));
    }
    Ok(plaintext)
}

/// Compares fixed-size authentication tags in constant time.
///
/// # Arguments
///
/// * `expected` — `&[u8; 16]`.
/// * `received` — `&[u8; 16]`.
///
/// # Returns
///
/// `bool` produced by `constant_time_tag_eq` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn constant_time_tag_eq(expected: &[u8; 16], received: &[u8; 16]) -> bool {
    let mut diff = 0_u8;
    for (&left, &right) in expected.iter().zip(received.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Placeholder API for AES-XTS during ongoing porting work.
///
/// # Arguments
/// * `cipher_a`: Data-key AES instance.
/// * `cipher_b`: Tweak-key AES instance.
/// * `tweak`: Initial 16-byte tweak value.
/// * `plaintext`: Block-aligned plaintext bytes.
///
/// # Returns
/// XTS ciphertext bytes with same length as `plaintext`.
pub fn aes_xts_encrypt(
    cipher_a: &AesCipher,
    cipher_b: &AesCipher,
    tweak: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    aes_xts_crypt(cipher_a, cipher_b, tweak, plaintext, true)
}

/// Decrypts AES-XTS over a data unit, including ciphertext-stealing for partial trailing block.
///
/// # Arguments
/// * `cipher_a`: Data-key AES instance.
/// * `cipher_b`: Tweak-key AES instance.
/// * `tweak`: Initial 16-byte tweak value.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// XTS plaintext bytes with same length as `ciphertext`.
pub fn aes_xts_decrypt(
    cipher_a: &AesCipher,
    cipher_b: &AesCipher,
    tweak: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    aes_xts_crypt(cipher_a, cipher_b, tweak, ciphertext, false)
}

/// Applies AES-XTS encryption or decryption with ciphertext stealing for non-block-aligned inputs.
///
/// # Arguments
///
/// * `cipher_a` — Data-path AES instance.
/// * `cipher_b` — Tweak-path AES instance used to derive the initial tweak.
/// * `tweak` — 16-byte starting tweak block.
/// * `input` — Plaintext (encrypt) or ciphertext (decrypt), at least 16 bytes.
/// * `encrypt` — `true` to encrypt, `false` to decrypt.
///
/// # Returns
///
/// On success, output bytes matching `input` length.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when `input` is shorter than one block or ciphertext stealing paths fail internal checks.
///
/// # Panics
///
/// This function does not panic.
fn aes_xts_crypt(
    cipher_a: &AesCipher,
    cipher_b: &AesCipher,
    tweak: &[u8; 16],
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>> {
    if input.len() < 16 {
        return Err(Error::InvalidLength(
            "aes-xts input must be at least one full 16-byte block",
        ));
    }
    let mut out = vec![0_u8; input.len()];
    let full_blocks = input.len() / 16;
    let rem = input.len() % 16;

    let mut tw = *tweak;
    cipher_b.encrypt_block(&mut tw);

    if rem == 0 {
        for block_idx in 0..full_blocks {
            let start = block_idx * 16;
            let mut block = [0_u8; 16];
            block.copy_from_slice(&input[start..start + 16]);
            xor_block_in_place(&mut block, &tw);
            if encrypt {
                cipher_a.encrypt_block(&mut block);
            } else {
                cipher_a.decrypt_block(&mut block);
            }
            xor_block_in_place(&mut block, &tw);
            out[start..start + 16].copy_from_slice(&block);
            xts_mul_x(&mut tw);
        }
        return Ok(out);
    }

    // Process all but the final full block that participates in ciphertext stealing.
    for block_idx in 0..(full_blocks - 1) {
        let start = block_idx * 16;
        let mut block = [0_u8; 16];
        block.copy_from_slice(&input[start..start + 16]);
        xor_block_in_place(&mut block, &tw);
        if encrypt {
            cipher_a.encrypt_block(&mut block);
        } else {
            cipher_a.decrypt_block(&mut block);
        }
        xor_block_in_place(&mut block, &tw);
        out[start..start + 16].copy_from_slice(&block);
        xts_mul_x(&mut tw);
    }

    let mut tw_next = tw;
    xts_mul_x(&mut tw_next);
    let last_full_start = (full_blocks - 1) * 16;
    let partial_start = full_blocks * 16;

    if encrypt {
        let mut block = [0_u8; 16];
        block.copy_from_slice(&input[last_full_start..last_full_start + 16]);
        xor_block_in_place(&mut block, &tw);
        cipher_a.encrypt_block(&mut block);
        xor_block_in_place(&mut block, &tw);

        // C_m is first r bytes of C*.
        out[partial_start..].copy_from_slice(&block[..rem]);

        // P* = P_m || C*[r..16], then encrypted with next tweak for C_{m-1}.
        let mut p_star = [0_u8; 16];
        p_star[..rem].copy_from_slice(&input[partial_start..]);
        p_star[rem..].copy_from_slice(&block[rem..]);
        xor_block_in_place(&mut p_star, &tw_next);
        cipher_a.encrypt_block(&mut p_star);
        xor_block_in_place(&mut p_star, &tw_next);
        out[last_full_start..last_full_start + 16].copy_from_slice(&p_star);
    } else {
        let mut c_m_minus_1 = [0_u8; 16];
        c_m_minus_1.copy_from_slice(&input[last_full_start..last_full_start + 16]);
        xor_block_in_place(&mut c_m_minus_1, &tw_next);
        cipher_a.decrypt_block(&mut c_m_minus_1);
        xor_block_in_place(&mut c_m_minus_1, &tw_next);

        // P_m is the first r bytes of decrypted C_{m-1}.
        out[partial_start..].copy_from_slice(&c_m_minus_1[..rem]);

        // Reconstruct C* = C_m || tail(P*), then decrypt with current tweak for P_{m-1}.
        let mut c_star = [0_u8; 16];
        c_star[..rem].copy_from_slice(&input[partial_start..]);
        c_star[rem..].copy_from_slice(&c_m_minus_1[rem..]);
        xor_block_in_place(&mut c_star, &tw);
        cipher_a.decrypt_block(&mut c_star);
        xor_block_in_place(&mut c_star, &tw);
        out[last_full_start..last_full_start + 16].copy_from_slice(&c_star);
    }

    Ok(out)
}

/// Expands AES key material into round keys for encryption and decryption.
///
/// # Arguments
///
/// * `key` — `&[u8]`.
/// * `nk` — `usize`.
/// * `rounds` — `usize`.
///
/// # Returns
///
/// `Vec<[u8` produced by `key_expansion` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn key_expansion(key: &[u8], nk: usize, rounds: usize) -> Vec<[u8; 16]> {
    let total_words = 4 * (rounds + 1);
    let mut w = vec![0_u32; total_words];
    for (i, word) in w.iter_mut().enumerate().take(nk) {
        let idx = i * 4;
        *word = u32::from_be_bytes([key[idx], key[idx + 1], key[idx + 2], key[idx + 3]]);
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ (u32::from(RCON[i / nk - 1]) << 24);
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
    let mut keys = Vec::with_capacity(rounds + 1);
    for r in 0..=rounds {
        let mut key_block = [0_u8; 16];
        for c in 0..4 {
            key_block[c * 4..(c + 1) * 4].copy_from_slice(&w[r * 4 + c].to_be_bytes());
        }
        keys.push(key_block);
    }
    keys
}

/// Rotates one 32-bit word by one byte to the left.
///
/// # Arguments
///
/// * `word` — `u32`.
///
/// # Returns
///
/// `u32` produced by `rot_word` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Applies AES S-box substitution to each byte of a 32-bit word.
///
/// # Arguments
///
/// * `word` — `u32`.
///
/// # Returns
///
/// `u32` produced by `sub_word` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[usize::from(bytes[0])],
        SBOX[usize::from(bytes[1])],
        SBOX[usize::from(bytes[2])],
        SBOX[usize::from(bytes[3])],
    ])
}

/// XORs one round key into current state.
///
/// # Arguments
///
/// * `state` — `&mut [u8; 16]`.
/// * `round_key` — `&[u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

/// Applies forward AES S-box to every state byte.
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
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = SBOX[usize::from(*byte)];
    }
}

/// Applies inverse AES S-box to every state byte.
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
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = INV_SBOX[usize::from(*byte)];
    }
}

/// Performs AES row shifts in forward direction.
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
fn shift_rows(state: &mut [u8; 16]) {
    let mut tmp = *state;
    tmp[1] = state[5];
    tmp[5] = state[9];
    tmp[9] = state[13];
    tmp[13] = state[1];
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    tmp[3] = state[15];
    tmp[7] = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];
    *state = tmp;
}

/// Performs AES row shifts in inverse direction.
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
fn inv_shift_rows(state: &mut [u8; 16]) {
    let mut tmp = *state;
    tmp[1] = state[13];
    tmp[5] = state[1];
    tmp[9] = state[5];
    tmp[13] = state[9];
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    tmp[3] = state[7];
    tmp[7] = state[11];
    tmp[11] = state[15];
    tmp[15] = state[3];
    *state = tmp;
}

/// Mixes each AES state column using Rijndael field multiplication.
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
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

/// Inversely mixes each AES state column for decryption rounds.
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
fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        state[i + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        state[i + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        state[i + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

/// Multiplies two bytes in GF(2^8) with AES reduction polynomial.
///
/// # Arguments
///
/// * `a` — `u8`.
/// * `b` — `u8`.
///
/// # Returns
///
/// `u8` produced by `gf_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0_u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Increments a 16-byte big-endian counter block in place.
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
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// Computes GHASH over AAD and ciphertext for GCM authentication.
///
/// # Arguments
///
/// * `h` — `u128`.
/// * `aad` — `&[u8]`.
/// * `ciphertext` — `&[u8]`.
///
/// # Returns
///
/// `u128` produced by `ghash` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = 0_u128;
    let mut a = aad.to_vec();
    let mut c = ciphertext.to_vec();
    pad16(&mut a);
    pad16(&mut c);
    for chunk in a.chunks_exact(16) {
        let x = u128::from_be_bytes(chunk.try_into().expect("16-byte chunk"));
        y = gf128_mul(y ^ x, h);
    }
    for chunk in c.chunks_exact(16) {
        let x = u128::from_be_bytes(chunk.try_into().expect("16-byte chunk"));
        y = gf128_mul(y ^ x, h);
    }
    let lengths = ((aad.len() as u128) << 64) | ((ciphertext.len() as u128) * 8);
    gf128_mul(y ^ lengths, h)
}

/// Multiplies two elements in GF(2^128) with GCM reduction polynomial.
///
/// # Arguments
///
/// * `x` — `u128`.
/// * `y` — `u128`.
///
/// # Returns
///
/// `u128` produced by `gf128_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn gf128_mul(mut x: u128, mut y: u128) -> u128 {
    let mut z = 0_u128;
    for _ in 0..128 {
        if (x & (1_u128 << 127)) != 0 {
            z ^= y;
        }
        let lsb = y & 1;
        y >>= 1;
        if lsb != 0 {
            y ^= 0xe1_u128 << 120;
        }
        x <<= 1;
    }
    z
}

/// Builds J0 nonce block per GCM specification.
///
/// # Arguments
///
/// * `h` — `u128`.
/// * `nonce` — `&[u8]`.
///
/// # Returns
///
/// `u128` produced by `gcm_j0` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn gcm_j0(h: u128, nonce: &[u8]) -> u128 {
    if nonce.len() == 12 {
        let mut j = [0_u8; 16];
        j[..12].copy_from_slice(nonce);
        j[15] = 1;
        return u128::from_be_bytes(j);
    }
    let mut n = nonce.to_vec();
    pad16(&mut n);
    let mut y = 0_u128;
    for chunk in n.chunks_exact(16) {
        let x = u128::from_be_bytes(chunk.try_into().expect("16-byte chunk"));
        y = gf128_mul(y ^ x, h);
    }
    let len_block = (nonce.len() as u128) * 8;
    gf128_mul(y ^ len_block, h)
}

/// Applies GCM counter-mode keystream XOR starting from provided counter block.
///
/// # Arguments
///
/// * `cipher` — `&AesCipher`.
/// * `initial_ctr` — `u128`.
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `gcm_ctr_xor` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn gcm_ctr_xor(cipher: &AesCipher, initial_ctr: u128, input: &[u8]) -> Vec<u8> {
    let mut ctr = initial_ctr;
    let mut out = vec![0_u8; input.len()];
    let mut offset = 0;
    while offset < input.len() {
        let mut stream = ctr.to_be_bytes();
        cipher.encrypt_block(&mut stream);
        let chunk_len = (input.len() - offset).min(16);
        for i in 0..chunk_len {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        inc32_u128(&mut ctr);
        offset += chunk_len;
    }
    out
}

/// Increments low 32-bit GCM counter portion of 128-bit counter block.
///
/// # Arguments
///
/// * `counter` — `&mut u128`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn inc32_u128(counter: &mut u128) {
    let mut bytes = counter.to_be_bytes();
    inc32(&mut bytes);
    *counter = u128::from_be_bytes(bytes);
}

/// Increments low 32-bit GCM counter portion in-place.
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
fn inc32(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// Pads byte vector with zeroes to reach next multiple of 16.
///
/// # Arguments
///
/// * `data` — `&mut Vec<u8>`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn pad16(data: &mut Vec<u8>) {
    let rem = data.len() % 16;
    if rem != 0 {
        data.resize(data.len() + (16 - rem), 0);
    }
}

/// Encodes length field in CCM q-byte big-endian form.
///
/// # Arguments
///
/// * `len` — `u64`.
/// * `q` — `usize`.
/// * `out` — `&mut [u8]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_len_q(len: u64, q: usize, out: &mut [u8]) {
    for i in 0..q {
        out[q - 1 - i] = ((len >> (8 * i)) & 0xFF) as u8;
    }
}

/// Increments CCM q-byte counter region in-place.
///
/// # Arguments
///
/// * `counter` — `&mut [u8; 16]`.
/// * `q` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn increment_q_counter(counter: &mut [u8; 16], q: usize) {
    for i in (16 - q..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// XORs one 16-byte block into another in-place.
///
/// # Arguments
///
/// * `dst` — `&mut [u8; 16]`.
/// * `src` — `&[u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn xor_block_in_place(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
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

/// Multiplies XTS tweak by x over GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1.
///
/// # Arguments
///
/// * `tweak` — `&mut [u8; 16]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn xts_mul_x(tweak: &mut [u8; 16]) {
    let mut carry = 0_u8;
    for byte in tweak.iter_mut() {
        let next_carry = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

const SBOX: [u8; 256] = [
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

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

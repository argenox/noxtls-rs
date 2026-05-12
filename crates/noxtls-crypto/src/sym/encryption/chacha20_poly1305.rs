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

use super::{poly1305_key_gen, poly1305_mac_padded16, poly1305_tags_equal, ChaCha20};
use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

/// Computes how many zero bytes RFC 8439 `pad16` appends for a given input length.
///
/// # Arguments
///
/// * `x` — Length of the preceding octet string in bytes.
///
/// # Returns
///
/// Number of zero bytes to append in `0..16`.
///
/// # Panics
///
/// This function does not panic.
fn pad16_len(x: usize) -> usize {
    let rem = x % 16;
    if rem == 0 {
        0
    } else {
        16 - rem
    }
}

/// Concatenates AAD, padding, ciphertext, padding, and 64-bit length words for Poly1305.
///
/// # Arguments
///
/// * `aad` — Associated authenticated data.
/// * `ciphertext` — Ciphertext bytes (same length as plaintext for RFC 8439 AEAD).
///
/// # Returns
///
/// Contiguous buffer whose length is a multiple of 16 bytes.
///
/// # Panics
///
/// This function does not panic.
fn build_mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let pad_a = pad16_len(aad.len());
    let pad_c = pad16_len(ciphertext.len());
    let mut out = Vec::with_capacity(aad.len() + pad_a + ciphertext.len() + pad_c + 16);
    out.extend_from_slice(aad);
    out.resize(out.len() + pad_a, 0);
    out.extend_from_slice(ciphertext);
    out.resize(out.len() + pad_c, 0);
    let aad_len = aad.len() as u64;
    let ct_len = ciphertext.len() as u64;
    out.extend_from_slice(&aad_len.to_le_bytes());
    out.extend_from_slice(&ct_len.to_le_bytes());
    out
}

/// Encrypts and authenticates plaintext with ChaCha20-Poly1305 (RFC 8439).
///
/// Uses block counter 0 for the Poly1305 one-time key and counter 1.. for keystream.
/// Rejects plaintext lengths at or above the ChaCha20 block counter wrap bound (~256 GiB).
///
/// # Arguments
/// * `key`: 32-byte key.
/// * `nonce`: 12-byte nonce (must be unique per key).
/// * `aad`: Additional authenticated data.
/// * `plaintext`: Plaintext to encrypt.
///
/// # Returns
/// `(ciphertext, tag)` with a 16-byte tag.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when plaintext exceeds the RFC 8439 counter range or when ChaCha20 keystream application fails.
///
/// # Panics
///
/// This function does not panic.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    const MAX_PLAINTEXT: usize = (1_usize << 32).saturating_mul(64).saturating_sub(64);
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::InvalidLength(
            "chacha20-poly1305 plaintext exceeds RFC 8439 counter range",
        ));
    }
    let otk = poly1305_key_gen(key, nonce);
    let mut cipher = ChaCha20::new(key, nonce, 1);
    let mut ciphertext = vec![0_u8; plaintext.len()];
    cipher.apply_keystream(plaintext, &mut ciphertext)?;
    let mac_data = build_mac_data(aad, &ciphertext);
    let tag = poly1305_mac_padded16(&otk, &mac_data);
    Ok((ciphertext, tag))
}

/// Verifies the Poly1305 tag and decrypts ChaCha20-Poly1305 ciphertext (RFC 8439).
///
/// # Arguments
/// * `key`: 32-byte key.
/// * `nonce`: 12-byte nonce.
/// * `aad`: Additional authenticated data.
/// * `ciphertext`: Ciphertext bytes.
/// * `tag`: 16-byte authentication tag.
///
/// # Returns
/// Plaintext on success, or authentication failure.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when ciphertext exceeds the RFC 8439 counter range, [`Error::CryptoFailure`] when the Poly1305 tag does not verify, or errors from keystream application.
///
/// # Panics
///
/// This function does not panic.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    const MAX_CIPHERTEXT: usize = (1_usize << 32).saturating_mul(64).saturating_sub(64);
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Error::InvalidLength(
            "chacha20-poly1305 ciphertext exceeds RFC 8439 counter range",
        ));
    }
    let otk = poly1305_key_gen(key, nonce);
    let mac_data = build_mac_data(aad, ciphertext);
    let expected = poly1305_mac_padded16(&otk, &mac_data);
    if !poly1305_tags_equal(tag, &expected) {
        return Err(Error::CryptoFailure(
            "chacha20-poly1305 authentication failed",
        ));
    }
    let mut cipher = ChaCha20::new(key, nonce, 1);
    let mut plaintext = vec![0_u8; ciphertext.len()];
    cipher.apply_keystream(ciphertext, &mut plaintext)?;
    Ok(plaintext)
}


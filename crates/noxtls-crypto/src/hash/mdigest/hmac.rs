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

use super::{noxtls_sha256, noxtls_sha384, noxtls_sha512};
use crate::internal_alloc::Vec;

/// Computes HMAC-SHA256 for the provided key and message.
///
/// # Arguments
/// * `key`: Secret HMAC key bytes.
/// * `data`: Message bytes to authenticate.
///
/// # Returns
/// A 32-byte HMAC-SHA256 authentication tag.
///
/// # Panics
///
/// Panics only if the internal digest serialization is not 32 bytes (indicates a programming error).
#[must_use]
pub fn noxtls_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_with_block(key, data, 64, HashVariant::Sha256)
        .try_into()
        .expect("hmac-sha256 output is always 32 bytes")
}

/// Computes HMAC-SHA512 for the provided key and message.
///
/// # Arguments
/// * `key`: Secret HMAC key bytes.
/// * `data`: Message bytes to authenticate.
///
/// # Returns
/// A 64-byte HMAC-SHA512 authentication tag.
///
/// # Panics
///
/// Panics only if the internal digest serialization is not 64 bytes (indicates a programming error).
#[must_use]
pub fn noxtls_hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    hmac_with_block(key, data, 128, HashVariant::Sha512)
        .try_into()
        .expect("hmac-sha512 output is always 64 bytes")
}

/// Computes HMAC-SHA384 for the provided key and message.
///
/// # Arguments
/// * `key`: Secret HMAC key bytes.
/// * `data`: Message bytes to authenticate.
///
/// # Returns
/// A 48-byte HMAC-SHA384 authentication tag.
///
/// # Panics
///
/// Panics only if the internal digest serialization is not 48 bytes (indicates a programming error).
#[must_use]
pub fn noxtls_hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    hmac_with_block(key, data, 128, HashVariant::Sha384)
        .try_into()
        .expect("hmac-sha384 output is always 48 bytes")
}

#[derive(Copy, Clone)]
enum HashVariant {
    Sha256,
    Sha384,
    Sha512,
}

/// Computes HMAC using the selected hash variant and block size.
///
/// # Arguments
///
/// * `key` — Secret key bytes (hashed if longer than `block_size`).
/// * `data` — Message bytes to authenticate.
/// * `block_size` — Inner/outer block size for the hash (64 for SHA-256, 128 for SHA-384/512 here).
/// * `variant` — Which digest function backs the HMAC construction.
///
/// # Returns
///
/// Raw HMAC digest bytes whose length matches the selected hash output size.
///
/// # Panics
///
/// This function does not panic for the `block_size` and `variant` pairs used by the public wrappers.
fn hmac_with_block(key: &[u8], data: &[u8], block_size: usize, variant: HashVariant) -> Vec<u8> {
    let mut k0 = vec![0_u8; block_size];
    if key.len() > block_size {
        let digest = match variant {
            HashVariant::Sha256 => noxtls_sha256(key).to_vec(),
            HashVariant::Sha384 => noxtls_sha384(key).to_vec(),
            HashVariant::Sha512 => noxtls_sha512(key).to_vec(),
        };
        k0[..digest.len()].copy_from_slice(&digest);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = vec![0x36_u8; block_size];
    let mut opad = vec![0x5c_u8; block_size];
    for i in 0..block_size {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = ipad;
    inner.extend_from_slice(data);
    let inner_hash = match variant {
        HashVariant::Sha256 => noxtls_sha256(&inner).to_vec(),
        HashVariant::Sha384 => noxtls_sha384(&inner).to_vec(),
        HashVariant::Sha512 => noxtls_sha512(&inner).to_vec(),
    };

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    match variant {
        HashVariant::Sha256 => noxtls_sha256(&outer).to_vec(),
        HashVariant::Sha384 => noxtls_sha384(&outer).to_vec(),
        HashVariant::Sha512 => noxtls_sha512(&outer).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::{noxtls_hmac_sha256, noxtls_hmac_sha384};
    use crate::internal_alloc::Vec;

    /// Decodes lowercase/uppercase hex into bytes for compact vector tests.
    ///
    /// # Arguments
    ///
    /// * `hex` — Even-length ASCII hex string.
    ///
    /// # Returns
    ///
    /// Decoded bytes as a `Vec<u8>`.
    ///
    /// # Panics
    ///
    /// Panics when `hex` has odd length or contains non-hex characters.
    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex string must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .expect("hex test vector should be valid")
            })
            .collect()
    }

    /// Verifies HMAC-SHA256 against RFC 4231 test case 1.
    #[test]
    fn noxtls_hmac_sha256_matches_rfc4231_case_1() {
        let key = vec![0x0b_u8; 20];
        let data = b"Hi There";
        let expected_full =
            decode_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let actual = noxtls_hmac_sha256(&key, data);
        assert_eq!(actual.as_slice(), expected_full.as_slice());
    }

    /// Verifies the exact TLS 1.3 no-PSK HKDF-Extract base case used for early secret.
    #[test]
    fn noxtls_hmac_sha256_matches_tls13_empty_psk_extract_case() {
        let key = [0_u8; 32];
        let data: [u8; 0] = [];
        let expected =
            decode_hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
        let actual = noxtls_hmac_sha256(&key, &data);
        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    /// Verifies HMAC-SHA384 against RFC 4231 test case 1.
    #[test]
    fn noxtls_hmac_sha384_matches_rfc4231_case_1() {
        let key = vec![0x0b_u8; 20];
        let data = b"Hi There";
        let expected = decode_hex(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        );
        let actual = noxtls_hmac_sha384(&key, data);
        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}

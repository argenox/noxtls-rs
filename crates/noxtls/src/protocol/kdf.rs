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
use noxtls_crypto::{
    noxtls_hkdf_expand_sha256, noxtls_hkdf_expand_sha384, noxtls_hkdf_extract_sha256,
    noxtls_hkdf_extract_sha384, noxtls_hmac_sha256, noxtls_hmac_sha384, noxtls_sha256,
    noxtls_sha384,
};

/// Identifies the hash noxtls_algorithm selected by a cipher suite or version profile for HKDF and transcript work.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    /// Returns digest length in bytes for the selected hash noxtls_algorithm.
    ///
    /// # Arguments
    ///
    /// * `self` — Selected hash noxtls_algorithm variant.
    ///
    /// # Returns
    ///
    /// `32` for SHA-256 and `48` for SHA-384 in this port.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// Extracts HKDF PRK using the selected hash noxtls_algorithm and an all-zero salt of digest length.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Hash backend used for HKDF-Extract.
/// * `ikm` — Input keying material supplied to HKDF-Extract.
///
/// # Returns
///
/// Owned PRK bytes of length `noxtls_hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm: HashAlgorithm, ikm: &[u8]) -> Vec<u8> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_extract_sha256(&[0_u8; 32], ikm).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hkdf_extract_sha384(&[0_u8; 48], ikm).to_vec(),
    }
}

/// Extracts HKDF PRK using caller-provided salt for TLS 1.3 stage chaining.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Hash backend used for HKDF-Extract.
/// * `salt` — Salt bytes; length should match the profile feeding this helper.
/// * `ikm` — Input keying material supplied to HKDF-Extract.
///
/// # Returns
///
/// Owned PRK bytes of length `noxtls_hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hkdf_extract_with_salt_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    salt: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_extract_sha256(salt, ikm).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hkdf_extract_sha384(salt, ikm).to_vec(),
    }
}

/// Expands HKDF key material using the selected hash noxtls_algorithm.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Hash backend used for HKDF-Expand.
/// * `prk` — Pseudorandom key from HKDF-Extract.
/// * `info` — HKDF info octets.
/// * `len` — Number of output bytes to expand.
///
/// # Returns
///
/// On success, `len` expanded octets.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the crypto backend rejects the expand request (for example invalid lengths).
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_hkdf_expand_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hkdf_expand_sha256(prk, info, len),
        HashAlgorithm::Sha384 => noxtls_hkdf_expand_sha384(prk, info, len),
    }
}

/// Expands TLS 1.3 HKDF-Label structure bytes using the selected hash backend.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Hash backend used for HKDF-Expand.
/// * `secret` — Secret input to HKDF-Expand (for example a handshake traffic secret).
/// * `label` — Label suffix appended after the `tls13 ` prefix inside the HKDF-Label string.
/// * `context` — Context octets embedded in the HKDF-Label.
/// * `len` — Number of output bytes to expand.
///
/// # Returns
///
/// On success, `len` expanded octets.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when the composed label or context exceeds `u8::MAX`, or other [`noxtls_core::Error`] values from HKDF expand.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_tls13_expand_label_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let mut hkdf_label = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(len as u16).to_be_bytes());
    let mut full_label = b"tls13 ".to_vec();
    full_label.extend_from_slice(label);
    if full_label.len() > u8::MAX as usize || context.len() > u8::MAX as usize {
        return Err(Error::InvalidLength("tls13 hkdf label/context too long"));
    }
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, &hkdf_label, len)
}

/// Computes the TLS `verify_data` / Finished MAC output using the suite-selected transcript hash.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — HMAC digest noxtls_algorithm matching the negotiated suite.
/// * `key` — Finished key material.
/// * `noxtls_transcript_hash` — Transcript hash bytes input to HMAC.
///
/// # Returns
///
/// Owned MAC tag bytes of digest length.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_finished_hmac_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    key: &[u8],
    noxtls_transcript_hash: &[u8],
) -> Vec<u8> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_hmac_sha256(key, noxtls_transcript_hash).to_vec(),
        HashAlgorithm::Sha384 => noxtls_hmac_sha384(key, noxtls_transcript_hash).to_vec(),
    }
}

/// Hashes `input` with the hash noxtls_algorithm used by the modeled key schedule.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Digest noxtls_algorithm to use.
/// * `input` — Message bytes to hash.
///
/// # Returns
///
/// Owned digest bytes of length `noxtls_hash_algorithm.output_len()`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm: HashAlgorithm, input: &[u8]) -> Vec<u8> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_sha256(input).to_vec(),
        HashAlgorithm::Sha384 => noxtls_sha384(input).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        noxtls_hash_bytes_for_algorithm, noxtls_hkdf_extract_for_hash,
        noxtls_hkdf_extract_with_salt_for_hash,
        noxtls_tls13_expand_label_for_hash, HashAlgorithm,
    };
    use crate::internal_alloc::Vec;

    /// Decodes ASCII hex for compact deterministic vector assertions.
    ///
    /// # Arguments
    ///
    /// * `hex` — Even-length hexadecimal string.
    ///
    /// # Returns
    ///
    /// Decoded bytes in allocation-backed storage.
    ///
    /// # Panics
    ///
    /// Panics if input length is odd or contains invalid hex characters.
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

    /// Verifies TLS 1.3 no-PSK early secret baseline (`HKDF-Extract(zeros, "")`).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[test]
    fn tls13_early_secret_sha256_no_psk_matches_vector() {
        let zero_psk = vec![0_u8; 32];
        let early_secret = noxtls_hkdf_extract_for_hash(HashAlgorithm::Sha256, &zero_psk);
        let expected =
            decode_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        assert_eq!(early_secret, expected);
    }

    /// Verifies TLS 1.3 `"derived"` secret uses `Hash("")` as context (RFC 8446 key schedule).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[test]
    fn tls13_derived_secret_uses_hash_empty_context_sha256() {
        let zero_psk = vec![0_u8; 32];
        let early_secret = noxtls_hkdf_extract_for_hash(HashAlgorithm::Sha256, &zero_psk);
        let empty_hash = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &[]);
        let derived = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &early_secret,
            b"derived",
            &empty_hash,
            32,
        )
        .expect("derived expansion should succeed");
        let expected =
            decode_hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        assert_eq!(derived, expected);
    }

    /// Guards against regression where `"derived"` incorrectly uses empty context bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[test]
    fn tls13_derived_secret_empty_context_is_not_hash_empty() {
        let zero_psk = vec![0_u8; 32];
        let early_secret = noxtls_hkdf_extract_for_hash(HashAlgorithm::Sha256, &zero_psk);
        let empty_hash = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &[]);
        let derived_hash_empty = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &early_secret,
            b"derived",
            &empty_hash,
            32,
        )
        .expect("derived expansion should succeed");
        let derived_empty_context = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &early_secret,
            b"derived",
            &[],
            32,
        )
        .expect("derived expansion should succeed");
        assert_ne!(derived_hash_empty, derived_empty_context);
    }

    /// Confirms captured live interop tuple derives the OpenSSL keylog server handshake secret.
    ///
    /// This test uses one known-good captured tuple (`CH || SH || shared_secret`) and asserts
    /// our key schedule output exactly matches OpenSSL `SERVER_HANDSHAKE_TRAFFIC_SECRET`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[test]
    fn tls13_live_capture_vector_matches_openssl_server_handshake_secret() {
        let client_hello = decode_hex(
            "010000dc0303000000006a055cb4217db52499bbddfff44c1defeac5565762c82f95a17236fd0000021301010000b1002b00050403040303000d000a00080403080408050807000a00060004001d00170033006b0069001d0020418e16d71446e5b00a0a3cdc2fa0c1fb94b15ca369f18e1b9a9f6787dd1f1e3c001700410409f2e16b27bc7f6a662389bf8dadb58534b8c3a63f7b1c781cca50dcf1c61f4408ffe2dcd48e7e3a93095eae95dccd9ae05131c1b5c330180e2f90dd6a9945c40000000e000c0000096c6f63616c686f73740010000b000908687474702f312e31",
        );
        let server_hello = decode_hex(
            "02000056030320999f4b894095557a4c925c0989f517545f991bf918e664dd89905c8cf8e7a000130100002e002b0002030400330024001d00208464b134835640ce007efb72cff6499bb98b55e4ebcd43139628722e60188e08",
        );
        let shared_secret = decode_hex(
            "b484067b774ab46a04494d7a7d8587daa4e3638283d4bfab1a2b88923a05e47b",
        );
        let expected_openssl_server_hs_traffic = decode_hex(
            "1eb327fe4e7b3f4608a5d68004f805c3f95f35ef4eafe5f71c13142076efe582",
        );

        let transcript_hash = noxtls_hash_bytes_for_algorithm(
            HashAlgorithm::Sha256,
            &[client_hello.as_slice(), server_hello.as_slice()].concat(),
        );
        let zero_psk = vec![0_u8; 32];
        let early_secret = noxtls_hkdf_extract_for_hash(HashAlgorithm::Sha256, &zero_psk);
        let empty_hash = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &[]);
        let derived_secret = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &early_secret,
            b"derived",
            &empty_hash,
            32,
        )
        .expect("derived expansion should succeed");
        let handshake_secret =
            noxtls_hkdf_extract_with_salt_for_hash(HashAlgorithm::Sha256, &derived_secret, &shared_secret);
        let server_hs_traffic = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &handshake_secret,
            b"s hs traffic",
            &transcript_hash,
            32,
        )
        .expect("server hs traffic expansion should succeed");

        assert_eq!(server_hs_traffic, expected_openssl_server_hs_traffic);
    }

    /// Verifies TLS 1.3 application traffic secret derivation depends on full Finished handshake wrapper.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[test]
    fn tls13_application_secret_uses_finished_handshake_wrapper_in_transcript() {
        const HANDSHAKE_FINISHED: u8 = 20;
        let handshake_secret =
            decode_hex("367a890ed9af3d0f096022c90f25504d293cab01ccb1c2a9f1d46d84609c7ea3");
        let transcript_before_finished = decode_hex(
            "010000dc0303000000006a05675b1d2cd90099bbddfff44c333de2239e0f62c82f95a17262980000021301010000b1002b00050403040303000d000a00080403080408050807000a00060004001d00170033006b0069001d00202498b40f85ae8e528f9fb66f4d7656c198dbcbfd446247fd9618788a205049100017004104e6cdd5cd8c709d9165cc6bfceb101c0f95398593f13387cfd81d6d06d1ca8caac6cc81eba343b3a6f1b221ab159cb3aa46e56a144a981f1cd875709a14832fcf0000000e000c0000096c6f63616c686f73740010000b000908687474702f312e31\
020000560303a8356131c6a348df98857b64e72f07da49b4cbee3c2eeec58806c1e6c4d2104700130100002e002b0002030400330024001d0020056d17c6a6f686538f212feecdc99e16b8ac284ad38bca1a8c7961dee2a59845",
        );
        let verify_data =
            decode_hex("2c4ce907db9756f1ec678de6bca16708dd4460c448f8706db05ebd42d366b563");

        let mut finished_message = Vec::with_capacity(4 + verify_data.len());
        finished_message.push(HANDSHAKE_FINISHED);
        finished_message.push(0);
        finished_message.push(0);
        finished_message.push(verify_data.len() as u8);
        finished_message.extend_from_slice(&verify_data);

        let transcript_with_wrapper = noxtls_hash_bytes_for_algorithm(
            HashAlgorithm::Sha256,
            &[transcript_before_finished.as_slice(), finished_message.as_slice()].concat(),
        );
        let transcript_without_wrapper = noxtls_hash_bytes_for_algorithm(
            HashAlgorithm::Sha256,
            &[transcript_before_finished.as_slice(), verify_data.as_slice()].concat(),
        );

        let empty_hash = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &[]);
        let derived = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &handshake_secret,
            b"derived",
            &empty_hash,
            32,
        )
        .expect("derived expansion should succeed");
        let master_secret =
            noxtls_hkdf_extract_with_salt_for_hash(HashAlgorithm::Sha256, &derived, &[0_u8; 32]);
        let server_app_with_wrapper = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &master_secret,
            b"s ap traffic",
            &transcript_with_wrapper,
            32,
        )
        .expect("server app traffic expansion should succeed");
        let server_app_without_wrapper = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &master_secret,
            b"s ap traffic",
            &transcript_without_wrapper,
            32,
        )
        .expect("server app traffic expansion should succeed");

        assert_ne!(server_app_with_wrapper, server_app_without_wrapper);
    }
}

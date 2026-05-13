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
    noxtls_mlkem_decapsulate, noxtls_mlkem_generate_keypair_auto, noxtls_p256_ecdh_shared_secret, noxtls_sha256,
    HmacDrbgSha256, MlKemPrivateKey, MlKemPublicKey, P256PrivateKey, P256PublicKey,
    X25519PrivateKey, X25519PublicKey,
};

const TLS13_KEY_SHARE_GROUP_SECP256R1: u16 = 0x0017;
const TLS13_KEY_SHARE_GROUP_X25519: u16 = 0x001D;
const TLS13_KEY_SHARE_GROUP_MLKEM768: u16 = 0x0201;
const TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID: u16 = 0x11EC;
const TLS13_SIGALG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const TLS13_SIGALG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const TLS13_SIGALG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const TLS13_SIGALG_ED25519: u16 = 0x0807;
const TLS13_SIGALG_MLDSA65: u16 = 0x0905;

/// Derives deterministic X25519 private scalar bytes from a seed and domain label using SHA-256.
///
/// # Arguments
///
/// * `seed` — High-entropy seed material.
/// * `label` — Domain-separation label concatenated with `seed` before hashing.
///
/// # Returns
///
/// A [`X25519PrivateKey`] constructed from the first 32 bytes of `SHA256(seed || label)`.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_derive_deterministic_x25519_private(seed: &[u8], label: &[u8]) -> X25519PrivateKey {
    let mut material = Vec::with_capacity(seed.len() + label.len());
    material.extend_from_slice(seed);
    material.extend_from_slice(label);
    X25519PrivateKey::from_bytes(noxtls_sha256(&material))
}

/// Derives a valid P-256 private key from `seed` and `label` by hashing with an incrementing counter.
///
/// # Arguments
///
/// * `seed` — High-entropy seed material.
/// * `label` — Domain-separation label concatenated with `seed` and counter before hashing.
///
/// # Returns
///
/// On success, a [`P256PrivateKey`] whose scalar is in-range for the curve.
///
/// # Errors
///
/// Returns [`Error::CryptoFailure`] when no valid scalar is found within the bounded retry budget.
///
/// # Panics
///
/// This function does not panic.
fn derive_deterministic_p256_private_bytes(seed: &[u8], label: &[u8]) -> Result<P256PrivateKey> {
    for counter in 0_u32..256 {
        let mut material = Vec::with_capacity(seed.len() + label.len() + 4);
        material.extend_from_slice(seed);
        material.extend_from_slice(label);
        material.extend_from_slice(&counter.to_be_bytes());
        let candidate: [u8; 32] = noxtls_sha256(&material);
        if let Ok(key) = P256PrivateKey::from_bytes(candidate) {
            return Ok(key);
        }
    }
    Err(Error::CryptoFailure(
        "tls13 deterministic p-256 private key derivation exhausted retry budget",
    ))
}

/// Derives a deterministic P-256 private scalar from a seed and domain label for modeled TLS 1.3.
///
/// # Arguments
///
/// * `seed` — High-entropy seed material.
/// * `label` — Domain-separation label.
///
/// # Returns
///
/// On success, a [`P256PrivateKey`] suitable for deterministic interop and tests.
///
/// # Errors
///
/// Returns [`Error::CryptoFailure`] when derivation exhausts its retry budget without finding a valid scalar.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_derive_deterministic_p256_private(seed: &[u8], label: &[u8]) -> Result<P256PrivateKey> {
    derive_deterministic_p256_private_bytes(seed, label)
}

/// Derives a deterministic ML-KEM-768 keypair from seed material and label using an internal DRBG.
///
/// # Arguments
///
/// * `seed` — High-entropy seed material.
/// * `label` — Domain-separation label.
///
/// # Returns
///
/// On success, `(private, public)` ML-KEM-768 keys.
///
/// # Errors
///
/// Returns [`Error::CryptoFailure`] when the DRBG cannot be initialized or ML-KEM key generation fails.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_derive_deterministic_mlkem768_keypair(
    seed: &[u8],
    label: &[u8],
) -> Result<(MlKemPrivateKey, MlKemPublicKey)> {
    let mut material = Vec::with_capacity(seed.len() + label.len());
    material.extend_from_slice(seed);
    material.extend_from_slice(label);
    let entropy = noxtls_sha256(&material);
    let mut drbg =
        HmacDrbgSha256::new(&entropy, b"mlkem768 deterministic nonce", b"tls13 mlkem")
            .map_err(|_| Error::CryptoFailure("failed to initialize deterministic mlkem drbg"))?;
    noxtls_mlkem_generate_keypair_auto(&mut drbg)
}

/// Returns `true` when the given TLS 1.3 `key_share` named group is supported by this build.
///
/// # Arguments
///
/// * `group` — IANA `NamedGroup` codepoint from an offered `KeyShareEntry`.
///
/// # Returns
///
/// `true` when `group` is one of the built-in X25519, P-256, ML-KEM-768, or hybrid profiles.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_tls13_key_share_group_supported(group: u16) -> bool {
    group == TLS13_KEY_SHARE_GROUP_X25519
        || group == TLS13_KEY_SHARE_GROUP_SECP256R1
        || group == TLS13_KEY_SHARE_GROUP_MLKEM768
        || group == TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID
}

/// Returns `true` when the given TLS 1.3 signature algorithm is supported by this build.
///
/// # Arguments
///
/// * `signature_algorithm` — IANA `SignatureScheme` codepoint from `signature_algorithms` / `signature_algorithms_cert`.
///
/// # Returns
///
/// `true` when the scheme is implemented for modeled handshakes.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_tls13_signature_algorithm_supported(signature_algorithm: u16) -> bool {
    signature_algorithm == TLS13_SIGALG_ECDSA_SECP256R1_SHA256
        || signature_algorithm == TLS13_SIGALG_RSA_PSS_RSAE_SHA256
        || signature_algorithm == TLS13_SIGALG_RSA_PSS_RSAE_SHA384
        || signature_algorithm == TLS13_SIGALG_ED25519
        || signature_algorithm == TLS13_SIGALG_MLDSA65
}

/// Evaluates whether ClientHello extension offers satisfy modeled TLS 1.3 key-exchange policy.
///
/// # Arguments
///
/// * `supported_versions` — Parsed `supported_versions` extension values.
/// * `key_share_groups` — Parsed `key_share` group identifiers.
/// * `signature_algorithms` — Parsed `signature_algorithms` list.
///
/// # Returns
///
/// `true` when TLS 1.3 is offered, at least one supported `key_share` group exists, and at least one supported signature scheme exists.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn noxtls_tls13_client_hello_offers_supported_key_exchange(
    supported_versions: &[u16],
    key_share_groups: &[u16],
    signature_algorithms: &[u16],
) -> bool {
    let has_tls13 = supported_versions.contains(&0x0304);
    let has_supported_key_share = key_share_groups
        .iter()
        .copied()
        .any(noxtls_tls13_key_share_group_supported);
    let has_supported_signature_algorithm = signature_algorithms
        .iter()
        .copied()
        .any(noxtls_tls13_signature_algorithm_supported);
    has_tls13 && has_supported_key_share && has_supported_signature_algorithm
}

/// Derives a TLS 1.3 X25519 ECDHE shared secret from the local private key and peer `key_share` bytes.
///
/// # Arguments
///
/// * `local_private` — Local X25519 private key.
/// * `peer_key_exchange` — 32-byte peer public key encoding from `KeyShareEntry.key_exchange`.
///
/// # Returns
///
/// On success, a 32-byte shared secret.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when `peer_key_exchange` is not exactly 32 bytes, or other errors from the checked ECDH path.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_derive_tls13_x25519_shared_secret(
    local_private: X25519PrivateKey,
    peer_key_exchange: &[u8],
) -> Result<[u8; 32]> {
    if peer_key_exchange.len() != 32 {
        return Err(Error::ParseFailure(
            "tls13 key_share entry must contain 32-byte x25519 key_exchange",
        ));
    }
    let peer_bytes: [u8; 32] = peer_key_exchange.try_into().map_err(|_| {
        Error::ParseFailure("tls13 key_share entry has invalid key_exchange length")
    })?;
    let peer = X25519PublicKey::from_bytes(peer_bytes);
    local_private.diffie_hellman_checked(peer)
}

/// Derives a TLS 1.3 ECDHE shared secret for `secp256r1` from the local private key and peer uncompressed point.
///
/// # Arguments
///
/// * `local_private` — Local P-256 private key.
/// * `peer_uncompressed` — SEC1 uncompressed public point bytes (`0x04 || X || Y`).
///
/// # Returns
///
/// On success, a 32-byte shared secret.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the peer point is not valid uncompressed SEC1 encoding or ECDH fails.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_derive_tls13_p256_shared_secret(
    local_private: &P256PrivateKey,
    peer_uncompressed: &[u8],
) -> Result<[u8; 32]> {
    let peer = P256PublicKey::from_uncompressed(peer_uncompressed)?;
    noxtls_p256_ecdh_shared_secret(local_private, &peer)
}

/// Derives an ML-KEM-768 shared secret from the local private key and peer ciphertext bytes.
///
/// # Arguments
///
/// * `local_private` — Local ML-KEM-768 private key.
/// * `peer_key_exchange` — Peer ciphertext bytes from `KeyShareEntry.key_exchange`.
///
/// # Returns
///
/// On success, a 32-byte shared secret.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when decapsulation fails.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_derive_tls13_mlkem768_shared_secret(
    local_private: &MlKemPrivateKey,
    peer_key_exchange: &[u8],
) -> Result<[u8; 32]> {
    noxtls_mlkem_decapsulate(local_private, peer_key_exchange)
}

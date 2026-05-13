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

//! Concrete public-key implementations (RSA, ECC, X25519/X448, Ed25519, ML-KEM, ML-DSA).
//!
//! Submodules are private; this module re-exports the supported API and provides
//! [`noxtls_ecc_generate_keypair_auto`] for unified ECC key generation.

mod bignum;
mod ed25519;
mod mldsa;
mod mlkem;
mod p256;
mod pq_selftest;
mod rsa;
mod x25519;
mod x448;

use crate::drbg::HmacDrbgSha256;
#[cfg(not(feature = "hazardous-legacy-crypto"))]
use noxtls_core::Error;
use noxtls_core::Result;

pub use ed25519::{
    noxtls_ed25519_generate_private_key_auto, noxtls_ed25519_public_key_from_subject_public_key_info,
    noxtls_ed25519_verify, Ed25519PrivateKey, Ed25519PublicKey,
};
pub use mldsa::{
    noxtls_mldsa_generate_keypair_auto, noxtls_mldsa_public_key_from_subject_public_key_info, noxtls_mldsa_verify,
    MlDsaPrivateKey, MlDsaPublicKey, OID_ID_MLDSA65,
};
pub use mlkem::{
    noxtls_mlkem_decapsulate, noxtls_mlkem_encapsulate_auto, noxtls_mlkem_generate_keypair_auto, MlKemPrivateKey,
    MlKemPublicKey, MLKEM_CIPHERTEXT_LEN, MLKEM_PRIVATE_KEY_LEN, MLKEM_PUBLIC_KEY_LEN,
    MLKEM_SHARED_SECRET_LEN,
};
pub use p256::{
    noxtls_p256_ecdh_shared_secret, noxtls_p256_ecdsa_sign_digest, noxtls_p256_ecdsa_sign_digest_auto,
    noxtls_p256_ecdsa_sign_sha256, noxtls_p256_ecdsa_sign_sha256_auto, noxtls_p256_ecdsa_verify_digest,
    noxtls_p256_ecdsa_verify_sha256, noxtls_p256_generate_private_key_auto, P256PrivateKey, P256PublicKey,
};
pub use pq_selftest::noxtls_run_pq_self_tests;
#[cfg(feature = "hazardous-legacy-crypto")]
pub use rsa::{noxtls_rsa_generate_keypair_auto, noxtls_rsa_generate_keypair_with_exponent_auto};
pub use rsa::{
    noxtls_rsa_generate_keypair_secure_auto, noxtls_rsa_generate_keypair_with_policy_auto,
    noxtls_rsaes_oaep_sha256_decrypt, noxtls_rsaes_oaep_sha256_decrypt_crt_only, noxtls_rsaes_oaep_sha256_encrypt_auto,
    noxtls_rsaes_pkcs1_v15_decrypt, noxtls_rsaes_pkcs1_v15_decrypt_crt_only, noxtls_rsaes_pkcs1_v15_encrypt_auto,
    noxtls_rsassa_pss_sha256_sign, noxtls_rsassa_pss_sha256_sign_auto, noxtls_rsassa_pss_sha256_verify,
    noxtls_rsassa_pss_sha384_sign, noxtls_rsassa_pss_sha384_sign_auto, noxtls_rsassa_pss_sha384_verify,
    noxtls_rsassa_sha1_sign, noxtls_rsassa_sha1_verify, noxtls_rsassa_sha256_sign, noxtls_rsassa_sha256_verify,
    noxtls_rsassa_sha384_sign, noxtls_rsassa_sha384_verify, noxtls_rsassa_sha512_sign, noxtls_rsassa_sha512_verify,
    RsaKeySizePolicy, RsaPrivateKey, RsaPublicKey,
};
pub use x25519::{
    noxtls_x25519, noxtls_x25519_basepoint, noxtls_x25519_generate_private_key_auto, noxtls_x25519_shared_secret,
    X25519PrivateKey, X25519PublicKey,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use x448::noxtls_x448_generate_private_key_auto;
#[cfg(feature = "hazardous-legacy-crypto")]
pub use x448::{noxtls_x448, noxtls_x448_basepoint, noxtls_x448_shared_secret};
pub use x448::{X448PrivateKey, X448PublicKey};

/// Selects one supported elliptic-curve key algorithm for unified key generation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EccKeyAlgorithm {
    /// NIST P-256 (secp256r1) key material.
    P256,
    /// Curve25519 X25519 key-exchange key material.
    X25519,
    /// Curve448 X448 key-exchange key material.
    X448,
    /// Ed25519 signing key material.
    Ed25519,
}

/// Wraps one generated ECC private key variant.
#[derive(Debug, Clone)]
pub enum EccPrivateKey {
    /// P-256 private scalar.
    P256(P256PrivateKey),
    /// X25519 private scalar.
    X25519(X25519PrivateKey),
    /// X448 private scalar.
    X448(X448PrivateKey),
    /// Ed25519 signing seed/key.
    Ed25519(Ed25519PrivateKey),
}

/// Wraps one generated ECC public key variant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EccPublicKey {
    /// P-256 public point.
    P256(P256PublicKey),
    /// X25519 public u-coordinate.
    X25519(X25519PublicKey),
    /// X448 public u-coordinate.
    X448(X448PublicKey),
    /// Ed25519 verifying key.
    Ed25519(Ed25519PublicKey),
}

/// Generates one ECC private/public keypair for the selected algorithm using DRBG entropy.
///
/// # Arguments
/// * `algorithm`: ECC algorithm to generate.
/// * `drbg`: DRBG source used for private-key randomness.
///
/// # Returns
/// `(private_key, public_key)` pair wrapped by enum variants matching `algorithm`.
///
/// # Errors
///
/// Returns any error produced by the algorithm-specific DRBG-driven generators (for example P-256 field validation, DRBG state errors, or malformed lengths from underlying calls).
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_ecc_generate_keypair_auto(
    algorithm: EccKeyAlgorithm,
    drbg: &mut HmacDrbgSha256,
) -> Result<(EccPrivateKey, EccPublicKey)> {
    match algorithm {
        EccKeyAlgorithm::P256 => {
            let private = noxtls_p256_generate_private_key_auto(drbg)?;
            let public = private.public_key()?;
            Ok((EccPrivateKey::P256(private), EccPublicKey::P256(public)))
        }
        EccKeyAlgorithm::X25519 => {
            let private = noxtls_x25519_generate_private_key_auto(drbg)?;
            let public = private.clone().public_key();
            Ok((EccPrivateKey::X25519(private), EccPublicKey::X25519(public)))
        }
        #[cfg(feature = "hazardous-legacy-crypto")]
        EccKeyAlgorithm::X448 => {
            let private = noxtls_x448_generate_private_key_auto(drbg)?;
            let public = private.clone().public_key();
            Ok((EccPrivateKey::X448(private), EccPublicKey::X448(public)))
        }
        #[cfg(not(feature = "hazardous-legacy-crypto"))]
        EccKeyAlgorithm::X448 => Err(Error::StateError(
            "x448 operations are disabled by default; enable `hazardous-legacy-crypto` to use non-constant-time x448 implementation",
        )),
        EccKeyAlgorithm::Ed25519 => {
            let private = noxtls_ed25519_generate_private_key_auto(drbg)?;
            let public = private.verifying_key();
            Ok((
                EccPrivateKey::Ed25519(private),
                EccPublicKey::Ed25519(public),
            ))
        }
    }
}

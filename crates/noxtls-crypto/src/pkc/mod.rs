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

//! Public-key cryptography: RSA, ECC, X25519/X448, Ed25519, ML-KEM, and ML-DSA.
//!
//! The internal `primitive` submodule contains concrete implementations; this file re-exports the
//! supported entry points for TLS and certificate workflows.

mod primitive;

pub use primitive::{
    noxtls_ecc_generate_keypair_auto, noxtls_ed25519_generate_private_key_auto,
    noxtls_ed25519_public_key_from_subject_public_key_info, noxtls_ed25519_verify, noxtls_mldsa_generate_keypair_auto,
    noxtls_mldsa_public_key_from_subject_public_key_info, noxtls_mldsa_verify, noxtls_mlkem_decapsulate,
    noxtls_mlkem_encapsulate_auto, noxtls_mlkem_generate_keypair_auto, noxtls_p256_ecdh_shared_secret,
    noxtls_p256_ecdsa_sign_digest, noxtls_p256_ecdsa_sign_digest_auto, noxtls_p256_ecdsa_sign_sha256,
    noxtls_p256_ecdsa_sign_sha256_auto, noxtls_p256_ecdsa_verify_digest, noxtls_p256_ecdsa_verify_sha256,
    noxtls_p256_generate_private_key_auto, noxtls_rsa_generate_keypair_secure_auto,
    noxtls_rsa_generate_keypair_with_policy_auto, noxtls_rsaes_oaep_sha256_decrypt,
    noxtls_rsaes_oaep_sha256_decrypt_crt_only, noxtls_rsaes_oaep_sha256_encrypt_auto, noxtls_rsaes_pkcs1_v15_decrypt,
    noxtls_rsaes_pkcs1_v15_decrypt_crt_only, noxtls_rsaes_pkcs1_v15_encrypt_auto, noxtls_rsassa_pss_sha256_sign,
    noxtls_rsassa_pss_sha256_sign_auto, noxtls_rsassa_pss_sha256_verify, noxtls_rsassa_pss_sha384_sign,
    noxtls_rsassa_pss_sha384_sign_auto, noxtls_rsassa_pss_sha384_verify, noxtls_rsassa_sha1_sign, noxtls_rsassa_sha1_verify,
    noxtls_rsassa_sha256_sign, noxtls_rsassa_sha256_verify, noxtls_rsassa_sha384_sign, noxtls_rsassa_sha384_verify,
    noxtls_rsassa_sha512_sign, noxtls_rsassa_sha512_verify, noxtls_run_pq_self_tests, noxtls_x25519, noxtls_x25519_basepoint,
    noxtls_x25519_generate_private_key_auto, noxtls_x25519_shared_secret, EccKeyAlgorithm, EccPrivateKey,
    EccPublicKey, Ed25519PrivateKey, Ed25519PublicKey, MlDsaPrivateKey, MlDsaPublicKey,
    MlKemPrivateKey, MlKemPublicKey, P256PrivateKey, P256PublicKey, RsaKeySizePolicy,
    RsaPrivateKey, RsaPublicKey, X25519PrivateKey, X25519PublicKey, X448PrivateKey, X448PublicKey,
    MLKEM_CIPHERTEXT_LEN, MLKEM_PRIVATE_KEY_LEN, MLKEM_PUBLIC_KEY_LEN, MLKEM_SHARED_SECRET_LEN,
    OID_ID_MLDSA65,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use primitive::{noxtls_rsa_generate_keypair_auto, noxtls_rsa_generate_keypair_with_exponent_auto};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use primitive::{noxtls_x448, noxtls_x448_basepoint, noxtls_x448_generate_private_key_auto, noxtls_x448_shared_secret};

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
    ecc_generate_keypair_auto, ed25519_generate_private_key_auto,
    ed25519_public_key_from_subject_public_key_info, ed25519_verify, mldsa_generate_keypair_auto,
    mldsa_public_key_from_subject_public_key_info, mldsa_verify, mlkem_decapsulate,
    mlkem_encapsulate_auto, mlkem_generate_keypair_auto, p256_ecdh_shared_secret,
    p256_ecdsa_sign_digest, p256_ecdsa_sign_digest_auto, p256_ecdsa_sign_sha256,
    p256_ecdsa_sign_sha256_auto, p256_ecdsa_verify_digest, p256_ecdsa_verify_sha256,
    p256_generate_private_key_auto, rsa_generate_keypair_secure_auto,
    rsa_generate_keypair_with_policy_auto, rsaes_oaep_sha256_decrypt,
    rsaes_oaep_sha256_decrypt_crt_only, rsaes_oaep_sha256_encrypt_auto, rsaes_pkcs1_v15_decrypt,
    rsaes_pkcs1_v15_decrypt_crt_only, rsaes_pkcs1_v15_encrypt_auto, rsassa_pss_sha256_sign,
    rsassa_pss_sha256_sign_auto, rsassa_pss_sha256_verify, rsassa_pss_sha384_sign,
    rsassa_pss_sha384_sign_auto, rsassa_pss_sha384_verify, rsassa_sha1_sign, rsassa_sha1_verify,
    rsassa_sha256_sign, rsassa_sha256_verify, rsassa_sha384_sign, rsassa_sha384_verify,
    rsassa_sha512_sign, rsassa_sha512_verify, run_pq_self_tests, x25519, x25519_basepoint,
    x25519_generate_private_key_auto, x25519_shared_secret, EccKeyAlgorithm, EccPrivateKey,
    EccPublicKey, Ed25519PrivateKey, Ed25519PublicKey, MlDsaPrivateKey, MlDsaPublicKey,
    MlKemPrivateKey, MlKemPublicKey, P256PrivateKey, P256PublicKey, RsaKeySizePolicy,
    RsaPrivateKey, RsaPublicKey, X25519PrivateKey, X25519PublicKey, X448PrivateKey, X448PublicKey,
    MLKEM_CIPHERTEXT_LEN, MLKEM_PRIVATE_KEY_LEN, MLKEM_PUBLIC_KEY_LEN, MLKEM_SHARED_SECRET_LEN,
    OID_ID_MLDSA65,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use primitive::{x448, x448_basepoint, x448_generate_private_key_auto, x448_shared_secret};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use primitive::{
    rsa_generate_keypair_auto, rsa_generate_keypair_with_exponent_auto,
};


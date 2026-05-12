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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![allow(clippy::incompatible_msrv)]
#![allow(clippy::manual_rotate)]

//! Cryptographic primitives for NoxTLS.
//!
//! This crate groups hash and MAC helpers ([`hash`]), deterministic randomness ([`drbg`]),
//! public-key algorithms ([`pkc`]), and symmetric ciphers ([`sym`]) behind a single
//! dependency surface re-exported from the crate root.

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod internal_alloc;

pub mod drbg;
pub mod hash;
pub mod pkc;
pub mod sym;

pub use drbg::HmacDrbgSha256;
pub use hash::{
    bcrypt_pbkdf_sha512, decode_hex, hkdf_expand_sha256, hkdf_expand_sha384, hkdf_extract_sha256,
    hkdf_extract_sha384, hmac_sha256, hmac_sha384, hmac_sha512, sha1, sha256, sha384, sha3_256,
    sha3_384, sha3_512, sha512, shake256, tls12_finished_verify_data_sha256,
    tls12_finished_verify_data_sha384, tls12_prf_sha256, tls12_prf_sha384, Digest, Sha256, Sha512,
    TlsTranscriptSha256, TlsTranscriptSha384,
};
#[allow(deprecated)]
pub use pkc::{
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
pub use pkc::{rsa_generate_keypair_auto, rsa_generate_keypair_with_exponent_auto};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use pkc::{x448, x448_basepoint, x448_generate_private_key_auto, x448_shared_secret};
pub use sym::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ccm_decrypt, aes_ccm_encrypt, aes_cfb_apply,
    aes_cfb_decrypt, aes_cfb_encrypt, aes_ctr_apply, aes_gcm_decrypt, aes_gcm_encrypt,
    aes_ofb_apply, aes_xts_decrypt, aes_xts_encrypt, aria_cbc_decrypt, aria_cbc_encrypt,
    aria_cfb_apply, aria_cfb_decrypt, aria_cfb_encrypt, aria_ctr_apply, aria_ctr_decrypt,
    aria_ctr_encrypt, aria_ofb_apply, aria_ofb_decrypt, aria_ofb_encrypt, camellia_cbc_decrypt,
    camellia_cbc_encrypt, camellia_cfb_apply, camellia_cfb_decrypt, camellia_cfb_encrypt,
    camellia_ctr_apply, camellia_ctr_decrypt, camellia_ctr_encrypt, camellia_ofb_apply,
    camellia_ofb_decrypt, camellia_ofb_encrypt, chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt, poly1305_key_gen, poly1305_mac, poly1305_tags_equal, AesCipher,
    AriaCipher, CamelliaCipher, ChaCha20,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use sym::{
    aes_ecb_decrypt, aes_ecb_encrypt, aria_ecb_decrypt, aria_ecb_encrypt, camellia_ecb_decrypt,
    camellia_ecb_encrypt, des_cbc_decrypt, des_cbc_encrypt, des_cfb_apply, des_cfb_decrypt,
    des_cfb_encrypt, des_ctr_apply, des_ctr_decrypt, des_ctr_encrypt, des_ecb_decrypt,
    des_ecb_encrypt, des_ofb_apply, des_ofb_decrypt, des_ofb_encrypt, DesCipher, Rc4,
};

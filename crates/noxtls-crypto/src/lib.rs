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
    noxtls_bcrypt_pbkdf_sha512, noxtls_decode_hex, noxtls_hkdf_expand_sha256,
    noxtls_hkdf_expand_sha384, noxtls_hkdf_extract_sha256, noxtls_hkdf_extract_sha384,
    noxtls_hmac_sha256, noxtls_hmac_sha384, noxtls_hmac_sha512, noxtls_sha1, noxtls_sha256,
    noxtls_sha384, noxtls_sha3_256, noxtls_sha3_384, noxtls_sha3_512, noxtls_sha512,
    noxtls_shake256, noxtls_tls12_finished_verify_data_sha256,
    noxtls_tls12_finished_verify_data_sha384, noxtls_tls12_prf_sha256, noxtls_tls12_prf_sha384,
    Digest, Sha256, Sha512, TlsTranscriptSha256, TlsTranscriptSha384,
};
#[allow(deprecated)]
pub use pkc::{
    noxtls_ecc_generate_keypair_auto, noxtls_ed25519_generate_private_key_auto,
    noxtls_ed25519_public_key_from_subject_public_key_info, noxtls_ed25519_verify,
    noxtls_mldsa_generate_keypair_auto, noxtls_mldsa_public_key_from_subject_public_key_info,
    noxtls_mldsa_verify, noxtls_mlkem_decapsulate, noxtls_mlkem_encapsulate_auto,
    noxtls_mlkem_generate_keypair_auto, noxtls_p256_ecdh_shared_secret,
    noxtls_p256_ecdsa_sign_digest, noxtls_p256_ecdsa_sign_digest_auto,
    noxtls_p256_ecdsa_sign_sha256, noxtls_p256_ecdsa_sign_sha256_auto,
    noxtls_p256_ecdsa_verify_digest, noxtls_p256_ecdsa_verify_sha256,
    noxtls_p256_generate_private_key_auto, noxtls_rsa_generate_keypair_secure_auto,
    noxtls_rsa_generate_keypair_with_policy_auto, noxtls_rsaes_oaep_sha256_decrypt,
    noxtls_rsaes_oaep_sha256_decrypt_crt_only, noxtls_rsaes_oaep_sha256_encrypt_auto,
    noxtls_rsaes_pkcs1_v15_decrypt, noxtls_rsaes_pkcs1_v15_decrypt_crt_only,
    noxtls_rsaes_pkcs1_v15_encrypt_auto, noxtls_rsassa_pss_sha256_sign,
    noxtls_rsassa_pss_sha256_sign_auto, noxtls_rsassa_pss_sha256_verify,
    noxtls_rsassa_pss_sha384_sign, noxtls_rsassa_pss_sha384_sign_auto,
    noxtls_rsassa_pss_sha384_verify, noxtls_rsassa_sha1_sign, noxtls_rsassa_sha1_verify,
    noxtls_rsassa_sha256_sign, noxtls_rsassa_sha256_verify, noxtls_rsassa_sha384_sign,
    noxtls_rsassa_sha384_verify, noxtls_rsassa_sha512_sign, noxtls_rsassa_sha512_verify,
    noxtls_run_pq_self_tests, noxtls_x25519, noxtls_x25519_basepoint,
    noxtls_x25519_generate_private_key_auto, noxtls_x25519_shared_secret, EccKeyAlgorithm,
    EccPrivateKey, EccPublicKey, Ed25519PrivateKey, Ed25519PublicKey, MlDsaPrivateKey,
    MlDsaPublicKey, MlKemPrivateKey, MlKemPublicKey, P256PrivateKey, P256PublicKey,
    RsaKeySizePolicy, RsaPrivateKey, RsaPublicKey, X25519PrivateKey, X25519PublicKey,
    X448PrivateKey, X448PublicKey, MLKEM_CIPHERTEXT_LEN, MLKEM_PRIVATE_KEY_LEN,
    MLKEM_PUBLIC_KEY_LEN, MLKEM_SHARED_SECRET_LEN, OID_ID_MLDSA65,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use pkc::{noxtls_rsa_generate_keypair_auto, noxtls_rsa_generate_keypair_with_exponent_auto};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use pkc::{
    noxtls_x448, noxtls_x448_basepoint, noxtls_x448_generate_private_key_auto,
    noxtls_x448_shared_secret,
};
pub use sym::{
    noxtls_aes_cbc_decrypt, noxtls_aes_cbc_encrypt, noxtls_aes_ccm_decrypt, noxtls_aes_ccm_encrypt,
    noxtls_aes_cfb_apply, noxtls_aes_cfb_decrypt, noxtls_aes_cfb_encrypt, noxtls_aes_ctr_apply,
    noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt, noxtls_aes_ofb_apply, noxtls_aes_xts_decrypt,
    noxtls_aes_xts_encrypt, noxtls_aria_cbc_decrypt, noxtls_aria_cbc_encrypt,
    noxtls_aria_cfb_apply, noxtls_aria_cfb_decrypt, noxtls_aria_cfb_encrypt, noxtls_aria_ctr_apply,
    noxtls_aria_ctr_decrypt, noxtls_aria_ctr_encrypt, noxtls_aria_ofb_apply,
    noxtls_aria_ofb_decrypt, noxtls_aria_ofb_encrypt, noxtls_camellia_cbc_decrypt,
    noxtls_camellia_cbc_encrypt, noxtls_camellia_cfb_apply, noxtls_camellia_cfb_decrypt,
    noxtls_camellia_cfb_encrypt, noxtls_camellia_ctr_apply, noxtls_camellia_ctr_decrypt,
    noxtls_camellia_ctr_encrypt, noxtls_camellia_ofb_apply, noxtls_camellia_ofb_decrypt,
    noxtls_camellia_ofb_encrypt, noxtls_chacha20_poly1305_decrypt,
    noxtls_chacha20_poly1305_encrypt, noxtls_poly1305_key_gen, noxtls_poly1305_mac,
    noxtls_poly1305_tags_equal, AesCipher, AriaCipher, CamelliaCipher, ChaCha20,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use sym::{
    noxtls_aes_ecb_decrypt, noxtls_aes_ecb_encrypt, noxtls_aria_ecb_decrypt,
    noxtls_aria_ecb_encrypt, noxtls_camellia_ecb_decrypt, noxtls_camellia_ecb_encrypt,
    noxtls_des_cbc_decrypt, noxtls_des_cbc_encrypt, noxtls_des_cfb_apply, noxtls_des_cfb_decrypt,
    noxtls_des_cfb_encrypt, noxtls_des_ctr_apply, noxtls_des_ctr_decrypt, noxtls_des_ctr_encrypt,
    noxtls_des_ecb_decrypt, noxtls_des_ecb_encrypt, noxtls_des_ofb_apply, noxtls_des_ofb_decrypt,
    noxtls_des_ofb_encrypt, DesCipher, Rc4,
};

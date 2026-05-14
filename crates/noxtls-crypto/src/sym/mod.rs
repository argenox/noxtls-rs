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

//! Symmetric encryption, AEAD, and message authentication (Poly1305).
//!
//! Block/stream modes live under the internal `encryption` submodule; hazardous legacy algorithms are gated by
//! the `hazardous-legacy-crypto` feature.

mod encryption;

pub use encryption::{
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
pub use encryption::{
    noxtls_aes_ecb_decrypt, noxtls_aes_ecb_encrypt, noxtls_aria_ecb_decrypt,
    noxtls_aria_ecb_encrypt, noxtls_camellia_ecb_decrypt, noxtls_camellia_ecb_encrypt,
    noxtls_des_cbc_decrypt, noxtls_des_cbc_encrypt, noxtls_des_cfb_apply, noxtls_des_cfb_decrypt,
    noxtls_des_cfb_encrypt, noxtls_des_ctr_apply, noxtls_des_ctr_decrypt, noxtls_des_ctr_encrypt,
    noxtls_des_ecb_decrypt, noxtls_des_ecb_encrypt, noxtls_des_ofb_apply, noxtls_des_ofb_decrypt,
    noxtls_des_ofb_encrypt, DesCipher, Rc4,
};

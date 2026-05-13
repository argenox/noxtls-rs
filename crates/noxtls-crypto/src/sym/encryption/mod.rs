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

//! Symmetric cipher modes (AES, ARIA, Camellia, ChaCha20-Poly1305) and Poly1305 helpers.
//!
//! Legacy algorithms live behind the `hazardous-legacy-crypto` feature; this file only wires exports.

mod aes;
mod aria;
mod camellia;
mod chacha20;
mod chacha20_poly1305;
#[cfg(feature = "hazardous-legacy-crypto")]
mod des;
mod poly1305;
#[cfg(feature = "hazardous-legacy-crypto")]
mod rc4;

pub use aes::{
    noxtls_aes_cbc_decrypt, noxtls_aes_cbc_encrypt, noxtls_aes_ccm_decrypt, noxtls_aes_ccm_encrypt, noxtls_aes_cfb_apply,
    noxtls_aes_cfb_decrypt, noxtls_aes_cfb_encrypt, noxtls_aes_ctr_apply, noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt,
    noxtls_aes_ofb_apply, noxtls_aes_xts_decrypt, noxtls_aes_xts_encrypt, AesCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use aes::{noxtls_aes_ecb_decrypt, noxtls_aes_ecb_encrypt};
pub use aria::{
    noxtls_aria_cbc_decrypt, noxtls_aria_cbc_encrypt, noxtls_aria_cfb_apply, noxtls_aria_cfb_decrypt, noxtls_aria_cfb_encrypt,
    noxtls_aria_ctr_apply, noxtls_aria_ctr_decrypt, noxtls_aria_ctr_encrypt, noxtls_aria_ofb_apply, noxtls_aria_ofb_decrypt,
    noxtls_aria_ofb_encrypt, AriaCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use aria::{noxtls_aria_ecb_decrypt, noxtls_aria_ecb_encrypt};
pub use camellia::{
    noxtls_camellia_cbc_decrypt, noxtls_camellia_cbc_encrypt, noxtls_camellia_cfb_apply, noxtls_camellia_cfb_decrypt,
    noxtls_camellia_cfb_encrypt, noxtls_camellia_ctr_apply, noxtls_camellia_ctr_decrypt, noxtls_camellia_ctr_encrypt,
    noxtls_camellia_ofb_apply, noxtls_camellia_ofb_decrypt, noxtls_camellia_ofb_encrypt, CamelliaCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use camellia::{noxtls_camellia_ecb_decrypt, noxtls_camellia_ecb_encrypt};
pub use chacha20::ChaCha20;
pub use chacha20_poly1305::{noxtls_chacha20_poly1305_decrypt, noxtls_chacha20_poly1305_encrypt};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use des::{
    noxtls_des_cbc_decrypt, noxtls_des_cbc_encrypt, noxtls_des_cfb_apply, noxtls_des_cfb_decrypt, noxtls_des_cfb_encrypt,
    noxtls_des_ctr_apply, noxtls_des_ctr_decrypt, noxtls_des_ctr_encrypt, noxtls_des_ecb_decrypt, noxtls_des_ecb_encrypt,
    noxtls_des_ofb_apply, noxtls_des_ofb_decrypt, noxtls_des_ofb_encrypt, DesCipher,
};
pub use poly1305::{noxtls_poly1305_key_gen, noxtls_poly1305_mac, noxtls_poly1305_mac_padded16, noxtls_poly1305_tags_equal};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use rc4::Rc4;

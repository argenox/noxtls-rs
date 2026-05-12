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
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ccm_decrypt, aes_ccm_encrypt, aes_cfb_apply,
    aes_cfb_decrypt, aes_cfb_encrypt, aes_ctr_apply, aes_gcm_decrypt, aes_gcm_encrypt,
    aes_ofb_apply, aes_xts_decrypt, aes_xts_encrypt, AesCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use aes::{aes_ecb_decrypt, aes_ecb_encrypt};
pub use aria::{
    aria_cbc_decrypt, aria_cbc_encrypt, aria_cfb_apply, aria_cfb_decrypt, aria_cfb_encrypt,
    aria_ctr_apply, aria_ctr_decrypt, aria_ctr_encrypt, aria_ofb_apply, aria_ofb_decrypt,
    aria_ofb_encrypt, AriaCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use aria::{aria_ecb_decrypt, aria_ecb_encrypt};
pub use camellia::{
    camellia_cbc_decrypt, camellia_cbc_encrypt, camellia_cfb_apply, camellia_cfb_decrypt,
    camellia_cfb_encrypt, camellia_ctr_apply, camellia_ctr_decrypt, camellia_ctr_encrypt,
    camellia_ofb_apply, camellia_ofb_decrypt, camellia_ofb_encrypt, CamelliaCipher,
};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use camellia::{camellia_ecb_decrypt, camellia_ecb_encrypt};
pub use chacha20::ChaCha20;
pub use chacha20_poly1305::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use des::{
    des_cbc_decrypt, des_cbc_encrypt, des_cfb_apply, des_cfb_decrypt, des_cfb_encrypt,
    des_ctr_apply, des_ctr_decrypt, des_ctr_encrypt, des_ecb_decrypt, des_ecb_encrypt,
    des_ofb_apply, des_ofb_decrypt, des_ofb_encrypt, DesCipher,
};
pub use poly1305::{poly1305_key_gen, poly1305_mac, poly1305_mac_padded16, poly1305_tags_equal};
#[cfg(feature = "hazardous-legacy-crypto")]
pub use rc4::Rc4;

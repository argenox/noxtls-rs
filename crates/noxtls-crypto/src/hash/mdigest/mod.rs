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

//! Message digests, HMAC, HKDF, TLS PRF/finished helpers, and hex decoding.
//!
//! Implementations are split by algorithm file; this module only wires `pub use` exports.

mod bcrypt_pbkdf;
mod digest;
mod hex;
mod hkdf;
mod hmac;
mod sha1;
mod sha256;
mod sha512;
mod tls;

pub use bcrypt_pbkdf::noxtls_bcrypt_pbkdf_sha512;
pub use digest::Digest;
pub use hex::noxtls_decode_hex;
pub use hkdf::{noxtls_hkdf_expand_sha256, noxtls_hkdf_expand_sha384, noxtls_hkdf_extract_sha256, noxtls_hkdf_extract_sha384};
pub use hmac::{noxtls_hmac_sha256, noxtls_hmac_sha384, noxtls_hmac_sha512};
pub use sha1::noxtls_sha1;
pub use sha256::{noxtls_sha256, Sha256};
pub use sha512::{noxtls_sha384, noxtls_sha512, Sha512};
pub use tls::{
    noxtls_tls12_finished_verify_data_sha256, noxtls_tls12_finished_verify_data_sha384, noxtls_tls12_prf_sha256,
    noxtls_tls12_prf_sha384, TlsTranscriptSha256, TlsTranscriptSha384,
};

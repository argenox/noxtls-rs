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

//! Hashing, HMAC/HKDF helpers, TLS transcript digests, and SHA-3 / SHAKE256.
//!
//! Public items are re-exported from [`crate`] for convenience; see submodules for details.

mod mdigest;
mod sha3;

pub use mdigest::{
    bcrypt_pbkdf_sha512,
    decode_hex, hkdf_expand_sha256, hkdf_expand_sha384, hkdf_extract_sha256, hkdf_extract_sha384,
    hmac_sha256, hmac_sha384, hmac_sha512, sha1, sha256, sha384, sha512,
    tls12_finished_verify_data_sha256, tls12_finished_verify_data_sha384, tls12_prf_sha256,
    tls12_prf_sha384, Digest, Sha256, Sha512, TlsTranscriptSha256, TlsTranscriptSha384,
};
pub use sha3::{sha3_256, sha3_384, sha3_512, shake256};

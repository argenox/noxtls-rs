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

//! Build a simple anchor + leaf chain and run `noxtls_validate_certificate_chain`.

use noxtls_core::Result;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::{
    noxtls_parse_certificate, noxtls_validate_certificate_chain,
    noxtls_write_self_signed_certificate_p256_sha256,
};

/// Validates a generated leaf certificate against a generated trust anchor.
///
/// # Arguments
///
/// _(none)_ — Uses fixed seeds and names; no CLI arguments.
///
/// # Returns
///
/// `Ok(())` after printing validation summary lines.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when certificate issuance or parsing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let trust_anchor_der = make_self_signed("anchor.noxtls.local", [0x44; 32], &[0x10])?;
    let leaf_der = make_self_signed("leaf.noxtls.local", [0x55; 32], &[0x11])?;

    let trust_anchor = noxtls_parse_certificate(&trust_anchor_der)?;
    let leaf = noxtls_parse_certificate(&leaf_der)?;
    let report = noxtls_validate_certificate_chain(&leaf, &[], &[trust_anchor], "20260101000000Z");

    match report {
        Ok(result) => {
            println!("chain_len={}", result.chain_len);
            println!("trust_anchor_index={}", result.trust_anchor_index);
        }
        Err(err) => println!("validation_error={err}"),
    }
    Ok(())
}

/// Creates one deterministic self-signed certificate with caller-selected identity and key seed.
///
/// # Arguments
///
/// * `common_name` — Subject common name.
/// * `key_seed` — 32-byte P-256 private key seed.
/// * `serial` — Serial number body.
///
/// # Returns
///
/// On success, DER-encoded certificate bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the key is invalid or certificate creation fails.
///
/// # Panics
///
/// This function does not panic.
fn make_self_signed(common_name: &str, key_seed: [u8; 32], serial: &[u8]) -> Result<Vec<u8>> {
    let private = P256PrivateKey::from_bytes(key_seed)?;
    let public = private.public_key()?;
    noxtls_write_self_signed_certificate_p256_sha256(
        serial,
        common_name,
        "240101000000Z",
        "300101000000Z",
        &public,
        &private,
    )
}

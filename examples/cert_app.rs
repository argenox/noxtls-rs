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

//! Generate matching leaf and anchor certificates and exercise hostname + chain validation APIs.

use noxtls_core::Result;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::{
    noxtls_certificate_matches_hostname, noxtls_parse_certificate, noxtls_validate_certificate_chain,
    noxtls_write_self_signed_certificate_p256_sha256,
};

/// Connect-style certificate verification demo using generated certificates.
///
/// # Arguments
///
/// _(none)_ — Uses fixed seeds and validity strings; no CLI arguments.
///
/// # Returns
///
/// `Ok(())` after printing hostname match and chain validation outcome.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when certificate issuance or parsing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let leaf_der = make_self_signed_cert("server.noxtls.local", [0x66; 32], &[0x20])?;
    let anchor_der = make_self_signed_cert("server.noxtls.local", [0x66; 32], &[0x20])?;

    let leaf = noxtls_parse_certificate(&leaf_der)?;
    let anchor = noxtls_parse_certificate(&anchor_der)?;

    let hostname_ok = noxtls_certificate_matches_hostname(&leaf, "server.noxtls.local");
    let chain_result = noxtls_validate_certificate_chain(&leaf, &[], &[anchor], "20260101000000Z");

    println!("hostname_ok={hostname_ok}");
    match chain_result {
        Ok(report) => println!("chain_ok=true chain_len={}", report.chain_len),
        Err(err) => println!("chain_ok=false reason={err}"),
    }
    Ok(())
}

/// Generates one deterministic self-signed certificate for certificate-app demos.
///
/// # Arguments
///
/// * `common_name` — Subject common name embedded in the certificate.
/// * `seed` — 32-byte private key seed passed to [`P256PrivateKey::from_bytes`].
/// * `serial` — Serial number body for the TBSCertificate.
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
fn make_self_signed_cert(common_name: &str, seed: [u8; 32], serial: &[u8]) -> Result<Vec<u8>> {
    let private = P256PrivateKey::from_bytes(seed)?;
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

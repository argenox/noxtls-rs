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

//! Example: emit a minimal self-signed P-256 certificate in DER and PEM (`cargo run -p noxtls --example cert_write`).

use noxtls_core::Result;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::{certificate_der_to_pem, write_self_signed_certificate_p256_sha256};

/// Writes a self-signed certificate in DER and PEM form using fixed demo inputs.
///
/// # Arguments
///
/// _(none)_ — No CLI arguments; serial, validity window, and keys are fixed.
///
/// # Returns
///
/// `Ok(())` after printing lengths and PEM, or an error if issuance fails.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the private key is invalid or certificate/PEM encoding fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let private = P256PrivateKey::from_bytes([0x88; 32])?;
    let public = private.public_key()?;
    let cert_der = write_self_signed_certificate_p256_sha256(
        &[0x30],
        "certwrite.noxtls.local",
        "240101000000Z",
        "300101000000Z",
        &public,
        &private,
    )?;
    let cert_pem = certificate_der_to_pem(&cert_der)?;

    println!("cert_der_len={}B", cert_der.len());
    println!("{cert_pem}");
    Ok(())
}

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

//! Example: build a deterministic P-256 CSR and print PEM (`cargo run -p noxtls --example cert_req`).

use noxtls_core::Result;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::{noxtls_der_to_pem, noxtls_write_csr_p256_sha256};

/// Generates a deterministic P-256 CSR and prints PEM output to stdout.
///
/// # Arguments
///
/// _(none)_ — Uses a fixed private scalar and common name; no CLI arguments.
///
/// # Returns
///
/// `Ok(())` after printing the CSR, or an error if key or CSR encoding fails.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the private key bytes are not a valid scalar or CSR/PEM encoding fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let private = P256PrivateKey::from_bytes([0x77; 32])?;
    let public = private.public_key()?;
    let csr_der = noxtls_write_csr_p256_sha256("csr.noxtls.local", &public, &private)?;
    let csr_pem = noxtls_der_to_pem(&csr_der, "CERTIFICATE REQUEST")?;

    println!("csr_der_len={}B", csr_der.len());
    println!("{csr_pem}");
    Ok(())
}

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

//! Load a CSR (PEM or DER) and print a short ASN.1 top-level summary.

use std::fs;

use noxtls_core::{Error, Result};
use noxtls_x509::{noxtls_parse_der_node, noxtls_pem_to_der};

/// Loads and dumps basic envelope details for a CSR file.
///
/// # Arguments
///
/// * `argv[1]` — Path to `request.der` or PEM CSR.
///
/// # Returns
///
/// `Ok(())` after printing CSR length and top-level TLV sizes, or an error.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the path is missing, the file cannot be read, PEM conversion fails, or DER parsing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let csr_path = read_csr_path()?;
    let csr_der = read_csr_der(&csr_path)?;
    let (node, tail) = noxtls_parse_der_node(&csr_der)?;

    println!("csr_len={}B", csr_der.len());
    println!("top_tag=0x{:02x}", node.tag);
    println!("top_body_len={}B", node.body.len());
    println!("tail_len={}B", tail.len());
    Ok(())
}

/// Reads the CSR path from `argv[1]` and prints usage when omitted.
///
/// # Arguments
///
/// _(none)_ — Reads `std::env::args()`.
///
/// # Returns
///
/// On success, the CSR filesystem path.
///
/// # Errors
///
/// Returns [`Error::StateError`] when the mandatory path argument is missing.
///
/// # Panics
///
/// This function does not panic.
fn read_csr_path() -> Result<String> {
    std::env::args().nth(1).ok_or_else(|| {
        eprintln!("usage: cargo run -p noxtls --example req_app -- <request.der|request.pem>");
        Error::StateError("missing CSR path argument")
    })
}

/// Loads a CSR from disk and normalizes PEM input to DER bytes.
///
/// # Arguments
///
/// * `csr_path` — Filesystem path to PEM or DER CSR bytes.
///
/// # Returns
///
/// On success, DER-encoded CSR octets suitable for `noxtls_parse_der_node`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the file cannot be read or PEM conversion fails for supported PEM labels.
///
/// # Panics
///
/// This function does not panic.
fn read_csr_der(csr_path: &str) -> Result<Vec<u8>> {
    let csr_bytes = fs::read(csr_path).map_err(|_| Error::StateError("failed to read CSR file"))?;
    if csr_bytes.starts_with(b"-----BEGIN ") {
        let csr_pem = std::str::from_utf8(&csr_bytes)
            .map_err(|_| Error::InvalidEncoding("CSR PEM must be UTF-8"))?;
        if let Ok(der) = noxtls_pem_to_der(csr_pem, "CERTIFICATE REQUEST") {
            return Ok(der);
        }
        return noxtls_pem_to_der(csr_pem, "NEW CERTIFICATE REQUEST");
    }
    Ok(csr_bytes)
}

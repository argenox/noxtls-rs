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

//! Parse a certificate from PEM or DER and print a few parsed fields.

use std::fs;

use noxtls_core::{Error, Result};
use noxtls_x509::{noxtls_certificate_pem_to_der, noxtls_parse_certificate};

/// Parses a certificate from a DER/PEM file and prints key certificate fields.
///
/// # Arguments
///
/// * `argv[1]` — Path to `cert.der` or `cert.pem`.
///
/// # Returns
///
/// `Ok(())` after printing summary fields, or an error when reading or parsing fails.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the path is missing, the file cannot be read, PEM is invalid UTF-8, or parsing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let cert_path = read_certificate_path()?;
    let cert_der = read_certificate_der(&cert_path)?;
    let cert = noxtls_parse_certificate(&cert_der)?;

    println!("version=v{}", cert.version);
    println!("serial_len={}B", cert.serial.len());
    println!("valid_from={}", cert.not_before);
    println!("valid_to={}", cert.not_after);
    println!("subject_public_key_len={}B", cert.subject_public_key.len());
    println!("san_dns_count={}", cert.subject_alt_dns_names.len());
    Ok(())
}

/// Reads the certificate path from `argv[1]` and prints usage when omitted.
///
/// # Arguments
///
/// _(none)_ — Reads `std::env::args()`.
///
/// # Returns
///
/// On success, the certificate filesystem path.
///
/// # Errors
///
/// Returns [`Error::StateError`] when the mandatory path argument is missing.
///
/// # Panics
///
/// This function does not panic.
fn read_certificate_path() -> Result<String> {
    std::env::args().nth(1).ok_or_else(|| {
        eprintln!(
            "usage: cargo run -p noxtls --example noxtls_parse_certificate -- <cert.der|cert.pem>"
        );
        Error::StateError("missing certificate path argument")
    })
}

/// Loads a certificate from disk and normalizes PEM input to DER bytes.
///
/// # Arguments
///
/// * `cert_path` — Filesystem path to PEM or DER certificate bytes.
///
/// # Returns
///
/// On success, DER-encoded certificate octets suitable for the `noxtls_parse_certificate` parser.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the file cannot be read, PEM is invalid UTF-8, or PEM conversion fails.
///
/// # Panics
///
/// This function does not panic.
fn read_certificate_der(cert_path: &str) -> Result<Vec<u8>> {
    let cert_bytes =
        fs::read(cert_path).map_err(|_| Error::StateError("failed to read certificate file"))?;
    if cert_bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let cert_pem = std::str::from_utf8(&cert_bytes)
            .map_err(|_| Error::InvalidEncoding("certificate PEM must be UTF-8"))?;
        return noxtls_certificate_pem_to_der(cert_pem);
    }
    Ok(cert_bytes)
}

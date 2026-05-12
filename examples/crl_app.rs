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

//! Example: load a CRL DER file and print a short ASN.1 top-level summary.

use std::fs;

use noxtls_core::{Error, Result};
use noxtls_x509::{parse_der_node, DerNode};

/// Loads a CRL DER file from argv and dumps top-level TLV information.
///
/// # Arguments
///
/// * `argv[1]` — Path to a DER-encoded CRL file.
///
/// # Returns
///
/// `Ok(())` after printing tag, body length, and trailing length, or an error.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the path is missing, the file cannot be read, or DER parsing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let crl_path = read_crl_path()?;
    let crl_der =
        fs::read(&crl_path).map_err(|_| Error::StateError("failed to read CRL DER file"))?;
    let (node, tail) = parse_der_node(&crl_der)?;
    dump_node_summary(&node, tail.len());
    Ok(())
}

/// Reads the CRL path from `argv[1]` and prints usage when omitted.
///
/// # Arguments
///
/// _(none)_ — Reads `std::env::args()`.
///
/// # Returns
///
/// On success, the CRL filesystem path string.
///
/// # Errors
///
/// Returns [`Error::StateError`] when the mandatory path argument is missing.
///
/// # Panics
///
/// This function does not panic.
fn read_crl_path() -> Result<String> {
    std::env::args().nth(1).ok_or_else(|| {
        eprintln!("usage: cargo run -p noxtls --example crl_app -- <crl.der>");
        Error::StateError("missing CRL path argument")
    })
}

/// Prints compact node details to help inspect CRL ASN.1 structures.
///
/// # Arguments
///
/// * `node` — Parsed top-level DER node.
/// * `tail_len` — Number of bytes remaining after the parsed node (should be `0` for a single TLV file).
///
/// # Returns
///
/// `()` after printing diagnostic lines to stdout.
///
/// # Panics
///
/// This function does not panic.
fn dump_node_summary(node: &DerNode<'_>, tail_len: usize) {
    println!("tag=0x{:02x}", node.tag);
    println!("body_len={}B", node.body.len());
    println!("tail_len={}B", tail_len);
}

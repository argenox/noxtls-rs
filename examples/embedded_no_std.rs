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

//! `std` example that prints the same `cargo check` hint used for `no_std` + `alloc` NoxTLS builds.

use noxtls_core::Result;
use noxtls_crypto::sha256;

/// Demonstrates APIs that are friendly to `no_std` + `alloc` builds when used from a hosted binary.
///
/// # Arguments
///
/// _(none)_ — No CLI arguments.
///
/// # Returns
///
/// `Ok(())` after printing a SHA-256 hex digest and a suggested `cargo check` command line.
///
/// # Errors
///
/// This entrypoint always returns `Ok(())`; hashing does not surface errors here.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let digest = sha256(b"noxtls embedded profile demo");
    println!("sha256={}", to_hex(&digest));
    println!("run_no_std_check=cargo check -p noxtls --no-default-features --features alloc");
    Ok(())
}

/// Encodes bytes into lowercase hex for predictable logging output.
///
/// # Arguments
///
/// * `bytes` — Raw digest or payload bytes to format.
///
/// # Returns
///
/// Owned lowercase hexadecimal string with two characters per input byte.
///
/// # Panics
///
/// This function does not panic.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex((byte >> 4) & 0x0f));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

/// Converts a 4-bit nibble into an ASCII lowercase hex character.
///
/// # Arguments
///
/// * `nibble` — Value in `0..=15`.
///
/// # Returns
///
/// ASCII hex digit for that nibble.
///
/// # Panics
///
/// This function does not panic for inputs produced by `to_hex` (always in range).
fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

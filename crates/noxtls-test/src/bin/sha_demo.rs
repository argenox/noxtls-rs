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

//! Prints a SHA-256 digest of a short static payload for quick crypto sanity checks.

use noxtls_crypto::sha256;

/// Computes `SHA256(b"noxtls")` and prints the digest as hex to stdout.
///
/// # Arguments
///
/// _(none)_ — No CLI arguments are read.
///
/// # Returns
///
/// Does not return a value to the caller; terminates the process after printing.
///
/// # Panics
///
/// This function does not panic.
fn main() {
    let digest = sha256(b"noxtls");
    println!("{:02x?}", digest);
}

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

//! Micro-benchmark binary for SHA-256 and ChaCha20 throughput on fixed 1 MiB buffers.

use std::time::Instant;

use noxtls_crypto::{noxtls_sha256, ChaCha20};

/// Runs SHA-256 and ChaCha20 timing loops and prints millisecond totals to stdout.
///
/// # Arguments
///
/// _(none)_ — Parses no CLI arguments; behavior is fixed.
///
/// # Returns
///
/// Does not return a value to the caller; terminates the process after printing timings.
///
/// # Panics
///
/// Panics if ChaCha20 keystream application fails unexpectedly (see `.expect` in the ChaCha20 loop).
fn main() {
    let data = vec![0x5a_u8; 1 << 20];
    let start = Instant::now();
    for _ in 0..256 {
        let _ = noxtls_sha256(&data);
    }
    let sha_time = start.elapsed();
    println!("sha256_1mib_x256_ms={}", sha_time.as_millis());

    let key = [0x11_u8; 32];
    let nonce = [0x22_u8; 12];
    let mut stream = vec![0_u8; data.len()];
    let start = Instant::now();
    for _ in 0..256 {
        let mut cipher = ChaCha20::noxtls_new(&key, &nonce, 1);
        cipher
            .apply_keystream(&data, &mut stream)
            .expect("chacha20 must complete");
    }
    let chacha_time = start.elapsed();
    println!("chacha20_1mib_x256_ms={}", chacha_time.as_millis());
}

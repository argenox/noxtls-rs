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

//! Tiny TCP listener: accept one client, read a small request buffer, write a fixed HTTP-style response.

use std::io::{Read, Write};
use std::net::TcpListener;

use noxtls_core::{Error, Result};

/// Serves one TCP client and returns a fixed HTTPS-style response payload.
///
/// # Arguments
///
/// * `argv[1]` — Optional bind address (default `127.0.0.1:8443`).
///
/// # Returns
///
/// `Ok(())` after one accept/read/write cycle, or an error when networking fails.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when binding, accepting, reading, or writing fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".to_owned());
    let listener = TcpListener::bind(&bind_addr)
        .map_err(|_| Error::StateError("failed to bind TCP listener"))?;
    println!("listening={bind_addr}");

    let (mut stream, peer) = listener
        .accept()
        .map_err(|_| Error::StateError("failed to accept TCP client"))?;
    let mut request = [0_u8; 1024];
    let len = stream
        .read(&mut request)
        .map_err(|_| Error::StateError("failed to read TCP request"))?;
    println!("peer={peer} request={}B", len);

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nnoxtls tls_server fixed reply";
    stream
        .write_all(response)
        .map_err(|_| Error::StateError("failed to write TCP response"))?;
    Ok(())
}

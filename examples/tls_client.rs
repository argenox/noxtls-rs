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

//! Minimal TLS 1.3 client: complete the modeled handshake, then seal and open one application record.

use noxtls::{CipherSuite, Connection, TlsVersion};
use noxtls_core::Result;

/// Demonstrates a compact TLS 1.3 client flow and protected application record roundtrip.
///
/// # Arguments
///
/// _(none)_ — Uses fixed random and canned `ServerHello` bytes.
///
/// # Returns
///
/// `Ok(())` after printing plaintext and ciphertext sizes, or an error when handshake or record operations fail.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when any modeled handshake or AEAD step fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let mut conn = establish_tls13_session()?;
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let protected = conn.seal_record(request, b"http-request")?;
    let opened = conn.open_own_record(&protected, b"http-request")?;

    println!("request_plaintext={}B", request.len());
    println!("record_ciphertext={}B", protected.ciphertext.len());
    println!("opened_payload={}", String::from_utf8_lossy(&opened));
    Ok(())
}

/// Creates a TLS 1.3 [`Connection`] that has completed the handshake state machine through `Finished`.
///
/// # Arguments
///
/// _(none)_ — Uses fixed client random and server handshake material.
///
/// # Returns
///
/// On success, a client connection ready for application traffic keys.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when any handshake step fails.
///
/// # Panics
///
/// This function does not panic.
fn establish_tls13_session() -> Result<Connection> {
    let mut conn = Connection::new(TlsVersion::Tls13);
    let client_hello = conn.send_client_hello(&[0x11; 32])?;
    let server_hello = Connection::build_server_hello(
        TlsVersion::Tls13,
        CipherSuite::TlsAes256GcmSha384,
        &[0x22; 32],
    )?;
    conn.recv_server_hello(&server_hello)?;
    let verify = conn.compute_finished_verify_data()?;
    conn.finish(&verify)?;
    println!("client_hello_bytes={}", client_hello.len());
    Ok(conn)
}

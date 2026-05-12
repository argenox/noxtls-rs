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

//! Minimal UDP client that sends one datagram and prints one reply (DTLS-style smoke test).

use std::net::UdpSocket;
use std::time::Duration;

use noxtls_core::{Error, Result};

/// Sends one datagram to a DTLS-style test server and reads one response datagram.
///
/// # Arguments
///
/// * `argv[1]` — Optional `host:port` server address (default `127.0.0.1:4444`).
///
/// # Returns
///
/// `Ok(())` after printing send/receive summaries, or an error when sockets or I/O fail.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when binding, timeouts, send, or receive operations fail.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4444".to_owned());
    let socket = UdpSocket::bind("127.0.0.1:0")
        .map_err(|_| Error::StateError("failed to bind UDP client socket"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::StateError("failed to set UDP client timeout"))?;

    let outbound = b"noxtls dtls_client hello";
    socket
        .send_to(outbound, &server)
        .map_err(|_| Error::StateError("failed to send UDP datagram"))?;

    let mut recv = [0_u8; 1500];
    let (len, from) = socket
        .recv_from(&mut recv)
        .map_err(|_| Error::StateError("failed to receive UDP datagram"))?;

    println!("sent={}B server={server}", outbound.len());
    println!("received={}B from={from}", len);
    println!("payload={}", String::from_utf8_lossy(&recv[..len]));
    Ok(())
}

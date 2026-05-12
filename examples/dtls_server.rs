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

//! Minimal UDP server that receives one datagram and echoes a fixed reply (DTLS-style smoke test).

use std::net::UdpSocket;

use noxtls_core::{Error, Result};

/// Waits for one datagram and replies with one datagram to the sender.
///
/// # Arguments
///
/// * `argv[1]` — Optional bind address (default `127.0.0.1:4444`).
///
/// # Returns
///
/// `Ok(())` after one receive/send pair, or an error when sockets or I/O fail.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when binding, receiving, or sending fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4444".to_owned());
    let socket = UdpSocket::bind(&bind_addr)
        .map_err(|_| Error::StateError("failed to bind UDP server socket"))?;

    let mut recv = [0_u8; 1500];
    let (len, from) = socket
        .recv_from(&mut recv)
        .map_err(|_| Error::StateError("failed to receive UDP datagram"))?;
    println!("received={}B from={from}", len);
    println!("payload={}", String::from_utf8_lossy(&recv[..len]));

    let response = b"noxtls dtls_server response";
    socket
        .send_to(response, from)
        .map_err(|_| Error::StateError("failed to send UDP response"))?;
    println!("sent={}B", response.len());
    Ok(())
}

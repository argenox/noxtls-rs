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

//! Exercises a modeled TLS 1.3 client session: record seal/open, fragmentation, and certificate-auth errors.

use noxtls::{CipherSuite, Connection, TlsVersion};

/// Runs the TLS 1.3 demo: handshake to `Finished`, record APIs, and certificate-auth failure cases.
///
/// # Arguments
///
/// _(none)_ — No CLI arguments are read.
///
/// # Returns
///
/// Does not return a value to the caller; terminates the process after printing demo output.
///
/// # Panics
///
/// Panics if any modeled handshake or record step that uses `.expect(...)` fails unexpectedly.
fn main() {
    let mut conn = establish_tls13_session();

    let app_record = conn
        .seal_record(b"demo-application-data", b"tls13-header")
        .expect("record seal should succeed");
    let app_plaintext = conn
        .open_own_record(&app_record, b"tls13-header")
        .expect("record open should succeed");
    println!(
        "single_record_plaintext={}",
        String::from_utf8_lossy(&app_plaintext)
    );

    let fragment_payload = b"fragmented-payload-through-record-layer";
    let fragments = conn
        .seal_record_fragments(fragment_payload, b"tls13-header", 10)
        .expect("fragmented seal should succeed");
    let reassembled = conn
        .open_own_record_fragments(&fragments, b"tls13-header")
        .expect("fragmented open should succeed");
    println!(
        "fragment_count={} reassembled={}",
        fragments.len(),
        String::from_utf8_lossy(&reassembled)
    );

    let mut tampered = fragments.clone();
    if tampered.len() > 1 {
        tampered[1].sequence = tampered[1].sequence.saturating_add(1);
        let err = conn
            .open_own_record_fragments(&tampered, b"tls13-header")
            .expect_err("non-contiguous fragments should fail");
        println!("fragment_order_error={err}");
    }

    run_tls13_certificate_auth_failure_scenarios();
}

/// Builds a [`Connection`] in `Finished` state after a minimal TLS 1.3 handshake for record-layer demos.
///
/// # Arguments
///
/// _(none)_ — Uses fixed random bytes and built-in server messages.
///
/// # Returns
///
/// A client [`Connection`] ready to seal and open application records.
///
/// # Panics
///
/// Panics if any intermediate `send_client_hello`, `recv_server_hello`, secret derivation, or `finish` step fails.
fn establish_tls13_session() -> Connection {
    let mut conn = Connection::new(TlsVersion::Tls13);
    let client_hello = conn
        .send_client_hello(&[0x42; 32])
        .expect("client hello should succeed");
    let server_hello = Connection::build_server_hello(
        TlsVersion::Tls13,
        CipherSuite::TlsAes256GcmSha384,
        &[0x24; 32],
    )
    .expect("server hello build should succeed");
    conn.recv_server_hello(&server_hello)
        .expect("server hello should succeed");
    let secret = conn
        .derive_handshake_secret()
        .expect("secret derivation should succeed");
    let verify = conn
        .compute_finished_verify_data()
        .expect("finished verify_data should compute");
    conn.finish(&verify).expect("finish should succeed");
    println!("client_hello_bytes={}", client_hello.len());
    println!("handshake_secret_head={:02x?}", &secret[..8]);
    conn
}

/// Prints expected error paths for strict TLS 1.3 certificate authentication configuration.
///
/// # Arguments
///
/// _(none)_ — Uses fixed malformed certificate material and controlled connection states.
///
/// # Returns
///
/// `()` after printing error summaries for missing anchors, malformed chains, and premature verify.
///
/// # Panics
///
/// Panics if constructing certificate messages or any `.expect` setup path fails.
fn run_tls13_certificate_auth_failure_scenarios() {
    let malformed_leaf = [0x30, 0x03, 0x02, 0x01, 0x01];
    let certificate_msg = Connection::build_certificate_message(&malformed_leaf)
        .expect("certificate message should build");

    let mut missing_anchors = establish_tls13_post_encrypted_extensions();
    missing_anchors.set_tls13_require_certificate_auth(true);
    let missing_anchors_err = missing_anchors
        .recv_certificate(&certificate_msg)
        .expect_err("strict auth without trust anchors should fail");
    println!("cert_auth_missing_anchor_error={missing_anchors_err}");

    let mut malformed_chain = establish_tls13_post_encrypted_extensions();
    malformed_chain.set_tls13_require_certificate_auth(true);
    malformed_chain
        .configure_tls13_server_auth(&[vec![0x30, 0x00]], &[], "20250101000000Z")
        .expect("server auth configuration should succeed");
    let malformed_leaf_err = malformed_chain
        .recv_certificate(&certificate_msg)
        .expect_err("malformed certificate should fail parsing");
    println!("cert_auth_malformed_leaf_error={malformed_leaf_err}");

    let mut cert_verify_chain = establish_tls13_post_encrypted_extensions();
    cert_verify_chain.set_tls13_require_certificate_auth(true);
    cert_verify_chain.state = noxtls::HandshakeState::ServerCertificateReceived;
    let cert_verify_msg = Connection::build_certificate_verify_message(0x0804, &[0xAA, 0xBB, 0xCC])
        .expect("certificate verify message should build");
    let cert_verify_err = cert_verify_chain
        .recv_certificate_verify(&cert_verify_msg)
        .expect_err("certificate verify without validated chain should fail");
    println!("cert_verify_without_chain_error={cert_verify_err}");
}

/// Advances a fresh TLS 1.3 client through `EncryptedExtensions` and returns the connection for auth tests.
///
/// # Arguments
///
/// _(none)_ — Uses fixed random values and canned server handshake bytes.
///
/// # Returns
///
/// A [`Connection`] whose state is suitable for injecting certificate and verify handshake messages.
///
/// # Panics
///
/// Panics if `ClientHello`, `ServerHello`, or `EncryptedExtensions` handling fails.
fn establish_tls13_post_encrypted_extensions() -> Connection {
    let mut conn = Connection::new(TlsVersion::Tls13);
    conn.send_client_hello(&[0x77; 32])
        .expect("client hello should succeed");
    let server_hello = Connection::build_server_hello(
        TlsVersion::Tls13,
        CipherSuite::TlsAes256GcmSha384,
        &[0x88; 32],
    )
    .expect("server hello build should succeed");
    conn.recv_server_hello(&server_hello)
        .expect("server hello should succeed");
    let encrypted_extensions = Connection::build_encrypted_extensions();
    conn.recv_encrypted_extensions(&encrypted_extensions)
        .expect("encrypted extensions should succeed");
    conn
}

// Copyright (c) 2019-2026, Argenox Technologies LLC
// All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only OR LicenseRef-Argenox-Commercial-License
//
// This file is part of the NoxTLS Library.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// Alternatively, this file may be used under the terms of a commercial
// license from Argenox Technologies LLC.
//
// See `noxtls/LICENSE` and `noxtls/LICENSE.md` in this repository for full details.
// CONTACT: info@argenox.com

//! Regression tests for TLS record nonces and DTLS 1.2 reassembly semantics.
//!
//! Evidence for `VULNERABILITY_ANALYSIS_TLS_CRYPTO_MATRIX.md` (repository root).

use super::dtls::noxtls_encode_dtls12_handshake_fragments;
use super::dtls::noxtls_reassemble_dtls12_handshake_fragments;
use super::record::noxtls_build_record_nonce;
use super::{
    CipherSuite, Connection, HandshakeState, ProtectedRecord, RecordContentType,
    Tls13ServerIdentityKey, TlsVersion,
};
use noxtls_core::Error;
use noxtls_crypto::P256PrivateKey;
use noxtls_x509::noxtls_write_self_signed_certificate_p256_sha256;

/// Builds one DTLS 1.2 handshake fragment wire encoding for tests.
///
/// # Arguments
///
/// * `handshake_type` — Wire handshake type byte.
/// * `message_len` — Total reconstructed handshake body length.
/// * `message_seq` — DTLS `message_seq` for this message.
/// * `fragment_offset` — Byte offset of this fragment in the full message.
/// * `fragment_body` — Payload bytes for this fragment.
///
/// # Returns
///
/// Owned `header || body` bytes.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
fn dtls12_test_fragment(
    handshake_type: u8,
    message_len: u32,
    message_seq: u16,
    fragment_offset: u32,
    fragment_body: &[u8],
) -> Vec<u8> {
    const HDR: usize = 12;
    let fragment_len = fragment_body.len() as u32;
    let mut v = Vec::with_capacity(HDR + fragment_body.len());
    v.push(handshake_type);
    v.push(((message_len >> 16) & 0xFF) as u8);
    v.push(((message_len >> 8) & 0xFF) as u8);
    v.push((message_len & 0xFF) as u8);
    v.extend_from_slice(&message_seq.to_be_bytes());
    v.push(((fragment_offset >> 16) & 0xFF) as u8);
    v.push(((fragment_offset >> 8) & 0xFF) as u8);
    v.push((fragment_offset & 0xFF) as u8);
    v.push(((fragment_len >> 16) & 0xFF) as u8);
    v.push(((fragment_len >> 8) & 0xFF) as u8);
    v.push((fragment_len & 0xFF) as u8);
    v.extend_from_slice(fragment_body);
    v
}

/// Verifies TLS 1.3 record nonce construction XORs the big-endian sequence into IV bytes 4..12.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn tls13_record_nonce_xor_matches_sequence() {
    let base = [0_u8; 12];
    let seq = 0x0102_0304_0506_0708_u64;
    let nonce = noxtls_build_record_nonce(&base, seq);
    let expected = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(nonce, expected);
}

/// Verifies non-overlapping DTLS 1.2 fragments reassemble to the original body.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn dtls12_reassemble_non_overlapping_round_trip() {
    let body = b"hello-dtls-reassembly".to_vec();
    let frags = noxtls_encode_dtls12_handshake_fragments(0x01, 0_u16, &body, 7).expect("encode");
    let (_, _, got) =
        noxtls_reassemble_dtls12_handshake_fragments(&frags, 65_536).expect("reassemble");
    assert_eq!(got, body);
}

/// Documents that overlapping fragment ranges keep the **last** applied bytes (defense / spec review).
///
/// # Panics
///
/// This function does not panic.
#[test]
fn dtls12_reassemble_overlapping_last_write_wins() {
    let message_len = 4_u32;
    let seq = 3_u16;
    let f1 = dtls12_test_fragment(0x0B, message_len, seq, 0, b"AA");
    let f2 = dtls12_test_fragment(0x0B, message_len, seq, 0, b"BB");
    let f3 = dtls12_test_fragment(0x0B, message_len, seq, 2, b"CC");
    let got =
        noxtls_reassemble_dtls12_handshake_fragments(&[f1, f2, f3], 65_536).expect("reassemble");
    assert_eq!(got.2, b"BBCC".as_slice());
}

/// Verifies TLS 1.3 interop profile emits classical-only offers used for live HTTPS compatibility.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn tls13_client_hello_interop_profile_uses_expected_groups_and_schemes() {
    let mut connection = Connection::noxtls_new(TlsVersion::Tls13);
    connection.noxtls_set_tls13_client_offer_pq_key_shares(false);
    connection.noxtls_set_tls13_client_offer_mldsa_signature(false);
    connection
        .noxtls_set_tls13_client_cipher_suites(&[CipherSuite::TlsAes128GcmSha256])
        .expect("set tls13 cipher override");
    let client_hello = connection
        .noxtls_send_client_hello(&[0x11_u8; 32])
        .expect("build client hello");

    let parsed = Connection::noxtls_parse_client_hello_info(&client_hello).expect("parse client hello");

    assert_eq!(
        parsed.offered_cipher_suites,
        vec![CipherSuite::TlsAes128GcmSha256]
    );
    assert_eq!(parsed.extensions.key_share_groups, vec![0x001D, 0x0017]);
    assert!(parsed.extensions.supported_versions.contains(&0x0304));
    assert!(parsed.extensions.supported_versions.contains(&0x0303));
    assert!(!parsed.extensions.signature_algorithms.contains(&0x0905));
}

/// Verifies TLS 1.3 encrypted handshake records remain openable after EncryptedExtensions processing.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn tls13_open_record_allowed_in_server_certificate_verified_state() {
    let states = [
        HandshakeState::KeysDerived,
        HandshakeState::ServerEncryptedExtensionsReceived,
        HandshakeState::ServerCertificateRequestReceived,
        HandshakeState::ServerCertificateReceived,
        HandshakeState::ServerCertificateVerified,
    ];
    for state in states {
        let mut connection = Connection::noxtls_new(TlsVersion::Tls13);
        connection.state = state;
        let record = ProtectedRecord {
            sequence: 0,
            ciphertext: vec![0_u8; 1],
            tag: [0_u8; 16],
        };

        let result = connection.noxtls_open_record(&record, &[]);
        assert!(result.is_err());
        let error = result.expect_err("record opening should fail without traffic keys");
        match error {
            Error::StateError(message) => {
                assert_ne!(message, "cannot open record before handshake noxtls_finish");
            }
            _ => {}
        }
    }
}

/// Verifies TLS 1.3 application traffic activation is gated until Finished state.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn tls13_application_key_activation_requires_finished_state() {
    let mut connection = Connection::noxtls_new(TlsVersion::Tls13);
    let error = connection
        .noxtls_activate_tls13_application_traffic_keys()
        .expect_err("activation should fail before Finished");
    match error {
        Error::StateError(message) => {
            assert_eq!(
                message,
                "application traffic keys can only be activated in finished state"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

/// Verifies TLS 1.3 server-role APIs complete a handshake roundtrip with a noxtls client.
///
/// # Panics
///
/// This function does not panic.
#[test]
fn tls13_server_role_handshake_roundtrip_with_noxtls_client() {
    let private_key =
        P256PrivateKey::from_bytes([0x11_u8; 32]).expect("p256 private key fixture should parse");
    let public_key = private_key.public_key().expect("p256 public key");
    let cert_der = noxtls_write_self_signed_certificate_p256_sha256(
        &[0x01],
        "localhost",
        "20200101000000Z",
        "20300101000000Z",
        &public_key,
        &private_key,
    )
    .expect("self-signed certificate should build");

    let mut client = Connection::noxtls_new(TlsVersion::Tls13);
    client.noxtls_set_tls13_client_offer_pq_key_shares(false);
    client
        .noxtls_set_tls13_client_cipher_suites(&[CipherSuite::TlsAes128GcmSha256])
        .expect("set client cipher suites");
    let client_hello = client
        .noxtls_send_client_hello(&[0x22_u8; 32])
        .expect("client hello should build");

    let mut server = Connection::noxtls_new_tls13_server();
    server
        .noxtls_configure_tls13_server_identity(
            &[cert_der],
            Tls13ServerIdentityKey::P256(private_key),
        )
        .expect("server identity should configure");
    let server_hello = server
        .noxtls_accept_tls13_client_hello(&client_hello, &[0x33_u8; 32])
        .expect("server should accept client hello");

    client
        .noxtls_recv_server_hello(&server_hello)
        .expect("client should process server hello");
    server
        .noxtls_derive_handshake_secret()
        .expect("server should derive handshake secret");
    let flight_packet = server
        .noxtls_build_tls13_server_handshake_flight()
        .expect("server handshake flight should build");
    let flight_aad = Connection::noxtls_tls13_packet_header_aad(&flight_packet)
        .expect("server flight packet header should parse");
    client
        .noxtls_process_tls13_server_encrypted_handshake_flight(&[flight_packet.clone()], &flight_aad)
        .expect("client should process encrypted server flight");
    assert_eq!(client.state, HandshakeState::Finished);

    let client_finished = client
        .noxtls_prepare_tls13_client_finished_message()
        .expect("client finished should build");
    let inner_len = client_finished
        .len()
        .checked_add(1)
        .expect("client finished inner length");
    let payload_len = inner_len
        .checked_add(16)
        .expect("client finished ciphertext length");
    let mut client_finished_aad = [0_u8; 5];
    client_finished_aad[0] = RecordContentType::ApplicationData.to_u8();
    client_finished_aad[1] = 0x03;
    client_finished_aad[2] = 0x03;
    client_finished_aad[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
    let client_finished_packet = client
        .noxtls_seal_tls13_record_packet(
            &client_finished,
            RecordContentType::Handshake.to_u8(),
            &client_finished_aad,
            0,
        )
        .expect("client finished packet should seal");
    server
        .noxtls_recv_client_finished_packet(&client_finished_packet)
        .expect("server should accept client finished");
    assert_eq!(server.state, HandshakeState::Finished);
}

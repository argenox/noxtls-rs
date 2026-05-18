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

//! Minimal TLS 1.3 HTTPS server that returns HTML showing the negotiated cipher suite.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noxtls::{
    Connection, HandshakeState, RecordContentType, Tls13ServerIdentityKey, TlsRecordDeframer,
    TLS_RECORD_HEADER_LEN,
};
use noxtls_core::{Error, Result};
use noxtls_pem::noxtls_pem_file_to_der_blocks;
use noxtls_x509::{
    noxtls_certificate_pem_to_der, noxtls_ec_private_key_pem_to_der_sec1,
    noxtls_p256_private_key_from_pem_pkcs8, noxtls_p256_private_key_from_pem_sec1,
    noxtls_private_key_pem_to_der_pkcs8, noxtls_rsa_private_key_from_pem_pkcs1,
    noxtls_rsa_private_key_from_pem_pkcs8,
};

const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
const TLS_RECORD_TYPE_APPLICATION_DATA: u8 = 23;
const TLS13_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8443";
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Parsed CLI options for the HTTPS server example.
#[derive(Debug, Clone)]
struct ServerConfig {
    bind_addr: String,
    cert_path: String,
    key_path: String,
    once: bool,
    timeout: Duration,
}

/// Runs the HTTPS server example using CLI-provided certificate and key paths.
///
/// # Arguments
///
/// * `argv` — Process arguments with `--bind`, `--cert`, `--key`, and optional `--once`.
///
/// # Returns
///
/// `Ok(())` after serving at least one connection unless `--once` limits the run.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when networking, PEM loading, or TLS handshake steps fail.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let config = parse_cli(std::env::args().collect())?;
    run_https_server(&config)
}

/// Parses CLI arguments into [`ServerConfig`].
///
/// # Arguments
///
/// * `args` — Raw process argument vector including executable name.
///
/// # Returns
///
/// On success, parsed server configuration.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when required options are missing or invalid.
///
/// # Panics
///
/// This function does not panic.
fn parse_cli(args: Vec<String>) -> Result<ServerConfig> {
    if args.len() < 2 {
        print_usage(args.first().map_or("tls_server", String::as_str));
        return Err(Error::InvalidLength("missing required arguments"));
    }

    let mut bind_addr = DEFAULT_BIND_ADDR.to_owned();
    let mut cert_path: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut once = false;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut index = 1_usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--bind" {
            index += 1;
            bind_addr = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --bind value"))?
                .clone();
        } else if let Some(value) = arg.strip_prefix("--bind=") {
            bind_addr = value.to_owned();
        } else if arg == "--cert" {
            index += 1;
            cert_path = Some(
                args.get(index)
                    .ok_or(Error::ParseFailure("missing --cert value"))?
                    .clone(),
            );
        } else if let Some(value) = arg.strip_prefix("--cert=") {
            cert_path = Some(value.to_owned());
        } else if arg == "--key" {
            index += 1;
            key_path = Some(
                args.get(index)
                    .ok_or(Error::ParseFailure("missing --key value"))?
                    .clone(),
            );
        } else if let Some(value) = arg.strip_prefix("--key=") {
            key_path = Some(value.to_owned());
        } else if arg == "--once" {
            once = true;
        } else if arg == "--timeout-ms" {
            index += 1;
            let value = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --timeout-ms value"))?;
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| Error::ParseFailure("invalid --timeout-ms value"))?;
        } else if let Some(value) = arg.strip_prefix("--timeout-ms=") {
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| Error::ParseFailure("invalid --timeout-ms value"))?;
        } else {
            return Err(Error::ParseFailure(
                "unknown argument (expected --bind, --cert, --key, --once, --timeout-ms)",
            ));
        }
        index += 1;
    }

    Ok(ServerConfig {
        bind_addr,
        cert_path: cert_path.ok_or(Error::ParseFailure("missing --cert path"))?,
        key_path: key_path.ok_or(Error::ParseFailure("missing --key path"))?,
        once,
        timeout: Duration::from_millis(timeout_ms),
    })
}

/// Prints CLI usage for the HTTPS server example.
///
/// # Arguments
///
/// * `exe_name` — Executable name shown in usage output.
///
/// # Returns
///
/// `()`.
///
/// # Panics
///
/// This function does not panic.
fn print_usage(exe_name: &str) {
    println!("usage:");
    println!(
        "  cargo run -p noxtls --example {exe_name} -- --cert server.pem --key server.key [--bind=127.0.0.1:8443] [--once] [--timeout-ms=10000]"
    );
}

/// Binds a TCP listener and serves HTTPS responses until `--once` stops the loop.
///
/// # Arguments
///
/// * `config` — Parsed server configuration.
///
/// # Returns
///
/// `Ok(())` after the configured accept loop completes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when bind/accept or per-connection handling fails.
///
/// # Panics
///
/// This function does not panic.
fn run_https_server(config: &ServerConfig) -> Result<()> {
    let identity = load_server_identity(&config.cert_path, &config.key_path)?;
    let listener = TcpListener::bind(&config.bind_addr)
        .map_err(|_| Error::StateError("failed to bind TCP listener"))?;
    println!("listening={}", config.bind_addr);
    loop {
        let (stream, peer) = listener
            .accept()
            .map_err(|_| Error::StateError("failed to accept TCP client"))?;
        println!("peer={peer}");
        if let Err(error) = serve_tls_connection(stream, &identity, config.timeout) {
            eprintln!("connection_error={error}");
        }
        if config.once {
            break;
        }
    }
    Ok(())
}

/// Loaded server certificate chain and signing key.
#[derive(Debug, Clone)]
struct ServerIdentity {
    certificate_chain_der: Vec<Vec<u8>>,
    signing_key: Tls13ServerIdentityKey,
}

/// Loads PEM certificate chain and flexible-format private key material.
///
/// # Arguments
///
/// * `cert_path` — PEM file containing one or more `CERTIFICATE` blocks.
/// * `key_path` — PEM private key file (`PRIVATE KEY`, `EC PRIVATE KEY`, or `RSA PRIVATE KEY`).
///
/// # Returns
///
/// On success, parsed certificate chain and signing key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when files cannot be read or key format is unsupported.
///
/// # Panics
///
/// This function does not panic.
fn load_server_identity(cert_path: &str, key_path: &str) -> Result<ServerIdentity> {
    let certificate_chain_der = load_certificate_chain_from_pem(cert_path)?;
    let signing_key = load_signing_key_from_pem(key_path)?;
    Ok(ServerIdentity {
        certificate_chain_der,
        signing_key,
    })
}

/// Reads a PEM certificate chain into DER blocks.
///
/// # Arguments
///
/// * `cert_path` — Filesystem path to PEM certificates.
///
/// # Returns
///
/// On success, DER-encoded certificates in source order.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the PEM file cannot be parsed.
///
/// # Panics
///
/// This function does not panic.
fn load_certificate_chain_from_pem(cert_path: &str) -> Result<Vec<Vec<u8>>> {
    let blocks = noxtls_pem_file_to_der_blocks(Path::new(cert_path), "CERTIFICATE")
        .map_err(|_| Error::ParseFailure("failed to parse certificate PEM file"))?;
    if blocks.is_empty() {
        return Err(Error::InvalidLength(
            "certificate file does not contain any CERTIFICATE blocks",
        ));
    }
    Ok(blocks)
}

/// Loads a private key from PEM, trying PKCS#8, SEC1, and PKCS#1 RSA encodings.
///
/// # Arguments
///
/// * `key_path` — Filesystem path to a PEM-encoded private key.
///
/// # Returns
///
/// On success, parsed [`Tls13ServerIdentityKey`].
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when no supported PEM label parses successfully.
///
/// # Panics
///
/// This function does not panic.
fn load_signing_key_from_pem(key_path: &str) -> Result<Tls13ServerIdentityKey> {
    let pem_bytes = fs::read(key_path).map_err(|_| Error::StateError("failed to read key file"))?;
    let pem_text = std::str::from_utf8(&pem_bytes)
        .map_err(|_| Error::InvalidEncoding("private key PEM must be UTF-8"))?;

    if pem_text.contains("BEGIN PRIVATE KEY") {
        let der = noxtls_private_key_pem_to_der_pkcs8(pem_text)?;
        if let Ok(key) = noxtls_p256_private_key_from_pem_pkcs8(pem_text) {
            return Ok(Tls13ServerIdentityKey::P256(key));
        }
        let rsa = noxtls_rsa_private_key_from_pem_pkcs8(pem_text)
            .map_err(|_| Error::ParseFailure("unsupported PKCS#8 private key algorithm"))?;
        let _ = der;
        return Ok(Tls13ServerIdentityKey::Rsa(rsa));
    }
    if pem_text.contains("BEGIN EC PRIVATE KEY") {
        let _der = noxtls_ec_private_key_pem_to_der_sec1(pem_text)?;
        let key = noxtls_p256_private_key_from_pem_sec1(pem_text)?;
        return Ok(Tls13ServerIdentityKey::P256(key));
    }
    if pem_text.contains("BEGIN RSA PRIVATE KEY") {
        let rsa = noxtls_rsa_private_key_from_pem_pkcs1(pem_text)?;
        return Ok(Tls13ServerIdentityKey::Rsa(rsa));
    }

    if let Ok(text) = std::str::from_utf8(&pem_bytes) {
        if text.contains("BEGIN CERTIFICATE") {
            let der = noxtls_certificate_pem_to_der(text)?;
            let _ = der;
        }
    }

    Err(Error::ParseFailure(
        "unsupported private key format (expected PKCS#8, SEC1 EC, or PKCS#1 RSA PEM)",
    ))
}

/// Completes one TLS 1.3 handshake and returns an HTML page with the negotiated suite.
///
/// # Arguments
///
/// * `stream` — Connected TCP stream for the client.
/// * `identity` — Server certificate chain and signing key.
/// * `timeout` — Per-read timeout for socket operations.
///
/// # Returns
///
/// `Ok(())` after the HTML response is written to the client.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when handshake or HTTP response steps fail.
///
/// # Panics
///
/// This function does not panic.
fn serve_tls_connection(
    mut stream: TcpStream,
    identity: &ServerIdentity,
    timeout: Duration,
) -> Result<()> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| Error::StateError("failed to configure read timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| Error::StateError("failed to configure write timeout"))?;

    let mut conn = Connection::noxtls_new_tls13_server();
    conn.noxtls_configure_tls13_server_identity(
        &identity.certificate_chain_der,
        identity.signing_key.clone(),
    )?;
    conn.noxtls_set_tls13_server_alpn_protocols(&[b"http/1.1"])?;

    let client_hello_record = read_handshake_record(&mut stream)?;
    let client_hello = extract_handshake_message(&client_hello_record, 1)?;
    let server_random = build_server_random_seed();
    let server_hello = conn.noxtls_accept_tls13_client_hello(&client_hello, &server_random)?;
    let server_hello_record =
        encode_tls13_handshake_record(&server_hello, TLS13_RECORD_LEGACY_VERSION)?;
    stream
        .write_all(&server_hello_record)
        .map_err(|_| Error::StateError("failed to send server hello record"))?;

    conn.noxtls_derive_handshake_secret()?;
    let server_flight = conn.noxtls_build_tls13_server_handshake_flight()?;
    stream
        .write_all(&server_flight)
        .map_err(|_| Error::StateError("failed to send server handshake flight"))?;

    let client_finished_record = read_application_data_record(&mut stream)?;
    conn.noxtls_recv_client_finished_packet(&client_finished_record)?;
    conn.noxtls_activate_tls13_application_traffic_keys()?;
    if conn.state != HandshakeState::Finished {
        return Err(Error::StateError("tls handshake did not reach finished state"));
    }

    let suite_name = conn
        .noxtls_cipher_suite_display_name()
        .unwrap_or("unknown");
    println!("negotiated_cipher_suite={suite_name}");

    let mut request_buf = Vec::new();
    read_http_request(&mut stream, &mut conn, &mut request_buf)?;
    println!("http_request_bytes={}", request_buf.len());

    let body = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>noxtls https_server</title></head><body><h1>Negotiated cipher suite</h1><p>{suite_name}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response_packet = seal_tls13_application_packet(&mut conn, response.as_bytes())?;
    stream
        .write_all(&response_packet)
        .map_err(|_| Error::StateError("failed to send encrypted http response"))?;
    println!("http_response_bytes={}", response.len());
    Ok(())
}

/// Reads one plaintext handshake record from the TCP stream.
///
/// # Arguments
///
/// * `stream` — Connected client TCP stream.
///
/// # Returns
///
/// On success, raw TLS record bytes for one handshake packet.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when framing or socket I/O fails.
///
/// # Panics
///
/// This function does not panic.
fn read_handshake_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut deframer = TlsRecordDeframer::noxtls_new();
    read_tls_record_with_deframer(stream, &mut deframer, TLS_RECORD_TYPE_HANDSHAKE)
}

/// Reads one TLS 1.3 application-data record from the TCP stream.
///
/// # Arguments
///
/// * `stream` — Connected client TCP stream.
///
/// # Returns
///
/// On success, raw TLS record bytes for one application-data packet.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when framing or socket I/O fails.
///
/// # Panics
///
/// This function does not panic.
fn read_application_data_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut deframer = TlsRecordDeframer::noxtls_new();
    read_tls_record_with_deframer(stream, &mut deframer, TLS_RECORD_TYPE_APPLICATION_DATA)
}

/// Reads HTTP request bytes from encrypted application-data records.
///
/// # Arguments
///
/// * `stream` — Connected client TCP stream.
/// * `conn` — Finished TLS server connection.
/// * `request_buf` — Output buffer receiving decrypted HTTP request bytes.
///
/// # Returns
///
/// `Ok(())` after at least part of the HTTP request has been read.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when record decryption fails.
///
/// # Panics
///
/// This function does not panic.
fn read_http_request(
    stream: &mut TcpStream,
    conn: &mut Connection,
    request_buf: &mut Vec<u8>,
) -> Result<()> {
    let mut deframer = TlsRecordDeframer::noxtls_new();
    for _ in 0..16 {
        let record = match read_tls_record_with_deframer(
            stream,
            &mut deframer,
            TLS_RECORD_TYPE_APPLICATION_DATA,
        ) {
            Ok(record) => record,
            Err(Error::StateError(_)) => break,
            Err(error) => return Err(error),
        };
        let aad = Connection::noxtls_tls13_packet_header_aad(&record)?;
        let (inner, content_type) = conn.noxtls_open_client_tls13_record_packet(&record, &aad)?;
        if content_type == RecordContentType::ApplicationData.to_u8() {
            request_buf.extend_from_slice(&inner);
            if request_buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
    }
    Ok(())
}

/// Reads one TLS record of the expected content type using a deframer.
///
/// # Arguments
///
/// * `stream` — Connected TCP stream.
/// * `deframer` — Record deframer accumulating partial reads.
/// * `expected_type` — Required TLS record content type byte.
///
/// # Returns
///
/// On success, one complete raw TLS record packet.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] on timeout, EOF, or unexpected record type.
///
/// # Panics
///
/// This function does not panic.
fn read_tls_record_with_deframer(
    stream: &mut TcpStream,
    deframer: &mut TlsRecordDeframer,
    expected_type: u8,
) -> Result<Vec<u8>> {
    let mut scratch = [0_u8; 4096];
    loop {
        if let Some(packet) = deframer.pop_packet()? {
            if packet.first().copied() != Some(expected_type) {
                return Err(Error::ParseFailure("unexpected tls record content type"));
            }
            return Ok(packet);
        }
        let read = stream
            .read(&mut scratch)
            .map_err(|_| Error::StateError("failed to read tls record from socket"))?;
        if read == 0 {
            return Err(Error::StateError(
                "connection closed before a full tls record",
            ));
        }
        deframer.push(&scratch[..read]);
    }
}

/// Extracts one handshake message of the requested type from a handshake record.
///
/// # Arguments
///
/// * `record` — Raw TLS handshake record bytes.
/// * `message_type` — Expected handshake message type byte.
///
/// # Returns
///
/// On success, encoded handshake message bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the record does not contain the requested message.
///
/// # Panics
///
/// This function does not panic.
fn extract_handshake_message(record: &[u8], message_type: u8) -> Result<Vec<u8>> {
    if record.len() < TLS_RECORD_HEADER_LEN {
        return Err(Error::ParseFailure("handshake record too short"));
    }
    let payload = &record[TLS_RECORD_HEADER_LEN..];
    let messages = split_handshake_messages(payload)?;
    messages
        .into_iter()
        .find(|message| message.first().copied() == Some(message_type))
        .ok_or(Error::ParseFailure("requested handshake message not found"))
}

/// Splits one handshake record payload into individual handshake messages.
///
/// # Arguments
///
/// * `payload` — TLS record payload containing handshake data.
///
/// # Returns
///
/// On success, handshake messages in receive order.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when handshake framing is truncated.
///
/// # Panics
///
/// This function does not panic.
fn split_handshake_messages(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut cursor = 0_usize;
    let mut messages = Vec::new();
    while cursor < payload.len() {
        if payload.len().saturating_sub(cursor) < 4 {
            return Err(Error::ParseFailure("truncated handshake header"));
        }
        let message_len = ((payload[cursor + 1] as usize) << 16)
            | ((payload[cursor + 2] as usize) << 8)
            | payload[cursor + 3] as usize;
        let full_len = 4_usize.saturating_add(message_len);
        if payload.len().saturating_sub(cursor) < full_len {
            return Err(Error::ParseFailure("truncated handshake message body"));
        }
        messages.push(payload[cursor..cursor + full_len].to_vec());
        cursor = cursor.saturating_add(full_len);
    }
    Ok(messages)
}

/// Encodes one plaintext TLS handshake record.
///
/// # Arguments
///
/// * `handshake_message` — Encoded handshake message bytes.
/// * `legacy_record_version` — Two-byte legacy record version for the outer header.
///
/// # Returns
///
/// On success, serialized TLSPlaintext bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the handshake message exceeds `u16` record length.
///
/// # Panics
///
/// This function does not panic.
fn encode_tls13_handshake_record(
    handshake_message: &[u8],
    legacy_record_version: [u8; 2],
) -> Result<Vec<u8>> {
    if handshake_message.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "handshake record payload exceeds u16",
        ));
    }
    let mut packet = Vec::with_capacity(TLS_RECORD_HEADER_LEN + handshake_message.len());
    packet.push(TLS_RECORD_TYPE_HANDSHAKE);
    packet.extend_from_slice(&legacy_record_version);
    packet.extend_from_slice(&(handshake_message.len() as u16).to_be_bytes());
    packet.extend_from_slice(handshake_message);
    Ok(packet)
}

/// Seals one TLS 1.3 application-data packet for an HTTP response.
///
/// # Arguments
///
/// * `conn` — Finished TLS server connection with application keys installed.
/// * `plaintext` — HTTP response bytes to protect.
///
/// # Returns
///
/// On success, serialized TLSCiphertext packet bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when record sealing fails.
///
/// # Panics
///
/// This function does not panic.
fn seal_tls13_application_packet(conn: &mut Connection, plaintext: &[u8]) -> Result<Vec<u8>> {
    let inner_len = plaintext
        .len()
        .checked_add(1)
        .ok_or(Error::InvalidLength("tls13 inner plaintext length overflow"))?;
    let payload_len = inner_len
        .checked_add(16)
        .ok_or(Error::InvalidLength("tls13 ciphertext payload length overflow"))?;
    let payload_len_u16 = u16::try_from(payload_len)
        .map_err(|_| Error::InvalidLength("tls13 ciphertext payload exceeds u16 length"))?;
    let mut aad = [0_u8; TLS_RECORD_HEADER_LEN];
    aad[0] = TLS_RECORD_TYPE_APPLICATION_DATA;
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3..5].copy_from_slice(&payload_len_u16.to_be_bytes());
    conn.noxtls_seal_server_tls13_record_packet(
        plaintext,
        RecordContentType::ApplicationData.to_u8(),
        &aad,
        0,
    )
}

/// Builds deterministic-ish 32-byte server random material from coarse local clock bytes.
///
/// # Arguments
///
/// _(none)_ — Uses current system time when available.
///
/// # Returns
///
/// 32 bytes suitable for ServerHello random.
///
/// # Panics
///
/// This function does not panic.
fn build_server_random_seed() -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let mut random = [0_u8; 32];
    let secs = now.as_secs().to_be_bytes();
    let nanos = now.subsec_nanos().to_be_bytes();
    random[..8].copy_from_slice(&secs);
    random[8..12].copy_from_slice(&nanos);
    for idx in 12..random.len() {
        random[idx] = random[idx - 12]
            .wrapping_add((idx as u8).wrapping_mul(23))
            .rotate_left(2);
    }
    random
}

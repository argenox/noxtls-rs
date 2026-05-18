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

//! Curl-like TLS probe for interoperability diagnostics with packet and handshake tracing.
//!
//! This example intentionally prioritizes trace visibility over ergonomics so platform bring-up
//! can capture wire-level artifacts and modeled state transitions. Inbound TLS records are assembled with
//! [`noxtls::TlsRecordDeframer`] so partial TCP reads are handled without losing framing.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use noxtls::{
    split_tls13_handshake_payload, CipherSuite, Connection, HandshakeState, RecordContentType,
    TlsRecordDeframer, TlsVersion, TLS_RECORD_HEADER_LEN,
};
use noxtls_core::{Error, Result};
use noxtls_pem::noxtls_pem_file_to_der_blocks;

const TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_RECORD_TYPE_ALERT: u8 = 21;
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 22;
const TLS_RECORD_TYPE_APPLICATION_DATA: u8 = 23;
const TLS13_CLIENT_HELLO_RECORD_VERSION: [u8; 2] = [0x03, 0x01];
const TLS13_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const TLS13_RECORD_TAG_LEN: usize = 16;
const TLS13_HANDSHAKE_MESSAGE_SERVER_HELLO: u8 = 2;
const TLS13_HANDSHAKE_MESSAGE_NEW_SESSION_TICKET: u8 = 4;
const TLS13_HANDSHAKE_MESSAGE_ENCRYPTED_EXTENSIONS: u8 = 8;
const TLS13_HANDSHAKE_MESSAGE_CERTIFICATE: u8 = 11;
const TLS13_HANDSHAKE_MESSAGE_CERTIFICATE_REQUEST: u8 = 13;
const TLS13_HANDSHAKE_MESSAGE_CERTIFICATE_VERIFY: u8 = 15;
const TLS13_HANDSHAKE_MESSAGE_FINISHED: u8 = 20;
const TLS13_HANDSHAKE_MESSAGE_KEY_UPDATE: u8 = 24;
const TLS13_HANDSHAKE_LEN_PREFIX_LEN: usize = 4;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_RECORDS: usize = 128;
const HEX_PREVIEW_LIMIT: usize = 64;
const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
const TLS13_KEY_SHARE_GROUP_SECP256R1: u16 = 0x0017;
const TLS13_KEY_SHARE_GROUP_X25519: u16 = 0x001D;
const TLS13_KEY_SHARE_GROUP_MLKEM768: u16 = 0x0201;
const TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID: u16 = 0x11EC;

/// Captures the parsed HTTPS endpoint components needed for socket connection and Host header.
#[derive(Debug, Clone)]
struct TargetUrl {
    host: String,
    port: u16,
    path_and_query: String,
}

/// Captures one TLS record packet parsed from wire bytes.
#[derive(Debug, Clone)]
struct TlsRecord {
    content_type: u8,
    version: [u8; 2],
    payload: Vec<u8>,
    raw: Vec<u8>,
}

/// Aggregates trace counters for final probe summary output.
#[derive(Debug, Default, Clone, Copy)]
struct TraceCounters {
    inbound_records: usize,
    plaintext_handshake_records: usize,
    encrypted_records: usize,
    change_cipher_spec_records: usize,
    alert_records: usize,
    decoded_handshake_messages: usize,
}

/// Captures optional TLS server-auth controls supplied through CLI flags.
#[derive(Debug, Clone)]
struct ServerAuthConfig {
    ca_bundle_path: String,
    validation_time: String,
}

/// Executes the TLS trace probe using URL and optional runtime flags from CLI.
///
/// # Arguments
///
/// * `argv[1]` — HTTPS URL to probe (for example `https://example.com/`).
/// * `--timeout-ms=<value>` — Optional per-read timeout in milliseconds.
/// * `--max-records=<value>` — Optional safety bound for inbound record processing.
///
/// # Returns
///
/// `Ok(())` when probe execution completes and diagnostics are printed.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] for invalid CLI, URL parse errors, connection issues, or handshake parse failures.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let (url, timeout, max_records, server_auth, offer_pq_keyshares) =
        parse_cli(std::env::args().collect())?;
    let target = parse_https_url(&url)?;
    run_trace_probe(&target, timeout, max_records, server_auth, offer_pq_keyshares)
}

/// Parses CLI arguments into probe runtime options.
///
/// # Arguments
///
/// * `args` — Raw CLI argument vector including executable path.
///
/// # Returns
///
/// On success, `(url, timeout, max_records)` used by the probe execution path.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when URL is missing or option values are invalid.
///
/// # Panics
///
/// This function does not panic.
fn parse_cli(
    args: Vec<String>,
) -> Result<(String, Duration, usize, Option<ServerAuthConfig>, bool)> {
    if args.len() < 2 {
        print_usage(args.first().map_or("tls_trace_curl", String::as_str));
        return Err(Error::InvalidLength("missing HTTPS url argument"));
    }

    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut max_records = DEFAULT_MAX_RECORDS;
    let mut ca_bundle_path: Option<String> = None;
    let mut validation_time = current_generalized_time_utc();
    let mut offer_pq_keyshares = false;
    let mut index = 2_usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if let Some(value) = arg.strip_prefix("--timeout-ms=") {
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| Error::ParseFailure("invalid --timeout-ms value"))?;
        } else if arg == "--timeout-ms" {
            index += 1;
            let value = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --timeout-ms value"))?;
            timeout_ms = value
                .parse::<u64>()
                .map_err(|_| Error::ParseFailure("invalid --timeout-ms value"))?;
        } else if let Some(value) = arg.strip_prefix("--max-records=") {
            max_records = value
                .parse::<usize>()
                .map_err(|_| Error::ParseFailure("invalid --max-records value"))?;
        } else if arg == "--max-records" {
            index += 1;
            let value = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --max-records value"))?;
            max_records = value
                .parse::<usize>()
                .map_err(|_| Error::ParseFailure("invalid --max-records value"))?;
        } else if let Some(value) = arg.strip_prefix("--ca=") {
            if value.is_empty() {
                return Err(Error::InvalidLength("invalid --ca value"));
            }
            ca_bundle_path = Some(value.to_owned());
        } else if arg == "--ca" {
            index += 1;
            let value = args.get(index).ok_or(Error::ParseFailure("missing --ca value"))?;
            if value.is_empty() {
                return Err(Error::InvalidLength("invalid --ca value"));
            }
            ca_bundle_path = Some(value.clone());
        } else if let Some(value) = arg.strip_prefix("--validation-time=") {
            if value.is_empty() {
                return Err(Error::InvalidLength("invalid --validation-time value"));
            }
            validation_time = value.to_owned();
        } else if let Some(value) = arg.strip_prefix("--pq-keyshares=") {
            offer_pq_keyshares = parse_bool_switch(value, "--pq-keyshares")?;
        } else if arg == "--validation-time" {
            index += 1;
            let value = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --validation-time value"))?;
            if value.is_empty() {
                return Err(Error::InvalidLength("invalid --validation-time value"));
            }
            validation_time = value.clone();
        } else if arg == "--pq-keyshares" {
            index += 1;
            let value = args
                .get(index)
                .ok_or(Error::ParseFailure("missing --pq-keyshares value"))?;
            offer_pq_keyshares = parse_bool_switch(value, "--pq-keyshares")?;
        } else {
            return Err(Error::ParseFailure(
                "unknown argument (expected --timeout-ms, --max-records, --ca, --validation-time, --pq-keyshares)",
            ));
        }
        index += 1;
    }

    if max_records == 0 {
        return Err(Error::InvalidLength(
            "--max-records must be greater than zero",
        ));
    }

    let server_auth = ca_bundle_path.map(|path| ServerAuthConfig {
        ca_bundle_path: path,
        validation_time,
    });

    Ok((
        args[1].clone(),
        Duration::from_millis(timeout_ms),
        max_records,
        server_auth,
        offer_pq_keyshares,
    ))
}

/// Prints short CLI usage and examples for the TLS trace probe.
///
/// # Arguments
///
/// * `exe_name` — Executable/program name shown in usage text.
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
        "  cargo run -p noxtls --example {exe_name} -- https://example.com/ [--timeout-ms=5000] [--max-records=128] [--ca=./mozilla.pem] [--validation-time=20260101000000Z] [--pq-keyshares=off]"
    );
}

/// Parses one HTTPS URL into host/port/path components needed by the probe.
///
/// # Arguments
///
/// * `url` — Full HTTPS URL string.
///
/// # Returns
///
/// Parsed [`TargetUrl`] with normalized path and default port when omitted.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] for unsupported schemes, missing host, or malformed port fields.
///
/// # Panics
///
/// This function does not panic.
fn parse_https_url(url: &str) -> Result<TargetUrl> {
    let without_scheme = url
        .strip_prefix("https://")
        .ok_or(Error::ParseFailure("url must start with https://"))?;

    let split_idx = without_scheme.find('/').unwrap_or(without_scheme.len());
    let authority = &without_scheme[..split_idx];
    let path = if split_idx < without_scheme.len() {
        without_scheme[split_idx..].to_owned()
    } else {
        "/".to_owned()
    };
    if authority.is_empty() {
        return Err(Error::ParseFailure("url authority must include host"));
    }

    let (host, port) = if let Some((host_part, port_part)) = authority.rsplit_once(':') {
        if host_part.contains(']') || host_part.contains('[') {
            return Err(Error::UnsupportedFeature(
                "ipv6 bracket authority parsing is not yet supported in this example",
            ));
        }
        let parsed_port = port_part
            .parse::<u16>()
            .map_err(|_| Error::ParseFailure("invalid numeric port in url"))?;
        (host_part.to_owned(), parsed_port)
    } else {
        (authority.to_owned(), 443_u16)
    };

    if host.is_empty() {
        return Err(Error::ParseFailure("url host must not be empty"));
    }

    Ok(TargetUrl {
        host,
        port,
        path_and_query: path,
    })
}

/// Runs the full trace flow: connect, send ClientHello, receive and decode server records.
///
/// # Arguments
///
/// * `target` — Parsed URL destination with host/port/path.
/// * `timeout` — Per-read timeout for socket operations.
/// * `max_records` — Maximum inbound records before forced stop.
///
/// # Returns
///
/// `Ok(())` after probe summary and diagnostics are printed.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] for socket setup/write failures or TLS message parse failures.
///
/// # Panics
///
/// This function does not panic.
fn run_trace_probe(
    target: &TargetUrl,
    timeout: Duration,
    max_records: usize,
    server_auth: Option<ServerAuthConfig>,
    offer_pq_keyshares: bool,
) -> Result<()> {
    println!(
        "target=https://{}:{}{}",
        target.host, target.port, target.path_and_query
    );
    println!(
        "probe_mode=noxtls-modeled-handshake timeout_ms={} max_records={}",
        timeout.as_millis(),
        max_records
    );

    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|_| Error::StateError("failed to connect tcp socket"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| Error::StateError("failed to configure read timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| Error::StateError("failed to configure write timeout"))?;

    let mut conn = Connection::noxtls_new(TlsVersion::Tls13);
    // Public web interop profile: avoid PQ draft groups/signatures in default ClientHello.
    conn.noxtls_set_tls13_client_offer_pq_key_shares(offer_pq_keyshares);
    conn.noxtls_set_tls13_client_offer_mldsa_signature(false);
    conn.noxtls_set_tls13_client_cipher_suites(&[CipherSuite::TlsAes128GcmSha256])?;
    conn.noxtls_set_tls13_server_name(Some(&target.host))?;
    if let Some(auth) = server_auth.as_ref() {
        let trust_anchors = load_trust_anchors_from_bundle(&auth.ca_bundle_path)?;
        conn.noxtls_set_tls13_require_certificate_auth(true);
        conn.noxtls_configure_tls13_server_auth(&trust_anchors, &[], &auth.validation_time)?;
        conn.noxtls_set_tls13_server_expected_hostname(Some(&target.host))?;
        println!(
            "tls13_server_auth=enabled trust_anchors={} validation_time={}",
            trust_anchors.len(),
            auth.validation_time
        );
    } else {
        println!("tls13_server_auth=disabled");
    }
    // Prefer deterministic HTTP/1.1 behavior for this live GET/response probe.
    conn.noxtls_set_tls13_alpn_protocols(&["http/1.1"])?;
    let early_data_policy = conn.noxtls_tls13_early_data_operational_policy();
    println!(
        "tls13_policy=require_acceptance:{} anti_replay:{}",
        early_data_policy.require_acceptance, early_data_policy.anti_replay_enabled
    );
    println!(
        "tls13_client_offer_pq_keyshares={}",
        if offer_pq_keyshares {
            "enabled"
        } else {
            "disabled"
        }
    );

    let random = build_client_random_seed();
    let client_hello = conn.noxtls_send_client_hello(&random)?;
    let client_hello_record =
        encode_tls13_client_hello_record(&client_hello, TLS13_CLIENT_HELLO_RECORD_VERSION)?;
    let hello_info = Connection::noxtls_parse_client_hello_info(&client_hello)?;
    log_client_hello_features(&hello_info, &target.host);
    println!(
        "tx_record[0]={}",
        summarize_packet_line(&client_hello_record)
    );
    stream
        .write_all(&client_hello_record)
        .map_err(|_| Error::StateError("failed to send client hello record"))?;

    let mut counters = TraceCounters::default();
    let mut observed_server_hello = false;
    let mut server_selected_key_share_group: Option<u16> = None;
    let mut deframer = TlsRecordDeframer::noxtls_new();
    let mut handshake_keys_derived = false;
    for _ in 0..max_records {
        match read_tls_record(&mut stream, &mut deframer) {
            Ok(record) => {
                counters.inbound_records = counters.inbound_records.saturating_add(1);
                log_inbound_record(counters.inbound_records, &record);

                match record.content_type {
                    TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                        counters.change_cipher_spec_records =
                            counters.change_cipher_spec_records.saturating_add(1);
                        println!("ccs=received compatibility change_cipher_spec");
                    }
                    TLS_RECORD_TYPE_ALERT => {
                        counters.alert_records = counters.alert_records.saturating_add(1);
                        if let Some((level, description)) = parse_alert_payload(&record.payload) {
                            println!(
                                "alert=received level={}({}) description={}({}) payload_len={}",
                                level,
                                alert_level_name(level),
                                description,
                                alert_description_name(description),
                                record.payload.len()
                            );
                        } else {
                            println!("alert=received alert payload len={}", record.payload.len());
                        }
                        break;
                    }
                    TLS_RECORD_TYPE_HANDSHAKE => {
                        counters.plaintext_handshake_records =
                            counters.plaintext_handshake_records.saturating_add(1);
                        let messages = split_handshake_messages(&record.payload)?;
                        for message in messages {
                            counters.decoded_handshake_messages =
                                counters.decoded_handshake_messages.saturating_add(1);
                            let handshake_type = message[0];
                            println!(
                                "handshake_message[{}]=type:{} len:{}",
                                counters.decoded_handshake_messages,
                                handshake_type_name(handshake_type),
                                message.len()
                            );
                            if handshake_type == TLS13_HANDSHAKE_MESSAGE_SERVER_HELLO {
                                conn.noxtls_recv_server_hello(&message)?;
                                observed_server_hello = true;
                                server_selected_key_share_group =
                                    parse_server_hello_selected_key_share_group(&message)?;
                                println!(
                                    "negotiated_cipher_suite={:?}",
                                    conn.noxtls_selected_cipher_suite()
                                );
                                println!(
                                    "server_hello_selected_key_share_group={}",
                                    format_key_share_group(server_selected_key_share_group)
                                );
                                println!("connection_state_after_server_hello={:?}", conn.state);
                            }
                        }
                    }
                    TLS_RECORD_TYPE_APPLICATION_DATA => {
                        counters.encrypted_records = counters.encrypted_records.saturating_add(1);
                        println!(
                            "encrypted_record=received tls13 application_data record len={}",
                            record.payload.len()
                        );
                        if !observed_server_hello {
                            println!(
                                "debug_note=ignoring encrypted record before server hello parse"
                            );
                            continue;
                        }
                        if !handshake_keys_derived {
                            conn.noxtls_derive_handshake_secret()?;
                            handshake_keys_derived = true;
                            println!("connection_state_after_key_derive={:?}", conn.state);
                        }
                        let aad = tls13_packet_header_aad(&record.raw)?;
                        let (inner, content_type) =
                            conn.noxtls_open_tls13_record_packet(&record.raw, &aad)?;
                        if content_type != RecordContentType::Handshake.to_u8() {
                            return Err(Error::ParseFailure(
                                "expected handshake inner content while waiting for server flight",
                            ));
                        }
                        let messages = split_tls13_handshake_payload(&inner)?;
                        process_server_handshake_messages(&mut conn, &messages)?;
                        counters.decoded_handshake_messages = counters
                            .decoded_handshake_messages
                            .saturating_add(messages.len());
                        if conn.state == HandshakeState::Finished {
                            println!("connection_state_after_server_finished={:?}", conn.state);
                            break;
                        }
                    }
                    other => {
                        println!("record_type_unknown={} len={}", other, record.payload.len());
                    }
                }
            }
            Err(error) => {
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut {
                    println!("read_timeout=stopping after timeout");
                    break;
                }
                eprintln!(
                    "io_debug=read_tls_record error kind={:?} detail={error}",
                    error.kind()
                );
                return Err(Error::StateError("failed to read tls record from socket"));
            }
        }
    }

    print_trace_summary(
        &conn,
        counters,
        observed_server_hello,
        server_selected_key_share_group,
    );
    if conn.state != HandshakeState::Finished {
        println!("result=handshake_not_finished");
        println!(
            "note=live encrypted server-flight + HTTP path is wired, but this run did not reach Finished (server alert/policy mismatch or unsupported peer profile)"
        );
        return Ok(());
    }

    let client_finished = conn.noxtls_prepare_tls13_client_finished_message()?;
    let client_finished_packet = seal_tls13_wire_packet(
        &mut conn,
        &client_finished,
        RecordContentType::Handshake.to_u8(),
        0,
    )?;
    println!(
        "tx_record[client_finished]={}",
        summarize_packet_line(&client_finished_packet)
    );
    stream
        .write_all(&client_finished_packet)
        .map_err(|_| Error::StateError("failed to send client finished packet"))?;
    conn.noxtls_activate_tls13_application_traffic_keys()?;

    if conn.noxtls_tls13_selected_alpn_protocol() != Some(b"http/1.1".as_slice()) {
        println!(
            "limitation=selected_alpn={:?} is not implemented by this example; only http/1.1 response parsing is wired",
            conn.noxtls_tls13_selected_alpn_protocol()
                .map(String::from_utf8_lossy)
                .map(|s| s.to_string())
        );
        return Ok(());
    }

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: noxtls-trace-curl/0.1\r\nAccept: */*\r\n\r\n",
        target.path_and_query, target.host
    );
    let request_packet = seal_tls13_wire_packet(
        &mut conn,
        request.as_bytes(),
        RecordContentType::ApplicationData.to_u8(),
        0,
    )?;
    println!(
        "tx_record[http_get]={}",
        summarize_packet_line(&request_packet)
    );
    stream
        .write_all(&request_packet)
        .map_err(|_| Error::StateError("failed to send encrypted http request"))?;

    let mut response_body = Vec::new();
    for _ in 0..max_records {
        match read_tls_record(&mut stream, &mut deframer) {
            Ok(record) => {
                log_inbound_record(counters.inbound_records.saturating_add(1), &record);
                match record.content_type {
                    TLS_RECORD_TYPE_ALERT => {
                        println!("alert=received outer alert record, stopping response loop");
                        break;
                    }
                    TLS_RECORD_TYPE_APPLICATION_DATA => {
                        let aad = tls13_packet_header_aad(&record.raw)?;
                        let (inner, content_type) =
                            conn.noxtls_open_tls13_record_packet(&record.raw, &aad)?;
                        match RecordContentType::from_u8(content_type) {
                            Some(RecordContentType::ApplicationData) => {
                                response_body.extend_from_slice(&inner);
                                println!("http_response_chunk_bytes={}", inner.len());
                            }
                            Some(RecordContentType::Handshake) => {
                                let messages = split_tls13_handshake_payload(&inner)?;
                                process_post_handshake_messages(&mut conn, &messages)?;
                                println!("post_handshake_messages={}", messages.len());
                            }
                            Some(RecordContentType::Alert) => {
                                if let Some((level, description)) = parse_alert_payload(&inner) {
                                    println!(
                                        "alert=decrypted level={}({}) description={}({})",
                                        level,
                                        alert_level_name(level),
                                        description,
                                        alert_description_name(description)
                                    );
                                }
                                break;
                            }
                            _ => {
                                return Err(Error::ParseFailure(
                                    "unexpected tls13 inner content type in response loop",
                                ));
                            }
                        }
                    }
                    TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC => {
                        println!("ccs=received during response loop");
                    }
                    TLS_RECORD_TYPE_HANDSHAKE => {
                        println!("debug_note=ignoring unexpected plaintext handshake after noxtls_finish");
                    }
                    _ => {}
                }
            }
            Err(error) => {
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut {
                    println!("read_timeout=stopping response loop");
                    break;
                }
                if error.kind() == ErrorKind::UnexpectedEof {
                    println!("peer_closed=connection closed by peer");
                    break;
                }
                return Err(Error::StateError(
                    "failed while reading encrypted http response",
                ));
            }
        }
    }
    if response_body.is_empty() {
        println!("http_response_bytes=0");
    } else {
        println!("http_response_bytes={}", response_body.len());
        println!("http_response_text_begin");
        println!("{}", String::from_utf8_lossy(&response_body));
        println!("http_response_text_end");
    }
    Ok(())
}

/// Routes decrypted TLS 1.3 server-handshake messages into connection state-machine handlers.
fn process_server_handshake_messages(conn: &mut Connection, messages: &[Vec<u8>]) -> Result<()> {
    for message in messages {
        let message_type = message[0];
        match message_type {
            TLS13_HANDSHAKE_MESSAGE_ENCRYPTED_EXTENSIONS => {
                conn.noxtls_recv_encrypted_extensions(message)?
            }
            TLS13_HANDSHAKE_MESSAGE_CERTIFICATE_REQUEST => {
                conn.noxtls_recv_certificate_request(message)?
            }
            TLS13_HANDSHAKE_MESSAGE_CERTIFICATE => conn.noxtls_recv_certificate(message)?,
            TLS13_HANDSHAKE_MESSAGE_CERTIFICATE_VERIFY => conn.noxtls_recv_certificate_verify(message)?,
            TLS13_HANDSHAKE_MESSAGE_FINISHED => conn.noxtls_recv_finished_message(message)?,
            _ => {
                return Err(Error::ParseFailure(
                    "unexpected handshake message type in encrypted server flight",
                ));
            }
        }
    }
    Ok(())
}

/// Routes TLS 1.3 post-handshake control messages.
fn process_post_handshake_messages(conn: &mut Connection, messages: &[Vec<u8>]) -> Result<()> {
    for message in messages {
        match message[0] {
            TLS13_HANDSHAKE_MESSAGE_NEW_SESSION_TICKET => {
                conn.noxtls_recv_new_session_ticket_message(message)?
            }
            TLS13_HANDSHAKE_MESSAGE_KEY_UPDATE => conn.noxtls_recv_key_update_message(message)?,
            _ => {
                return Err(Error::ParseFailure(
                    "unexpected post-handshake message type",
                ))
            }
        }
    }
    Ok(())
}

/// Builds TLS 1.3 outer-record header bytes used as AEAD AAD.
fn tls13_packet_header_aad(packet: &[u8]) -> Result<[u8; TLS_RECORD_HEADER_LEN]> {
    if packet.len() < TLS_RECORD_HEADER_LEN {
        return Err(Error::ParseFailure("tls13 packet too short for header"));
    }
    let mut aad = [0_u8; TLS_RECORD_HEADER_LEN];
    aad.copy_from_slice(&packet[..TLS_RECORD_HEADER_LEN]);
    let payload_len = u16::from_be_bytes([aad[3], aad[4]]) as usize;
    if packet.len() != TLS_RECORD_HEADER_LEN.saturating_add(payload_len) {
        return Err(Error::ParseFailure("tls13 packet length mismatch"));
    }
    Ok(aad)
}

/// Seals one TLS 1.3 packet while computing RFC-style outer-header AAD locally.
fn seal_tls13_wire_packet(
    conn: &mut Connection,
    content: &[u8],
    content_type: u8,
    padding_len: usize,
) -> Result<Vec<u8>> {
    let inner_len = content
        .len()
        .checked_add(1)
        .and_then(|v| v.checked_add(padding_len))
        .ok_or(Error::InvalidLength(
            "tls13 inner plaintext length overflow",
        ))?;
    let payload_len = inner_len
        .checked_add(TLS13_RECORD_TAG_LEN)
        .ok_or(Error::InvalidLength(
            "tls13 ciphertext payload length overflow",
        ))?;
    let payload_len_u16 = u16::try_from(payload_len)
        .map_err(|_| Error::InvalidLength("tls13 ciphertext payload exceeds u16 length"))?;
    let mut aad = [0_u8; TLS_RECORD_HEADER_LEN];
    aad[0] = TLS_RECORD_TYPE_APPLICATION_DATA;
    aad[1] = TLS13_RECORD_LEGACY_VERSION[0];
    aad[2] = TLS13_RECORD_LEGACY_VERSION[1];
    aad[3..5].copy_from_slice(&payload_len_u16.to_be_bytes());
    conn.noxtls_seal_tls13_record_packet(content, content_type, &aad, padding_len)
}

/// Parses two-byte TLS alert payload into `(level, description)` when present.
///
/// # Arguments
///
/// * `payload` — Raw alert record payload bytes.
///
/// # Returns
///
/// `Some((level, description))` when payload contains at least two bytes, otherwise `None`.
///
/// # Panics
///
/// This function does not panic.
fn parse_alert_payload(payload: &[u8]) -> Option<(u8, u8)> {
    if payload.len() < 2 {
        return None;
    }
    Some((payload[0], payload[1]))
}

/// Builds deterministic-ish 32-byte client random material from coarse local clock bytes.
///
/// # Arguments
///
/// * _(none)_ — Uses current system time when available.
///
/// # Returns
///
/// 32 bytes suitable for `noxtls_send_client_hello`.
///
/// # Panics
///
/// This function does not panic.
fn build_client_random_seed() -> [u8; 32] {
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
            .wrapping_add((idx as u8).wrapping_mul(17))
            .rotate_left(1);
    }
    random
}

/// Loads trust anchors from a PEM certificate bundle for TLS 1.3 server-auth checks.
///
/// # Arguments
///
/// * `bundle_path` — Filesystem path to PEM bundle containing one or more `CERTIFICATE` blocks.
///
/// # Returns
///
/// DER-encoded trust anchors in source-order.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the file cannot be read/parsed, or no anchors are present.
///
/// # Panics
///
/// This function does not panic.
fn load_trust_anchors_from_bundle(bundle_path: &str) -> Result<Vec<Vec<u8>>> {
    let anchors = noxtls_pem_file_to_der_blocks(Path::new(bundle_path), "CERTIFICATE")
        .map_err(|_| Error::ParseFailure("failed to parse --ca bundle as PEM certificates"))?;
    if anchors.is_empty() {
        return Err(Error::InvalidLength(
            "--ca bundle does not contain any CERTIFICATE blocks",
        ));
    }
    Ok(anchors)
}

/// Formats current UTC time as ASN.1 GeneralizedTime (`YYYYMMDDHHMMSSZ`).
///
/// # Arguments
///
/// * _(none)_ — Uses current system clock, falling back to Unix epoch on error.
///
/// # Returns
///
/// GeneralizedTime string suitable for certificate-chain validation.
///
/// # Panics
///
/// This function does not panic.
fn current_generalized_time_utc() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let total_secs = now.as_secs();
    let days_since_epoch = (total_secs / 86_400) as i64;
    let seconds_of_day = (total_secs % 86_400) as u32;

    let (year, month, day) = civil_from_days_since_epoch(days_since_epoch);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z")
}

/// Converts Unix day offset to Gregorian `(year, month, day)` in UTC.
///
/// # Arguments
///
/// * `days_since_epoch` — Signed day offset from 1970-01-01 UTC.
///
/// # Returns
///
/// Gregorian date tuple `(year, month, day)`.
///
/// # Panics
///
/// This function does not panic.
fn civil_from_days_since_epoch(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// Encodes one plaintext TLS record carrying a ClientHello handshake message.
///
/// # Arguments
///
/// * `handshake_message` — Encoded TLS handshake message bytes.
/// * `legacy_record_version` — Two-byte legacy record version for outer TLSPlaintext header.
///
/// # Returns
///
/// Serialized TLSPlaintext bytes ready for socket transmit.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when handshake bytes exceed `u16` record length.
///
/// # Panics
///
/// This function does not panic.
fn encode_tls13_client_hello_record(
    handshake_message: &[u8],
    legacy_record_version: [u8; 2],
) -> Result<Vec<u8>> {
    if handshake_message.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "client hello record payload exceeds u16",
        ));
    }

    let mut packet = Vec::with_capacity(TLS_RECORD_HEADER_LEN + handshake_message.len());
    packet.push(TLS_RECORD_TYPE_HANDSHAKE);
    packet.extend_from_slice(&legacy_record_version);
    packet.extend_from_slice(&(handshake_message.len() as u16).to_be_bytes());
    packet.extend_from_slice(handshake_message);
    Ok(packet)
}

/// Reads one full TLS record packet (`header + payload`) using a [`TlsRecordDeframer`] so partial socket reads coalesce.
///
/// # Arguments
///
/// * `stream` — Connected TCP stream for TLS wire bytes.
/// * `deframer` — Record buffer used across reads until one full record is available.
///
/// # Returns
///
/// Parsed [`TlsRecord`] with raw packet bytes and decoded header fields.
///
/// # Errors
///
/// Returns [`std::io::Error`] when socket read fails, EOF occurs before a full record, or deframing rejects a header.
///
/// # Panics
///
/// This function does not panic.
fn read_tls_record(
    stream: &mut TcpStream,
    deframer: &mut TlsRecordDeframer,
) -> std::io::Result<TlsRecord> {
    let mut scratch = [0_u8; 2048];
    loop {
        match deframer.pop_packet() {
            Ok(Some(raw)) => return tls_record_from_raw_bytes(raw),
            Ok(None) => {}
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("tls record deframe: {err}"),
                ));
            }
        }
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before a full tls record",
            ));
        }
        deframer.push(&scratch[..read]);
    }
}

fn tls_record_from_raw_bytes(raw: Vec<u8>) -> std::io::Result<TlsRecord> {
    if raw.len() < TLS_RECORD_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tls record shorter than header",
        ));
    }
    let content_type = raw[0];
    let version = [raw[1], raw[2]];
    let payload_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    if TLS_RECORD_HEADER_LEN.saturating_add(payload_len) != raw.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tls record length mismatch",
        ));
    }
    let payload = raw[TLS_RECORD_HEADER_LEN..].to_vec();
    Ok(TlsRecord {
        content_type,
        version,
        payload,
        raw,
    })
}

/// Splits one handshake record payload into complete handshake messages.
///
/// # Arguments
///
/// * `payload` — TLS record payload bytes with one or more handshake messages.
///
/// # Returns
///
/// Vector of handshake messages (`type || len(3) || body`) in receive order.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when a message header/body is truncated.
///
/// # Panics
///
/// This function does not panic.
fn split_handshake_messages(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut cursor = 0_usize;
    let mut messages = Vec::new();
    while cursor < payload.len() {
        if payload.len().saturating_sub(cursor) < TLS13_HANDSHAKE_LEN_PREFIX_LEN {
            return Err(Error::ParseFailure(
                "truncated handshake header in plaintext record payload",
            ));
        }
        let message_len = ((payload[cursor + 1] as usize) << 16)
            | ((payload[cursor + 2] as usize) << 8)
            | payload[cursor + 3] as usize;
        let full_len = TLS13_HANDSHAKE_LEN_PREFIX_LEN.saturating_add(message_len);
        if payload.len().saturating_sub(cursor) < full_len {
            return Err(Error::ParseFailure(
                "truncated handshake message body in plaintext record payload",
            ));
        }
        messages.push(payload[cursor..cursor + full_len].to_vec());
        cursor = cursor.saturating_add(full_len);
    }
    Ok(messages)
}

/// Logs parsed client-offered TLS capabilities before network transmission.
///
/// # Arguments
///
/// * `info` — Parsed ClientHello suite and extension metadata.
/// * `host` — Server name being targeted.
///
/// # Returns
///
/// `()`.
///
/// # Panics
///
/// This function does not panic.
fn log_client_hello_features(info: &noxtls::ClientHelloInfo, host: &str) {
    println!("client_hello_target_host={host}");
    println!("client_hello_suites={:?}", info.offered_cipher_suites);
    println!(
        "client_hello_supported_versions={:x?}",
        info.extensions.supported_versions
    );
    println!(
        "client_hello_signature_algorithms={:x?}",
        info.extensions.signature_algorithms
    );
    println!(
        "client_hello_key_share_groups={:x?}",
        info.extensions.key_share_groups
    );
    println!(
        "client_hello_alpn={:?}",
        info.extensions
            .alpn_protocols
            .iter()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .collect::<Vec<_>>()
    );
    println!(
        "client_hello_early_data_offered={}",
        info.extensions.early_data_offered
    );
    println!(
        "client_hello_psk_identity_count={}",
        info.extensions.psk_identity_count
    );
}

/// Logs one inbound TLS packet with header and a truncated hex preview.
///
/// # Arguments
///
/// * `record_idx` — 1-based inbound packet index.
/// * `record` — Parsed TLS record.
///
/// # Returns
///
/// `()`.
///
/// # Panics
///
/// This function does not panic.
fn log_inbound_record(record_idx: usize, record: &TlsRecord) {
    println!(
        "rx_record[{record_idx}]=type:{} version={:02x}{:02x} payload_len={} raw_preview={}",
        record_type_name(record.content_type),
        record.version[0],
        record.version[1],
        record.payload.len(),
        hex_preview(&record.raw, HEX_PREVIEW_LIMIT)
    );
}

/// Emits final high-level handshake and feature telemetry summary.
///
/// # Arguments
///
/// * `conn` — Connection state machine after probe processing.
/// * `counters` — Packet/message counters gathered during probing.
/// * `observed_server_hello` — Whether a plaintext ServerHello was seen and parsed.
///
/// # Returns
///
/// `()`.
///
/// # Panics
///
/// This function does not panic.
fn print_trace_summary(
    conn: &Connection,
    counters: TraceCounters,
    observed_server_hello: bool,
    server_selected_key_share_group: Option<u16>,
) {
    println!("summary_inbound_records={}", counters.inbound_records);
    println!(
        "summary_plaintext_handshake_records={}",
        counters.plaintext_handshake_records
    );
    println!("summary_encrypted_records={}", counters.encrypted_records);
    println!(
        "summary_change_cipher_spec_records={}",
        counters.change_cipher_spec_records
    );
    println!("summary_alert_records={}", counters.alert_records);
    println!(
        "summary_decoded_handshake_messages={}",
        counters.decoded_handshake_messages
    );
    println!("summary_observed_server_hello={observed_server_hello}");
    println!("summary_connection_state={:?}", conn.state);
    println!("summary_selected_suite={:?}", conn.noxtls_selected_cipher_suite());
    println!(
        "summary_tls13_server_name_acknowledged={}",
        conn.noxtls_tls13_server_name_acknowledged()
    );
    println!(
        "summary_tls13_selected_alpn={:?}",
        conn.noxtls_tls13_selected_alpn_protocol()
            .map(String::from_utf8_lossy)
            .map(|s| s.to_string())
    );
    println!(
        "summary_server_hello_selected_key_share_group={}",
        format_key_share_group(server_selected_key_share_group)
    );
    println!(
        "summary_tls13_early_data_telemetry={:?}",
        conn.noxtls_tls13_early_data_telemetry()
    );
}

/// Parses `on|off|true|false|1|0` style CLI switches to booleans.
///
/// # Arguments
///
/// * `value` — Raw option value text from CLI.
/// * `flag_name` — Option name used for diagnostics.
///
/// # Returns
///
/// Parsed boolean toggle.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when `value` is not a recognized boolean literal.
///
/// # Panics
///
/// This function does not panic.
fn parse_bool_switch(value: &str, flag_name: &str) -> Result<bool> {
    if value.eq_ignore_ascii_case("on")
        || value.eq_ignore_ascii_case("true")
        || value == "1"
    {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("false")
        || value == "0"
    {
        return Ok(false);
    }
    Err(Error::ParseFailure(match flag_name {
        "--pq-keyshares" => "invalid --pq-keyshares value (expected on/off)",
        _ => "invalid boolean option value",
    }))
}

/// Extracts selected TLS 1.3 `key_share` named group from a ServerHello message.
///
/// # Arguments
///
/// * `server_hello` — Full encoded TLS handshake message for `ServerHello`.
///
/// # Returns
///
/// `Some(group)` when key_share extension is present and well-formed, otherwise `None`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when handshake framing or extension lengths are malformed.
///
/// # Panics
///
/// This function does not panic.
fn parse_server_hello_selected_key_share_group(server_hello: &[u8]) -> Result<Option<u16>> {
    if server_hello.len() < TLS13_HANDSHAKE_LEN_PREFIX_LEN {
        return Err(Error::ParseFailure("server hello handshake framing is truncated"));
    }
    if server_hello[0] != TLS13_HANDSHAKE_MESSAGE_SERVER_HELLO {
        return Err(Error::ParseFailure(
            "expected server hello handshake message type",
        ));
    }
    let body_len = ((server_hello[1] as usize) << 16)
        | ((server_hello[2] as usize) << 8)
        | server_hello[3] as usize;
    if server_hello.len() != TLS13_HANDSHAKE_LEN_PREFIX_LEN + body_len {
        return Err(Error::ParseFailure("server hello handshake length mismatch"));
    }
    let body = &server_hello[TLS13_HANDSHAKE_LEN_PREFIX_LEN..];
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        return Err(Error::ParseFailure("server hello body is truncated"));
    }
    let mut cursor = &body[2 + 32..];
    let session_id_len = cursor[0] as usize;
    cursor = &cursor[1..];
    if cursor.len() < session_id_len + 2 + 1 + 2 {
        return Err(Error::ParseFailure("server hello session id field is truncated"));
    }
    cursor = &cursor[session_id_len..];
    cursor = &cursor[2..];
    cursor = &cursor[1..];
    let extensions_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    cursor = &cursor[2..];
    if cursor.len() < extensions_len {
        return Err(Error::ParseFailure("server hello extensions are truncated"));
    }
    let mut extensions = &cursor[..extensions_len];
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return Err(Error::ParseFailure("server hello extension header is truncated"));
        }
        let ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        extensions = &extensions[4..];
        if extensions.len() < ext_len {
            return Err(Error::ParseFailure("server hello extension payload is truncated"));
        }
        let ext_data = &extensions[..ext_len];
        extensions = &extensions[ext_len..];
        if ext_type == TLS_EXTENSION_KEY_SHARE {
            if ext_data.len() < 4 {
                return Err(Error::ParseFailure("server hello key_share extension is malformed"));
            }
            let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            return Ok(Some(group));
        }
    }
    Ok(None)
}

/// Formats key-share group for logs with symbolic name and hex code.
///
/// # Arguments
///
/// * `group` — Optional TLS NamedGroup negotiated in ServerHello key_share.
///
/// # Returns
///
/// Human-readable symbolic group name plus hex value, or `none`.
///
/// # Panics
///
/// This function does not panic.
fn format_key_share_group(group: Option<u16>) -> String {
    let Some(group_id) = group else {
        return "none".to_owned();
    };
    let name = match group_id {
        TLS13_KEY_SHARE_GROUP_X25519 => "x25519",
        TLS13_KEY_SHARE_GROUP_SECP256R1 => "secp256r1",
        TLS13_KEY_SHARE_GROUP_MLKEM768 => "mlkem768",
        TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID => "x25519_mlkem768_hybrid",
        _ => "unknown",
    };
    format!("{name}(0x{group_id:04x})")
}

/// Returns a short printable label for one TLS record content type.
///
/// # Arguments
///
/// * `content_type` — TLS record content type byte.
///
/// # Returns
///
/// Static label for known types, or `"unknown"` for others.
///
/// # Panics
///
/// This function does not panic.
fn record_type_name(content_type: u8) -> &'static str {
    match content_type {
        TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC => "change_cipher_spec",
        TLS_RECORD_TYPE_ALERT => "alert",
        TLS_RECORD_TYPE_HANDSHAKE => "handshake",
        TLS_RECORD_TYPE_APPLICATION_DATA => "application_data",
        _ => "unknown",
    }
}

/// Returns a short printable label for one handshake message type.
///
/// # Arguments
///
/// * `message_type` — Handshake message type byte.
///
/// # Returns
///
/// Static label for known types, or `"unknown"` for others.
///
/// # Panics
///
/// This function does not panic.
fn handshake_type_name(message_type: u8) -> &'static str {
    match message_type {
        1 => "client_hello",
        2 => "server_hello",
        4 => "new_session_ticket",
        8 => "encrypted_extensions",
        11 => "certificate",
        13 => "certificate_request",
        15 => "certificate_verify",
        20 => "finished",
        _ => "unknown",
    }
}

/// Returns a short printable label for one TLS alert level value.
///
/// # Arguments
///
/// * `level` — Alert level byte.
///
/// # Returns
///
/// Static label for known levels, or `"unknown"` when not mapped.
///
/// # Panics
///
/// This function does not panic.
fn alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "warning",
        2 => "fatal",
        _ => "unknown",
    }
}

/// Returns a short printable label for one TLS alert description code.
///
/// # Arguments
///
/// * `description` — Alert description byte.
///
/// # Returns
///
/// Static label for known descriptions, or `"unknown"` when not mapped.
///
/// # Panics
///
/// This function does not panic.
fn alert_description_name(description: u8) -> &'static str {
    match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        47 => "illegal_parameter",
        70 => "protocol_version",
        80 => "internal_error",
        109 => "missing_extension",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

/// Builds a one-line packet summary used in outbound tracing.
///
/// # Arguments
///
/// * `packet` — Serialized TLS packet bytes.
///
/// # Returns
///
/// Human-readable record type/version/length/hex preview line.
///
/// # Panics
///
/// This function does not panic.
fn summarize_packet_line(packet: &[u8]) -> String {
    if packet.len() < TLS_RECORD_HEADER_LEN {
        return "invalid_packet_too_short".to_owned();
    }
    let payload_len = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    format!(
        "type:{} version={:02x}{:02x} payload_len={} raw_preview={}",
        record_type_name(packet[0]),
        packet[1],
        packet[2],
        payload_len,
        hex_preview(packet, HEX_PREVIEW_LIMIT)
    )
}

/// Encodes bytes as lowercase hexadecimal preview with truncation suffix.
///
/// # Arguments
///
/// * `bytes` — Source bytes to summarize.
/// * `max_len` — Maximum number of bytes to include before ellipsis.
///
/// # Returns
///
/// Hex string preview with `...(+N bytes)` when truncated.
///
/// # Panics
///
/// This function does not panic.
fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    let shown_len = bytes.len().min(max_len);
    let mut out = String::with_capacity(shown_len.saturating_mul(2).saturating_add(16));
    for byte in &bytes[..shown_len] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    if bytes.len() > shown_len {
        out.push_str(&format!("...(+{} bytes)", bytes.len() - shown_len));
    }
    out
}

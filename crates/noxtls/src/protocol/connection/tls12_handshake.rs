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

//! TLS 1.2 handshake sequencing and message-shape helpers for `Connection`.

use super::*;

impl Connection {
    /// Processes TLS 1.2 server handshake flight in canonical order.
    ///
    /// Expected sequence:
    /// * `ServerHello`
    /// * `Certificate`
    /// * optional `ServerKeyExchange`
    /// * optional `CertificateRequest`
    /// * `ServerHelloDone`
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `ServerCertificateVerified`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_server_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 server flight processing requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ClientHelloSent {
            return Err(Error::StateError(
                "tls12 server flight can only be processed after client hello",
            ));
        }
        if messages.len() < 3 {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight is too short",
            ));
        }

        let mut index = 0_usize;
        self.noxtls_recv_server_hello(&messages[index])?;
        index += 1;
        let (next_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight expected certificate after server hello",
            ));
        }
        self.noxtls_recv_tls12_server_certificate(&messages[index])?;
        index += 1;

        while index < messages.len() {
            let (message_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
            if message_type == HANDSHAKE_SERVER_KEY_EXCHANGE {
                self.noxtls_recv_tls12_server_key_exchange(&messages[index])?;
                index += 1;
                continue;
            }
            if message_type == HANDSHAKE_CERTIFICATE_REQUEST {
                self.noxtls_recv_tls12_server_certificate_request(&messages[index])?;
                index += 1;
                continue;
            }
            break;
        }

        if index >= messages.len() {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight missing server hello done",
            ));
        }
        self.noxtls_recv_tls12_server_hello_done(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls12 server handshake messages",
            ));
        }
        self.state = HandshakeState::ServerCertificateVerified;
        Ok(())
    }

    /// Records an inbound TLS 1.2 ChangeCipherSpec transition before client Finished.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// `Ok(())` when the transition is accepted for the current handshake phase.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_tls12_change_cipher_spec(&mut self) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 change cipher spec requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ServerCertificateVerified {
            return Err(Error::StateError(
                "tls12 change cipher spec can only be processed after server handshake flight",
            ));
        }
        self.tls12_change_cipher_spec_seen = true;
        Ok(())
    }

    /// Processes TLS 1.2 client handshake flight after server has sent `ServerHelloDone`.
    ///
    /// Expected sequence:
    /// * `ClientKeyExchange`
    /// * optional `CertificateVerify`
    /// * `Finished` (requires prior `ChangeCipherSpec` signal)
    ///
    /// # Arguments
    /// * `messages`: Ordered client handshake messages from the peer.
    ///
    /// # Returns
    /// `Ok(())` when client flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_client_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 client flight processing requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ServerCertificateVerified {
            return Err(Error::StateError(
                "tls12 client flight can only be processed after server handshake flight",
            ));
        }
        if messages.len() < 2 {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight is too short",
            ));
        }
        let mut index = 0_usize;
        let (next_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight expected client key exchange first",
            ));
        }
        self.noxtls_recv_tls12_client_key_exchange(&messages[index])?;
        index += 1;

        if index < messages.len() {
            let (message_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
            if message_type == HANDSHAKE_CERTIFICATE_VERIFY {
                self.noxtls_recv_tls12_client_certificate_verify(&messages[index])?;
                index += 1;
            }
        }

        if !self.tls12_change_cipher_spec_seen {
            return Err(Error::ParseFailure(
                "tls12 expected change cipher spec before finished",
            ));
        }
        if index >= messages.len() {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight missing finished message",
            ));
        }
        self.noxtls_recv_tls12_client_finished(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls12 client handshake messages",
            ));
        }

        self.tls12_change_cipher_spec_seen = false;
        self.state = HandshakeState::Finished;
        Ok(())
    }

    /// Processes TLS 1.2 server flight and attempts automatic alert emission on failure.
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` on successful processing, or `Err((error, alert_packet))` where `alert_packet`
    /// contains the mapped TLS 1.2 alert packet when emission succeeds on this connection.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_server_handshake_flight_with_alert(
        &mut self,
        messages: &[Vec<u8>],
    ) -> core::result::Result<(), (Error, Option<Vec<u8>>)> {
        match self.noxtls_process_tls12_server_handshake_flight(messages) {
            Ok(()) => Ok(()),
            Err(error) => {
                let alert_packet = self.noxtls_send_tls12_alert_for_handshake_error(&error).ok();
                Err((error, alert_packet))
            }
        }
    }

    /// Processes TLS 1.2 client flight and attempts automatic alert emission on failure.
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from client.
    ///
    /// # Returns
    /// `Ok(())` on successful processing, or `Err((error, alert_packet))` where `alert_packet`
    /// contains the mapped TLS 1.2 alert packet when emission succeeds on this connection.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_client_handshake_flight_with_alert(
        &mut self,
        messages: &[Vec<u8>],
    ) -> core::result::Result<(), (Error, Option<Vec<u8>>)> {
        match self.noxtls_process_tls12_client_handshake_flight(messages) {
            Ok(()) => Ok(()),
            Err(error) => {
                let alert_packet = self.noxtls_send_tls12_alert_for_handshake_error(&error).ok();
                Err((error, alert_packet))
            }
        }
    }

    /// Maps a TLS 1.2 handshake processing error into a deterministic fatal alert description.
    ///
    /// # Arguments
    /// * `error`: Handshake processing error returned by TLS 1.2 sequencing/parsing helpers.
    ///
    /// # Returns
    /// `(AlertLevel::Fatal, AlertDescription)` selected for wire-level signaling policy.
    #[must_use]
    /// # Arguments
    ///
    /// * `error` — `error: &Error`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls12_alert_for_handshake_error(error: &Error) -> (AlertLevel, AlertDescription) {
        let description = match error {
            Error::StateError(message) => {
                if message.contains("can only be processed")
                    || message.contains("expected")
                    || message.contains("missing")
                {
                    AlertDescription::UnexpectedMessage
                } else {
                    AlertDescription::InternalError
                }
            }
            Error::ParseFailure(message) | Error::InvalidLength(message) => {
                if message.contains("expected")
                    || message.contains("missing")
                    || message.contains("unexpected trailing")
                    || message.contains("invalid")
                    || message.contains("malformed")
                    || message.contains("must be empty")
                    || message.contains("must not be empty")
                {
                    AlertDescription::UnexpectedMessage
                } else {
                    AlertDescription::IllegalParameter
                }
            }
            Error::InvalidEncoding(_message) => AlertDescription::IllegalParameter,
            Error::UnsupportedFeature(_message) | Error::CryptoFailure(_message) => {
                AlertDescription::HandshakeFailure
            }
        };
        (AlertLevel::Fatal, description)
    }

    /// Parses and records a TLS 1.2 Certificate handshake message with basic structure checks.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_server_certificate(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "tls12 certificate can only be processed after server hello",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure(
                "invalid tls12 certificate message type",
            ));
        }
        let certificates = noxtls_parse_tls12_certificate_list(body)?;
        if self.tls13_require_certificate_auth {
            self.noxtls_validate_tls13_server_certificate_chain(&certificates)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateReceived;
        Ok(())
    }

    /// Parses and records a TLS 1.2 ServerKeyExchange message when present.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_server_key_exchange(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 server key exchange can only be processed after certificate",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_SERVER_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "invalid tls12 server key exchange message type",
            ));
        }
        noxtls_parse_tls12_server_key_exchange_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 CertificateRequest message when server asks for client auth.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_server_certificate_request(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 certificate request can only be processed after certificate",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE_REQUEST {
            return Err(Error::ParseFailure(
                "invalid tls12 certificate request message type",
            ));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 certificate request body must not be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 ServerHelloDone message as end-of-server-flight marker.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_server_hello_done(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 server hello done can only be processed after certificate flight",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_SERVER_HELLO_DONE {
            return Err(Error::ParseFailure(
                "invalid tls12 server hello done message type",
            ));
        }
        if !body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 server hello done body must be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 ClientKeyExchange message as client-flight entrypoint.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_client_key_exchange(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "invalid tls12 client key exchange message type",
            ));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 client key exchange body must not be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records an optional TLS 1.2 client CertificateVerify handshake message.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_client_certificate_verify(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE_VERIFY {
            return Err(Error::ParseFailure(
                "invalid tls12 client certificate verify message type",
            ));
        }
        noxtls_parse_tls12_certificate_verify_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records TLS 1.2 client Finished handshake message shape.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_recv_tls12_client_finished(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_FINISHED {
            return Err(Error::ParseFailure("invalid tls12 finished message type"));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure("tls12 finished body must not be empty"));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }
}

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

//! DTLS 1.2 record, cookie, anti-amplification, and retransmit helpers.

use super::*;

impl Connection {
    /// Encodes a DTLS1.2 datagram record packet from content type, epoch, sequence, and payload.
    ///
    /// # Arguments
    /// * `content_type`: Record content type byte to place in DTLS header.
    /// * `epoch`: DTLS epoch value.
    /// * `sequence`: 48-bit DTLS record sequence number.
    /// * `payload`: Record payload bytes.
    ///
    /// # Returns
    /// Encoded DTLS record datagram bytes (`header || payload`).
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls12_record_packet(
        &self,
        content_type: RecordContentType,
        epoch: u16,
        sequence: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 record packet builder requires DTLS1.2 connection",
            ));
        }
        noxtls_encode_dtls_record_packet(content_type, [0xFE, 0xFD], epoch, sequence, payload)
    }

    /// Parses a DTLS1.2 datagram record packet into header fields and payload bytes.
    ///
    /// # Arguments
    /// * `packet`: Encoded DTLS record datagram bytes.
    ///
    /// # Returns
    /// Tuple of parsed DTLS record header and payload bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_parse_dtls12_record_packet(
        &self,
        packet: &[u8],
    ) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 record packet parser requires DTLS1.2 connection",
            ));
        }
        let (header, payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok((header, payload))
    }

    /// Fragments one DTLS1.2 handshake message into transport-sized handshake fragments.
    ///
    /// # Arguments
    /// * `handshake_type`: Handshake message type codepoint.
    /// * `message_seq`: DTLS handshake message sequence value.
    /// * `body`: Full handshake body bytes to fragment.
    /// * `max_fragment_len`: Maximum bytes per fragment payload.
    ///
    /// # Returns
    /// Ordered encoded DTLS handshake fragments.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_fragment_dtls12_handshake_message(
        &self,
        handshake_type: u8,
        message_seq: u16,
        body: &[u8],
        max_fragment_len: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake fragmentation requires DTLS1.2 connection",
            ));
        }
        noxtls_encode_dtls12_handshake_fragments(
            handshake_type,
            message_seq,
            body,
            max_fragment_len,
        )
    }

    /// Reassembles encoded DTLS1.2 handshake fragments into one complete message.
    ///
    /// # Arguments
    /// * `fragments`: Encoded handshake fragments for one message sequence.
    /// * `max_message_len`: Maximum total bytes accepted for one reassembled handshake message.
    ///
    /// # Returns
    /// Tuple of `(handshake_type, message_seq, full_handshake_body)`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_reassemble_dtls12_handshake_fragments(
        &self,
        fragments: &[Vec<u8>],
        max_message_len: usize,
    ) -> Result<(u8, u16, Vec<u8>)> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake reassembly requires DTLS1.2 connection",
            ));
        }
        noxtls_reassemble_dtls12_handshake_fragments(fragments, max_message_len)
    }

    /// Enables or disables DTLS1.2 anti-amplification transmit budget enforcement.
    ///
    /// When enabled, outbound datagrams are capped to `3x` observed inbound bytes until
    /// cookie validation succeeds.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `enforced` — `enforced: bool`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_anti_amplification_enforced(&mut self, enforced: bool) {
        self.dtls12_anti_amplification_enforced = enforced;
    }

    /// Records inbound DTLS datagram size for anti-amplification accounting.
    ///
    /// # Arguments
    /// * `bytes`: Number of bytes received from the peer datagram transport.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_record_dtls12_inbound_datagram(&mut self, bytes: usize) {
        self.dtls12_inbound_bytes = self.dtls12_inbound_bytes.saturating_add(bytes as u64);
    }

    /// Returns true when sending a datagram of `bytes` would stay within anti-amplification budget.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `bytes` — `bytes: usize`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_can_send_datagram_bytes(&self, bytes: usize) -> bool {
        if !self.dtls12_anti_amplification_enforced {
            return true;
        }
        if matches!(
            self.noxtls_dtls12_handshake_phase,
            Dtls12HandshakePhase::AwaitingClientKeyExchange
                | Dtls12HandshakePhase::AwaitingFinished
                | Dtls12HandshakePhase::Connected
        ) {
            return true;
        }
        let budget = self
            .dtls12_inbound_bytes
            .saturating_mul(DTLS12_ANTI_AMPLIFICATION_FACTOR);
        self.dtls12_outbound_bytes.saturating_add(bytes as u64) <= budget
    }

    /// Records outbound DTLS datagram size after validating anti-amplification budget.
    ///
    /// # Arguments
    /// * `bytes`: Number of bytes intended for outbound datagram transmission.
    ///
    /// # Returns
    /// `Ok(())` when transmission is allowed and accounted.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_record_dtls12_outbound_datagram(&mut self, bytes: usize) -> Result<()> {
        if !self.noxtls_dtls12_can_send_datagram_bytes(bytes) {
            return Err(Error::StateError(
                "dtls12 anti-amplification budget exceeded before cookie validation",
            ));
        }
        self.dtls12_outbound_bytes = self.dtls12_outbound_bytes.saturating_add(bytes as u64);
        Ok(())
    }

    /// Processes first DTLS1.2 `ClientHello` and returns a cookie challenge.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded ClientHello handshake message bytes.
    /// * `cookie_secret`: Server-local secret used to derive stateless cookie bytes.
    ///
    /// # Returns
    /// Encoded `HelloVerifyRequest` carrying derived cookie.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls12_client_hello_without_cookie(
        &mut self,
        client_hello: &[u8],
        cookie_secret: &[u8],
    ) -> Result<Vec<u8>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 cookie exchange requires DTLS1.2 connection",
            ));
        }
        if self.noxtls_dtls12_handshake_phase != Dtls12HandshakePhase::AwaitingClientHello {
            return Err(Error::StateError(
                "dtls12 cookie challenge requires initial client-hello phase",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(client_hello)?;
        if message_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::ParseFailure(
                "dtls12 cookie exchange requires client hello message",
            ));
        }
        let cookie = self.noxtls_compute_dtls12_cookie(client_hello, cookie_secret)?;
        self.dtls12_expected_cookie = Some(cookie.clone());
        self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingClientHelloWithCookie;
        self.noxtls_build_dtls12_hello_verify_request(&cookie)
    }

    /// Processes second DTLS1.2 `ClientHello` containing verified cookie bytes.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded retried ClientHello handshake message bytes.
    /// * `cookie`: Cookie bytes echoed by the client.
    /// * `cookie_secret`: Server-local secret used to derive expected cookie bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls12_client_hello_with_cookie(
        &mut self,
        client_hello: &[u8],
        cookie: &[u8],
        cookie_secret: &[u8],
    ) -> Result<()> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 cookie exchange requires DTLS1.2 connection",
            ));
        }
        if self.noxtls_dtls12_handshake_phase != Dtls12HandshakePhase::AwaitingClientHelloWithCookie {
            return Err(Error::StateError(
                "dtls12 cookie verification requires retry client-hello phase",
            ));
        }
        if cookie.is_empty() {
            return Err(Error::InvalidLength(
                "dtls12 client cookie must not be empty",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(client_hello)?;
        if message_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::ParseFailure(
                "dtls12 cookie verification requires client hello message",
            ));
        }
        let expected = self.noxtls_compute_dtls12_cookie(client_hello, cookie_secret)?;
        let Some(challenge_cookie) = self.dtls12_expected_cookie.as_ref() else {
            return Err(Error::StateError(
                "dtls12 cookie challenge must be issued before verification",
            ));
        };
        if !noxtls_constant_time_eq(challenge_cookie, cookie) || !noxtls_constant_time_eq(&expected, cookie) {
            return Err(Error::ParseFailure("dtls12 client cookie mismatch"));
        }
        self.dtls12_expected_cookie = None;
        self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingClientKeyExchange;
        self.state = HandshakeState::ClientHelloSent;
        Ok(())
    }

    /// Advances deterministic DTLS1.2 client-flight sequencing after cookie verification.
    ///
    /// Allowed handshake ordering:
    /// * `ClientKeyExchange`
    /// * `Finished`
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `message` — `message: &[u8]`.
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
    pub fn noxtls_process_dtls12_client_handshake_message(&mut self, message: &[u8]) -> Result<()> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake sequencing requires DTLS1.2 connection",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(message)?;
        match self.noxtls_dtls12_handshake_phase {
            Dtls12HandshakePhase::AwaitingClientKeyExchange => {
                if message_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
                    return Err(Error::ParseFailure(
                        "dtls12 expected client key exchange handshake message",
                    ));
                }
                self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingFinished;
                Ok(())
            }
            Dtls12HandshakePhase::AwaitingFinished => {
                if message_type != HANDSHAKE_FINISHED {
                    return Err(Error::ParseFailure(
                        "dtls12 expected finished handshake message",
                    ));
                }
                self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::Connected;
                self.state = HandshakeState::Finished;
                Ok(())
            }
            _ => Err(Error::StateError(
                "dtls12 handshake message received in invalid phase",
            )),
        }
    }

    /// Returns current deterministic DTLS1.2 handshake phase label for diagnostics/tests.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_handshake_phase(&self) -> &'static str {
        match self.noxtls_dtls12_handshake_phase {
            Dtls12HandshakePhase::AwaitingClientHello => "awaiting_client_hello",
            Dtls12HandshakePhase::AwaitingClientHelloWithCookie => {
                "awaiting_client_hello_with_cookie"
            }
            Dtls12HandshakePhase::AwaitingClientKeyExchange => "awaiting_client_key_exchange",
            Dtls12HandshakePhase::AwaitingFinished => "awaiting_finished",
            Dtls12HandshakePhase::Connected => "connected",
        }
    }

    /// Derives bounded DTLS1.2 cookie bytes from server secret and ClientHello transcript bytes.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `client_hello` — `client_hello: &[u8]`.
    /// * `cookie_secret` — `cookie_secret: &[u8]`.
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
    fn noxtls_compute_dtls12_cookie(&self, client_hello: &[u8], cookie_secret: &[u8]) -> Result<Vec<u8>> {
        if cookie_secret.is_empty() {
            return Err(Error::InvalidLength(
                "dtls12 cookie secret must not be empty",
            ));
        }
        let mut material = Vec::with_capacity(cookie_secret.len() + client_hello.len());
        material.extend_from_slice(cookie_secret);
        material.extend_from_slice(client_hello);
        let digest = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &material);
        let cookie_len = digest.len().min(16);
        Ok(digest[..cookie_len].to_vec())
    }

    /// Encodes DTLS1.2 HelloVerifyRequest carrying one stateless cookie challenge value.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `cookie` — `cookie: &[u8]`.
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
    fn noxtls_build_dtls12_hello_verify_request(&self, cookie: &[u8]) -> Result<Vec<u8>> {
        if cookie.is_empty() {
            return Err(Error::InvalidLength("dtls12 cookie must not be empty"));
        }
        if cookie.len() > DTLS12_MAX_COOKIE_LEN {
            return Err(Error::InvalidLength(
                "dtls12 cookie exceeds 8-bit cookie length field",
            ));
        }
        let mut body = Vec::with_capacity(3 + cookie.len());
        body.extend_from_slice(&[0xFE, 0xFD]);
        body.push(cookie.len() as u8);
        body.extend_from_slice(cookie);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_HELLO_VERIFY_REQUEST,
            &body,
        ))
    }

    /// Configures the initial DTLS retransmit timeout used for outbound flight scheduling.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `timeout_ms`: Initial resend delay in milliseconds; values below 1 are clamped.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_retransmit_initial_timeout_ms(&mut self, timeout_ms: u64) -> Result<()> {
        self.noxtls_ensure_dtls12_mode()?;
        self.dtls_retransmit_initial_timeout_ms = timeout_ms.max(1);
        Ok(())
    }

    /// Configures maximum resend attempts before a DTLS packet is dropped.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `attempts`: Number of due retransmits allowed before retirement; values below 1 are clamped.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_max_retransmit_attempts(&mut self, attempts: u8) -> Result<()> {
        self.noxtls_ensure_dtls12_mode()?;
        self.dtls_max_retransmit_attempts = attempts.max(1);
        Ok(())
    }

    /// Builds and schedules one outbound DTLS packet for timer-driven retransmission.
    ///
    /// # Arguments
    /// * `content_type`: DTLS record content type.
    /// * `epoch`: DTLS epoch value for this packet.
    /// * `sequence`: 48-bit DTLS sequence number.
    /// * `payload`: Record payload bytes.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Serialized DTLS datagram packet ready for immediate transmission.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls12_record_packet_for_flight(
        &mut self,
        content_type: RecordContentType,
        epoch: u16,
        sequence: u64,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls12_mode()?;
        let packet = self.noxtls_build_dtls12_record_packet(content_type, epoch, sequence, payload)?;
        self.dtls_retransmit_tracker.track_outbound_with_schedule(
            epoch,
            sequence,
            &packet,
            now_ms,
            self.dtls_retransmit_initial_timeout_ms,
        )?;
        Ok(packet)
    }

    /// Marks one DTLS outbound packet as acknowledged by `(epoch, sequence)`.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `epoch` — `epoch: u16`.
    /// * `sequence` — `sequence: u64`.
    ///
    /// # Returns
    /// `true` if a tracked packet matched and was marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls12_record_acked(&mut self, epoch: u16, sequence: u64) -> Result<bool> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self.dtls_retransmit_tracker.mark_acked(epoch, sequence))
    }

    /// Returns due retransmit packets and updates their backoff schedule.
    ///
    /// # Arguments
    /// * `now_ms`: Current monotonic timestamp used to decide due timers.
    ///
    /// # Returns
    /// DTLS packets that should be retransmitted now.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_poll_dtls12_due_retransmit_packets(&mut self, now_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self
            .dtls_retransmit_tracker
            .collect_due_retransmit_packets(now_ms, self.dtls_max_retransmit_attempts))
    }

    /// Returns currently unacknowledged DTLS packets regardless of timer state.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_pending_retransmit_packets(&self) -> Vec<Vec<u8>> {
        if !self.version.is_dtls() {
            return Vec::new();
        }
        self.dtls_retransmit_tracker.pending_retransmit_packets()
    }

    /// Prunes acknowledged DTLS packets from retransmit tracking.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// Number of pruned packet records.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_prune_dtls12_acked_records(&mut self) -> Result<usize> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self.dtls_retransmit_tracker.prune_acked())
    }

    /// Ensures DTLS-specific packet scheduler APIs are used only for DTLS profiles.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
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
    pub(crate) fn noxtls_ensure_dtls12_mode(&self) -> Result<()> {
        if !self.version.is_dtls() {
            return Err(Error::StateError(
                "dtls retransmit scheduler requires DTLS connection",
            ));
        }
        Ok(())
    }
}

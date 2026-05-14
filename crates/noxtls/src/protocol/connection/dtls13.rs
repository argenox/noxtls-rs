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

//! DTLS 1.3 record protection, active-flight tracking, and retransmit orchestration.

use super::*;

impl Connection {
    /// Installs DTLS1.3-style traffic keys and static IVs used for protected records.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `client_key`: Outbound client write key (AES-128-GCM).
    /// * `client_iv`: Outbound client static IV.
    /// * `server_key`: Inbound server write key (AES-128-GCM).
    /// * `server_iv`: Inbound server static IV.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_install_dtls13_traffic_keys(
        &mut self,
        client_key: [u8; 16],
        client_iv: [u8; 12],
        server_key: [u8; 16],
        server_iv: [u8; 12],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.dtls13_client_write_key = Some(client_key);
        self.dtls13_client_write_iv = Some(client_iv);
        self.dtls13_server_write_key = Some(server_key);
        self.dtls13_server_write_iv = Some(server_iv);
        self.dtls13_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        self.dtls13_client_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        Ok(())
    }

    /// Returns the installed DTLS 1.3 AES-128-GCM **server** handshake write key and IV.
    ///
    /// Populated after [`Self::noxtls_derive_handshake_secret`] (or equivalent record-protection install)
    /// for TLS 1.3 / DTLS 1.3. Intended for harnesses that seal synthetic server handshake records
    /// with the same material [`Self::noxtls_open_dtls13_record`] expects.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `Ok((key, iv))` when both values are installed.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when the connection is not DTLS 1.3 or keys are absent.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls13_handshake_server_write_material(&self) -> Result<([u8; 16], [u8; 12])> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_server_write_key.ok_or(Error::StateError(
            "dtls13 server write key is not installed",
        ))?;
        let iv = self
            .dtls13_server_write_iv
            .ok_or(Error::StateError("dtls13 server write iv is not installed"))?;
        Ok((key, iv))
    }

    /// Sets the outbound DTLS epoch and resets per-epoch sequence to zero.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `epoch`: New outbound epoch value.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls13_outbound_epoch(&mut self, epoch: u16) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot change dtls13 outbound epoch while active flight is incomplete",
            ));
        }
        if epoch < self.dtls13_outbound_epoch {
            return Err(Error::StateError("dtls13 outbound epoch must be monotonic"));
        }
        self.dtls13_outbound_epoch = epoch;
        self.dtls13_outbound_sequence = 0;
        Ok(())
    }

    /// Seals one DTLS1.3 protected record with installed client traffic keys.
    ///
    /// # Arguments
    /// * `plaintext`: Payload bytes to encrypt.
    ///
    /// # Returns
    /// Serialized DTLS packet (`header || ciphertext || tag`).
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls13_mode()?;
        self.noxtls_ensure_dtls13_tx_sequence_available()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        let packet = noxtls_seal_dtls13_aes128gcm_record(
            self.dtls13_outbound_epoch,
            self.dtls13_outbound_sequence,
            &key,
            &iv,
            plaintext,
        )?;
        self.dtls13_outbound_sequence = self.dtls13_outbound_sequence.saturating_add(1);
        Ok(packet)
    }

    /// Seals one DTLS1.3 protected record and schedules it for retransmission.
    ///
    /// # Arguments
    /// * `plaintext`: Payload bytes to encrypt.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Serialized DTLS packet (`header || ciphertext || tag`) tracked in retransmit state.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record_for_flight(
        &mut self,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls13_mode()?;
        let packet = self.noxtls_seal_dtls13_record(plaintext)?;
        let (header, _payload) = noxtls_parse_dtls_record_packet(&packet)?;
        self.dtls_retransmit_tracker.track_outbound_with_schedule(
            header.epoch,
            header.sequence,
            &packet,
            now_ms,
            self.dtls_retransmit_initial_timeout_ms,
        )?;
        Ok(packet)
    }

    /// Seals a DTLS1.3 multi-record flight and schedules each packet for retransmission.
    ///
    /// # Arguments
    /// * `plaintext_records`: Ordered plaintext payloads to seal as individual DTLS packets.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Ordered serialized DTLS packets tracked in retransmit state.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record_flight(
        &mut self,
        plaintext_records: &[&[u8]],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if plaintext_records.is_empty() {
            return Err(Error::InvalidLength(
                "dtls13 record flight must contain at least one payload",
            ));
        }
        let mut packets = Vec::with_capacity(plaintext_records.len());
        for plaintext in plaintext_records {
            packets.push(self.noxtls_seal_dtls13_record_for_flight(plaintext, now_ms)?);
        }
        Ok(packets)
    }

    /// Starts a DTLS1.3 active flight and tracks its packet keys for completion checks.
    ///
    /// # Arguments
    /// * `plaintext_records`: Ordered plaintext payloads to seal as one active flight.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Ordered serialized DTLS packets for immediate transmission.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_start_dtls13_active_flight(
        &mut self,
        plaintext_records: &[&[u8]],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot start noxtls_new dtls13 active flight while previous flight is incomplete",
            ));
        }
        let packets = self.noxtls_seal_dtls13_record_flight(plaintext_records, now_ms)?;
        self.dtls13_active_flight.clear();
        for packet in &packets {
            self.dtls13_active_flight
                .push(self.noxtls_parse_dtls_packet_key(packet)?);
        }
        self.dtls13_active_flight_started_at_ms = Some(now_ms);
        self.noxtls_dtls13_active_flight_failed = false;
        Ok(packets)
    }

    /// Configures timeout budget for DTLS1.3 active-flight completion.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `timeout_ms`: Maximum elapsed milliseconds before active flight is considered timed out.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls13_active_flight_timeout_ms(&mut self, timeout_ms: u64) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.dtls13_active_flight_timeout_ms = timeout_ms.max(1);
        Ok(())
    }

    /// Opens one DTLS1.3 protected record with installed server traffic keys and replay checks.
    ///
    /// # Arguments
    /// * `packet`: Serialized DTLS protected record.
    ///
    /// # Returns
    /// Parsed DTLS header and decrypted plaintext bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_dtls13_record(&mut self, packet: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_server_write_key.ok_or(Error::StateError(
            "dtls13 server write key is not installed",
        ))?;
        let iv = self
            .dtls13_server_write_iv
            .ok_or(Error::StateError("dtls13 server write iv is not installed"))?;
        noxtls_open_dtls13_aes128gcm_record(
            packet,
            &key,
            &iv,
            &mut self.dtls13_inbound_replay_tracker,
        )
    }

    /// Opens one DTLS1.3 protected record using installed client traffic keys.
    ///
    /// This is intended for server-side validation of encrypted client flights.
    ///
    /// # Arguments
    /// * `packet`: Serialized DTLS protected record.
    ///
    /// # Returns
    /// Parsed DTLS header and decrypted plaintext bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_dtls13_client_record(
        &mut self,
        packet: &[u8],
    ) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        noxtls_open_dtls13_aes128gcm_record(
            packet,
            &key,
            &iv,
            &mut self.dtls13_client_inbound_replay_tracker,
        )
    }

    /// Processes encrypted DTLS server post-hello handshake flight in strict TLS1.3 message order.
    ///
    /// Expected decrypted sequence:
    /// * `EncryptedExtensions`
    /// * optional `CertificateRequest`
    /// * `Certificate`
    /// * `CertificateVerify`
    /// * `Finished`
    ///
    /// # Arguments
    /// * `packets`: Encrypted DTLS packets carrying one handshake message each.
    ///
    /// # Returns
    /// `Ok(())` when decrypted flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_encrypted_server_flight_after_hello(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "dtls13 encrypted server flight requires server hello state",
            ));
        }
        if packets.len() < 4 {
            return Err(Error::ParseFailure(
                "dtls13 encrypted server flight is too short",
            ));
        }
        self.noxtls_derive_handshake_secret()?;
        let mut messages = Vec::with_capacity(packets.len());
        for packet in packets {
            let (_header, plaintext) = self.noxtls_open_dtls13_record(packet)?;
            messages.push(plaintext);
        }
        let mut index = 0_usize;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing dtls13 encrypted server handshake messages",
            ));
        }
        Ok(())
    }

    /// Processes full DTLS server handshake flight from ServerHello through encrypted post-hello flight.
    ///
    /// Expected sequence:
    /// * `ServerHello` (plaintext handshake wrapper)
    /// * encrypted post-hello packets consumed by `noxtls_process_dtls13_encrypted_server_flight_after_hello`
    ///
    /// # Arguments
    /// * `server_hello`: Encoded ServerHello handshake message.
    /// * `encrypted_packets`: Encrypted DTLS packets carrying post-hello server handshake messages.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_full_server_handshake_flight(
        &mut self,
        server_hello: &[u8],
        encrypted_packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.noxtls_recv_server_hello(server_hello)?;
        self.noxtls_process_dtls13_encrypted_server_flight_after_hello(encrypted_packets)
    }

    /// Processes encrypted DTLS client post-hello handshake flight with strict message ordering.
    ///
    /// Allowed decrypted sequence:
    /// * `Finished`
    /// * `Certificate`, `CertificateVerify`, `Finished`
    ///
    /// # Arguments
    /// * `packets`: Encrypted DTLS packets carrying client post-hello handshake messages.
    ///
    /// # Returns
    /// `Ok(())` when decrypted message ordering is valid.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_encrypted_client_flight_after_server_hello(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if packets.is_empty() {
            return Err(Error::ParseFailure(
                "dtls13 encrypted client flight is too short",
            ));
        }
        let mut message_types = Vec::with_capacity(packets.len());
        for packet in packets {
            let (_header, plaintext) = self.noxtls_open_dtls13_client_record(packet)?;
            let (handshake_type, _body) = noxtls_parse_handshake_message(&plaintext)?;
            message_types.push(handshake_type);
        }
        if message_types == [HANDSHAKE_FINISHED] {
            return Ok(());
        }
        if message_types
            == [
                HANDSHAKE_CERTIFICATE,
                HANDSHAKE_CERTIFICATE_VERIFY,
                HANDSHAKE_FINISHED,
            ]
        {
            return Ok(());
        }
        Err(Error::ParseFailure(
            "invalid dtls13 encrypted client flight message ordering",
        ))
    }

    /// Builds and schedules one outbound encrypted DTLS1.3 client post-hello handshake flight.
    ///
    /// Allowed plaintext message ordering:
    /// * `Finished`
    /// * `Certificate`, `CertificateVerify`, `Finished`
    ///
    /// # Arguments
    /// * `messages`: Ordered encoded handshake messages for one outbound client flight.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Encrypted DTLS packets tracked as the current active flight.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls13_encrypted_client_flight_after_server_hello(
        &mut self,
        messages: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.state != HandshakeState::ServerHelloReceived
            && self.state != HandshakeState::ServerCertificateVerified
            && self.state != HandshakeState::KeysDerived
        {
            return Err(Error::StateError(
                "dtls13 encrypted client flight requires post-server-hello state",
            ));
        }
        self.noxtls_validate_dtls13_client_post_hello_flight_order(messages)?;
        let plaintext_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        self.noxtls_start_dtls13_active_flight(&plaintext_refs, now_ms)
    }

    /// Advances outbound DTLS epoch and resets per-epoch record sequence counter.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// New outbound epoch value.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_advance_dtls13_outbound_epoch(&mut self) -> Result<u16> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot advance dtls13 outbound epoch while active flight is incomplete",
            ));
        }
        if self.dtls13_outbound_epoch == u16::MAX {
            return Err(Error::StateError("dtls13 outbound epoch exhausted"));
        }
        self.dtls13_outbound_epoch = self.dtls13_outbound_epoch.saturating_add(1);
        self.dtls13_outbound_sequence = 0;
        Ok(self.dtls13_outbound_epoch)
    }

    /// Opens a locally sealed DTLS1.3 protected record using installed client traffic keys.
    ///
    /// This loopback helper is intended for local validation paths where records were produced
    /// by `noxtls_seal_dtls13_record` on the same connection instance.
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
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
    pub fn noxtls_open_own_dtls13_record(&self, packet: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        let mut replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        noxtls_open_dtls13_aes128gcm_record(packet, &key, &iv, &mut replay_tracker)
    }

    /// Marks a tracked DTLS outbound packet as acknowledged using parsed record header fields.
    ///
    /// # Arguments
    /// * `packet`: DTLS record packet containing epoch/sequence metadata.
    ///
    /// # Returns
    /// `true` when matching tracked packet is found and marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls13_record_acked_from_packet(&mut self, packet: &[u8]) -> Result<bool> {
        self.noxtls_ensure_dtls13_mode()?;
        let (header, _payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok(self
            .dtls_retransmit_tracker
            .mark_acked(header.epoch, header.sequence))
    }

    /// Marks every DTLS packet in one flight as acknowledged using packet headers.
    ///
    /// # Arguments
    /// * `packets`: DTLS packets that belong to one outbound flight.
    ///
    /// # Returns
    /// Count of packets that matched tracked records and were marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls13_flight_acked_from_packets(&mut self, packets: &[Vec<u8>]) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        let mut marked = 0_usize;
        for packet in packets {
            if self.noxtls_mark_dtls13_record_acked_from_packet(packet)? {
                marked = marked.saturating_add(1);
            }
        }
        Ok(marked)
    }

    /// Polls retransmit scheduler for due packets belonging to the current active flight.
    ///
    /// # Arguments
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Due packets that should be resent for active-flight completion.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_poll_dtls13_active_flight_due_packets(&mut self, now_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(Vec::new());
        }
        if self.noxtls_dtls13_active_flight_has_timed_out(now_ms) {
            let _ = self.noxtls_abort_dtls13_active_flight()?;
            return Err(Error::StateError(
                "dtls13 active flight timed out before completion",
            ));
        }
        if self.noxtls_dtls13_active_flight_missing_tracked_records() {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = true;
            return Err(Error::StateError(
                "dtls13 active flight failed after retransmit budget exhausted",
            ));
        }
        let due_packets = self.noxtls_poll_dtls12_due_retransmit_packets(now_ms)?;
        let mut filtered = Vec::new();
        for packet in due_packets {
            let key = self.noxtls_parse_dtls_packet_key(&packet)?;
            if self.dtls13_active_flight.contains(&key) {
                filtered.push(packet);
            }
        }
        if self.noxtls_dtls13_active_flight_missing_tracked_records() {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = true;
            return Err(Error::StateError(
                "dtls13 active flight failed after retransmit budget exhausted",
            ));
        }
        Ok(filtered)
    }

    /// Acknowledges packets for the current active DTLS1.3 flight and prunes acked records.
    ///
    /// # Arguments
    /// * `packets`: Acked DTLS packets for this flight.
    ///
    /// # Returns
    /// Number of active-flight packets newly marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_acknowledge_dtls13_active_flight_packets(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(0);
        }
        let mut marked = 0_usize;
        for packet in packets {
            let key = self.noxtls_parse_dtls_packet_key(packet)?;
            if !self.dtls13_active_flight.contains(&key) {
                continue;
            }
            if self.noxtls_mark_dtls12_record_acked(key.0, key.1)? {
                marked = marked.saturating_add(1);
            }
        }
        let _ = self.noxtls_prune_dtls12_acked_records()?;
        if self.noxtls_is_dtls13_active_flight_complete()? {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = false;
        }
        Ok(marked)
    }

    /// Aborts the current active DTLS1.3 flight and removes its retransmit obligations.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// Number of active-flight records removed from retransmit tracking.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_abort_dtls13_active_flight(&mut self) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(0);
        }
        for (epoch, sequence) in &self.dtls13_active_flight {
            let _ = self.dtls_retransmit_tracker.mark_acked(*epoch, *sequence);
        }
        let removed = self.noxtls_prune_dtls12_acked_records()?;
        self.dtls13_active_flight.clear();
        self.dtls13_active_flight_started_at_ms = None;
        self.noxtls_dtls13_active_flight_failed = false;
        Ok(removed)
    }

    /// Reports whether the most recent active DTLS1.3 flight failed due to retry budget exhaustion.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls13_active_flight_failed(&self) -> bool {
        self.noxtls_dtls13_active_flight_failed
    }

    /// Reports whether all packets from the current active DTLS1.3 flight are complete.
    ///
    /// A flight is complete when no tracked unacknowledged retransmit record remains
    /// for any packet key registered in `noxtls_start_dtls13_active_flight`.
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
    pub fn noxtls_is_dtls13_active_flight_complete(&self) -> Result<bool> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(true);
        }
        for (epoch, sequence) in &self.dtls13_active_flight {
            let still_pending = self.dtls_retransmit_tracker.records().iter().any(|record| {
                record.epoch == *epoch && record.sequence == *sequence && !record.acknowledged
            });
            if still_pending {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Parses `(epoch, sequence)` key used for DTLS retransmit record correlation.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
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
    fn noxtls_parse_dtls_packet_key(&self, packet: &[u8]) -> Result<(u16, u64)> {
        let (header, _payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok((header.epoch, header.sequence))
    }

    /// Reports whether active-flight elapsed time exceeded configured timeout budget.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `now_ms` — `now_ms: u64`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_dtls13_active_flight_has_timed_out(&self, now_ms: u64) -> bool {
        let Some(started_at_ms) = self.dtls13_active_flight_started_at_ms else {
            return false;
        };
        now_ms.saturating_sub(started_at_ms) > self.dtls13_active_flight_timeout_ms
    }

    /// Returns true when active-flight keys no longer exist in retransmit tracker records.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_dtls13_active_flight_missing_tracked_records(&self) -> bool {
        self.dtls13_active_flight.iter().any(|(epoch, sequence)| {
            !self
                .dtls_retransmit_tracker
                .records()
                .iter()
                .any(|record| record.epoch == *epoch && record.sequence == *sequence)
        })
    }

    /// Validates allowed DTLS1.3 client post-hello flight message ordering.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `messages` — `messages: &[Vec<u8>]`.
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
    fn noxtls_validate_dtls13_client_post_hello_flight_order(
        &self,
        messages: &[Vec<u8>],
    ) -> Result<()> {
        if messages.is_empty() {
            return Err(Error::InvalidLength(
                "dtls13 encrypted client flight must contain at least one message",
            ));
        }
        let mut message_types = Vec::with_capacity(messages.len());
        for message in messages {
            let (handshake_type, _body) = noxtls_parse_handshake_message(message)?;
            message_types.push(handshake_type);
        }
        if message_types == [HANDSHAKE_FINISHED] {
            return Ok(());
        }
        if message_types
            == [
                HANDSHAKE_CERTIFICATE,
                HANDSHAKE_CERTIFICATE_VERIFY,
                HANDSHAKE_FINISHED,
            ]
        {
            return Ok(());
        }
        Err(Error::ParseFailure(
            "invalid dtls13 client post-hello flight message ordering",
        ))
    }

    /// Ensures DTLS1.3 packet APIs are used only for DTLS profiles.
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
    fn noxtls_ensure_dtls13_mode(&self) -> Result<()> {
        if !self.version.is_dtls() {
            return Err(Error::StateError("dtls13 APIs require DTLS connection"));
        }
        Ok(())
    }

    /// Ensures DTLS outbound record sequence space remains available before sealing.
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
    fn noxtls_ensure_dtls13_tx_sequence_available(&self) -> Result<()> {
        if self.dtls13_outbound_sequence > DTLS13_MAX_SEQUENCE {
            return Err(Error::StateError(
                "dtls13 outbound record sequence exhausted",
            ));
        }
        Ok(())
    }

    /// Mirrors installed record-protection keys into DTLS1.3 traffic state when using DTLS profile.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub(crate) fn noxtls_sync_dtls13_traffic_keys_from_record_protection_state(&mut self) {
        if !self.version.is_dtls() {
            return;
        }
        self.dtls13_client_write_key = self.client_write_key.map(|full| {
            full[..16]
                .try_into()
                .expect("dtls13 shim copies first 16 bytes of traffic key material")
        });
        self.dtls13_client_write_iv = self.client_write_iv;
        self.dtls13_server_write_key = self.server_write_key.map(|full| {
            full[..16]
                .try_into()
                .expect("dtls13 shim copies first 16 bytes of traffic key material")
        });
        self.dtls13_server_write_iv = self.server_write_iv;
        self.dtls13_outbound_epoch = 0;
        self.dtls13_outbound_sequence = 0;
        self.dtls13_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        self.dtls13_client_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
    }
}

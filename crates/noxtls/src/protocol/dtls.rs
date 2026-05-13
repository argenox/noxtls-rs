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

use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};
use noxtls_crypto::{noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt, AesCipher};

use super::state::RecordContentType;

const DTLS_RECORD_HEADER_LEN: usize = 13;
const DTLS_MAX_SEQUENCE: u64 = (1_u64 << 48) - 1;
const DTLS13_AEAD_TAG_LEN: usize = 16;
const DTLS12_HANDSHAKE_FRAGMENT_HEADER_LEN: usize = 12;

/// Represents a DTLS record-layer header for datagram framing.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DtlsRecordHeader {
    pub content_type: RecordContentType,
    pub version: [u8; 2],
    pub epoch: u16,
    pub sequence: u64,
    pub length: u16,
}

/// Represents one DTLS1.2 handshake fragment header and payload bytes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DtlsHandshakeFragment {
    pub handshake_type: u8,
    pub message_len: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_len: u32,
    pub fragment_body: Vec<u8>,
}

/// Tracks a DTLS anti-replay bitmap for one epoch.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct DtlsReplayWindow {
    latest_sequence: u64,
    bitmap: u64,
    initialized: bool,
}

/// Serializable snapshot of one DTLS replay-window state.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct DtlsReplayWindowSnapshot {
    pub latest_sequence: u64,
    pub bitmap: u64,
    pub initialized: bool,
}

impl DtlsReplayWindow {
    /// Creates a fresh replay window with no accepted records.
    #[must_use]
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// A new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks and marks a sequence number according to DTLS replay-window rules.
    ///
    /// # Arguments
    /// * `sequence` — Incoming record sequence number for this epoch.
    ///
    /// # Returns
    /// `true` when record is accepted and state updated; `false` on replay/too-old.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn check_and_mark(&mut self, sequence: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.latest_sequence = sequence;
            self.bitmap = 1;
            return true;
        }
        if sequence > self.latest_sequence {
            let shift = sequence - self.latest_sequence;
            if shift >= 64 {
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift as u32;
            }
            self.bitmap |= 1;
            self.latest_sequence = sequence;
            return true;
        }
        let delta = self.latest_sequence - sequence;
        if delta >= 64 {
            return false;
        }
        let mask = 1_u64 << (delta as u32);
        if (self.bitmap & mask) != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }

    /// Returns a copyable snapshot of replay-window state for persistence or transfer.
    ///
    /// # Arguments
    /// * `self`: Replay window to snapshot.
    ///
    /// # Returns
    /// Snapshot containing latest sequence, bitmap, and initialization flag.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn snapshot(&self) -> DtlsReplayWindowSnapshot {
        DtlsReplayWindowSnapshot {
            latest_sequence: self.latest_sequence,
            bitmap: self.bitmap,
            initialized: self.initialized,
        }
    }

    /// Restores replay-window state from a previously captured snapshot.
    ///
    /// # Arguments
    /// * `self`: Replay window to update.
    /// * `snapshot`: Snapshot payload to apply.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn restore_from_snapshot(&mut self, snapshot: DtlsReplayWindowSnapshot) {
        self.latest_sequence = snapshot.latest_sequence;
        self.bitmap = snapshot.bitmap;
        self.initialized = snapshot.initialized;
    }
}

/// Tracks DTLS anti-replay state across epoch transitions.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct DtlsEpochReplayTracker {
    current_epoch: Option<u16>,
    current_window: DtlsReplayWindow,
    previous_epoch: Option<u16>,
    previous_window: DtlsReplayWindow,
}

impl DtlsEpochReplayTracker {
    /// Creates an epoch-aware replay tracker with empty state.
    #[must_use]
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// A new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks one `(epoch, sequence)` pair against epoch + replay-window policy.
    ///
    /// # Arguments
    /// * `epoch` — DTLS epoch for incoming record.
    /// * `sequence` — 48-bit sequence number carried by that epoch.
    ///
    /// # Returns
    /// `true` when accepted and tracked; `false` for replay or too-old epoch/sequence.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn check_and_mark(&mut self, epoch: u16, sequence: u64) -> bool {
        let Some(current_epoch) = self.current_epoch else {
            self.current_epoch = Some(epoch);
            self.current_window = DtlsReplayWindow::new();
            return self.current_window.check_and_mark(sequence);
        };
        if epoch == current_epoch {
            return self.current_window.check_and_mark(sequence);
        }
        if let Some(previous_epoch) = self.previous_epoch {
            if epoch == previous_epoch {
                return self.previous_window.check_and_mark(sequence);
            }
        }
        if epoch > current_epoch {
            self.promote_epoch(epoch);
            return self.current_window.check_and_mark(sequence);
        }
        false
    }

    // Promotes replay windows for a newly observed higher epoch.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `new_epoch` — `new_epoch: u16`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn promote_epoch(&mut self, new_epoch: u16) {
        self.previous_epoch = self.current_epoch;
        self.previous_window = self.current_window;
        self.current_epoch = Some(new_epoch);
        self.current_window = DtlsReplayWindow::new();
    }
}

/// Stores one outbound DTLS packet entry for potential retransmission.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DtlsFlightRecord {
    pub epoch: u16,
    pub sequence: u64,
    pub packet: Vec<u8>,
    pub acknowledged: bool,
    pub retransmit_count: u8,
    pub last_sent_at_ms: u64,
    pub next_retransmit_at_ms: u64,
    pub retransmit_timeout_ms: u64,
}

/// Tracks outbound DTLS flight packets for retransmission and ack processing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DtlsFlightRetransmitTracker {
    records: Vec<DtlsFlightRecord>,
    max_records: usize,
}

impl DtlsFlightRetransmitTracker {
    /// Creates a retransmit tracker with bounded packet history.
    ///
    /// Values smaller than 1 are clamped to 1.
    #[must_use]
    /// # Arguments
    ///
    /// * `max_records` — `max_records: usize`.
    ///
    /// # Returns
    ///
    /// A new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Vec::new(),
            max_records: max_records.max(1),
        }
    }

    /// Tracks one outbound DTLS packet keyed by `(epoch, sequence)`.
    ///
    /// If the key already exists, packet bytes are replaced and ack state is reset.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `epoch` — `epoch: u16`.
    /// * `sequence` — `sequence: u64`.
    /// * `packet` — `packet: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn track_outbound(&mut self, epoch: u16, sequence: u64, packet: &[u8]) -> Result<()> {
        self.track_outbound_with_schedule(epoch, sequence, packet, 0, 1_000)
    }

    /// Tracks one outbound DTLS packet with explicit resend scheduling parameters.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `epoch` — DTLS epoch tied to this packet.
    /// * `sequence` — 48-bit DTLS sequence number.
    /// * `packet` — Serialized DTLS datagram bytes to retain.
    /// * `now_ms` — Monotonic timestamp used as send baseline.
    /// * `initial_timeout_ms` — Initial delay before first retransmit; values below 1 are clamped.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn track_outbound_with_schedule(
        &mut self,
        epoch: u16,
        sequence: u64,
        packet: &[u8],
        now_ms: u64,
        initial_timeout_ms: u64,
    ) -> Result<()> {
        if sequence > DTLS_MAX_SEQUENCE {
            return Err(Error::InvalidLength(
                "dtls sequence number exceeds 48-bit range",
            ));
        }
        let timeout_ms = initial_timeout_ms.max(1);
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.epoch == epoch && record.sequence == sequence)
        {
            record.packet = packet.to_vec();
            record.acknowledged = false;
            record.retransmit_count = 0;
            record.last_sent_at_ms = now_ms;
            record.retransmit_timeout_ms = timeout_ms;
            record.next_retransmit_at_ms = now_ms.saturating_add(timeout_ms);
            return Ok(());
        }
        self.records.push(DtlsFlightRecord {
            epoch,
            sequence,
            packet: packet.to_vec(),
            acknowledged: false,
            retransmit_count: 0,
            last_sent_at_ms: now_ms,
            next_retransmit_at_ms: now_ms.saturating_add(timeout_ms),
            retransmit_timeout_ms: timeout_ms,
        });
        while self.records.len() > self.max_records {
            self.records.remove(0);
        }
        Ok(())
    }

    /// Marks one tracked packet as acknowledged by `(epoch, sequence)`.
    ///
    /// Returns `true` when matching entry is found and updated.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `epoch` — `epoch: u16`.
    /// * `sequence` — `sequence: u64`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn mark_acked(&mut self, epoch: u16, sequence: u64) -> bool {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.epoch == epoch && record.sequence == sequence)
        {
            record.acknowledged = true;
            return true;
        }
        false
    }

    /// Returns all currently unacknowledged packets in tracked order.
    #[must_use]
    /// # Arguments
    ///
    /// * `self` — Immutable receiver `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn pending_retransmit_packets(&self) -> Vec<Vec<u8>> {
        self.records
            .iter()
            .filter(|record| !record.acknowledged)
            .map(|record| record.packet.clone())
            .collect()
    }

    /// Returns all currently due retransmit packets and advances their resend schedule.
    ///
    /// Retransmit timeout is doubled after each due resend (bounded by `u64::MAX`).
    /// Records that hit `max_retransmit_attempts` are dropped before returning.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `now_ms` — `now_ms: u64`.
    /// * `max_retransmit_attempts` — `max_retransmit_attempts: u8`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn collect_due_retransmit_packets(
        &mut self,
        now_ms: u64,
        max_retransmit_attempts: u8,
    ) -> Vec<Vec<u8>> {
        self.records.retain(|record| {
            record.acknowledged || record.retransmit_count < max_retransmit_attempts
        });

        let mut due_packets = Vec::new();
        for record in self.records.iter_mut() {
            if record.acknowledged || now_ms < record.next_retransmit_at_ms {
                continue;
            }
            due_packets.push(record.packet.clone());
            record.retransmit_count = record.retransmit_count.saturating_add(1);
            record.last_sent_at_ms = now_ms;
            record.retransmit_timeout_ms = record.retransmit_timeout_ms.saturating_mul(2).max(1);
            record.next_retransmit_at_ms = now_ms.saturating_add(record.retransmit_timeout_ms);
        }
        due_packets
    }

    /// Removes acknowledged records and returns the number removed.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn prune_acked(&mut self) -> usize {
        let original_len = self.records.len();
        self.records.retain(|record| !record.acknowledged);
        original_len.saturating_sub(self.records.len())
    }

    /// Returns immutable view of tracked flight records.
    #[must_use]
    /// # Arguments
    ///
    /// * `self` — Immutable receiver `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn records(&self) -> &[DtlsFlightRecord] {
        &self.records
    }
}

/// Encodes DTLS record header fields into the 13-byte wire format.
/// # Arguments
///
/// * `header` — `header: DtlsRecordHeader`.
///
/// # Returns
///
/// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_encode_dtls_record_header(header: DtlsRecordHeader) -> Result<[u8; DTLS_RECORD_HEADER_LEN]> {
    if header.sequence > DTLS_MAX_SEQUENCE {
        return Err(Error::InvalidLength(
            "dtls sequence number exceeds 48-bit range",
        ));
    }
    let mut out = [0_u8; DTLS_RECORD_HEADER_LEN];
    out[0] = header.content_type.to_u8();
    out[1..3].copy_from_slice(&header.version);
    out[3..5].copy_from_slice(&header.epoch.to_be_bytes());
    out[5] = ((header.sequence >> 40) & 0xFF) as u8;
    out[6] = ((header.sequence >> 32) & 0xFF) as u8;
    out[7] = ((header.sequence >> 24) & 0xFF) as u8;
    out[8] = ((header.sequence >> 16) & 0xFF) as u8;
    out[9] = ((header.sequence >> 8) & 0xFF) as u8;
    out[10] = (header.sequence & 0xFF) as u8;
    out[11..13].copy_from_slice(&header.length.to_be_bytes());
    Ok(out)
}

/// Parses a DTLS record header and returns header + remaining bytes.
/// # Arguments
///
/// * `input` — `input: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_parse_dtls_record_header(input: &[u8]) -> Result<(DtlsRecordHeader, &[u8])> {
    if input.len() < DTLS_RECORD_HEADER_LEN {
        return Err(Error::ParseFailure("dtls record header truncated"));
    }
    let content_type = RecordContentType::from_u8(input[0])
        .ok_or(Error::ParseFailure("unknown dtls record content type"))?;
    let version = [input[1], input[2]];
    let epoch = u16::from_be_bytes([input[3], input[4]]);
    let sequence = (u64::from(input[5]) << 40)
        | (u64::from(input[6]) << 32)
        | (u64::from(input[7]) << 24)
        | (u64::from(input[8]) << 16)
        | (u64::from(input[9]) << 8)
        | u64::from(input[10]);
    let length = u16::from_be_bytes([input[11], input[12]]);
    let header = DtlsRecordHeader {
        content_type,
        version,
        epoch,
        sequence,
        length,
    };
    Ok((header, &input[DTLS_RECORD_HEADER_LEN..]))
}

/// Encodes a full DTLS record packet (`header || payload`).
/// # Arguments
///
/// * `content_type` — `content_type: RecordContentType`.
/// * `version` — `version: [u8; 2]`.
/// * `epoch` — `epoch: u16`.
/// * `sequence` — `sequence: u64`.
/// * `payload` — `payload: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_encode_dtls_record_packet(
    content_type: RecordContentType,
    version: [u8; 2],
    epoch: u16,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "dtls payload exceeds 16-bit length field",
        ));
    }
    let header = DtlsRecordHeader {
        content_type,
        version,
        epoch,
        sequence,
        length: payload.len() as u16,
    };
    let mut out = Vec::with_capacity(DTLS_RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(&noxtls_encode_dtls_record_header(header)?);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parses a full DTLS record packet and validates payload length match.
/// # Arguments
///
/// * `input` — `input: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_parse_dtls_record_packet(input: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
    let (header, body) = noxtls_parse_dtls_record_header(input)?;
    if body.len() != usize::from(header.length) {
        return Err(Error::ParseFailure(
            "dtls payload length does not match header",
        ));
    }
    Ok((header, body.to_vec()))
}

/// Splits one DTLS1.2 handshake body into ordered fragments.
///
/// # Arguments
/// * `handshake_type` — DTLS handshake message type codepoint.
/// * `message_seq` — DTLS handshake message sequence number.
/// * `body` — Full handshake body bytes to fragment.
/// * `max_fragment_len` — Maximum fragment payload bytes per output fragment.
///
/// # Returns
/// Ordered encoded DTLS handshake fragments (`header || fragment_body`).
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_encode_dtls12_handshake_fragments(
    handshake_type: u8,
    message_seq: u16,
    body: &[u8],
    max_fragment_len: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_fragment_len == 0 {
        return Err(Error::InvalidLength(
            "dtls12 handshake max fragment length must be greater than zero",
        ));
    }
    if body.len() > 0x00FF_FFFF {
        return Err(Error::InvalidLength(
            "dtls12 handshake body exceeds 24-bit message length",
        ));
    }
    if body.is_empty() {
        return Ok(vec![encode_dtls12_handshake_fragment(
            handshake_type,
            message_seq,
            0,
            0,
            &[],
        )?]);
    }
    let mut out = Vec::new();
    let mut offset = 0_usize;
    while offset < body.len() {
        let end = (offset + max_fragment_len).min(body.len());
        out.push(encode_dtls12_handshake_fragment(
            handshake_type,
            message_seq,
            body.len() as u32,
            offset as u32,
            &body[offset..end],
        )?);
        offset = end;
    }
    Ok(out)
}

/// Parses one encoded DTLS1.2 handshake fragment.
/// # Arguments
///
/// * `input` — `input: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_parse_dtls12_handshake_fragment(input: &[u8]) -> Result<DtlsHandshakeFragment> {
    if input.len() < DTLS12_HANDSHAKE_FRAGMENT_HEADER_LEN {
        return Err(Error::ParseFailure(
            "dtls12 handshake fragment header truncated",
        ));
    }
    let handshake_type = input[0];
    let message_len =
        (u32::from(input[1]) << 16) | (u32::from(input[2]) << 8) | u32::from(input[3]);
    let message_seq = u16::from_be_bytes([input[4], input[5]]);
    let fragment_offset =
        (u32::from(input[6]) << 16) | (u32::from(input[7]) << 8) | u32::from(input[8]);
    let fragment_len =
        (u32::from(input[9]) << 16) | (u32::from(input[10]) << 8) | u32::from(input[11]);
    let body = &input[DTLS12_HANDSHAKE_FRAGMENT_HEADER_LEN..];
    if body.len() != fragment_len as usize {
        return Err(Error::ParseFailure(
            "dtls12 handshake fragment length does not match header",
        ));
    }
    if fragment_offset > message_len {
        return Err(Error::ParseFailure(
            "dtls12 handshake fragment offset exceeds message length",
        ));
    }
    let fragment_end = fragment_offset.saturating_add(fragment_len);
    if fragment_end > message_len {
        return Err(Error::ParseFailure(
            "dtls12 handshake fragment range exceeds message length",
        ));
    }
    Ok(DtlsHandshakeFragment {
        handshake_type,
        message_len,
        message_seq,
        fragment_offset,
        fragment_len,
        fragment_body: body.to_vec(),
    })
}

/// Reassembles DTLS1.2 handshake fragments into one complete message body.
///
/// # Arguments
/// * `fragments` — Encoded fragments for one handshake message sequence.
/// * `max_message_len` — Upper bound for anti-amplification/reassembly memory safety.
///
/// # Returns
/// Tuple of `(handshake_type, message_seq, full_body)` when reassembly is complete.
/// # Errors
///
/// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
///
/// # Panics
///
/// This function does not panic.
///
pub fn noxtls_reassemble_dtls12_handshake_fragments(
    fragments: &[Vec<u8>],
    max_message_len: usize,
) -> Result<(u8, u16, Vec<u8>)> {
    if fragments.is_empty() {
        return Err(Error::InvalidLength(
            "dtls12 reassembly requires at least one fragment",
        ));
    }
    let first = noxtls_parse_dtls12_handshake_fragment(&fragments[0])?;
    let total_len = first.message_len as usize;
    if total_len > max_message_len {
        return Err(Error::InvalidLength(
            "dtls12 handshake reassembly exceeds configured size limit",
        ));
    }
    let mut out = vec![0_u8; total_len];
    let mut filled = vec![false; total_len];
    for encoded in fragments {
        let fragment = noxtls_parse_dtls12_handshake_fragment(encoded)?;
        if fragment.handshake_type != first.handshake_type
            || fragment.message_seq != first.message_seq
            || fragment.message_len != first.message_len
        {
            return Err(Error::ParseFailure(
                "dtls12 reassembly fragments must share type, sequence, and total length",
            ));
        }
        let start = fragment.fragment_offset as usize;
        let end = start + fragment.fragment_len as usize;
        out[start..end].copy_from_slice(&fragment.fragment_body);
        for slot in &mut filled[start..end] {
            *slot = true;
        }
    }
    if filled.iter().any(|is_set| !is_set) {
        return Err(Error::ParseFailure(
            "dtls12 reassembly is incomplete after applying fragments",
        ));
    }
    Ok((first.handshake_type, first.message_seq, out))
}

/// Encodes one DTLS 1.2 handshake fragment with a 12-byte header and fragment body.
///
/// # Arguments
///
/// * `handshake_type` — TLS `HandshakeType` for this fragment.
/// * `message_seq` — DTLS `message_seq` value shared across fragments of one message.
/// * `message_len` — Total reconstructed handshake message length in bytes (24-bit).
/// * `fragment_offset` — Byte offset of this fragment within the full message (24-bit).
/// * `fragment_body` — Fragment payload bytes.
///
/// # Returns
///
/// On success, owned bytes containing the fragment header followed by `fragment_body`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when any 24-bit field overflows its wire range or the fragment range exceeds `message_len`.
///
/// # Panics
///
/// This function does not panic.
fn encode_dtls12_handshake_fragment(
    handshake_type: u8,
    message_seq: u16,
    message_len: u32,
    fragment_offset: u32,
    fragment_body: &[u8],
) -> Result<Vec<u8>> {
    if message_len > 0x00FF_FFFF {
        return Err(Error::InvalidLength(
            "dtls12 handshake message length exceeds 24-bit field",
        ));
    }
    if fragment_offset > 0x00FF_FFFF {
        return Err(Error::InvalidLength(
            "dtls12 fragment offset exceeds 24-bit field",
        ));
    }
    if fragment_body.len() > 0x00FF_FFFF {
        return Err(Error::InvalidLength(
            "dtls12 fragment length exceeds 24-bit field",
        ));
    }
    let fragment_len = fragment_body.len() as u32;
    if fragment_offset.saturating_add(fragment_len) > message_len {
        return Err(Error::InvalidLength(
            "dtls12 fragment range exceeds handshake message length",
        ));
    }
    let mut out = Vec::with_capacity(DTLS12_HANDSHAKE_FRAGMENT_HEADER_LEN + fragment_body.len());
    out.push(handshake_type);
    out.push(((message_len >> 16) & 0xFF) as u8);
    out.push(((message_len >> 8) & 0xFF) as u8);
    out.push((message_len & 0xFF) as u8);
    out.extend_from_slice(&message_seq.to_be_bytes());
    out.push(((fragment_offset >> 16) & 0xFF) as u8);
    out.push(((fragment_offset >> 8) & 0xFF) as u8);
    out.push((fragment_offset & 0xFF) as u8);
    out.push(((fragment_len >> 16) & 0xFF) as u8);
    out.push(((fragment_len >> 8) & 0xFF) as u8);
    out.push((fragment_len & 0xFF) as u8);
    out.extend_from_slice(fragment_body);
    Ok(out)
}

/// Computes serialized DTLS1.3 AES-128-GCM record packet size for a plaintext length.
///
/// # Arguments
///
/// * `plaintext_len` — Number of plaintext payload bytes to protect.
///
/// # Returns
///
/// Total packet size (`DTLS record header + ciphertext + AEAD tag`).
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when length arithmetic overflows or the payload exceeds the 16-bit DTLS length field.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_dtls13_aes128gcm_record_size(plaintext_len: usize) -> Result<usize> {
    let payload_len =
        plaintext_len
            .checked_add(DTLS13_AEAD_TAG_LEN)
            .ok_or(Error::InvalidLength(
                "dtls encrypted payload length overflow",
            ))?;
    if payload_len > usize::from(u16::MAX) {
        return Err(Error::InvalidLength(
            "dtls encrypted payload exceeds 16-bit length field",
        ));
    }
    DTLS_RECORD_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(Error::InvalidLength("dtls packet length overflow"))
}

/// Seals one DTLS1.3-style protected record packet using AES-GCM.
///
/// # Arguments
///
/// * `epoch` — DTLS epoch value for replay domain separation.
/// * `sequence` — 48-bit per-epoch record sequence number.
/// * `key` — 16-byte AEAD key material.
/// * `static_iv` — 12-byte static IV used for per-record nonce derivation.
/// * `plaintext` — Plaintext bytes to encrypt and authenticate.
///
/// # Returns
///
/// Full DTLS packet (`header || ciphertext || tag`) with outer content type `application_data`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when the sequence is out of range or sizing fails, [`Error::ParseFailure`] for header issues, or other errors from AES-GCM or cipher setup.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_seal_dtls13_aes128gcm_record(
    epoch: u16,
    sequence: u64,
    key: &[u8; 16],
    static_iv: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if sequence > DTLS_MAX_SEQUENCE {
        return Err(Error::InvalidLength(
            "dtls sequence number exceeds 48-bit range",
        ));
    }
    let nonce = build_dtls13_nonce(*static_iv, epoch, sequence);
    let cipher = AesCipher::new(key)?;
    let payload_len = noxtls_dtls13_aes128gcm_record_size(plaintext.len())? - DTLS_RECORD_HEADER_LEN;
    let header = DtlsRecordHeader {
        content_type: RecordContentType::ApplicationData,
        version: [0xFE, 0xFD],
        epoch,
        sequence,
        length: payload_len as u16,
    };
    let header_bytes = noxtls_encode_dtls_record_header(header)?;
    let (ciphertext, tag) = noxtls_aes_gcm_encrypt(&cipher, &nonce, &header_bytes, plaintext)?;
    let mut packet = Vec::with_capacity(noxtls_dtls13_aes128gcm_record_size(plaintext.len())?);
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(&tag);
    Ok(packet)
}

/// Opens one DTLS1.3-style protected record packet using AES-GCM and replay checks.
///
/// # Arguments
///
/// * `packet` — Encoded DTLS packet (`header || ciphertext || tag`).
/// * `key` — 16-byte AEAD key material.
/// * `static_iv` — 12-byte static IV used for per-record nonce derivation.
/// * `replay_tracker` — Epoch-aware replay tracker updated on successful acceptance path.
///
/// # Returns
///
/// Tuple of parsed DTLS header and decrypted plaintext bytes.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] for malformed headers or ciphertext, [`Error::StateError`] on replay, or errors from AES-GCM decryption.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_open_dtls13_aes128gcm_record(
    packet: &[u8],
    key: &[u8; 16],
    static_iv: &[u8; 12],
    replay_tracker: &mut DtlsEpochReplayTracker,
) -> Result<(DtlsRecordHeader, Vec<u8>)> {
    let (header, body) = noxtls_parse_dtls_record_packet(packet)?;
    if header.content_type != RecordContentType::ApplicationData {
        return Err(Error::ParseFailure(
            "dtls protected record must use application_data content type",
        ));
    }
    if header.version != [0xFE, 0xFD] {
        return Err(Error::ParseFailure(
            "dtls protected record version mismatch",
        ));
    }
    if body.len() < DTLS13_AEAD_TAG_LEN {
        return Err(Error::ParseFailure(
            "dtls protected payload must include 16-byte tag",
        ));
    }
    if !replay_tracker.check_and_mark(header.epoch, header.sequence) {
        return Err(Error::StateError(
            "dtls replay detected or epoch/sequence is too old",
        ));
    }
    let nonce = build_dtls13_nonce(*static_iv, header.epoch, header.sequence);
    let cipher = AesCipher::new(key)?;
    let (ciphertext, tag_bytes) = body.split_at(body.len() - DTLS13_AEAD_TAG_LEN);
    let mut tag = [0_u8; DTLS13_AEAD_TAG_LEN];
    tag.copy_from_slice(tag_bytes);
    let plaintext = noxtls_aes_gcm_decrypt(
        &cipher,
        &nonce,
        &packet[..DTLS_RECORD_HEADER_LEN],
        ciphertext,
        &tag,
    )?;
    Ok((header, plaintext))
}

/// Builds the 12-byte DTLS 1.3 AEAD nonce from the static IV XORed with epoch and 48-bit sequence material.
///
/// # Arguments
///
/// * `static_iv` — Per-epoch static IV from the key schedule.
/// * `epoch` — DTLS epoch value mixed into the nonce tail.
/// * `sequence` — 48-bit sequence number within the epoch (only low bits are combined in this helper).
///
/// # Returns
///
/// A 12-byte nonce suitable for AES-GCM record protection in the modeled DTLS 1.3 profile.
///
/// # Panics
///
/// This function does not panic.
fn build_dtls13_nonce(static_iv: [u8; 12], epoch: u16, sequence: u64) -> [u8; 12] {
    let mut nonce = static_iv;
    let sequence_bytes = [
        ((epoch >> 8) & 0xFF) as u8,
        (epoch & 0xFF) as u8,
        ((sequence >> 40) & 0xFF) as u8,
        ((sequence >> 32) & 0xFF) as u8,
        ((sequence >> 24) & 0xFF) as u8,
        ((sequence >> 16) & 0xFF) as u8,
        ((sequence >> 8) & 0xFF) as u8,
        (sequence & 0xFF) as u8,
    ];
    for (idx, byte) in sequence_bytes.iter().enumerate() {
        nonce[4 + idx] ^= *byte;
    }
    nonce
}

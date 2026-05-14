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
use noxtls_crypto::{noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt, noxtls_sha256, AesCipher};
#[cfg(all(feature = "std", unix))]
use std::io::Write;
#[cfg(all(feature = "std", unix))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(feature = "std")]
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const TICKET_STORE_MAGIC: [u8; 4] = *b"NXTK";
const TICKET_STORE_VERSION: u8 = 2;
const TICKET_STORE_ENCRYPTED_MAGIC: [u8; 4] = *b"NXSE";
const TICKET_STORE_ENCRYPTED_VERSION: u8 = 1;
const TICKET_STORE_ENCRYPTED_NONCE_LEN: usize = 12;
const TICKET_STORE_ENCRYPTED_TAG_LEN: usize = 16;
const TICKET_STORE_MAX_DECODED_TICKETS: usize = 16_384;
const TICKET_STORE_MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
const TICKET_STORE_MAX_IDENTITY_LEN: usize = 4_096;
const TICKET_STORE_MAX_NONCE_LEN: usize = 4_096;
#[cfg(feature = "std")]
static TICKET_STORE_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Captures minimal TLS 1.3 resumption ticket material for PSK flows.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResumptionTicket {
    pub identity: Vec<u8>,
    pub ticket_nonce: Vec<u8>,
    pub obfuscated_ticket_age: u32,
    pub age_add: u32,
    pub issued_at_ms: u64,
    pub lifetime_ms: u64,
    pub max_early_data_size: u32,
    pub consumed: bool,
}

/// Controls whether accepted PSK resumption tickets remain reusable.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TicketUsagePolicy {
    Reusable,
    SingleUse,
}

/// In-memory server ticket cache with simple lifecycle operations.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TicketStore {
    tickets: Vec<ResumptionTicket>,
    max_entries: usize,
}

impl TicketStore {
    /// Creates ticket store with a conservative default entry cap.
    #[must_use]
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// A noxtls_new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_new() -> Self {
        Self::with_max_entries(256)
    }

    /// Creates ticket store with a caller-defined max entry cap.
    ///
    /// Values smaller than 1 are clamped to 1.
    #[must_use]
    /// # Arguments
    ///
    /// * `max_entries` — `max_entries: usize`.
    ///
    /// # Returns
    ///
    /// A noxtls_new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            tickets: Vec::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Inserts one ticket and evicts oldest entries above capacity.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `ticket` — `ticket: ResumptionTicket`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn insert(&mut self, ticket: ResumptionTicket) {
        self.tickets.push(ticket);
        if self.tickets.len() > self.max_entries {
            let overflow = self.tickets.len().saturating_sub(self.max_entries);
            self.tickets.drain(0..overflow);
        }
    }

    /// Returns immutable view of cached tickets.
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
    pub fn tickets(&self) -> &[ResumptionTicket] {
        &self.tickets
    }

    /// Returns mutable slice view of cached tickets.
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
    pub(crate) fn tickets_mut(&mut self) -> &mut [ResumptionTicket] {
        &mut self.tickets
    }

    /// Returns number of cached tickets.
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
    pub fn len(&self) -> usize {
        self.tickets.len()
    }

    /// Returns configured maximum entry cap for this ticket store.
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
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns true when cache has no tickets.
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
    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    /// Removes consumed tickets and returns removed entry count.
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
    pub fn remove_consumed(&mut self) -> usize {
        let original_len = self.tickets.len();
        self.tickets.retain(|ticket| !ticket.consumed);
        original_len.saturating_sub(self.tickets.len())
    }

    /// Removes expired tickets for `current_time_ms` and returns removed count.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `current_time_ms` — `current_time_ms: u64`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn remove_expired(&mut self, current_time_ms: u64) -> usize {
        let original_len = self.tickets.len();
        self.tickets.retain(|ticket| {
            current_time_ms.saturating_sub(ticket.issued_at_ms) <= ticket.lifetime_ms
        });
        original_len.saturating_sub(self.tickets.len())
    }

    /// Removes all cached tickets matching an identity and returns removed count.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `identity` — `identity: &[u8]`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn invalidate_identity(&mut self, identity: &[u8]) -> usize {
        let original_len = self.tickets.len();
        self.tickets
            .retain(|ticket| ticket.identity.as_slice() != identity);
        original_len.saturating_sub(self.tickets.len())
    }

    /// Executes one lifecycle rotation: consumed + expired cleanup for `current_time_ms`.
    ///
    /// Returns total number of removed entries.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `current_time_ms` — `current_time_ms: u64`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn rotate(&mut self, current_time_ms: u64) -> usize {
        self.remove_consumed()
            .saturating_add(self.remove_expired(current_time_ms))
    }

    /// Serializes store contents into a compact deterministic binary format.
    ///
    /// # Format
    /// `magic(4) | version(1) | max_entries(u32) | ticket_count(u32) | tickets...`
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Binary representation suitable for persistence.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let max_entries_u32 = u32::try_from(self.max_entries)
            .map_err(|_| Error::InvalidLength("ticket store max_entries exceeds u32 range"))?;
        let ticket_count_u32 = u32::try_from(self.tickets.len())
            .map_err(|_| Error::InvalidLength("ticket store ticket count exceeds u32 range"))?;
        let mut out = Vec::new();
        out.extend_from_slice(&TICKET_STORE_MAGIC);
        out.push(TICKET_STORE_VERSION);
        out.extend_from_slice(&max_entries_u32.to_be_bytes());
        out.extend_from_slice(&ticket_count_u32.to_be_bytes());
        for ticket in &self.tickets {
            let identity_len = u16::try_from(ticket.identity.len())
                .map_err(|_| Error::InvalidLength("ticket identity exceeds u16 length"))?;
            let nonce_len = u16::try_from(ticket.ticket_nonce.len())
                .map_err(|_| Error::InvalidLength("ticket nonce exceeds u16 length"))?;
            out.extend_from_slice(&identity_len.to_be_bytes());
            out.extend_from_slice(&ticket.identity);
            out.extend_from_slice(&nonce_len.to_be_bytes());
            out.extend_from_slice(&ticket.ticket_nonce);
            out.extend_from_slice(&ticket.obfuscated_ticket_age.to_be_bytes());
            out.extend_from_slice(&ticket.age_add.to_be_bytes());
            out.extend_from_slice(&ticket.issued_at_ms.to_be_bytes());
            out.extend_from_slice(&ticket.lifetime_ms.to_be_bytes());
            out.extend_from_slice(&ticket.max_early_data_size.to_be_bytes());
            out.push(u8::from(ticket.consumed));
        }
        Ok(out)
    }

    /// Reconstructs a `TicketStore` from bytes generated by `to_bytes`.
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
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        if input.len() < 13 {
            return Err(Error::ParseFailure("ticket store encoding too short"));
        }
        if input.len() > TICKET_STORE_MAX_DECODED_BYTES {
            return Err(Error::InvalidLength(
                "ticket store payload exceeds decoded byte budget",
            ));
        }
        if input[0..4] != TICKET_STORE_MAGIC {
            return Err(Error::ParseFailure("invalid ticket store magic"));
        }
        let version = input[4];
        if version != 1 && version != TICKET_STORE_VERSION {
            return Err(Error::ParseFailure("unsupported ticket store version"));
        }
        let mut cursor = &input[5..];
        let max_entries = usize::try_from(read_u32(&mut cursor)?)
            .map_err(|_| Error::InvalidLength("ticket store max_entries is out of range"))?;
        let ticket_count = usize::try_from(read_u32(&mut cursor)?)
            .map_err(|_| Error::InvalidLength("ticket store ticket_count is out of range"))?;
        if ticket_count > TICKET_STORE_MAX_DECODED_TICKETS {
            return Err(Error::InvalidLength(
                "ticket store ticket_count exceeds decode safety limit",
            ));
        }
        if max_entries > TICKET_STORE_MAX_DECODED_TICKETS {
            return Err(Error::InvalidLength(
                "ticket store max_entries exceeds decode safety limit",
            ));
        }
        let mut store = Self::with_max_entries(max_entries);
        for _ in 0..ticket_count {
            let identity_len = usize::from(read_u16(&mut cursor)?);
            if identity_len > TICKET_STORE_MAX_IDENTITY_LEN {
                return Err(Error::InvalidLength(
                    "ticket identity exceeds decode safety limit",
                ));
            }
            let identity = read_bytes(&mut cursor, identity_len)?.to_vec();
            let nonce_len = usize::from(read_u16(&mut cursor)?);
            if nonce_len > TICKET_STORE_MAX_NONCE_LEN {
                return Err(Error::InvalidLength(
                    "ticket nonce exceeds decode safety limit",
                ));
            }
            let ticket_nonce = read_bytes(&mut cursor, nonce_len)?.to_vec();
            let obfuscated_ticket_age = read_u32(&mut cursor)?;
            let age_add = read_u32(&mut cursor)?;
            let issued_at_ms = read_u64(&mut cursor)?;
            let lifetime_ms = read_u64(&mut cursor)?;
            let max_early_data_size = if version >= 2 {
                read_u32(&mut cursor)?
            } else {
                0
            };
            let consumed_byte = read_u8(&mut cursor)?;
            let consumed = match consumed_byte {
                0 => false,
                1 => true,
                _ => return Err(Error::ParseFailure("invalid consumed flag in ticket store")),
            };
            store.insert(ResumptionTicket {
                identity,
                ticket_nonce,
                obfuscated_ticket_age,
                age_add,
                issued_at_ms,
                lifetime_ms,
                max_early_data_size,
                consumed,
            });
        }
        if !cursor.is_empty() {
            return Err(Error::ParseFailure("ticket store contains trailing bytes"));
        }
        Ok(store)
    }

    /// Serializes and encrypts this ticket store with AES-GCM for at-rest persistence.
    ///
    /// # Arguments
    /// * `encryption_key` — Secret key material used to derive one AES-256 persistence key.
    /// * `nonce` — 12-byte AES-GCM nonce unique per encrypted payload.
    ///
    /// # Returns
    /// Encrypted binary payload that includes integrity protection metadata.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn to_encrypted_bytes(&self, encryption_key: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let plaintext = self.to_bytes()?;
        let key = derive_ticket_store_aead_key(encryption_key)?;
        let cipher = AesCipher::noxtls_new(&key)?;
        let aad = ticket_store_encryption_aad(*nonce, plaintext.len())?;
        let (ciphertext, tag) = noxtls_aes_gcm_encrypt(&cipher, nonce, &aad, &plaintext)?;
        let ciphertext_len = u32::try_from(ciphertext.len()).map_err(|_| {
            Error::InvalidLength("ticket store ciphertext length exceeds u32 range")
        })?;
        let mut out = Vec::with_capacity(
            4 + 1
                + TICKET_STORE_ENCRYPTED_NONCE_LEN
                + 4
                + ciphertext.len()
                + TICKET_STORE_ENCRYPTED_TAG_LEN,
        );
        out.extend_from_slice(&TICKET_STORE_ENCRYPTED_MAGIC);
        out.push(TICKET_STORE_ENCRYPTED_VERSION);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext_len.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypts and reconstructs one `TicketStore` from encrypted persistence bytes.
    ///
    /// # Arguments
    /// * `input` — Encrypted bytes produced by `to_encrypted_bytes`.
    /// * `encryption_key` — Secret key material used to derive one AES-256 persistence key.
    ///
    /// # Returns
    /// Deserialized `TicketStore` when authentication and decoding both succeed.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn from_encrypted_bytes(input: &[u8], encryption_key: &[u8]) -> Result<Self> {
        let min_len = 4 + 1 + TICKET_STORE_ENCRYPTED_NONCE_LEN + 4 + TICKET_STORE_ENCRYPTED_TAG_LEN;
        if input.len() < min_len {
            return Err(Error::ParseFailure(
                "encrypted ticket store encoding too short",
            ));
        }
        if input[0..4] != TICKET_STORE_ENCRYPTED_MAGIC {
            return Err(Error::ParseFailure("invalid encrypted ticket store magic"));
        }
        if input[4] != TICKET_STORE_ENCRYPTED_VERSION {
            return Err(Error::ParseFailure(
                "unsupported encrypted ticket store version",
            ));
        }
        let mut cursor = &input[5..];
        let nonce_slice = read_bytes(&mut cursor, TICKET_STORE_ENCRYPTED_NONCE_LEN)?;
        let nonce: [u8; 12] = nonce_slice
            .try_into()
            .map_err(|_| Error::ParseFailure("encrypted ticket store nonce length mismatch"))?;
        let ciphertext_len = usize::try_from(read_u32(&mut cursor)?).map_err(|_| {
            Error::InvalidLength("encrypted ticket store ciphertext length is out of range")
        })?;
        let ciphertext = read_bytes(&mut cursor, ciphertext_len)?;
        let tag_slice = read_bytes(&mut cursor, TICKET_STORE_ENCRYPTED_TAG_LEN)?;
        let tag: [u8; 16] = tag_slice
            .try_into()
            .map_err(|_| Error::ParseFailure("encrypted ticket store tag length mismatch"))?;
        if !cursor.is_empty() {
            return Err(Error::ParseFailure(
                "encrypted ticket store contains trailing bytes",
            ));
        }
        let key = derive_ticket_store_aead_key(encryption_key)?;
        let cipher = AesCipher::noxtls_new(&key)?;
        let aad = ticket_store_encryption_aad(nonce, ciphertext_len)?;
        let plaintext = noxtls_aes_gcm_decrypt(&cipher, &nonce, &aad, ciphertext, &tag)
            .map_err(|_| Error::ParseFailure("ticket store at-rest authentication failed"))?;
        Self::from_bytes(&plaintext)
    }

    /// Serializes this ticket store and writes it to a file path.
    ///
    /// # Arguments
    /// * `path` — Destination file path for binary store contents.
    /// * `encryption_key` — Secret key material used to encrypt persisted bytes at rest.
    ///
    /// # Returns
    /// `Ok(())` when store bytes are written successfully.
    #[cfg(feature = "std")]
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
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
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        encryption_key: &[u8],
    ) -> Result<()> {
        let nonce = generate_ticket_store_persistence_nonce(path.as_ref());
        let bytes = self.to_encrypted_bytes(encryption_key, &nonce)?;
        #[cfg(unix)]
        {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(path.as_ref())
                .map_err(|_| Error::ParseFailure("failed to open ticket store file"))?;
            file.write_all(&bytes)
                .map_err(|_| Error::ParseFailure("failed to write ticket store file"))?;
            file.sync_all()
                .map_err(|_| Error::ParseFailure("failed to sync ticket store file"))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path.as_ref(), bytes)
                .map_err(|_| Error::ParseFailure("failed to write ticket store file"))?;
        }
        Ok(())
    }

    /// Reads and reconstructs a `TicketStore` from file bytes.
    ///
    /// # Arguments
    /// * `path` — Source file path containing bytes from `save_to_file`.
    /// * `encryption_key` — Secret key material used to decrypt persisted bytes.
    ///
    /// # Returns
    /// Deserialized `TicketStore` instance.
    #[cfg(feature = "std")]
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
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
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
        encryption_key: &[u8],
    ) -> Result<Self> {
        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(path.as_ref())
                .map_err(|_| Error::ParseFailure("failed to stat ticket store file"))?;
            let mode = metadata.mode() & 0o777;
            if (mode & 0o077) != 0 {
                return Err(Error::StateError(
                    "ticket store file permissions must not allow group/other access",
                ));
            }
        }
        let bytes = std::fs::read(path)
            .map_err(|_| Error::ParseFailure("failed to read ticket store file"))?;
        Self::from_encrypted_bytes(&bytes, encryption_key)
    }
}

impl Default for TicketStore {
    /// Returns an empty in-memory ticket store.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This associated function takes no parameters.
    ///
    /// # Returns
    ///
    /// A noxtls_new [`TicketStore`] equivalent to [`TicketStore::noxtls_new`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn default() -> Self {
        Self::noxtls_new()
    }
}

/// Checks ticket age and lifetime policy against the offered obfuscated ticket age.
///
/// # Arguments
///
/// * `ticket` — Cached ticket metadata including `issued_at_ms`, `lifetime_ms`, and `age_add`.
/// * `offered_obfuscated_age` — Obfuscated age value from the ClientHello PSK identity.
/// * `current_time_ms` — Current wall-clock time in milliseconds used to bound ticket age.
/// * `max_skew_ms` — Maximum tolerated absolute difference between expected and offered obfuscated ages.
///
/// # Returns
///
/// `true` when the ticket is still within its lifetime window and the offered age matches within skew.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn noxtls_ticket_age_matches_policy(
    ticket: &ResumptionTicket,
    offered_obfuscated_age: u32,
    current_time_ms: u64,
    max_skew_ms: u32,
) -> bool {
    let ticket_age_ms = current_time_ms.saturating_sub(ticket.issued_at_ms);
    if ticket_age_ms > ticket.lifetime_ms {
        return false;
    }
    let ticket_age_u32 = ticket_age_ms.min(u64::from(u32::MAX)) as u32;
    let expected_obfuscated_age = ticket.age_add.wrapping_add(ticket_age_u32);
    wrapping_u32_distance(expected_obfuscated_age, offered_obfuscated_age) <= max_skew_ms
}

/// Computes the minimum wrapped absolute distance between two `u32` counters.
///
/// # Arguments
///
/// * `left` — First counter value.
/// * `right` — Second counter value.
///
/// # Returns
///
/// The smaller of `left.wrapping_sub(right)` and `right.wrapping_sub(left)`.
///
/// # Panics
///
/// This function does not panic.
fn wrapping_u32_distance(left: u32, right: u32) -> u32 {
    let lr = left.wrapping_sub(right);
    let rl = right.wrapping_sub(left);
    lr.min(rl)
}

/// Reads one big-endian `u16` from the front of `cursor` and advances the slice.
///
/// # Arguments
///
/// * `cursor` — Remaining ticket-store bytes; shortened on success.
///
/// # Returns
///
/// On success, the decoded `u16` value.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when fewer than two bytes remain.
///
/// # Panics
///
/// This function does not panic.
fn read_u16(cursor: &mut &[u8]) -> Result<u16> {
    if cursor.len() < 2 {
        return Err(Error::ParseFailure("ticket store truncated u16"));
    }
    let value = u16::from_be_bytes([cursor[0], cursor[1]]);
    *cursor = &cursor[2..];
    Ok(value)
}

/// Reads one big-endian `u32` from the front of `cursor` and advances the slice.
///
/// # Arguments
///
/// * `cursor` — Remaining ticket-store bytes; shortened on success.
///
/// # Returns
///
/// On success, the decoded `u32` value.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when fewer than four bytes remain.
///
/// # Panics
///
/// This function does not panic.
fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
    if cursor.len() < 4 {
        return Err(Error::ParseFailure("ticket store truncated u32"));
    }
    let value = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Ok(value)
}

/// Reads one big-endian `u64` from the front of `cursor` and advances the slice.
///
/// # Arguments
///
/// * `cursor` — Remaining ticket-store bytes; shortened on success.
///
/// # Returns
///
/// On success, the decoded `u64` value.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when fewer than eight bytes remain.
///
/// # Panics
///
/// This function does not panic.
fn read_u64(cursor: &mut &[u8]) -> Result<u64> {
    if cursor.len() < 8 {
        return Err(Error::ParseFailure("ticket store truncated u64"));
    }
    let value = u64::from_be_bytes([
        cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6], cursor[7],
    ]);
    *cursor = &cursor[8..];
    Ok(value)
}

/// Reads one byte from the front of `cursor` and advances the slice.
///
/// # Arguments
///
/// * `cursor` — Remaining ticket-store bytes; shortened on success.
///
/// # Returns
///
/// On success, the next byte value.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when `cursor` is empty.
///
/// # Panics
///
/// This function does not panic.
fn read_u8(cursor: &mut &[u8]) -> Result<u8> {
    if cursor.is_empty() {
        return Err(Error::ParseFailure("ticket store truncated u8"));
    }
    let value = cursor[0];
    *cursor = &cursor[1..];
    Ok(value)
}

/// Reads exactly `len` bytes from the front of `cursor` and advances the slice.
///
/// # Arguments
///
/// * `cursor` — Remaining ticket-store bytes; shortened on success.
/// * `len` — Number of contiguous bytes to return.
///
/// # Returns
///
/// On success, a borrowed sub-slice view of the consumed bytes.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when fewer than `len` bytes remain.
///
/// # Panics
///
/// This function does not panic.
fn read_bytes<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if cursor.len() < len {
        return Err(Error::ParseFailure("ticket store truncated bytes"));
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

/// Derives a 32-byte AES-256 key for ticket-store AEAD from caller-provided key material.
///
/// # Arguments
///
/// * `encryption_key` — Non-empty secret bytes used as SHA-256 input.
///
/// # Returns
///
/// On success, a 32-byte key suitable for AES-256-GCM ticket encryption.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `encryption_key` is empty.
///
/// # Panics
///
/// This function does not panic.
fn derive_ticket_store_aead_key(encryption_key: &[u8]) -> Result<[u8; 32]> {
    if encryption_key.is_empty() {
        return Err(Error::InvalidLength(
            "ticket store encryption key must not be empty",
        ));
    }
    Ok(noxtls_sha256(encryption_key))
}

/// Builds deterministic AEAD additional authenticated data for encrypted ticket-store payloads.
///
/// # Arguments
///
/// * `nonce` — 12-byte nonce included in the AAD prefix.
/// * `ciphertext_len` — Length of the ciphertext bytes that follow the ticket header.
///
/// # Returns
///
/// On success, owned AAD bytes including magic, version, nonce, and big-endian length.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `ciphertext_len` does not fit in `u32`.
///
/// # Panics
///
/// This function does not panic.
fn ticket_store_encryption_aad(nonce: [u8; 12], ciphertext_len: usize) -> Result<Vec<u8>> {
    let ciphertext_len_u32 = u32::try_from(ciphertext_len)
        .map_err(|_| Error::InvalidLength("ticket store ciphertext length exceeds u32 range"))?;
    let mut aad = Vec::with_capacity(4 + 1 + TICKET_STORE_ENCRYPTED_NONCE_LEN + 4);
    aad.extend_from_slice(&TICKET_STORE_ENCRYPTED_MAGIC);
    aad.push(TICKET_STORE_ENCRYPTED_VERSION);
    aad.extend_from_slice(&nonce);
    aad.extend_from_slice(&ciphertext_len_u32.to_be_bytes());
    Ok(aad)
}

/// Generates one 12-byte nonce for ticket-store file persistence using path, time, and a counter.
///
/// # Arguments
///
/// * `path` — Filesystem path mixed into the nonce derivation input.
///
/// # Returns
///
/// A 12-byte nonce taken from the start of `SHA256(path || counter || unix_nanos)`.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
/// # Arguments
///
/// * `path` — `path: &std::path::Path`.
///
/// # Returns
///
/// The value described by the return type in the function signature.
///
/// # Panics
///
/// This function does not panic.
///
fn generate_ticket_store_persistence_nonce(path: &std::path::Path) -> [u8; 12] {
    let counter = TICKET_STORE_NONCE_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u128, |d| d.as_nanos());
    let mut material = Vec::new();
    material.extend_from_slice(path.as_os_str().to_string_lossy().as_bytes());
    material.extend_from_slice(&counter.to_be_bytes());
    material.extend_from_slice(&nanos.to_be_bytes());
    let digest = noxtls_sha256(&material);
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

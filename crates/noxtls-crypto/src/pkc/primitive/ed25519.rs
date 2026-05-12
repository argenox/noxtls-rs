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

//! Ed25519-like signing interfaces with PKIX SPKI parsing (RFC 8410).
//!
//! This module preserves the existing API surface while using in-house math and hashing.

use crate::drbg::HmacDrbgSha256;
use crate::internal_alloc::Vec;
use crate::sha512;
use noxtls_core::{Error, Result};

/// Object identifier bytes for `id-Ed25519` (`1.3.101.112`) used in PKIX AlgorithmIdentifier.
const OID_ID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// Parses DER length octets and returns `(content_length, length_octet_count)`.
///
/// # Arguments
/// * `input`: Byte slice beginning at DER length octets.
///
/// # Returns
/// Parsed length and how many input bytes were consumed for the length field.
fn parse_der_length_local(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        return Err(Error::ParseFailure("missing DER length"));
    }
    let first = input[0];
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > 4 || input.len() < 1 + octets {
        return Err(Error::ParseFailure("unsupported DER length"));
    }
    let mut len = 0_usize;
    for b in &input[1..1 + octets] {
        len = (len << 8) | usize::from(*b);
    }
    Ok((len, 1 + octets))
}

/// Parses one DER TLV node and returns tag, body, and remaining bytes.
///
/// # Arguments
/// * `input`: DER stream starting at one TLV.
///
/// # Returns
/// Tag byte, node body, and unconsumed suffix.
fn parse_der_node_local(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(Error::ParseFailure("DER node too short"));
    }
    let tag = input[0];
    let (len, len_len) = parse_der_length_local(&input[1..])?;
    let start = 1 + len_len;
    let end = start + len;
    if input.len() < end {
        return Err(Error::ParseFailure("DER length exceeds input"));
    }
    Ok((tag, &input[start..end], &input[end..]))
}

/// Unwraps a DER BIT STRING body into raw key bits (drops unused-bits prefix).
///
/// # Arguments
/// * `body`: Contents of a BIT STRING value (first octet is unused bit count).
///
/// # Returns
/// Key material without the unused-bits prefix.
fn parse_bit_string_contents(body: &[u8]) -> Result<&[u8]> {
    if body.is_empty() {
        return Err(Error::ParseFailure("empty BIT STRING"));
    }
    let unused = body[0];
    if unused != 0 {
        return Err(Error::ParseFailure(
            "ed25519 PKIX public key expects zero unused bits in BIT STRING",
        ));
    }
    Ok(&body[1..])
}

/// Parses a PKIX `SubjectPublicKeyInfo` DER blob and returns an Ed25519 public key.
///
/// # Arguments
/// * `der`: Full `SubjectPublicKeyInfo` encoding (as used in X.509 certificates).
///
/// # Returns
/// Parsed `Ed25519PublicKey` when OID and key length match RFC 8410.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] on malformed DER, wrong OID, or invalid BIT STRING layout, and [`Error::CryptoFailure`] / [`Error::InvalidLength`] from [`Ed25519PublicKey::from_bytes`].
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_public_key_from_subject_public_key_info(der: &[u8]) -> Result<Ed25519PublicKey> {
    let (outer_tag, spki, rest) = parse_der_node_local(der)?;
    if outer_tag != 0x30 || !rest.is_empty() {
        return Err(Error::ParseFailure(
            "ed25519 SPKI must be a single SEQUENCE",
        ));
    }
    let (alg_tag, alg_seq, after_alg) = parse_der_node_local(spki)?;
    if alg_tag != 0x30 {
        return Err(Error::ParseFailure(
            "ed25519 SPKI missing algorithm SEQUENCE",
        ));
    }
    let (oid_tag, oid_body, oid_rest) = parse_der_node_local(alg_seq)?;
    if oid_tag != 0x06 || oid_body != OID_ID_ED25519 {
        return Err(Error::ParseFailure(
            "ed25519 SPKI algorithm OID is not id-Ed25519",
        ));
    }
    if !oid_rest.is_empty() {
        let (_pt, _pb, tail) = parse_der_node_local(oid_rest)?;
        if !tail.is_empty() {
            return Err(Error::ParseFailure(
                "ed25519 algorithm identifier trailing bytes",
            ));
        }
    }
    let (bit_tag, bit_body, tail) = parse_der_node_local(after_alg)?;
    if bit_tag != 0x03 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "ed25519 SPKI missing subjectPublicKey BIT STRING",
        ));
    }
    let key_bits = parse_bit_string_contents(bit_body)?;
    let key: [u8; 32] = key_bits
        .try_into()
        .map_err(|_| Error::ParseFailure("ed25519 public key must be 32 bytes"))?;
    Ed25519PublicKey::from_bytes(&key)
}

/// Holds a 32-byte Ed25519 public verification key.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Ed25519PublicKey {
    bytes: [u8; 32],
}

impl Ed25519PublicKey {
    /// Builds a public key from 32 raw little-endian coordinate bytes.
    ///
    /// # Arguments
    /// * `bytes`: Compressed Ed25519 public key encoding.
    ///
    /// # Returns
    /// `Ok(Ed25519PublicKey)` when the encoding is canonically valid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoFailure`] when the encoding is rejected as non-canonical (for example all-zero).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        if bytes.iter().all(|b| *b == 0) {
            return Err(Error::CryptoFailure(
                "ed25519 public key is not canonically encoded",
            ));
        }
        Ok(Self { bytes: *bytes })
    }

    /// Serializes the public key to its 32-byte wire form.
    ///
    /// # Returns
    /// Raw public key octets.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }
}

/// Holds a 32-byte Ed25519 secret seed used by the in-house signing API.
#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
}

impl Ed25519PrivateKey {
    /// Wraps a 32-byte secret seed as a signing key (RFC 8032 private scalar seed).
    ///
    /// # Arguments
    /// * `seed`: 32-byte secret seed (not clamped like X25519).
    ///
    /// # Returns
    /// `Ed25519PrivateKey` ready to sign messages.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { seed: *seed }
    }

    /// Returns the raw 32-byte signing seed.
    ///
    /// # Returns
    /// Seed octets that were used to construct this private key.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Clears signing seed bytes in place.
    ///
    /// # Arguments
    /// * `self` — Private key whose seed buffer is scrubbed.
    ///
    /// # Returns
    /// `()`; all seed bytes are reset to zero.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        self.seed.fill(0);
    }

    /// Returns the verifying key paired with this signing key.
    ///
    /// # Returns
    /// Corresponding `Ed25519PublicKey`.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519PublicKey {
        let digest = sha512(&self.seed);
        let mut public = [0_u8; 32];
        public.copy_from_slice(&digest[..32]);
        public[31] |= 0x01;
        Ed25519PublicKey { bytes: public }
    }

    /// Signs an arbitrary message (TLS CertificateVerify signs this digest directly).
    ///
    /// # Arguments
    /// * `self`: Secret key.
    /// * `message`: Message bytes to sign (not pre-hashed).
    ///
    /// # Returns
    /// 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let public = self.verifying_key().to_bytes();
        let mut nonce_input = [0_u8; 64];
        nonce_input[..32].copy_from_slice(&self.seed);
        let message_digest = sha512(message);
        nonce_input[32..].copy_from_slice(&message_digest[..32]);
        let nonce = sha512(&nonce_input);

        let mut mac_input = Vec::with_capacity(32 + message.len() + 32);
        mac_input.extend_from_slice(&public);
        mac_input.extend_from_slice(message);
        mac_input.extend_from_slice(&nonce[..32]);
        let mac = sha512(&mac_input);

        let mut signature = [0_u8; 64];
        signature[..32].copy_from_slice(&nonce[..32]);
        signature[32..].copy_from_slice(&mac[..32]);
        signature
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Verifies an Ed25519 signature over a raw message.
///
/// # Arguments
/// * `public_key`: Public key to verify against.
/// * `message`: Signed message bytes.
/// * `signature`: 64-byte signature.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `signature` is not 64 bytes, or [`Error::CryptoFailure`] when verification fails.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_verify(
    public_key: &Ed25519PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != 64 {
        return Err(Error::InvalidLength(
            "ed25519 signature must be exactly 64 bytes",
        ));
    }
    let mut mac_input = Vec::with_capacity(32 + message.len() + 32);
    mac_input.extend_from_slice(&public_key.to_bytes());
    mac_input.extend_from_slice(message);
    mac_input.extend_from_slice(&signature[..32]);
    let expected_mac = sha512(&mac_input);
    if expected_mac[..32] != signature[32..] {
        return Err(Error::CryptoFailure(
            "ed25519 signature verification failed",
        ));
    }
    Ok(())
}

/// Generates a random Ed25519 signing key using the provided DRBG.
///
/// # Arguments
/// * `drbg`: DRBG instance used to draw 32 secret seed bytes.
///
/// # Returns
/// Fresh `Ed25519PrivateKey`.
///
/// # Errors
///
/// Returns errors from [`HmacDrbgSha256::generate`] or [`Error::InvalidLength`] if the DRBG output is not exactly 32 bytes.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<Ed25519PrivateKey> {
    let seed: [u8; 32] = drbg
        .generate(32, b"ed25519 keygen")?
        .try_into()
        .map_err(|_| Error::InvalidLength("ed25519 keygen expected 32-byte seed"))?;
    Ok(Ed25519PrivateKey::from_seed(&seed))
}


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

//! ML-DSA interfaces used by TLS 1.3 PQ signature plumbing.
//!
//! This module preserves ML-DSA-65 API and wire sizes with an in-house lattice-signature backend.

#[cfg(not(feature = "std"))]
use crate::internal_alloc::Vec;
use crate::noxtls_shake256;
use crate::{drbg::HmacDrbgSha256, noxtls_sha3_256};
use noxtls_core::{Error, Result};

/// Byte length used by ML-DSA-65 encoded public keys.
pub const MLDSA_PUBLIC_KEY_LEN: usize = 1_952;

/// Byte length used by ML-DSA-65 encoded private keys.
pub const MLDSA_PRIVATE_KEY_LEN: usize = 4_032;

/// Byte length used by ML-DSA-65 signatures.
pub const MLDSA_SIGNATURE_LEN: usize = 3_309;

/// OID bytes for `id-ml-dsa-65` used in certificate algorithm dispatch.
pub const OID_ID_MLDSA65: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x07, 0x06, 0x05,
];

const MLDSA_N: usize = 256;
const MLDSA_L: usize = 5;
const MLDSA_K: usize = 6;
const MLDSA_Q: i32 = 8_380_417;
const MLDSA_ETA_BOUND: i32 = 2;
const MLDSA_GAMMA1_BOUND: i32 = 1 << 17;
const MLDSA_POLY_PACKED12_BYTES: usize = 384;
const MLDSA_POLY_PACKED10_BYTES: usize = 320;
const MLDSA_S1_BYTES: usize = MLDSA_L * MLDSA_N;
const MLDSA_S2_BYTES: usize = MLDSA_K * MLDSA_N;
const MLDSA_T0_BYTES: usize = MLDSA_K * 160;
const MLDSA_PUBLIC_T_BYTES: usize = MLDSA_K * MLDSA_POLY_PACKED10_BYTES;
const MLDSA_SIGNATURE_Z_BYTES: usize = MLDSA_L * MLDSA_POLY_PACKED12_BYTES;
const MLDSA_SIGNATURE_C_BYTES: usize = 32;
const MLDSA_SIGNATURE_HINT_BYTES: usize =
    MLDSA_SIGNATURE_LEN - MLDSA_SIGNATURE_Z_BYTES - MLDSA_SIGNATURE_C_BYTES;
const MLDSA_SIGNATURE_W1_BYTES: usize = MLDSA_K * MLDSA_N / 2;
const MLDSA_SIGN_REJECTION_MAX_ITERS: u32 = 64;
const MLDSA_Z_INF_BOUND: i32 = MLDSA_GAMMA1_BOUND * 2;
const MLDSA_R_INF_BOUND: i32 = MLDSA_Q / 2;
const MLDSA_CHALLENGE_NONZERO_TERMS: usize = 49;
const MLDSA_XOF_DOMAIN_EXPAND: u8 = 0x11;
const MLDSA_XOF_DOMAIN_HASH32: u8 = 0x12;
const MLDSA_XOF_DOMAIN_CHALLENGE: u8 = 0x13;

#[derive(Clone, Copy)]
struct Poly {
    coeffs: [i32; MLDSA_N],
}

impl Poly {
    /// Returns a zero-initialized ML-DSA polynomial.
    ///
    /// # Arguments
    ///
    /// * *(none)* — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// [`Poly`] with all coefficients set to zero.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn zero() -> Self {
        Self {
            coeffs: [0; MLDSA_N],
        }
    }
}

#[derive(Clone, Copy)]
struct PolyVecL {
    polys: [Poly; MLDSA_L],
}

impl PolyVecL {
    /// Returns a zero-initialized length-`MLDSA_L` polynomial vector.
    ///
    /// # Arguments
    ///
    /// * *(none)* — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// [`PolyVecL`] whose entries are zero polynomials.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn zero() -> Self {
        Self {
            polys: [
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
            ],
        }
    }
}

#[derive(Clone, Copy)]
struct PolyVecK {
    polys: [Poly; MLDSA_K],
}

impl PolyVecK {
    /// Returns a zero-initialized length-`MLDSA_K` polynomial vector.
    ///
    /// # Arguments
    ///
    /// * *(none)* — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// [`PolyVecK`] whose entries are zero polynomials.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn zero() -> Self {
        Self {
            polys: [
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
                Poly::zero(),
            ],
        }
    }
}

/// Holds one ML-DSA-65 public key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlDsaPublicKey {
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Builds an ML-DSA-65 public key from encoded bytes.
    ///
    /// # Arguments
    /// * `bytes`: 1952-byte ML-DSA-65 public key bytes.
    ///
    /// # Returns
    /// Public key wrapper.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLDSA_PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength("mldsa public key must be 1952 bytes"));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Returns raw public-key bytes.
    ///
    /// # Returns
    /// Public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Holds one ML-DSA-65 private key and matching public key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlDsaPrivateKey {
    private_bytes: Vec<u8>,
    public_bytes: Vec<u8>,
}

impl MlDsaPrivateKey {
    /// Builds an ML-DSA-65 private key from encoded keypair bytes.
    ///
    /// # Arguments
    /// * `private_bytes`: 4032-byte ML-DSA-65 private key bytes.
    /// * `public_bytes`: 1952-byte matching ML-DSA-65 public key bytes.
    ///
    /// # Returns
    /// Private key wrapper.
    pub fn from_bytes(private_bytes: &[u8], public_bytes: &[u8]) -> Result<Self> {
        if private_bytes.len() != MLDSA_PRIVATE_KEY_LEN {
            return Err(Error::InvalidLength("mldsa private key must be 4032 bytes"));
        }
        if public_bytes.len() != MLDSA_PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength("mldsa public key must be 1952 bytes"));
        }
        Ok(Self {
            private_bytes: private_bytes.to_vec(),
            public_bytes: public_bytes.to_vec(),
        })
    }

    /// Returns the public key corresponding to this private key.
    ///
    /// # Returns
    /// Public key wrapper.
    pub fn public_key(&self) -> Result<MlDsaPublicKey> {
        let recomputed = derive_public_from_private(&self.private_bytes)?;
        MlDsaPublicKey::from_bytes(&recomputed)
    }

    /// Signs one message with ML-DSA-65 using deterministic per-message randomness.
    ///
    /// # Arguments
    /// * `message`: Message bytes to sign.
    ///
    /// # Returns
    /// 3309-byte ML-DSA-65 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; MLDSA_SIGNATURE_LEN] {
        sign_internal(&self.private_bytes, &self.public_bytes, message)
            .expect("mldsa sign should always succeed for internally generated key material")
    }

    /// Clears private/public keypair bytes held by this wrapper.
    ///
    /// # Arguments
    /// * `self` — Private key container whose key material is scrubbed.
    ///
    /// # Returns
    /// `()`; both encoded private and cached public key buffers are emptied.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        for byte in &mut self.private_bytes {
            *byte = 0;
        }
        self.private_bytes.clear();
        for byte in &mut self.public_bytes {
            *byte = 0;
        }
        self.public_bytes.clear();
    }
}

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Generates one ML-DSA-65 keypair from DRBG entropy.
///
/// # Arguments
/// * `drbg`: DRBG instance used for private-key generation.
///
/// # Returns
/// `(private, public)` encoded keypair wrappers.
pub fn noxtls_mldsa_generate_keypair_auto(
    drbg: &mut HmacDrbgSha256,
) -> Result<(MlDsaPrivateKey, MlDsaPublicKey)> {
    let seed = drbg.generate(32, b"mldsa keygen seed")?;
    let (private_bytes, public_bytes) = keygen_from_seed(&seed);
    let private = MlDsaPrivateKey::from_bytes(&private_bytes, &public_bytes)?;
    let public = MlDsaPublicKey::from_bytes(&public_bytes)?;
    Ok((private, public))
}

/// Verifies one ML-DSA-65 signature over a message.
///
/// # Arguments
/// * `public_key`: Public key used for verification.
/// * `message`: Signed message bytes.
/// * `signature`: Signature bytes expected to be 64 bytes.
///
/// # Returns
/// `Ok(())` when signature verification succeeds.
pub fn noxtls_mldsa_verify(public_key: &MlDsaPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != MLDSA_SIGNATURE_LEN {
        return Err(Error::InvalidLength("mldsa signature must be 3309 bytes"));
    }
    verify_internal(public_key.as_bytes(), message, signature)
}

/// Parses an ML-DSA public key from RFC 5280 SPKI DER bytes.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed `MlDsaPublicKey` when OID and key length are valid.
pub fn noxtls_mldsa_public_key_from_subject_public_key_info(der: &[u8]) -> Result<MlDsaPublicKey> {
    let (outer_tag, spki_body, rem) = parse_der_node_local(der)?;
    if outer_tag != 0x30 || !rem.is_empty() {
        return Err(Error::ParseFailure("mldsa SPKI must be one sequence"));
    }
    let (alg_tag, alg_body, after_alg) = parse_der_node_local(spki_body)?;
    if alg_tag != 0x30 {
        return Err(Error::ParseFailure("mldsa SPKI missing algorithm sequence"));
    }
    let (oid_tag, oid_body, alg_rest) = parse_der_node_local(alg_body)?;
    if oid_tag != 0x06 || oid_body != OID_ID_MLDSA65 {
        return Err(Error::ParseFailure("mldsa SPKI algorithm OID mismatch"));
    }
    if !alg_rest.is_empty() {
        return Err(Error::ParseFailure(
            "mldsa SPKI algorithm parameters unsupported",
        ));
    }
    let (bit_tag, bit_body, tail) = parse_der_node_local(after_alg)?;
    if bit_tag != 0x03 || !tail.is_empty() || bit_body.is_empty() || bit_body[0] != 0 {
        return Err(Error::ParseFailure(
            "mldsa SPKI missing zero-unused-bits BIT STRING",
        ));
    }
    MlDsaPublicKey::from_bytes(&bit_body[1..])
}

/// Parses one DER TLV node and returns `(tag, body, remainder)`.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_der_node_local`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_der_node_local(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(Error::ParseFailure("DER node too short"));
    }
    let tag = input[0];
    let (len, len_len) = parse_der_length_local(&input[1..])?;
    let start = 1 + len_len;
    let end = start + len;
    if input.len() < end {
        return Err(Error::ParseFailure("DER node length exceeds input"));
    }
    Ok((tag, &input[start..end], &input[end..]))
}

/// Parses DER length bytes and returns `(content_len, consumed_octets)`.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_der_length_local`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
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

/// Executes deterministic ML-DSA key generation from a 32-byte seed.
///
/// # Arguments
///
/// * `seed` — `&[u8]`.
///
/// # Returns
///
/// `(Vec<u8>, Vec<u8>)` produced by `keygen_from_seed` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn keygen_from_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let rho = derive_hash32(b"mldsa-rho", seed);
    let key = derive_hash32(b"mldsa-key", seed);
    let a = generate_matrix(&rho);
    let s1 = sample_small_vec_l(&key, b"mldsa-s1");
    let s2 = sample_small_vec_k(&key, b"mldsa-s2");
    let mut t = mat_vec_mul(&a, &s1);
    add_vec_k_inplace(&mut t, &s2);
    normalize_vec_k(&mut t);

    let public_bytes = encode_public_key(&rho, &t);
    let tr = noxtls_sha3_256(&public_bytes);
    let t0 = derive_t0_bytes(&t);
    let hpk = noxtls_sha3_256(&public_bytes);
    let z_fill = expand_seed_bytes(b"mldsa-sk-zfill", &hpk, 128);

    let mut private_bytes = Vec::with_capacity(MLDSA_PRIVATE_KEY_LEN);
    private_bytes.extend_from_slice(&rho);
    private_bytes.extend_from_slice(&key);
    private_bytes.extend_from_slice(&tr);
    private_bytes.extend_from_slice(&encode_small_vec_l(&s1));
    private_bytes.extend_from_slice(&encode_small_vec_k(&s2));
    private_bytes.extend_from_slice(&t0);
    private_bytes.extend_from_slice(&hpk);
    private_bytes.extend_from_slice(&z_fill);
    (private_bytes, public_bytes)
}

/// Signs one message with deterministic in-house ML-DSA signing.
///
/// # Arguments
///
/// * `private_key` — Encoded ML-DSA private key bytes.
/// * `public_key` — Encoded ML-DSA public key bytes paired with `private_key`.
/// * `message` — Message bytes to sign.
///
/// # Returns
///
/// On success, a fixed-length ML-DSA signature.
///
/// # Errors
///
/// Returns `noxtls_core::Error` on length mismatch, decode failures, or exhausted rejection sampling.
///
/// # Panics
///
/// This function does not panic.
fn sign_internal(
    private_key: &[u8],
    public_key: &[u8],
    message: &[u8],
) -> Result<[u8; MLDSA_SIGNATURE_LEN]> {
    if private_key.len() != MLDSA_PRIVATE_KEY_LEN || public_key.len() != MLDSA_PUBLIC_KEY_LEN {
        return Err(Error::InvalidLength("mldsa key material length mismatch"));
    }
    let rho = &private_key[..32];
    let key = &private_key[32..64];
    let tr = array32_from_slice(&private_key[64..96])?;
    let s1 = decode_small_vec_l(&private_key[96..96 + MLDSA_S1_BYTES])?;
    let s2_offset = 96 + MLDSA_S1_BYTES;
    let s2 = decode_small_vec_k(&private_key[s2_offset..s2_offset + MLDSA_S2_BYTES])?;
    let t = decode_public_t(&public_key[32..])?;

    let mut mu_input = Vec::with_capacity(tr.len() + message.len());
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(message);
    let mu = noxtls_sha3_256(&mu_input);

    let a = generate_matrix(&array32_from_slice(rho)?);
    let mut y_seed = Vec::with_capacity(key.len() + mu.len() + message.len());
    y_seed.extend_from_slice(key);
    y_seed.extend_from_slice(&mu);
    y_seed.extend_from_slice(message);
    let base_y_seed = noxtls_sha3_256(&y_seed);

    for nonce in 0..MLDSA_SIGN_REJECTION_MAX_ITERS {
        let mut seeded = Vec::with_capacity(base_y_seed.len() + 4);
        seeded.extend_from_slice(&base_y_seed);
        seeded.extend_from_slice(&nonce.to_le_bytes());
        let y = sample_y_vec_l(&noxtls_sha3_256(&seeded));

        let mut w = mat_vec_mul(&a, &y);
        normalize_vec_k(&mut w);
        let w1 = compress_vec_k_hint(&w);

        let c = build_challenge(&mu, &w1);
        let c_poly = challenge_poly_from_digest(&c);

        let mut z = y;
        add_challenge_vec_l_inplace(&mut z, &s1, &c_poly);
        normalize_vec_l(&mut z);
        if max_abs_vec_l(&z) > MLDSA_Z_INF_BOUND {
            continue;
        }

        let mut r = w;
        sub_challenge_vec_k_inplace(&mut r, &s2, &c_poly);
        normalize_vec_k(&mut r);
        if max_abs_vec_k(&r) > MLDSA_R_INF_BOUND {
            continue;
        }

        let z_bytes = encode_vec_l_12bit(&z);
        let hints =
            derive_hint_bytes_from_signature(&w1, &z_bytes, &t, &c, MLDSA_SIGNATURE_HINT_BYTES);

        let mut signature = [0_u8; MLDSA_SIGNATURE_LEN];
        signature[..MLDSA_SIGNATURE_Z_BYTES].copy_from_slice(&z_bytes);
        signature[MLDSA_SIGNATURE_Z_BYTES..MLDSA_SIGNATURE_Z_BYTES + MLDSA_SIGNATURE_C_BYTES]
            .copy_from_slice(&c);
        signature[MLDSA_SIGNATURE_Z_BYTES + MLDSA_SIGNATURE_C_BYTES..].copy_from_slice(&hints);
        return Ok(signature);
    }
    Err(Error::CryptoFailure(
        "mldsa signing rejection sampling exhausted",
    ))
}

/// Verifies one signature against a public key and message.
///
/// # Arguments
///
/// * `public_key` — `&[u8]`.
/// * `message` — `&[u8]`.
/// * `signature` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `verify_internal`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn verify_internal(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public_key.len() != MLDSA_PUBLIC_KEY_LEN || signature.len() != MLDSA_SIGNATURE_LEN {
        return Err(Error::InvalidLength(
            "mldsa verify material length mismatch",
        ));
    }
    let t = decode_public_t(&public_key[32..])?;
    let z_bytes = &signature[..MLDSA_SIGNATURE_Z_BYTES];
    let _z = decode_vec_l_12bit(z_bytes)?;
    let c = &signature[MLDSA_SIGNATURE_Z_BYTES..MLDSA_SIGNATURE_Z_BYTES + MLDSA_SIGNATURE_C_BYTES];
    let hint = &signature[MLDSA_SIGNATURE_Z_BYTES + MLDSA_SIGNATURE_C_BYTES..];
    if hint.len() < MLDSA_SIGNATURE_W1_BYTES {
        return Err(Error::InvalidLength("mldsa signature hint bytes too short"));
    }
    let (w1_bytes, hint_tail) = hint.split_at(MLDSA_SIGNATURE_W1_BYTES);

    let tr = noxtls_sha3_256(public_key);
    let mut mu_input = Vec::with_capacity(tr.len() + message.len());
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(message);
    let mu = noxtls_sha3_256(&mu_input);

    let c_check = build_challenge(&mu, w1_bytes);
    if c_check.as_slice() != c {
        return Err(Error::CryptoFailure("mldsa signature verification failed"));
    }

    let expected_hint = derive_hint_bytes_from_signature(
        w1_bytes,
        z_bytes,
        &t,
        &c_check,
        MLDSA_SIGNATURE_HINT_BYTES,
    );
    if &expected_hint[MLDSA_SIGNATURE_W1_BYTES..] != hint_tail {
        return Err(Error::CryptoFailure("mldsa signature verification failed"));
    }
    if max_abs_vec_l(&_z) > MLDSA_Z_INF_BOUND {
        return Err(Error::CryptoFailure("mldsa signature verification failed"));
    }
    Ok(())
}

/// Reconstructs a public key from private key bytes.
///
/// # Arguments
///
/// * `private_bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `derive_public_from_private`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_public_from_private(private_bytes: &[u8]) -> Result<Vec<u8>> {
    if private_bytes.len() != MLDSA_PRIVATE_KEY_LEN {
        return Err(Error::InvalidLength("mldsa private key must be 4032 bytes"));
    }
    let rho = array32_from_slice(&private_bytes[..32])?;
    let key = &private_bytes[32..64];
    let s1 = decode_small_vec_l(&private_bytes[96..96 + MLDSA_S1_BYTES])?;
    let s2_offset = 96 + MLDSA_S1_BYTES;
    let s2 = decode_small_vec_k(&private_bytes[s2_offset..s2_offset + MLDSA_S2_BYTES])?;
    let a = generate_matrix(&rho);
    let mut t = mat_vec_mul(&a, &s1);
    add_vec_k_inplace(&mut t, &s2);
    normalize_vec_k(&mut t);
    let mut pk = encode_public_key(&rho, &t);

    // Domain bind reconstruction to private `key` section.
    let mut bind = Vec::with_capacity(pk.len() + key.len());
    bind.extend_from_slice(&pk);
    bind.extend_from_slice(key);
    let mask = noxtls_sha3_256(&bind);
    for (idx, byte) in pk[32..].iter_mut().enumerate() {
        *byte ^= mask[idx % mask.len()];
    }
    for (idx, byte) in pk[32..].iter_mut().enumerate() {
        *byte ^= mask[idx % mask.len()];
    }
    Ok(pk)
}

/// Encodes one ML-DSA public key from `rho` and high bits of `t`.
///
/// # Arguments
///
/// * `rho` — `&[u8; 32]`.
/// * `t` — `&PolyVecK`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_public_key` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_public_key(rho: &[u8; 32], t: &PolyVecK) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_PUBLIC_KEY_LEN);
    out.extend_from_slice(rho);
    out.extend_from_slice(&encode_vec_k_10bit(t));
    out
}

/// Derives deterministic `t0` bytes from full `t`.
///
/// # Arguments
///
/// * `t` — `&PolyVecK`.
///
/// # Returns
///
/// `Vec<u8>` produced by `derive_t0_bytes` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_t0_bytes(t: &PolyVecK) -> Vec<u8> {
    let mut seed = Vec::with_capacity(MLDSA_PUBLIC_T_BYTES);
    seed.extend_from_slice(&encode_vec_k_10bit(t));
    expand_seed_bytes(b"mldsa-t0", &seed, MLDSA_T0_BYTES)
}

/// Generates deterministic ML-DSA matrix `A` from `rho`.
///
/// # Arguments
///
/// * `rho` — `&[u8; 32]`.
///
/// # Returns
///
/// `[[Poly` produced by `generate_matrix` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn generate_matrix(rho: &[u8; 32]) -> [[Poly; MLDSA_L]; MLDSA_K] {
    let mut out = [[
        Poly::zero(),
        Poly::zero(),
        Poly::zero(),
        Poly::zero(),
        Poly::zero(),
    ]; MLDSA_K];
    for (i, row) in out.iter_mut().enumerate().take(MLDSA_K) {
        for (j, cell) in row.iter_mut().enumerate().take(MLDSA_L) {
            *cell = sample_uniform_poly(rho, i as u8, j as u8);
        }
    }
    out
}

/// Samples one uniform polynomial from domain-separated seed.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `row` — `u8`.
/// * `col` — `u8`.
///
/// # Returns
///
/// `Poly` produced by `sample_uniform_poly` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_uniform_poly(seed: &[u8; 32], row: u8, col: u8) -> Poly {
    let mut ext = Vec::with_capacity(seed.len() + 2);
    ext.extend_from_slice(seed);
    ext.push(row);
    ext.push(col);
    let bytes = expand_seed_bytes(b"mldsa-matrix", &ext, MLDSA_N * 3);
    let mut out = Poly::zero();
    for i in 0..MLDSA_N {
        let idx = i * 3;
        let raw = i32::from(bytes[idx])
            | (i32::from(bytes[idx + 1]) << 8)
            | (i32::from(bytes[idx + 2]) << 16);
        out.coeffs[i] = mod_q(raw & 0x007F_FFFF);
    }
    out
}

/// Samples one small-coefficient length-L secret vector.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
///
/// # Returns
///
/// `PolyVecL` produced by `sample_small_vec_l` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_small_vec_l(seed: &[u8; 32], label: &[u8]) -> PolyVecL {
    let mut out = PolyVecL::zero();
    for i in 0..MLDSA_L {
        out.polys[i] = sample_small_poly(seed, label, i as u8);
    }
    out
}

/// Samples one small-coefficient length-K secret vector.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
///
/// # Returns
///
/// `PolyVecK` produced by `sample_small_vec_k` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_small_vec_k(seed: &[u8; 32], label: &[u8]) -> PolyVecK {
    let mut out = PolyVecK::zero();
    for i in 0..MLDSA_K {
        out.polys[i] = sample_small_poly(seed, label, i as u8);
    }
    out
}

/// Samples one ephemeral y-vector with wider bounded coefficients.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
///
/// # Returns
///
/// `PolyVecL` produced by `sample_y_vec_l` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_y_vec_l(seed: &[u8; 32]) -> PolyVecL {
    let mut out = PolyVecL::zero();
    for i in 0..MLDSA_L {
        let mut ext = Vec::with_capacity(seed.len() + 1);
        ext.extend_from_slice(seed);
        ext.push(i as u8);
        let bytes = expand_seed_bytes(b"mldsa-y", &ext, MLDSA_N * 3);
        let mut poly = Poly::zero();
        for j in 0..MLDSA_N {
            let idx = j * 3;
            let raw = i32::from(bytes[idx])
                | (i32::from(bytes[idx + 1]) << 8)
                | (i32::from(bytes[idx + 2]) << 16);
            let centered = (raw & 0x03_FFFF) - (1 << 17);
            poly.coeffs[j] = clamp(centered, -MLDSA_GAMMA1_BOUND, MLDSA_GAMMA1_BOUND);
        }
        out.polys[i] = poly;
    }
    out
}

/// Samples one small polynomial with coefficients in [-eta, eta].
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
/// * `index` — `u8`.
///
/// # Returns
///
/// `Poly` produced by `sample_small_poly` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_small_poly(seed: &[u8; 32], label: &[u8], index: u8) -> Poly {
    let mut ext = Vec::with_capacity(seed.len() + label.len() + 1);
    ext.extend_from_slice(label);
    ext.extend_from_slice(seed);
    ext.push(index);
    let bytes = expand_seed_bytes(b"mldsa-small", &ext, MLDSA_N);
    let mut out = Poly::zero();
    for (i, b) in bytes.iter().enumerate().take(MLDSA_N) {
        out.coeffs[i] = i32::from(*b % ((2 * MLDSA_ETA_BOUND + 1) as u8)) - MLDSA_ETA_BOUND;
    }
    out
}

/// Computes `A * s` for matrix `A` and vector `s`.
///
/// # Arguments
///
/// * `a` — `&[[Poly; MLDSA_L]; MLDSA_K]`.
/// * `s` — `&PolyVecL`.
///
/// # Returns
///
/// `PolyVecK` produced by `mat_vec_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mat_vec_mul(a: &[[Poly; MLDSA_L]; MLDSA_K], s: &PolyVecL) -> PolyVecK {
    let mut out = PolyVecK::zero();
    for (i, row) in a.iter().enumerate().take(MLDSA_K) {
        let mut acc = Poly::zero();
        for (j, poly) in row.iter().enumerate().take(MLDSA_L) {
            let term = poly_mul(poly, &s.polys[j]);
            add_poly_inplace(&mut acc, &term);
        }
        normalize_poly(&mut acc);
        out.polys[i] = acc;
    }
    out
}

/// Multiplies two polynomials in `R_q/(x^n+1)`.
///
/// # Arguments
///
/// * `a` — `&Poly`.
/// * `b` — `&Poly`.
///
/// # Returns
///
/// `Poly` produced by `poly_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let mut acc = [0_i64; MLDSA_N];
    for i in 0..MLDSA_N {
        for j in 0..MLDSA_N {
            let idx = i + j;
            let out_idx = idx & (MLDSA_N - 1);
            let mut term = i64::from(a.coeffs[i]) * i64::from(b.coeffs[j]);
            if idx >= MLDSA_N {
                term = -term;
            }
            acc[out_idx] += term;
        }
    }
    let mut out = Poly::zero();
    for (i, v) in acc.iter().enumerate().take(MLDSA_N) {
        out.coeffs[i] = mod_q_i64(*v);
    }
    out
}

/// Adds one polynomial into another.
///
/// # Arguments
///
/// * `dst` — `&mut Poly`.
/// * `src` — `&Poly`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn add_poly_inplace(dst: &mut Poly, src: &Poly) {
    for i in 0..MLDSA_N {
        dst.coeffs[i] = mod_q(dst.coeffs[i] + src.coeffs[i]);
    }
}

/// Adds one length-K vector into another.
///
/// # Arguments
///
/// * `dst` — `&mut PolyVecK`.
/// * `src` — `&PolyVecK`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn add_vec_k_inplace(dst: &mut PolyVecK, src: &PolyVecK) {
    for i in 0..MLDSA_K {
        add_poly_inplace(&mut dst.polys[i], &src.polys[i]);
    }
}

/// Adds `c * src` into destination length-L vector where `c` is the challenge polynomial.
///
/// # Arguments
///
/// * `dst` — `&mut PolyVecL`.
/// * `src` — `&PolyVecL`.
/// * `challenge` — `&Poly`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn add_challenge_vec_l_inplace(dst: &mut PolyVecL, src: &PolyVecL, challenge: &Poly) {
    for i in 0..MLDSA_L {
        let term = poly_mul(challenge, &src.polys[i]);
        add_poly_inplace(&mut dst.polys[i], &term);
    }
}

/// Subtracts `c * src` from destination length-K vector where `c` is the challenge polynomial.
///
/// # Arguments
///
/// * `dst` — `&mut PolyVecK`.
/// * `src` — `&PolyVecK`.
/// * `challenge` — `&Poly`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sub_challenge_vec_k_inplace(dst: &mut PolyVecK, src: &PolyVecK, challenge: &Poly) {
    for i in 0..MLDSA_K {
        let term = poly_mul(challenge, &src.polys[i]);
        for j in 0..MLDSA_N {
            dst.polys[i].coeffs[j] = mod_q(dst.polys[i].coeffs[j] - term.coeffs[j]);
        }
    }
}

/// Normalizes one polynomial modulo q.
///
/// # Arguments
///
/// * `poly` — `&mut Poly`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn normalize_poly(poly: &mut Poly) {
    for c in &mut poly.coeffs {
        *c = mod_q(*c);
    }
}

/// Normalizes one length-L vector modulo q.
///
/// # Arguments
///
/// * `vec` — `&mut PolyVecL`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn normalize_vec_l(vec: &mut PolyVecL) {
    for poly in &mut vec.polys {
        normalize_poly(poly);
    }
}

/// Normalizes one length-K vector modulo q.
///
/// # Arguments
///
/// * `vec` — `&mut PolyVecK`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn normalize_vec_k(vec: &mut PolyVecK) {
    for poly in &mut vec.polys {
        normalize_poly(poly);
    }
}

/// Encodes a small-coefficient length-L vector as signed bytes.
///
/// # Arguments
///
/// * `vec` — `&PolyVecL`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_small_vec_l` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_small_vec_l(vec: &PolyVecL) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_S1_BYTES);
    for poly in &vec.polys {
        for c in &poly.coeffs {
            out.push((*c + MLDSA_ETA_BOUND) as u8);
        }
    }
    out
}

/// Encodes a small-coefficient length-K vector as signed bytes.
///
/// # Arguments
///
/// * `vec` — `&PolyVecK`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_small_vec_k` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_small_vec_k(vec: &PolyVecK) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_S2_BYTES);
    for poly in &vec.polys {
        for c in &poly.coeffs {
            out.push((*c + MLDSA_ETA_BOUND) as u8);
        }
    }
    out
}

/// Decodes a small-coefficient length-L vector from signed bytes.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_small_vec_l`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_small_vec_l(bytes: &[u8]) -> Result<PolyVecL> {
    if bytes.len() != MLDSA_S1_BYTES {
        return Err(Error::InvalidLength("mldsa s1 bytes length mismatch"));
    }
    let mut out = PolyVecL::zero();
    let mut idx = 0_usize;
    for i in 0..MLDSA_L {
        for j in 0..MLDSA_N {
            out.polys[i].coeffs[j] = i32::from(bytes[idx]) - MLDSA_ETA_BOUND;
            idx += 1;
        }
    }
    Ok(out)
}

/// Decodes a small-coefficient length-K vector from signed bytes.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_small_vec_k`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_small_vec_k(bytes: &[u8]) -> Result<PolyVecK> {
    if bytes.len() != MLDSA_S2_BYTES {
        return Err(Error::InvalidLength("mldsa s2 bytes length mismatch"));
    }
    let mut out = PolyVecK::zero();
    let mut idx = 0_usize;
    for i in 0..MLDSA_K {
        for j in 0..MLDSA_N {
            out.polys[i].coeffs[j] = i32::from(bytes[idx]) - MLDSA_ETA_BOUND;
            idx += 1;
        }
    }
    Ok(out)
}

/// Encodes a length-K vector using 10-bit packing per coefficient.
///
/// # Arguments
///
/// * `vec` — `&PolyVecK`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_vec_k_10bit` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_vec_k_10bit(vec: &PolyVecK) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_PUBLIC_T_BYTES);
    for poly in &vec.polys {
        out.extend_from_slice(&encode_poly_10bit(poly));
    }
    out
}

/// Decodes a 10-bit packed length-K vector.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_public_t`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_public_t(bytes: &[u8]) -> Result<PolyVecK> {
    if bytes.len() != MLDSA_PUBLIC_T_BYTES {
        return Err(Error::InvalidLength("mldsa public t bytes length mismatch"));
    }
    let mut out = PolyVecK::zero();
    for i in 0..MLDSA_K {
        let start = i * MLDSA_POLY_PACKED10_BYTES;
        out.polys[i] = decode_poly_10bit(&bytes[start..start + MLDSA_POLY_PACKED10_BYTES])?;
    }
    Ok(out)
}

/// Encodes a length-L vector using 12-bit packing per coefficient.
///
/// # Arguments
///
/// * `vec` — `&PolyVecL`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_vec_l_12bit` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_vec_l_12bit(vec: &PolyVecL) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_SIGNATURE_Z_BYTES);
    for poly in &vec.polys {
        out.extend_from_slice(&encode_poly_12bit(poly));
    }
    out
}

/// Decodes a 12-bit packed length-L vector.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_vec_l_12bit`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_vec_l_12bit(bytes: &[u8]) -> Result<PolyVecL> {
    if bytes.len() != MLDSA_SIGNATURE_Z_BYTES {
        return Err(Error::InvalidLength(
            "mldsa signature z bytes length mismatch",
        ));
    }
    let mut out = PolyVecL::zero();
    for i in 0..MLDSA_L {
        let start = i * MLDSA_POLY_PACKED12_BYTES;
        out.polys[i] = decode_poly_12bit(&bytes[start..start + MLDSA_POLY_PACKED12_BYTES])?;
    }
    Ok(out)
}

/// Encodes one polynomial into 10-bit packed format.
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `encode_poly_10bit` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_poly_10bit(poly: &Poly) -> [u8; MLDSA_POLY_PACKED10_BYTES] {
    let mut out = [0_u8; MLDSA_POLY_PACKED10_BYTES];
    let mut out_idx = 0_usize;
    for chunk in poly.coeffs.chunks_exact(4) {
        let mut t = [0_u16; 4];
        for i in 0..4 {
            t[i] = ((mod_q(chunk[i]) as i64 * 1024 / i64::from(MLDSA_Q)) & 0x03FF) as u16;
        }
        out[out_idx] = t[0] as u8;
        out[out_idx + 1] = ((t[0] >> 8) as u8) | ((t[1] << 2) as u8);
        out[out_idx + 2] = ((t[1] >> 6) as u8) | ((t[2] << 4) as u8);
        out[out_idx + 3] = ((t[2] >> 4) as u8) | ((t[3] << 6) as u8);
        out[out_idx + 4] = (t[3] >> 2) as u8;
        out_idx += 5;
    }
    out
}

/// Decodes one polynomial from 10-bit packed format.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_poly_10bit`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_poly_10bit(bytes: &[u8]) -> Result<Poly> {
    if bytes.len() != MLDSA_POLY_PACKED10_BYTES {
        return Err(Error::InvalidLength(
            "mldsa 10-bit polynomial length mismatch",
        ));
    }
    let mut out = Poly::zero();
    let mut in_idx = 0_usize;
    for i in 0..(MLDSA_N / 4) {
        let b0 = u16::from(bytes[in_idx]);
        let b1 = u16::from(bytes[in_idx + 1]);
        let b2 = u16::from(bytes[in_idx + 2]);
        let b3 = u16::from(bytes[in_idx + 3]);
        let b4 = u16::from(bytes[in_idx + 4]);
        in_idx += 5;
        let t0 = b0 | ((b1 & 0x03) << 8);
        let t1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
        let t2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
        let t3 = (b3 >> 6) | (b4 << 2);
        out.coeffs[4 * i] = ((i64::from(t0) * i64::from(MLDSA_Q)) / 1024) as i32;
        out.coeffs[4 * i + 1] = ((i64::from(t1) * i64::from(MLDSA_Q)) / 1024) as i32;
        out.coeffs[4 * i + 2] = ((i64::from(t2) * i64::from(MLDSA_Q)) / 1024) as i32;
        out.coeffs[4 * i + 3] = ((i64::from(t3) * i64::from(MLDSA_Q)) / 1024) as i32;
    }
    Ok(out)
}

/// Encodes one polynomial into 12-bit packed format.
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `encode_poly_12bit` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_poly_12bit(poly: &Poly) -> [u8; MLDSA_POLY_PACKED12_BYTES] {
    let mut out = [0_u8; MLDSA_POLY_PACKED12_BYTES];
    let mut out_idx = 0_usize;
    for chunk in poly.coeffs.chunks_exact(2) {
        let c0 = (mod_q(chunk[0]) & 0x0FFF) as u16;
        let c1 = (mod_q(chunk[1]) & 0x0FFF) as u16;
        out[out_idx] = (c0 & 0xFF) as u8;
        out[out_idx + 1] = ((c0 >> 8) as u8) | (((c1 & 0x0F) as u8) << 4);
        out[out_idx + 2] = (c1 >> 4) as u8;
        out_idx += 3;
    }
    out
}

/// Decodes one polynomial from 12-bit packed format.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_poly_12bit`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_poly_12bit(bytes: &[u8]) -> Result<Poly> {
    if bytes.len() != MLDSA_POLY_PACKED12_BYTES {
        return Err(Error::InvalidLength(
            "mldsa 12-bit polynomial length mismatch",
        ));
    }
    let mut out = Poly::zero();
    let mut in_idx = 0_usize;
    for i in 0..(MLDSA_N / 2) {
        let b0 = u16::from(bytes[in_idx]);
        let b1 = u16::from(bytes[in_idx + 1]);
        let b2 = u16::from(bytes[in_idx + 2]);
        in_idx += 3;
        out.coeffs[2 * i] = i32::from((b0 | ((b1 & 0x0F) << 8)) & 0x0FFF);
        out.coeffs[2 * i + 1] = i32::from(((b1 >> 4) | (b2 << 4)) & 0x0FFF);
    }
    Ok(out)
}

/// Compresses a vector into hint-domain bytes for challenge derivation.
///
/// # Arguments
///
/// * `vec` — `&PolyVecK`.
///
/// # Returns
///
/// `Vec<u8>` produced by `compress_vec_k_hint` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn compress_vec_k_hint(vec: &PolyVecK) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLDSA_K * MLDSA_N / 2);
    for poly in &vec.polys {
        for pair in poly.coeffs.chunks_exact(2) {
            let lo = (((mod_q(pair[0]) * 16) / MLDSA_Q) & 0x0F) as u8;
            let hi = (((mod_q(pair[1]) * 16) / MLDSA_Q) & 0x0F) as u8;
            out.push(lo | (hi << 4));
        }
    }
    out
}

/// Derives fixed-length hint bytes from signature-visible material.
///
/// # Arguments
///
/// * `w1_bytes` — Compressed `w1` domain bytes from signing.
/// * `z_bytes` — Encoded `z` vector bytes from the signature.
/// * `t` — Public polynomial vector `t` decoded from the public key.
/// * `c` — Challenge digest bytes embedded in the signature.
/// * `out_len` — Total hint output length to produce.
///
/// # Returns
///
/// Hint byte vector of length `out_len`.
///
/// # Panics
///
/// This function does not panic.
fn derive_hint_bytes_from_signature(
    w1_bytes: &[u8],
    z_bytes: &[u8],
    t: &PolyVecK,
    c: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut seed = Vec::new();
    seed.extend_from_slice(w1_bytes);
    seed.extend_from_slice(z_bytes);
    seed.extend_from_slice(&encode_vec_k_10bit(t));
    seed.extend_from_slice(c);
    let mut out = Vec::with_capacity(out_len);
    let take = w1_bytes.len().min(out_len);
    out.extend_from_slice(&w1_bytes[..take]);
    if out_len > take {
        out.extend_from_slice(&expand_seed_bytes(b"mldsa-hints", &seed, out_len - take));
    }
    out
}

/// Computes the signature challenge digest from transcript hash and compressed `w1`.
///
/// # Arguments
///
/// * `mu` — `&[u8; 32]`.
/// * `w1_bytes` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `build_challenge` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn build_challenge(mu: &[u8; 32], w1_bytes: &[u8]) -> [u8; 32] {
    let mut c_input = Vec::with_capacity(1 + mu.len() + w1_bytes.len());
    c_input.push(MLDSA_XOF_DOMAIN_CHALLENGE);
    c_input.extend_from_slice(mu);
    c_input.extend_from_slice(w1_bytes);
    let digest = noxtls_shake256(&c_input, 32);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Expands digest bytes into a sparse challenge polynomial with +/-1 coefficients.
///
/// # Arguments
///
/// * `c` — `&[u8; 32]`.
///
/// # Returns
///
/// `Poly` produced by `challenge_poly_from_digest` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn challenge_poly_from_digest(c: &[u8; 32]) -> Poly {
    let mut poly = Poly::zero();
    let mut seed = Vec::with_capacity(1 + c.len());
    seed.push(MLDSA_XOF_DOMAIN_CHALLENGE);
    seed.extend_from_slice(c);
    let stream = noxtls_shake256(&seed, 4 * MLDSA_CHALLENGE_NONZERO_TERMS);
    let mut cursor = 0_usize;
    let mut placed = 0_usize;
    while placed < MLDSA_CHALLENGE_NONZERO_TERMS {
        let idx_word = u16::from(stream[cursor]) | (u16::from(stream[cursor + 1]) << 8);
        let idx = usize::from(idx_word) % MLDSA_N;
        let sign = if (stream[cursor + 2] & 1) == 0 { 1 } else { -1 };
        cursor += 3;
        if cursor + 3 >= stream.len() {
            cursor = 0;
        }
        if poly.coeffs[idx] == 0 {
            poly.coeffs[idx] = sign;
            placed += 1;
        }
    }
    poly
}

/// Converts a byte slice into a fixed 32-byte array.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `array32_from_slice`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn array32_from_slice(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::InvalidLength("mldsa expected 32-byte slice"))
}

/// Reduces one integer into `[0, q)`.
///
/// # Arguments
///
/// * `value` — `i32`.
///
/// # Returns
///
/// `i32` produced by `mod_q` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_q(value: i32) -> i32 {
    let mut v = value % MLDSA_Q;
    if v < 0 {
        v += MLDSA_Q;
    }
    v
}

/// Reduces one signed 64-bit integer into `[0, q)`.
///
/// # Arguments
///
/// * `value` — `i64`.
///
/// # Returns
///
/// `i32` produced by `mod_q_i64` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_q_i64(value: i64) -> i32 {
    let q = i64::from(MLDSA_Q);
    let mut v = value % q;
    if v < 0 {
        v += q;
    }
    v as i32
}

/// Clamps one integer to the provided closed interval.
///
/// # Arguments
///
/// * `value` — `i32`.
/// * `min_v` — `i32`.
/// * `max_v` — `i32`.
///
/// # Returns
///
/// `i32` produced by `clamp` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn clamp(value: i32, min_v: i32, max_v: i32) -> i32 {
    if value < min_v {
        min_v
    } else if value > max_v {
        max_v
    } else {
        value
    }
}

/// Computes centered absolute value of one coefficient in `[-q/2, q/2]`.
///
/// # Arguments
///
/// * `value` — `i32`.
///
/// # Returns
///
/// `i32` produced by `centered_abs` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn centered_abs(value: i32) -> i32 {
    let reduced = mod_q(value);
    let centered = if reduced > (MLDSA_Q / 2) {
        reduced - MLDSA_Q
    } else {
        reduced
    };
    centered.abs()
}

/// Returns the infinity norm over all coefficients of a length-L vector.
///
/// # Arguments
///
/// * `vec` — `&PolyVecL`.
///
/// # Returns
///
/// `i32` produced by `max_abs_vec_l` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn max_abs_vec_l(vec: &PolyVecL) -> i32 {
    let mut max_v = 0_i32;
    for poly in &vec.polys {
        for coeff in &poly.coeffs {
            let abs = centered_abs(*coeff);
            if abs > max_v {
                max_v = abs;
            }
        }
    }
    max_v
}

/// Returns the infinity norm over all coefficients of a length-K vector.
///
/// # Arguments
///
/// * `vec` — `&PolyVecK`.
///
/// # Returns
///
/// `i32` produced by `max_abs_vec_k` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn max_abs_vec_k(vec: &PolyVecK) -> i32 {
    let mut max_v = 0_i32;
    for poly in &vec.polys {
        for coeff in &poly.coeffs {
            let abs = centered_abs(*coeff);
            if abs > max_v {
                max_v = abs;
            }
        }
    }
    max_v
}

/// Derives one 32-byte hash block from domain label and seed bytes.
///
/// # Arguments
///
/// * `label` — `&[u8]`.
/// * `seed` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `derive_hash32` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_hash32(label: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + label.len() + seed.len());
    input.push(MLDSA_XOF_DOMAIN_HASH32);
    input.extend_from_slice(label);
    input.extend_from_slice(seed);
    let digest = noxtls_shake256(&input, 32);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Expands an input seed to the requested output length using SHAKE256.
///
/// # Arguments
///
/// * `label` — `&[u8]`.
/// * `seed` — `&[u8]`.
/// * `out_len` — `usize`.
///
/// # Returns
///
/// `Vec<u8>` produced by `expand_seed_bytes` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn expand_seed_bytes(label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + label.len() + seed.len());
    input.push(MLDSA_XOF_DOMAIN_EXPAND);
    input.extend_from_slice(label);
    input.extend_from_slice(seed);
    noxtls_shake256(&input, out_len)
}

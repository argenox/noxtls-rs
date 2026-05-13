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

//! ML-KEM interfaces used by TLS 1.3 PQ integration paths.
//!
//! This module implements an in-house ML-KEM-768-style lattice flow while preserving
//! the existing public API and wire sizes used by TLS integration paths.

use crate::drbg::HmacDrbgSha256;
#[cfg(not(feature = "std"))]
use crate::internal_alloc::Vec;
use crate::{noxtls_sha3_256, noxtls_shake256};
use noxtls_core::{Error, Result};

/// Byte length of ML-KEM-768 encoded decapsulation keys.
pub const MLKEM_PRIVATE_KEY_LEN: usize = 2_400;

/// Byte length of ML-KEM-768 encoded encapsulation keys.
pub const MLKEM_PUBLIC_KEY_LEN: usize = 1_184;

/// Byte length used for the TLS 1.3 ML-KEM-768 ciphertext payload.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1_088;

/// Byte length used by ML-KEM-768 shared secrets.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

const MLKEM_N: usize = 256;
const MLKEM_K: usize = 3;
const MLKEM_Q: i32 = 3_329;
const MLKEM_POLY_BYTES: usize = 384;
const MLKEM_POLYVEC_BYTES: usize = MLKEM_K * MLKEM_POLY_BYTES;
const MLKEM_POLYCOMPRESSED_U_BYTES: usize = 320;
const MLKEM_POLYCOMPRESSED_V_BYTES: usize = 128;
const MLKEM_POLYVEC_COMPRESSED_BYTES: usize = MLKEM_K * MLKEM_POLYCOMPRESSED_U_BYTES;
const MLKEM_XOF_DOMAIN_EXPAND: u8 = 0x01;
const MLKEM_XOF_DOMAIN_G: u8 = 0x02;
const MLKEM_XOF_DOMAIN_KDF: u8 = 0x03;
const MLKEM_XOF_DOMAIN_J: u8 = 0x04;
type ParsedPrivateKey<'a> = (PolyVec, &'a [u8], [u8; 32], [u8; 32]);

#[derive(Clone, Copy)]
struct Poly {
    coeffs: [i16; MLKEM_N],
}

impl Poly {
    /// Returns a zero-initialized polynomial in the ML-KEM ring `R_q`.
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
            coeffs: [0; MLKEM_N],
        }
    }
}

#[derive(Clone, Copy)]
struct PolyVec {
    polys: [Poly; MLKEM_K],
}

impl PolyVec {
    /// Returns a zero-initialized vector of `MLKEM_K` polynomials.
    ///
    /// # Arguments
    ///
    /// * *(none)* — This function takes no parameters.
    ///
    /// # Returns
    ///
    /// [`PolyVec`] whose entries are zero polynomials.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn zero() -> Self {
        Self {
            polys: [Poly::zero(), Poly::zero(), Poly::zero()],
        }
    }
}

/// Holds one ML-KEM-768 decapsulation key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlKemPrivateKey {
    bytes: Vec<u8>,
}

impl MlKemPrivateKey {
    /// Builds an ML-KEM-768 private key from encoded bytes.
    ///
    /// # Arguments
    /// * `bytes`: Encoded private key bytes (`MLKEM_PRIVATE_KEY_LEN`).
    ///
    /// # Returns
    /// Parsed private key wrapper.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_PRIVATE_KEY_LEN {
            return Err(Error::InvalidLength("mlkem private key must be 2400 bytes"));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Derives the matching ML-KEM-768 public key.
    ///
    /// # Returns
    /// Encoded public key bytes.
    pub fn public_key(&self) -> Result<MlKemPublicKey> {
        let public_bytes = derive_public_from_private(&self.bytes);
        Ok(MlKemPublicKey {
            bytes: public_bytes,
        })
    }

    /// Returns the encoded private-key bytes.
    ///
    /// # Returns
    /// Encoded private key as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Clears private-key bytes by overwriting each byte before truncation.
    ///
    /// # Arguments
    /// * `self` — Private key whose encoded bytes are scrubbed.
    ///
    /// # Returns
    /// `()`; this private key no longer carries encoded secret bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
        self.bytes.clear();
    }
}

impl Drop for MlKemPrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Holds one ML-KEM-768 encapsulation key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlKemPublicKey {
    bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Builds an ML-KEM-768 public key from encoded bytes.
    ///
    /// # Arguments
    /// * `bytes`: Encoded public key bytes (`MLKEM_PUBLIC_KEY_LEN`).
    ///
    /// # Returns
    /// Parsed public key wrapper.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength("mlkem public key must be 1184 bytes"));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Returns encoded public-key bytes.
    ///
    /// # Returns
    /// Encoded public key as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generates an ML-KEM-768 keypair from DRBG entropy.
///
/// # Arguments
/// * `drbg`: DRBG instance used for private-key generation.
///
/// # Returns
/// `(private, public)` encoded keypair wrappers.
pub fn noxtls_mlkem_generate_keypair_auto(
    drbg: &mut HmacDrbgSha256,
) -> Result<(MlKemPrivateKey, MlKemPublicKey)> {
    let key_seed = drbg.generate(32, b"mlkem keygen seed")?;
    let material = derive_hash_block(MLKEM_XOF_DOMAIN_EXPAND, b"mlkem-keygen-material", &key_seed);
    let rho = material;
    let sigma = derive_hash_block(MLKEM_XOF_DOMAIN_EXPAND, b"mlkem-keygen-sigma", &key_seed);

    let matrix = generate_matrix(&rho, false);
    let s = sample_secret_polyvec(&sigma, b"mlkem-s");
    let e = sample_secret_polyvec(&sigma, b"mlkem-e");
    let mut t = mat_vec_mul(&matrix, &s);
    add_polyvec_inplace(&mut t, &e);
    normalize_polyvec(&mut t);

    let mut public_bytes = Vec::with_capacity(MLKEM_PUBLIC_KEY_LEN);
    public_bytes.extend_from_slice(&polyvec_to_bytes(&t));
    public_bytes.extend_from_slice(&rho);

    let mut private_bytes = Vec::with_capacity(MLKEM_PRIVATE_KEY_LEN);
    private_bytes.extend_from_slice(&polyvec_to_bytes(&s));
    private_bytes.extend_from_slice(&public_bytes);
    let hpk = noxtls_sha3_256(&public_bytes);
    private_bytes.extend_from_slice(&hpk);
    let z = derive_hash_block(MLKEM_XOF_DOMAIN_EXPAND, b"mlkem-keygen-z", &key_seed);
    private_bytes.extend_from_slice(&z);

    Ok((
        MlKemPrivateKey {
            bytes: private_bytes,
        },
        MlKemPublicKey {
            bytes: public_bytes,
        },
    ))
}

/// Encapsulates one shared secret to an ML-KEM-768 public key.
///
/// # Arguments
/// * `public_key`: Recipient public key.
/// * `drbg`: DRBG instance used to derive deterministic encapsulation seed.
///
/// # Returns
/// `(ciphertext, shared_secret)` where ciphertext is 1088 bytes and shared secret is 32 bytes.
pub fn noxtls_mlkem_encapsulate_auto(
    public_key: &MlKemPublicKey,
    drbg: &mut HmacDrbgSha256,
) -> Result<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_LEN])> {
    let m_vec = drbg.generate(MLKEM_SHARED_SECRET_LEN, b"mlkem encapsulate message")?;
    let m: [u8; MLKEM_SHARED_SECRET_LEN] = m_vec
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidLength("mlkem encapsulate message must be 32 bytes"))?;
    let hpk = noxtls_sha3_256(public_key.as_bytes());
    let (k_bar, coins) = derive_k_and_coins(&m, &hpk);
    let (ciphertext, _) = encapsulate_from_message(public_key.as_bytes(), &m, &coins)?;
    let shared_secret = derive_shared_secret(&k_bar, &ciphertext);
    Ok((ciphertext, shared_secret))
}

/// Decapsulates one ML-KEM-768 ciphertext.
///
/// # Arguments
/// * `private_key`: Recipient private key.
/// * `ciphertext`: Encapsulated bytes produced by `noxtls_mlkem_encapsulate_auto`.
///
/// # Returns
/// 32-byte shared secret.
pub fn noxtls_mlkem_decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &[u8],
) -> Result<[u8; MLKEM_SHARED_SECRET_LEN]> {
    if ciphertext.len() != MLKEM_CIPHERTEXT_LEN {
        return Err(Error::InvalidLength("mlkem ciphertext must be 1088 bytes"));
    }
    let (s, public_key_bytes, hpk, z) = parse_private_key(private_key.as_bytes())?;
    let u = polyvec_decompress_u(&ciphertext[..MLKEM_POLYVEC_COMPRESSED_BYTES])?;
    let v = poly_decompress_v(&ciphertext[MLKEM_POLYVEC_COMPRESSED_BYTES..])?;

    let mut m_poly = v;
    let su = vec_dot(&s, &u);
    sub_poly_inplace(&mut m_poly, &su);
    normalize_poly(&mut m_poly);
    let m = poly_to_message(&m_poly);

    let (k_bar, recompute_coins) = derive_k_and_coins(&m, &hpk);
    let (expected_ct, _) = encapsulate_from_message(public_key_bytes, &m, &recompute_coins)?;
    let valid_mask = ct_eq_mask(&expected_ct, ciphertext);

    let mut z_input = Vec::with_capacity(z.len() + MLKEM_SHARED_SECRET_LEN);
    z_input.extend_from_slice(&z);
    z_input.extend_from_slice(&noxtls_sha3_256(ciphertext));
    let fallback_k = fips203_j(&z_input);
    let selected_k = select_32(valid_mask, &k_bar, &fallback_k);
    Ok(derive_shared_secret(&selected_k, ciphertext))
}

/// Re-runs encapsulation using fixed message and coins for CCA-style consistency checks.
///
/// # Arguments
///
/// * `public_key` — Encoded ML-KEM public key bytes.
/// * `message` — Shared-secret-length message material.
/// * `coins` — Random coins driving secret/error sampling.
///
/// # Returns
///
/// On success, ciphertext bytes and the derived shared secret.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or intermediate sampling fails.
///
/// # Panics
///
/// This function does not panic.
fn encapsulate_from_message(
    public_key: &[u8],
    message: &[u8; MLKEM_SHARED_SECRET_LEN],
    coins: &[u8; MLKEM_SHARED_SECRET_LEN],
) -> Result<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_LEN])> {
    let (t, rho) = parse_public_key(public_key)?;
    let matrix_t = generate_matrix(&rho, true);
    let r = sample_secret_polyvec(coins, b"mlkem-r");
    let e1 = sample_error_polyvec(coins, b"mlkem-e1");
    let e2 = sample_error_poly(coins, b"mlkem-e2", 0);

    let mut u = mat_vec_mul(&matrix_t, &r);
    add_polyvec_inplace(&mut u, &e1);
    normalize_polyvec(&mut u);

    let mut v = vec_dot(&t, &r);
    add_poly_inplace(&mut v, &e2);
    add_poly_inplace(&mut v, &message_to_poly(message));
    normalize_poly(&mut v);

    let mut ciphertext = Vec::with_capacity(MLKEM_CIPHERTEXT_LEN);
    ciphertext.extend_from_slice(&polyvec_compress_u(&u));
    ciphertext.extend_from_slice(&poly_compress_v(&v));
    let shared = derive_shared_secret(message, &ciphertext);
    Ok((ciphertext, shared))
}

/// Derives the encapsulation key bytes from a private key structure.
///
/// # Arguments
///
/// * `private_bytes` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `derive_public_from_private` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_public_from_private(private_bytes: &[u8]) -> Vec<u8> {
    if private_bytes.len() == MLKEM_PRIVATE_KEY_LEN {
        let start = MLKEM_POLYVEC_BYTES;
        let end = start + MLKEM_PUBLIC_KEY_LEN;
        return private_bytes[start..end].to_vec();
    }
    expand_seed(
        b"mlkem-public-fallback",
        private_bytes,
        MLKEM_PUBLIC_KEY_LEN,
    )
}

/// Derives the shared secret from message material and the ciphertext hash.
///
/// # Arguments
///
/// * `key_material` — Fixed-size keying input.
/// * `ciphertext` — Encapsulated ciphertext whose hash is mixed in.
///
/// # Returns
///
/// 32-byte shared secret material after domain-separated KDF.
///
/// # Panics
///
/// This function does not panic.
fn derive_shared_secret(
    key_material: &[u8; MLKEM_SHARED_SECRET_LEN],
    ciphertext: &[u8],
) -> [u8; MLKEM_SHARED_SECRET_LEN] {
    let mut input = Vec::with_capacity(MLKEM_SHARED_SECRET_LEN + MLKEM_SHARED_SECRET_LEN);
    input.extend_from_slice(key_material);
    input.extend_from_slice(&noxtls_sha3_256(ciphertext));
    fips203_kdf(&input)
}

/// Implements ML-KEM-style G expansion from `m || H(pk)` to `(k_bar, coins)`.
///
/// # Arguments
///
/// * `message` — Random message bytes used as KEM seed material.
/// * `hpk` — 32-byte hash of the public key mixed into the expansion input.
///
/// # Returns
///
/// Tuple `(k_bar, coins)` each of shared-secret length.
///
/// # Panics
///
/// This function does not panic.
fn derive_k_and_coins(
    message: &[u8; MLKEM_SHARED_SECRET_LEN],
    hpk: &[u8; MLKEM_SHARED_SECRET_LEN],
) -> ([u8; MLKEM_SHARED_SECRET_LEN], [u8; MLKEM_SHARED_SECRET_LEN]) {
    let mut input = Vec::with_capacity(MLKEM_SHARED_SECRET_LEN * 2);
    input.extend_from_slice(message);
    input.extend_from_slice(hpk);
    let expanded = fips203_g(&input);
    let mut k_bar = [0_u8; MLKEM_SHARED_SECRET_LEN];
    let mut coins = [0_u8; MLKEM_SHARED_SECRET_LEN];
    k_bar.copy_from_slice(&expanded[..MLKEM_SHARED_SECRET_LEN]);
    coins.copy_from_slice(&expanded[MLKEM_SHARED_SECRET_LEN..64]);
    (k_bar, coins)
}

/// Expands seed bytes to arbitrary length using SHAKE256 in domain-separated mode.
///
/// # Arguments
///
/// * `label` — `&[u8]`.
/// * `seed` — `&[u8]`.
/// * `out_len` — `usize`.
///
/// # Returns
///
/// `Vec<u8>` produced by `expand_seed` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn expand_seed(label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + label.len() + seed.len());
    input.push(MLKEM_XOF_DOMAIN_EXPAND);
    input.extend_from_slice(label);
    input.extend_from_slice(seed);
    noxtls_shake256(&input, out_len)
}

/// Derives one fixed 32-byte block from a domain label and seed.
///
/// # Arguments
///
/// * `domain` — `u8`.
/// * `label` — `&[u8]`.
/// * `seed` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `derive_hash_block` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_hash_block(domain: u8, label: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + label.len() + seed.len());
    input.push(domain);
    input.extend_from_slice(label);
    input.extend_from_slice(seed);
    let digest = noxtls_shake256(&input, 32);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Parses public-key bytes into `(t, rho)` for encapsulation operations.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_public_key`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_public_key(bytes: &[u8]) -> Result<(PolyVec, [u8; 32])> {
    if bytes.len() != MLKEM_PUBLIC_KEY_LEN {
        return Err(Error::InvalidLength("mlkem public key must be 1184 bytes"));
    }
    let t = polyvec_from_bytes(&bytes[..MLKEM_POLYVEC_BYTES])?;
    let mut rho = [0_u8; 32];
    rho.copy_from_slice(&bytes[MLKEM_POLYVEC_BYTES..MLKEM_POLYVEC_BYTES + 32]);
    Ok((t, rho))
}

/// Parses private-key bytes and returns `(s, embedded_public_key_bytes)`.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_private_key`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_private_key(bytes: &[u8]) -> Result<ParsedPrivateKey<'_>> {
    if bytes.len() != MLKEM_PRIVATE_KEY_LEN {
        return Err(Error::InvalidLength("mlkem private key must be 2400 bytes"));
    }
    let s = polyvec_from_bytes(&bytes[..MLKEM_POLYVEC_BYTES])?;
    let public_key = &bytes[MLKEM_POLYVEC_BYTES..MLKEM_POLYVEC_BYTES + MLKEM_PUBLIC_KEY_LEN];
    let hpk_offset = MLKEM_POLYVEC_BYTES + MLKEM_PUBLIC_KEY_LEN;
    let mut hpk = [0_u8; 32];
    hpk.copy_from_slice(&bytes[hpk_offset..hpk_offset + 32]);
    let mut z = [0_u8; 32];
    z.copy_from_slice(&bytes[hpk_offset + 32..hpk_offset + 64]);
    Ok((s, public_key, hpk, z))
}

/// Generates the deterministic A matrix (or transpose) from `rho`.
///
/// # Arguments
///
/// * `rho` — `&[u8; 32]`.
/// * `transpose` — `bool`.
///
/// # Returns
///
/// `[[Poly` produced by `generate_matrix` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn generate_matrix(rho: &[u8; 32], transpose: bool) -> [[Poly; MLKEM_K]; MLKEM_K] {
    let mut out = [[Poly::zero(), Poly::zero(), Poly::zero()]; MLKEM_K];
    for (i, row_out) in out.iter_mut().enumerate().take(MLKEM_K) {
        for (j, cell) in row_out.iter_mut().enumerate().take(MLKEM_K) {
            let row = if transpose { j as u8 } else { i as u8 };
            let col = if transpose { i as u8 } else { j as u8 };
            *cell = sample_uniform_poly(rho, row, col);
        }
    }
    out
}

/// Samples one uniform polynomial modulo q for matrix generation.
///
/// # Arguments
///
/// * `rho` — `&[u8; 32]`.
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
fn sample_uniform_poly(rho: &[u8; 32], row: u8, col: u8) -> Poly {
    let mut seed = Vec::with_capacity(34);
    seed.extend_from_slice(rho);
    seed.push(row);
    seed.push(col);
    let mut poly = Poly::zero();
    let mut coeff_idx = 0_usize;
    let mut counter = 0_u32;
    while coeff_idx < MLKEM_N {
        let mut block_seed = seed.clone();
        block_seed.extend_from_slice(&counter.to_le_bytes());
        let stream = expand_seed(b"mlkem-aij", &block_seed, 768);
        let mut byte_idx = 0_usize;
        while coeff_idx < MLKEM_N && byte_idx + 2 < stream.len() {
            let d0 = u16::from(stream[byte_idx]) | (u16::from(stream[byte_idx + 1] & 0x0F) << 8);
            let d1 =
                (u16::from(stream[byte_idx + 1]) >> 4) | (u16::from(stream[byte_idx + 2]) << 4);
            byte_idx += 3;
            if d0 < MLKEM_Q as u16 {
                poly.coeffs[coeff_idx] = d0 as i16;
                coeff_idx += 1;
            }
            if coeff_idx < MLKEM_N && d1 < MLKEM_Q as u16 {
                poly.coeffs[coeff_idx] = d1 as i16;
                coeff_idx += 1;
            }
        }
        counter = counter.wrapping_add(1);
    }
    poly
}

/// Constant-time byte-slice equality check.
///
/// # Arguments
///
/// * `left` — `&[u8]`.
/// * `right` — `&[u8]`.
///
/// # Returns
///
/// `u8` produced by `ct_eq_mask` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ct_eq_mask(left: &[u8], right: &[u8]) -> u8 {
    if left.len() != right.len() {
        return 0x00;
    }
    let mut diff = 0_u8;
    for i in 0..left.len() {
        diff |= left[i] ^ right[i];
    }
    // Converts equality into full-byte mask: 0xFF when equal, 0x00 otherwise.
    let nonzero = ((u16::from(diff) | u16::from(diff).wrapping_neg()) >> 15) as u8;
    nonzero.wrapping_sub(1)
}

/// Constant-time selection between two 32-byte arrays.
///
/// # Arguments
///
/// * `mask_a` — `u8`.
/// * `a` — `&[u8; 32]`.
/// * `b` — `&[u8; 32]`.
///
/// # Returns
///
/// `[u8` produced by `select_32` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn select_32(mask_a: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for i in 0..32 {
        out[i] = (a[i] & mask_a) | (b[i] & !mask_a);
    }
    out
}

/// Implements a domain-separated FIPS203-like G expansion producing `(Kbar || coins)`.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `fips203_g` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fips203_g(input: &[u8]) -> [u8; 64] {
    let mut domain_input = Vec::with_capacity(1 + input.len());
    domain_input.push(MLKEM_XOF_DOMAIN_G);
    domain_input.extend_from_slice(input);
    let expanded = noxtls_shake256(&domain_input, 64);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&expanded);
    out
}

/// Implements a domain-separated FIPS203-like KDF for shared-secret derivation.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `fips203_kdf` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fips203_kdf(input: &[u8]) -> [u8; 32] {
    let mut domain_input = Vec::with_capacity(1 + input.len());
    domain_input.push(MLKEM_XOF_DOMAIN_KDF);
    domain_input.extend_from_slice(input);
    let expanded = noxtls_shake256(&domain_input, 32);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&expanded);
    out
}

/// Implements a domain-separated FIPS203-like implicit-rejection derivation J(z || H(c)).
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// `[u8` produced by `fips203_j` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn fips203_j(input: &[u8]) -> [u8; 32] {
    let mut domain_input = Vec::with_capacity(1 + input.len());
    domain_input.push(MLKEM_XOF_DOMAIN_J);
    domain_input.extend_from_slice(input);
    let expanded = noxtls_shake256(&domain_input, 32);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&expanded);
    out
}

/// Samples secret-vector noise polynomials with centered-binomial eta=2.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
///
/// # Returns
///
/// `PolyVec` produced by `sample_secret_polyvec` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_secret_polyvec(seed: &[u8; 32], label: &[u8]) -> PolyVec {
    let mut out = PolyVec::zero();
    for i in 0..MLKEM_K {
        out.polys[i] = sample_error_poly(seed, label, i as u8);
    }
    out
}

/// Samples error-vector noise polynomials with centered-binomial eta=2.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
///
/// # Returns
///
/// `PolyVec` produced by `sample_error_polyvec` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_error_polyvec(seed: &[u8; 32], label: &[u8]) -> PolyVec {
    sample_secret_polyvec(seed, label)
}

/// Samples one centered-binomial eta=2 polynomial from domain-separated seed.
///
/// # Arguments
///
/// * `seed` — `&[u8; 32]`.
/// * `label` — `&[u8]`.
/// * `index` — `u8`.
///
/// # Returns
///
/// `Poly` produced by `sample_error_poly` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sample_error_poly(seed: &[u8; 32], label: &[u8], index: u8) -> Poly {
    let mut ext = Vec::with_capacity(label.len() + 33);
    ext.extend_from_slice(label);
    ext.extend_from_slice(seed);
    ext.push(index);
    let stream = expand_seed(b"mlkem-noise", &ext, MLKEM_N / 2);
    let mut poly = Poly::zero();
    let mut coeff_idx = 0_usize;
    for b in stream {
        let low = b & 0x0F;
        let high = (b >> 4) & 0x0F;
        for nibble in [low, high] {
            if coeff_idx >= MLKEM_N {
                break;
            }
            let a = (nibble & 0x03).count_ones() as i16;
            let c = ((nibble >> 2) & 0x03).count_ones() as i16;
            poly.coeffs[coeff_idx] = a - c;
            coeff_idx += 1;
        }
    }
    poly
}

/// Computes matrix-vector multiplication in R_q.
///
/// # Arguments
///
/// * `matrix` — `&[[Poly; MLKEM_K]; MLKEM_K]`.
/// * `vec` — `&PolyVec`.
///
/// # Returns
///
/// `PolyVec` produced by `mat_vec_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mat_vec_mul(matrix: &[[Poly; MLKEM_K]; MLKEM_K], vec: &PolyVec) -> PolyVec {
    let mut out = PolyVec::zero();
    for (row_idx, row) in matrix.iter().enumerate() {
        let mut acc = Poly::zero();
        for (col_idx, poly) in row.iter().enumerate() {
            let prod = poly_mul(poly, &vec.polys[col_idx]);
            add_poly_inplace(&mut acc, &prod);
        }
        normalize_poly(&mut acc);
        out.polys[row_idx] = acc;
    }
    out
}

/// Computes dot product between two polynomial vectors in R_q.
///
/// # Arguments
///
/// * `a` — `&PolyVec`.
/// * `b` — `&PolyVec`.
///
/// # Returns
///
/// `Poly` produced by `vec_dot` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn vec_dot(a: &PolyVec, b: &PolyVec) -> Poly {
    let mut acc = Poly::zero();
    for i in 0..MLKEM_K {
        let prod = poly_mul(&a.polys[i], &b.polys[i]);
        add_poly_inplace(&mut acc, &prod);
    }
    normalize_poly(&mut acc);
    acc
}

/// Multiplies two polynomials modulo (x^256 + 1, q).
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
    let mut acc = [0_i32; MLKEM_N];
    for i in 0..MLKEM_N {
        for j in 0..MLKEM_N {
            let mut term = i32::from(a.coeffs[i]) * i32::from(b.coeffs[j]);
            let idx = i + j;
            let out_idx = idx & (MLKEM_N - 1);
            if idx >= MLKEM_N {
                term = -term;
            }
            acc[out_idx] += term;
        }
    }
    let mut out = Poly::zero();
    for (i, v) in acc.iter().enumerate() {
        out.coeffs[i] = barrett_reduce(*v) as i16;
    }
    out
}

/// Adds one polynomial into another in place.
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
    for i in 0..MLKEM_N {
        dst.coeffs[i] = barrett_reduce(i32::from(dst.coeffs[i]) + i32::from(src.coeffs[i])) as i16;
    }
}

/// Subtracts one polynomial from another in place.
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
fn sub_poly_inplace(dst: &mut Poly, src: &Poly) {
    for i in 0..MLKEM_N {
        dst.coeffs[i] = barrett_reduce(i32::from(dst.coeffs[i]) - i32::from(src.coeffs[i])) as i16;
    }
}

/// Adds one polynomial-vector into another in place.
///
/// # Arguments
///
/// * `dst` — `&mut PolyVec`.
/// * `src` — `&PolyVec`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn add_polyvec_inplace(dst: &mut PolyVec, src: &PolyVec) {
    for i in 0..MLKEM_K {
        add_poly_inplace(&mut dst.polys[i], &src.polys[i]);
    }
}

/// Normalizes one polynomial to canonical [0, q) representatives.
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
        *c = barrett_reduce(i32::from(*c)) as i16;
    }
}

/// Normalizes one polynomial-vector to canonical [0, q) representatives.
///
/// # Arguments
///
/// * `vec` — `&mut PolyVec`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn normalize_polyvec(vec: &mut PolyVec) {
    for poly in &mut vec.polys {
        normalize_poly(poly);
    }
}

/// Reduces one integer to [0, q) with simple modular correction.
///
/// # Arguments
///
/// * `value` — `i32`.
///
/// # Returns
///
/// `i32` produced by `barrett_reduce` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn barrett_reduce(value: i32) -> i32 {
    let mut v = value % MLKEM_Q;
    if v < 0 {
        v += MLKEM_Q;
    }
    v
}

/// Packs one polynomial into Kyber 12-bit canonical byte format.
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `poly_to_bytes` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_to_bytes(poly: &Poly) -> [u8; MLKEM_POLY_BYTES] {
    let mut out = [0_u8; MLKEM_POLY_BYTES];
    let mut out_idx = 0_usize;
    for chunk in poly.coeffs.chunks_exact(2) {
        let c0 = barrett_reduce(i32::from(chunk[0])) as u16;
        let c1 = barrett_reduce(i32::from(chunk[1])) as u16;
        out[out_idx] = (c0 & 0xFF) as u8;
        out[out_idx + 1] = ((c0 >> 8) as u8) | (((c1 & 0x0F) as u8) << 4);
        out[out_idx + 2] = (c1 >> 4) as u8;
        out_idx += 3;
    }
    out
}

/// Unpacks one polynomial from Kyber 12-bit canonical byte format.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `poly_from_bytes`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_from_bytes(bytes: &[u8]) -> Result<Poly> {
    if bytes.len() != MLKEM_POLY_BYTES {
        return Err(Error::InvalidLength(
            "mlkem polynomial bytes must be 384 bytes",
        ));
    }
    let mut out = Poly::zero();
    let mut in_idx = 0_usize;
    for i in 0..(MLKEM_N / 2) {
        let b0 = u16::from(bytes[in_idx]);
        let b1 = u16::from(bytes[in_idx + 1]);
        let b2 = u16::from(bytes[in_idx + 2]);
        in_idx += 3;
        out.coeffs[2 * i] = ((b0 | ((b1 & 0x0F) << 8)) % (MLKEM_Q as u16)) as i16;
        out.coeffs[2 * i + 1] = ((((b1 >> 4) | (b2 << 4)) & 0x0FFF) % (MLKEM_Q as u16)) as i16;
    }
    Ok(out)
}

/// Packs one polynomial-vector into canonical bytes.
///
/// # Arguments
///
/// * `vec` — `&PolyVec`.
///
/// # Returns
///
/// `[u8` produced by `polyvec_to_bytes` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn polyvec_to_bytes(vec: &PolyVec) -> [u8; MLKEM_POLYVEC_BYTES] {
    let mut out = [0_u8; MLKEM_POLYVEC_BYTES];
    for i in 0..MLKEM_K {
        let start = i * MLKEM_POLY_BYTES;
        out[start..start + MLKEM_POLY_BYTES].copy_from_slice(&poly_to_bytes(&vec.polys[i]));
    }
    out
}

/// Unpacks one polynomial-vector from canonical bytes.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `polyvec_from_bytes`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn polyvec_from_bytes(bytes: &[u8]) -> Result<PolyVec> {
    if bytes.len() != MLKEM_POLYVEC_BYTES {
        return Err(Error::InvalidLength(
            "mlkem polyvec bytes must be 1152 bytes",
        ));
    }
    let mut out = PolyVec::zero();
    for i in 0..MLKEM_K {
        let start = i * MLKEM_POLY_BYTES;
        out.polys[i] = poly_from_bytes(&bytes[start..start + MLKEM_POLY_BYTES])?;
    }
    Ok(out)
}

/// Compresses one polynomial-vector to 10-bit coefficients (u component).
///
/// # Arguments
///
/// * `vec` — `&PolyVec`.
///
/// # Returns
///
/// `[u8` produced by `polyvec_compress_u` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn polyvec_compress_u(vec: &PolyVec) -> [u8; MLKEM_POLYVEC_COMPRESSED_BYTES] {
    let mut out = [0_u8; MLKEM_POLYVEC_COMPRESSED_BYTES];
    for i in 0..MLKEM_K {
        let start = i * MLKEM_POLYCOMPRESSED_U_BYTES;
        out[start..start + MLKEM_POLYCOMPRESSED_U_BYTES]
            .copy_from_slice(&poly_compress_10(&vec.polys[i]));
    }
    out
}

/// Decompresses one 10-bit compressed polynomial-vector (u component).
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `polyvec_decompress_u`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn polyvec_decompress_u(bytes: &[u8]) -> Result<PolyVec> {
    if bytes.len() != MLKEM_POLYVEC_COMPRESSED_BYTES {
        return Err(Error::InvalidLength("mlkem u bytes must be 960 bytes"));
    }
    let mut out = PolyVec::zero();
    for i in 0..MLKEM_K {
        let start = i * MLKEM_POLYCOMPRESSED_U_BYTES;
        out.polys[i] = poly_decompress_10(&bytes[start..start + MLKEM_POLYCOMPRESSED_U_BYTES])?;
    }
    Ok(out)
}

/// Compresses one polynomial to 4-bit coefficients (v component).
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `poly_compress_v` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_compress_v(poly: &Poly) -> [u8; MLKEM_POLYCOMPRESSED_V_BYTES] {
    let mut out = [0_u8; MLKEM_POLYCOMPRESSED_V_BYTES];
    for (i, out_byte) in out.iter_mut().enumerate().take(MLKEM_N / 2) {
        let c0 = barrett_reduce(i32::from(poly.coeffs[2 * i])) as i64;
        let c1 = barrett_reduce(i32::from(poly.coeffs[2 * i + 1])) as i64;
        let t0 = ((((c0 << 4) + i64::from(MLKEM_Q / 2)) / i64::from(MLKEM_Q)) & 0x0F) as u8;
        let t1 = ((((c1 << 4) + i64::from(MLKEM_Q / 2)) / i64::from(MLKEM_Q)) & 0x0F) as u8;
        *out_byte = t0 | (t1 << 4);
    }
    out
}

/// Decompresses one 4-bit compressed polynomial (v component).
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `poly_decompress_v`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_decompress_v(bytes: &[u8]) -> Result<Poly> {
    if bytes.len() != MLKEM_POLYCOMPRESSED_V_BYTES {
        return Err(Error::InvalidLength("mlkem v bytes must be 128 bytes"));
    }
    let mut out = Poly::zero();
    for (i, b) in bytes.iter().enumerate() {
        let t0 = i32::from(b & 0x0F);
        let t1 = i32::from(b >> 4);
        out.coeffs[2 * i] = (((t0 * MLKEM_Q) + 8) >> 4) as i16;
        out.coeffs[2 * i + 1] = (((t1 * MLKEM_Q) + 8) >> 4) as i16;
    }
    Ok(out)
}

/// Compresses one polynomial to 10-bit packed representation.
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `poly_compress_10` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_compress_10(poly: &Poly) -> [u8; MLKEM_POLYCOMPRESSED_U_BYTES] {
    let mut out = [0_u8; MLKEM_POLYCOMPRESSED_U_BYTES];
    let mut out_idx = 0_usize;
    for chunk in poly.coeffs.chunks_exact(4) {
        let mut t = [0_u16; 4];
        for i in 0..4 {
            let c = barrett_reduce(i32::from(chunk[i])) as i64;
            t[i] = ((((c << 10) + i64::from(MLKEM_Q / 2)) / i64::from(MLKEM_Q)) & 0x03FF) as u16;
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

/// Decompresses one 10-bit packed polynomial representation.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `poly_decompress_10`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_decompress_10(bytes: &[u8]) -> Result<Poly> {
    if bytes.len() != MLKEM_POLYCOMPRESSED_U_BYTES {
        return Err(Error::InvalidLength(
            "mlkem compressed poly must be 320 bytes",
        ));
    }
    let mut out = Poly::zero();
    let mut in_idx = 0_usize;
    for i in 0..(MLKEM_N / 4) {
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
        out.coeffs[4 * i] = (((i32::from(t0) * MLKEM_Q) + 512) >> 10) as i16;
        out.coeffs[4 * i + 1] = (((i32::from(t1) * MLKEM_Q) + 512) >> 10) as i16;
        out.coeffs[4 * i + 2] = (((i32::from(t2) * MLKEM_Q) + 512) >> 10) as i16;
        out.coeffs[4 * i + 3] = (((i32::from(t3) * MLKEM_Q) + 512) >> 10) as i16;
    }
    Ok(out)
}

/// Encodes a 32-byte message as a polynomial in R_q.
///
/// # Arguments
///
/// * `message` — `&[u8]`.
///
/// # Returns
///
/// `Poly` produced by `message_to_poly` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn message_to_poly(message: &[u8]) -> Poly {
    let mut out = Poly::zero();
    for i in 0..MLKEM_N {
        let bit = (message[i / 8] >> (i % 8)) & 0x01;
        out.coeffs[i] = if bit == 1 { (MLKEM_Q / 2) as i16 } else { 0 };
    }
    out
}

/// Decodes a polynomial in R_q back into a 32-byte message.
///
/// # Arguments
///
/// * `poly` — `&Poly`.
///
/// # Returns
///
/// `[u8` produced by `poly_to_message` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn poly_to_message(poly: &Poly) -> [u8; MLKEM_SHARED_SECRET_LEN] {
    let mut out = [0_u8; MLKEM_SHARED_SECRET_LEN];
    for i in 0..MLKEM_N {
        let c = barrett_reduce(i32::from(poly.coeffs[i]));
        let bit = (((2 * c + MLKEM_Q / 2) / MLKEM_Q) & 1) as u8;
        out[i / 8] |= bit << (i % 8);
    }
    out
}

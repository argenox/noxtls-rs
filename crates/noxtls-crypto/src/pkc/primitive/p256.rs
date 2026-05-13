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

use core::cmp::Ordering;

use crate::drbg::HmacDrbgSha256;
use crate::hash::noxtls_sha256;
use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

use super::bignum::BigUint;

/// Represents a P-256 private scalar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct P256PrivateKey {
    scalar: BigUint,
}

/// Represents a P-256 public point on secp256r1.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct P256PublicKey {
    point: CurvePoint,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CurvePoint {
    x: BigUint,
    y: BigUint,
    infinity: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    infinity: bool,
}

impl P256PrivateKey {
    /// Parses and validates a private scalar as a big-endian 32-byte value.
    ///
    /// # Arguments
    /// * `bytes`: 32-byte private scalar encoding.
    ///
    /// # Returns
    /// Parsed `P256PrivateKey` when scalar is in the valid range `(0, n)`.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let scalar = BigUint::from_be_bytes(&bytes);
        if scalar.is_zero() {
            return Err(Error::CryptoFailure("p256 private scalar must be non-zero"));
        }
        let n = curve_order_n();
        if scalar.cmp(&n) != Ordering::Less {
            return Err(Error::CryptoFailure("p256 private scalar out of range"));
        }
        Ok(Self { scalar })
    }

    /// Serializes the private scalar as canonical 32-byte big-endian octets.
    ///
    /// # Arguments
    /// * `self`: Private key scalar to encode.
    ///
    /// # Returns
    /// 32-byte scalar encoding used by SEC1/PKCS#8 wrappers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when internal scalar encoding cannot be represented in 32 bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        let bytes = self.scalar.to_be_bytes_padded(32)?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Clears private scalar material by zeroing backing limbs in place.
    ///
    /// # Arguments
    /// * `self` — Private key whose scalar memory is scrubbed.
    ///
    /// # Returns
    /// `()`; leaves the scalar in a cleared zero state.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        self.scalar.clear();
    }

    /// Computes the corresponding public key by scalar multiplication of the base point.
    ///
    /// # Arguments
    /// * `self`: Private key used for base-point multiplication.
    ///
    /// # Returns
    /// Derived `P256PublicKey`.
    pub fn public_key(&self) -> Result<P256PublicKey> {
        let g = curve_base_point();
        let point = scalar_mul(&self.scalar, &g)?;
        if point.infinity {
            return Err(Error::CryptoFailure(
                "p256 public key derivation produced infinity",
            ));
        }
        Ok(P256PublicKey { point })
    }

    /// Performs checked ECDH with peer public key and returns 32-byte x-coordinate secret.
    ///
    /// # Arguments
    /// * `self`: Local private key.
    /// * `peer`: Peer public key to validate and use.
    ///
    /// # Returns
    /// 32-byte shared secret from affine x-coordinate.
    pub fn diffie_hellman(&self, peer: &P256PublicKey) -> Result<[u8; 32]> {
        peer.validate()?;
        let shared = scalar_mul(&self.scalar, &peer.point)?;
        if shared.infinity {
            return Err(Error::CryptoFailure("p256 shared point is at infinity"));
        }
        let secret = shared.x.to_be_bytes_padded(32)?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(&secret);
        if is_all_zero(&out) {
            return Err(Error::CryptoFailure("p256 shared secret is all-zero"));
        }
        Ok(out)
    }

    /// Signs a message with P-256 ECDSA using SHA-256 and deterministic nonce derivation.
    ///
    /// # Arguments
    /// * `message`: Message bytes to hash and sign.
    ///
    /// # Returns
    /// Signature tuple `(r, s)` as 32-byte big-endian scalars.
    pub fn sign_sha256(&self, message: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let digest = noxtls_sha256(message);
        self.sign_digest(&digest)
    }

    /// Signs a message with P-256 ECDSA using SHA-256 and DRBG-generated nonce candidates.
    ///
    /// # Arguments
    /// * `message`: Message bytes to hash and sign.
    /// * `drbg`: DRBG used to generate per-signature nonce candidates.
    ///
    /// # Returns
    /// Signature tuple `(r, s)` as 32-byte big-endian scalars.
    pub fn sign_sha256_auto(
        &self,
        message: &[u8],
        drbg: &mut HmacDrbgSha256,
    ) -> Result<([u8; 32], [u8; 32])> {
        let digest = noxtls_sha256(message);
        self.sign_digest_auto(&digest, drbg)
    }

    /// Signs a precomputed 32-byte digest with P-256 ECDSA using deterministic nonce derivation.
    ///
    /// # Arguments
    /// * `digest`: Precomputed SHA-256 digest bytes to sign.
    ///
    /// # Returns
    /// Signature tuple `(r, s)` as 32-byte big-endian scalars.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let n = curve_order_n();
        let g = curve_base_point();
        let e = BigUint::from_be_bytes(digest).modulo(&n);
        let d = self.scalar.clone();

        // Deterministic nonce derivation keeps signatures reproducible for fixed key+digest.
        let mut counter = 0_u32;
        loop {
            let k = derive_signing_nonce(&d, digest, counter).modulo(&n);
            counter = counter.wrapping_add(1);
            if k.is_zero() {
                if counter == 0 {
                    return Err(Error::CryptoFailure(
                        "p256 ecdsa nonce derivation exhausted",
                    ));
                }
                continue;
            }

            let rp = scalar_mul(&k, &g)?;
            if rp.infinity {
                if counter == 0 {
                    return Err(Error::CryptoFailure(
                        "p256 ecdsa nonce derivation exhausted",
                    ));
                }
                continue;
            }
            let r_bn = rp.x.modulo(&n);
            if r_bn.is_zero() {
                if counter == 0 {
                    return Err(Error::CryptoFailure(
                        "p256 ecdsa nonce derivation exhausted",
                    ));
                }
                continue;
            }

            let rd = mod_mul(&r_bn, &d, &n);
            let e_plus_rd = e.add(&rd).modulo(&n);
            let k_inv = mod_inv(&k, &n)?;
            let s_bn = mod_mul(&k_inv, &e_plus_rd, &n);
            if s_bn.is_zero() {
                if counter == 0 {
                    return Err(Error::CryptoFailure(
                        "p256 ecdsa nonce derivation exhausted",
                    ));
                }
                continue;
            }

            let mut r = [0_u8; 32];
            let mut s = [0_u8; 32];
            r.copy_from_slice(&r_bn.to_be_bytes_padded(32)?);
            s.copy_from_slice(&s_bn.to_be_bytes_padded(32)?);
            return Ok((r, s));
        }
    }

    /// Signs a precomputed 32-byte digest with P-256 ECDSA using DRBG-generated nonce candidates.
    ///
    /// # Arguments
    /// * `digest`: Precomputed SHA-256 digest bytes to sign.
    /// * `drbg`: DRBG used to generate per-signature nonce candidates.
    ///
    /// # Returns
    /// Signature tuple `(r, s)` as 32-byte big-endian scalars.
    pub fn sign_digest_auto(
        &self,
        digest: &[u8; 32],
        drbg: &mut HmacDrbgSha256,
    ) -> Result<([u8; 32], [u8; 32])> {
        let n = curve_order_n();
        let g = curve_base_point();
        let e = BigUint::from_be_bytes(digest).modulo(&n);
        let d = self.scalar.clone();

        for _ in 0..64 {
            let nonce_bytes = drbg.generate(32, b"p256_ecdsa_nonce")?;
            let nonce_arr: [u8; 32] = nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidLength("p256 ecdsa nonce length mismatch"))?;
            let k = BigUint::from_be_bytes(&nonce_arr).modulo(&n);
            if k.is_zero() {
                continue;
            }

            let rp = scalar_mul(&k, &g)?;
            if rp.infinity {
                continue;
            }
            let r_bn = rp.x.modulo(&n);
            if r_bn.is_zero() {
                continue;
            }

            let rd = mod_mul(&r_bn, &d, &n);
            let e_plus_rd = e.add(&rd).modulo(&n);
            let k_inv = mod_inv(&k, &n)?;
            let s_bn = mod_mul(&k_inv, &e_plus_rd, &n);
            if s_bn.is_zero() {
                continue;
            }

            let mut r = [0_u8; 32];
            let mut s = [0_u8; 32];
            r.copy_from_slice(&r_bn.to_be_bytes_padded(32)?);
            s.copy_from_slice(&s_bn.to_be_bytes_padded(32)?);
            return Ok((r, s));
        }
        Err(Error::CryptoFailure(
            "p256 ecdsa nonce generation exhausted retry budget",
        ))
    }
}

impl Drop for P256PrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

impl P256PublicKey {
    /// Parses uncompressed SEC1 point bytes (`04 || X || Y`) and validates curve membership.
    ///
    /// # Arguments
    /// * `bytes`: SEC1 uncompressed public key bytes.
    ///
    /// # Returns
    /// Parsed and validated `P256PublicKey`.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidLength(
                "p256 uncompressed public key must be 65 bytes",
            ));
        }
        if bytes[0] != 0x04 {
            return Err(Error::ParseFailure(
                "p256 public key must be uncompressed SEC1 format",
            ));
        }
        let x = BigUint::from_be_bytes(&bytes[1..33]);
        let y = BigUint::from_be_bytes(&bytes[33..65]);
        let point = CurvePoint {
            x,
            y,
            infinity: false,
        };
        let key = Self { point };
        key.validate()?;
        Ok(key)
    }

    /// Encodes public point in uncompressed SEC1 format (`04 || X || Y`).
    ///
    /// # Arguments
    /// * `self`: Public key to encode.
    ///
    /// # Returns
    /// 65-byte uncompressed SEC1 encoding.
    pub fn to_uncompressed(&self) -> Result<[u8; 65]> {
        self.validate()?;
        let mut out = [0_u8; 65];
        out[0] = 0x04;
        let x = self.point.x.to_be_bytes_padded(32)?;
        let y = self.point.y.to_be_bytes_padded(32)?;
        out[1..33].copy_from_slice(&x);
        out[33..65].copy_from_slice(&y);
        Ok(out)
    }

    /// Validates public point for range checks and on-curve equation.
    ///
    /// # Arguments
    /// * `self`: Public key point to validate.
    ///
    /// # Returns
    /// `Ok(())` when the point is finite, in range, and on curve.
    pub fn validate(&self) -> Result<()> {
        if self.point.infinity {
            return Err(Error::CryptoFailure(
                "p256 public point at infinity is invalid",
            ));
        }
        let p = curve_modulus_p();
        if self.point.x.cmp(&p) != Ordering::Less || self.point.y.cmp(&p) != Ordering::Less {
            return Err(Error::CryptoFailure(
                "p256 public point coordinates out of field range",
            ));
        }
        if !is_point_on_curve(&self.point) {
            return Err(Error::CryptoFailure("p256 public point is not on curve"));
        }
        Ok(())
    }
}

/// Computes P-256 ECDH shared secret x-coordinate.
///
/// # Arguments
/// * `private_key`: Local private key for scalar multiplication.
/// * `peer_public_key`: Peer public key to validate and use.
///
/// # Returns
/// 32-byte shared secret from the resulting affine x-coordinate.
pub fn noxtls_p256_ecdh_shared_secret(
    private_key: &P256PrivateKey,
    peer_public_key: &P256PublicKey,
) -> Result<[u8; 32]> {
    private_key.diffie_hellman(peer_public_key)
}

/// Signs a message with P-256 ECDSA over SHA-256(message).
///
/// # Arguments
/// * `private_key`: Private key used for signing.
/// * `message`: Message bytes to hash and sign.
///
/// # Returns
/// Signature tuple `(r, s)` as 32-byte scalars.
pub fn noxtls_p256_ecdsa_sign_sha256(
    private_key: &P256PrivateKey,
    message: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    private_key.sign_sha256(message)
}

/// Signs a message with P-256 ECDSA over SHA-256(message) using DRBG-generated nonces.
///
/// # Arguments
/// * `private_key`: Private key used for signing.
/// * `message`: Message bytes to hash and sign.
/// * `drbg`: DRBG used to generate per-signature nonce candidates.
///
/// # Returns
/// Signature tuple `(r, s)` as 32-byte scalars.
pub fn noxtls_p256_ecdsa_sign_sha256_auto(
    private_key: &P256PrivateKey,
    message: &[u8],
    drbg: &mut HmacDrbgSha256,
) -> Result<([u8; 32], [u8; 32])> {
    private_key.sign_sha256_auto(message, drbg)
}

/// Signs a precomputed 32-byte digest with P-256 ECDSA.
///
/// # Arguments
/// * `private_key`: Private key used for signing.
/// * `digest`: Precomputed 32-byte digest.
///
/// # Returns
/// Signature tuple `(r, s)` as 32-byte scalars.
pub fn noxtls_p256_ecdsa_sign_digest(
    private_key: &P256PrivateKey,
    digest: &[u8; 32],
) -> Result<([u8; 32], [u8; 32])> {
    private_key.sign_digest(digest)
}

/// Signs a precomputed 32-byte digest with P-256 ECDSA using DRBG-generated nonces.
///
/// # Arguments
/// * `private_key`: Private key used for signing.
/// * `digest`: Precomputed 32-byte digest.
/// * `drbg`: DRBG used to generate per-signature nonce candidates.
///
/// # Returns
/// Signature tuple `(r, s)` as 32-byte scalars.
pub fn noxtls_p256_ecdsa_sign_digest_auto(
    private_key: &P256PrivateKey,
    digest: &[u8; 32],
    drbg: &mut HmacDrbgSha256,
) -> Result<([u8; 32], [u8; 32])> {
    private_key.sign_digest_auto(digest, drbg)
}

/// Verifies a P-256 ECDSA signature over SHA-256(message) using raw `(r, s)` values.
///
/// # Arguments
/// * `public_key`: Public key used for verification.
/// * `message`: Original message bytes.
/// * `r`: Signature `r` scalar in big-endian form.
/// * `s`: Signature `s` scalar in big-endian form.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_p256_ecdsa_verify_sha256(
    public_key: &P256PublicKey,
    message: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<()> {
    let digest = noxtls_sha256(message);
    noxtls_p256_ecdsa_verify_digest(public_key, &digest, r, s)
}

/// Verifies a P-256 ECDSA signature over a precomputed 32-byte digest.
///
/// # Arguments
/// * `public_key`: Public key used for verification.
/// * `digest`: Precomputed 32-byte digest.
/// * `r`: Signature `r` scalar in big-endian form.
/// * `s`: Signature `s` scalar in big-endian form.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_p256_ecdsa_verify_digest(
    public_key: &P256PublicKey,
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<()> {
    public_key.validate()?;

    let n = curve_order_n();
    if is_all_zero(r) || is_all_zero(s) {
        return Err(Error::CryptoFailure(
            "p256 ecdsa signature scalars must be non-zero",
        ));
    }
    let r_bn = BigUint::from_be_bytes(r);
    let s_bn = BigUint::from_be_bytes(s);
    if r_bn.cmp(&n) != Ordering::Less || s_bn.cmp(&n) != Ordering::Less {
        return Err(Error::CryptoFailure(
            "p256 ecdsa signature scalars out of range",
        ));
    }

    let e = BigUint::from_be_bytes(digest).modulo(&n);
    let w = mod_inv(&s_bn, &n)?;
    let u1 = mod_mul(&e, &w, &n);
    let u2 = mod_mul(&r_bn, &w, &n);

    let g = curve_base_point();
    let p1 = scalar_mul_jacobian(&u1, &g);
    let p2 = scalar_mul_jacobian(&u2, &public_key.point);
    let r_point = jacobian_add(&p1, &p2).to_affine()?;
    if r_point.infinity {
        return Err(Error::CryptoFailure(
            "p256 ecdsa verification produced point at infinity",
        ));
    }
    let v = r_point.x.modulo(&n);
    let v_bytes = v.to_be_bytes_padded(32)?;
    if ct_bytes_eq(v_bytes.as_slice(), r) {
        return Ok(());
    }
    Err(Error::CryptoFailure("p256 ecdsa verification failed"))
}

/// Generates a P-256 private key from DRBG output with bounded retry for scalar-range checks.
///
/// # Arguments
/// * `drbg`: DRBG instance used to fill private scalar candidate bytes.
///
/// # Returns
/// Parsed `P256PrivateKey` when a generated scalar is in the valid range `(0, n)`.
pub fn noxtls_p256_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<P256PrivateKey> {
    for _ in 0..64 {
        let scalar = drbg.generate(32, b"p256_private_scalar")?;
        let bytes: [u8; 32] = scalar
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidLength("p256 private scalar length mismatch"))?;
        if let Ok(key) = P256PrivateKey::from_bytes(bytes) {
            return Ok(key);
        }
    }
    Err(Error::CryptoFailure(
        "p256 private key generation exhausted retry budget",
    ))
}

/// Performs scalar multiplication by double-and-add in Jacobian coordinates. Parameters: `scalar` multiplier and `point` affine input point.
///
/// # Arguments
///
/// * `scalar` — `&BigUint`.
/// * `point` — `&CurvePoint`.
///
/// # Returns
///
/// On success, the `Ok` payload from `scalar_mul`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn scalar_mul(scalar: &BigUint, point: &CurvePoint) -> Result<CurvePoint> {
    scalar_mul_jacobian(scalar, point).to_affine()
}

/// Performs scalar multiplication and keeps result in Jacobian coordinates. Parameters: `scalar` multiplier and `point` affine input point.
///
/// # Arguments
///
/// * `scalar` — `&BigUint`.
/// * `point` — `&CurvePoint`.
///
/// # Returns
///
/// `JacobianPoint` produced by `scalar_mul_jacobian` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn scalar_mul_jacobian(scalar: &BigUint, point: &CurvePoint) -> JacobianPoint {
    if point.infinity {
        return JacobianPoint::infinity();
    }

    let base = JacobianPoint::from_affine(point);
    let table = precompute_nibble_window(&base);
    let mut acc = JacobianPoint::infinity();
    let bits = scalar.to_be_bytes();
    for byte in bits {
        let hi = usize::from(byte >> 4);
        for _ in 0..4 {
            acc = jacobian_double(&acc);
        }
        if hi != 0 {
            acc = jacobian_add(&acc, &table[hi]);
        }

        let lo = usize::from(byte & 0x0F);
        for _ in 0..4 {
            acc = jacobian_double(&acc);
        }
        if lo != 0 {
            acc = jacobian_add(&acc, &table[lo]);
        }
    }
    acc
}

/// Precomputes [0..15] * P table for nibble-window scalar multiplication.
///
/// # Arguments
///
/// * `base` — `&JacobianPoint`.
///
/// # Returns
///
/// `Vec<JacobianPoint>` produced by `precompute_nibble_window` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn precompute_nibble_window(base: &JacobianPoint) -> Vec<JacobianPoint> {
    let mut table = Vec::with_capacity(16);
    table.push(JacobianPoint::infinity());
    table.push(base.clone());
    for idx in 2..16 {
        let next = jacobian_add(&table[idx - 1], base);
        table.push(next);
    }
    table
}

/// Returns true when point satisfies secp256r1 equation over field modulus. Parameter: `point` affine candidate point.
///
/// # Arguments
///
/// * `point` — `&CurvePoint`.
///
/// # Returns
///
/// `bool` produced by `is_point_on_curve` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn is_point_on_curve(point: &CurvePoint) -> bool {
    if point.infinity {
        return false;
    }
    let p = curve_modulus_p();
    let a = curve_a();
    let b = curve_b();
    let y_sq = mod_mul(&point.y, &point.y, &p);
    let x_sq = mod_mul(&point.x, &point.x, &p);
    let x_cu = mod_mul(&x_sq, &point.x, &p);
    let ax = mod_mul(&a, &point.x, &p);
    let rhs = mod_add(&mod_add(&x_cu, &ax, &p), &b, &p);
    y_sq == rhs
}

impl CurvePoint {
    // Returns additive identity point representation.
    // Returns: affine infinity marker point.
    fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }
}

impl JacobianPoint {
    // Returns additive identity point representation.
    // Returns: Jacobian infinity marker point.
    fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            z: BigUint::zero(),
            infinity: true,
        }
    }

    // Converts an affine point into Jacobian representation.
    // Parameter: `point` affine input point to lift.
    fn from_affine(point: &CurvePoint) -> Self {
        if point.infinity {
            return Self::infinity();
        }
        Self {
            x: point.x.clone(),
            y: point.y.clone(),
            z: BigUint::one(),
            infinity: false,
        }
    }

    // Converts Jacobian point into affine representation with one modular inverse.
    // Parameter: `self` Jacobian point to convert.
    // Returns: affine point or infinity when projective point is at infinity.
    fn to_affine(&self) -> Result<CurvePoint> {
        if self.infinity || self.z.is_zero() {
            return Ok(CurvePoint::infinity());
        }
        let p = curve_modulus_p();
        let z_inv = mod_inv(&self.z, &p)?;
        let z_inv2 = mod_mul(&z_inv, &z_inv, &p);
        let z_inv3 = mod_mul(&z_inv2, &z_inv, &p);
        Ok(CurvePoint {
            x: mod_mul(&self.x, &z_inv2, &p),
            y: mod_mul(&self.y, &z_inv3, &p),
            infinity: false,
        })
    }
}

/// Doubles a Jacobian point using secp256r1 a=-3 formulas. Parameter: `a` Jacobian point to double.
///
/// # Arguments
///
/// * `a` — `&JacobianPoint`.
///
/// # Returns
///
/// `JacobianPoint` produced by `jacobian_double` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn jacobian_double(a: &JacobianPoint) -> JacobianPoint {
    if a.infinity || a.y.is_zero() {
        return JacobianPoint::infinity();
    }
    let p = curve_modulus_p();
    let two = BigUint::from_u128(2);
    let three = BigUint::from_u128(3);
    let four = BigUint::from_u128(4);
    let eight = BigUint::from_u128(8);

    let yy = mod_mul(&a.y, &a.y, &p);
    let yyyy = mod_mul(&yy, &yy, &p);
    let x_yy = mod_mul(&a.x, &yy, &p);
    let s = mod_mul(&x_yy, &four, &p);

    let zz = mod_mul(&a.z, &a.z, &p);
    let x_minus_zz = mod_sub(&a.x, &zz, &p);
    let x_plus_zz = mod_add(&a.x, &zz, &p);
    let m_term = mod_mul(&x_minus_zz, &x_plus_zz, &p);
    let m = mod_mul(&m_term, &three, &p);

    let m2 = mod_mul(&m, &m, &p);
    let two_s = mod_mul(&s, &two, &p);
    let x3 = mod_sub(&m2, &two_s, &p);
    let s_minus_x3 = mod_sub(&s, &x3, &p);
    let m_s_minus_x3 = mod_mul(&m, &s_minus_x3, &p);
    let eight_yyyy = mod_mul(&yyyy, &eight, &p);
    let y3 = mod_sub(&m_s_minus_x3, &eight_yyyy, &p);
    let yz = mod_mul(&a.y, &a.z, &p);
    let z3 = mod_mul(&yz, &two, &p);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

/// Adds two Jacobian points using complete formulas with exceptional-case handling. Parameters: `a` and `b` Jacobian input points.
///
/// # Arguments
///
/// * `a` — `&JacobianPoint`.
/// * `b` — `&JacobianPoint`.
///
/// # Returns
///
/// `JacobianPoint` produced by `jacobian_add` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn jacobian_add(a: &JacobianPoint, b: &JacobianPoint) -> JacobianPoint {
    if a.infinity {
        return b.clone();
    }
    if b.infinity {
        return a.clone();
    }

    let p = curve_modulus_p();
    let two = BigUint::from_u128(2);

    let z1z1 = mod_mul(&a.z, &a.z, &p);
    let z2z2 = mod_mul(&b.z, &b.z, &p);
    let u1 = mod_mul(&a.x, &z2z2, &p);
    let u2 = mod_mul(&b.x, &z1z1, &p);

    let z1_cubed = mod_mul(&z1z1, &a.z, &p);
    let z2_cubed = mod_mul(&z2z2, &b.z, &p);
    let s1 = mod_mul(&a.y, &z2_cubed, &p);
    let s2 = mod_mul(&b.y, &z1_cubed, &p);

    if u1 == u2 {
        if s1 != s2 {
            return JacobianPoint::infinity();
        }
        return jacobian_double(a);
    }

    let h = mod_sub(&u2, &u1, &p);
    let two_h = mod_mul(&h, &two, &p);
    let i = mod_mul(&two_h, &two_h, &p);
    let j = mod_mul(&h, &i, &p);
    let s2_minus_s1 = mod_sub(&s2, &s1, &p);
    let r = mod_mul(&s2_minus_s1, &two, &p);
    let v = mod_mul(&u1, &i, &p);

    let r2 = mod_mul(&r, &r, &p);
    let two_v = mod_mul(&v, &two, &p);
    let x3 = mod_sub(&mod_sub(&r2, &j, &p), &two_v, &p);

    let v_minus_x3 = mod_sub(&v, &x3, &p);
    let r_v_minus_x3 = mod_mul(&r, &v_minus_x3, &p);
    let two_s1 = mod_mul(&s1, &two, &p);
    let two_s1_j = mod_mul(&two_s1, &j, &p);
    let y3 = mod_sub(&r_v_minus_x3, &two_s1_j, &p);

    let z1_plus_z2 = mod_add(&a.z, &b.z, &p);
    let z1_plus_z2_sq = mod_mul(&z1_plus_z2, &z1_plus_z2, &p);
    let z_sum = mod_sub(&mod_sub(&z1_plus_z2_sq, &z1z1, &p), &z2z2, &p);
    let z3 = mod_mul(&z_sum, &h, &p);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

/// Computes `(a + b) mod m`. Parameters: operands `a`, `b`, and modulus `m`.
///
/// # Arguments
///
/// * `a` — `&BigUint`.
/// * `b` — `&BigUint`.
/// * `m` — `&BigUint`.
///
/// # Returns
///
/// `BigUint` produced by `mod_add` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_add(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    a.add(b).modulo(m)
}

/// Computes `(a - b) mod m`. Parameters: operands `a`, `b`, and modulus `m`.
///
/// # Arguments
///
/// * `a` — `&BigUint`.
/// * `b` — `&BigUint`.
/// * `m` — `&BigUint`.
///
/// # Returns
///
/// `BigUint` produced by `mod_sub` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    if a.cmp(b) != Ordering::Less {
        a.sub(b).modulo(m)
    } else {
        m.sub(&b.sub(a)).modulo(m)
    }
}

/// Computes `(a * b) mod m`. Parameters: operands `a`, `b`, and modulus `m`.
///
/// # Arguments
///
/// * `a` — `&BigUint`.
/// * `b` — `&BigUint`.
/// * `m` — `&BigUint`.
///
/// # Returns
///
/// `BigUint` produced by `mod_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_mul(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    a.mul(b).modulo(m)
}

/// Computes multiplicative inverse via Fermat's little theorem for prime modulus. Parameters: `a` value to invert and `m` prime modulus.
///
/// # Arguments
///
/// * `a` — `&BigUint`.
/// * `m` — `&BigUint`.
///
/// # Returns
///
/// On success, the `Ok` payload from `mod_inv`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_inv(a: &BigUint, m: &BigUint) -> Result<BigUint> {
    if a.is_zero() {
        return Err(Error::CryptoFailure(
            "p256 modular inverse of zero is undefined",
        ));
    }
    let two = BigUint::from_u128(2);
    let exp = m.sub(&two);
    Ok(BigUint::mod_exp(a, &exp, m))
}

/// Returns secp256r1 field modulus p. Returns: prime field modulus as `BigUint`.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `BigUint` produced by `curve_modulus_p` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn curve_modulus_p() -> BigUint {
    BigUint::from_be_bytes(&[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ])
}

/// Returns secp256r1 curve coefficient a. Returns: curve `a` coefficient as `BigUint`.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `BigUint` produced by `curve_a` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn curve_a() -> BigUint {
    BigUint::from_be_bytes(&[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfc,
    ])
}

/// Returns secp256r1 curve coefficient b. Returns: curve `b` coefficient as `BigUint`.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `BigUint` produced by `curve_b` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn curve_b() -> BigUint {
    BigUint::from_be_bytes(&[
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86,
        0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2,
        0x60, 0x4b,
    ])
}

/// Returns secp256r1 subgroup order n. Returns: subgroup order as `BigUint`.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `BigUint` produced by `curve_order_n` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn curve_order_n() -> BigUint {
    BigUint::from_be_bytes(&[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ])
}

/// Returns secp256r1 base point G. Returns: affine base point coordinates.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// `CurvePoint` produced by `curve_base_point` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn curve_base_point() -> CurvePoint {
    CurvePoint {
        x: BigUint::from_be_bytes(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ]),
        y: BigUint::from_be_bytes(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ]),
        infinity: false,
    }
}

/// Returns true if every byte in the 32-byte input is zero. Parameter: `bytes` candidate secret bytes.
///
/// # Arguments
///
/// * `bytes` — `&[u8; 32]`.
///
/// # Returns
///
/// `bool` produced by `is_all_zero` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn is_all_zero(bytes: &[u8; 32]) -> bool {
    let mut acc = 0_u8;
    for byte in bytes {
        acc |= *byte;
    }
    acc == 0
}

/// Compares two byte slices in constant-time when lengths are equal. Parameters: `left` and `right` byte slices to compare.
///
/// # Arguments
///
/// * `left` — `&[u8]`.
/// * `right` — `&[u8]`.
///
/// # Returns
///
/// `bool` produced by `ct_bytes_eq` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ct_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&l, &r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

/// Derives a deterministic per-signature nonce candidate from key scalar, digest, and counter. Parameters: `private_scalar` signer key, `digest` message hash, and `counter` retry index.
///
/// # Arguments
///
/// * `private_scalar` — `&BigUint`.
/// * `digest` — `&[u8; 32]`.
/// * `counter` — `u32`.
///
/// # Returns
///
/// `BigUint` produced by `derive_signing_nonce` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn derive_signing_nonce(private_scalar: &BigUint, digest: &[u8; 32], counter: u32) -> BigUint {
    let mut seed = Vec::with_capacity(68);
    let scalar_bytes = private_scalar
        .to_be_bytes_padded(32)
        .expect("p256 private scalar should fit in 32 bytes");
    seed.extend_from_slice(&scalar_bytes);
    seed.extend_from_slice(digest);
    seed.extend_from_slice(&counter.to_be_bytes());
    BigUint::from_be_bytes(&noxtls_sha256(&seed))
}

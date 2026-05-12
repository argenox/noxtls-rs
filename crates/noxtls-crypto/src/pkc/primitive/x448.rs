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

#[cfg(feature = "hazardous-legacy-crypto")]
use crate::drbg::HmacDrbgSha256;
use noxtls_core::{Error, Result};

const X448_SIZE: usize = 56;
#[cfg(not(feature = "hazardous-legacy-crypto"))]
const X448_DISABLED_MESSAGE: &str =
    "x448 operations are disabled by default; enable `hazardous-legacy-crypto` to use x448";

/// Represents an X448 private scalar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X448PrivateKey {
    scalar: [u8; X448_SIZE],
}

/// Represents an X448 public key (Montgomery u-coordinate).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct X448PublicKey {
    pub bytes: [u8; X448_SIZE],
}

impl X448PrivateKey {
    /// Creates a private key from raw scalar bytes.
    ///
    /// # Arguments
    /// * `bytes`: Raw 56-byte private scalar prior to RFC 7748 clamping.
    ///
    /// # Returns
    /// `X448PrivateKey` wrapping the provided scalar bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X448_SIZE]) -> Self {
        Self { scalar: bytes }
    }

    /// Returns the raw 56-byte private scalar bytes.
    ///
    /// # Arguments
    /// * `self`: Private key whose scalar bytes should be copied.
    ///
    /// # Returns
    /// Raw private scalar octets as stored in this key.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X448_SIZE] {
        self.scalar
    }

    /// Clears private scalar bytes in place.
    ///
    /// # Arguments
    /// * `self` — Private key whose scalar buffer is scrubbed.
    ///
    /// # Returns
    /// `()`; all scalar bytes are reset to zero.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        self.scalar.fill(0);
    }

    /// Returns the clamped private scalar bytes.
    ///
    /// # Arguments
    /// * `self`: Private key whose scalar should be clamped for ladder use.
    ///
    /// # Returns
    /// RFC 7748-clamped scalar bytes.
    #[must_use]
    pub fn clamped_scalar(&self) -> [u8; X448_SIZE] {
        clamp_scalar(self.scalar)
    }

    /// Computes the corresponding public key from Curve448 basepoint.
    ///
    /// # Arguments
    /// * `self`: Private key used for scalar multiplication with basepoint.
    ///
    /// # Returns
    /// Derived X448 public key bytes.
    #[cfg(feature = "hazardous-legacy-crypto")]
    #[must_use]
    pub fn public_key(&self) -> X448PublicKey {
        X448PublicKey {
            bytes: x448_basepoint(&self.scalar),
        }
    }

    /// Performs ECDH with a peer public key and returns shared secret bytes.
    ///
    /// # Arguments
    /// * `self`: Local private key.
    /// * `peer`: Peer public key bytes.
    ///
    /// # Returns
    /// 56-byte shared secret result from X448 scalar multiplication.
    #[cfg(feature = "hazardous-legacy-crypto")]
    #[must_use]
    pub fn diffie_hellman(&self, peer: X448PublicKey) -> [u8; X448_SIZE] {
        x448(&self.scalar, &peer.bytes)
    }

    /// Performs checked ECDH and rejects invalid/weak peer keys and zero shared outputs.
    ///
    /// # Arguments
    /// * `self`: Local private key.
    /// * `peer`: Peer public key to validate and use.
    ///
    /// # Returns
    /// Shared secret when peer validation succeeds and output is non-zero.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`X448PublicKey::validate`], or [`Error::CryptoFailure`] when the derived shared secret is all-zero.
    pub fn diffie_hellman_checked(&self, peer: X448PublicKey) -> Result<[u8; X448_SIZE]> {
        #[cfg(not(feature = "hazardous-legacy-crypto"))]
        {
            let _ = peer;
            Err(Error::StateError(X448_DISABLED_MESSAGE))
        }
        #[cfg(feature = "hazardous-legacy-crypto")]
        {
            peer.validate()?;
            let shared = self.diffie_hellman(peer);
            if is_all_zero(&shared) {
                return Err(Error::CryptoFailure("x448 shared secret is all-zero"));
            }
            Ok(shared)
        }
    }
}

impl Drop for X448PrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

impl X448PublicKey {
    /// Creates a public key from raw bytes.
    ///
    /// # Arguments
    /// * `bytes`: Raw 56-byte Montgomery u-coordinate.
    ///
    /// # Returns
    /// `X448PublicKey` wrapping the provided bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X448_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns true when raw public-key bytes are all-zero.
    ///
    /// # Arguments
    /// * `self`: Public key bytes to inspect.
    ///
    /// # Returns
    /// `true` when all 56 bytes are zero.
    #[must_use]
    pub fn is_all_zero(self) -> bool {
        is_all_zero(&self.bytes)
    }

    /// Validates peer public key for baseline X448 safety checks.
    ///
    /// # Arguments
    /// * `self`: Peer public key candidate to validate.
    ///
    /// # Returns
    /// `Ok(())` when key is not one of the rejected low-order encodings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoFailure`] when the u-coordinate is all-zero or equals one (low-order points).
    pub fn validate(self) -> Result<()> {
        if is_all_zero(&self.bytes) {
            return Err(Error::CryptoFailure(
                "x448 peer public key is low-order (zero)",
            ));
        }
        if is_montgomery_u_one(&self.bytes) {
            return Err(Error::CryptoFailure(
                "x448 peer public key is low-order (u=1)",
            ));
        }
        Ok(())
    }
}

/// Computes X448 scalar multiplication over arbitrary u-coordinate.
///
/// # Arguments
/// * `scalar`: Private scalar bytes (clamped internally).
/// * `u`: Peer Montgomery u-coordinate bytes.
///
/// # Returns
/// 56-byte X448 scalar multiplication output.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn x448(scalar: &[u8; X448_SIZE], u: &[u8; X448_SIZE]) -> [u8; X448_SIZE] {
    let k = clamp_scalar(*scalar);
    let x1 = FieldElement448::from_bytes(u);
    let mut x2 = FieldElement448::one();
    let mut z2 = FieldElement448::zero();
    let mut x3 = x1;
    let mut z3 = FieldElement448::one();
    let mut swap = 0_u8;

    for t in (0..448).rev() {
        let k_t = (k[t / 8] >> (t & 7)) & 1;
        swap ^= k_t;
        FieldElement448::cswap(&mut x2, &mut x3, swap);
        FieldElement448::cswap(&mut z2, &mut z3, swap);
        swap = k_t;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let da_plus_cb = da.add(&cb);
        let da_minus_cb = da.sub(&cb);

        x3 = da_plus_cb.square();
        z3 = x1.mul(&da_minus_cb.square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(39081)));
    }

    FieldElement448::cswap(&mut x2, &mut x3, swap);
    FieldElement448::cswap(&mut z2, &mut z3, swap);
    x2.mul(&z2.invert()).to_bytes()
}

/// Computes X448 scalar multiplication against standard basepoint.
///
/// # Arguments
/// * `scalar`: Private scalar bytes (clamped internally).
///
/// # Returns
/// 56-byte public key u-coordinate for the Curve448 basepoint.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn x448_basepoint(scalar: &[u8; X448_SIZE]) -> [u8; X448_SIZE] {
    let mut basepoint = [0_u8; X448_SIZE];
    basepoint[0] = 5;
    x448(scalar, &basepoint)
}

/// Computes X448 shared secret and validates non-zero output.
///
/// # Arguments
/// * `private_key`: Local private key used for key agreement.
/// * `peer_public_key`: Peer public key to validate and use.
///
/// # Returns
/// Shared secret when peer key and output pass safety checks.
///
/// # Errors
///
/// Forwards errors from [`X448PrivateKey::diffie_hellman_checked`].
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn x448_shared_secret(
    private_key: X448PrivateKey,
    peer_public_key: X448PublicKey,
) -> Result<[u8; X448_SIZE]> {
    private_key.diffie_hellman_checked(peer_public_key)
}

/// Generates an X448 private key from DRBG output.
///
/// # Arguments
/// * `drbg`: DRBG instance used to fill private scalar bytes.
///
/// # Returns
/// X448 private key containing DRBG-derived scalar bytes.
///
/// # Errors
///
/// Returns DRBG errors from [`HmacDrbgSha256::generate`], or [`Error::InvalidLength`] if the DRBG output is not exactly `X448_SIZE` bytes.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn x448_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<X448PrivateKey> {
    let scalar = drbg.generate(X448_SIZE, b"x448_private_scalar")?;
    let bytes: [u8; X448_SIZE] = scalar
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidLength("x448 private scalar length mismatch"))?;
    Ok(X448PrivateKey::from_bytes(bytes))
}

/// Clamps a raw Curve448 scalar according to RFC 7748 bit clearing and setting rules.
///
/// # Arguments
///
/// * `scalar` — Raw 56-byte scalar before masking.
///
/// # Returns
///
/// Clamped scalar bytes suitable for the Montgomery ladder.
///
/// # Panics
///
/// This function does not panic.
fn clamp_scalar(mut scalar: [u8; X448_SIZE]) -> [u8; X448_SIZE] {
    scalar[0] &= 252;
    scalar[55] |= 128;
    scalar
}

#[cfg(feature = "hazardous-legacy-crypto")]
const MASK56: u64 = (1_u64 << 56) - 1;
#[cfg(feature = "hazardous-legacy-crypto")]
const MODULUS_LIMBS: [u64; 8] = [
    MASK56,
    MASK56,
    MASK56,
    MASK56,
    MASK56 - 1,
    MASK56,
    MASK56,
    MASK56,
];

#[cfg(feature = "hazardous-legacy-crypto")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FieldElement448([u64; 8]);

#[cfg(feature = "hazardous-legacy-crypto")]
impl FieldElement448 {
    /// Returns the additive identity in the Curve448 base field representation.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This helper takes no parameters.
    ///
    /// # Returns
    ///
    /// Field element with all limbs set to zero.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn zero() -> Self {
        Self([0; 8])
    }

    /// Returns the multiplicative identity in the Curve448 base field representation.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This helper takes no parameters.
    ///
    /// # Returns
    ///
    /// Field element equal to one.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Decodes a 56-byte little-endian field encoding into eight 56-bit limbs.
    ///
    /// # Arguments
    ///
    /// * `input` — Curve448 u-coordinate or intermediate field bytes.
    ///
    /// # Returns
    ///
    /// Field element reduced modulo `p = 2^448 - 2^224 - 1`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn from_bytes(input: &[u8; X448_SIZE]) -> Self {
        let mut limbs = [0_u64; 8];
        for (idx, limb) in limbs.iter_mut().enumerate() {
            let start = idx * 7;
            let mut value = 0_u64;
            for byte in 0..7 {
                value |= u64::from(input[start + byte]) << (byte * 8);
            }
            *limb = value & MASK56;
        }
        Self(limbs).carry_reduce()
    }

    /// Encodes a normalized field element into a little-endian 56-byte string.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element to canonicalize and encode.
    ///
    /// # Returns
    ///
    /// Canonical 56-byte output suitable for X448 wire representation.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn to_bytes(self) -> [u8; X448_SIZE] {
        let normalized = self.normalize();
        let mut out = [0_u8; X448_SIZE];
        for (idx, limb) in normalized.0.iter().enumerate() {
            let start = idx * 7;
            for byte in 0..7 {
                out[start + byte] = ((limb >> (byte * 8)) & 0xff) as u8;
            }
        }
        out
    }

    /// Adds two field elements modulo Curve448 prime `p`.
    ///
    /// # Arguments
    ///
    /// * `self` — Left operand.
    /// * `rhs` — Right operand.
    ///
    /// # Returns
    ///
    /// Reduced sum `(self + rhs) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn add(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 8];
        for (idx, item) in out.iter_mut().enumerate() {
            *item = self.0[idx].wrapping_add(rhs.0[idx]);
        }
        Self(out).carry_reduce()
    }

    /// Subtracts two field elements modulo Curve448 prime `p`.
    ///
    /// # Arguments
    ///
    /// * `self` — Minuend.
    /// * `rhs` — Subtrahend.
    ///
    /// # Returns
    ///
    /// Reduced difference `(self - rhs) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn sub(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 8];
        for (idx, item) in out.iter_mut().enumerate() {
            let lhs = i128::from(self.0[idx]) + i128::from(MODULUS_LIMBS[idx]) * 2;
            let rhs_value = i128::from(rhs.0[idx]);
            *item = (lhs - rhs_value) as u64;
        }
        Self(out).carry_reduce()
    }

    /// Multiplies a field element by a small scalar and reduces modulo `p`.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element to scale.
    /// * `scalar` — Small integer multiplier.
    ///
    /// # Returns
    ///
    /// Reduced product `(self * scalar) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn mul_small(&self, scalar: u64) -> Self {
        let mut wide = [0_u128; 16];
        for (idx, limb) in self.0.iter().enumerate() {
            wide[idx] = u128::from(*limb) * u128::from(scalar);
        }
        Self::reduce_wide(wide)
    }

    /// Multiplies two field elements modulo Curve448 prime `p`.
    ///
    /// # Arguments
    ///
    /// * `self` — Left operand.
    /// * `rhs` — Right operand.
    ///
    /// # Returns
    ///
    /// Reduced product `(self * rhs) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn mul(&self, rhs: &Self) -> Self {
        let mut wide = [0_u128; 16];
        for i in 0..8 {
            for j in 0..8 {
                wide[i + j] =
                    wide[i + j].wrapping_add(u128::from(self.0[i]) * u128::from(rhs.0[j]));
            }
        }
        Self::reduce_wide(wide)
    }

    /// Squares a field element modulo Curve448 prime `p`.
    ///
    /// # Arguments
    ///
    /// * `self` — Operand to square.
    ///
    /// # Returns
    ///
    /// Reduced square `(self * self) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn square(&self) -> Self {
        self.mul(self)
    }

    /// Computes multiplicative inverse by fixed-exponent exponentiation.
    ///
    /// # Arguments
    ///
    /// * `self` — Non-zero field element to invert.
    ///
    /// # Returns
    ///
    /// Multiplicative inverse `self^(p-2) mod p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn invert(&self) -> Self {
        let mut result = Self::one();
        for bit in (0..448).rev() {
            result = result.square();
            if bit != 224 && bit != 1 {
                result = result.mul(self);
            }
        }
        result
    }

    /// Conditionally swaps two field elements in constant-time style.
    ///
    /// # Arguments
    ///
    /// * `a` — First value to potentially swap.
    /// * `b` — Second value to potentially swap.
    /// * `choice` — Swap control bit (`1` swaps, `0` keeps order).
    ///
    /// # Returns
    ///
    /// `()`; values are modified in place.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn cswap(a: &mut Self, b: &mut Self, choice: u8) {
        let mask = 0_u64.wrapping_sub(u64::from(choice & 1));
        for idx in 0..8 {
            let temp = mask & (a.0[idx] ^ b.0[idx]);
            a.0[idx] ^= temp;
            b.0[idx] ^= temp;
        }
    }

    /// Reduces a 16-limb product into Curve448 field representation.
    ///
    /// # Arguments
    ///
    /// * `wide` — Wide base-`2^56` product limbs.
    ///
    /// # Returns
    ///
    /// Reduced field element modulo `p`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn reduce_wide(mut wide: [u128; 16]) -> Self {
        for idx in (8..16).rev() {
            let value = wide[idx];
            wide[idx] = 0;
            wide[idx - 8] = wide[idx - 8].wrapping_add(value);
            wide[idx - 4] = wide[idx - 4].wrapping_add(value);
        }
        for idx in (8..12).rev() {
            let value = wide[idx];
            wide[idx] = 0;
            wide[idx - 8] = wide[idx - 8].wrapping_add(value);
            wide[idx - 4] = wide[idx - 4].wrapping_add(value);
        }

        let mut limbs = [0_u128; 8];
        limbs.copy_from_slice(&wide[..8]);
        for _ in 0..4 {
            let mut carry = 0_u128;
            for item in limbs.iter_mut().take(8) {
                let value = item.wrapping_add(carry);
                *item = value & u128::from(MASK56);
                carry = value >> 56;
            }
            limbs[0] = limbs[0].wrapping_add(carry);
            limbs[4] = limbs[4].wrapping_add(carry);
        }

        let mut out = [0_u64; 8];
        for (idx, item) in out.iter_mut().enumerate() {
            *item = (limbs[idx] & u128::from(MASK56)) as u64;
        }
        Self(out).carry_reduce()
    }

    /// Propagates carries across 56-bit limbs and folds top carry via `2^448 = 2^224 + 1`.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element with potentially oversized limbs.
    ///
    /// # Returns
    ///
    /// Partially reduced field element.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn carry_reduce(self) -> Self {
        let mut limbs = self.0;
        for _ in 0..2 {
            let mut carry = 0_u64;
            for item in limbs.iter_mut().take(8) {
                let value = item.wrapping_add(carry);
                *item = value & MASK56;
                carry = value >> 56;
            }
            limbs[0] = limbs[0].wrapping_add(carry);
            limbs[4] = limbs[4].wrapping_add(carry);
        }
        for item in limbs.iter_mut().take(8) {
            *item &= MASK56;
        }
        Self(limbs)
    }

    /// Canonicalizes a reduced field element into the unique representative in `[0, p)`.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element after carry reduction.
    ///
    /// # Returns
    ///
    /// Canonical field element for serialization.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn normalize(self) -> Self {
        let reduced = self.carry_reduce();
        let mut sub = [0_u64; 8];
        let mut borrow = 0_i128;
        for idx in 0..8 {
            let diff = i128::from(reduced.0[idx]) - i128::from(MODULUS_LIMBS[idx]) - borrow;
            borrow = (diff >> 127) & 1;
            sub[idx] = (diff + (borrow << 56)) as u64 & MASK56;
        }
        let use_sub = (borrow ^ 1) as u64;
        let mask = 0_u64.wrapping_sub(use_sub);
        let mut out = [0_u64; 8];
        for idx in 0..8 {
            out[idx] = (reduced.0[idx] & !mask) | (sub[idx] & mask);
        }
        Self(out)
    }
}

/// Returns `true` when every byte in the 56-byte array is zero.
///
/// # Arguments
///
/// * `bytes` — Fixed-size buffer to OR-fold.
///
/// # Returns
///
/// `true` if all bytes are zero.
///
/// # Panics
///
/// This function does not panic.
fn is_all_zero(bytes: &[u8; X448_SIZE]) -> bool {
    let mut acc = 0_u8;
    for byte in bytes {
        acc |= *byte;
    }
    acc == 0
}

/// Returns `true` when the little-endian Montgomery u-coordinate equals one.
///
/// # Arguments
///
/// * `bytes` — 56-byte u-coordinate in wire order.
///
/// # Returns
///
/// `true` when `bytes` encodes the integer one.
///
/// # Panics
///
/// This function does not panic.
fn is_montgomery_u_one(bytes: &[u8; X448_SIZE]) -> bool {
    bytes[0] == 1 && bytes[1..].iter().all(|byte| *byte == 0)
}

#[cfg(all(test, feature = "hazardous-legacy-crypto"))]
mod tests {
    use super::{x448, X448_SIZE};

    /// Decodes fixed-length hexadecimal into a 56-byte array.
    ///
    /// # Arguments
    ///
    /// * `hex` — Lowercase hexadecimal string expected to encode exactly 56 bytes.
    ///
    /// # Returns
    ///
    /// 56-byte decoded array for use in X448 known-answer tests.
    ///
    /// # Panics
    ///
    /// Panics if `hex` length is not exactly 112 characters or contains invalid hex digits.
    fn decode_hex_56(hex: &str) -> [u8; X448_SIZE] {
        assert_eq!(hex.len(), X448_SIZE * 2);
        let mut out = [0_u8; X448_SIZE];
        for idx in 0..X448_SIZE {
            let byte = u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16)
                .expect("hex test vector must be valid");
            out[idx] = byte;
        }
        out
    }

    /// Validates the RFC 7748 X448 one-shot shared-secret known-answer test.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This test takes no parameters.
    ///
    /// # Returns
    ///
    /// `()`; assertions pass when computed shared secret matches the RFC vector.
    ///
    /// # Panics
    ///
    /// Panics if the implementation output differs from the expected RFC 7748 value.
    #[test]
    fn x448_rfc7748_shared_secret_kat() {
        let alice_private = decode_hex_56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let bob_private = decode_hex_56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let alice_public_expected = decode_hex_56(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let bob_public_expected = decode_hex_56(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        let shared_expected = decode_hex_56(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );

        let mut basepoint = [0_u8; X448_SIZE];
        basepoint[0] = 5;
        let alice_public = x448(&alice_private, &basepoint);
        let bob_public = x448(&bob_private, &basepoint);
        assert_eq!(alice_public, alice_public_expected);
        assert_eq!(bob_public, bob_public_expected);
        let shared_ab = x448(&alice_private, &bob_public);
        let shared_ba = x448(&bob_private, &alice_public);

        assert_eq!(shared_ab, shared_expected);
        assert_eq!(shared_ba, shared_expected);
    }

    /// Validates an additional RFC 7748 fixed scalar-point test vector.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This test takes no parameters.
    ///
    /// # Returns
    ///
    /// `()`; assertions pass when scalar multiplication matches the RFC fixed vector.
    ///
    /// # Panics
    ///
    /// Panics if the computed scalar multiplication output differs from the expected value.
    #[test]
    fn x448_rfc7748_fixed_vector_kat() {
        let scalar = decode_hex_56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let point = decode_hex_56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let expected = decode_hex_56(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        );

        assert_eq!(x448(&scalar, &point), expected);
    }
}

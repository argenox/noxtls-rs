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

use crate::drbg::HmacDrbgSha256;
use noxtls_core::{Error, Result};

const MASK51: u64 = (1_u64 << 51) - 1;
const P: [u64; 5] = [
    (1_u64 << 51) - 19,
    (1_u64 << 51) - 1,
    (1_u64 << 51) - 1,
    (1_u64 << 51) - 1,
    (1_u64 << 51) - 1,
];

/// Represents an X25519 private scalar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X25519PrivateKey {
    scalar: [u8; 32],
}

/// Represents an X25519 public key (Montgomery u-coordinate).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct X25519PublicKey {
    pub bytes: [u8; 32],
}

impl X25519PrivateKey {
    /// Creates a private key from raw scalar bytes.
    ///
    /// # Arguments
    /// * `bytes`: Raw 32-byte private scalar prior to RFC 7748 clamping.
    ///
    /// # Returns
    /// `X25519PrivateKey` wrapping the provided scalar bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { scalar: bytes }
    }

    /// Returns the raw 32-byte private scalar bytes.
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
    pub fn to_bytes(&self) -> [u8; 32] {
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
    pub fn clamped_scalar(&self) -> [u8; 32] {
        clamp_scalar(self.scalar)
    }

    /// Computes the corresponding public key from Curve25519 basepoint.
    ///
    /// # Arguments
    /// * `self`: Private key used for scalar multiplication with basepoint.
    ///
    /// # Returns
    /// Derived X25519 public key bytes.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            bytes: noxtls_x25519_basepoint(&self.scalar),
        }
    }

    /// Performs ECDH with a peer public key and returns shared secret bytes.
    ///
    /// # Arguments
    /// * `self`: Local private key.
    /// * `peer`: Peer public key bytes.
    ///
    /// # Returns
    /// 32-byte shared secret result from X25519 scalar multiplication.
    #[must_use]
    pub fn diffie_hellman(&self, peer: X25519PublicKey) -> [u8; 32] {
        noxtls_x25519(&self.scalar, &peer.bytes)
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
    /// Returns the same errors as [`X25519PublicKey::validate`], or [`Error::CryptoFailure`] when the derived shared secret is all-zero.
    pub fn diffie_hellman_checked(&self, peer: X25519PublicKey) -> Result<[u8; 32]> {
        peer.validate()?;
        let shared = self.diffie_hellman(peer);
        if is_all_zero(&shared) {
            return Err(Error::CryptoFailure("noxtls_x25519 shared secret is all-zero"));
        }
        Ok(shared)
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

impl X25519PublicKey {
    /// Creates a public key from raw bytes.
    ///
    /// # Arguments
    /// * `bytes`: Raw 32-byte Montgomery u-coordinate.
    ///
    /// # Returns
    /// `X25519PublicKey` wrapping the provided bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns true when raw public-key bytes are all-zero.
    ///
    /// # Arguments
    /// * `self`: Public key bytes to inspect.
    ///
    /// # Returns
    /// `true` when all 32 bytes are zero.
    #[must_use]
    pub fn is_all_zero(self) -> bool {
        is_all_zero(&self.bytes)
    }

    /// Validates peer public key for baseline X25519 safety checks.
    ///
    /// # Arguments
    /// * `self`: Peer public key candidate to validate.
    ///
    /// # Returns
    /// `Ok(())` when key is not one of the rejected low-order encodings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoFailure`] when the RFC 7748 masked u-coordinate is all-zero or equal to one (low-order points).
    pub fn validate(self) -> Result<()> {
        let masked = self.masked_u_coordinate();
        if is_all_zero(&masked) {
            return Err(Error::CryptoFailure(
                "noxtls_x25519 peer public key is low-order (masked zero)",
            ));
        }
        if is_montgomery_u_one(&masked) {
            return Err(Error::CryptoFailure(
                "noxtls_x25519 peer public key is low-order (u=1)",
            ));
        }
        Ok(())
    }

    /// Returns the peer u-coordinate with RFC 7748 high-bit masking applied.
    ///
    /// # Arguments
    ///
    /// * `self` — Public key bytes to copy and mask.
    ///
    /// # Returns
    ///
    /// 32-byte masked Montgomery u-coordinate.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn masked_u_coordinate(self) -> [u8; 32] {
        let mut masked = self.bytes;
        masked[31] &= 0x7f;
        masked
    }
}

/// Computes X25519 scalar multiplication over arbitrary u-coordinate.
///
/// # Arguments
/// * `scalar`: Private scalar bytes (clamped internally).
/// * `u`: Peer Montgomery u-coordinate bytes.
///
/// # Returns
/// 32-byte X25519 scalar multiplication output.
#[must_use]
pub fn noxtls_x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = clamp_scalar(*scalar);
    let mut u_masked = *u;
    u_masked[31] &= 0x7f;
    let x1 = FieldElement::from_bytes(&u_masked);

    let mut x2 = FieldElement::one();
    let mut z2 = FieldElement::zero();
    let mut x3 = x1;
    let mut z3 = FieldElement::one();
    let mut swap = 0_u8;

    for t in (0..255).rev() {
        let k_t = (k[t / 8] >> (t & 7)) & 1;
        swap ^= k_t;
        FieldElement::cswap(&mut x2, &mut x3, swap);
        FieldElement::cswap(&mut z2, &mut z3, swap);
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
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121665)));
    }

    FieldElement::cswap(&mut x2, &mut x3, swap);
    FieldElement::cswap(&mut z2, &mut z3, swap);

    x2.mul(&z2.invert()).to_bytes()
}

/// Computes X25519 scalar multiplication against standard basepoint.
///
/// # Arguments
/// * `scalar`: Private scalar bytes (clamped internally).
///
/// # Returns
/// 32-byte public key u-coordinate for the Curve25519 basepoint.
#[must_use]
pub fn noxtls_x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut basepoint = [0_u8; 32];
    basepoint[0] = 9;
    noxtls_x25519(scalar, &basepoint)
}

/// Computes X25519 shared secret and validates non-zero output.
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
/// Forwards errors from [`X25519PrivateKey::diffie_hellman_checked`].
pub fn noxtls_x25519_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> Result<[u8; 32]> {
    private_key.diffie_hellman_checked(peer_public_key)
}

/// Generates an X25519 private key from DRBG output.
///
/// # Arguments
/// * `drbg`: DRBG instance used to fill private scalar bytes.
///
/// # Returns
/// X25519 private key containing DRBG-derived scalar bytes.
///
/// # Errors
///
/// Returns DRBG errors from [`HmacDrbgSha256::generate`], or [`Error::InvalidLength`] if the DRBG output is not exactly 32 bytes.
pub fn noxtls_x25519_generate_private_key_auto(drbg: &mut HmacDrbgSha256) -> Result<X25519PrivateKey> {
    let scalar = drbg.generate(32, b"x25519_private_scalar")?;
    let bytes: [u8; 32] = scalar
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidLength("noxtls_x25519 private scalar length mismatch"))?;
    Ok(X25519PrivateKey::from_bytes(bytes))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct FieldElement([u64; 5]);

impl FieldElement {
    /// Returns the additive identity in the Curve25519 base field representation.
    ///
    /// # Returns
    ///
    /// Field element with all limbs zero.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn zero() -> Self {
        Self([0; 5])
    }

    /// Returns the multiplicative identity in the Curve25519 base field representation.
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
        Self([1, 0, 0, 0, 0])
    }

    /// Decodes a little-endian 32-byte field encoding into five 51-bit limbs.
    ///
    /// # Arguments
    ///
    /// * `input` — Canonical or non-canonical 32-byte field element encoding.
    ///
    /// # Returns
    ///
    /// Unreduced field element after limb unpacking and carry folding.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn from_bytes(input: &[u8; 32]) -> Self {
        let l0 = load8(input, 0) & MASK51;
        let l1 = (load8(input, 6) >> 3) & MASK51;
        let l2 = (load8(input, 12) >> 6) & MASK51;
        let l3 = (load8(input, 19) >> 1) & MASK51;
        let l4 = (load8(input, 24) >> 12) & MASK51;
        Self([l0, l1, l2, l3, l4]).carry_reduce()
    }

    /// Encodes a normalized field element into a little-endian 32-byte string.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element to normalize and encode.
    ///
    /// # Returns
    ///
    /// Canonical 32-byte encoding suitable for wire formats.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn to_bytes(self) -> [u8; 32] {
        let h = self.normalize();
        let mut out = [0_u8; 32];
        for (byte_idx, out_byte) in out.iter_mut().enumerate() {
            let mut value = 0_u8;
            for bit in 0..8 {
                let bit_idx = byte_idx * 8 + bit;
                if bit_idx < 255 && h.bit(bit_idx) {
                    value |= 1 << bit;
                }
            }
            *out_byte = value;
        }
        out
    }

    /// Adds two field elements and applies carry reduction.
    ///
    /// # Arguments
    ///
    /// * `self` — Left operand.
    /// * `rhs` — Right operand.
    ///
    /// # Returns
    ///
    /// Sum modulo \\(2^{255} - 19\\) in limb form.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn add(&self, rhs: &Self) -> Self {
        let mut out = [0_u64; 5];
        for (idx, item) in out.iter_mut().enumerate() {
            *item = self.0[idx].wrapping_add(rhs.0[idx]);
        }
        Self(out).carry_reduce()
    }

    /// Subtracts two field elements modulo \\(p = 2^{255} - 19\\) with borrow-safe limb arithmetic.
    ///
    /// # Arguments
    ///
    /// * `self` — Minuend.
    /// * `rhs` — Subtrahend.
    ///
    /// # Returns
    ///
    /// Difference after adding \\(2p\\) internally to avoid underflow, then reducing.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn sub(&self, rhs: &Self) -> Self {
        // Add 2p before subtract to avoid underflow in limb arithmetic.
        let mut out = [0_u64; 5];
        for (idx, item) in out.iter_mut().enumerate() {
            *item = self.0[idx]
                .wrapping_add(P[idx] << 1)
                .wrapping_sub(rhs.0[idx]);
        }
        Self(out).carry_reduce()
    }

    /// Multiplies a field element by a small scalar constant and reduces the result.
    ///
    /// # Arguments
    ///
    /// * `self` — Field element to scale.
    /// * `scalar` — Small integer multiplier (used with the Curve25519 `121665` constant).
    ///
    /// # Returns
    ///
    /// Product after limb-wise multiply-accumulate and reduction.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn mul_small(&self, scalar: u64) -> Self {
        let mut out = [0_u64; 5];
        let mut carry = 0_u128;
        for (idx, item) in out.iter_mut().enumerate() {
            let v = (self.0[idx] as u128) * (scalar as u128) + carry;
            *item = (v as u64) & MASK51;
            carry = v >> 51;
        }
        out[0] = out[0].wrapping_add((carry as u64) * 19);
        Self(out).carry_reduce()
    }

    /// Multiplies two field elements using 128-bit limb products modulo \\(2^{255} - 19\\).
    ///
    /// # Arguments
    ///
    /// * `self` — Left operand.
    /// * `rhs` — Right operand.
    ///
    /// # Returns
    ///
    /// Product after schoolbook multiplication, carry propagation, and reduction.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;

        let c0 = (a[0] as u128) * (b[0] as u128)
            + 19 * ((a[1] as u128) * (b[4] as u128)
                + (a[2] as u128) * (b[3] as u128)
                + (a[3] as u128) * (b[2] as u128)
                + (a[4] as u128) * (b[1] as u128));
        let c1 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + 19 * ((a[2] as u128) * (b[4] as u128)
                + (a[3] as u128) * (b[3] as u128)
                + (a[4] as u128) * (b[2] as u128));
        let c2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + 19 * ((a[3] as u128) * (b[4] as u128) + (a[4] as u128) * (b[3] as u128));
        let c3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + 19 * ((a[4] as u128) * (b[4] as u128));
        let c4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);

        let mut out = [0_u64; 5];
        out[0] = (c0 as u64) & MASK51;
        let mut carry = c0 >> 51;
        let c1 = c1 + carry;
        out[1] = (c1 as u64) & MASK51;
        carry = c1 >> 51;
        let c2 = c2 + carry;
        out[2] = (c2 as u64) & MASK51;
        carry = c2 >> 51;
        let c3 = c3 + carry;
        out[3] = (c3 as u64) & MASK51;
        carry = c3 >> 51;
        let c4 = c4 + carry;
        out[4] = (c4 as u64) & MASK51;
        carry = c4 >> 51;
        out[0] = out[0].wrapping_add((carry as u64) * 19);
        Self(out).carry_reduce()
    }

    /// Squares a field element by delegating to [`Self::mul`].
    ///
    /// # Arguments
    ///
    /// * `self` — Operand to square.
    ///
    /// # Returns
    ///
    /// \\(self^2\\) modulo \\(p\\).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn square(&self) -> Self {
        self.mul(self)
    }

    /// Computes the multiplicative inverse via exponentiation to \\(p - 2\\).
    ///
    /// # Arguments
    ///
    /// * `self` — Non-zero field element to invert (caller must ensure non-zero in this construction).
    ///
    /// # Returns
    ///
    /// Multiplicative inverse used by the Montgomery ladder output step.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn invert(&self) -> Self {
        // Exponentiation by p-2 = 2^255 - 21.
        let mut exp = [0xff_u8; 32];
        exp[0] = 0xeb;
        exp[31] = 0x7f;

        let mut base = *self;
        let mut result = Self::one();
        for i in 0..255 {
            if ((exp[i / 8] >> (i & 7)) & 1) == 1 {
                result = result.mul(&base);
            }
            base = base.square();
        }
        result
    }

    /// Constant-time conditional swap of two field elements for Montgomery ladder steps.
    ///
    /// # Arguments
    ///
    /// * `a` — First operand; may be swapped with `b`.
    /// * `b` — Second operand; may be swapped with `a`.
    /// * `choice` — `1` swaps limbs, `0` leaves them unchanged (mask-derived).
    ///
    /// # Returns
    ///
    /// `()`; mutates `a` and `b` in place.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn cswap(a: &mut Self, b: &mut Self, choice: u8) {
        let mask = 0_u64.wrapping_sub(u64::from(choice));
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Propagates carries across 51-bit limbs and folds the high carry modulo \\(p\\).
    ///
    /// # Arguments
    ///
    /// * `self` — Possibly unreduced limb array after arithmetic.
    ///
    /// # Returns
    ///
    /// Partially reduced element after two carry passes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn carry_reduce(self) -> Self {
        let mut h = self.0;
        for _ in 0..2 {
            let c0 = h[0] >> 51;
            h[0] &= MASK51;
            h[1] = h[1].wrapping_add(c0);
            let c1 = h[1] >> 51;
            h[1] &= MASK51;
            h[2] = h[2].wrapping_add(c1);
            let c2 = h[2] >> 51;
            h[2] &= MASK51;
            h[3] = h[3].wrapping_add(c2);
            let c3 = h[3] >> 51;
            h[3] &= MASK51;
            h[4] = h[4].wrapping_add(c3);
            let c4 = h[4] >> 51;
            h[4] &= MASK51;
            h[0] = h[0].wrapping_add(c4 * 19);
        }
        Self(h)
    }

    /// Canonicalizes an element to its unique representative in \\([0, p)\\).
    ///
    /// # Arguments
    ///
    /// * `self` — Field element after [`Self::carry_reduce`].
    ///
    /// # Returns
    ///
    /// Fully reduced limbs suitable for bit extraction in [`Self::to_bytes`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    fn normalize(self) -> Self {
        let mut h = self.carry_reduce().0;
        let mut t = [0_u64; 5];
        let mut borrow = 0_i128;
        for i in 0..5 {
            let tmp = (h[i] as i128) - (P[i] as i128) - borrow;
            if tmp < 0 {
                t[i] = (tmp + (1_i128 << 51)) as u64;
                borrow = 1;
            } else {
                t[i] = tmp as u64;
                borrow = 0;
            }
        }
        if borrow == 0 {
            h = t;
        }
        Self(h)
    }

    /// Returns a single bit from the canonical 255-bit limb representation.
    ///
    /// # Arguments
    ///
    /// * `self` — Canonical field element.
    /// * `bit_idx` — Bit index in \\([0, 254]\\) mapped into 51-bit limbs.
    ///
    /// # Returns
    ///
    /// `true` when the selected bit is set.
    ///
    /// # Panics
    ///
    /// This function does not panic for indices used by [`Self::to_bytes`].
    #[must_use]
    fn bit(&self, bit_idx: usize) -> bool {
        let limb = bit_idx / 51;
        let offset = bit_idx % 51;
        ((self.0[limb] >> offset) & 1) == 1
    }
}

/// Loads eight little-endian bytes from `input[offset..offset + 8]`.
///
/// # Arguments
///
/// * `input` — 32-byte buffer providing the limb slice.
/// * `offset` — Start index of the eight-byte chunk (must allow eight bytes).
///
/// # Returns
///
/// Little-endian `u64` value from the selected bytes.
///
/// # Panics
///
/// Panics if `offset + 8` exceeds `input` length (internal callers use fixed offsets only).
fn load8(input: &[u8; 32], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("slice must be 8 bytes"),
    )
}

/// Clamps a raw Curve25519 scalar according to RFC 7748 bit clearing and setting rules.
///
/// # Arguments
///
/// * `scalar` — Raw 32-byte scalar before masking.
///
/// # Returns
///
/// Clamped scalar bytes suitable for the Montgomery ladder.
///
/// # Panics
///
/// This function does not panic.
fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// Returns `true` when every byte in the 32-byte array is zero.
///
/// # Arguments
///
/// * `bytes` — Fixed-size buffer to test in constant time style (byte OR fold).
///
/// # Returns
///
/// `true` if all bytes are zero.
///
/// # Panics
///
/// This function does not panic.
fn is_all_zero(bytes: &[u8; 32]) -> bool {
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
/// * `bytes` — 32-byte u-coordinate in wire order.
///
/// # Returns
///
/// `true` when `bytes` encodes the integer one.
///
/// # Panics
///
/// This function does not panic.
fn is_montgomery_u_one(bytes: &[u8; 32]) -> bool {
    bytes[0] == 1 && bytes[1..].iter().all(|byte| *byte == 0)
}

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

use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

/// Stores an unsigned big integer as little-endian 32-bit limbs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    /// Creates a zero-valued big integer.
    ///
    /// # Returns
    /// `BigUint` equal to zero.
    #[must_use]
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    /// Creates a one-valued big integer.
    ///
    /// # Returns
    /// `BigUint` equal to one.
    #[must_use]
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Creates a big integer from a `u128`.
    ///
    /// # Arguments
    /// * `value`: Unsigned integer value to convert into limb representation.
    ///
    /// # Returns
    /// `BigUint` containing the same numeric value.
    #[must_use]
    pub fn from_u128(mut value: u128) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        while value != 0 {
            limbs.push((value & 0xFFFF_FFFF) as u32);
            value >>= 32;
        }
        Self { limbs }
    }

    /// Parses a big-endian byte array into a big integer.
    ///
    /// # Arguments
    /// * `bytes`: Big-endian byte string to parse.
    ///
    /// # Returns
    /// Parsed `BigUint` value.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        Self::from_limbs(bytes_to_limbs_le(bytes))
    }

    /// Encodes the big integer as minimal big-endian bytes.
    ///
    /// # Arguments
    /// * `self`: Integer value to encode.
    ///
    /// # Returns
    /// Minimal big-endian encoding (single zero byte for value zero).
    #[must_use]
    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        let first_nonzero = out
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(out.len() - 1);
        out[first_nonzero..].to_vec()
    }

    /// Encodes the big integer as fixed-size big-endian bytes.
    ///
    /// # Arguments
    /// * `self`: Integer value to encode.
    /// * `len`: Required output length in bytes.
    ///
    /// # Returns
    /// Zero-left-padded big-endian encoding with exact `len`.
    pub fn to_be_bytes_padded(&self, len: usize) -> Result<Vec<u8>> {
        let raw = self.to_be_bytes();
        if raw.len() > len {
            return Err(Error::InvalidLength(
                "big integer does not fit target length",
            ));
        }
        let mut out = vec![0_u8; len - raw.len()];
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// Returns true when the integer value equals zero.
    ///
    /// # Arguments
    /// * `self`: Integer value to inspect.
    ///
    /// # Returns
    /// `true` when this value is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Clears limb storage by zeroing each word before releasing vector contents.
    ///
    /// # Arguments
    /// * `self` — Big integer whose backing limbs are scrubbed in place.
    ///
    /// # Returns
    /// `()`; leaves this value in the same logical state as [`Self::zero`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn clear(&mut self) {
        for limb in &mut self.limbs {
            *limb = 0;
        }
        self.limbs.clear();
    }

    /// Returns true when the integer value is odd.
    ///
    /// # Arguments
    /// * `self`: Integer value to inspect.
    ///
    /// # Returns
    /// `true` when the least-significant bit is set.
    #[must_use]
    pub fn is_odd(&self) -> bool {
        !self.is_zero() && (self.limbs[0] & 1) == 1
    }

    /// Compares two big integers.
    ///
    /// # Arguments
    /// * `self`: Left operand.
    /// * `other`: Right operand.
    ///
    /// # Returns
    /// Ordering relationship between `self` and `other`.
    #[must_use]
    pub fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for idx in (0..self.limbs.len()).rev() {
            if self.limbs[idx] != other.limbs[idx] {
                return self.limbs[idx].cmp(&other.limbs[idx]);
            }
        }
        Ordering::Equal
    }

    /// Adds two big integers and returns the sum.
    ///
    /// # Arguments
    /// * `self`: Left operand.
    /// * `other`: Right operand.
    ///
    /// # Returns
    /// Sum of both operands.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let max_len = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(max_len + 1);
        let mut carry = 0_u64;
        for idx in 0..max_len {
            let a = u64::from(*self.limbs.get(idx).unwrap_or(&0));
            let b = u64::from(*other.limbs.get(idx).unwrap_or(&0));
            let sum = a + b + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        Self::from_limbs(out)
    }

    /// Subtracts `other` from `self`; caller must ensure `self >= other`.
    ///
    /// # Arguments
    /// * `self`: Minuend value.
    /// * `other`: Subtrahend value.
    ///
    /// # Returns
    /// Difference `self - other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert!(self.cmp(other) != Ordering::Less);
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0_i64;
        for idx in 0..self.limbs.len() {
            let a = i64::from(self.limbs[idx]);
            let b = i64::from(*other.limbs.get(idx).unwrap_or(&0));
            let diff = a - b - borrow;
            if diff < 0 {
                out.push((diff + (1_i64 << 32)) as u32);
                borrow = 1;
            } else {
                out.push(diff as u32);
                borrow = 0;
            }
        }
        Self::from_limbs(out)
    }

    /// Multiplies two big integers and returns the product.
    ///
    /// # Arguments
    /// * `self`: Left operand.
    /// * `other`: Right operand.
    ///
    /// # Returns
    /// Product of both operands.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0_u32; self.limbs.len() + other.limbs.len()];
        for (i, a) in self.limbs.iter().enumerate() {
            let mut carry = 0_u64;
            for (j, b) in other.limbs.iter().enumerate() {
                let idx = i + j;
                let cur = u64::from(out[idx]) + u64::from(*a) * u64::from(*b) + carry;
                out[idx] = cur as u32;
                carry = cur >> 32;
            }
            let mut idx = i + other.limbs.len();
            while carry != 0 && idx < out.len() {
                let cur = u64::from(out[idx]) + carry;
                out[idx] = cur as u32;
                carry = cur >> 32;
                idx += 1;
            }
        }
        Self::from_limbs(out)
    }

    /// Right-shifts the integer by one bit.
    ///
    /// # Arguments
    /// * `self`: Integer value to shift.
    ///
    /// # Returns
    /// Shifted value `self >> 1`.
    #[must_use]
    pub fn shr1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0_u32; self.limbs.len()];
        let mut carry = 0_u32;
        for idx in (0..self.limbs.len()).rev() {
            out[idx] = (self.limbs[idx] >> 1) | (carry << 31);
            carry = self.limbs[idx] & 1;
        }
        Self::from_limbs(out)
    }

    /// Left-shifts the integer by `bits` bits.
    ///
    /// # Arguments
    /// * `self`: Integer value to shift.
    /// * `bits`: Number of bits to shift left.
    ///
    /// # Returns
    /// Shifted value `self << bits`.
    #[must_use]
    pub fn shl_bits(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let word_shift = bits / 32;
        let bit_shift = bits % 32;
        let mut out = vec![0_u32; self.limbs.len() + word_shift + 1];
        for (idx, limb) in self.limbs.iter().enumerate() {
            let out_idx = idx + word_shift;
            out[out_idx] |= limb << bit_shift;
            if bit_shift != 0 {
                out[out_idx + 1] |= limb >> (32 - bit_shift);
            }
        }
        Self::from_limbs(out)
    }

    /// Computes `self mod modulus`.
    ///
    /// # Arguments
    /// * `self`: Dividend value.
    /// * `modulus`: Positive modulus.
    ///
    /// # Returns
    /// Remainder in the range `[0, modulus)`, or zero when modulus is zero.
    #[must_use]
    pub fn modulo(&self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        if self.cmp(modulus) == Ordering::Less {
            return self.clone();
        }
        if modulus.limbs.len() == 1 {
            let rem_u32 = modulo_small_u32(&self.limbs, modulus.limbs[0]);
            return Self::from_u128(u128::from(rem_u32));
        }
        let n_limbs = modulus.limbs.len();
        let fast_2n_supported = n_limbs == 8
            || n_limbs == 12
            || n_limbs == 16
            || n_limbs == 24
            || n_limbs == 32
            || n_limbs == 64;
        if fast_2n_supported && self.limbs.len() == n_limbs * 2 {
            if let Some(rem) = mod_2n_by_n_limb(&self.limbs, &modulus.limbs) {
                return Self::from_limbs(rem);
            }
        }

        // Ported from C limb reducer: bitwise remainder using 32-bit little-endian limbs.
        let mut rem_limbs = vec![0_u32; modulus.limbs.len() + 1];
        let self_bytes = self.to_be_bytes();
        for byte in self_bytes {
            for bit in (0..8).rev() {
                limbs_lshift1(&mut rem_limbs);
                if ((byte >> bit) & 1) == 1 {
                    rem_limbs[0] |= 1;
                }
                if rem_limbs[modulus.limbs.len()] != 0
                    || ge_limbs_prefix(&rem_limbs, &modulus.limbs, modulus.limbs.len())
                {
                    let high = rem_limbs[modulus.limbs.len()];
                    sub_limbs_prefix(&mut rem_limbs, &modulus.limbs, modulus.limbs.len());
                    if high > 0 {
                        rem_limbs[modulus.limbs.len()] = high - 1;
                    }
                }
            }
        }
        Self::from_limbs(rem_limbs[..modulus.limbs.len()].to_vec())
    }

    /// Computes modular exponentiation `base^exp mod modulus`.
    ///
    /// # Arguments
    /// * `base`: Base value.
    /// * `exp`: Exponent value.
    /// * `modulus`: Modulus value.
    ///
    /// # Returns
    /// Result of `base^exp mod modulus`.
    #[must_use]
    pub fn mod_exp(base: &Self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            return Self::zero();
        }
        let mut result = Self::one();
        let mut b = base.modulo(modulus);
        let mut e = exp.clone();
        while !e.is_zero() {
            if e.is_odd() {
                result = mod_mul(&result, &b, modulus);
            }
            e = e.shr1();
            b = mod_mul(&b, &b, modulus);
        }
        result
    }

    /// Returns the bit length of the integer.
    ///
    /// # Arguments
    /// * `self`: Integer value to inspect.
    ///
    /// # Returns
    /// Number of significant bits required to represent the value.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let last = *self.limbs.last().expect("non-zero has at least one limb");
        32 * (self.limbs.len() - 1) + (32 - last.leading_zeros() as usize)
    }

    /// Returns true when the integer value is even.
    ///
    /// # Arguments
    /// * `self`: Integer value to inspect.
    ///
    /// # Returns
    /// `true` when the least-significant bit is clear.
    #[must_use]
    pub fn is_even(&self) -> bool {
        self.is_zero() || (self.limbs[0] & 1) == 0
    }

    /// Computes `self mod modulus` where modulus fits in one `u32`.
    ///
    /// # Arguments
    /// * `self`: Dividend value.
    /// * `modulus`: Small positive divisor.
    ///
    /// # Returns
    /// Remainder value in `[0, modulus)`, or zero when modulus is zero.
    #[must_use]
    pub fn mod_u32(&self, modulus: u32) -> u32 {
        modulo_small_u32(&self.limbs, modulus)
    }

    /// Divides by another big integer and returns `(quotient, remainder)`.
    ///
    /// # Arguments
    /// * `self`: Dividend value.
    /// * `divisor`: Positive divisor.
    ///
    /// # Returns
    /// Quotient and remainder where `self = quotient * divisor + remainder`.
    #[must_use]
    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            return (Self::zero(), self.clone());
        }
        if self.cmp(divisor).is_lt() {
            return (Self::zero(), self.clone());
        }
        let mut quotient = Self::zero();
        let mut remainder = self.clone();
        let max_shift = remainder.bit_len() - divisor.bit_len();
        for shift in (0..=max_shift).rev() {
            let shifted_divisor = divisor.shl_bits(shift);
            if remainder.cmp(&shifted_divisor).is_ge() {
                remainder = remainder.sub(&shifted_divisor);
                let q_bit = Self::one().shl_bits(shift);
                quotient = quotient.add(&q_bit);
            }
        }
        (quotient, remainder)
    }

    /// Computes greatest common divisor using Euclid's noxtls_algorithm.
    ///
    /// # Arguments
    /// * `left`: First integer value.
    /// * `right`: Second integer value.
    ///
    /// # Returns
    /// Greatest common divisor `gcd(left, right)`.
    #[must_use]
    pub fn gcd(left: &Self, right: &Self) -> Self {
        let mut a = left.clone();
        let mut b = right.clone();
        while !b.is_zero() {
            let r = a.modulo(&b);
            a = b;
            b = r;
        }
        a
    }

    /// Computes modular inverse `a^{-1} mod m` using extended Euclid updates modulo `m`.
    ///
    /// # Arguments
    /// * `a`: Value to invert.
    /// * `m`: Positive modulus.
    ///
    /// # Returns
    /// `Some(inverse)` when `gcd(a, m) = 1`, otherwise `None`.
    #[must_use]
    pub fn mod_inverse(a: &Self, m: &Self) -> Option<Self> {
        if m.is_zero() {
            return None;
        }
        let mut t = Self::zero();
        let mut new_t = Self::one();
        let mut r = m.clone();
        let mut new_r = a.modulo(m);
        while !new_r.is_zero() {
            let (q, rem) = r.div_rem(&new_r);
            let q_new_t = q.mul(&new_t).modulo(m);
            let next_t = if t.cmp(&q_new_t).is_ge() {
                t.sub(&q_new_t)
            } else {
                t.add(m).sub(&q_new_t)
            };
            t = new_t;
            new_t = next_t.modulo(m);
            r = new_r;
            new_r = rem;
        }
        if r.cmp(&Self::one()).is_ne() {
            return None;
        }
        Some(t.modulo(m))
    }

    // Creates a BigUint from limbs and strips leading zero limbs.
    // Parameters: `limbs` little-endian limb array that may include leading zeros.
    fn from_limbs(mut limbs: Vec<u32>) -> Self {
        while matches!(limbs.last(), Some(0)) {
            limbs.pop();
        }
        Self { limbs }
    }
}

/// Computes `(a * b) mod modulus` using add-double method. Parameters: `a` and `b` operands, `modulus` modulus for reduction.
///
/// # Arguments
///
/// * `a` — `&BigUint`.
/// * `b` — `&BigUint`.
/// * `modulus` — `&BigUint`.
///
/// # Returns
///
/// `BigUint` produced by `mod_mul` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    a.mul(b).modulo(modulus)
}

/// Converts big-endian bytes to little-endian 32-bit limbs. Parameters: `bytes` big-endian integer encoding.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u32>` produced by `bytes_to_limbs_le` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn bytes_to_limbs_le(bytes: &[u8]) -> Vec<u32> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let limb_len = bytes.len().div_ceil(4);
    let mut limbs = vec![0_u32; limb_len];
    for (i, byte) in bytes.iter().rev().enumerate() {
        let limb_idx = i >> 2;
        let shift = (i & 3) << 3;
        limbs[limb_idx] |= u32::from(*byte) << shift;
    }
    limbs
}

/// Computes (big integer in limbs) mod small 32-bit modulus. Parameters: `limbs` little-endian 32-bit words and `modulus` small divisor.
///
/// # Arguments
///
/// * `limbs` — `&[u32]`.
/// * `modulus` — `u32`.
///
/// # Returns
///
/// `u32` produced by `modulo_small_u32` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn modulo_small_u32(limbs: &[u32], modulus: u32) -> u32 {
    if modulus == 0 {
        return 0;
    }
    let mut rem = 0_u64;
    for limb in limbs.iter().rev() {
        rem = ((rem << 32) + u64::from(*limb)) % u64::from(modulus);
    }
    rem as u32
}

/// Left-shifts a little-endian limb array by one bit in place. Parameters: `limbs` mutable little-endian limb array.
///
/// # Arguments
///
/// * `limbs` — `&mut [u32]`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn limbs_lshift1(limbs: &mut [u32]) {
    let mut carry = 0_u32;
    for limb in limbs {
        let next_carry = (*limb >> 31) & 1;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
}

/// Returns true when a[0..len] >= b[0..len] for little-endian limbs. Parameters: `a` and `b` limb arrays and `len` comparison prefix length.
///
/// # Arguments
///
/// * `a` — `&[u32]`.
/// * `b` — `&[u32]`.
/// * `len` — `usize`.
///
/// # Returns
///
/// `bool` produced by `ge_limbs_prefix` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ge_limbs_prefix(a: &[u32], b: &[u32], len: usize) -> bool {
    for idx in (0..len).rev() {
        if a[idx] != b[idx] {
            return a[idx] > b[idx];
        }
    }
    true
}

/// Subtracts b[0..len] from a[0..len] for little-endian limbs. Parameters: `a` mutable minuend limbs, `b` subtrahend limbs, `len` prefix length.
///
/// # Arguments
///
/// * `a` — `&mut [u32]`.
/// * `b` — `&[u32]`.
/// * `len` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sub_limbs_prefix(a: &mut [u32], b: &[u32], len: usize) {
    let mut borrow = 0_u64;
    for idx in 0..len {
        let av = u64::from(a[idx]);
        let bv = u64::from(b[idx]) + borrow;
        if av < bv {
            a[idx] = (av + (1_u64 << 32) - bv) as u32;
            borrow = 1;
        } else {
            a[idx] = (av - bv) as u32;
            borrow = 0;
        }
    }
}

/// Fast Knuth-style reduction for dividend length exactly 2*n limbs. Parameters: `dividend` of length `2*n` and `divisor` of length `n`.
///
/// # Arguments
///
/// * `dividend` — `&[u32]`.
/// * `divisor` — `&[u32]`.
///
/// # Returns
///
/// `Option<Vec<u32>>` produced by `mod_2n_by_n_limb` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mod_2n_by_n_limb(dividend: &[u32], divisor: &[u32]) -> Option<Vec<u32>> {
    let n = divisor.len();
    if n < 2 || dividend.len() != n * 2 || *divisor.last()? == 0 {
        return None;
    }

    let m = n * 2;
    let mut v = divisor.to_vec();
    let mut u = vec![0_u32; m + 1];
    u[..m].copy_from_slice(dividend);

    // Knuth D1 normalization.
    let norm_shift = v[n - 1].leading_zeros() as usize;
    if norm_shift > 0 {
        limbs_shl_bits(&mut v, norm_shift);
        limbs_shl_bits(&mut u, norm_shift);
    }

    // Knuth D2..D6 quotient-digit loop.
    for j in (0..=(m - n)).rev() {
        let num = (u64::from(u[j + n]) << 32) | u64::from(u[j + n - 1]);
        let den = u64::from(v[n - 1]);
        let mut qhat = (num / den).min(u64::from(u32::MAX));
        let mut rhat = num - (qhat * den);

        if n > 1 {
            loop {
                let lhs = qhat * u64::from(v[n - 2]);
                if (rhat >> 32) != 0 {
                    break;
                }
                let rhs = (rhat << 32) + u64::from(u[j + n - 2]);
                if lhs <= rhs {
                    break;
                }
                qhat -= 1;
                rhat += den;
            }
        }

        if qhat != 0 {
            let borrow = limb_mul_sub(&mut u, j, qhat as u32, &v);
            if borrow {
                let carry_out = limb_add_at(&mut u, j, &v);
                if carry_out != 0 && (j + n + 1) <= m {
                    u[j + n + 1] = u[j + n + 1].wrapping_add(carry_out);
                }
            }
        }
    }

    // Normalize remainder to [0, v).
    while u[n] != 0 || ge_limbs_prefix(&u, &v, n) {
        if sub_limbs_borrow_prefix(&mut u, &v, n) {
            if u[n] != 0 {
                u[n] -= 1;
            } else {
                break;
            }
        }
    }

    // Unnormalize.
    if norm_shift > 0 {
        limbs_shr_bits(&mut u[..n], norm_shift);
    }

    let mut rem = u[..n].to_vec();
    if ge_limbs_prefix(&rem, divisor, n) {
        sub_limbs_prefix(&mut rem, divisor, n);
    }
    Some(rem)
}

/// Shifts little-endian limbs left by k bits where 0 < k < 32. Parameters: `limbs` mutable limb array and `k` shift count.
///
/// # Arguments
///
/// * `limbs` — `&mut [u32]`.
/// * `k` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn limbs_shl_bits(limbs: &mut [u32], k: usize) {
    if k == 0 || k >= 32 {
        return;
    }
    let mut carry = 0_u32;
    for limb in limbs {
        let v = *limb;
        *limb = (v << k) | carry;
        carry = v >> (32 - k);
    }
}

/// Shifts little-endian limbs right by k bits where 0 < k < 32. Parameters: `limbs` mutable limb array and `k` shift count.
///
/// # Arguments
///
/// * `limbs` — `&mut [u32]`.
/// * `k` — `usize`.
///
/// # Returns
///
/// `()` when there is no return data.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn limbs_shr_bits(limbs: &mut [u32], k: usize) {
    if k == 0 || k >= 32 {
        return;
    }
    let mut carry = 0_u32;
    for idx in (0..limbs.len()).rev() {
        let v = limbs[idx];
        limbs[idx] = (v >> k) | carry;
        carry = v << (32 - k);
    }
}

/// Subtracts q*mod from rem[start..start+n] and returns borrow-out. Parameters: `rem` mutable remainder limbs, `start` offset, `q` quotient digit, and `modulus` normalized divisor limbs.
///
/// # Arguments
///
/// * `rem` — `&mut [u32]`.
/// * `start` — `usize`.
/// * `q` — `u32`.
/// * `modulus` — `&[u32]`.
///
/// # Returns
///
/// `bool` produced by `limb_mul_sub` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn limb_mul_sub(rem: &mut [u32], start: usize, q: u32, modulus: &[u32]) -> bool {
    let n = modulus.len();
    let mut carry = 0_u64;
    let mut borrow = 0_u64;
    for i in 0..n {
        let prod = (u64::from(modulus[i]) * u64::from(q)) + carry;
        let sub = u64::from(prod as u32) + borrow;
        let rem_i = u64::from(rem[start + i]);
        carry = prod >> 32;
        if rem_i < sub {
            rem[start + i] = (rem_i + (1_u64 << 32) - sub) as u32;
            borrow = 1;
        } else {
            rem[start + i] = (rem_i - sub) as u32;
            borrow = 0;
        }
    }
    let k = carry + borrow;
    let rem_hi = u64::from(rem[start + n]);
    rem[start + n] = rem_hi.wrapping_sub(k) as u32;
    rem_hi < k
}

/// Adds modulus at rem[start..start+n], returns carry-out. Parameters: `rem` mutable remainder limbs, `start` offset, and `modulus` addend.
///
/// # Arguments
///
/// * `rem` — `&mut [u32]`.
/// * `start` — `usize`.
/// * `modulus` — `&[u32]`.
///
/// # Returns
///
/// `u32` produced by `limb_add_at` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn limb_add_at(rem: &mut [u32], start: usize, modulus: &[u32]) -> u32 {
    let n = modulus.len();
    let mut carry = 0_u64;
    for i in 0..n {
        let sum = u64::from(rem[start + i]) + u64::from(modulus[i]) + carry;
        rem[start + i] = sum as u32;
        carry = sum >> 32;
    }
    let sum_hi = u64::from(rem[start + n]) + carry;
    rem[start + n] = sum_hi as u32;
    (sum_hi >> 32) as u32
}

/// Subtracts b[0..len] from a[0..len], returns borrow-out. Parameters: `a` mutable minuend limbs, `b` subtrahend limbs, and `len` prefix length.
///
/// # Arguments
///
/// * `a` — `&mut [u32]`.
/// * `b` — `&[u32]`.
/// * `len` — `usize`.
///
/// # Returns
///
/// `bool` produced by `sub_limbs_borrow_prefix` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn sub_limbs_borrow_prefix(a: &mut [u32], b: &[u32], len: usize) -> bool {
    let mut borrow = 0_u64;
    for idx in 0..len {
        let av = u64::from(a[idx]);
        let bv = u64::from(b[idx]) + borrow;
        if av < bv {
            a[idx] = (av + (1_u64 << 32) - bv) as u32;
            borrow = 1;
        } else {
            a[idx] = (av - bv) as u32;
            borrow = 0;
        }
    }
    borrow != 0
}

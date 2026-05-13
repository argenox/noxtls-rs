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
use crate::hash::{noxtls_sha1, noxtls_sha256, noxtls_sha384, noxtls_sha512};
use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

use super::bignum::BigUint;

const RSA_KEYGEN_MIN_BITS: usize = 1024;
const RSA_KEYGEN_MAX_BITS: usize = 4096;
const RSA_MIN_SECURE_BITS: usize = 2048;
const RSA_RECOMMENDED_SECURE_BITS: usize = 3072;

/// Represents an RSA private key with arbitrary-size modulus and exponent.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub d: BigUint,
    crt: Option<RsaPrivateCrtComponents>,
}

/// Represents an RSA public key with arbitrary-size modulus and exponent.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

/// Stores optional RSA CRT decomposition parameters for accelerated private operations.
#[derive(Debug, Clone)]
struct RsaPrivateCrtComponents {
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
}

/// Defines secure RSA key-size policy thresholds for safe key-generation entry points.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RsaKeySizePolicy {
    /// Requires at least 2048-bit RSA modulus length.
    Minimum2048,
    /// Requires at least 3072-bit RSA modulus length.
    Minimum3072,
}

impl RsaKeySizePolicy {
    /// Returns the minimum RSA modulus size in bits for this policy.
    ///
    /// # Arguments
    ///
    /// * `self` — Selected policy variant.
    ///
    /// # Returns
    ///
    /// Minimum modulus bit length required for key generation.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn min_bits(self) -> usize {
        match self {
            Self::Minimum2048 => RSA_MIN_SECURE_BITS,
            Self::Minimum3072 => RSA_RECOMMENDED_SECURE_BITS,
        }
    }
}

impl RsaPrivateKey {
    /// Creates private key from big-endian modulus and private exponent bytes.
    ///
    /// # Arguments
    /// * `n`: RSA modulus encoded as big-endian bytes.
    /// * `d`: RSA private exponent encoded as big-endian bytes.
    ///
    /// # Returns
    /// Parsed `RsaPrivateKey` when both fields are non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when fields are empty, or when modulus size is below
    /// 2048 bits in default-safe builds (legacy-compatible hazardous mode permits smaller imports),
    /// or other RSA component validation errors from [`validate_private_components`].
    pub fn from_be_bytes(n: &[u8], d: &[u8]) -> Result<Self> {
        if n.is_empty() || d.is_empty() {
            return Err(Error::InvalidLength(
                "rsa private key fields must not be empty",
            ));
        }
        let key = Self {
            n: BigUint::from_be_bytes(n),
            d: BigUint::from_be_bytes(d),
            crt: None,
        };
        if !cfg!(feature = "hazardous-legacy-crypto") && key.n.bit_len() < RSA_MIN_SECURE_BITS {
            return Err(Error::InvalidLength(
                "rsa private key modulus must be at least 2048 bits",
            ));
        }
        validate_private_components(&key.n, &key.d)?;
        Ok(key)
    }

    /// Creates private key from small integers for compatibility tests.
    ///
    /// # Arguments
    /// * `n`: RSA modulus value.
    /// * `d`: RSA private exponent value.
    ///
    /// # Returns
    /// `RsaPrivateKey` converted from the provided integer values.
    #[must_use]
    pub fn from_u128(n: u128, d: u128) -> Self {
        Self {
            n: BigUint::from_u128(n),
            d: BigUint::from_u128(d),
            crt: None,
        }
    }

    /// Clears private key material to a zeroized placeholder state.
    ///
    /// # Notes
    /// This mirrors explicit key free/reset lifecycle flows from the C surface.
    pub fn clear(&mut self) {
        self.n.clear();
        self.d.clear();
        if let Some(crt) = self.crt.as_mut() {
            crt.p.clear();
            crt.q.clear();
            crt.dp.clear();
            crt.dq.clear();
            crt.qinv.clear();
        }
        self.crt = None;
    }

    /// Attaches RSA CRT decomposition components to this private key.
    ///
    /// # Arguments
    /// * `p`: First RSA prime factor.
    /// * `q`: Second RSA prime factor.
    /// * `dp`: `d mod (p - 1)` CRT exponent.
    /// * `dq`: `d mod (q - 1)` CRT exponent.
    /// * `qinv`: `q^{-1} mod p` CRT coefficient.
    ///
    /// # Returns
    /// Updated private key configured with CRT components.
    pub fn with_crt_components(
        mut self,
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qinv: &[u8],
    ) -> Result<Self> {
        let crt = RsaPrivateCrtComponents {
            p: BigUint::from_be_bytes(p),
            q: BigUint::from_be_bytes(q),
            dp: BigUint::from_be_bytes(dp),
            dq: BigUint::from_be_bytes(dq),
            qinv: BigUint::from_be_bytes(qinv),
        };
        validate_crt_components(&self.n, &crt)?;
        self.crt = Some(crt);
        Ok(self)
    }

    /// Signs a representative digest interpreted as big-endian integer modulo `n`.
    ///
    /// # Arguments
    /// * `digest`: Digest bytes to convert into an RSA message representative.
    ///
    /// # Returns
    /// Signature bytes padded to modulus length.
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.is_empty() {
            return Err(Error::InvalidLength("digest must not be empty"));
        }
        validate_private_components(&self.n, &self.d)?;
        let m = BigUint::from_be_bytes(digest).modulo(&self.n);
        let s = BigUint::mod_exp(&m, &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PKCS1-v1_5 style encoding with SHA-256.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    ///
    /// # Returns
    /// PKCS#1 v1.5 RSA signature bytes.
    pub fn sign_pkcs1_v15_sha256(&self, msg: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let hash = noxtls_sha256(msg);
        let em = emsa_pkcs1_v15_encode(
            &hash,
            PKCS1_V15_DIGESTINFO_SHA256_PREFIX,
            self.modulus_len(),
        )?;
        let m = BigUint::from_be_bytes(&em);
        let s = BigUint::mod_exp(&m, &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PKCS1-v1_5 style encoding with SHA-1.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    ///
    /// # Returns
    /// PKCS#1 v1.5 RSA signature bytes.
    pub fn sign_pkcs1_v15_sha1(&self, msg: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let hash = noxtls_sha1(msg);
        let em =
            emsa_pkcs1_v15_encode(&hash, PKCS1_V15_DIGESTINFO_SHA1_PREFIX, self.modulus_len())?;
        let m = BigUint::from_be_bytes(&em);
        let s = BigUint::mod_exp(&m, &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PKCS1-v1_5 style encoding with SHA-384.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    ///
    /// # Returns
    /// PKCS#1 v1.5 RSA signature bytes.
    pub fn sign_pkcs1_v15_sha384(&self, msg: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let hash = noxtls_sha384(msg);
        let em = emsa_pkcs1_v15_encode(
            &hash,
            PKCS1_V15_DIGESTINFO_SHA384_PREFIX,
            self.modulus_len(),
        )?;
        let m = BigUint::from_be_bytes(&em);
        let s = BigUint::mod_exp(&m, &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PKCS1-v1_5 style encoding with SHA-512.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    ///
    /// # Returns
    /// PKCS#1 v1.5 RSA signature bytes.
    pub fn sign_pkcs1_v15_sha512(&self, msg: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let hash = noxtls_sha512(msg);
        let em = emsa_pkcs1_v15_encode(
            &hash,
            PKCS1_V15_DIGESTINFO_SHA512_PREFIX,
            self.modulus_len(),
        )?;
        let m = BigUint::from_be_bytes(&em);
        let s = BigUint::mod_exp(&m, &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PSS with SHA-256 and caller-provided salt.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    /// * `salt`: Caller-provided random salt used by PSS encoding.
    ///
    /// # Returns
    /// RSASSA-PSS RSA signature bytes.
    pub fn sign_pss_sha256(&self, msg: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let em_bits = self.n.bit_len().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let m_hash = noxtls_sha256(msg);
        let em = emsa_pss_encode_sha256(&m_hash, salt, em_bits, em_len)?;
        let s = BigUint::mod_exp(&BigUint::from_be_bytes(&em), &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Signs a message using RSASSA-PSS with SHA-384 and caller-provided salt.
    ///
    /// # Arguments
    /// * `msg`: Message bytes to hash and sign.
    /// * `salt`: Caller-provided random salt used by PSS encoding.
    ///
    /// # Returns
    /// RSASSA-PSS RSA signature bytes.
    pub fn sign_pss_sha384(&self, msg: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        let em_bits = self.n.bit_len().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let m_hash = noxtls_sha384(msg);
        let em = emsa_pss_encode_sha384(&m_hash, salt, em_bits, em_len)?;
        let s = BigUint::mod_exp(&BigUint::from_be_bytes(&em), &self.d, &self.n);
        s.to_be_bytes_padded(self.modulus_len())
    }

    /// Decrypts RSAES-PKCS1-v1_5 ciphertext with private exponent `d`.
    ///
    /// # Arguments
    /// * `ciphertext`: Ciphertext bytes with length equal to modulus length.
    ///
    /// # Returns
    /// Decrypted plaintext when PKCS#1 v1.5 structure is valid.
    pub fn decrypt_pkcs1_v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        if ciphertext.len() != self.modulus_len() {
            return Err(Error::CryptoFailure("rsa decryption failed"));
        }
        let em = BigUint::mod_exp(&BigUint::from_be_bytes(ciphertext), &self.d, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        decode_pkcs1_v15_plaintext(&em)
    }

    /// Decrypts RSAES-PKCS1-v1_5 ciphertext using configured CRT components.
    ///
    /// # Arguments
    /// * `ciphertext`: Ciphertext bytes with length equal to modulus length.
    ///
    /// # Returns
    /// Decrypted plaintext when CRT components are configured and PKCS#1 v1.5 structure is valid.
    pub fn decrypt_pkcs1_v15_crt_only(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        if ciphertext.len() != self.modulus_len() {
            return Err(Error::CryptoFailure("rsa decryption failed"));
        }
        let crt = self
            .crt
            .as_ref()
            .ok_or(Error::StateError("rsa crt parameters are not configured"))?;
        let c = BigUint::from_be_bytes(ciphertext);
        let m1 = BigUint::mod_exp(&c, &crt.dp, &crt.p);
        let m2 = BigUint::mod_exp(&c, &crt.dq, &crt.q);
        let diff = if m1.cmp(&m2).is_ge() {
            m1.sub(&m2)
        } else {
            m1.add(&crt.p).sub(&m2)
        };
        let h = crt.qinv.mul(&diff).modulo(&crt.p);
        let m = m2.add(&crt.q.mul(&h));
        let em = m.to_be_bytes_padded(self.modulus_len())?;
        decode_pkcs1_v15_plaintext(&em)
    }

    /// Decrypts RSAES-OAEP ciphertext with SHA-256 and caller-provided label.
    ///
    /// # Arguments
    /// * `ciphertext`: Ciphertext bytes with length equal to modulus length.
    /// * `label`: OAEP label bytes hashed into encoding parameters.
    ///
    /// # Returns
    /// Decrypted plaintext when OAEP structure validates.
    pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        if ciphertext.len() != self.modulus_len() {
            return Err(Error::CryptoFailure("rsa decryption failed"));
        }
        let em = BigUint::mod_exp(&BigUint::from_be_bytes(ciphertext), &self.d, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        decode_oaep_sha256_plaintext(&em, label)
    }

    /// Decrypts RSAES-OAEP ciphertext using configured CRT components.
    ///
    /// # Arguments
    /// * `ciphertext`: Ciphertext bytes with length equal to modulus length.
    /// * `label`: OAEP label bytes hashed into encoding parameters.
    ///
    /// # Returns
    /// Decrypted plaintext when CRT parameters are configured and OAEP structure validates.
    pub fn decrypt_oaep_sha256_crt_only(&self, ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>> {
        validate_private_components(&self.n, &self.d)?;
        if ciphertext.len() != self.modulus_len() {
            return Err(Error::CryptoFailure("rsa decryption failed"));
        }
        let crt = self
            .crt
            .as_ref()
            .ok_or(Error::StateError("rsa crt parameters are not configured"))?;
        let c = BigUint::from_be_bytes(ciphertext);
        let m1 = BigUint::mod_exp(&c, &crt.dp, &crt.p);
        let m2 = BigUint::mod_exp(&c, &crt.dq, &crt.q);
        let diff = if m1.cmp(&m2).is_ge() {
            m1.sub(&m2)
        } else {
            m1.add(&crt.p).sub(&m2)
        };
        let h = crt.qinv.mul(&diff).modulo(&crt.p);
        let m = m2.add(&crt.q.mul(&h));
        let em = m.to_be_bytes_padded(self.modulus_len())?;
        decode_oaep_sha256_plaintext(&em, label)
    }

    /// Returns the RSA modulus length in bytes for PKCS encoding helpers.
    ///
    /// # Arguments
    ///
    /// * `self` — Private key whose modulus `n` defines the length.
    ///
    /// # Returns
    ///
    /// Byte length of the big-endian modulus encoding.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn modulus_len(&self) -> usize {
        self.n.to_be_bytes().len()
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

impl RsaPublicKey {
    /// Creates public key from big-endian modulus and exponent bytes.
    ///
    /// # Arguments
    /// * `n`: RSA modulus encoded as big-endian bytes.
    /// * `e`: RSA public exponent encoded as big-endian bytes.
    ///
    /// # Returns
    /// Parsed `RsaPublicKey` when both fields are non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when fields are empty, or when modulus size is below
    /// 2048 bits in default-safe builds (legacy-compatible hazardous mode permits smaller imports),
    /// or other RSA component validation errors from [`validate_public_components`].
    pub fn from_be_bytes(n: &[u8], e: &[u8]) -> Result<Self> {
        if n.is_empty() || e.is_empty() {
            return Err(Error::InvalidLength(
                "rsa public key fields must not be empty",
            ));
        }
        let key = Self {
            n: BigUint::from_be_bytes(n),
            e: BigUint::from_be_bytes(e),
        };
        if !cfg!(feature = "hazardous-legacy-crypto") && key.n.bit_len() < RSA_MIN_SECURE_BITS {
            return Err(Error::InvalidLength(
                "rsa public key modulus must be at least 2048 bits",
            ));
        }
        validate_public_components(&key.n, &key.e)?;
        Ok(key)
    }

    /// Creates public key from small integers for compatibility tests.
    ///
    /// # Arguments
    /// * `n`: RSA modulus value.
    /// * `e`: RSA public exponent value.
    ///
    /// # Returns
    /// `RsaPublicKey` converted from the provided integer values.
    #[must_use]
    pub fn from_u128(n: u128, e: u128) -> Self {
        Self {
            n: BigUint::from_u128(n),
            e: BigUint::from_u128(e),
        }
    }

    /// Clears public key material to a zeroized placeholder state.
    ///
    /// # Notes
    /// This mirrors explicit key free/reset lifecycle flows from the C surface.
    pub fn clear(&mut self) {
        self.n = BigUint::zero();
        self.e = BigUint::zero();
    }

    /// Verifies a digest representative by recovering signature with exponent `e`.
    ///
    /// # Arguments
    /// * `digest`: Expected digest representative bytes.
    /// * `signature`: RSA signature to verify.
    ///
    /// # Returns
    /// `Ok(())` when the recovered representative equals `digest mod n`.
    pub fn verify_digest(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        if digest.is_empty() {
            return Err(Error::InvalidLength("digest must not be empty"));
        }
        validate_public_components(&self.n, &self.e)?;
        let k = self.modulus_len();
        let expected = BigUint::from_be_bytes(digest)
            .modulo(&self.n)
            .to_be_bytes_padded(k)?;
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(k)?;
        if ct_bytes_eq(&recovered, &expected) {
            Ok(())
        } else {
            Err(Error::CryptoFailure("RSA verification failed"))
        }
    }

    /// Verifies RSASSA-PKCS1-v1_5 signature for SHA-256 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PKCS#1 v1.5 encoded.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pkcs1_v15_sha256(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let expected = emsa_pkcs1_v15_encode(
            &noxtls_sha256(msg),
            PKCS1_V15_DIGESTINFO_SHA256_PREFIX,
            self.modulus_len(),
        )?;
        if ct_bytes_eq(&recovered, &expected) {
            Ok(())
        } else {
            Err(Error::CryptoFailure("RSA verification failed"))
        }
    }

    /// Verifies RSASSA-PKCS1-v1_5 signature for SHA-1 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PKCS#1 v1.5 encoded.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pkcs1_v15_sha1(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let expected = emsa_pkcs1_v15_encode(
            &noxtls_sha1(msg),
            PKCS1_V15_DIGESTINFO_SHA1_PREFIX,
            self.modulus_len(),
        )?;
        if ct_bytes_eq(&recovered, &expected) {
            Ok(())
        } else {
            Err(Error::CryptoFailure("RSA verification failed"))
        }
    }

    /// Verifies RSASSA-PKCS1-v1_5 signature for SHA-384 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PKCS#1 v1.5 encoded.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pkcs1_v15_sha384(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let expected = emsa_pkcs1_v15_encode(
            &noxtls_sha384(msg),
            PKCS1_V15_DIGESTINFO_SHA384_PREFIX,
            self.modulus_len(),
        )?;
        if ct_bytes_eq(&recovered, &expected) {
            Ok(())
        } else {
            Err(Error::CryptoFailure("RSA verification failed"))
        }
    }

    /// Verifies RSASSA-PKCS1-v1_5 signature for SHA-512 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PKCS#1 v1.5 encoded.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pkcs1_v15_sha512(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let expected = emsa_pkcs1_v15_encode(
            &noxtls_sha512(msg),
            PKCS1_V15_DIGESTINFO_SHA512_PREFIX,
            self.modulus_len(),
        )?;
        if ct_bytes_eq(&recovered, &expected) {
            Ok(())
        } else {
            Err(Error::CryptoFailure("RSA verification failed"))
        }
    }

    /// Verifies RSASSA-PSS signature for SHA-256 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PSS encoded.
    /// * `salt_len`: Expected salt length used by signer.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pss_sha256(&self, msg: &[u8], signature: &[u8], salt_len: usize) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let em_bits = self.n.bit_len().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let em = &recovered[recovered.len() - em_len..];
        emsa_pss_verify_sha256(&noxtls_sha256(msg), em, em_bits, salt_len)
    }

    /// Verifies RSASSA-PSS signature for SHA-384 hashed message.
    ///
    /// # Arguments
    /// * `msg`: Original message bytes.
    /// * `signature`: RSA signature expected to be PSS encoded.
    /// * `salt_len`: Expected salt length used by signer.
    ///
    /// # Returns
    /// `Ok(())` when signature verification succeeds.
    pub fn verify_pss_sha384(&self, msg: &[u8], signature: &[u8], salt_len: usize) -> Result<()> {
        validate_public_components(&self.n, &self.e)?;
        if signature.len() != self.modulus_len() {
            return Err(Error::InvalidLength("rsa signature length mismatch"));
        }
        let em_bits = self.n.bit_len().saturating_sub(1);
        let em_len = em_bits.div_ceil(8);
        let recovered = BigUint::mod_exp(&BigUint::from_be_bytes(signature), &self.e, &self.n)
            .to_be_bytes_padded(self.modulus_len())?;
        let em = &recovered[recovered.len() - em_len..];
        emsa_pss_verify_sha384(&noxtls_sha384(msg), em, em_bits, salt_len)
    }

    /// Encrypts plaintext using RSAES-PKCS1-v1_5 with DRBG-sourced non-zero padding.
    ///
    /// # Arguments
    /// * `plaintext`: Plaintext bytes to encrypt.
    /// * `drbg`: DRBG used to generate PKCS#1 v1.5 PS bytes.
    ///
    /// # Returns
    /// Ciphertext bytes padded to modulus length.
    pub fn encrypt_pkcs1_v15_auto(
        &self,
        plaintext: &[u8],
        drbg: &mut HmacDrbgSha256,
    ) -> Result<Vec<u8>> {
        validate_public_components(&self.n, &self.e)?;
        let k = self.modulus_len();
        if plaintext.len() > k.saturating_sub(11) {
            return Err(Error::InvalidLength(
                "rsa plaintext too long for pkcs1 v1.5 encryption",
            ));
        }
        let ps_len = k - plaintext.len() - 3;
        let ps = drbg_nonzero_padding(drbg, ps_len)?;
        let mut em = Vec::with_capacity(k);
        em.push(0x00);
        em.push(0x02);
        em.extend_from_slice(&ps);
        em.push(0x00);
        em.extend_from_slice(plaintext);
        let c = BigUint::mod_exp(&BigUint::from_be_bytes(&em), &self.e, &self.n);
        c.to_be_bytes_padded(k)
    }

    /// Encrypts plaintext using RSAES-OAEP with SHA-256 and DRBG-derived seed.
    ///
    /// # Arguments
    /// * `plaintext`: Plaintext bytes to encrypt.
    /// * `label`: OAEP label bytes hashed into encoding parameters.
    /// * `drbg`: DRBG used to generate OAEP seed bytes.
    ///
    /// # Returns
    /// Ciphertext bytes padded to modulus length.
    pub fn encrypt_oaep_sha256_auto(
        &self,
        plaintext: &[u8],
        label: &[u8],
        drbg: &mut HmacDrbgSha256,
    ) -> Result<Vec<u8>> {
        validate_public_components(&self.n, &self.e)?;
        let k = self.modulus_len();
        let seed = drbg.generate(32, b"rsa_oaep_sha256_seed")?;
        let em = emea_oaep_encode_sha256(plaintext, label, &seed, k)?;
        let c = BigUint::mod_exp(&BigUint::from_be_bytes(&em), &self.e, &self.n);
        c.to_be_bytes_padded(k)
    }

    /// Returns the RSA modulus length in bytes for encryption and encoding helpers.
    ///
    /// # Arguments
    ///
    /// * `self` — Public key whose modulus `n` defines the length.
    ///
    /// # Returns
    ///
    /// Byte length of the big-endian modulus encoding.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn modulus_len(&self) -> usize {
        self.n.to_be_bytes().len()
    }
}

/// Generates an RSA keypair with a caller-provided public exponent using DRBG entropy.
///
/// # Arguments
/// * `modulus_bits`: Target modulus size in bits (supported range: 1024..=4096).
/// * `public_exponent`: Public exponent value (must be odd and >= 3).
/// * `drbg`: DRBG source used to sample prime candidates.
///
/// # Returns
/// Generated `(private_key, public_key)` pair including CRT parameters.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_rsa_generate_keypair_with_exponent_auto(
    modulus_bits: usize,
    public_exponent: u32,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    rsa_generate_keypair_backend_auto(modulus_bits, public_exponent, drbg)
}

/// Generates RSA keypair material with backend-supported modulus range and exponent checks.
///
/// # Arguments
///
/// * `modulus_bits` — Target modulus size in bits (supported inclusive range enforced inside).
/// * `public_exponent` — Desired public exponent (must be odd and at least 3).
/// * `drbg` — DRBG used for prime sampling and auxiliary randomness.
///
/// # Returns
///
/// On success, a `(private_key, public_key)` pair including CRT parameters when applicable.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parameters are out of range, prime search fails, or internal invariants fail.
///
/// # Panics
///
/// This function does not panic.
fn rsa_generate_keypair_backend_auto(
    modulus_bits: usize,
    public_exponent: u32,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    if !(RSA_KEYGEN_MIN_BITS..=RSA_KEYGEN_MAX_BITS).contains(&modulus_bits) {
        return Err(Error::InvalidLength(
            "rsa modulus bits must be in supported range 1024..=4096",
        ));
    }
    if public_exponent < 3 || (public_exponent & 1) == 0 {
        return Err(Error::CryptoFailure(
            "rsa public exponent must be odd and at least 3",
        ));
    }
    let e = BigUint::from_u128(u128::from(public_exponent));
    let one = BigUint::one();
    let p_bits = modulus_bits / 2;
    let q_bits = modulus_bits - p_bits;
    let mut attempts = 0_u32;
    while attempts < 256 {
        let mut p = generate_rsa_prime_candidate_auto(p_bits, &e, drbg)?;
        let mut q = generate_rsa_prime_candidate_auto(q_bits, &e, drbg)?;
        let mut distinct_attempts = 0_u32;
        while p.cmp(&q).is_eq() {
            if distinct_attempts >= 32 {
                break;
            }
            q = generate_rsa_prime_candidate_auto(q_bits, &e, drbg)?;
            distinct_attempts = distinct_attempts.saturating_add(1);
        }
        if p.cmp(&q).is_eq() {
            attempts = attempts.saturating_add(1);
            continue;
        }
        if p.cmp(&q).is_gt() {
            core::mem::swap(&mut p, &mut q);
        }
        let n = p.mul(&q);
        if n.bit_len() != modulus_bits {
            attempts = attempts.saturating_add(1);
            continue;
        }
        let pm1 = p.sub(&one);
        let qm1 = q.sub(&one);
        let phi = pm1.mul(&qm1);
        if BigUint::gcd(&e, &phi).cmp(&one).is_ne() {
            attempts = attempts.saturating_add(1);
            continue;
        }
        let Some(d) = BigUint::mod_inverse(&e, &phi) else {
            attempts = attempts.saturating_add(1);
            continue;
        };
        let dp = d.modulo(&pm1);
        let dq = d.modulo(&qm1);
        let Some(qinv) = BigUint::mod_inverse(&q, &p) else {
            attempts = attempts.saturating_add(1);
            continue;
        };
        let private = RsaPrivateKey {
            n: n.clone(),
            d,
            crt: Some(RsaPrivateCrtComponents { p, q, dp, dq, qinv }),
        };
        let public = RsaPublicKey { n, e };
        validate_private_components(&private.n, &private.d)?;
        validate_public_components(&public.n, &public.e)?;
        validate_crt_components(&private.n, private.crt.as_ref().expect("crt must exist"))?;
        return Ok((private, public));
    }
    Err(Error::StateError(
        "rsa key generation exhausted attempt budget",
    ))
}

/// Generates an RSA keypair with default public exponent `65537` using DRBG entropy.
///
/// # Arguments
/// * `modulus_bits`: Target modulus size in bits (supported range: 1024..=4096).
/// * `drbg`: DRBG source used to sample prime candidates.
///
/// # Returns
/// Generated `(private_key, public_key)` pair including CRT parameters.
#[cfg(feature = "hazardous-legacy-crypto")]
pub fn noxtls_rsa_generate_keypair_auto(
    modulus_bits: usize,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    rsa_generate_keypair_backend_auto(modulus_bits, 65_537, drbg)
}

/// Generates an RSA keypair under one secure minimum key-size policy.
///
/// # Arguments
/// * `modulus_bits`: Target modulus size in bits for generated key material.
/// * `public_exponent`: Public exponent value (must be odd and >= 3).
/// * `policy`: Secure minimum modulus-size policy to enforce.
/// * `drbg`: DRBG source used to sample prime candidates.
///
/// # Returns
/// Generated `(private_key, public_key)` pair when key size satisfies policy and backend support.
pub fn noxtls_rsa_generate_keypair_with_policy_auto(
    modulus_bits: usize,
    public_exponent: u32,
    policy: RsaKeySizePolicy,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    if !(RSA_MIN_SECURE_BITS..=RSA_KEYGEN_MAX_BITS).contains(&modulus_bits) {
        return Err(Error::InvalidLength(
            "secure rsa modulus bits must be in supported range 2048..=4096",
        ));
    }
    if modulus_bits < policy.min_bits() {
        return Err(Error::InvalidLength(
            "rsa modulus bits do not satisfy configured secure policy minimum",
        ));
    }
    rsa_generate_keypair_backend_auto(modulus_bits, public_exponent, drbg)
}

/// Generates an RSA keypair with secure minimum modulus policy and default exponent `65537`.
///
/// # Arguments
/// * `modulus_bits`: Target modulus size in bits for generated key material.
/// * `policy`: Secure minimum modulus-size policy to enforce.
/// * `drbg`: DRBG source used to sample prime candidates.
///
/// # Returns
/// Generated `(private_key, public_key)` pair when key size satisfies secure policy.
pub fn noxtls_rsa_generate_keypair_secure_auto(
    modulus_bits: usize,
    policy: RsaKeySizePolicy,
    drbg: &mut HmacDrbgSha256,
) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    noxtls_rsa_generate_keypair_with_policy_auto(modulus_bits, 65_537, policy, drbg)
}

/// Hashes and signs message using RSASSA-PKCS1-v1_5 with SHA-256.
///
/// # Arguments
/// * `private`: RSA private key used to produce the signature.
/// * `msg`: Message bytes to hash and sign.
///
/// # Returns
/// PKCS#1 v1.5 RSA signature bytes.
pub fn noxtls_rsassa_sha256_sign(private: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    private.sign_pkcs1_v15_sha256(msg)
}

/// Hashes and verifies message using RSASSA-PKCS1-v1_5 with SHA-256.
///
/// # Arguments
/// * `public`: RSA public key used to verify the signature.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_sha256_verify(public: &RsaPublicKey, msg: &[u8], signature: &[u8]) -> Result<()> {
    public.verify_pkcs1_v15_sha256(msg, signature)
}

/// Hashes and signs message using RSASSA-PKCS1-v1_5 with SHA-1.
///
/// # Arguments
/// * `private`: RSA private key used to produce the signature.
/// * `msg`: Message bytes to hash and sign.
///
/// # Returns
/// PKCS#1 v1.5 RSA signature bytes.
pub fn noxtls_rsassa_sha1_sign(private: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    private.sign_pkcs1_v15_sha1(msg)
}

/// Hashes and verifies message using RSASSA-PKCS1-v1_5 with SHA-1.
///
/// # Arguments
/// * `public`: RSA public key used to verify the signature.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_sha1_verify(public: &RsaPublicKey, msg: &[u8], signature: &[u8]) -> Result<()> {
    public.verify_pkcs1_v15_sha1(msg, signature)
}

/// Hashes and signs message using RSASSA-PKCS1-v1_5 with SHA-384.
///
/// # Arguments
/// * `private`: RSA private key used to produce the signature.
/// * `msg`: Message bytes to hash and sign.
///
/// # Returns
/// PKCS#1 v1.5 RSA signature bytes.
pub fn noxtls_rsassa_sha384_sign(private: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    private.sign_pkcs1_v15_sha384(msg)
}

/// Hashes and verifies message using RSASSA-PKCS1-v1_5 with SHA-384.
///
/// # Arguments
/// * `public`: RSA public key used to verify the signature.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_sha384_verify(public: &RsaPublicKey, msg: &[u8], signature: &[u8]) -> Result<()> {
    public.verify_pkcs1_v15_sha384(msg, signature)
}

/// Hashes and signs message using RSASSA-PKCS1-v1_5 with SHA-512.
///
/// # Arguments
/// * `private`: RSA private key used to produce the signature.
/// * `msg`: Message bytes to hash and sign.
///
/// # Returns
/// PKCS#1 v1.5 RSA signature bytes.
pub fn noxtls_rsassa_sha512_sign(private: &RsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    private.sign_pkcs1_v15_sha512(msg)
}

/// Hashes and verifies message using RSASSA-PKCS1-v1_5 with SHA-512.
///
/// # Arguments
/// * `public`: RSA public key used to verify the signature.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_sha512_verify(public: &RsaPublicKey, msg: &[u8], signature: &[u8]) -> Result<()> {
    public.verify_pkcs1_v15_sha512(msg, signature)
}

/// Signs message using RSASSA-PSS with SHA-256 and caller-provided salt.
///
/// # Arguments
/// * `private`: RSA private key used to sign.
/// * `msg`: Message bytes to hash and sign.
/// * `salt`: Caller-provided random salt used by PSS encoding.
///
/// # Returns
/// RSASSA-PSS signature bytes.
pub fn noxtls_rsassa_pss_sha256_sign(private: &RsaPrivateKey, msg: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    private.sign_pss_sha256(msg, salt)
}

/// Signs message using RSASSA-PSS with SHA-256 and DRBG-generated salt.
///
/// # Arguments
/// * `private`: RSA private key used to sign.
/// * `msg`: Message bytes to hash and sign.
/// * `drbg`: DRBG used to generate PSS salt bytes.
/// * `salt_len`: Requested salt length in bytes.
///
/// # Returns
/// RSASSA-PSS signature bytes.
pub fn noxtls_rsassa_pss_sha256_sign_auto(
    private: &RsaPrivateKey,
    msg: &[u8],
    drbg: &mut HmacDrbgSha256,
    salt_len: usize,
) -> Result<Vec<u8>> {
    let salt = drbg.generate(salt_len, b"rsa_pss_sha256_salt")?;
    private.sign_pss_sha256(msg, &salt)
}

/// Verifies RSASSA-PSS signature for SHA-256 with expected salt length.
///
/// # Arguments
/// * `public`: RSA public key used to verify.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
/// * `salt_len`: Expected salt length used in PSS encoding.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_pss_sha256_verify(
    public: &RsaPublicKey,
    msg: &[u8],
    signature: &[u8],
    salt_len: usize,
) -> Result<()> {
    public.verify_pss_sha256(msg, signature, salt_len)
}

/// Signs message using RSASSA-PSS with SHA-384 and caller-provided salt.
///
/// # Arguments
/// * `private`: RSA private key used to sign.
/// * `msg`: Message bytes to hash and sign.
/// * `salt`: Caller-provided random salt used by PSS encoding.
///
/// # Returns
/// RSASSA-PSS signature bytes.
pub fn noxtls_rsassa_pss_sha384_sign(private: &RsaPrivateKey, msg: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    private.sign_pss_sha384(msg, salt)
}

/// Signs message using RSASSA-PSS with SHA-384 and DRBG-generated salt.
///
/// # Arguments
/// * `private`: RSA private key used to sign.
/// * `msg`: Message bytes to hash and sign.
/// * `drbg`: DRBG used to generate PSS salt bytes.
/// * `salt_len`: Requested salt length in bytes.
///
/// # Returns
/// RSASSA-PSS signature bytes.
pub fn noxtls_rsassa_pss_sha384_sign_auto(
    private: &RsaPrivateKey,
    msg: &[u8],
    drbg: &mut HmacDrbgSha256,
    salt_len: usize,
) -> Result<Vec<u8>> {
    let salt = drbg.generate(salt_len, b"rsa_pss_sha384_salt")?;
    private.sign_pss_sha384(msg, &salt)
}

/// Verifies RSASSA-PSS signature for SHA-384 with expected salt length.
///
/// # Arguments
/// * `public`: RSA public key used to verify.
/// * `msg`: Original message bytes.
/// * `signature`: Signature bytes to validate.
/// * `salt_len`: Expected salt length used in PSS encoding.
///
/// # Returns
/// `Ok(())` when the signature is valid.
pub fn noxtls_rsassa_pss_sha384_verify(
    public: &RsaPublicKey,
    msg: &[u8],
    signature: &[u8],
    salt_len: usize,
) -> Result<()> {
    public.verify_pss_sha384(msg, signature, salt_len)
}

/// Encrypts plaintext using RSAES-PKCS1-v1_5 with DRBG-generated non-zero padding.
///
/// # Arguments
/// * `public`: RSA public key used to encrypt.
/// * `plaintext`: Plaintext bytes to encrypt.
/// * `drbg`: DRBG used to generate PKCS#1 v1.5 PS bytes.
///
/// # Returns
/// Ciphertext bytes padded to modulus length.
pub fn noxtls_rsaes_pkcs1_v15_encrypt_auto(
    public: &RsaPublicKey,
    plaintext: &[u8],
    drbg: &mut HmacDrbgSha256,
) -> Result<Vec<u8>> {
    public.encrypt_pkcs1_v15_auto(plaintext, drbg)
}

/// Decrypts RSAES-PKCS1-v1_5 ciphertext.
///
/// # Arguments
/// * `private`: RSA private key used to decrypt.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Decrypted plaintext bytes.
pub fn noxtls_rsaes_pkcs1_v15_decrypt(private: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    private.decrypt_pkcs1_v15(ciphertext)
}

/// Decrypts RSAES-PKCS1-v1_5 ciphertext via CRT-only compatibility API.
///
/// # Arguments
/// * `private`: RSA private key used to decrypt.
/// * `ciphertext`: Ciphertext bytes to decrypt.
///
/// # Returns
/// Decrypted plaintext bytes.
///
/// # Notes
/// This API mirrors the C compatibility surface. Current Rust key material stores
/// `(n, d)` only, so it delegates to standard private exponent decryption while
/// preserving external API shape for parity tracking.
pub fn noxtls_rsaes_pkcs1_v15_decrypt_crt_only(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    private.decrypt_pkcs1_v15_crt_only(ciphertext)
}

/// Encrypts plaintext using RSAES-OAEP with SHA-256 and DRBG-derived seed.
///
/// # Arguments
/// * `public`: RSA public key used to encrypt.
/// * `plaintext`: Plaintext bytes to encrypt.
/// * `label`: OAEP label bytes hashed into encoding parameters.
/// * `drbg`: DRBG used to generate OAEP seed bytes.
///
/// # Returns
/// Ciphertext bytes padded to modulus length.
pub fn noxtls_rsaes_oaep_sha256_encrypt_auto(
    public: &RsaPublicKey,
    plaintext: &[u8],
    label: &[u8],
    drbg: &mut HmacDrbgSha256,
) -> Result<Vec<u8>> {
    public.encrypt_oaep_sha256_auto(plaintext, label, drbg)
}

/// Decrypts RSAES-OAEP ciphertext with SHA-256 and caller-provided label.
///
/// # Arguments
/// * `private`: RSA private key used to decrypt.
/// * `ciphertext`: Ciphertext bytes to decrypt.
/// * `label`: OAEP label bytes hashed into encoding parameters.
///
/// # Returns
/// Decrypted plaintext bytes.
pub fn noxtls_rsaes_oaep_sha256_decrypt(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>> {
    private.decrypt_oaep_sha256(ciphertext, label)
}

/// Decrypts RSAES-OAEP ciphertext via CRT-only compatibility API.
///
/// # Arguments
/// * `private`: RSA private key used to decrypt.
/// * `ciphertext`: Ciphertext bytes to decrypt.
/// * `label`: OAEP label bytes hashed into encoding parameters.
///
/// # Returns
/// Decrypted plaintext bytes.
pub fn noxtls_rsaes_oaep_sha256_decrypt_crt_only(
    private: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>> {
    private.decrypt_oaep_sha256_crt_only(ciphertext, label)
}

const PKCS1_V15_DIGESTINFO_SHA1_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
];
const PKCS1_V15_DIGESTINFO_SHA256_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const PKCS1_V15_DIGESTINFO_SHA384_PREFIX: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const PKCS1_V15_DIGESTINFO_SHA512_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Encodes digest bytes into EMSA-PKCS1-v1_5 block for modulus length `k`.
///
/// # Arguments
///
/// * `hash` — `&[u8]`.
/// * `digest_info_prefix` — `&[u8]`.
/// * `k` — `usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from `emsa_pkcs1_v15_encode`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn emsa_pkcs1_v15_encode(hash: &[u8], digest_info_prefix: &[u8], k: usize) -> Result<Vec<u8>> {
    let t_len = digest_info_prefix.len() + hash.len();
    if k < t_len + 11 {
        return Err(Error::InvalidLength("rsa modulus too short for pkcs1 v1.5"));
    }
    let ps_len = k - t_len - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(core::iter::repeat_n(0xff_u8, ps_len));
    em.push(0x00);
    em.extend_from_slice(digest_info_prefix);
    em.extend_from_slice(hash);
    Ok(em)
}

/// Encodes a message hash using EMSA-PSS (SHA-256) with caller-provided salt.
///
/// # Arguments
///
/// * `m_hash` — 32-byte message digest.
/// * `salt` — PSS salt bytes.
/// * `em_bits` — Effective encoded message bit length.
/// * `em_len` — Encoded message byte length `em_bits` maps to.
///
/// # Returns
///
/// On success, the encoded message bytes.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when the modulus is too short for the chosen parameters.
///
/// # Panics
///
/// This function does not panic.
fn emsa_pss_encode_sha256(
    m_hash: &[u8; 32],
    salt: &[u8],
    em_bits: usize,
    em_len: usize,
) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 32;
    if em_len < HASH_LEN + salt.len() + 2 {
        return Err(Error::InvalidLength("rsa modulus too short for pss"));
    }

    let mut m_prime = vec![0_u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let h = noxtls_sha256(&m_prime);

    let ps_len = em_len - salt.len() - HASH_LEN - 2;
    let mut db = vec![0_u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(salt);

    let db_mask = mgf1_sha256(&h, em_len - HASH_LEN - 1)?;
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }

    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 {
        db[0] &= 0xff_u8 >> unused_bits;
    }

    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

/// Verifies an EMSA-PSS (SHA-256) encoded message block against a digest and salt length.
///
/// # Arguments
///
/// * `m_hash` — Expected 32-byte message digest.
/// * `em` — Encoded message bytes to verify.
/// * `em_bits` — Effective encoded message bit length.
/// * `salt_len` — Expected salt byte length embedded in the encoding.
///
/// # Returns
///
/// `Ok(())` when the PSS structure and digest match.
///
/// # Errors
///
/// Returns `noxtls_core::Error` on malformed padding, hash mismatch, or insufficient length.
///
/// # Panics
///
/// This function does not panic.
fn emsa_pss_verify_sha256(
    m_hash: &[u8; 32],
    em: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<()> {
    const HASH_LEN: usize = 32;
    if em.len() < HASH_LEN + salt_len + 2 {
        return Err(Error::InvalidLength("rsa modulus too short for pss"));
    }
    if em.last().copied() != Some(0xbc) {
        return Err(Error::CryptoFailure("RSA verification failed"));
    }

    let db_len = em.len() - HASH_LEN - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..HASH_LEN];

    let unused_bits = 8 * em.len() - em_bits;
    if unused_bits > 0 {
        let mask = 0xff_u8 << (8 - unused_bits);
        if masked_db[0] & mask != 0 {
            return Err(Error::CryptoFailure("RSA verification failed"));
        }
    }

    let db_mask = mgf1_sha256(h, db_len)?;
    let mut db = masked_db.to_vec();
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }
    if unused_bits > 0 {
        db[0] &= 0xff_u8 >> unused_bits;
    }

    let ps_len = em.len() - HASH_LEN - salt_len - 2;
    if !ct_all_zero(&db[..ps_len]) || db[ps_len] != 0x01 {
        return Err(Error::CryptoFailure("RSA verification failed"));
    }
    let salt = &db[db.len() - salt_len..];

    let mut m_prime = vec![0_u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let expected_h = noxtls_sha256(&m_prime);
    if ct_bytes_eq(expected_h.as_slice(), h) {
        Ok(())
    } else {
        Err(Error::CryptoFailure("RSA verification failed"))
    }
}

/// Encodes a message hash using EMSA-PSS (SHA-384) with caller-provided salt.
///
/// # Arguments
///
/// * `m_hash` — 48-byte message digest.
/// * `salt` — PSS salt bytes.
/// * `em_bits` — Effective encoded message bit length.
/// * `em_len` — Encoded message byte length.
///
/// # Returns
///
/// On success, the encoded message bytes.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when the modulus is too short for the chosen parameters.
///
/// # Panics
///
/// This function does not panic.
fn emsa_pss_encode_sha384(
    m_hash: &[u8; 48],
    salt: &[u8],
    em_bits: usize,
    em_len: usize,
) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 48;
    if em_len < HASH_LEN + salt.len() + 2 {
        return Err(Error::InvalidLength("rsa modulus too short for pss"));
    }

    let mut m_prime = vec![0_u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let h = noxtls_sha384(&m_prime);

    let ps_len = em_len - salt.len() - HASH_LEN - 2;
    let mut db = vec![0_u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(salt);

    let db_mask = mgf1_sha384(&h, em_len - HASH_LEN - 1)?;
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }

    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 {
        db[0] &= 0xff_u8 >> unused_bits;
    }

    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

/// Verifies an EMSA-PSS (SHA-384) encoded message block against a digest and salt length.
///
/// # Arguments
///
/// * `m_hash` — Expected 48-byte message digest.
/// * `em` — Encoded message bytes to verify.
/// * `em_bits` — Effective encoded message bit length.
/// * `salt_len` — Expected salt byte length.
///
/// # Returns
///
/// `Ok(())` when the PSS structure and digest match.
///
/// # Errors
///
/// Returns `noxtls_core::Error` on malformed padding, hash mismatch, or insufficient length.
///
/// # Panics
///
/// This function does not panic.
fn emsa_pss_verify_sha384(
    m_hash: &[u8; 48],
    em: &[u8],
    em_bits: usize,
    salt_len: usize,
) -> Result<()> {
    const HASH_LEN: usize = 48;
    if em.len() < HASH_LEN + salt_len + 2 {
        return Err(Error::InvalidLength("rsa modulus too short for pss"));
    }
    if em.last().copied() != Some(0xbc) {
        return Err(Error::CryptoFailure("RSA verification failed"));
    }

    let db_len = em.len() - HASH_LEN - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..HASH_LEN];

    let unused_bits = 8 * em.len() - em_bits;
    if unused_bits > 0 {
        let mask = 0xff_u8 << (8 - unused_bits);
        if masked_db[0] & mask != 0 {
            return Err(Error::CryptoFailure("RSA verification failed"));
        }
    }

    let db_mask = mgf1_sha384(h, db_len)?;
    let mut db = masked_db.to_vec();
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }
    if unused_bits > 0 {
        db[0] &= 0xff_u8 >> unused_bits;
    }

    let ps_len = em.len() - HASH_LEN - salt_len - 2;
    if !ct_all_zero(&db[..ps_len]) || db[ps_len] != 0x01 {
        return Err(Error::CryptoFailure("RSA verification failed"));
    }
    let salt = &db[db.len() - salt_len..];

    let mut m_prime = vec![0_u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let expected_h = noxtls_sha384(&m_prime);
    if ct_bytes_eq(expected_h.as_slice(), h) {
        Ok(())
    } else {
        Err(Error::CryptoFailure("RSA verification failed"))
    }
}

/// Implements MGF1 using SHA-256. Parameters: `seed` mask-generation seed and `out_len` requested mask length.
///
/// # Arguments
///
/// * `seed` — `&[u8]`.
/// * `out_len` — `usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from `mgf1_sha256`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mgf1_sha256(seed: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0_u32;
    while out.len() < out_len {
        if counter == u32::MAX {
            return Err(Error::InvalidLength("mgf1 output too large"));
        }
        let mut block_input = Vec::with_capacity(seed.len() + 4);
        block_input.extend_from_slice(seed);
        block_input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&noxtls_sha256(&block_input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    Ok(out)
}

/// Implements MGF1 using SHA-384.
///
/// # Arguments
///
/// * `seed` — `&[u8]`.
/// * `out_len` — `usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from `mgf1_sha384`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn mgf1_sha384(seed: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0_u32;
    while out.len() < out_len {
        if counter == u32::MAX {
            return Err(Error::InvalidLength("mgf1 output too large"));
        }
        let mut block_input = Vec::with_capacity(seed.len() + 4);
        block_input.extend_from_slice(seed);
        block_input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&noxtls_sha384(&block_input));
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    Ok(out)
}

/// Builds DRBG-backed non-zero PKCS#1 v1.5 padding bytes for encryption.
///
/// # Arguments
///
/// * `drbg` — `&mut HmacDrbgSha256`.
/// * `len` — `usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from `drbg_nonzero_padding`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn drbg_nonzero_padding(drbg: &mut HmacDrbgSha256, len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let block = drbg.generate(len.saturating_sub(out.len()), b"rsa_pkcs1_v15_ps")?;
        for byte in block {
            if byte != 0 {
                out.push(byte);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// Encodes a message with EME-OAEP-SHA256 using a caller-provided seed.
///
/// # Arguments
///
/// * `plaintext` — Message bytes to encode.
/// * `label` — OAEP label bytes.
/// * `seed` — 32-byte seed (must match `HASH_LEN`).
/// * `k` — Modulus byte length (encoded message size target).
///
/// # Returns
///
/// On success, the encoded message as a byte vector of length `k`.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when lengths are inconsistent with OAEP-SHA256 constraints.
///
/// # Panics
///
/// This function does not panic.
fn emea_oaep_encode_sha256(
    plaintext: &[u8],
    label: &[u8],
    seed: &[u8],
    k: usize,
) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 32;
    if seed.len() != HASH_LEN {
        return Err(Error::InvalidLength("rsa oaep seed must be 32 bytes"));
    }
    if k < (2 * HASH_LEN + 2) {
        return Err(Error::InvalidLength(
            "rsa modulus too short for oaep sha256",
        ));
    }
    if plaintext.len() > k - (2 * HASH_LEN + 2) {
        return Err(Error::InvalidLength(
            "rsa plaintext too long for oaep sha256",
        ));
    }
    let l_hash = noxtls_sha256(label);
    let ps_len = k - plaintext.len() - (2 * HASH_LEN + 2);
    let mut db = Vec::with_capacity(k - HASH_LEN - 1);
    db.extend_from_slice(&l_hash);
    db.extend(core::iter::repeat_n(0_u8, ps_len));
    db.push(0x01);
    db.extend_from_slice(plaintext);
    let db_mask = mgf1_sha256(seed, k - HASH_LEN - 1)?;
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }
    let seed_mask = mgf1_sha256(&db, HASH_LEN)?;
    let mut masked_seed = seed.to_vec();
    for (byte, mask) in masked_seed.iter_mut().zip(seed_mask.iter()) {
        *byte ^= *mask;
    }
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&db);
    Ok(em)
}

/// Decodes EME-OAEP encoded bytes using SHA-256 and caller-provided label.
///
/// # Arguments
///
/// * `encoded` — `&[u8]`.
/// * `label` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_oaep_sha256_plaintext`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_oaep_sha256_plaintext(encoded: &[u8], label: &[u8]) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 32;
    if encoded.len() < (2 * HASH_LEN + 2) {
        return Err(Error::InvalidLength(
            "rsa modulus too short for oaep sha256",
        ));
    }
    let mut invalid = 0_u8;
    invalid |= encoded[0];
    let (masked_seed, masked_db) = encoded[1..].split_at(HASH_LEN);
    let seed_mask = mgf1_sha256(masked_db, HASH_LEN)?;
    let mut seed = masked_seed.to_vec();
    for (byte, mask) in seed.iter_mut().zip(seed_mask.iter()) {
        *byte ^= *mask;
    }
    let db_mask = mgf1_sha256(&seed, masked_db.len())?;
    let mut db = masked_db.to_vec();
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }
    let expected_l_hash = noxtls_sha256(label);
    invalid |= u8::from(!ct_bytes_eq(&db[..HASH_LEN], expected_l_hash.as_slice()));
    let rest = &db[HASH_LEN..];
    let mut marker_idx = 0_usize;
    let mut found_marker = 0_u8;
    let mut invalid_ps = 0_u8;
    for (idx, &byte) in rest.iter().enumerate() {
        let is_zero = u8::from(byte == 0);
        let is_one = u8::from(byte == 1);
        let before_marker = 1_u8 ^ found_marker;
        let should_set = before_marker & is_one;
        marker_idx = ct_select_usize(should_set, idx, marker_idx);
        invalid_ps |= before_marker & (1_u8 ^ is_zero) & (1_u8 ^ is_one);
        found_marker |= is_one;
    }
    invalid |= invalid_ps;
    invalid |= 1_u8 ^ found_marker;
    if invalid != 0 {
        return Err(Error::CryptoFailure("rsa decryption failed"));
    }
    Ok(rest[marker_idx.saturating_add(1)..].to_vec())
}

/// Decodes PKCS#1 v1.5 encoded message and returns plaintext.
///
/// # Arguments
///
/// * `encoded` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `decode_pkcs1_v15_plaintext`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn decode_pkcs1_v15_plaintext(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.len() < 11 {
        return Err(Error::CryptoFailure("rsa decryption failed"));
    }
    let mut invalid = 0_u8;
    invalid |= encoded[0];
    invalid |= encoded[1] ^ 0x02;

    let mut sep_idx = 0_usize;
    let mut found_sep = 0_u8;
    for (idx, &byte) in encoded.iter().enumerate().skip(2) {
        let is_zero = u8::from(byte == 0);
        let should_set = is_zero & (1_u8 ^ found_sep);
        sep_idx = ct_select_usize(should_set, idx, sep_idx);
        found_sep |= is_zero;
    }
    if found_sep == 0 {
        invalid |= 1;
    }
    if sep_idx < 10 {
        invalid |= 1;
    }
    if invalid != 0 {
        return Err(Error::CryptoFailure("rsa decryption failed"));
    }
    Ok(encoded[sep_idx + 1..].to_vec())
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

/// Returns true when every byte in one slice is zero without early exit. Parameter: `bytes` candidate slice.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// `bool` produced by `ct_all_zero` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ct_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0_u8;
    for &byte in bytes {
        acc |= byte;
    }
    acc == 0
}

/// Selects one of two usize values using one-byte selector without branch-on-secret. Parameters: `selector` must be 0 or 1, `if_one` selected when 1, `if_zero` when 0.
///
/// # Arguments
///
/// * `selector` — `u8`.
/// * `if_one` — `usize`.
/// * `if_zero` — `usize`.
///
/// # Returns
///
/// `usize` produced by `ct_select_usize` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn ct_select_usize(selector: u8, if_one: usize, if_zero: usize) -> usize {
    let mask = (0_usize).wrapping_sub(usize::from(selector));
    (if_one & mask) | (if_zero & !mask)
}

/// Validates RSA private-key scalar components before private operations.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
/// * `d` — `&BigUint`.
///
/// # Returns
///
/// On success, the `Ok` payload from `validate_private_components`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn validate_private_components(n: &BigUint, d: &BigUint) -> Result<()> {
    validate_modulus(n)?;
    if d.is_zero() {
        return Err(Error::CryptoFailure(
            "rsa private exponent must be non-zero",
        ));
    }
    if !d.is_odd() {
        return Err(Error::CryptoFailure("rsa private exponent must be odd"));
    }
    if d.cmp(n).is_ge() {
        return Err(Error::CryptoFailure(
            "rsa private exponent must be smaller than modulus",
        ));
    }
    Ok(())
}

/// Validates RSA public-key scalar components before public operations.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
/// * `e` — `&BigUint`.
///
/// # Returns
///
/// On success, the `Ok` payload from `validate_public_components`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn validate_public_components(n: &BigUint, e: &BigUint) -> Result<()> {
    validate_modulus(n)?;
    let three = BigUint::from_u128(3);
    if e.cmp(&three).is_lt() {
        return Err(Error::CryptoFailure(
            "rsa public exponent must be at least 3",
        ));
    }
    if !e.is_odd() {
        return Err(Error::CryptoFailure("rsa public exponent must be odd"));
    }
    if e.cmp(n).is_ge() {
        return Err(Error::CryptoFailure(
            "rsa public exponent must be smaller than modulus",
        ));
    }
    Ok(())
}

/// Validates shared modulus requirements for RSA public/private keys.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
///
/// # Returns
///
/// On success, the `Ok` payload from `validate_modulus`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn validate_modulus(n: &BigUint) -> Result<()> {
    let three = BigUint::from_u128(3);
    if n.cmp(&three).is_lt() {
        return Err(Error::CryptoFailure("rsa modulus must be greater than 3"));
    }
    if !n.is_odd() {
        return Err(Error::CryptoFailure("rsa modulus must be odd"));
    }
    Ok(())
}

/// Validates CRT parameter relationships for a private RSA key.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
/// * `crt` — `&RsaPrivateCrtComponents`.
///
/// # Returns
///
/// On success, the `Ok` payload from `validate_crt_components`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when validation or a numeric step fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn validate_crt_components(n: &BigUint, crt: &RsaPrivateCrtComponents) -> Result<()> {
    if crt.p.is_zero()
        || crt.q.is_zero()
        || crt.dp.is_zero()
        || crt.dq.is_zero()
        || crt.qinv.is_zero()
    {
        return Err(Error::CryptoFailure("rsa crt parameters must be non-zero"));
    }
    if !crt.p.is_odd() || !crt.q.is_odd() {
        return Err(Error::CryptoFailure("rsa crt primes must be odd"));
    }
    if crt.p.mul(&crt.q).cmp(n).is_ne() {
        return Err(Error::CryptoFailure(
            "rsa crt prime product must equal modulus",
        ));
    }
    if crt.dp.cmp(&crt.p).is_ge() || crt.dq.cmp(&crt.q).is_ge() {
        return Err(Error::CryptoFailure("rsa crt exponents must be reduced"));
    }
    if crt.qinv.cmp(&crt.p).is_ge() {
        return Err(Error::CryptoFailure(
            "rsa crt coefficient must be smaller than p",
        ));
    }
    let one = BigUint::one();
    if crt.q.mul(&crt.qinv).modulo(&crt.p).cmp(&one).is_ne() {
        return Err(Error::CryptoFailure(
            "rsa crt coefficient must be inverse of q modulo p",
        ));
    }
    Ok(())
}

/// Samples odd RSA prime candidates until one passes primality and coprimality checks.
///
/// # Arguments
///
/// * `bits` — Desired prime bit width.
/// * `e` — Public exponent used for the gcd(`p-1`, `e`) test.
/// * `drbg` — DRBG source for random candidates.
///
/// # Returns
///
/// On success, a probable prime `BigUint` of the requested width.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when randomness is unavailable or generation exhausts its attempt budget.
///
/// # Panics
///
/// This function does not panic.
fn generate_rsa_prime_candidate_auto(
    bits: usize,
    e: &BigUint,
    drbg: &mut HmacDrbgSha256,
) -> Result<BigUint> {
    let one = BigUint::one();
    let mut attempts = 0_u32;
    while attempts < 20_000 {
        let candidate = random_biguint_with_bits(bits, drbg, b"rsa_prime_candidate")?;
        if candidate.bit_len() != bits {
            attempts = attempts.saturating_add(1);
            continue;
        }
        if !is_probable_prime(&candidate) {
            attempts = attempts.saturating_add(1);
            continue;
        }
        let pm1 = candidate.sub(&one);
        if BigUint::gcd(e, &pm1).cmp(&one).is_eq() {
            return Ok(candidate);
        }
        attempts = attempts.saturating_add(1);
    }
    Err(Error::StateError(
        "rsa prime generation exhausted attempt budget",
    ))
}

/// Samples a random odd `BigUint` with an exact bit width from DRBG output.
///
/// # Arguments
///
/// * `bits` — Target bit width (at least 2).
/// * `drbg` — DRBG used to draw random bytes.
/// * `label` — Domain separation label passed to `drbg.generate`.
///
/// # Returns
///
/// On success, an odd integer occupying exactly `bits` bits.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when `bits` is too small or DRBG output is insufficient.
///
/// # Panics
///
/// This function does not panic.
fn random_biguint_with_bits(
    bits: usize,
    drbg: &mut HmacDrbgSha256,
    label: &[u8],
) -> Result<BigUint> {
    if bits < 2 {
        return Err(Error::InvalidLength(
            "rsa prime candidate bits must be at least 2",
        ));
    }
    let byte_len = bits.div_ceil(8);
    let mut random = drbg.generate(byte_len, label)?;
    let top_bits = bits % 8;
    if top_bits != 0 {
        random[0] &= (1_u8 << top_bits) - 1;
    }
    let high_bit_index = (bits - 1) % 8;
    random[0] |= 1_u8 << high_bit_index;
    let last = random.len() - 1;
    random[last] |= 1;
    Ok(BigUint::from_be_bytes(&random))
}

/// Performs probabilistic primality check for BigUint candidates.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
///
/// # Returns
///
/// `bool` produced by `is_probable_prime` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn is_probable_prime(n: &BigUint) -> bool {
    let two = BigUint::from_u128(2);
    if n.cmp(&two).is_lt() {
        return false;
    }
    for small in [2_u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let small_bn = BigUint::from_u128(u128::from(small));
        if n.cmp(&small_bn).is_eq() {
            return true;
        }
        if n.mod_u32(small) == 0 {
            return false;
        }
    }
    let one = BigUint::one();
    let n_minus_one = n.sub(&one);
    let mut d = n_minus_one.clone();
    let mut s = 0_u32;
    while d.is_even() {
        d = d.shr1();
        s = s.saturating_add(1);
    }
    for witness in [2_u32, 3, 5, 7, 11, 13, 17, 19, 23, 29] {
        if !miller_rabin_round(n, &d, s, witness) {
            return false;
        }
    }
    true
}

/// Runs one Miller-Rabin witness round for one odd candidate.
///
/// # Arguments
///
/// * `n` — `&BigUint`.
/// * `d` — `&BigUint`.
/// * `s` — `u32`.
/// * `witness` — `u32`.
///
/// # Returns
///
/// `bool` produced by `miller_rabin_round` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn miller_rabin_round(n: &BigUint, d: &BigUint, s: u32, witness: u32) -> bool {
    let a = BigUint::from_u128(u128::from(witness)).modulo(n);
    if a.is_zero() {
        return true;
    }
    let one = BigUint::one();
    let n_minus_one = n.sub(&one);
    let mut x = BigUint::mod_exp(&a, d, n);
    if x.cmp(&one).is_eq() || x.cmp(&n_minus_one).is_eq() {
        return true;
    }
    for _ in 1..s {
        x = x.mul(&x).modulo(n);
        if x.cmp(&n_minus_one).is_eq() {
            return true;
        }
    }
    false
}

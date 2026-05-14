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

//! ML-KEM wrappers used by TLS 1.3 PQ key-share integration.
//!
//! This module keeps the existing noxtls API surface while delegating core
//! ML-KEM-768 operations to the RustCrypto `ml-kem` implementation aligned with
//! FIPS 203 semantics.

use crate::drbg::HmacDrbgSha256;
#[cfg(not(feature = "std"))]
use crate::internal_alloc::Vec;
use ml_kem::kem::Decapsulate;
use ml_kem::{
    B32, Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use noxtls_core::{Error, Result};

type MlKem768DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;
type MlKem768EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
type MlKem768DecapsulationKeyEncoded = Encoded<MlKem768DecapsulationKey>;
type MlKem768EncapsulationKeyEncoded = Encoded<MlKem768EncapsulationKey>;
type MlKem768CiphertextEncoded = Ciphertext<MlKem768>;

/// Byte length of ML-KEM-768 encoded decapsulation keys.
pub const MLKEM_PRIVATE_KEY_LEN: usize = 2_400;

/// Byte length of ML-KEM-768 encoded encapsulation keys.
pub const MLKEM_PUBLIC_KEY_LEN: usize = 1_184;

/// Byte length used for the TLS 1.3 ML-KEM-768 ciphertext payload.
pub const MLKEM_CIPHERTEXT_LEN: usize = 1_088;

/// Byte length used by ML-KEM-768 shared secrets.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// DRBG label used to derive deterministic keygen seed `d`.
const MLKEM_KEYGEN_D_LABEL: &[u8] = b"mlkem keygen d";
/// DRBG label used to derive deterministic keygen seed `z`.
const MLKEM_KEYGEN_Z_LABEL: &[u8] = b"mlkem keygen z";
/// DRBG label used to derive deterministic encapsulation message seed `m`.
const MLKEM_ENCAP_M_LABEL: &[u8] = b"mlkem encapsulate m";

/// Holds one ML-KEM-768 decapsulation key.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MlKemPrivateKey {
    bytes: Vec<u8>,
}

impl MlKemPrivateKey {
    /// Builds an ML-KEM-768 private key from encoded bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` — Encoded private key bytes; length must be `MLKEM_PRIVATE_KEY_LEN`.
    ///
    /// # Returns
    ///
    /// Parsed [`MlKemPrivateKey`] wrapper containing an owned encoded key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `bytes` is not 2400 bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM_PRIVATE_KEY_LEN {
            return Err(Error::InvalidLength("mlkem private key must be 2400 bytes"));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Derives the matching ML-KEM-768 public key from this private key.
    ///
    /// # Arguments
    ///
    /// * `self` — Encoded decapsulation key wrapper.
    ///
    /// # Returns
    ///
    /// On success, the corresponding [`MlKemPublicKey`] encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] if the key bytes cannot be parsed by the ML-KEM backend.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn public_key(&self) -> Result<MlKemPublicKey> {
        let private = noxtls_mlkem_parse_private_key(self.as_bytes())?;
        let public = private.encapsulation_key().as_bytes();
        Ok(MlKemPublicKey {
            bytes: public.as_slice().to_vec(),
        })
    }

    /// Returns the encoded private-key bytes.
    ///
    /// # Arguments
    ///
    /// * `self` — Encoded private key wrapper.
    ///
    /// # Returns
    ///
    /// Immutable slice of encoded private-key bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Overwrites and clears stored private-key bytes.
    ///
    /// # Arguments
    ///
    /// * `self` — Mutable key wrapper to scrub.
    ///
    /// # Returns
    ///
    /// `()` after zeroing and truncating internal storage.
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
    /// Scrubs private-key bytes when the wrapper is dropped.
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
    ///
    /// * `bytes` — Encoded public key bytes; length must be `MLKEM_PUBLIC_KEY_LEN`.
    ///
    /// # Returns
    ///
    /// Parsed [`MlKemPublicKey`] wrapper containing an owned encoded key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `bytes` is not 1184 bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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
    /// # Arguments
    ///
    /// * `self` — Encoded public key wrapper.
    ///
    /// # Returns
    ///
    /// Immutable slice of encoded public-key bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generates an ML-KEM-768 keypair from DRBG entropy.
///
/// # Arguments
///
/// * `drbg` — DRBG instance used to derive deterministic ML-KEM seeds (`d`, `z`).
///
/// # Returns
///
/// On success, `(private, public)` wrappers with encoded ML-KEM-768 key material.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] if DRBG output fails or generated key sizes are inconsistent.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_mlkem_generate_keypair_auto(
    drbg: &mut HmacDrbgSha256,
) -> Result<(MlKemPrivateKey, MlKemPublicKey)> {
    let d = noxtls_mlkem_generate_b32_from_drbg(drbg, MLKEM_KEYGEN_D_LABEL)?;
    let z = noxtls_mlkem_generate_b32_from_drbg(drbg, MLKEM_KEYGEN_Z_LABEL)?;
    let (private, public) = MlKem768::generate_deterministic(&d, &z);

    let private_bytes = private.as_bytes();
    let public_bytes = public.as_bytes();
    if private_bytes.len() != MLKEM_PRIVATE_KEY_LEN || public_bytes.len() != MLKEM_PUBLIC_KEY_LEN {
        return Err(Error::CryptoFailure("ml-kem backend encoded length mismatch"));
    }

    Ok((
        MlKemPrivateKey {
            bytes: private_bytes.as_slice().to_vec(),
        },
        MlKemPublicKey {
            bytes: public_bytes.as_slice().to_vec(),
        },
    ))
}

/// Encapsulates one shared secret to an ML-KEM-768 public key.
///
/// # Arguments
///
/// * `public_key` — Recipient ML-KEM-768 encapsulation key.
/// * `drbg` — DRBG used to derive deterministic encapsulation message seed `m`.
///
/// # Returns
///
/// On success, `(ciphertext, shared_secret)` where ciphertext is 1088 bytes and shared secret is 32 bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] if key decoding fails, DRBG output fails, or encapsulation fails.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_mlkem_encapsulate_auto(
    public_key: &MlKemPublicKey,
    drbg: &mut HmacDrbgSha256,
) -> Result<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_LEN])> {
    let backend_public_key = noxtls_mlkem_parse_public_key(public_key.as_bytes())?;
    let m = noxtls_mlkem_generate_b32_from_drbg(drbg, MLKEM_ENCAP_M_LABEL)?;
    let (ciphertext, shared_secret) = backend_public_key
        .encapsulate_deterministic(&m)
        .map_err(|_| Error::CryptoFailure("ml-kem encapsulation failed"))?;

    if ciphertext.len() != MLKEM_CIPHERTEXT_LEN {
        return Err(Error::CryptoFailure("ml-kem backend ciphertext length mismatch"));
    }
    let shared_secret_bytes = noxtls_mlkem_shared_secret_to_array(shared_secret.as_slice())?;
    Ok((ciphertext.as_slice().to_vec(), shared_secret_bytes))
}

/// Decapsulates one ML-KEM-768 ciphertext.
///
/// # Arguments
///
/// * `private_key` — Recipient ML-KEM-768 decapsulation key.
/// * `ciphertext` — Encapsulated bytes; length must be `MLKEM_CIPHERTEXT_LEN`.
///
/// # Returns
///
/// On success, the 32-byte shared secret derived by ML-KEM decapsulation.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when key/ciphertext decoding fails or decapsulation fails.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_mlkem_decapsulate(
    private_key: &MlKemPrivateKey,
    ciphertext: &[u8],
) -> Result<[u8; MLKEM_SHARED_SECRET_LEN]> {
    let backend_private_key = noxtls_mlkem_parse_private_key(private_key.as_bytes())?;
    let backend_ciphertext = noxtls_mlkem_parse_ciphertext(ciphertext)?;
    let shared_secret = backend_private_key
        .decapsulate(&backend_ciphertext)
        .map_err(|_| Error::CryptoFailure("ml-kem decapsulation failed"))?;
    noxtls_mlkem_shared_secret_to_array(shared_secret.as_slice())
}

/// Derives one 32-byte deterministic ML-KEM input from DRBG output.
///
/// # Arguments
///
/// * `drbg` — DRBG state used to generate output bytes.
/// * `label` — Domain-separation label passed to DRBG generation.
///
/// # Returns
///
/// On success, one [`B32`] value suitable for deterministic ML-KEM APIs.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DRBG generation fails or output length is not 32 bytes.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_generate_b32_from_drbg(drbg: &mut HmacDrbgSha256, label: &[u8]) -> Result<B32> {
    let bytes = drbg.generate(MLKEM_SHARED_SECRET_LEN, label)?;
    noxtls_mlkem_parse_b32(bytes.as_slice(), "ml-kem deterministic input must be 32 bytes")
}

/// Converts an input byte slice into ML-KEM `B32` typed bytes.
///
/// # Arguments
///
/// * `bytes` — Raw byte slice expected to be exactly 32 bytes.
/// * `error_message` — Error text used when conversion fails.
///
/// # Returns
///
/// On success, a typed [`B32`] value copied from `bytes`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `bytes` is not exactly 32 bytes.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_parse_b32(bytes: &[u8], error_message: &'static str) -> Result<B32> {
    B32::try_from(bytes).map_err(|_| Error::InvalidLength(error_message))
}

/// Parses encoded ML-KEM private-key bytes into backend key state.
///
/// # Arguments
///
/// * `private_key_bytes` — Encoded private key bytes expected to be 2400 bytes.
///
/// # Returns
///
/// On success, decoded backend decapsulation key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for malformed input length.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_parse_private_key(private_key_bytes: &[u8]) -> Result<MlKem768DecapsulationKey> {
    let encoded = MlKem768DecapsulationKeyEncoded::try_from(private_key_bytes)
        .map_err(|_| Error::InvalidLength("mlkem private key must be 2400 bytes"))?;
    Ok(MlKem768DecapsulationKey::from_bytes(&encoded))
}

/// Parses encoded ML-KEM public-key bytes into backend key state.
///
/// # Arguments
///
/// * `public_key_bytes` — Encoded public key bytes expected to be 1184 bytes.
///
/// # Returns
///
/// On success, decoded backend encapsulation key.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for malformed input length.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_parse_public_key(public_key_bytes: &[u8]) -> Result<MlKem768EncapsulationKey> {
    let encoded = MlKem768EncapsulationKeyEncoded::try_from(public_key_bytes)
        .map_err(|_| Error::InvalidLength("mlkem public key must be 1184 bytes"))?;
    Ok(MlKem768EncapsulationKey::from_bytes(&encoded))
}

/// Parses encoded ciphertext bytes into backend ciphertext representation.
///
/// # Arguments
///
/// * `ciphertext` — Encoded ciphertext expected to be 1088 bytes.
///
/// # Returns
///
/// On success, decoded backend ciphertext value.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] for malformed input length.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_parse_ciphertext(ciphertext: &[u8]) -> Result<MlKem768CiphertextEncoded> {
    MlKem768CiphertextEncoded::try_from(ciphertext)
        .map_err(|_| Error::InvalidLength("mlkem ciphertext must be 1088 bytes"))
}

/// Converts backend shared-secret bytes into a fixed-size array.
///
/// # Arguments
///
/// * `shared_secret` — Byte slice expected to contain exactly 32 bytes.
///
/// # Returns
///
/// On success, a `[u8; 32]` shared secret copy.
///
/// # Errors
///
/// Returns [`Error::CryptoFailure`] when shared-secret length is inconsistent.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_mlkem_shared_secret_to_array(
    shared_secret: &[u8],
) -> Result<[u8; MLKEM_SHARED_SECRET_LEN]> {
    shared_secret
        .try_into()
        .map_err(|_| Error::CryptoFailure("ml-kem backend shared-secret length mismatch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a deterministic DRBG instance for ML-KEM tests.
    ///
    /// # Arguments
    ///
    /// * *(none)* — Test helper uses fixed entropy/nonce/personalization values.
    ///
    /// # Returns
    ///
    /// One initialized [`HmacDrbgSha256`] instance.
    ///
    /// # Panics
    ///
    /// Panics when DRBG initialization fails for fixed test inputs.
    fn noxtls_test_drbg() -> HmacDrbgSha256 {
        HmacDrbgSha256::noxtls_new(
            &[0x42; 32],
            b"mlkem deterministic test nonce",
            b"mlkem deterministic test personalization",
        )
        .expect("deterministic test drbg must initialize")
    }

    /// Verifies wrapper key generation bytes match direct RustCrypto ML-KEM output.
    ///
    /// # Arguments
    ///
    /// * *(none)* — Test derives deterministic seeds from matching DRBG states.
    ///
    /// # Returns
    ///
    /// `()` when encoded wrapper key bytes equal backend deterministic key bytes.
    ///
    /// # Panics
    ///
    /// Panics on unexpected conversion or crypto errors in deterministic test flow.
    #[test]
    fn noxtls_mlkem_keygen_matches_backend_deterministic_material() {
        let mut wrapper_drbg = noxtls_test_drbg();
        let mut backend_drbg = noxtls_test_drbg();
        let (wrapper_private, wrapper_public) =
            noxtls_mlkem_generate_keypair_auto(&mut wrapper_drbg).expect("wrapper keygen");

        let d = noxtls_mlkem_generate_b32_from_drbg(&mut backend_drbg, MLKEM_KEYGEN_D_LABEL)
            .expect("backend d seed");
        let z = noxtls_mlkem_generate_b32_from_drbg(&mut backend_drbg, MLKEM_KEYGEN_Z_LABEL)
            .expect("backend z seed");
        let (backend_private, backend_public) = MlKem768::generate_deterministic(&d, &z);

        assert_eq!(wrapper_private.as_bytes(), backend_private.as_bytes().as_slice());
        assert_eq!(wrapper_public.as_bytes(), backend_public.as_bytes().as_slice());
    }

    /// Verifies wrapper encapsulation and decapsulation match backend deterministic flow.
    ///
    /// # Arguments
    ///
    /// * *(none)* — Test uses fixed DRBG seeds and generated key material.
    ///
    /// # Returns
    ///
    /// `()` when wrapper/backend ciphertext and shared secrets are identical.
    ///
    /// # Panics
    ///
    /// Panics on unexpected conversion or cryptographic errors in test flow.
    #[test]
    fn noxtls_mlkem_encap_decap_matches_backend_deterministic_material() {
        let mut keygen_drbg = noxtls_test_drbg();
        let (wrapper_private, wrapper_public) =
            noxtls_mlkem_generate_keypair_auto(&mut keygen_drbg).expect("wrapper keygen");

        let mut wrapper_encap_drbg = noxtls_test_drbg();
        let mut backend_encap_drbg = noxtls_test_drbg();

        let (wrapper_ciphertext, wrapper_sender_secret) =
            noxtls_mlkem_encapsulate_auto(&wrapper_public, &mut wrapper_encap_drbg)
                .expect("wrapper encapsulation");
        let wrapper_receiver_secret =
            noxtls_mlkem_decapsulate(&wrapper_private, &wrapper_ciphertext).expect("wrapper decap");
        assert_eq!(wrapper_sender_secret, wrapper_receiver_secret);

        let backend_public = noxtls_mlkem_parse_public_key(wrapper_public.as_bytes())
            .expect("backend public parsing");
        let m = noxtls_mlkem_generate_b32_from_drbg(&mut backend_encap_drbg, MLKEM_ENCAP_M_LABEL)
            .expect("backend m seed");
        let (backend_ciphertext, backend_secret) = backend_public
            .encapsulate_deterministic(&m)
            .expect("backend encapsulation");
        assert_eq!(wrapper_ciphertext.as_slice(), backend_ciphertext.as_slice());
        assert_eq!(wrapper_sender_secret.as_slice(), backend_secret.as_slice());
    }
}

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
use noxtls_crypto::{
    rsaes_oaep_sha256_decrypt, rsaes_pkcs1_v15_decrypt, rsassa_pss_sha256_sign, rsassa_sha256_sign,
    x25519_shared_secret, RsaPrivateKey, X25519PrivateKey, X25519PublicKey,
};

/// Opaque external key handle used by providers to locate key material.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExternalKeyHandle {
    id: Vec<u8>,
}

/// Names supported signing operations for external/provider-backed keys.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeySignAlgorithm {
    RsaPkcs1Sha256,
    RsaPssSha256,
}

/// Names supported decryption operations for external/provider-backed keys.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyDecryptAlgorithm {
    RsaPkcs1v15,
    RsaOaepSha256,
}

/// Names supported key-derivation operations for external/provider-backed keys.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyDeriveAlgorithm {
    X25519,
}

/// Carries one provider sign operation request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeySignRequest<'a> {
    pub handle: &'a ExternalKeyHandle,
    pub algorithm: KeySignAlgorithm,
    pub message: &'a [u8],
    pub salt: Option<&'a [u8]>,
}

/// Carries one provider decrypt operation request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyDecryptRequest<'a> {
    pub handle: &'a ExternalKeyHandle,
    pub algorithm: KeyDecryptAlgorithm,
    pub ciphertext: &'a [u8],
    pub label: Option<&'a [u8]>,
}

/// Carries one provider key-derivation operation request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyDeriveRequest<'a> {
    pub handle: &'a ExternalKeyHandle,
    pub algorithm: KeyDeriveAlgorithm,
    pub peer_public_key: &'a [u8],
}

/// Trait boundary for external key operations backed by software, HSM, or remote KMS providers.
pub trait ExternalKeyProvider {
    /// Performs a provider-backed signing operation.
    ///
    /// # Arguments
    ///
    /// * `request` — Sign request carrying handle, algorithm, message bytes, and optional salt.
    ///
    /// # Returns
    ///
    /// Signature bytes produced by the configured provider.
    ///
    /// # Errors
    ///
    /// Returns provider or algorithm errors when key lookup, input validation, or signing fails.
    fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>>;

    /// Performs a provider-backed decryption operation.
    ///
    /// # Arguments
    ///
    /// * `request` — Decrypt request carrying handle, algorithm, ciphertext, and optional OAEP label.
    ///
    /// # Returns
    ///
    /// Plaintext bytes produced by the configured provider.
    ///
    /// # Errors
    ///
    /// Returns provider or algorithm errors when key lookup, input validation, or decrypt fails.
    fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>>;

    /// Performs a provider-backed key-derivation operation.
    ///
    /// # Arguments
    ///
    /// * `request` — Derive request carrying handle, algorithm, and peer public key bytes.
    ///
    /// # Returns
    ///
    /// Derived shared secret bytes.
    ///
    /// # Errors
    ///
    /// Returns provider or algorithm errors when key lookup, input validation, or derivation fails.
    fn derive_shared_secret(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>>;
}

/// In-tree software provider implementing the same external key-provider trait boundary.
#[derive(Debug, Clone, Default)]
pub struct SoftwareKeyProvider {
    rsa_signing_keys: Vec<(ExternalKeyHandle, RsaPrivateKey)>,
    rsa_decrypt_keys: Vec<(ExternalKeyHandle, RsaPrivateKey)>,
    x25519_keys: Vec<(ExternalKeyHandle, X25519PrivateKey)>,
}

impl ExternalKeyHandle {
    /// Creates one external key handle from raw identifier bytes.
    ///
    /// # Arguments
    ///
    /// * `id` — Opaque key identifier bytes used by provider lookup logic.
    ///
    /// # Returns
    ///
    /// `ExternalKeyHandle` wrapping `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `id` is empty.
    pub fn new(id: &[u8]) -> Result<Self> {
        if id.is_empty() {
            return Err(Error::InvalidLength("external key handle must not be empty"));
        }
        Ok(Self { id: id.to_vec() })
    }

    /// Borrows the opaque identifier bytes for provider adapter conversions.
    ///
    /// # Arguments
    ///
    /// * `self` — External key handle whose identifier bytes are required.
    ///
    /// # Returns
    ///
    /// Borrowed opaque identifier bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.id
    }
}

impl SoftwareKeyProvider {
    /// Creates an empty software provider with no registered keys.
    ///
    /// # Returns
    ///
    /// New provider instance ready for key registration.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one RSA key handle for signing operations.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle associated with `key`.
    /// * `key` — RSA private key used for sign requests.
    ///
    /// # Returns
    ///
    /// `Ok(())` when key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when `handle` is already registered for signing.
    pub fn register_rsa_signing_key(
        &mut self,
        handle: ExternalKeyHandle,
        key: RsaPrivateKey,
    ) -> Result<()> {
        if self
            .rsa_signing_keys
            .iter()
            .any(|(existing, _)| existing == &handle)
        {
            return Err(Error::StateError(
                "rsa signing key handle is already registered",
            ));
        }
        self.rsa_signing_keys.push((handle, key));
        Ok(())
    }

    /// Registers one RSA key handle for decryption operations.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle associated with `key`.
    /// * `key` — RSA private key used for decrypt requests.
    ///
    /// # Returns
    ///
    /// `Ok(())` when key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when `handle` is already registered for decryption.
    pub fn register_rsa_decryption_key(
        &mut self,
        handle: ExternalKeyHandle,
        key: RsaPrivateKey,
    ) -> Result<()> {
        if self
            .rsa_decrypt_keys
            .iter()
            .any(|(existing, _)| existing == &handle)
        {
            return Err(Error::StateError(
                "rsa decryption key handle is already registered",
            ));
        }
        self.rsa_decrypt_keys.push((handle, key));
        Ok(())
    }

    /// Registers one X25519 key handle for key-derivation operations.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle associated with `key`.
    /// * `key` — X25519 private key used for derive requests.
    ///
    /// # Returns
    ///
    /// `Ok(())` when key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when `handle` is already registered for X25519 derivation.
    pub fn register_x25519_key(
        &mut self,
        handle: ExternalKeyHandle,
        key: X25519PrivateKey,
    ) -> Result<()> {
        if self.x25519_keys.iter().any(|(existing, _)| existing == &handle) {
            return Err(Error::StateError("x25519 key handle is already registered"));
        }
        self.x25519_keys.push((handle, key));
        Ok(())
    }

    /// Looks up one registered RSA signing key by external handle.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle from the incoming sign request.
    ///
    /// # Returns
    ///
    /// Reference to the registered RSA private signing key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when the handle is unknown.
    fn rsa_signing_key(&self, handle: &ExternalKeyHandle) -> Result<&RsaPrivateKey> {
        self.rsa_signing_keys
            .iter()
            .find_map(|(existing, key)| (existing == handle).then_some(key))
            .ok_or(Error::StateError("unknown rsa signing key handle"))
    }

    /// Looks up one registered RSA decryption key by external handle.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle from the incoming decrypt request.
    ///
    /// # Returns
    ///
    /// Reference to the registered RSA private decrypt key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when the handle is unknown.
    fn rsa_decryption_key(&self, handle: &ExternalKeyHandle) -> Result<&RsaPrivateKey> {
        self.rsa_decrypt_keys
            .iter()
            .find_map(|(existing, key)| (existing == handle).then_some(key))
            .ok_or(Error::StateError("unknown rsa decryption key handle"))
    }

    /// Looks up one registered X25519 key by external handle.
    ///
    /// # Arguments
    ///
    /// * `handle` — External key handle from the incoming derive request.
    ///
    /// # Returns
    ///
    /// Clone of the registered X25519 private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when the handle is unknown.
    fn x25519_private_key(&self, handle: &ExternalKeyHandle) -> Result<X25519PrivateKey> {
        self.x25519_keys
            .iter()
            .find_map(|(existing, key)| (existing == handle).then_some(key.clone()))
            .ok_or(Error::StateError("unknown x25519 key handle"))
    }
}

impl ExternalKeyProvider for SoftwareKeyProvider {
    /// Performs software-provider signing using the registered key handle and selected algorithm.
    ///
    /// # Arguments
    ///
    /// * `request` — Sign request to execute.
    ///
    /// # Returns
    ///
    /// Signature bytes for the requested message.
    ///
    /// # Errors
    ///
    /// Returns key lookup failures, unsupported algorithm details, or algorithm-level signing failures.
    fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>> {
        let key = self.rsa_signing_key(request.handle)?;
        match request.algorithm {
            KeySignAlgorithm::RsaPkcs1Sha256 => rsassa_sha256_sign(key, request.message),
            KeySignAlgorithm::RsaPssSha256 => {
                let salt = request.salt.ok_or(Error::InvalidLength(
                    "rsa-pss-sha256 signing requires a salt",
                ))?;
                rsassa_pss_sha256_sign(key, request.message, salt)
            }
        }
    }

    /// Performs software-provider decryption using the registered key handle and selected algorithm.
    ///
    /// # Arguments
    ///
    /// * `request` — Decrypt request to execute.
    ///
    /// # Returns
    ///
    /// Decrypted plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns key lookup failures, or a uniform decryption-failure error for any algorithm-level decrypt failure.
    fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>> {
        let key = self.rsa_decryption_key(request.handle)?;
        let plaintext = match request.algorithm {
            KeyDecryptAlgorithm::RsaPkcs1v15 => rsaes_pkcs1_v15_decrypt(key, request.ciphertext),
            KeyDecryptAlgorithm::RsaOaepSha256 => {
                let label = request.label.unwrap_or(&[]);
                rsaes_oaep_sha256_decrypt(key, request.ciphertext, label)
            }
        };
        plaintext.map_err(|_| Error::CryptoFailure("key provider decryption failed"))
    }

    /// Performs software-provider shared-secret derivation using the registered key handle.
    ///
    /// # Arguments
    ///
    /// * `request` — Derive request to execute.
    ///
    /// # Returns
    ///
    /// Derived shared secret bytes.
    ///
    /// # Errors
    ///
    /// Returns key lookup failures, peer key parsing failures, or algorithm-level derive failures.
    fn derive_shared_secret(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>> {
        match request.algorithm {
            KeyDeriveAlgorithm::X25519 => {
                let private_key = self.x25519_private_key(request.handle)?;
                let peer_bytes: [u8; 32] = request
                    .peer_public_key
                    .try_into()
                    .map_err(|_| Error::InvalidLength("x25519 peer public key must be 32 bytes"))?;
                let peer_public = X25519PublicKey::from_bytes(peer_bytes);
                let shared = x25519_shared_secret(private_key, peer_public)?;
                Ok(shared.to_vec())
            }
        }
    }
}

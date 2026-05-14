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

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use noxtls_core::{Error, Result};

use crate::provider::{
    AeadEncryptRequest, AeadEncryptResponse, KeyDecryptRequest, KeyDeriveRequest, KeySignRequest,
    PsaCryptoBackend,
};

/// Implements the PSA backend trait for FFI-backed targets.
#[derive(Clone, Debug, Default)]
pub struct FfiPsaBackend;

impl FfiPsaBackend {
    /// Creates a noxtls_new FFI-backed backend adapter.
    ///
    /// # Arguments
    ///
    /// * `()` - This constructor has no parameters.
    ///
    /// # Returns
    ///
    /// A default [`FfiPsaBackend`] instance.
    pub fn noxtls_new() -> Self {
        Self
    }

    /// Returns whether this build includes direct PSA FFI shims.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance for capability checks.
    ///
    /// # Returns
    ///
    /// `true` when the `mbedtls-psa-ffi` feature is enabled, otherwise `false`.
    pub fn has_ffi_shims(&self) -> bool {
        cfg!(feature = "mbedtls-psa-ffi")
    }
}

impl PsaCryptoBackend for FfiPsaBackend {
    /// Signs input digest bytes using a key handle and noxtls_algorithm selected in request.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving sign request dispatch.
    /// * `request` - Sign request carrying key handle, noxtls_algorithm, and digest bytes.
    ///
    /// # Returns
    ///
    /// Signature bytes if supported by this backend implementation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>> {
        let _ = request;
        Err(Error::UnsupportedFeature(
            "psa ffi sign unavailable without linked backend",
        ))
    }

    /// Decrypts ciphertext bytes using a key handle and requested mechanism.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving decrypt request dispatch.
    /// * `request` - Decrypt request containing handle, noxtls_algorithm, and ciphertext.
    ///
    /// # Returns
    ///
    /// Decrypted plaintext bytes if backend supports this operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>> {
        let _ = request;
        Err(Error::UnsupportedFeature(
            "psa ffi decrypt unavailable without linked backend",
        ))
    }

    /// Derives shared-secret bytes for a key handle and peer public key.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving derive request dispatch.
    /// * `request` - Derive request with handle, noxtls_algorithm, and peer public bytes.
    ///
    /// # Returns
    ///
    /// Shared secret bytes derived by the configured noxtls_algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn noxtls_derive(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>> {
        let _ = request;
        Err(Error::UnsupportedFeature(
            "psa ffi derive unavailable without linked backend",
        ))
    }

    /// Fills the output buffer with random bytes from PSA entropy source.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving random generation request.
    /// * `out` - Mutable byte slice to fill with random output.
    ///
    /// # Returns
    ///
    /// `Ok(())` when random bytes were produced.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn random(&self, out: &mut [u8]) -> Result<()> {
        let _ = out;
        Err(Error::UnsupportedFeature(
            "psa ffi random unavailable without linked backend",
        ))
    }

    /// Computes SHA-256 digest for the input payload.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving hash request dispatch.
    /// * `input` - Bytes to hash with SHA-256.
    ///
    /// # Returns
    ///
    /// A 32-byte SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn noxtls_sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        let _ = input;
        Err(Error::UnsupportedFeature(
            "psa ffi sha256 unavailable without linked backend",
        ))
    }

    /// Encrypts plaintext bytes with AES-GCM and returns ciphertext plus tag.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend instance receiving AEAD encryption request.
    /// * `request` - AES-GCM request with key, nonce, AAD, and plaintext.
    ///
    /// # Returns
    ///
    /// Ciphertext and 16-byte tag on successful encryption.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] until concrete FFI hooks are linked.
    fn noxtls_aes_gcm_encrypt(
        &self,
        request: &AeadEncryptRequest<'_>,
    ) -> Result<AeadEncryptResponse> {
        let _ = request;
        Err(Error::UnsupportedFeature(
            "psa ffi aes-gcm unavailable without linked backend",
        ))
    }
}

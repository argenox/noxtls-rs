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
use alloc::{collections::BTreeMap, vec::Vec};
use noxtls_core::{Error, Result};
use noxtls_crypto::{
    aes_gcm_encrypt, p256_ecdh_shared_secret, p256_ecdsa_sign_sha256, rsaes_oaep_sha256_decrypt,
    rsaes_pkcs1_v15_decrypt, rsassa_pss_sha256_sign, rsassa_sha256_sign, sha256, x25519,
    AesCipher, P256PrivateKey, P256PublicKey, RsaPrivateKey,
};

/// Identifies a backend-managed external key object.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PsaExternalKeyHandle {
    id: Vec<u8>,
}

impl PsaExternalKeyHandle {
    /// Constructs an external key handle from opaque identifier bytes.
    ///
    /// # Arguments
    ///
    /// * `id` - Opaque provider-owned key identifier bytes.
    ///
    /// # Returns
    ///
    /// A new [`PsaExternalKeyHandle`] owning the identifier bytes.
    pub fn new(id: Vec<u8>) -> Self {
        Self { id }
    }

    /// Borrows the opaque key identifier bytes.
    ///
    /// # Arguments
    ///
    /// * `self` - Handle whose stable identifier bytes are required.
    ///
    /// # Returns
    ///
    /// Borrowed opaque bytes identifying the provider key object.
    pub fn as_bytes(&self) -> &[u8] {
        &self.id
    }
}

/// Enumerates signing algorithms supported by PSA provider mappings.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsaSignAlgorithm {
    /// RSA PKCS#1 v1.5 signing with SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSA PSS signing with SHA-256 digest.
    RsaPssSha256,
    /// ECDSA signing over P-256 with SHA-256 digest.
    EcdsaP256Sha256,
}

/// Enumerates decrypt algorithms supported by PSA provider mappings.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsaDecryptAlgorithm {
    /// RSA PKCS#1 v1.5 decryption.
    RsaPkcs1v15,
    /// RSA OAEP decryption using SHA-256.
    RsaOaepSha256,
}

/// Enumerates derive algorithms supported by PSA provider mappings.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsaDeriveAlgorithm {
    /// X25519 shared secret derivation.
    X25519,
    /// P-256 ECDH shared secret derivation.
    EcdhP256,
}

/// Carries data required for backend sign operations.
#[derive(Clone, Debug)]
pub struct KeySignRequest<'a> {
    /// Opaque provider handle to signing key object.
    pub handle: &'a PsaExternalKeyHandle,
    /// Algorithm selector for sign operation.
    pub algorithm: PsaSignAlgorithm,
    /// Input message bytes to be signed.
    pub message: &'a [u8],
    /// Optional PSS salt bytes for algorithms requiring explicit salt.
    pub salt: Option<&'a [u8]>,
}

/// Carries data required for backend decrypt operations.
#[derive(Clone, Debug)]
pub struct KeyDecryptRequest<'a> {
    /// Opaque provider handle to decrypt key object.
    pub handle: &'a PsaExternalKeyHandle,
    /// Algorithm selector for decrypt operation.
    pub algorithm: PsaDecryptAlgorithm,
    /// Ciphertext bytes to decrypt.
    pub ciphertext: &'a [u8],
    /// Optional OAEP label bytes for algorithms requiring explicit label.
    pub label: Option<&'a [u8]>,
}

/// Carries data required for backend derive operations.
#[derive(Clone, Debug)]
pub struct KeyDeriveRequest<'a> {
    /// Opaque provider handle to derive key object.
    pub handle: &'a PsaExternalKeyHandle,
    /// Algorithm selector for derive operation.
    pub algorithm: PsaDeriveAlgorithm,
    /// Peer public-key bytes in algorithm-expected encoding.
    pub peer_public_key: &'a [u8],
}

/// Carries AES-GCM encrypt operation inputs.
#[derive(Clone, Debug)]
pub struct AeadEncryptRequest<'a> {
    /// Symmetric encryption key bytes.
    pub key: &'a [u8],
    /// Nonce bytes for AES-GCM operation.
    pub nonce: &'a [u8],
    /// Associated authenticated data bytes.
    pub aad: &'a [u8],
    /// Plaintext bytes to encrypt.
    pub plaintext: &'a [u8],
}

/// Carries AES-GCM encryption outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AeadEncryptResponse {
    /// Produced ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Produced 16-byte authentication tag.
    pub tag: [u8; 16],
}

/// Defines backend operations required by PSA provider surface.
pub trait PsaCryptoBackend {
    /// Executes an asymmetric signing operation.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving sign request.
    /// * `request` - Sign request containing handle, algorithm, and digest.
    ///
    /// # Returns
    ///
    /// Signature bytes generated by the backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when handle resolution, policy checks, or crypto operation fails.
    fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>>;

    /// Executes an asymmetric decrypt operation.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving decrypt request.
    /// * `request` - Decrypt request containing handle, algorithm, and ciphertext.
    ///
    /// # Returns
    ///
    /// Plaintext bytes on successful decrypt.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when handle resolution, policy checks, or crypto operation fails.
    fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>>;

    /// Executes a key-agreement derive operation.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving derive request.
    /// * `request` - Derive request containing handle, algorithm, and peer key.
    ///
    /// # Returns
    ///
    /// Shared secret bytes for the selected derive algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when handle resolution, policy checks, or derive operation fails.
    fn derive(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>>;

    /// Fills output bytes with random data.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving random request.
    /// * `out` - Mutable output buffer for random bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the output buffer is fully written.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when backend cannot provide entropy.
    fn random(&self, out: &mut [u8]) -> Result<()>;

    /// Computes a SHA-256 digest.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving hash request.
    /// * `input` - Bytes to hash.
    ///
    /// # Returns
    ///
    /// A 32-byte SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when hashing fails for the backend.
    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]>;

    /// Encrypts plaintext with AES-GCM.
    ///
    /// # Arguments
    ///
    /// * `self` - Backend implementation receiving AEAD request.
    /// * `request` - AES-GCM request with key, nonce, AAD, and plaintext.
    ///
    /// # Returns
    ///
    /// Ciphertext bytes plus a 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when backend lacks AES-GCM support or encryption fails.
    fn aes_gcm_encrypt(&self, request: &AeadEncryptRequest<'_>) -> Result<AeadEncryptResponse>;
}

/// Adapts a concrete backend into a stable PSA provider API.
#[derive(Clone, Debug)]
pub struct PsaProvider<B> {
    backend: B,
}

impl<B> PsaProvider<B> {
    /// Constructs a provider from a concrete backend implementation.
    ///
    /// # Arguments
    ///
    /// * `backend` - Backend implementation used by provider operations.
    ///
    /// # Returns
    ///
    /// A new [`PsaProvider`] owning the backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: PsaCryptoBackend> PsaProvider<B> {
    /// Dispatches signing requests to the configured backend.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `request` - Signing request to execute.
    ///
    /// # Returns
    ///
    /// Signature bytes produced by backend.
    ///
    /// # Errors
    ///
    /// Returns backend-provided [`Error`] on failures.
    pub fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>> {
        self.backend.sign(request)
    }

    /// Dispatches decrypt requests with uniform decrypt failure posture.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `request` - Decrypt request to execute.
    ///
    /// # Returns
    ///
    /// Plaintext bytes returned by backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoFailure`] for decrypt failures to avoid oracle leakage.
    pub fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>> {
        self.backend
            .decrypt(request)
            .map_err(|_| Error::CryptoFailure("psa cryptographic operation failed"))
    }

    /// Dispatches derive requests to the configured backend.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `request` - Derive request to execute.
    ///
    /// # Returns
    ///
    /// Shared secret bytes produced by backend.
    ///
    /// # Errors
    ///
    /// Returns backend-provided [`Error`] on failures.
    pub fn derive(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>> {
        self.backend.derive(request)
    }

    /// Fills output bytes with backend-provided random data.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `out` - Mutable output buffer to fill.
    ///
    /// # Returns
    ///
    /// `Ok(())` when random output was written to the caller buffer.
    ///
    /// # Errors
    ///
    /// Returns backend-provided [`Error`] when random generation fails.
    pub fn random(&self, out: &mut [u8]) -> Result<()> {
        self.backend.random(out)
    }

    /// Computes SHA-256 using backend digest implementation.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `input` - Bytes to hash.
    ///
    /// # Returns
    ///
    /// 32-byte SHA-256 digest bytes.
    ///
    /// # Errors
    ///
    /// Returns backend-provided [`Error`] on hashing failures.
    pub fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        self.backend.sha256(input)
    }

    /// Encrypts plaintext with backend AES-GCM implementation.
    ///
    /// # Arguments
    ///
    /// * `self` - Provider dispatching to backend.
    /// * `request` - AES-GCM request with key/nonce/aad/plaintext.
    ///
    /// # Returns
    ///
    /// Ciphertext bytes plus a 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns backend-provided [`Error`] when encryption fails.
    pub fn aes_gcm_encrypt(&self, request: &AeadEncryptRequest<'_>) -> Result<AeadEncryptResponse> {
        self.backend.aes_gcm_encrypt(request)
    }
}

/// Stores policy flags for registered key handles.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct HandlePolicy {
    allow_sign: bool,
    allow_decrypt: bool,
    allow_derive: bool,
}

/// Represents the private key material variants used for software-backed tests.
#[derive(Clone, Debug)]
enum SoftwarePrivateMaterial {
    Rsa(RsaPrivateKey),
    X25519([u8; 32]),
    P256(P256PrivateKey),
}

/// Implements an in-process backend that mirrors PSA handle semantics for tests.
#[derive(Clone, Debug, Default)]
pub struct PsaSoftwareBackend {
    keys: BTreeMap<Vec<u8>, (SoftwarePrivateMaterial, HandlePolicy)>,
}

impl PsaSoftwareBackend {
    /// Constructs an empty software backend.
    ///
    /// # Arguments
    ///
    /// * `()` - This constructor has no parameters.
    ///
    /// # Returns
    ///
    /// A new empty [`PsaSoftwareBackend`] value.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Registers an RSA private key with handle-level usage policy.
    ///
    /// # Arguments
    ///
    /// * `handle` - Opaque key handle used for future operations.
    /// * `key` - RSA private key material owned by backend.
    /// * `allow_sign` - Whether sign operations are authorized for this handle.
    /// * `allow_decrypt` - Whether decrypt operations are authorized for this handle.
    ///
    /// # Returns
    ///
    /// `Ok(())` after key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] if the handle is already registered.
    pub fn register_rsa_key(
        &mut self,
        handle: PsaExternalKeyHandle,
        key: RsaPrivateKey,
        allow_sign: bool,
        allow_decrypt: bool,
    ) -> Result<()> {
        self.insert_key(
            handle,
            SoftwarePrivateMaterial::Rsa(key),
            HandlePolicy {
                allow_sign,
                allow_decrypt,
                allow_derive: false,
            },
        )
    }

    /// Registers an X25519 private key with derive-policy controls.
    ///
    /// # Arguments
    ///
    /// * `handle` - Opaque key handle used for future derive operations.
    /// * `key` - X25519 private scalar bytes.
    /// * `allow_derive` - Whether derive operations are authorized for this handle.
    ///
    /// # Returns
    ///
    /// `Ok(())` after key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] if the handle is already registered.
    pub fn register_x25519_key(
        &mut self,
        handle: PsaExternalKeyHandle,
        key: [u8; 32],
        allow_derive: bool,
    ) -> Result<()> {
        self.insert_key(
            handle,
            SoftwarePrivateMaterial::X25519(key),
            HandlePolicy {
                allow_sign: false,
                allow_decrypt: false,
                allow_derive,
            },
        )
    }

    /// Registers a P-256 private key with derive/sign policy controls.
    ///
    /// # Arguments
    ///
    /// * `handle` - Opaque key handle used for future operations.
    /// * `key` - P-256 private key material.
    /// * `allow_sign` - Whether sign operations are authorized for this handle.
    /// * `allow_derive` - Whether derive operations are authorized for this handle.
    ///
    /// # Returns
    ///
    /// `Ok(())` after key registration succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] if the handle is already registered.
    pub fn register_p256_key(
        &mut self,
        handle: PsaExternalKeyHandle,
        key: P256PrivateKey,
        allow_sign: bool,
        allow_derive: bool,
    ) -> Result<()> {
        self.insert_key(
            handle,
            SoftwarePrivateMaterial::P256(key),
            HandlePolicy {
                allow_sign,
                allow_decrypt: false,
                allow_derive,
            },
        )
    }

    /// Inserts a key record while enforcing unique handle ownership.
    ///
    /// # Arguments
    ///
    /// * `handle` - Opaque key handle used as map key.
    /// * `material` - Private material variant to store.
    /// * `policy` - Allowed operation policy for this handle.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the record is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] when handle already exists.
    fn insert_key(
        &mut self,
        handle: PsaExternalKeyHandle,
        material: SoftwarePrivateMaterial,
        policy: HandlePolicy,
    ) -> Result<()> {
        if self.keys.contains_key(handle.as_bytes()) {
            return Err(Error::StateError("psa key handle already registered"));
        }
        self.keys.insert(handle.id, (material, policy));
        Ok(())
    }

    /// Resolves a key record and policy by handle identifier.
    ///
    /// # Arguments
    ///
    /// * `handle` - Opaque handle whose key material is required.
    ///
    /// # Returns
    ///
    /// Borrowed private material and policy tuple for the handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PolicyViolation`] when the handle is unknown.
    fn resolve_key(
        &self,
        handle: &PsaExternalKeyHandle,
    ) -> Result<&(SoftwarePrivateMaterial, HandlePolicy)> {
        self.keys
            .get(handle.as_bytes())
            .ok_or(Error::StateError("psa key handle invalid"))
    }
}

impl PsaCryptoBackend for PsaSoftwareBackend {
    /// Executes signing operations using software cryptographic primitives.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state containing registered keys.
    /// * `request` - Sign request with handle, algorithm, and digest.
    ///
    /// # Returns
    ///
    /// Signature bytes from RSA sign operations.
    ///
    /// # Errors
    ///
    /// Returns policy or crypto errors for unknown handles, denied usage, or bad key type.
    fn sign(&self, request: &KeySignRequest<'_>) -> Result<Vec<u8>> {
        let (material, policy) = self.resolve_key(request.handle)?;
        if !policy.allow_sign {
            return Err(Error::StateError("psa sign not permitted by key policy"));
        }
        match (request.algorithm, material) {
            (PsaSignAlgorithm::RsaPkcs1Sha256, SoftwarePrivateMaterial::Rsa(key)) => {
                rsassa_sha256_sign(key, request.message)
            }
            (PsaSignAlgorithm::RsaPssSha256, SoftwarePrivateMaterial::Rsa(key)) => {
                let salt = request.salt.ok_or(Error::InvalidLength(
                    "rsa-pss-sha256 signing requires a salt",
                ))?;
                rsassa_pss_sha256_sign(key, request.message, salt)
            }
            (PsaSignAlgorithm::EcdsaP256Sha256, SoftwarePrivateMaterial::P256(key)) => {
                let (r, s) = p256_ecdsa_sign_sha256(key, request.message)?;
                let mut signature = Vec::with_capacity(64);
                signature.extend_from_slice(&r);
                signature.extend_from_slice(&s);
                Ok(signature)
            }
            _ => Err(Error::UnsupportedFeature("psa sign algorithm/key mismatch")),
        }
    }

    /// Executes decrypt operations using software cryptographic primitives.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state containing registered keys.
    /// * `request` - Decrypt request with handle, algorithm, and ciphertext.
    ///
    /// # Returns
    ///
    /// Plaintext bytes decrypted from input ciphertext.
    ///
    /// # Errors
    ///
    /// Returns policy or crypto errors for unknown handles, denied usage, or bad key type.
    fn decrypt(&self, request: &KeyDecryptRequest<'_>) -> Result<Vec<u8>> {
        let (material, policy) = self.resolve_key(request.handle)?;
        if !policy.allow_decrypt {
            return Err(Error::StateError(
                "psa decrypt not permitted by key policy",
            ));
        }
        match (request.algorithm, material) {
            (PsaDecryptAlgorithm::RsaPkcs1v15, SoftwarePrivateMaterial::Rsa(key)) => {
                rsaes_pkcs1_v15_decrypt(key, request.ciphertext)
            }
            (PsaDecryptAlgorithm::RsaOaepSha256, SoftwarePrivateMaterial::Rsa(key)) => {
                rsaes_oaep_sha256_decrypt(key, request.ciphertext, request.label.unwrap_or(&[]))
            }
            _ => Err(Error::UnsupportedFeature("psa decrypt algorithm/key mismatch")),
        }
    }

    /// Executes derive operations using software X25519 primitive.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state containing registered keys.
    /// * `request` - Derive request with handle, algorithm, and peer key.
    ///
    /// # Returns
    ///
    /// Shared secret bytes from X25519 derive operation.
    ///
    /// # Errors
    ///
    /// Returns policy or parse errors for unknown handles, denied usage, or invalid peer key.
    fn derive(&self, request: &KeyDeriveRequest<'_>) -> Result<Vec<u8>> {
        let (material, policy) = self.resolve_key(request.handle)?;
        if !policy.allow_derive {
            return Err(Error::StateError("psa derive not permitted by key policy"));
        }
        match (request.algorithm, material) {
            (PsaDeriveAlgorithm::X25519, SoftwarePrivateMaterial::X25519(private)) => {
                if request.peer_public_key.len() != 32 {
                    return Err(Error::ParseFailure("x25519 peer public key length invalid"));
                }
                let mut peer = [0u8; 32];
                peer.copy_from_slice(request.peer_public_key);
                Ok(x25519(private, &peer).to_vec())
            }
            (PsaDeriveAlgorithm::EcdhP256, SoftwarePrivateMaterial::P256(private)) => {
                let peer = P256PublicKey::from_uncompressed(request.peer_public_key)?;
                Ok(p256_ecdh_shared_secret(private, &peer)?.to_vec())
            }
            _ => Err(Error::UnsupportedFeature("psa derive algorithm/key mismatch")),
        }
    }

    /// Produces deterministic random bytes for validation-only posture.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state (not used by this implementation).
    /// * `out` - Mutable output buffer to fill with deterministic bytes.
    ///
    /// # Returns
    ///
    /// `Ok(())` once all output bytes are filled.
    ///
    /// # Errors
    ///
    /// This function does not return errors in the software backend.
    fn random(&self, out: &mut [u8]) -> Result<()> {
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(17).wrapping_add(0x5A);
        }
        Ok(())
    }

    /// Computes SHA-256 digest with software primitive implementation.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state (not used by this implementation).
    /// * `input` - Input bytes to hash.
    ///
    /// # Returns
    ///
    /// 32-byte SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns crypto error if digest primitive reports a failure.
    fn sha256(&self, input: &[u8]) -> Result<[u8; 32]> {
        Ok(sha256(input))
    }

    /// Encrypts using AES-GCM software primitive.
    ///
    /// # Arguments
    ///
    /// * `self` - Software backend state (not used by this implementation).
    /// * `request` - Encryption request with key, nonce, AAD, and plaintext.
    ///
    /// # Returns
    ///
    /// Ciphertext bytes plus 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] because software AES-GCM path is not wired here.
    fn aes_gcm_encrypt(&self, request: &AeadEncryptRequest<'_>) -> Result<AeadEncryptResponse> {
        let cipher = AesCipher::new(request.key)?;
        let (ciphertext, tag) =
            aes_gcm_encrypt(&cipher, request.nonce, request.aad, request.plaintext)?;
        Ok(AeadEncryptResponse { ciphertext, tag })
    }
}

/// Type alias for default software-backed PSA provider.
pub type PsaSoftwareProvider = PsaProvider<PsaSoftwareBackend>;

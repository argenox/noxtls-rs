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

use crate::internal_alloc::{String, Vec};
use noxtls_core::{Error, Result};
use noxtls_crypto::{
    Ed25519PrivateKey, Ed25519PublicKey, MlDsaPublicKey, P256PrivateKey, P256PublicKey,
    RsaPrivateKey, RsaPublicKey, X25519PrivateKey, X25519PublicKey, X448PrivateKey, X448PublicKey,
    OID_ID_MLDSA65,
};
use noxtls_pem::{
    ec_private_key_pem_to_der_sec1, private_key_der_to_pem_pkcs8, private_key_pem_to_der_pkcs8,
    public_key_der_to_pem_spki, public_key_pem_to_der_spki, rsa_private_key_pem_to_der_pkcs1,
    rsa_public_key_der_to_pem_pkcs1, rsa_public_key_pem_to_der_pkcs1,
};
#[cfg(feature = "std")]
use noxtls_pem::{der_to_pem_file, pem_file_to_der};
#[cfg(feature = "std")]
use std::path::Path;

use super::parse_der_node;

const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_X25519: &[u8] = &[0x2B, 0x65, 0x6E];
const OID_X448: &[u8] = &[0x2B, 0x65, 0x6F];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

/// Holds core PKCS#1 RSA private-key fields needed by current consumers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaPrivateKeyDerParts {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
}

/// Holds PKCS#1 RSA public-key modulus/exponent fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaPublicKeyDerParts {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// Holds PKCS#8 `PrivateKeyInfo` fields for algorithm dispatch and key extraction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Pkcs8PrivateKeyInfoDerParts {
    pub algorithm_oid: Vec<u8>,
    pub algorithm_parameters_oid: Option<Vec<u8>>,
    pub private_key: Vec<u8>,
}

/// Holds SPKI fields for algorithm dispatch and key extraction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SpkiPublicKeyInfoDerParts {
    pub algorithm_oid: Vec<u8>,
    pub algorithm_parameters_oid: Option<Vec<u8>>,
    pub subject_public_key: Vec<u8>,
}

/// Serializes `RsaPublicKey` into PKCS#1 `RSAPublicKey` DER.
///
/// # Arguments
/// * `public`: RSA public key to serialize.
///
/// # Returns
/// DER-encoded PKCS#1 `RSAPublicKey` bytes.
pub fn rsa_public_key_to_pkcs1_der(public: &RsaPublicKey) -> Result<Vec<u8>> {
    let modulus = encode_der_integer(&public.n.to_be_bytes());
    let exponent = encode_der_integer(&public.e.to_be_bytes());
    encode_der_sequence(&[modulus, exponent].concat())
}

/// Serializes `RsaPublicKey` into SPKI DER using `rsaEncryption` OID.
///
/// # Arguments
/// * `public`: RSA public key to serialize.
///
/// # Returns
/// DER-encoded `SubjectPublicKeyInfo` bytes.
pub fn rsa_public_key_to_spki_der(public: &RsaPublicKey) -> Result<Vec<u8>> {
    let pkcs1 = rsa_public_key_to_pkcs1_der(public)?;
    encode_spki_public_key_info_der(OID_RSA_ENCRYPTION, None, &pkcs1)
}

/// Serializes `RsaPublicKey` into PEM SPKI `PUBLIC KEY`.
///
/// # Arguments
/// * `public`: RSA public key to serialize.
///
/// # Returns
/// PEM-encoded SPKI public key.
pub fn rsa_public_key_to_pem_spki(public: &RsaPublicKey) -> Result<String> {
    let der = rsa_public_key_to_spki_der(public)?;
    public_key_der_to_pem_spki(&der)
}

/// Serializes `RsaPublicKey` into PEM PKCS#1 `RSA PUBLIC KEY`.
///
/// # Arguments
/// * `public`: RSA public key to serialize.
///
/// # Returns
/// PEM-encoded PKCS#1 RSA public key.
pub fn rsa_public_key_to_pem_pkcs1(public: &RsaPublicKey) -> Result<String> {
    let der = rsa_public_key_to_pkcs1_der(public)?;
    rsa_public_key_der_to_pem_pkcs1(&der)
}

/// Serializes `P256PublicKey` into SPKI DER (`id-ecPublicKey` + `prime256v1`).
///
/// # Arguments
/// * `public`: P-256 public key to serialize.
///
/// # Returns
/// DER-encoded `SubjectPublicKeyInfo` bytes.
pub fn p256_public_key_to_spki_der(public: &P256PublicKey) -> Result<Vec<u8>> {
    let sec1 = public.to_uncompressed()?;
    encode_spki_public_key_info_der(OID_EC_PUBLIC_KEY, Some(OID_PRIME256V1), &sec1)
}

/// Serializes `P256PublicKey` into PEM SPKI `PUBLIC KEY`.
///
/// # Arguments
/// * `public`: P-256 public key to serialize.
///
/// # Returns
/// PEM-encoded SPKI public key.
pub fn p256_public_key_to_pem_spki(public: &P256PublicKey) -> Result<String> {
    let der = p256_public_key_to_spki_der(public)?;
    public_key_der_to_pem_spki(&der)
}

/// Serializes `X25519PublicKey` into SPKI DER (RFC 8410).
///
/// # Arguments
/// * `public`: X25519 public key to serialize.
///
/// # Returns
/// DER-encoded `SubjectPublicKeyInfo` bytes.
pub fn x25519_public_key_to_spki_der(public: X25519PublicKey) -> Result<Vec<u8>> {
    encode_spki_public_key_info_der(OID_X25519, None, &public.bytes)
}

/// Serializes `X25519PublicKey` into PEM SPKI `PUBLIC KEY`.
///
/// # Arguments
/// * `public`: X25519 public key to serialize.
///
/// # Returns
/// PEM-encoded SPKI public key.
pub fn x25519_public_key_to_pem_spki(public: X25519PublicKey) -> Result<String> {
    let der = x25519_public_key_to_spki_der(public)?;
    public_key_der_to_pem_spki(&der)
}

/// Serializes `X448PublicKey` into SPKI DER (RFC 8410).
///
/// # Arguments
/// * `public`: X448 public key to serialize.
///
/// # Returns
/// DER-encoded `SubjectPublicKeyInfo` bytes.
pub fn x448_public_key_to_spki_der(public: X448PublicKey) -> Result<Vec<u8>> {
    encode_spki_public_key_info_der(OID_X448, None, &public.bytes)
}

/// Serializes `X448PublicKey` into PEM SPKI `PUBLIC KEY`.
///
/// # Arguments
/// * `public`: X448 public key to serialize.
///
/// # Returns
/// PEM-encoded SPKI public key.
pub fn x448_public_key_to_pem_spki(public: X448PublicKey) -> Result<String> {
    let der = x448_public_key_to_spki_der(public)?;
    public_key_der_to_pem_spki(&der)
}

/// Serializes `Ed25519PublicKey` into SPKI DER (RFC 8410 `id-Ed25519`).
///
/// # Arguments
/// * `public`: Ed25519 public key to serialize.
///
/// # Returns
/// DER-encoded `SubjectPublicKeyInfo` bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested TLV encoding fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_public_key_to_spki_der(public: Ed25519PublicKey) -> Result<Vec<u8>> {
    encode_spki_public_key_info_der(OID_ED25519, None, &public.to_bytes())
}

/// Serializes `Ed25519PublicKey` into PEM SPKI `PUBLIC KEY`.
///
/// # Arguments
/// * `public`: Ed25519 public key to serialize.
///
/// # Returns
/// PEM-encoded SPKI public key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or PEM wrapping fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_public_key_to_pem_spki(public: Ed25519PublicKey) -> Result<String> {
    let der = ed25519_public_key_to_spki_der(public)?;
    public_key_der_to_pem_spki(&der)
}

/// Serializes `P256PrivateKey` into PKCS#8 DER (`id-ecPublicKey` + `prime256v1`).
///
/// # Arguments
/// * `private`: P-256 private key to serialize.
///
/// # Returns
/// DER-encoded `PrivateKeyInfo` containing SEC1 `ECPrivateKey` bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when scalar extraction or nested DER encoding fails.
///
/// # Panics
///
/// This function does not panic.
pub fn p256_private_key_to_pkcs8_der(private: &P256PrivateKey) -> Result<Vec<u8>> {
    let scalar = private.to_bytes()?;
    let sec1 = encode_der_sequence(
        &[
            encode_der_integer(&[0x01]),
            encode_der_node(0x04, &scalar),
        ]
        .concat(),
    )?;
    encode_pkcs8_private_key_info_der(OID_EC_PUBLIC_KEY, Some(OID_PRIME256V1), &sec1)
}

/// Serializes `P256PrivateKey` into PEM PKCS#8 `PRIVATE KEY`.
///
/// # Arguments
/// * `private`: P-256 private key to serialize.
///
/// # Returns
/// PEM-encoded PKCS#8 private key text.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or PEM wrapping fails.
///
/// # Panics
///
/// This function does not panic.
pub fn p256_private_key_to_pem_pkcs8(private: &P256PrivateKey) -> Result<String> {
    let der = p256_private_key_to_pkcs8_der(private)?;
    private_key_der_to_pem_pkcs8(&der)
}

/// Serializes `X25519PrivateKey` into PKCS#8 DER (`id-X25519`).
///
/// # Arguments
/// * `private`: X25519 private key to serialize.
///
/// # Returns
/// DER-encoded `PrivateKeyInfo` where `privateKey` wraps a 32-byte scalar.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested DER encoding fails.
///
/// # Panics
///
/// This function does not panic.
pub fn x25519_private_key_to_pkcs8_der(private: X25519PrivateKey) -> Result<Vec<u8>> {
    let curve_private_key = encode_der_node(0x04, &private.to_bytes());
    encode_pkcs8_private_key_info_der(OID_X25519, None, &curve_private_key)
}

/// Serializes `X25519PrivateKey` into PEM PKCS#8 `PRIVATE KEY`.
///
/// # Arguments
/// * `private`: X25519 private key to serialize.
///
/// # Returns
/// PEM-encoded PKCS#8 private key text.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or PEM wrapping fails.
///
/// # Panics
///
/// This function does not panic.
pub fn x25519_private_key_to_pem_pkcs8(private: X25519PrivateKey) -> Result<String> {
    let der = x25519_private_key_to_pkcs8_der(private)?;
    private_key_der_to_pem_pkcs8(&der)
}

/// Serializes `X448PrivateKey` into PKCS#8 DER (`id-X448`).
///
/// # Arguments
/// * `private`: X448 private key to serialize.
///
/// # Returns
/// DER-encoded `PrivateKeyInfo` where `privateKey` wraps a 56-byte scalar.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested DER encoding fails.
///
/// # Panics
///
/// This function does not panic.
pub fn x448_private_key_to_pkcs8_der(private: X448PrivateKey) -> Result<Vec<u8>> {
    let curve_private_key = encode_der_node(0x04, &private.to_bytes());
    encode_pkcs8_private_key_info_der(OID_X448, None, &curve_private_key)
}

/// Serializes `X448PrivateKey` into PEM PKCS#8 `PRIVATE KEY`.
///
/// # Arguments
/// * `private`: X448 private key to serialize.
///
/// # Returns
/// PEM-encoded PKCS#8 private key text.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or PEM wrapping fails.
///
/// # Panics
///
/// This function does not panic.
pub fn x448_private_key_to_pem_pkcs8(private: X448PrivateKey) -> Result<String> {
    let der = x448_private_key_to_pkcs8_der(private)?;
    private_key_der_to_pem_pkcs8(&der)
}

/// Serializes `Ed25519PrivateKey` into PKCS#8 DER (`id-Ed25519`).
///
/// # Arguments
/// * `private`: Ed25519 private key to serialize.
///
/// # Returns
/// DER-encoded `PrivateKeyInfo` where `privateKey` wraps a 32-byte signing seed.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested DER encoding fails.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_private_key_to_pkcs8_der(private: &Ed25519PrivateKey) -> Result<Vec<u8>> {
    let curve_private_key = encode_der_node(0x04, &private.to_seed());
    encode_pkcs8_private_key_info_der(OID_ED25519, None, &curve_private_key)
}

/// Serializes `Ed25519PrivateKey` into PEM PKCS#8 `PRIVATE KEY`.
///
/// # Arguments
/// * `private`: Ed25519 private key to serialize.
///
/// # Returns
/// PEM-encoded PKCS#8 private key text.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or PEM wrapping fails.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_private_key_to_pem_pkcs8(private: &Ed25519PrivateKey) -> Result<String> {
    let der = ed25519_private_key_to_pkcs8_der(private)?;
    private_key_der_to_pem_pkcs8(&der)
}

/// Builds `RsaPrivateKey` from PKCS#1 DER bytes.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#1 `RSAPrivateKey`.
///
/// # Returns
/// Parsed RSA private key usable by `noxtls-crypto`.
pub fn rsa_private_key_from_pkcs1_der(der: &[u8]) -> Result<RsaPrivateKey> {
    let parts = parse_pkcs1_rsa_private_key_der(der)?;
    RsaPrivateKey::from_be_bytes(&parts.modulus, &parts.private_exponent)
}

/// Builds `RsaPrivateKey` from PKCS#8 DER bytes for RSA keys.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#8 `PrivateKeyInfo`.
///
/// # Returns
/// Parsed RSA private key usable by `noxtls-crypto`.
pub fn rsa_private_key_from_pkcs8_der(der: &[u8]) -> Result<RsaPrivateKey> {
    let info = parse_pkcs8_private_key_info_der(der)?;
    if info.algorithm_oid != OID_RSA_ENCRYPTION {
        return Err(Error::UnsupportedFeature(
            "pkcs8 private key algorithm is not RSA",
        ));
    }
    rsa_private_key_from_pkcs1_der(&info.private_key)
}

/// Builds `P256PrivateKey` from PKCS#8 DER bytes for `id-ecPublicKey` + `prime256v1`.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#8 `PrivateKeyInfo`.
///
/// # Returns
/// Parsed P-256 private key usable by `noxtls-crypto`.
pub fn p256_private_key_from_pkcs8_der(der: &[u8]) -> Result<P256PrivateKey> {
    let info = parse_pkcs8_private_key_info_der(der)?;
    if info.algorithm_oid != OID_EC_PUBLIC_KEY {
        return Err(Error::UnsupportedFeature(
            "pkcs8 private key algorithm is not EC",
        ));
    }
    if info.algorithm_parameters_oid.as_deref() != Some(OID_PRIME256V1) {
        return Err(Error::UnsupportedFeature(
            "pkcs8 ec curve is not prime256v1",
        ));
    }
    let scalar = parse_sec1_ec_private_key_scalar(&info.private_key)?;
    P256PrivateKey::from_bytes(scalar)
}

/// Builds `X25519PrivateKey` from PKCS#8 DER bytes for RFC 8410 X25519 keys.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#8 `PrivateKeyInfo`.
///
/// # Returns
/// Parsed X25519 private key usable by `noxtls-crypto`.
pub fn x25519_private_key_from_pkcs8_der(der: &[u8]) -> Result<X25519PrivateKey> {
    let info = parse_pkcs8_private_key_info_der(der)?;
    if info.algorithm_oid != OID_X25519 {
        return Err(Error::UnsupportedFeature(
            "pkcs8 private key algorithm is not X25519",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "x25519 algorithm parameters are not supported",
        ));
    }
    let scalar = parse_x25519_private_key_bytes(&info.private_key)?;
    Ok(X25519PrivateKey::from_bytes(scalar))
}

/// Builds `X448PrivateKey` from PKCS#8 DER bytes for RFC 8410 X448 keys.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#8 `PrivateKeyInfo`.
///
/// # Returns
/// Parsed X448 private key usable by `noxtls-crypto`.
pub fn x448_private_key_from_pkcs8_der(der: &[u8]) -> Result<X448PrivateKey> {
    let info = parse_pkcs8_private_key_info_der(der)?;
    if info.algorithm_oid != OID_X448 {
        return Err(Error::UnsupportedFeature(
            "pkcs8 private key algorithm is not X448",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "x448 algorithm parameters are not supported",
        ));
    }
    let scalar = parse_x448_private_key_bytes(&info.private_key)?;
    Ok(X448PrivateKey::from_bytes(scalar))
}

/// Builds `Ed25519PrivateKey` from PKCS#8 DER bytes for RFC 8410 Ed25519 keys.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#8 `PrivateKeyInfo`.
///
/// # Returns
/// Parsed Ed25519 private key usable by `noxtls-crypto`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the algorithm OID is not Ed25519, parameters are present,
/// or the nested `CurvePrivateKey` octets are not a valid 32-byte seed encoding.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_private_key_from_pkcs8_der(der: &[u8]) -> Result<Ed25519PrivateKey> {
    let info = parse_pkcs8_private_key_info_der(der)?;
    if info.algorithm_oid != OID_ED25519 {
        return Err(Error::UnsupportedFeature(
            "pkcs8 private key algorithm is not Ed25519",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "ed25519 algorithm parameters are not supported",
        ));
    }
    let seed = parse_ed25519_private_key_seed(&info.private_key)?;
    Ok(Ed25519PrivateKey::from_seed(&seed))
}

/// Builds `P256PrivateKey` from SEC1 ECPrivateKey DER bytes.
///
/// # Arguments
/// * `der`: DER-encoded SEC1 `ECPrivateKey`.
///
/// # Returns
/// Parsed P-256 private key usable by `noxtls-crypto`.
pub fn p256_private_key_from_sec1_der(der: &[u8]) -> Result<P256PrivateKey> {
    let scalar = parse_sec1_ec_private_key_scalar(der)?;
    P256PrivateKey::from_bytes(scalar)
}

/// Builds `RsaPublicKey` from PKCS#1 DER bytes.
///
/// # Arguments
/// * `der`: DER-encoded PKCS#1 `RSAPublicKey`.
///
/// # Returns
/// Parsed RSA public key usable by `noxtls-crypto`.
pub fn rsa_public_key_from_pkcs1_der(der: &[u8]) -> Result<RsaPublicKey> {
    let parts = parse_pkcs1_rsa_public_key_der(der)?;
    RsaPublicKey::from_be_bytes(&parts.modulus, &parts.public_exponent)
}

/// Builds `RsaPublicKey` from DER SPKI bytes for RSA keys.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed RSA public key usable by `noxtls-crypto`.
pub fn rsa_public_key_from_spki_der(der: &[u8]) -> Result<RsaPublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_RSA_ENCRYPTION {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not RSA",
        ));
    }
    rsa_public_key_from_pkcs1_der(&info.subject_public_key)
}

/// Builds `P256PublicKey` from DER SPKI bytes for `id-ecPublicKey` + `prime256v1`.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed P-256 public key usable by `noxtls-crypto`.
pub fn p256_public_key_from_spki_der(der: &[u8]) -> Result<P256PublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_EC_PUBLIC_KEY {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not EC",
        ));
    }
    if info.algorithm_parameters_oid.as_deref() != Some(OID_PRIME256V1) {
        return Err(Error::UnsupportedFeature("spki ec curve is not prime256v1"));
    }
    P256PublicKey::from_uncompressed(&info.subject_public_key)
}

/// Parses DER-encoded ECDSA signature `SEQUENCE { INTEGER r; INTEGER s }` into 32-byte scalars.
///
/// # Arguments
/// * `signature_der`: ECDSA signature in ASN.1 DER form (as used in TLS `CertificateVerify`).
///
/// # Returns
/// Fixed-width `(r, s)` scalars suitable for `noxtls_crypto::p256_ecdsa_verify_*` APIs.
pub fn parse_ecdsa_signature_der(signature_der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let (seq, rem) = parse_der_node(signature_der)?;
    if seq.tag != 0x30 || !rem.is_empty() {
        return Err(Error::ParseFailure(
            "ecdsa signature must be top-level DER sequence",
        ));
    }
    let (r_node, rest) = parse_der_node(seq.body)?;
    let (s_node, tail) = parse_der_node(rest)?;
    if r_node.tag != 0x02 || s_node.tag != 0x02 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "ecdsa signature sequence must contain r and s integers only",
        ));
    }
    let r = der_integer_to_p256_scalar(r_node.body)?;
    let s = der_integer_to_p256_scalar(s_node.body)?;
    Ok((r, s))
}

/// Converts one DER INTEGER body into a 32-byte unsigned scalar for P-256.
///
/// # Arguments
///
/// * `value` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `der_integer_to_p256_scalar`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn der_integer_to_p256_scalar(value: &[u8]) -> Result<[u8; 32]> {
    if value.is_empty() {
        return Err(Error::ParseFailure("ecdsa der integer must not be empty"));
    }
    if value[0] & 0x80 != 0 {
        return Err(Error::ParseFailure(
            "ecdsa der integer must be non-negative",
        ));
    }
    if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
        return Err(Error::ParseFailure(
            "ecdsa der integer must use minimal encoding",
        ));
    }
    let normalized = if value.len() > 1 && value[0] == 0x00 {
        &value[1..]
    } else {
        value
    };
    if normalized.len() > 32 {
        return Err(Error::InvalidLength(
            "ecdsa der integer too large for p-256 scalar",
        ));
    }
    let mut out = [0_u8; 32];
    out[32 - normalized.len()..].copy_from_slice(normalized);
    Ok(out)
}

/// Builds `X25519PublicKey` from DER SPKI bytes for RFC 8410 X25519 keys.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed X25519 public key usable by `noxtls-crypto`.
pub fn x25519_public_key_from_spki_der(der: &[u8]) -> Result<X25519PublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_X25519 {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not X25519",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "x25519 algorithm parameters are not supported",
        ));
    }
    if info.subject_public_key.len() != 32 {
        return Err(Error::InvalidLength("x25519 public key must be 32 bytes"));
    }
    let mut public = [0_u8; 32];
    public.copy_from_slice(&info.subject_public_key);
    Ok(X25519PublicKey::from_bytes(public))
}

/// Builds `X448PublicKey` from DER SPKI bytes for RFC 8410 X448 keys.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed X448 public key usable by `noxtls-crypto`.
pub fn x448_public_key_from_spki_der(der: &[u8]) -> Result<X448PublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_X448 {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not X448",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "x448 algorithm parameters are not supported",
        ));
    }
    if info.subject_public_key.len() != 56 {
        return Err(Error::InvalidLength("x448 public key must be 56 bytes"));
    }
    let mut public = [0_u8; 56];
    public.copy_from_slice(&info.subject_public_key);
    Ok(X448PublicKey::from_bytes(public))
}

/// Builds `Ed25519PublicKey` from DER SPKI bytes for RFC 8410 Ed25519 keys.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed Ed25519 public key usable by `noxtls-crypto`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the algorithm OID is not Ed25519, parameters are present,
/// the subject key length is wrong, or the key bytes fail canonical public-key checks.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_public_key_from_spki_der(der: &[u8]) -> Result<Ed25519PublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_ED25519 {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not Ed25519",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "ed25519 algorithm parameters are not supported",
        ));
    }
    if info.subject_public_key.len() != 32 {
        return Err(Error::InvalidLength(
            "ed25519 public key must be 32 bytes",
        ));
    }
    let mut public = [0_u8; 32];
    public.copy_from_slice(&info.subject_public_key);
    Ed25519PublicKey::from_bytes(&public)
}

/// Builds `MlDsaPublicKey` from DER SPKI bytes for experimental ML-DSA keys.
///
/// # Arguments
/// * `der`: DER-encoded `SubjectPublicKeyInfo`.
///
/// # Returns
/// Parsed ML-DSA public key usable by `noxtls-crypto`.
pub fn mldsa_public_key_from_spki_der(der: &[u8]) -> Result<MlDsaPublicKey> {
    let info = parse_spki_public_key_info_der(der)?;
    if info.algorithm_oid != OID_ID_MLDSA65 {
        return Err(Error::UnsupportedFeature(
            "spki public key algorithm is not ML-DSA-65",
        ));
    }
    if info.algorithm_parameters_oid.is_some() {
        return Err(Error::UnsupportedFeature(
            "mldsa algorithm parameters are not supported",
        ));
    }
    MlDsaPublicKey::from_bytes(&info.subject_public_key)
}

/// Builds `RsaPrivateKey` from PEM PKCS#1 `RSA PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#1 RSA private key.
///
/// # Returns
/// Parsed RSA private key usable by `noxtls-crypto`.
pub fn rsa_private_key_from_pem_pkcs1(pem: &str) -> Result<RsaPrivateKey> {
    let der = rsa_private_key_pem_to_der_pkcs1(pem)?;
    rsa_private_key_from_pkcs1_der(&der)
}

/// Builds `RsaPrivateKey` from PEM PKCS#8 `PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#8 private key.
///
/// # Returns
/// Parsed RSA private key usable by `noxtls-crypto`.
pub fn rsa_private_key_from_pem_pkcs8(pem: &str) -> Result<RsaPrivateKey> {
    let der = private_key_pem_to_der_pkcs8(pem)?;
    rsa_private_key_from_pkcs8_der(&der)
}

/// Builds `P256PrivateKey` from PEM PKCS#8 `PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#8 EC private key.
///
/// # Returns
/// Parsed P-256 private key usable by `noxtls-crypto`.
pub fn p256_private_key_from_pem_pkcs8(pem: &str) -> Result<P256PrivateKey> {
    let der = private_key_pem_to_der_pkcs8(pem)?;
    p256_private_key_from_pkcs8_der(&der)
}

/// Builds `X25519PrivateKey` from PEM PKCS#8 `PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#8 X25519 private key.
///
/// # Returns
/// Parsed X25519 private key usable by `noxtls-crypto`.
pub fn x25519_private_key_from_pem_pkcs8(pem: &str) -> Result<X25519PrivateKey> {
    let der = private_key_pem_to_der_pkcs8(pem)?;
    x25519_private_key_from_pkcs8_der(&der)
}

/// Builds `X448PrivateKey` from PEM PKCS#8 `PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#8 X448 private key.
///
/// # Returns
/// Parsed X448 private key usable by `noxtls-crypto`.
pub fn x448_private_key_from_pem_pkcs8(pem: &str) -> Result<X448PrivateKey> {
    let der = private_key_pem_to_der_pkcs8(pem)?;
    x448_private_key_from_pkcs8_der(&der)
}

/// Builds `Ed25519PrivateKey` from PEM PKCS#8 `PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#8 Ed25519 private key.
///
/// # Returns
/// Parsed Ed25519 private key usable by `noxtls-crypto`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when PEM decoding or PKCS#8 parsing fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_private_key_from_pem_pkcs8(pem: &str) -> Result<Ed25519PrivateKey> {
    let der = private_key_pem_to_der_pkcs8(pem)?;
    ed25519_private_key_from_pkcs8_der(&der)
}

/// Builds `P256PrivateKey` from PEM SEC1 `EC PRIVATE KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SEC1 EC private key.
///
/// # Returns
/// Parsed P-256 private key usable by `noxtls-crypto`.
pub fn p256_private_key_from_pem_sec1(pem: &str) -> Result<P256PrivateKey> {
    let der = ec_private_key_pem_to_der_sec1(pem)?;
    p256_private_key_from_sec1_der(&der)
}

/// Builds `RsaPublicKey` from PEM SPKI `PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SPKI public key.
///
/// # Returns
/// Parsed RSA public key usable by `noxtls-crypto`.
pub fn rsa_public_key_from_pem_spki(pem: &str) -> Result<RsaPublicKey> {
    let der = public_key_pem_to_der_spki(pem)?;
    rsa_public_key_from_spki_der(&der)
}

/// Builds `RsaPublicKey` from PEM PKCS#1 `RSA PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one PKCS#1 RSA public key.
///
/// # Returns
/// Parsed RSA public key usable by `noxtls-crypto`.
pub fn rsa_public_key_from_pem_pkcs1(pem: &str) -> Result<RsaPublicKey> {
    let der = rsa_public_key_pem_to_der_pkcs1(pem)?;
    rsa_public_key_from_pkcs1_der(&der)
}

/// Builds `P256PublicKey` from PEM SPKI `PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SPKI EC public key.
///
/// # Returns
/// Parsed P-256 public key usable by `noxtls-crypto`.
pub fn p256_public_key_from_pem_spki(pem: &str) -> Result<P256PublicKey> {
    let der = public_key_pem_to_der_spki(pem)?;
    p256_public_key_from_spki_der(&der)
}

/// Builds `X25519PublicKey` from PEM SPKI `PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SPKI X25519 public key.
///
/// # Returns
/// Parsed X25519 public key usable by `noxtls-crypto`.
pub fn x25519_public_key_from_pem_spki(pem: &str) -> Result<X25519PublicKey> {
    let der = public_key_pem_to_der_spki(pem)?;
    x25519_public_key_from_spki_der(&der)
}

/// Builds `X448PublicKey` from PEM SPKI `PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SPKI X448 public key.
///
/// # Returns
/// Parsed X448 public key usable by `noxtls-crypto`.
pub fn x448_public_key_from_pem_spki(pem: &str) -> Result<X448PublicKey> {
    let der = public_key_pem_to_der_spki(pem)?;
    x448_public_key_from_spki_der(&der)
}

/// Builds `Ed25519PublicKey` from PEM SPKI `PUBLIC KEY` text.
///
/// # Arguments
/// * `pem`: PEM text containing one SPKI Ed25519 public key.
///
/// # Returns
/// Parsed Ed25519 public key usable by `noxtls-crypto`.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when PEM decoding or SPKI parsing fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
pub fn ed25519_public_key_from_pem_spki(pem: &str) -> Result<Ed25519PublicKey> {
    let der = public_key_pem_to_der_spki(pem)?;
    ed25519_public_key_from_spki_der(&der)
}

/// Reads one PKCS#8 `PRIVATE KEY` PEM file and parses it as `P256PrivateKey`.
///
/// # Arguments
/// * `path`: Filesystem path to a PEM file containing one PKCS#8 P-256 key.
///
/// # Returns
/// Parsed P-256 private key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when file IO, PEM decoding, or PKCS#8 parsing fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn p256_private_key_from_pem_file_pkcs8(path: &Path) -> Result<P256PrivateKey> {
    let der = pem_file_to_der(path, "PRIVATE KEY")?;
    p256_private_key_from_pkcs8_der(&der)
}

/// Encodes `P256PrivateKey` as PKCS#8 PEM and writes it to a file.
///
/// # Arguments
/// * `path`: Destination path for PEM text.
/// * `private`: P-256 private key to serialize.
///
/// # Returns
/// `Ok(())` after writing one `PRIVATE KEY` PEM block.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or file write fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn p256_private_key_to_pem_file_pkcs8(path: &Path, private: &P256PrivateKey) -> Result<()> {
    let der = p256_private_key_to_pkcs8_der(private)?;
    der_to_pem_file(path, &der, "PRIVATE KEY")
}

/// Reads one PKCS#8 `PRIVATE KEY` PEM file and parses it as `X25519PrivateKey`.
///
/// # Arguments
/// * `path`: Filesystem path to a PEM file containing one PKCS#8 X25519 key.
///
/// # Returns
/// Parsed X25519 private key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when file IO, PEM decoding, or PKCS#8 parsing fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn x25519_private_key_from_pem_file_pkcs8(path: &Path) -> Result<X25519PrivateKey> {
    let der = pem_file_to_der(path, "PRIVATE KEY")?;
    x25519_private_key_from_pkcs8_der(&der)
}

/// Encodes `X25519PrivateKey` as PKCS#8 PEM and writes it to a file.
///
/// # Arguments
/// * `path`: Destination path for PEM text.
/// * `private`: X25519 private key to serialize.
///
/// # Returns
/// `Ok(())` after writing one `PRIVATE KEY` PEM block.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or file write fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn x25519_private_key_to_pem_file_pkcs8(path: &Path, private: X25519PrivateKey) -> Result<()> {
    let der = x25519_private_key_to_pkcs8_der(private)?;
    der_to_pem_file(path, &der, "PRIVATE KEY")
}

/// Reads one PKCS#8 `PRIVATE KEY` PEM file and parses it as `X448PrivateKey`.
///
/// # Arguments
/// * `path`: Filesystem path to a PEM file containing one PKCS#8 X448 key.
///
/// # Returns
/// Parsed X448 private key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when file IO, PEM decoding, or PKCS#8 parsing fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn x448_private_key_from_pem_file_pkcs8(path: &Path) -> Result<X448PrivateKey> {
    let der = pem_file_to_der(path, "PRIVATE KEY")?;
    x448_private_key_from_pkcs8_der(&der)
}

/// Encodes `X448PrivateKey` as PKCS#8 PEM and writes it to a file.
///
/// # Arguments
/// * `path`: Destination path for PEM text.
/// * `private`: X448 private key to serialize.
///
/// # Returns
/// `Ok(())` after writing one `PRIVATE KEY` PEM block.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or file write fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn x448_private_key_to_pem_file_pkcs8(path: &Path, private: X448PrivateKey) -> Result<()> {
    let der = x448_private_key_to_pkcs8_der(private)?;
    der_to_pem_file(path, &der, "PRIVATE KEY")
}

/// Reads one PKCS#8 `PRIVATE KEY` PEM file and parses it as `Ed25519PrivateKey`.
///
/// # Arguments
/// * `path`: Filesystem path to a PEM file containing one PKCS#8 Ed25519 key.
///
/// # Returns
/// Parsed Ed25519 private key.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when file IO, PEM decoding, or PKCS#8 parsing fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn ed25519_private_key_from_pem_file_pkcs8(path: &Path) -> Result<Ed25519PrivateKey> {
    let der = pem_file_to_der(path, "PRIVATE KEY")?;
    ed25519_private_key_from_pkcs8_der(&der)
}

/// Encodes `Ed25519PrivateKey` as PKCS#8 PEM and writes it to a file.
///
/// # Arguments
/// * `path`: Destination path for PEM text.
/// * `private`: Ed25519 private key to serialize.
///
/// # Returns
/// `Ok(())` after writing one `PRIVATE KEY` PEM block.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when DER encoding or file write fails.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "std")]
pub fn ed25519_private_key_to_pem_file_pkcs8(
    path: &Path,
    private: &Ed25519PrivateKey,
) -> Result<()> {
    let der = ed25519_private_key_to_pkcs8_der(private)?;
    der_to_pem_file(path, &der, "PRIVATE KEY")
}

/// Parses PKCS#1 RSAPrivateKey DER and returns key field parts.
///
/// # Arguments
/// * `der`: DER-encoded `RSAPrivateKey` sequence bytes.
///
/// # Returns
/// Parsed RSA private-key fields (`n`, `e`, `d`).
pub fn parse_pkcs1_rsa_private_key_der(der: &[u8]) -> Result<RsaPrivateKeyDerParts> {
    let (seq, tail) = parse_der_node(der)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "pkcs1 rsa private key must be top-level sequence",
        ));
    }
    let mut cursor = seq.body;
    let (version, rest) = parse_der_node(cursor)?;
    if version.tag != 0x02 || version.body.is_empty() {
        return Err(Error::ParseFailure("pkcs1 rsa private key missing version"));
    }
    if version.body[version.body.len() - 1] > 1 {
        return Err(Error::ParseFailure(
            "unsupported pkcs1 rsa private key version",
        ));
    }
    cursor = rest;
    let (modulus, rest) = parse_der_integer(cursor, "pkcs1 rsa private key missing modulus")?;
    let (public_exponent, rest) =
        parse_der_integer(rest, "pkcs1 rsa private key missing public exponent")?;
    let (private_exponent, _rest) =
        parse_der_integer(rest, "pkcs1 rsa private key missing private exponent")?;
    Ok(RsaPrivateKeyDerParts {
        modulus,
        public_exponent,
        private_exponent,
    })
}

/// Parses PKCS#1 RSAPublicKey DER and returns modulus/exponent fields.
///
/// # Arguments
/// * `der`: DER-encoded `RSAPublicKey` sequence bytes.
///
/// # Returns
/// Parsed RSA public-key fields (`n`, `e`).
pub fn parse_pkcs1_rsa_public_key_der(der: &[u8]) -> Result<RsaPublicKeyDerParts> {
    let (seq, tail) = parse_der_node(der)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "pkcs1 rsa public key must be top-level sequence",
        ));
    }
    let (modulus, rest) = parse_der_integer(seq.body, "pkcs1 rsa public key missing modulus")?;
    let (public_exponent, rest) =
        parse_der_integer(rest, "pkcs1 rsa public key missing public exponent")?;
    if !rest.is_empty() {
        return Err(Error::ParseFailure(
            "unexpected bytes in pkcs1 rsa public key",
        ));
    }
    Ok(RsaPublicKeyDerParts {
        modulus,
        public_exponent,
    })
}

/// Parses PKCS#8 PrivateKeyInfo DER and extracts algorithm OID and key octets.
///
/// # Arguments
/// * `der`: DER-encoded `PrivateKeyInfo` bytes.
///
/// # Returns
/// Parsed algorithm OID and private-key octet string payload.
pub fn parse_pkcs8_private_key_info_der(der: &[u8]) -> Result<Pkcs8PrivateKeyInfoDerParts> {
    let (seq, tail) = parse_der_node(der)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "pkcs8 private key must be top-level sequence",
        ));
    }
    let (version, rest) = parse_der_node(seq.body)?;
    if version.tag != 0x02 || version.body.is_empty() {
        return Err(Error::ParseFailure("pkcs8 private key missing version"));
    }
    let (algorithm, rest) = parse_der_node(rest)?;
    if algorithm.tag != 0x30 {
        return Err(Error::ParseFailure(
            "pkcs8 private key missing algorithm identifier",
        ));
    }
    let (oid, params_tail) = parse_der_node(algorithm.body)?;
    if oid.tag != 0x06 {
        return Err(Error::ParseFailure(
            "pkcs8 private key algorithm missing oid",
        ));
    }
    let algorithm_parameters_oid = if params_tail.is_empty() {
        None
    } else {
        let (params, tail) = parse_der_node(params_tail)?;
        if !tail.is_empty() {
            return Err(Error::ParseFailure(
                "unsupported pkcs8 algorithm parameters",
            ));
        }
        if params.tag == 0x06 {
            Some(params.body.to_vec())
        } else if params.tag == 0x05 && params.body.is_empty() {
            None
        } else {
            return Err(Error::ParseFailure(
                "unsupported pkcs8 algorithm parameters",
            ));
        }
    };
    let (private_key, _rest) = parse_der_node(rest)?;
    if private_key.tag != 0x04 {
        return Err(Error::ParseFailure(
            "pkcs8 private key missing private key octets",
        ));
    }
    Ok(Pkcs8PrivateKeyInfoDerParts {
        algorithm_oid: oid.body.to_vec(),
        algorithm_parameters_oid,
        private_key: private_key.body.to_vec(),
    })
}

/// Parses SubjectPublicKeyInfo DER and extracts algorithm OID and key bit-string bytes.
///
/// # Arguments
/// * `der`: DER-encoded SPKI bytes.
///
/// # Returns
/// Parsed algorithm OID and subject public key bit-string payload bytes.
pub fn parse_spki_public_key_info_der(der: &[u8]) -> Result<SpkiPublicKeyInfoDerParts> {
    let (seq, tail) = parse_der_node(der)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("spki must be top-level sequence"));
    }
    let (algorithm, rest) = parse_der_node(seq.body)?;
    if algorithm.tag != 0x30 {
        return Err(Error::ParseFailure("spki missing algorithm identifier"));
    }
    let (oid, params_tail) = parse_der_node(algorithm.body)?;
    if oid.tag != 0x06 {
        return Err(Error::ParseFailure("spki algorithm missing oid"));
    }
    let algorithm_parameters_oid = if params_tail.is_empty() {
        None
    } else {
        let (params, tail) = parse_der_node(params_tail)?;
        if !tail.is_empty() {
            return Err(Error::ParseFailure("unsupported spki algorithm parameters"));
        }
        if params.tag == 0x06 {
            Some(params.body.to_vec())
        } else if params.tag == 0x05 && params.body.is_empty() {
            None
        } else {
            return Err(Error::ParseFailure("unsupported spki algorithm parameters"));
        }
    };
    let (subject_public_key, rest) = parse_der_node(rest)?;
    if subject_public_key.tag != 0x03 || !rest.is_empty() {
        return Err(Error::ParseFailure(
            "spki missing subject public key bit string",
        ));
    }
    let key_bytes = parse_der_bit_string(subject_public_key.body)?;
    Ok(SpkiPublicKeyInfoDerParts {
        algorithm_oid: oid.body.to_vec(),
        algorithm_parameters_oid,
        subject_public_key: key_bytes,
    })
}

/// Parses one DER `INTEGER` TLV and returns canonical positive big-endian bytes plus the tail slice.
///
/// # Arguments
///
/// * `input` — DER input beginning at an INTEGER tag.
/// * `missing_message` — Parse failure message when the tag or body is invalid.
///
/// # Returns
///
/// On success, `(integer_body, rest)` where `integer_body` has no redundant leading zero except when needed for sign.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the node is missing, not an INTEGER, or empty.
///
/// # Panics
///
/// This function does not panic.
fn parse_der_integer<'a>(
    input: &'a [u8],
    missing_message: &'static str,
) -> Result<(Vec<u8>, &'a [u8])> {
    let (node, rest) = parse_der_node(input)?;
    if node.tag != 0x02 || node.body.is_empty() {
        return Err(Error::ParseFailure(missing_message));
    }
    let mut bytes = node.body;
    if bytes.len() > 1 && bytes[0] == 0x00 {
        bytes = &bytes[1..];
    }
    Ok((bytes.to_vec(), rest))
}

/// Parses DER BIT STRING payload and removes unused-bit count byte.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_der_bit_string`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_der_bit_string(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(Error::ParseFailure("empty DER bit string"));
    }
    if input[0] > 7 {
        return Err(Error::ParseFailure(
            "invalid DER bit string unused-bit count",
        ));
    }
    Ok(input[1..].to_vec())
}

/// Parses SEC1 ECPrivateKey DER and returns 32-byte private scalar.
///
/// # Arguments
///
/// * `der` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_sec1_ec_private_key_scalar`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_sec1_ec_private_key_scalar(der: &[u8]) -> Result<[u8; 32]> {
    let (seq, tail) = parse_der_node(der)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "sec1 ec private key must be top-level sequence",
        ));
    }
    let (version, rest) = parse_der_node(seq.body)?;
    if version.tag != 0x02 || version.body.is_empty() {
        return Err(Error::ParseFailure("sec1 ec private key missing version"));
    }
    if version.body[version.body.len() - 1] != 0x01 {
        return Err(Error::ParseFailure(
            "unsupported sec1 ec private key version",
        ));
    }
    let (private_key, _rest) = parse_der_node(rest)?;
    if private_key.tag != 0x04 {
        return Err(Error::ParseFailure(
            "sec1 ec private key missing private key octets",
        ));
    }
    if private_key.body.len() != 32 {
        return Err(Error::InvalidLength(
            "p256 private key scalar must be 32 bytes",
        ));
    }
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(private_key.body);
    Ok(scalar)
}

/// Parses X25519 private-key bytes from PKCS#8 privateKey field contents.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_x25519_private_key_bytes`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_x25519_private_key_bytes(input: &[u8]) -> Result<[u8; 32]> {
    if input.len() == 32 {
        let mut scalar = [0_u8; 32];
        scalar.copy_from_slice(input);
        return Ok(scalar);
    }
    let (inner, tail) = parse_der_node(input)?;
    if inner.tag != 0x04 || !tail.is_empty() || inner.body.len() != 32 {
        return Err(Error::ParseFailure("invalid x25519 private key bytes"));
    }
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(inner.body);
    Ok(scalar)
}

/// Parses X448 private-key bytes from PKCS#8 privateKey field contents.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_x448_private_key_bytes`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_x448_private_key_bytes(input: &[u8]) -> Result<[u8; 56]> {
    if input.len() == 56 {
        let mut scalar = [0_u8; 56];
        scalar.copy_from_slice(input);
        return Ok(scalar);
    }
    let (inner, tail) = parse_der_node(input)?;
    if inner.tag != 0x04 || !tail.is_empty() || inner.body.len() != 56 {
        return Err(Error::ParseFailure("invalid x448 private key bytes"));
    }
    let mut scalar = [0_u8; 56];
    scalar.copy_from_slice(inner.body);
    Ok(scalar)
}

/// Parses Ed25519 private-key seed bytes from PKCS#8 `privateKey` field contents (RFC 8410 `CurvePrivateKey`).
///
/// # Arguments
///
/// * `input` — Octets from the PKCS#8 `PrivateKeyInfo.privateKey` OCTET STRING body.
///
/// # Returns
///
/// On success, a 32-byte secret seed suitable for [`Ed25519PrivateKey::from_seed`].
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the slice is not exactly 32 raw bytes and not a single
/// DER `OCTET STRING` wrapping exactly 32 seed octets.
///
/// # Panics
///
/// This function does not panic.
fn parse_ed25519_private_key_seed(input: &[u8]) -> Result<[u8; 32]> {
    if input.len() == 32 {
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(input);
        return Ok(seed);
    }
    let (inner, tail) = parse_der_node(input)?;
    if inner.tag != 0x04 || !tail.is_empty() || inner.body.len() != 32 {
        return Err(Error::ParseFailure("invalid ed25519 private key bytes"));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(inner.body);
    Ok(seed)
}

/// Encodes integer bytes as DER INTEGER with positive-sign prefix when needed.
///
/// # Arguments
///
/// * `value` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_der_integer` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_der_integer(value: &[u8]) -> Vec<u8> {
    let mut body = if value.is_empty() {
        vec![0x00]
    } else {
        value.to_vec()
    };
    while body.len() > 1 && body[0] == 0x00 {
        body.remove(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00);
    }
    encode_der_node(0x02, &body)
}

/// Encodes DER SEQUENCE from concatenated child encodings.
///
/// # Arguments
///
/// * `children` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `encode_der_sequence`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_der_sequence(children: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0x30];
    out.extend_from_slice(&encode_der_len(children.len())?);
    out.extend_from_slice(children);
    Ok(out)
}

/// Encodes one DER TLV node from tag and body bytes.
///
/// # Arguments
///
/// * `tag` — `u8`.
/// * `body` — `&[u8]`.
///
/// # Returns
///
/// `Vec<u8>` produced by `encode_der_node` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_der_node(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_der_len(body.len()).expect("der len should encode"));
    out.extend_from_slice(body);
    out
}

/// Encodes DER length bytes in short/long form.
///
/// # Arguments
///
/// * `len` — `usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from `encode_der_len`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn encode_der_len(len: usize) -> Result<Vec<u8>> {
    if len < 128 {
        return Ok(vec![len as u8]);
    }
    let len_u32 = u32::try_from(len).map_err(|_| Error::InvalidLength("der length too large"))?;
    let bytes = len_u32.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let content = &bytes[first_nonzero..];
    let mut out = vec![0x80 | (content.len() as u8)];
    out.extend_from_slice(content);
    Ok(out)
}

/// Encodes an X.509 `SubjectPublicKeyInfo` SEQUENCE from algorithm OID, optional parameters OID, and key material.
///
/// # Arguments
///
/// * `algorithm_oid` — DER OID body bytes (without tag/length) for the public-key algorithm.
/// * `algorithm_parameters_oid` — When `Some`, a second OID node for parameters (for example EC named curve).
/// * `subject_public_key` — Raw public key octets placed inside a BIT STRING with no unused bits.
///
/// # Returns
///
/// On success, the full SPKI DER SEQUENCE.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested TLV encoding fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
fn encode_spki_public_key_info_der(
    algorithm_oid: &[u8],
    algorithm_parameters_oid: Option<&[u8]>,
    subject_public_key: &[u8],
) -> Result<Vec<u8>> {
    let algorithm = {
        let mut algorithm_body = Vec::new();
        algorithm_body.extend_from_slice(&encode_der_node(0x06, algorithm_oid));
        if let Some(params_oid) = algorithm_parameters_oid {
            algorithm_body.extend_from_slice(&encode_der_node(0x06, params_oid));
        }
        encode_der_node(0x30, &algorithm_body)
    };
    let mut bit_string_body = vec![0x00];
    bit_string_body.extend_from_slice(subject_public_key);
    let subject_public_key = encode_der_node(0x03, &bit_string_body);
    encode_der_sequence(&[algorithm, subject_public_key].concat())
}

/// Encodes a PKCS#8 `PrivateKeyInfo` SEQUENCE for private-key material.
///
/// # Arguments
///
/// * `algorithm_oid` — DER OID body bytes for `AlgorithmIdentifier.algorithm`.
/// * `algorithm_parameters_oid` — Optional DER OID body for `AlgorithmIdentifier.parameters`.
/// * `private_key` — Raw bytes inserted as the body of the `privateKey` OCTET STRING.
///
/// # Returns
///
/// On success, the full PKCS#8 DER `PrivateKeyInfo` bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when nested DER sequence/length encoding fails.
///
/// # Panics
///
/// This function does not panic.
fn encode_pkcs8_private_key_info_der(
    algorithm_oid: &[u8],
    algorithm_parameters_oid: Option<&[u8]>,
    private_key: &[u8],
) -> Result<Vec<u8>> {
    let version = encode_der_integer(&[0x00]);
    let algorithm = {
        let mut algorithm_body = Vec::new();
        algorithm_body.extend_from_slice(&encode_der_node(0x06, algorithm_oid));
        if let Some(params_oid) = algorithm_parameters_oid {
            algorithm_body.extend_from_slice(&encode_der_node(0x06, params_oid));
        }
        encode_der_node(0x30, &algorithm_body)
    };
    let private_key = encode_der_node(0x04, private_key);
    encode_der_sequence(&[version, algorithm, private_key].concat())
}

#[cfg(test)]
mod ed25519_pkcs8_tests {
    use super::*;
    use noxtls_pem::private_key_der_to_pem_pkcs8;
    #[cfg(feature = "std")]
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn sample_ed25519_seed() -> [u8; 32] {
        let mut seed = [0_u8; 32];
        for i in 0..32 {
            seed[i] = i as u8 + 1;
        }
        seed
    }

    /// Builds PKCS#8 `PrivateKeyInfo` for Ed25519 with nested `OCTET STRING` seed encoding.
    fn ed25519_pkcs8_der_nested_octet(seed: &[u8; 32]) -> Vec<u8> {
        let mut der = Vec::new();
        der.extend_from_slice(&[
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        der.extend_from_slice(seed);
        der
    }

    /// Builds PKCS#8 `PrivateKeyInfo` for Ed25519 with a raw 32-byte seed inside the outer OCTET STRING.
    fn ed25519_pkcs8_der_raw_seed(seed: &[u8; 32]) -> Vec<u8> {
        let mut der = Vec::new();
        der.extend_from_slice(&[
            0x30, 0x2C, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x20,
        ]);
        der.extend_from_slice(seed);
        der
    }

    /// Confirms RFC 8410 nested `CurvePrivateKey` PKCS#8 encoding parses and matches SPKI roundtrip.
    #[test]
    fn ed25519_pkcs8_nested_octet_parses_and_spki_roundtrips() {
        let seed = sample_ed25519_seed();
        let der = ed25519_pkcs8_der_nested_octet(&seed);
        let sk = ed25519_private_key_from_pkcs8_der(&der).expect("pkcs8 nested");
        let pk_der = ed25519_public_key_to_spki_der(sk.verifying_key()).expect("spki der");
        let pk_back = ed25519_public_key_from_spki_der(&pk_der).expect("spki parse");
        assert_eq!(pk_back.to_bytes(), sk.verifying_key().to_bytes());
    }

    /// Confirms PKCS#8 with a raw 32-byte `privateKey` body parses to the same verifying key.
    #[test]
    fn ed25519_pkcs8_raw_seed_in_private_key_field_parses() {
        let mut seed = [0_u8; 32];
        for i in 0..32 {
            seed[i] = i as u8 + 7;
        }
        let der = ed25519_pkcs8_der_raw_seed(&seed);
        let sk = ed25519_private_key_from_pkcs8_der(&der).expect("pkcs8 raw");
        let expect = Ed25519PrivateKey::from_seed(&seed).verifying_key().to_bytes();
        assert_eq!(sk.verifying_key().to_bytes(), expect);
    }

    /// Confirms PEM PKCS#8 roundtrip for Ed25519 keys.
    #[test]
    fn ed25519_pem_pkcs8_roundtrip() {
        let seed = [9_u8; 32];
        let der = ed25519_pkcs8_der_nested_octet(&seed);
        let pem = private_key_der_to_pem_pkcs8(&der).expect("pem encode");
        let sk = ed25519_private_key_from_pem_pkcs8(&pem).expect("pem decode");
        assert_eq!(
            sk.verifying_key().to_bytes(),
            Ed25519PrivateKey::from_seed(&seed)
                .verifying_key()
                .to_bytes()
        );
    }

    /// Confirms PEM SPKI roundtrip for Ed25519 public keys.
    #[test]
    fn ed25519_pem_spki_roundtrip() {
        let sk = Ed25519PrivateKey::from_seed(&sample_ed25519_seed());
        let pk = sk.verifying_key();
        let pem = ed25519_public_key_to_pem_spki(pk).expect("pem spki");
        let pk_back = ed25519_public_key_from_pem_spki(&pem).expect("pem parse");
        assert_eq!(pk_back.to_bytes(), pk.to_bytes());
    }

    /// Confirms P-256 PKCS#8 serialization roundtrip preserves the derived public key.
    #[test]
    fn p256_pkcs8_serialize_roundtrip() {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let sk = P256PrivateKey::from_bytes(scalar).expect("p256 seed");
        let der = p256_private_key_to_pkcs8_der(&sk).expect("serialize");
        let decoded = p256_private_key_from_pkcs8_der(&der).expect("parse");
        let expected_pub = sk.public_key().expect("pub a").to_uncompressed().expect("sec1 a");
        let decoded_pub = decoded
            .public_key()
            .expect("pub b")
            .to_uncompressed()
            .expect("sec1 b");
        assert_eq!(decoded_pub, expected_pub);
    }

    /// Confirms X25519 PKCS#8 serialization roundtrip preserves the public key.
    #[test]
    fn x25519_pkcs8_serialize_roundtrip() {
        let private = X25519PrivateKey::from_bytes([0x21; 32]);
        let der = x25519_private_key_to_pkcs8_der(private.clone()).expect("serialize");
        let decoded = x25519_private_key_from_pkcs8_der(&der).expect("parse");
        assert_eq!(decoded.public_key().bytes, private.public_key().bytes);
    }

    /// Confirms X448 PKCS#8 serialization roundtrip preserves private scalar bytes.
    #[test]
    fn x448_pkcs8_serialize_roundtrip() {
        let private = X448PrivateKey::from_bytes([0x37; 56]);
        let der = x448_private_key_to_pkcs8_der(private.clone()).expect("serialize");
        let decoded = x448_private_key_from_pkcs8_der(&der).expect("parse");
        assert_eq!(decoded.to_bytes(), private.to_bytes());
    }

    /// Confirms Ed25519 PKCS#8 serializer roundtrips through parser.
    #[test]
    fn ed25519_pkcs8_serialize_roundtrip() {
        let private = Ed25519PrivateKey::from_seed(&sample_ed25519_seed());
        let der = ed25519_private_key_to_pkcs8_der(&private).expect("serialize");
        let decoded = ed25519_private_key_from_pkcs8_der(&der).expect("parse");
        assert_eq!(
            decoded.verifying_key().to_bytes(),
            private.verifying_key().to_bytes()
        );
    }

    /// Creates a unique temp path for key-format file lifecycle tests.
    ///
    /// # Arguments
    ///
    /// * `stem` — File-name stem.
    ///
    /// # Returns
    ///
    /// A path in the process temp directory that should not collide with other tests.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[cfg(feature = "std")]
    fn unique_temp_file(stem: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("noxtls_{stem}_{}_{}.pem", std::process::id(), nanos))
    }

    /// Confirms PKCS#8 private-key file read/write wrappers roundtrip an Ed25519 key.
    #[cfg(feature = "std")]
    #[test]
    fn ed25519_pkcs8_file_roundtrip() {
        let path = unique_temp_file("ed25519_pkcs8");
        let private = Ed25519PrivateKey::from_seed(&sample_ed25519_seed());
        ed25519_private_key_to_pem_file_pkcs8(&path, &private).expect("write");
        let decoded = ed25519_private_key_from_pem_file_pkcs8(&path).expect("read");
        assert_eq!(
            decoded.verifying_key().to_bytes(),
            private.verifying_key().to_bytes()
        );
        let _ = fs::remove_file(path);
    }

    /// Confirms PKCS#8 private-key file read/write wrappers roundtrip X25519 keys.
    #[cfg(feature = "std")]
    #[test]
    fn x25519_pkcs8_file_roundtrip() {
        let path = unique_temp_file("x25519_pkcs8");
        let private = X25519PrivateKey::from_bytes([0x42; 32]);
        x25519_private_key_to_pem_file_pkcs8(&path, private.clone()).expect("write");
        let decoded = x25519_private_key_from_pem_file_pkcs8(&path).expect("read");
        assert_eq!(decoded.public_key().bytes, private.public_key().bytes);
        let _ = fs::remove_file(path);
    }

    /// Confirms PKCS#8 private-key file read/write wrappers roundtrip P-256 keys.
    #[cfg(feature = "std")]
    #[test]
    fn p256_pkcs8_file_roundtrip() {
        let path = unique_temp_file("p256_pkcs8");
        let mut scalar = [0_u8; 32];
        scalar[31] = 3;
        let private = P256PrivateKey::from_bytes(scalar).expect("p256");
        p256_private_key_to_pem_file_pkcs8(&path, &private).expect("write");
        let decoded = p256_private_key_from_pem_file_pkcs8(&path).expect("read");
        let expected_pub = private
            .public_key()
            .expect("pub a")
            .to_uncompressed()
            .expect("sec1 a");
        let decoded_pub = decoded
            .public_key()
            .expect("pub b")
            .to_uncompressed()
            .expect("sec1 b");
        assert_eq!(decoded_pub, expected_pub);
        let _ = fs::remove_file(path);
    }

    /// Confirms PKCS#8 private-key file read/write wrappers roundtrip X448 private scalar bytes.
    #[cfg(feature = "std")]
    #[test]
    fn x448_pkcs8_file_roundtrip() {
        let path = unique_temp_file("x448_pkcs8");
        let private = X448PrivateKey::from_bytes([0x17; 56]);
        x448_private_key_to_pem_file_pkcs8(&path, private.clone()).expect("write");
        let decoded = x448_private_key_from_pem_file_pkcs8(&path).expect("read");
        assert_eq!(decoded.to_bytes(), private.to_bytes());
        let _ = fs::remove_file(path);
    }
}


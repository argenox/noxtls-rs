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
    p256_ecdsa_sign_sha256, rsassa_sha256_sign, P256PrivateKey, P256PublicKey, RsaPrivateKey,
    RsaPublicKey,
};

use super::{p256_public_key_to_spki_der, rsa_public_key_to_spki_der};

/// Writes DER INTEGER encoding for a positive integer value.
///
/// # Arguments
/// * `value`: Big-endian integer bytes to encode.
///
/// # Returns
/// DER-encoded INTEGER TLV bytes.
pub fn write_der_integer(value: &[u8]) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Err(Error::InvalidLength("der integer value must not be empty"));
    }
    let mut body = value.to_vec();
    while body.len() > 1 && body[0] == 0 {
        body.remove(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00);
    }
    let mut out = vec![0x02];
    out.extend_from_slice(&encode_der_len(body.len())?);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Writes DER SEQUENCE around already-encoded child elements.
///
/// # Arguments
/// * `encoded_children`: Concatenated DER-encoded child TLVs.
///
/// # Returns
/// DER-encoded SEQUENCE TLV bytes.
pub fn write_der_sequence(encoded_children: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0x30];
    out.extend_from_slice(&encode_der_len(encoded_children.len())?);
    out.extend_from_slice(encoded_children);
    Ok(out)
}

/// Writes DER OBJECT IDENTIFIER encoding from content octets.
///
/// # Arguments
/// * `oid_content`: BER/DER OID content octets (without tag/length).
///
/// # Returns
/// DER-encoded OBJECT IDENTIFIER TLV bytes.
pub fn write_der_oid(oid_content: &[u8]) -> Result<Vec<u8>> {
    if oid_content.is_empty() {
        return Err(Error::InvalidLength("der oid value must not be empty"));
    }
    let mut out = vec![0x06];
    out.extend_from_slice(&encode_der_len(oid_content.len())?);
    out.extend_from_slice(oid_content);
    Ok(out)
}

/// Writes DER BIT STRING encoding with zero unused bits.
///
/// # Arguments
/// * `bits`: Bit-string payload bytes to encode.
///
/// # Returns
/// DER-encoded BIT STRING TLV bytes.
pub fn write_der_bit_string(bits: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0x03];
    out.extend_from_slice(&encode_der_len(bits.len() + 1)?);
    out.push(0x00); // unused-bit count
    out.extend_from_slice(bits);
    Ok(out)
}

/// Writes a minimal certificate-like DER structure for fixture generation workflows.
///
/// # Arguments
/// * `serial`: Certificate serial number bytes.
/// * `raw_tbs`: Pre-encoded TBSCertificate child bytes to embed.
///
/// # Returns
/// DER bytes containing a minimal certificate-like sequence.
pub fn write_minimal_certificate_der(serial: &[u8], raw_tbs: &[u8]) -> Result<Vec<u8>> {
    let serial_der = write_der_integer(serial)?;
    let mut tbs_children = Vec::new();
    tbs_children.extend_from_slice(&serial_der);
    tbs_children.extend_from_slice(raw_tbs);
    let tbs_der = write_der_sequence(&tbs_children)?;
    write_der_sequence(&tbs_der)
}

/// Writes a self-signed X.509 v3 certificate using RSA PKCS#1 v1.5 SHA-256.
///
/// # Arguments
/// * `serial`: Certificate serial number bytes.
/// * `common_name`: Subject/issuer commonName for self-signed identity.
/// * `not_before`: DER time string (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`).
/// * `not_after`: DER time string (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`).
/// * `public_key`: RSA public key for SPKI.
/// * `private_key`: RSA private key for self-signature.
///
/// # Returns
/// DER-encoded X.509 certificate.
pub fn write_self_signed_certificate_rsa_sha256(
    serial: &[u8],
    common_name: &str,
    not_before: &str,
    not_after: &str,
    public_key: &RsaPublicKey,
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>> {
    let spki_der = rsa_public_key_to_spki_der(public_key)?;
    let tbs_der = build_certificate_tbs(
        serial,
        common_name,
        not_before,
        not_after,
        &algorithm_identifier_sha256_with_rsa()?,
        &spki_der,
        true,
    )?;
    let signature = rsassa_sha256_sign(private_key, &tbs_der)?;
    build_certificate_der(
        &tbs_der,
        &algorithm_identifier_sha256_with_rsa()?,
        &signature,
    )
}

/// Writes a self-signed X.509 v3 certificate using ECDSA P-256 SHA-256.
///
/// # Arguments
/// * `serial`: Certificate serial number bytes.
/// * `common_name`: Subject/issuer commonName for self-signed identity.
/// * `not_before`: DER time string (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`).
/// * `not_after`: DER time string (`YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`).
/// * `public_key`: P-256 public key for SPKI.
/// * `private_key`: P-256 private key for self-signature.
///
/// # Returns
/// DER-encoded X.509 certificate.
pub fn write_self_signed_certificate_p256_sha256(
    serial: &[u8],
    common_name: &str,
    not_before: &str,
    not_after: &str,
    public_key: &P256PublicKey,
    private_key: &P256PrivateKey,
) -> Result<Vec<u8>> {
    let spki_der = p256_public_key_to_spki_der(public_key)?;
    let tbs_der = build_certificate_tbs(
        serial,
        common_name,
        not_before,
        not_after,
        &algorithm_identifier_ecdsa_sha256()?,
        &spki_der,
        true,
    )?;
    let (r, s) = p256_ecdsa_sign_sha256(private_key, &tbs_der)?;
    let signature_der = write_ecdsa_signature_der(&r, &s)?;
    build_certificate_der(
        &tbs_der,
        &algorithm_identifier_ecdsa_sha256()?,
        &signature_der,
    )
}

/// Writes a PKCS#10 CSR using RSA PKCS#1 v1.5 SHA-256.
///
/// # Arguments
/// * `common_name`: CSR subject commonName.
/// * `public_key`: RSA public key for SubjectPublicKeyInfo.
/// * `private_key`: RSA private key used to sign CertificationRequestInfo.
///
/// # Returns
/// DER-encoded CertificationRequest.
pub fn write_csr_rsa_sha256(
    common_name: &str,
    public_key: &RsaPublicKey,
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>> {
    let spki_der = rsa_public_key_to_spki_der(public_key)?;
    let cri_der = build_csr_info(common_name, &spki_der)?;
    let signature = rsassa_sha256_sign(private_key, &cri_der)?;
    build_csr_der(
        &cri_der,
        &algorithm_identifier_sha256_with_rsa()?,
        &signature,
    )
}

/// Writes a PKCS#10 CSR using ECDSA P-256 SHA-256.
///
/// # Arguments
/// * `common_name`: CSR subject commonName.
/// * `public_key`: P-256 public key for SubjectPublicKeyInfo.
/// * `private_key`: P-256 private key used to sign CertificationRequestInfo.
///
/// # Returns
/// DER-encoded CertificationRequest.
pub fn write_csr_p256_sha256(
    common_name: &str,
    public_key: &P256PublicKey,
    private_key: &P256PrivateKey,
) -> Result<Vec<u8>> {
    let spki_der = p256_public_key_to_spki_der(public_key)?;
    let cri_der = build_csr_info(common_name, &spki_der)?;
    let (r, s) = p256_ecdsa_sign_sha256(private_key, &cri_der)?;
    let signature_der = write_ecdsa_signature_der(&r, &s)?;
    build_csr_der(
        &cri_der,
        &algorithm_identifier_ecdsa_sha256()?,
        &signature_der,
    )
}

/// Builds `TBSCertificate` DER for self-signed, fixture-grade certificates.
///
/// # Arguments
///
/// * `serial` — Serial number body for `write_der_integer`.
/// * `common_name` — Subject and issuer common name string.
/// * `not_before` / `not_after` — Validity strings passed to `write_validity`.
/// * `signature_algorithm` — Pre-encoded `AlgorithmIdentifier` DER bytes for the TBS field.
/// * `spki_der` — Subject `SubjectPublicKeyInfo` DER.
/// * `is_ca` — When `true`, writes CA-oriented extensions via `write_extensions`.
///
/// # Returns
///
/// On success, the concatenated `TBSCertificate` SEQUENCE bytes.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when any nested DER writer fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
fn build_certificate_tbs(
    serial: &[u8],
    common_name: &str,
    not_before: &str,
    not_after: &str,
    signature_algorithm: &[u8],
    spki_der: &[u8],
    is_ca: bool,
) -> Result<Vec<u8>> {
    let version_ctx = write_der_explicit_context(0, &write_der_integer(&[0x02])?)?;
    let serial_der = write_der_integer(serial)?;
    let name_der = write_common_name(common_name)?;
    let validity = write_validity(not_before, not_after)?;
    let extensions = write_der_explicit_context(3, &write_extensions(is_ca)?)?;
    let mut tbs_children = Vec::new();
    tbs_children.extend_from_slice(&version_ctx);
    tbs_children.extend_from_slice(&serial_der);
    tbs_children.extend_from_slice(signature_algorithm);
    tbs_children.extend_from_slice(&name_der);
    tbs_children.extend_from_slice(&validity);
    tbs_children.extend_from_slice(&name_der);
    tbs_children.extend_from_slice(spki_der);
    tbs_children.extend_from_slice(&extensions);
    write_der_sequence(&tbs_children)
}

/// Builds the top-level X.509 `Certificate` SEQUENCE from TBS, algorithm identifier, and signature.
///
/// # Arguments
///
/// * `tbs_der` — `TBSCertificate` DER.
/// * `signature_algorithm` — Same `AlgorithmIdentifier` encoding as embedded in the TBS.
/// * `signature` — Raw signature octets (not BIT STRING wrapped).
///
/// # Returns
///
/// On success, the full certificate DER SEQUENCE.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when BIT STRING or SEQUENCE encoding fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic.
fn build_certificate_der(
    tbs_der: &[u8],
    signature_algorithm: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    let signature_bit_string = write_der_bit_string(signature)?;
    let mut cert_children = Vec::new();
    cert_children.extend_from_slice(tbs_der);
    cert_children.extend_from_slice(signature_algorithm);
    cert_children.extend_from_slice(&signature_bit_string);
    write_der_sequence(&cert_children)
}

/// Builds CertificationRequestInfo DER for PKCS#10.
///
/// # Arguments
///
/// * `common_name` — `&str`.
/// * `spki_der` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `build_csr_info`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn build_csr_info(common_name: &str, spki_der: &[u8]) -> Result<Vec<u8>> {
    let version = write_der_integer(&[0x00])?;
    let subject = write_common_name(common_name)?;
    let attributes = write_der_explicit_context(0, &[])?;
    let mut info_children = Vec::new();
    info_children.extend_from_slice(&version);
    info_children.extend_from_slice(&subject);
    info_children.extend_from_slice(spki_der);
    info_children.extend_from_slice(&attributes);
    write_der_sequence(&info_children)
}

/// Builds final PKCS#10 CSR DER from CRI, AlgorithmIdentifier, and raw signature bytes.
///
/// # Arguments
///
/// * `cri_der` — `&[u8]`.
/// * `signature_algorithm` — `&[u8]`.
/// * `signature` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `build_csr_der`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn build_csr_der(cri_der: &[u8], signature_algorithm: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let signature_bit_string = write_der_bit_string(signature)?;
    let mut csr_children = Vec::new();
    csr_children.extend_from_slice(cri_der);
    csr_children.extend_from_slice(signature_algorithm);
    csr_children.extend_from_slice(&signature_bit_string);
    write_der_sequence(&csr_children)
}

/// Builds AlgorithmIdentifier for sha256WithRSAEncryption.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// On success, the `Ok` payload from `algorithm_identifier_sha256_with_rsa`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn algorithm_identifier_sha256_with_rsa() -> Result<Vec<u8>> {
    let oid = write_der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])?;
    let null = write_der_null()?;
    let mut body = Vec::new();
    body.extend_from_slice(&oid);
    body.extend_from_slice(&null);
    write_der_sequence(&body)
}

/// Builds AlgorithmIdentifier for ecdsa-with-SHA256.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// On success, the `Ok` payload from `algorithm_identifier_ecdsa_sha256`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn algorithm_identifier_ecdsa_sha256() -> Result<Vec<u8>> {
    let oid = write_der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])?;
    write_der_sequence(&oid)
}

/// Builds Name ::= SEQUENCE OF RDN containing one commonName UTF8String.
///
/// # Arguments
///
/// * `common_name` — `&str`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_common_name`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_common_name(common_name: &str) -> Result<Vec<u8>> {
    if common_name.is_empty() {
        return Err(Error::InvalidLength("common name must not be empty"));
    }
    let oid_cn = write_der_oid(&[0x55, 0x04, 0x03])?;
    let value = write_der_utf8_string(common_name.as_bytes())?;
    let mut atv = Vec::new();
    atv.extend_from_slice(&oid_cn);
    atv.extend_from_slice(&value);
    let atv_seq = write_der_sequence(&atv)?;
    let rdn_set = write_der_set(&atv_seq)?;
    write_der_sequence(&rdn_set)
}

/// Builds Validity ::= SEQUENCE { notBefore, notAfter } with UTC/generalized time tags.
///
/// # Arguments
///
/// * `not_before` — `&str`.
/// * `not_after` — `&str`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_validity`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_validity(not_before: &str, not_after: &str) -> Result<Vec<u8>> {
    let not_before_der = write_der_time(not_before)?;
    let not_after_der = write_der_time(not_after)?;
    let mut body = Vec::new();
    body.extend_from_slice(&not_before_der);
    body.extend_from_slice(&not_after_der);
    write_der_sequence(&body)
}

/// Builds v3 basic constraints extension sequence.
///
/// # Arguments
///
/// * `is_ca` — `bool`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_extensions`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_extensions(is_ca: bool) -> Result<Vec<u8>> {
    let ext = write_basic_constraints_extension(is_ca)?;
    write_der_sequence(&ext)
}

/// Writes one BasicConstraints extension with critical flag and cA boolean.
///
/// # Arguments
///
/// * `is_ca` — `bool`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_basic_constraints_extension`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_basic_constraints_extension(is_ca: bool) -> Result<Vec<u8>> {
    let oid = write_der_oid(&[0x55, 0x1D, 0x13])?;
    let critical = write_der_boolean(true)?;
    let value_seq = {
        let ca = write_der_boolean(is_ca)?;
        write_der_sequence(&ca)?
    };
    let ext_value = write_der_octet_string(&value_seq)?;
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&oid);
    ext_body.extend_from_slice(&critical);
    ext_body.extend_from_slice(&ext_value);
    write_der_sequence(&ext_body)
}

/// Writes DER NULL value.
///
/// # Arguments
///
/// * *(none)* — This function takes no parameters.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_null`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_null() -> Result<Vec<u8>> {
    let mut out = vec![0x05];
    out.extend_from_slice(&encode_der_len(0)?);
    Ok(out)
}

/// Writes DER BOOLEAN value.
///
/// # Arguments
///
/// * `value` — `bool`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_boolean`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_boolean(value: bool) -> Result<Vec<u8>> {
    let mut out = vec![0x01];
    out.extend_from_slice(&encode_der_len(1)?);
    out.push(if value { 0xFF } else { 0x00 });
    Ok(out)
}

/// Writes DER UTF8String value.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_utf8_string`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_utf8_string(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::InvalidLength("utf8 string must not be empty"));
    }
    let mut out = vec![0x0C];
    out.extend_from_slice(&encode_der_len(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Writes DER SET value wrapping already-encoded children.
///
/// # Arguments
///
/// * `encoded_children` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_set`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_set(encoded_children: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0x31];
    out.extend_from_slice(&encode_der_len(encoded_children.len())?);
    out.extend_from_slice(encoded_children);
    Ok(out)
}

/// Writes DER OCTET STRING value.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_octet_string`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_octet_string(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0x04];
    out.extend_from_slice(&encode_der_len(bytes.len())?);
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Writes DER explicit context-specific wrapper `[tag_no] EXPLICIT`.
///
/// # Arguments
///
/// * `tag_no` — `u8`.
/// * `encoded_child` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_explicit_context`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_explicit_context(tag_no: u8, encoded_child: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0xA0 | tag_no];
    out.extend_from_slice(&encode_der_len(encoded_child.len())?);
    out.extend_from_slice(encoded_child);
    Ok(out)
}

/// Writes DER time node for UTCTime or GeneralizedTime text.
///
/// # Arguments
///
/// * `time` — `&str`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_der_time`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_der_time(time: &str) -> Result<Vec<u8>> {
    let (tag, body) = if time.len() == 13 {
        (0x17, time.as_bytes())
    } else if time.len() == 15 {
        (0x18, time.as_bytes())
    } else {
        return Err(Error::InvalidLength(
            "time must be UTCTime or GeneralizedTime textual length",
        ));
    };
    if !time.ends_with('Z') || !time[..time.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidEncoding(
            "time must end with Z and contain digits",
        ));
    }
    let mut out = vec![tag];
    out.extend_from_slice(&encode_der_len(body.len())?);
    out.extend_from_slice(body);
    Ok(out)
}

/// Writes DER-encoded ECDSA signature sequence from fixed-width r and s values.
///
/// # Arguments
///
/// * `r` — `&[u8; 32]`.
/// * `s` — `&[u8; 32]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `write_ecdsa_signature_der`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn write_ecdsa_signature_der(r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>> {
    let r_der = write_der_integer(r)?;
    let s_der = write_der_integer(s)?;
    let mut body = Vec::new();
    body.extend_from_slice(&r_der);
    body.extend_from_slice(&s_der);
    write_der_sequence(&body)
}

/// Encodes a DER definite length prefix in short or long form for the given content length.
///
/// # Arguments
///
/// * `len` — Number of content octets following the length bytes.
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
    let mut out = Vec::with_capacity(content.len() + 1);
    out.push(0x80 | (content.len() as u8));
    out.extend_from_slice(content);
    Ok(out)
}

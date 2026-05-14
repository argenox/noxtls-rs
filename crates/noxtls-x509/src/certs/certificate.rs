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

#[cfg(not(feature = "std"))]
use crate::internal_alloc::ToOwned;
use crate::internal_alloc::{String, Vec};
use noxtls_core::{Error, Result};

use super::{noxtls_parse_der_length, noxtls_parse_der_node};

const MAX_CERTIFICATE_DER_LEN: usize = 1 << 20;
const MAX_EXTENSION_COUNT: usize = 256;
const MAX_SAN_DNS_NAME_COUNT: usize = 1024;
const MAX_CERTIFICATE_POLICY_COUNT: usize = 256;
const MAX_POLICY_MAPPING_COUNT: usize = 256;
const MAX_URI_COUNT: usize = 1024;
const MAX_EKU_COUNT: usize = 256;
const MAX_GENERAL_SUBTREE_COUNT: usize = 256;

/// Captures parsed certificate fields needed for PKI and TLS flows.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub version: u8,
    pub serial: Vec<u8>,
    pub tbs_signature_algorithm_oid: Vec<u8>,
    pub issuer_raw: &'a [u8],
    pub not_before: String,
    pub not_after: String,
    pub subject_raw: &'a [u8],
    pub subject_public_key_algorithm_oid: Vec<u8>,
    pub subject_public_key: Vec<u8>,
    pub certificate_signature_algorithm_oid: Vec<u8>,
    pub signature_value: Vec<u8>,
    pub basic_constraints_ca: Option<bool>,
    pub basic_constraints_path_len: Option<u32>,
    pub key_usage_bits: Option<u16>,
    pub subject_alt_dns_names: Vec<String>,
    pub certificate_policies: Vec<Vec<u8>>,
    pub policy_mappings: Vec<(Vec<u8>, Vec<u8>)>,
    pub extended_key_usage_oids: Vec<Vec<u8>>,
    pub name_constraints_permitted_dns: Vec<String>,
    pub name_constraints_excluded_dns: Vec<String>,
    pub policy_constraints_require_explicit_policy: Option<u32>,
    pub policy_constraints_inhibit_policy_mapping: Option<u32>,
    pub inhibit_any_policy_skip_certs: Option<u32>,
    pub crl_distribution_uris: Vec<String>,
    pub authority_info_access_uris: Vec<String>,
    pub raw_tbs: &'a [u8],
    pub raw_tbs_der: &'a [u8],
}

/// Matches `hostname` against certificate DNS identities.
///
/// # Arguments
/// * `cert`: Parsed certificate carrying SAN and subject fields.
/// * `hostname`: Hostname to verify.
///
/// # Returns
/// `true` when hostname matches SAN dNSName entries, or subject CN when SAN is absent.
#[must_use]
pub fn noxtls_certificate_matches_hostname(cert: &Certificate<'_>, hostname: &str) -> bool {
    let Some(normalized_hostname) = normalize_dns_name(hostname, false) else {
        return false;
    };
    if !cert.subject_alt_dns_names.is_empty() {
        return cert
            .subject_alt_dns_names
            .iter()
            .any(|dns_name| dns_name_matches_hostname(dns_name, &normalized_hostname));
    }
    let common_name = subject_common_name(cert.subject_raw);
    common_name
        .as_deref()
        .is_some_and(|cn| dns_name_matches_hostname(cn, &normalized_hostname))
}

/// Parses a top-level DER certificate sequence and extracts core fields.
///
/// # Arguments
/// * `input`: Full DER-encoded X.509 certificate bytes.
///
/// # Returns
/// Parsed `Certificate` view with extracted core fields and extension data.
pub fn noxtls_parse_certificate(input: &[u8]) -> Result<Certificate<'_>> {
    if input.len() > MAX_CERTIFICATE_DER_LEN {
        return Err(Error::ParseFailure("certificate exceeds parser size limit"));
    }
    let (cert_seq, rem) = noxtls_parse_der_node(input)?;
    if cert_seq.tag != 0x30 || !rem.is_empty() {
        return Err(Error::ParseFailure(
            "certificate must be top-level sequence",
        ));
    }

    let raw_tbs_der = first_der_encoded(cert_seq.body)?;
    let (tbs, cert_rest) = noxtls_parse_der_node(cert_seq.body)?;
    if tbs.tag != 0x30 {
        return Err(Error::ParseFailure("missing TBSCertificate sequence"));
    }
    let (cert_sig_alg, cert_sig_rest) = noxtls_parse_der_node(cert_rest)?;
    if cert_sig_alg.tag != 0x30 {
        return Err(Error::ParseFailure(
            "missing certificate signature noxtls_algorithm",
        ));
    }
    let (signature_value_node, cert_tail) = noxtls_parse_der_node(cert_sig_rest)?;
    if signature_value_node.tag != 0x03 || !cert_tail.is_empty() {
        return Err(Error::ParseFailure("missing certificate signature value"));
    }

    let mut tbs_cursor = tbs.body;
    let mut version = 1_u8;

    let (first, maybe_rest) = noxtls_parse_der_node(tbs_cursor)?;
    if first.tag == 0xA0 {
        let (version_node, version_tail) = noxtls_parse_der_node(first.body)?;
        if version_node.tag != 0x02 || !version_tail.is_empty() || version_node.body.is_empty() {
            return Err(Error::ParseFailure("invalid certificate version"));
        }
        let version_zero_based = parse_der_positive_integer_u32(version_node.body)?;
        if version_zero_based > 2 {
            return Err(Error::ParseFailure("unsupported certificate version"));
        }
        version = version_zero_based as u8 + 1;
        tbs_cursor = maybe_rest;
    }

    let (serial, rest) = noxtls_parse_der_node(tbs_cursor)?;
    if serial.tag != 0x02 {
        return Err(Error::ParseFailure("missing certificate serial"));
    }
    tbs_cursor = rest;

    let (tbs_sig_alg, rest) = noxtls_parse_der_node(tbs_cursor)?;
    if tbs_sig_alg.tag != 0x30 {
        return Err(Error::ParseFailure("missing TBS signature noxtls_algorithm"));
    }
    tbs_cursor = rest;

    let (issuer, rest) = noxtls_parse_der_node(tbs_cursor)?;
    if issuer.tag != 0x30 {
        return Err(Error::ParseFailure("missing certificate issuer"));
    }
    tbs_cursor = rest;

    let (validity, rest) = noxtls_parse_der_node(tbs_cursor)?;
    if validity.tag != 0x30 {
        return Err(Error::ParseFailure("missing certificate validity"));
    }
    tbs_cursor = rest;
    let (not_before, not_after) = parse_validity(validity.body)?;

    let (subject, rest) = noxtls_parse_der_node(tbs_cursor)?;
    if subject.tag != 0x30 {
        return Err(Error::ParseFailure("missing certificate subject"));
    }
    tbs_cursor = rest;

    let (spki, mut tbs_tail) = noxtls_parse_der_node(tbs_cursor)?;
    if spki.tag != 0x30 {
        return Err(Error::ParseFailure("missing subject public key info"));
    }
    while matches!(tbs_tail.first(), Some(0x81 | 0x82)) {
        let (_node, rest) = noxtls_parse_der_node(tbs_tail)?;
        tbs_tail = rest;
    }

    let mut basic_constraints_ca = None;
    let mut basic_constraints_path_len = None;
    let mut key_usage_bits = None;
    let mut subject_alt_dns_names = Vec::new();
    let mut certificate_policies = Vec::new();
    let mut policy_mappings = Vec::new();
    let mut extended_key_usage_oids = Vec::new();
    let mut name_constraints_permitted_dns = Vec::new();
    let mut name_constraints_excluded_dns = Vec::new();
    let mut policy_constraints_require_explicit_policy = None;
    let mut policy_constraints_inhibit_policy_mapping = None;
    let mut inhibit_any_policy_skip_certs = None;
    let mut crl_distribution_uris = Vec::new();
    let mut authority_info_access_uris = Vec::new();
    if !tbs_tail.is_empty() {
        let (extensions_ctx, tail) = noxtls_parse_der_node(tbs_tail)?;
        if extensions_ctx.tag != 0xA3 || !tail.is_empty() {
            return Err(Error::ParseFailure(
                "unexpected TBSCertificate fields after subject public key info",
            ));
        }
        (
            basic_constraints_ca,
            basic_constraints_path_len,
            key_usage_bits,
            subject_alt_dns_names,
            certificate_policies,
            policy_mappings,
            extended_key_usage_oids,
            name_constraints_permitted_dns,
            name_constraints_excluded_dns,
            policy_constraints_require_explicit_policy,
            policy_constraints_inhibit_policy_mapping,
            inhibit_any_policy_skip_certs,
            crl_distribution_uris,
            authority_info_access_uris,
        ) = parse_extensions(extensions_ctx.body)?;
    }

    Ok(Certificate {
        version,
        serial: serial.body.to_vec(),
        tbs_signature_algorithm_oid: parse_algorithm_identifier_oid(tbs_sig_alg.body)?,
        issuer_raw: issuer.body,
        not_before,
        not_after,
        subject_raw: subject.body,
        subject_public_key_algorithm_oid: parse_spki_algorithm_oid(spki.body)?,
        subject_public_key: parse_spki_subject_public_key(spki.body)?,
        certificate_signature_algorithm_oid: parse_algorithm_identifier_oid(cert_sig_alg.body)?,
        signature_value: parse_bit_string(signature_value_node.body)?,
        basic_constraints_ca,
        basic_constraints_path_len,
        key_usage_bits,
        subject_alt_dns_names,
        certificate_policies,
        policy_mappings,
        extended_key_usage_oids,
        name_constraints_permitted_dns,
        name_constraints_excluded_dns,
        policy_constraints_require_explicit_policy,
        policy_constraints_inhibit_policy_mapping,
        inhibit_any_policy_skip_certs,
        crl_distribution_uris,
        authority_info_access_uris,
        raw_tbs: tbs.body,
        raw_tbs_der,
    })
}

/// Returns the full encoded first DER node bytes from `input`.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `first_der_encoded`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn first_der_encoded(input: &[u8]) -> Result<&[u8]> {
    if input.len() < 2 {
        return Err(Error::ParseFailure("DER node too short"));
    }
    let (len, len_len) = noxtls_parse_der_length(&input[1..])?;
    let total_len = 1_usize
        .checked_add(len_len)
        .and_then(|value| value.checked_add(len))
        .ok_or(Error::ParseFailure("DER length arithmetic overflow"))?;
    if input.len() < total_len {
        return Err(Error::ParseFailure("DER length exceeds input"));
    }
    Ok(&input[..total_len])
}

/// Parses AlgorithmIdentifier SEQUENCE and returns the OID bytes.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_algorithm_identifier_oid`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_algorithm_identifier_oid(input: &[u8]) -> Result<Vec<u8>> {
    let (oid_node, rest) = noxtls_parse_der_node(input)?;
    if oid_node.tag != 0x06 {
        return Err(Error::ParseFailure("noxtls_algorithm identifier missing OID"));
    }
    if !rest.is_empty() {
        let (_params, tail) = noxtls_parse_der_node(rest)?;
        if !tail.is_empty() {
            return Err(Error::ParseFailure(
                "noxtls_algorithm identifier has trailing fields",
            ));
        }
    }
    Ok(oid_node.body.to_vec())
}

/// Parses SPKI and returns noxtls_algorithm OID bytes.
///
/// # Arguments
///
/// * `spki_body` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_spki_algorithm_oid`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_spki_algorithm_oid(spki_body: &[u8]) -> Result<Vec<u8>> {
    let (alg_node, rest) = noxtls_parse_der_node(spki_body)?;
    if alg_node.tag != 0x30 {
        return Err(Error::ParseFailure(
            "subjectPublicKeyInfo missing noxtls_algorithm",
        ));
    }
    if rest.is_empty() {
        return Err(Error::ParseFailure(
            "subjectPublicKeyInfo missing public key",
        ));
    }
    parse_algorithm_identifier_oid(alg_node.body)
}

/// Parses SPKI and returns BIT STRING subject public key bytes.
///
/// # Arguments
///
/// * `spki_body` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_spki_subject_public_key`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_spki_subject_public_key(spki_body: &[u8]) -> Result<Vec<u8>> {
    let (_alg_node, rest) = noxtls_parse_der_node(spki_body)?;
    let (subject_key_node, tail) = noxtls_parse_der_node(rest)?;
    if subject_key_node.tag != 0x03 {
        return Err(Error::ParseFailure(
            "subjectPublicKeyInfo missing public key",
        ));
    }
    if !tail.is_empty() {
        return Err(Error::ParseFailure(
            "subjectPublicKeyInfo contains trailing bytes",
        ));
    }
    parse_bit_string(subject_key_node.body)
}

/// Parses DER validity sequence to `(not_before, not_after)` strings.
///
/// # Arguments
///
/// * `validity_body` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_validity`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_validity(validity_body: &[u8]) -> Result<(String, String)> {
    let (not_before_node, rest) = noxtls_parse_der_node(validity_body)?;
    let (not_after_node, tail) = noxtls_parse_der_node(rest)?;
    if !tail.is_empty() {
        return Err(Error::ParseFailure("unexpected bytes in validity"));
    }
    let not_before = parse_time_node(&not_before_node)?;
    let not_after = parse_time_node(&not_after_node)?;
    Ok((not_before, not_after))
}

/// Parses UTCTime or GeneralizedTime node into a UTF-8 string.
///
/// # Arguments
///
/// * `node` — `&super::DerNode<'_>`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_time_node`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_time_node(node: &super::DerNode<'_>) -> Result<String> {
    if node.tag != 0x17 && node.tag != 0x18 {
        return Err(Error::ParseFailure(
            "validity time must be UTC or generalized",
        ));
    }
    core::str::from_utf8(node.body)
        .map(|s| s.to_owned())
        .map_err(|_| Error::ParseFailure("invalid UTF-8 in time field"))
}

/// Extracts subject CN string from RDN sequence body when present.
///
/// # Arguments
///
/// * `subject_raw` — `&[u8]`.
///
/// # Returns
///
/// `Option<String>` produced by `subject_common_name` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn subject_common_name(subject_raw: &[u8]) -> Option<String> {
    const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    let mut rdn_cursor = subject_raw;
    while !rdn_cursor.is_empty() {
        let (rdn_set, rest) = noxtls_parse_der_node(rdn_cursor).ok()?;
        if rdn_set.tag != 0x31 {
            return None;
        }
        let mut attr_cursor = rdn_set.body;
        while !attr_cursor.is_empty() {
            let (attr_seq, attr_rest) = noxtls_parse_der_node(attr_cursor).ok()?;
            if attr_seq.tag != 0x30 {
                return None;
            }
            let (oid, value_rest) = noxtls_parse_der_node(attr_seq.body).ok()?;
            let (value, tail) = noxtls_parse_der_node(value_rest).ok()?;
            if oid.tag == 0x06
                && oid.body == OID_COMMON_NAME
                && tail.is_empty()
                && (value.tag == 0x0C || value.tag == 0x13 || value.tag == 0x16)
            {
                return core::str::from_utf8(value.body).ok().map(str::to_owned);
            }
            attr_cursor = attr_rest;
        }
        rdn_cursor = rest;
    }
    None
}

/// Matches DNS name pattern (including left-most wildcard) against hostname.
///
/// # Arguments
///
/// * `pattern` — `&str`.
/// * `hostname` — `&str`.
///
/// # Returns
///
/// `bool` produced by `dns_name_matches_hostname` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn dns_name_matches_hostname(pattern: &str, hostname: &str) -> bool {
    let Some(pat) = normalize_dns_name(pattern, true) else {
        return false;
    };
    let Some(host) = normalize_dns_name(hostname, false) else {
        return false;
    };
    if let Some(suffix) = pat.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        if !suffix.contains('.') {
            // Wildcards must not match only a registry-style single-label suffix.
            return false;
        }
        if !host.ends_with(suffix) {
            return false;
        }
        let prefix = &host[..host.len().saturating_sub(suffix.len())];
        if !prefix.ends_with('.') {
            return false;
        }
        let label = &prefix[..prefix.len() - 1];
        return !label.is_empty() && !label.contains('.');
    }
    host == pat
}

/// Normalizes and validates DNS names for comparison.
///
/// When `allow_wildcard` is true, only a left-most full-label wildcard (`*.`) is accepted.
///
/// # Arguments
///
/// * `name` — Candidate DNS name or pattern.
/// * `allow_wildcard` — When `true`, permits a single leading `*.` label wildcard form.
///
/// # Returns
///
/// `Option<String>` produced by `normalize_dns_name` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn normalize_dns_name(name: &str, allow_wildcard: bool) -> Option<String> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    let lowered = name.to_ascii_lowercase();
    let trimmed = lowered.strip_suffix('.').unwrap_or(&lowered);
    if trimmed.is_empty() {
        return None;
    }
    if allow_wildcard && trimmed.starts_with("*.") {
        let suffix = trimmed.strip_prefix("*.")?;
        if suffix.is_empty() || suffix.contains('*') {
            return None;
        }
        if !dns_name_labels_valid(suffix) {
            return None;
        }
        return Some(trimmed.to_owned());
    }
    if trimmed.contains('*') {
        return None;
    }
    if !dns_name_labels_valid(trimmed) {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Validates dot-separated DNS labels using ASCII LDH rules.
///
/// # Arguments
///
/// * `name` — `&str`.
///
/// # Returns
///
/// `bool` produced by `dns_name_labels_valid` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn dns_name_labels_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

/// Parses DER BIT STRING and returns payload bytes after the unused-bit count.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_bit_string`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_bit_string(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(Error::ParseFailure("empty DER bit string"));
    }
    let unused = input[0];
    if unused > 7 {
        return Err(Error::ParseFailure(
            "invalid DER bit string unused-bit count",
        ));
    }
    if unused != 0 {
        return Err(Error::ParseFailure(
            "non-byte-aligned DER bit string is unsupported",
        ));
    }
    Ok(input[1..].to_vec())
}

/// Parses a v3 `Extensions` SEQUENCE and extracts selected PKI-critical fields used by this crate.
///
/// # Arguments
///
/// * `input` — DER bytes of the `extensions` field (the `[3] EXPLICIT` wrapper body: a SEQUENCE OF `Extension`).
///
/// # Returns
///
/// On success, a tuple in field order:
///
/// * `basic_constraints_ca` — Parsed `cA` flag when `basicConstraints` is present.
/// * `basic_constraints_path_len` — Optional `pathLenConstraint`.
/// * `key_usage_bits` — Low-order key usage bits when `keyUsage` is present.
/// * `subject_alt_dns_names` — DNS names from `subjectAltName`.
/// * `certificate_policies` — Policy OID encodings from `certificatePolicies`.
/// * `policy_mappings` — `(issuerPolicy, subjectPolicy)` pairs from `policyMappings`.
/// * `extended_key_usage_oids` — EKU OID encodings.
/// * `name_constraints_permitted_dns` / `name_constraints_excluded_dns` — DNS subtrees from `nameConstraints`.
/// * `policy_constraints_require_explicit_policy` / `policy_constraints_inhibit_policy_mapping` — `policyConstraints` counters.
/// * `inhibit_any_policy_skip_certs` — Skip count from `inhibitAnyPolicy`.
/// * `crl_distribution_uris` — CRL distribution HTTP/LDAP style URIs.
/// * `authority_info_access_uris` — AIA CA issuers / OCSP style URIs.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the extension container layout is invalid or an individual extension cannot be parsed.
///
/// # Panics
///
/// This function does not panic.
fn parse_extensions(
    input: &[u8],
) -> Result<(
    Option<bool>,
    Option<u32>,
    Option<u16>,
    Vec<String>,
    Vec<Vec<u8>>,
    Vec<(Vec<u8>, Vec<u8>)>,
    Vec<Vec<u8>>,
    Vec<String>,
    Vec<String>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Vec<String>,
    Vec<String>,
)> {
    let (extensions_seq, tail) = noxtls_parse_der_node(input)?;
    if extensions_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid certificate extensions"));
    }

    let mut ext_cursor = extensions_seq.body;
    let mut basic_constraints_ca = None;
    let mut basic_constraints_path_len = None;
    let mut key_usage_bits = None;
    let mut subject_alt_dns_names = Vec::new();
    let mut certificate_policies = Vec::new();
    let mut policy_mappings = Vec::new();
    let mut extended_key_usage_oids = Vec::new();
    let mut name_constraints_permitted_dns = Vec::new();
    let mut name_constraints_excluded_dns = Vec::new();
    let mut policy_constraints_require_explicit_policy = None;
    let mut policy_constraints_inhibit_policy_mapping = None;
    let mut inhibit_any_policy_skip_certs = None;
    let mut crl_distribution_uris = Vec::new();
    let mut authority_info_access_uris = Vec::new();
    let mut extension_count = 0_usize;

    while !ext_cursor.is_empty() {
        extension_count = extension_count.saturating_add(1);
        if extension_count > MAX_EXTENSION_COUNT {
            return Err(Error::ParseFailure(
                "certificate has too many extensions for parser limit",
            ));
        }
        let (ext_node, rest) = noxtls_parse_der_node(ext_cursor)?;
        ext_cursor = rest;
        if ext_node.tag != 0x30 {
            return Err(Error::ParseFailure("invalid extension sequence"));
        }
        let (oid_node, mut ext_rest) = noxtls_parse_der_node(ext_node.body)?;
        if oid_node.tag != 0x06 {
            return Err(Error::ParseFailure("extension missing OID"));
        }
        let (_critical, maybe_rest) = parse_optional_boolean(ext_rest)?;
        ext_rest = maybe_rest;
        let (extn_value_node, ext_tail) = noxtls_parse_der_node(ext_rest)?;
        if extn_value_node.tag != 0x04 || !ext_tail.is_empty() {
            return Err(Error::ParseFailure(
                "extension missing extnValue octet string",
            ));
        }
        match oid_node.body {
            [0x55, 0x1d, 0x13] => {
                let (ca, path_len) = parse_basic_constraints(extn_value_node.body)?;
                basic_constraints_ca = Some(ca);
                basic_constraints_path_len = path_len;
            }
            [0x55, 0x1d, 0x0f] => {
                key_usage_bits = Some(parse_key_usage(extn_value_node.body)?);
            }
            [0x55, 0x1d, 0x11] => {
                subject_alt_dns_names = parse_subject_alt_name_dns(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x20] => {
                certificate_policies = parse_certificate_policies(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x21] => {
                policy_mappings = parse_policy_mappings(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x25] => {
                extended_key_usage_oids = parse_extended_key_usage(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x1e] => {
                (
                    name_constraints_permitted_dns,
                    name_constraints_excluded_dns,
                ) = parse_name_constraints(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x24] => {
                (
                    policy_constraints_require_explicit_policy,
                    policy_constraints_inhibit_policy_mapping,
                ) = parse_policy_constraints(extn_value_node.body)?;
            }
            [0x55, 0x1d, 0x36] => {
                inhibit_any_policy_skip_certs =
                    Some(parse_inhibit_any_policy(extn_value_node.body)?);
            }
            [0x55, 0x1d, 0x1f] => {
                crl_distribution_uris = parse_crl_distribution_points(extn_value_node.body)?;
            }
            [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01] => {
                authority_info_access_uris = parse_authority_info_access(extn_value_node.body)?;
            }
            _ => {}
        }
    }

    Ok((
        basic_constraints_ca,
        basic_constraints_path_len,
        key_usage_bits,
        subject_alt_dns_names,
        certificate_policies,
        policy_mappings,
        extended_key_usage_oids,
        name_constraints_permitted_dns,
        name_constraints_excluded_dns,
        policy_constraints_require_explicit_policy,
        policy_constraints_inhibit_policy_mapping,
        inhibit_any_policy_skip_certs,
        crl_distribution_uris,
        authority_info_access_uris,
    ))
}

/// Parses optional BOOLEAN and returns `(value_if_present, remaining_bytes)`.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_optional_boolean`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_optional_boolean(input: &[u8]) -> Result<(Option<bool>, &[u8])> {
    if input.is_empty() {
        return Ok((None, input));
    }
    let (node, rest) = noxtls_parse_der_node(input)?;
    if node.tag != 0x01 {
        return Ok((None, input));
    }
    if node.body.len() != 1 {
        return Err(Error::ParseFailure("invalid BOOLEAN length in extension"));
    }
    Ok((Some(node.body[0] != 0), rest))
}

/// Parses BasicConstraints extension payload.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_basic_constraints`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_basic_constraints(extn_octets: &[u8]) -> Result<(bool, Option<u32>)> {
    let (seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid basicConstraints encoding"));
    }
    let mut cursor = seq.body;
    let mut ca = false;
    let mut path_len = None;

    if !cursor.is_empty() {
        let (node, rest) = noxtls_parse_der_node(cursor)?;
        if node.tag == 0x01 {
            if node.body.len() != 1 {
                return Err(Error::ParseFailure("invalid basicConstraints cA boolean"));
            }
            ca = node.body[0] != 0;
            cursor = rest;
        }
    }
    if !cursor.is_empty() {
        let (path_node, path_tail) = noxtls_parse_der_node(cursor)?;
        if path_node.tag != 0x02 || !path_tail.is_empty() || path_node.body.is_empty() {
            return Err(Error::ParseFailure(
                "invalid basicConstraints pathLenConstraint",
            ));
        }
        path_len = Some(parse_der_positive_integer_u32(path_node.body)?);
    }
    Ok((ca, path_len))
}

/// Parses KeyUsage extension payload into low-order usage bits.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_key_usage`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_key_usage(extn_octets: &[u8]) -> Result<u16> {
    let (bit_string_node, tail) = noxtls_parse_der_node(extn_octets)?;
    if bit_string_node.tag != 0x03 || !tail.is_empty() || bit_string_node.body.is_empty() {
        return Err(Error::ParseFailure("invalid keyUsage encoding"));
    }
    let unused_bits = bit_string_node.body[0];
    if unused_bits > 7 {
        return Err(Error::ParseFailure("invalid keyUsage unused bits"));
    }
    let mut value = 0_u16;
    for (idx, byte) in bit_string_node.body[1..].iter().enumerate() {
        value |= u16::from(*byte) << (idx * 8);
    }
    if unused_bits != 0 {
        let used_bits = (bit_string_node.body.len() - 1) * 8 - usize::from(unused_bits);
        if used_bits < 16 {
            let keep_mask = (1_u32 << used_bits) - 1;
            value &= keep_mask as u16;
        }
    }
    Ok(value)
}

/// Parses SubjectAltName extension payload and extracts dNSName values.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_subject_alt_name_dns`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_subject_alt_name_dns(extn_octets: &[u8]) -> Result<Vec<String>> {
    let (general_names_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if general_names_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid subjectAltName encoding"));
    }
    let mut names = Vec::new();
    let mut cursor = general_names_seq.body;
    while !cursor.is_empty() {
        let (name_node, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if name_node.tag == 0x82 {
            if names.len() >= MAX_SAN_DNS_NAME_COUNT {
                return Err(Error::ParseFailure(
                    "subjectAltName has too many dNSName entries",
                ));
            }
            let dns = core::str::from_utf8(name_node.body)
                .map_err(|_| Error::ParseFailure("invalid UTF-8 in subjectAltName dNSName"))?;
            names.push(dns.to_owned());
        }
    }
    Ok(names)
}

/// Parses positive DER INTEGER into `u32`.
///
/// # Arguments
///
/// * `bytes` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_der_positive_integer_u32`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_der_positive_integer_u32(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() {
        return Err(Error::ParseFailure("invalid empty INTEGER"));
    }
    if bytes.len() > 5 {
        return Err(Error::ParseFailure("integer too large for u32"));
    }
    if bytes[0] & 0x80 != 0 {
        return Err(Error::ParseFailure("negative INTEGER is not supported"));
    }
    if bytes.len() > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
        return Err(Error::ParseFailure("non-canonical INTEGER encoding"));
    }
    let mut value = 0_u32;
    for byte in bytes {
        value = value
            .checked_shl(8)
            .ok_or(Error::ParseFailure("integer shift overflow"))?
            | u32::from(*byte);
    }
    Ok(value)
}

/// Parses certificatePolicies extension payload into policy OID byte vectors.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_certificate_policies`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_certificate_policies(extn_octets: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (policies_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if policies_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid certificatePolicies encoding"));
    }
    let mut policies = Vec::new();
    let mut cursor = policies_seq.body;
    while !cursor.is_empty() {
        let (policy_info, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if policy_info.tag != 0x30 {
            return Err(Error::ParseFailure("invalid PolicyInformation sequence"));
        }
        let (policy_oid, policy_tail) = noxtls_parse_der_node(policy_info.body)?;
        if policy_oid.tag != 0x06 {
            return Err(Error::ParseFailure("certificate policy missing OID"));
        }
        if !policy_tail.is_empty() {
            // Policy qualifiers are intentionally unsupported in current scope.
            return Err(Error::ParseFailure(
                "unsupported certificate policy qualifiers",
            ));
        }
        if policies.len() >= MAX_CERTIFICATE_POLICY_COUNT {
            return Err(Error::ParseFailure(
                "certificatePolicies has too many entries for parser limit",
            ));
        }
        policies.push(policy_oid.body.to_vec());
    }
    Ok(policies)
}

/// Parses policyMappings extension payload into `(issuerDomainPolicy, subjectDomainPolicy)` OID pairs.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_policy_mappings`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_policy_mappings(extn_octets: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let (mappings_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if mappings_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid policyMappings encoding"));
    }
    let mut mappings = Vec::new();
    let mut cursor = mappings_seq.body;
    while !cursor.is_empty() {
        let (mapping, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if mapping.tag != 0x30 {
            return Err(Error::ParseFailure("invalid policyMappings entry"));
        }
        let (issuer_policy, mapping_rest) = noxtls_parse_der_node(mapping.body)?;
        let (subject_policy, mapping_tail) = noxtls_parse_der_node(mapping_rest)?;
        if issuer_policy.tag != 0x06 || subject_policy.tag != 0x06 || !mapping_tail.is_empty() {
            return Err(Error::ParseFailure("invalid policyMappings policy OIDs"));
        }
        if mappings.len() >= MAX_POLICY_MAPPING_COUNT {
            return Err(Error::ParseFailure(
                "policyMappings has too many entries for parser limit",
            ));
        }
        mappings.push((issuer_policy.body.to_vec(), subject_policy.body.to_vec()));
    }
    Ok(mappings)
}

/// Parses cRLDistributionPoints extension payload and extracts URI general names.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_crl_distribution_points`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_crl_distribution_points(extn_octets: &[u8]) -> Result<Vec<String>> {
    let (dp_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if dp_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "invalid cRLDistributionPoints encoding",
        ));
    }
    let mut uris = Vec::new();
    let mut dp_cursor = dp_seq.body;
    while !dp_cursor.is_empty() {
        let (dp_node, rest) = noxtls_parse_der_node(dp_cursor)?;
        dp_cursor = rest;
        if dp_node.tag != 0x30 {
            return Err(Error::ParseFailure("invalid DistributionPoint sequence"));
        }
        let mut dp_fields = dp_node.body;
        while !dp_fields.is_empty() {
            let (field_node, field_rest) = noxtls_parse_der_node(dp_fields)?;
            dp_fields = field_rest;
            if field_node.tag != 0xA0 {
                continue;
            }
            let (general_names, gn_tail) = noxtls_parse_der_node(field_node.body)?;
            if general_names.tag != 0x30 || !gn_tail.is_empty() {
                return Err(Error::ParseFailure(
                    "invalid DistributionPointName fullName",
                ));
            }
            let mut gn_cursor = general_names.body;
            while !gn_cursor.is_empty() {
                let (general_name, gn_rest) = noxtls_parse_der_node(gn_cursor)?;
                gn_cursor = gn_rest;
                if general_name.tag == 0x86 {
                    if uris.len() >= MAX_URI_COUNT {
                        return Err(Error::ParseFailure(
                            "cRLDistributionPoints has too many URIs for parser limit",
                        ));
                    }
                    let uri = core::str::from_utf8(general_name.body)
                        .map_err(|_| Error::ParseFailure("invalid UTF-8 in CRL URI"))?;
                    uris.push(uri.to_owned());
                }
            }
        }
    }
    Ok(uris)
}

/// Parses extendedKeyUsage extension payload into key-purpose OID byte vectors.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_extended_key_usage`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_extended_key_usage(extn_octets: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (eku_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if eku_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid extendedKeyUsage encoding"));
    }
    let mut usages = Vec::new();
    let mut cursor = eku_seq.body;
    while !cursor.is_empty() {
        let (usage, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if usage.tag != 0x06 {
            return Err(Error::ParseFailure("invalid extendedKeyUsage purpose OID"));
        }
        if usages.len() >= MAX_EKU_COUNT {
            return Err(Error::ParseFailure(
                "extendedKeyUsage has too many entries for parser limit",
            ));
        }
        usages.push(usage.body.to_vec());
    }
    Ok(usages)
}

/// Parses nameConstraints extension payload and returns permitted/excluded DNS suffixes.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_name_constraints`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_name_constraints(extn_octets: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let (constraints_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if constraints_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid nameConstraints encoding"));
    }
    let mut permitted_dns = Vec::new();
    let mut excluded_dns = Vec::new();
    let mut cursor = constraints_seq.body;
    while !cursor.is_empty() {
        let (subtrees, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        match subtrees.tag {
            0xA0 => parse_general_subtrees_dns(subtrees.body, &mut permitted_dns)?,
            0xA1 => parse_general_subtrees_dns(subtrees.body, &mut excluded_dns)?,
            _ => return Err(Error::ParseFailure("invalid nameConstraints subtree tag")),
        }
    }
    Ok((permitted_dns, excluded_dns))
}

/// Parses one GeneralSubtrees sequence and appends DNS-name subtree values.
///
/// # Arguments
///
/// * `input` — `&[u8]`.
/// * `out` — `&mut Vec<String>`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_general_subtrees_dns`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_general_subtrees_dns(input: &[u8], out: &mut Vec<String>) -> Result<()> {
    let (subtrees_seq, tail) = noxtls_parse_der_node(input)?;
    if subtrees_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid GeneralSubtrees encoding"));
    }
    let mut cursor = subtrees_seq.body;
    while !cursor.is_empty() {
        let (subtree, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if subtree.tag != 0x30 {
            return Err(Error::ParseFailure("invalid GeneralSubtree entry"));
        }
        let (base, mut base_rest) = noxtls_parse_der_node(subtree.body)?;
        if base.tag == 0x82 {
            if out.len() >= MAX_GENERAL_SUBTREE_COUNT {
                return Err(Error::ParseFailure(
                    "nameConstraints has too many DNS subtrees for parser limit",
                ));
            }
            let dns = core::str::from_utf8(base.body)
                .map_err(|_| Error::ParseFailure("invalid UTF-8 in nameConstraints dNSName"))?;
            out.push(dns.to_owned());
        }
        while !base_rest.is_empty() {
            let (bound, rest) = noxtls_parse_der_node(base_rest)?;
            match bound.tag {
                0x80 | 0x81 => {
                    if bound.body.is_empty() {
                        return Err(Error::ParseFailure(
                            "invalid empty nameConstraints subtree bound",
                        ));
                    }
                    let _ = parse_der_positive_integer_u32(bound.body)?;
                }
                _ => {
                    return Err(Error::ParseFailure(
                        "invalid GeneralSubtree optional bound tag",
                    ));
                }
            }
            base_rest = rest;
        }
    }
    Ok(())
}

/// Parses authorityInfoAccess extension payload and extracts URI accessLocation values.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_authority_info_access`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_authority_info_access(extn_octets: &[u8]) -> Result<Vec<String>> {
    let (descriptions_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if descriptions_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid authorityInfoAccess encoding"));
    }
    let mut uris = Vec::new();
    let mut cursor = descriptions_seq.body;
    while !cursor.is_empty() {
        let (description, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        if description.tag != 0x30 {
            return Err(Error::ParseFailure("invalid AccessDescription entry"));
        }
        let (_method, location_rest) = noxtls_parse_der_node(description.body)?;
        let (location, tail) = noxtls_parse_der_node(location_rest)?;
        if !tail.is_empty() {
            return Err(Error::ParseFailure(
                "invalid AccessDescription trailing fields",
            ));
        }
        if location.tag == 0x86 {
            if uris.len() >= MAX_URI_COUNT {
                return Err(Error::ParseFailure(
                    "authorityInfoAccess has too many URIs for parser limit",
                ));
            }
            let uri = core::str::from_utf8(location.body)
                .map_err(|_| Error::ParseFailure("invalid UTF-8 in AIA URI"))?;
            uris.push(uri.to_owned());
        }
    }
    Ok(uris)
}

/// Parses policyConstraints extension payload and returns `requireExplicitPolicy` and `inhibitPolicyMapping`.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_policy_constraints`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_policy_constraints(extn_octets: &[u8]) -> Result<(Option<u32>, Option<u32>)> {
    let (constraints_seq, tail) = noxtls_parse_der_node(extn_octets)?;
    if constraints_seq.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid policyConstraints encoding"));
    }
    let mut require_explicit_policy = None;
    let mut inhibit_policy_mapping = None;
    let mut cursor = constraints_seq.body;
    while !cursor.is_empty() {
        let (node, rest) = noxtls_parse_der_node(cursor)?;
        cursor = rest;
        match node.tag {
            0x80 | 0xA0 => {
                require_explicit_policy = Some(parse_policy_constraint_skip_certs(&node)?);
            }
            0x81 | 0xA1 => {
                inhibit_policy_mapping = Some(parse_policy_constraint_skip_certs(&node)?);
            }
            _ => return Err(Error::ParseFailure("invalid policyConstraints field tag")),
        }
    }
    Ok((require_explicit_policy, inhibit_policy_mapping))
}

/// Parses inhibitAnyPolicy extension payload and returns its skipCerts value.
///
/// # Arguments
///
/// * `extn_octets` — `&[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_inhibit_any_policy`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_inhibit_any_policy(extn_octets: &[u8]) -> Result<u32> {
    let (skip_certs_node, tail) = noxtls_parse_der_node(extn_octets)?;
    if skip_certs_node.tag != 0x02 || !tail.is_empty() || skip_certs_node.body.is_empty() {
        return Err(Error::ParseFailure("invalid inhibitAnyPolicy encoding"));
    }
    parse_der_positive_integer_u32(skip_certs_node.body)
}

/// Parses one policyConstraints tagged SkipCerts field into `u32`.
///
/// # Arguments
///
/// * `node` — `&super::DerNode<'_>`.
///
/// # Returns
///
/// On success, the `Ok` payload from `parse_policy_constraint_skip_certs`; see implementation for value shape.
///
/// # Errors
///
/// Returns `noxtls_core::Error` when parsing or validation fails; see implementation for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn parse_policy_constraint_skip_certs(node: &super::DerNode<'_>) -> Result<u32> {
    if node.body.is_empty() {
        return Err(Error::ParseFailure("invalid empty policyConstraints value"));
    }
    if node.tag == 0x80 || node.tag == 0x81 {
        return parse_der_positive_integer_u32(node.body);
    }
    let (inner_integer, tail) = noxtls_parse_der_node(node.body)?;
    if inner_integer.tag != 0x02 || !tail.is_empty() || inner_integer.body.is_empty() {
        return Err(Error::ParseFailure(
            "invalid policyConstraints integer wrapper",
        ));
    }
    parse_der_positive_integer_u32(inner_integer.body)
}

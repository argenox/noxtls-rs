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

use core::fmt::{Display, Formatter};

#[cfg(not(feature = "std"))]
use crate::internal_alloc::ToOwned;
use crate::internal_alloc::{String, Vec};

use noxtls_crypto::{
    ed25519_verify, mldsa_verify, p256_ecdsa_verify_sha256, rsassa_pss_sha256_verify,
    rsassa_pss_sha384_verify, rsassa_sha256_verify, rsassa_sha384_verify, rsassa_sha512_verify,
    Ed25519PublicKey, MlDsaPublicKey, P256PublicKey, RsaPublicKey, OID_ID_MLDSA65,
};

use super::{parse_der_node, Certificate};

/// Describes why certificate path validation failed.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ValidationError {
    InvalidNowTimeFormat,
    CertificateNotYetValid,
    CertificateExpired,
    IssuerNotFound,
    IssuerNotCa,
    IssuerMissingKeyCertSign,
    PathLenExceeded,
    UntrustedRoot,
    ChainLoopDetected,
    MaxChainDepthExceeded,
    SignatureAlgorithmMismatch,
    UnsupportedSignatureAlgorithm,
    UnsupportedPublicKeyAlgorithm,
    PublicKeyDecodeFailed,
    SignatureVerificationFailed,
    MissingRequiredPolicy,
    MissingRequiredExtendedKeyUsage,
    ExplicitPolicyRequired,
    PolicyMappingInhibited,
    NameConstraintsViolation,
    MissingRevocationInfo,
    MissingRevocationLocator,
}

impl Display for ValidationError {
    // Formats validation errors as stable human-readable messages.
    // Parameter: `f` formatter sink for error string output.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidNowTimeFormat => f.write_str("invalid now timestamp format"),
            Self::CertificateNotYetValid => f.write_str("certificate is not yet valid"),
            Self::CertificateExpired => f.write_str("certificate is expired"),
            Self::IssuerNotFound => f.write_str("certificate issuer not found"),
            Self::IssuerNotCa => f.write_str("issuer certificate is not a CA"),
            Self::IssuerMissingKeyCertSign => {
                f.write_str("issuer certificate key usage missing keyCertSign")
            }
            Self::PathLenExceeded => f.write_str("issuer pathLenConstraint exceeded"),
            Self::UntrustedRoot => {
                f.write_str("certificate chain does not terminate at trust anchor")
            }
            Self::ChainLoopDetected => f.write_str("certificate chain loop detected"),
            Self::MaxChainDepthExceeded => f.write_str("certificate chain depth exceeded"),
            Self::SignatureAlgorithmMismatch => {
                f.write_str("certificate signature algorithm mismatch")
            }
            Self::UnsupportedSignatureAlgorithm => {
                f.write_str("certificate signature algorithm is unsupported")
            }
            Self::UnsupportedPublicKeyAlgorithm => {
                f.write_str("issuer public key algorithm is unsupported")
            }
            Self::PublicKeyDecodeFailed => f.write_str("issuer public key decode failed"),
            Self::SignatureVerificationFailed => {
                f.write_str("certificate signature verification failed")
            }
            Self::MissingRequiredPolicy => f.write_str("certificate missing required policy OID"),
            Self::MissingRequiredExtendedKeyUsage => {
                f.write_str("certificate missing required extended key usage")
            }
            Self::ExplicitPolicyRequired => {
                f.write_str("effective certificate policy set is empty")
            }
            Self::PolicyMappingInhibited => {
                f.write_str("certificate policyMappings present while policy mapping is inhibited")
            }
            Self::NameConstraintsViolation => {
                f.write_str("certificate subject violates issuer name constraints")
            }
            Self::MissingRevocationInfo => {
                f.write_str("certificate missing revocation distribution info")
            }
            Self::MissingRevocationLocator => {
                f.write_str("certificate missing CRL distribution point and AIA locator")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

/// Summarizes key properties of a validated certificate chain.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidationReport {
    pub chain_len: usize,
    pub trust_anchor_index: usize,
    pub effective_policy_oids: Vec<Vec<u8>>,
}

/// Controls optional policy and revocation-related path validation requirements.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ValidationOptions {
    pub required_policy_oid: Option<Vec<u8>>,
    pub required_extended_key_usage_oid: Option<Vec<u8>>,
    pub require_explicit_policy: bool,
    pub require_crl_distribution_points: bool,
    pub require_revocation_locator: bool,
    pub inhibit_policy_mapping: bool,
}

/// Validates certificate chain with signature enforcement at each hop.
///
/// # Arguments
/// * `leaf`: End-entity certificate to validate.
/// * `intermediates`: Candidate intermediate issuer certificates.
/// * `trust_anchors`: Trusted root certificates.
/// * `now`: Validation time string (UTCTime or GeneralizedTime).
///
/// # Returns
/// `ValidationReport` when path building and checks succeed.
pub fn validate_certificate_chain<'a>(
    leaf: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now: &str,
) -> core::result::Result<ValidationReport, ValidationError> {
    validate_certificate_chain_with_options(
        leaf,
        intermediates,
        trust_anchors,
        now,
        &ValidationOptions::default(),
    )
}

/// Validates certificate chain with caller-provided policy/revocation options.
///
/// # Arguments
/// * `leaf`: End-entity certificate to validate.
/// * `intermediates`: Candidate intermediate issuer certificates.
/// * `trust_anchors`: Trusted root certificates.
/// * `now`: Validation time string (UTCTime or GeneralizedTime).
/// * `options`: Additional policy and revocation requirements.
///
/// # Returns
/// `ValidationReport` when validation succeeds under `options`.
pub fn validate_certificate_chain_with_options<'a>(
    leaf: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now: &str,
    options: &ValidationOptions,
) -> core::result::Result<ValidationReport, ValidationError> {
    validate_certificate_chain_internal(leaf, intermediates, trust_anchors, now, true, options)
}

/// Validates certificate path constraints without enforcing signature checks.
///
/// # Arguments
/// * `leaf`: End-entity certificate to validate.
/// * `intermediates`: Candidate intermediate issuer certificates.
/// * `trust_anchors`: Trusted root certificates.
/// * `now`: Validation time string (UTCTime or GeneralizedTime).
///
/// # Returns
/// `ValidationReport` when constraint checks succeed.
pub fn validate_certificate_chain_constraints_only<'a>(
    leaf: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now: &str,
) -> core::result::Result<ValidationReport, ValidationError> {
    validate_certificate_chain_internal(
        leaf,
        intermediates,
        trust_anchors,
        now,
        false,
        &ValidationOptions::default(),
    )
}

/// Validates certificate chain with explicit strict-signature naming for callers.
///
/// # Arguments
/// * `leaf`: End-entity certificate to validate.
/// * `intermediates`: Candidate intermediate issuer certificates.
/// * `trust_anchors`: Trusted root certificates.
/// * `now`: Validation time string (UTCTime or GeneralizedTime).
///
/// # Returns
/// `ValidationReport` when strict chain validation succeeds.
pub fn validate_certificate_chain_strict<'a>(
    leaf: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now: &str,
) -> core::result::Result<ValidationReport, ValidationError> {
    validate_certificate_chain(leaf, intermediates, trust_anchors, now)
}

/// Shared X.509 chain validation implementation with optional signature enforcement.
///
/// # Arguments
///
/// * `leaf` — End-entity certificate being validated.
/// * `intermediates` — Candidate intermediate certificates.
/// * `trust_anchors` — Trusted anchor certificates (must be non-empty).
/// * `now` — Validation time string (UTCTime or GeneralizedTime text).
/// * `enforce_signatures` — When `true`, issuer signatures are verified while walking the chain.
/// * `options` — Policy, EKU, and revocation knobs applied during validation.
///
/// # Returns
///
/// On success, a populated [`ValidationReport`].
///
/// # Errors
///
/// Returns [`ValidationError`] when the chain cannot be built, policy checks fail, or signatures do not verify.
///
/// # Panics
///
/// This function does not panic.
fn validate_certificate_chain_internal<'a>(
    leaf: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now: &str,
    enforce_signatures: bool,
    options: &ValidationOptions,
) -> core::result::Result<ValidationReport, ValidationError> {
    if trust_anchors.is_empty() {
        return Err(ValidationError::UntrustedRoot);
    }

    let now_canonical = canonical_time(now).ok_or(ValidationError::InvalidNowTimeFormat)?;
    validate_chain_step(
        leaf,
        intermediates,
        trust_anchors,
        &now_canonical,
        enforce_signatures,
        options,
        1,
        0,
        0,
        ChainValidationState {
            visited_serials: Vec::new(),
            effective_policy_oids: None,
            explicit_policy_skip_certs: if options.require_explicit_policy {
                Some(0)
            } else {
                None
            },
            inhibit_any_policy_skip_certs: None,
            inhibit_policy_mapping_skip_certs: if options.inhibit_policy_mapping {
                Some(0)
            } else {
                None
            },
        },
    )
}

#[derive(Clone, Debug, Default)]
struct ChainValidationState {
    visited_serials: Vec<Vec<u8>>,
    effective_policy_oids: Option<Vec<Vec<u8>>>,
    explicit_policy_skip_certs: Option<u32>,
    inhibit_any_policy_skip_certs: Option<u32>,
    inhibit_policy_mapping_skip_certs: Option<u32>,
}

/// Recursively validates one chain step and backtracks across issuer candidates.
///
/// # Arguments
///
/// * `current` — Certificate under inspection at this depth.
/// * `intermediates` — Pool of intermediate issuers still available.
/// * `trust_anchors` — Trusted anchors for terminal issuer resolution.
/// * `now_canonical` — Canonicalized comparison time (`YYYYMMDDHHMMSSZ`).
/// * `enforce_signatures` — Whether to verify `current` against its selected issuer.
/// * `options` — Validation options controlling policies and revocation checks.
/// * `chain_len` — 1-based depth of `current` from the leaf.
/// * `ca_hops_below_issuer` — Remaining CA hops permitted under `pathLenConstraint` for the pending issuer.
/// * `hop_count` — Recursion guard counting traversal steps.
/// * `state` — Mutable policy and visited-serial state carried through recursion.
///
/// # Returns
///
/// On success, a [`ValidationReport`] once a trusted anchor is reached.
///
/// # Errors
///
/// Returns [`ValidationError`] on depth limits, time window violations, unsupported algorithms, or exhausted candidates.
///
/// # Panics
///
/// This function does not panic.
fn validate_chain_step<'a>(
    current: &Certificate<'a>,
    intermediates: &[Certificate<'a>],
    trust_anchors: &[Certificate<'a>],
    now_canonical: &str,
    enforce_signatures: bool,
    options: &ValidationOptions,
    chain_len: usize,
    ca_hops_below_issuer: usize,
    hop_count: usize,
    mut state: ChainValidationState,
) -> core::result::Result<ValidationReport, ValidationError> {
    const OID_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];
    if hop_count > 16 {
        return Err(ValidationError::MaxChainDepthExceeded);
    }

    validate_time(current, now_canonical)?;
    validate_policy_and_revocation(current, options, chain_len == 1)?;
    update_inhibit_any_policy_skip_certs(&mut state.inhibit_any_policy_skip_certs, current);
    update_effective_policies(
        &mut state.effective_policy_oids,
        current,
        explicit_policy_is_active(state.inhibit_any_policy_skip_certs),
        OID_ANY_POLICY,
    );
    update_explicit_policy_skip_certs(&mut state.explicit_policy_skip_certs, current);
    enforce_explicit_policy_progress(
        &state.effective_policy_oids,
        state.explicit_policy_skip_certs,
    )?;
    update_inhibit_policy_mapping_skip_certs(&mut state.inhibit_policy_mapping_skip_certs, current);
    enforce_policy_mapping(current, state.inhibit_policy_mapping_skip_certs)?;
    if state
        .visited_serials
        .iter()
        .any(|serial| serial.as_slice() == current.serial.as_slice())
    {
        return Err(ValidationError::ChainLoopDetected);
    }
    state.visited_serials.push(current.serial.clone());

    if current.subject_raw == current.issuer_raw {
        let anchor_idx = trust_anchors
            .iter()
            .position(|anchor| anchor.subject_raw == current.subject_raw)
            .ok_or(ValidationError::UntrustedRoot)?;
        let policies = finalize_effective_policies(
            &state.effective_policy_oids,
            state.explicit_policy_skip_certs,
        )?;
        return Ok(ValidationReport {
            chain_len,
            trust_anchor_index: anchor_idx,
            effective_policy_oids: policies,
        });
    }

    if let Some(anchor_idx) = trust_anchors
        .iter()
        .position(|anchor| anchor.subject_raw == current.issuer_raw)
    {
        let issuer = &trust_anchors[anchor_idx];
        validate_time(issuer, now_canonical)?;
        validate_policy_and_revocation(issuer, options, false)?;
        apply_policy_mappings_for_issuer(&mut state.effective_policy_oids, issuer);
        update_inhibit_any_policy_skip_certs(&mut state.inhibit_any_policy_skip_certs, issuer);
        update_effective_policies(
            &mut state.effective_policy_oids,
            issuer,
            explicit_policy_is_active(state.inhibit_any_policy_skip_certs),
            OID_ANY_POLICY,
        );
        update_explicit_policy_skip_certs(&mut state.explicit_policy_skip_certs, issuer);
        enforce_explicit_policy_progress(
            &state.effective_policy_oids,
            state.explicit_policy_skip_certs,
        )?;
        update_inhibit_policy_mapping_skip_certs(
            &mut state.inhibit_policy_mapping_skip_certs,
            issuer,
        );
        enforce_policy_mapping(current, state.inhibit_policy_mapping_skip_certs)?;
        enforce_policy_mapping(issuer, state.inhibit_policy_mapping_skip_certs)?;
        validate_issuer_constraints(issuer, ca_hops_below_issuer)?;
        validate_name_constraints(issuer, current)?;
        if enforce_signatures {
            verify_certificate_signature(current, issuer)?;
        }
        let policies = finalize_effective_policies(
            &state.effective_policy_oids,
            state.explicit_policy_skip_certs,
        )?;
        return Ok(ValidationReport {
            chain_len: chain_len + 1,
            trust_anchor_index: anchor_idx,
            effective_policy_oids: policies,
        });
    }

    let issuer_candidates: Vec<&Certificate<'a>> = intermediates
        .iter()
        .filter(|candidate| candidate.subject_raw == current.issuer_raw)
        .collect();
    if issuer_candidates.is_empty() {
        return Err(ValidationError::IssuerNotFound);
    }

    let mut last_error = ValidationError::IssuerNotFound;
    for issuer in issuer_candidates {
        let mut next_state = state.clone();
        let candidate_result = (|| -> core::result::Result<ValidationReport, ValidationError> {
            validate_time(issuer, now_canonical)?;
            validate_policy_and_revocation(issuer, options, false)?;
            apply_policy_mappings_for_issuer(&mut next_state.effective_policy_oids, issuer);
            update_inhibit_any_policy_skip_certs(
                &mut next_state.inhibit_any_policy_skip_certs,
                issuer,
            );
            update_effective_policies(
                &mut next_state.effective_policy_oids,
                issuer,
                explicit_policy_is_active(next_state.inhibit_any_policy_skip_certs),
                OID_ANY_POLICY,
            );
            update_explicit_policy_skip_certs(&mut next_state.explicit_policy_skip_certs, issuer);
            enforce_explicit_policy_progress(
                &next_state.effective_policy_oids,
                next_state.explicit_policy_skip_certs,
            )?;
            update_inhibit_policy_mapping_skip_certs(
                &mut next_state.inhibit_policy_mapping_skip_certs,
                issuer,
            );
            enforce_policy_mapping(current, next_state.inhibit_policy_mapping_skip_certs)?;
            enforce_policy_mapping(issuer, next_state.inhibit_policy_mapping_skip_certs)?;
            validate_issuer_constraints(issuer, ca_hops_below_issuer)?;
            validate_name_constraints(issuer, current)?;
            if enforce_signatures {
                verify_certificate_signature(current, issuer)?;
            }
            decrement_skip_certs_counter(&mut next_state.inhibit_any_policy_skip_certs, current);
            decrement_skip_certs_counter(&mut next_state.explicit_policy_skip_certs, current);
            decrement_skip_certs_counter(
                &mut next_state.inhibit_policy_mapping_skip_certs,
                current,
            );

            validate_chain_step(
                issuer,
                intermediates,
                trust_anchors,
                now_canonical,
                enforce_signatures,
                options,
                chain_len + 1,
                ca_hops_below_issuer + 1,
                hop_count + 1,
                next_state,
            )
        })();
        match candidate_result {
            Ok(report) => return Ok(report),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// Verifies one certificate signature using issuer public key material.
///
/// # Arguments
/// * `certificate`: Certificate whose signature should be verified.
/// * `issuer`: Issuer certificate providing public key material.
///
/// # Returns
/// `Ok(())` when signature verification succeeds.
pub fn verify_certificate_signature(
    certificate: &Certificate<'_>,
    issuer: &Certificate<'_>,
) -> core::result::Result<(), ValidationError> {
    const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    const OID_SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    const OID_SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

    if certificate.tbs_signature_algorithm_oid != certificate.certificate_signature_algorithm_oid {
        return Err(ValidationError::SignatureAlgorithmMismatch);
    }
    if issuer.subject_public_key_algorithm_oid == OID_RSA_ENCRYPTION {
        let (n, e) = parse_rsa_public_key_der(&issuer.subject_public_key)?;
        let public_key = RsaPublicKey::from_be_bytes(&n, &e)
            .map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
        if certificate.certificate_signature_algorithm_oid == OID_SHA256_WITH_RSA {
            return rsassa_sha256_verify(
                &public_key,
                certificate.raw_tbs_der,
                &certificate.signature_value,
            )
            .map_err(|_| ValidationError::SignatureVerificationFailed);
        }
        if certificate.certificate_signature_algorithm_oid == OID_SHA384_WITH_RSA {
            return rsassa_sha384_verify(
                &public_key,
                certificate.raw_tbs_der,
                &certificate.signature_value,
            )
            .map_err(|_| ValidationError::SignatureVerificationFailed);
        }
        if certificate.certificate_signature_algorithm_oid == OID_SHA512_WITH_RSA {
            return rsassa_sha512_verify(
                &public_key,
                certificate.raw_tbs_der,
                &certificate.signature_value,
            )
            .map_err(|_| ValidationError::SignatureVerificationFailed);
        }
        if certificate.certificate_signature_algorithm_oid == OID_RSASSA_PSS {
            // Until RSASSA-PSS parameters are parsed from AlgorithmIdentifier, accept SHA-256
            // and SHA-384 common profiles by trying the expected default salt lengths.
            if rsassa_pss_sha256_verify(
                &public_key,
                certificate.raw_tbs_der,
                &certificate.signature_value,
                32,
            )
            .is_ok()
            {
                return Ok(());
            }
            return rsassa_pss_sha384_verify(
                &public_key,
                certificate.raw_tbs_der,
                &certificate.signature_value,
                48,
            )
            .map_err(|_| ValidationError::SignatureVerificationFailed);
        }
        return Err(ValidationError::UnsupportedSignatureAlgorithm);
    }

    if issuer.subject_public_key_algorithm_oid == OID_EC_PUBLIC_KEY {
        if certificate.certificate_signature_algorithm_oid != OID_ECDSA_WITH_SHA256 {
            return Err(ValidationError::UnsupportedSignatureAlgorithm);
        }
        let public_key = P256PublicKey::from_uncompressed(&issuer.subject_public_key)
            .map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
        let (r, s) = parse_ecdsa_signature_der(&certificate.signature_value)?;
        return p256_ecdsa_verify_sha256(&public_key, certificate.raw_tbs_der, &r, &s)
            .map_err(|_| ValidationError::SignatureVerificationFailed);
    }

    if issuer.subject_public_key_algorithm_oid.as_slice() == OID_ED25519 {
        if certificate.certificate_signature_algorithm_oid.as_slice() != OID_ED25519 {
            return Err(ValidationError::UnsupportedSignatureAlgorithm);
        }
        if certificate.signature_value.len() != 64 {
            return Err(ValidationError::SignatureVerificationFailed);
        }
        let key_bytes: [u8; 32] = issuer
            .subject_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
        let public_key = Ed25519PublicKey::from_bytes(&key_bytes)
            .map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
        return ed25519_verify(
            &public_key,
            certificate.raw_tbs_der,
            certificate.signature_value.as_slice(),
        )
        .map_err(|_| ValidationError::SignatureVerificationFailed);
    }

    if issuer.subject_public_key_algorithm_oid.as_slice() == OID_ID_MLDSA65 {
        if certificate.certificate_signature_algorithm_oid.as_slice() != OID_ID_MLDSA65 {
            return Err(ValidationError::UnsupportedSignatureAlgorithm);
        }
        let public_key = MlDsaPublicKey::from_bytes(&issuer.subject_public_key)
            .map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
        return mldsa_verify(
            &public_key,
            certificate.raw_tbs_der,
            certificate.signature_value.as_slice(),
        )
        .map_err(|_| ValidationError::SignatureVerificationFailed);
    }

    Err(ValidationError::UnsupportedPublicKeyAlgorithm)
}

/// Validates issuer CA basic constraints, `keyCertSign`, and `pathLenConstraint` against the pending path.
///
/// # Arguments
///
/// * `issuer` — Issuer certificate that must act as a CA for this hop.
/// * `ca_hops_below_issuer` — Number of additional CA certificates below this issuer on the built path.
///
/// # Returns
///
/// `Ok(())` when issuer constraints allow signing the child certificate.
///
/// # Errors
///
/// Returns [`ValidationError`] when the issuer is not a CA, lacks `keyCertSign`, or violates `pathLenConstraint`.
///
/// # Panics
///
/// This function does not panic.
fn validate_issuer_constraints(
    issuer: &Certificate<'_>,
    ca_hops_below_issuer: usize,
) -> core::result::Result<(), ValidationError> {
    if issuer.basic_constraints_ca != Some(true) {
        return Err(ValidationError::IssuerNotCa);
    }
    if let Some(key_usage) = issuer.key_usage_bits {
        // KeyUsage bit 5 (keyCertSign) maps to mask 0x0004 in DER bit-order.
        if (key_usage & 0x0004) == 0 {
            return Err(ValidationError::IssuerMissingKeyCertSign);
        }
    }
    if let Some(path_len) = issuer.basic_constraints_path_len {
        if ca_hops_below_issuer > path_len as usize {
            return Err(ValidationError::PathLenExceeded);
        }
    }
    Ok(())
}

/// Validates the certificate validity interval against a canonical `YYYYMMDDHHMMSSZ` comparison string.
///
/// # Arguments
///
/// * `cert` — Certificate whose `notBefore` / `notAfter` fields are checked.
/// * `now_canonical` — Current time in canonical form for lexicographic comparison.
///
/// # Returns
///
/// `Ok(())` when `now_canonical` lies within the certificate validity window.
///
/// # Errors
///
/// Returns [`ValidationError`] when time fields cannot be canonicalized or the certificate is not yet valid / expired.
///
/// # Panics
///
/// This function does not panic.
fn validate_time(
    cert: &Certificate<'_>,
    now_canonical: &str,
) -> core::result::Result<(), ValidationError> {
    let not_before =
        canonical_time(&cert.not_before).ok_or(ValidationError::InvalidNowTimeFormat)?;
    let not_after = canonical_time(&cert.not_after).ok_or(ValidationError::InvalidNowTimeFormat)?;
    if now_canonical < not_before.as_str() {
        return Err(ValidationError::CertificateNotYetValid);
    }
    if now_canonical > not_after.as_str() {
        return Err(ValidationError::CertificateExpired);
    }
    Ok(())
}

/// Converts UTCTime or GeneralizedTime text into canonical `YYYYMMDDHHMMSSZ`.
///
/// # Arguments
///
/// * `input` — `&str`.
///
/// # Returns
///
/// `Option<String>` produced by `canonical_time` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn canonical_time(input: &str) -> Option<String> {
    if input.len() == 15 && input.ends_with('Z') {
        let body = &input[..14];
        if body.chars().all(|c| c.is_ascii_digit()) {
            return Some(input.to_owned());
        }
        return None;
    }
    if input.len() == 13 && input.ends_with('Z') {
        let yy = &input[..2];
        let rest = &input[2..12];
        if !yy.chars().all(|c| c.is_ascii_digit()) || !rest.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let yy_value = yy.parse::<u32>().ok()?;
        let century = if yy_value >= 50 { "19" } else { "20" };
        return Some(format!("{century}{yy}{rest}Z"));
    }
    None
}

/// Parses a PKCS#1 `RSAPublicKey` SEQUENCE into raw modulus and exponent bytes.
///
/// # Arguments
///
/// * `public_key_der` — DER `SubjectPublicKeyInfo` public key BIT STRING payload for RSA.
///
/// # Returns
///
/// On success, `(modulus, exponent)` big-endian integer bodies without extra length padding beyond DER rules.
///
/// # Errors
///
/// Returns [`ValidationError::PublicKeyDecodeFailed`] when the SEQUENCE layout is not a two-INTEGER PKCS#1 key.
///
/// # Panics
///
/// This function does not panic.
fn parse_rsa_public_key_der(
    public_key_der: &[u8],
) -> core::result::Result<(Vec<u8>, Vec<u8>), ValidationError> {
    let (rsa_seq, rem) =
        parse_der_node(public_key_der).map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
    if rsa_seq.tag != 0x30 || !rem.is_empty() {
        return Err(ValidationError::PublicKeyDecodeFailed);
    }
    let (modulus_node, rest) =
        parse_der_node(rsa_seq.body).map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
    let (exponent_node, tail) =
        parse_der_node(rest).map_err(|_| ValidationError::PublicKeyDecodeFailed)?;
    if modulus_node.tag != 0x02 || exponent_node.tag != 0x02 || !tail.is_empty() {
        return Err(ValidationError::PublicKeyDecodeFailed);
    }
    Ok((modulus_node.body.to_vec(), exponent_node.body.to_vec()))
}

/// Parses an ECDSA signature `SEQUENCE { r INTEGER, s INTEGER }` into fixed 32-byte P-256 scalars.
///
/// # Arguments
///
/// * `signature_der` — DER-encoded ECDSA signature bytes.
///
/// # Returns
///
/// On success, `(r, s)` each 32 bytes for use with the in-crypto P-256 verifier.
///
/// # Errors
///
/// Returns [`ValidationError::SignatureVerificationFailed`] when DER structure or integer normalization is invalid.
///
/// # Panics
///
/// This function does not panic.
fn parse_ecdsa_signature_der(
    signature_der: &[u8],
) -> core::result::Result<([u8; 32], [u8; 32]), ValidationError> {
    let (seq, rem) =
        parse_der_node(signature_der).map_err(|_| ValidationError::SignatureVerificationFailed)?;
    if seq.tag != 0x30 || !rem.is_empty() {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    let (r_node, rest) =
        parse_der_node(seq.body).map_err(|_| ValidationError::SignatureVerificationFailed)?;
    let (s_node, tail) =
        parse_der_node(rest).map_err(|_| ValidationError::SignatureVerificationFailed)?;
    if r_node.tag != 0x02 || s_node.tag != 0x02 || !tail.is_empty() {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    let r = ecdsa_integer_to_scalar32(r_node.body)?;
    let s = ecdsa_integer_to_scalar32(s_node.body)?;
    Ok((r, s))
}

/// Converts one DER INTEGER to a 32-byte unsigned scalar for P-256 signature verification.
///
/// # Arguments
///
/// * `value` — `&[u8]`.
///
/// # Returns
///
/// On success, a 32-byte big-endian unsigned scalar with leading zero padding when the integer is shorter than 32 bytes.
///
/// # Errors
///
/// Returns [`ValidationError::SignatureVerificationFailed`] when the INTEGER is empty, negatively signed, non-minimally encoded, or longer than 32 bytes.
///
/// # Panics
///
/// This function does not panic.
fn ecdsa_integer_to_scalar32(value: &[u8]) -> core::result::Result<[u8; 32], ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    if value[0] & 0x80 != 0 {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    let normalized = if value.len() > 1 && value[0] == 0x00 {
        &value[1..]
    } else {
        value
    };
    if normalized.len() > 32 {
        return Err(ValidationError::SignatureVerificationFailed);
    }
    let mut out = [0_u8; 32];
    out[32 - normalized.len()..].copy_from_slice(normalized);
    Ok(out)
}

/// Validates configured policy OIDs, extended key usage, and revocation locator requirements.
///
/// # Arguments
///
/// * `cert` — Certificate being checked at this chain position.
/// * `options` — Caller-selected validation options.
/// * `is_leaf` — `true` when `cert` is the end-entity (leaf) certificate.
///
/// # Returns
///
/// `Ok(())` when optional policy and revocation requirements are satisfied.
///
/// # Errors
///
/// Returns [`ValidationError`] when a required policy, EKU, CRL/AIA locator, or similar constraint is missing.
///
/// # Panics
///
/// This function does not panic.
fn validate_policy_and_revocation(
    cert: &Certificate<'_>,
    options: &ValidationOptions,
    is_leaf: bool,
) -> core::result::Result<(), ValidationError> {
    if let Some(required_policy) = &options.required_policy_oid {
        if cert
            .certificate_policies
            .iter()
            .all(|policy| policy != required_policy)
        {
            return Err(ValidationError::MissingRequiredPolicy);
        }
    }
    if options.require_crl_distribution_points
        && cert.crl_distribution_uris.is_empty()
        && cert.subject_raw != cert.issuer_raw
    {
        return Err(ValidationError::MissingRevocationInfo);
    }
    if options.require_revocation_locator
        && cert.crl_distribution_uris.is_empty()
        && cert.authority_info_access_uris.is_empty()
        && cert.subject_raw != cert.issuer_raw
    {
        return Err(ValidationError::MissingRevocationLocator);
    }
    if is_leaf {
        if let Some(required_eku) = &options.required_extended_key_usage_oid {
            if cert
                .extended_key_usage_oids
                .iter()
                .all(|usage| usage != required_eku)
            {
                return Err(ValidationError::MissingRequiredExtendedKeyUsage);
            }
        }
    }
    Ok(())
}

/// Updates the effective policy OID set by intersecting with the current certificate's policies when present.
///
/// # Arguments
///
/// * `effective_policy_oids` — Accumulated policy OID set carried through the walk.
/// * `cert` — Certificate whose `certificatePolicies` extension contributes to the intersection.
/// * `inhibit_any_policy_active` — When `true`, `anyPolicy` is not treated as a wildcard.
/// * `any_policy_oid` — Raw OID bytes for `anyPolicy`.
///
/// # Returns
///
/// This function returns nothing; it mutates `effective_policy_oids` in place.
///
/// # Panics
///
/// This function does not panic.
fn update_effective_policies(
    effective_policy_oids: &mut Option<Vec<Vec<u8>>>,
    cert: &Certificate<'_>,
    inhibit_any_policy_active: bool,
    any_policy_oid: &[u8],
) {
    if cert.certificate_policies.is_empty() {
        return;
    }
    let current = unique_policies(&cert.certificate_policies);
    let has_any_policy = current.iter().any(|policy| policy == any_policy_oid);
    if has_any_policy && !inhibit_any_policy_active {
        // Treat anyPolicy as wildcard in this simplified model.
        return;
    }
    match effective_policy_oids {
        None => *effective_policy_oids = Some(current),
        Some(existing) => {
            existing.retain(|policy| current.iter().any(|candidate| candidate == policy));
        }
    }
}

/// Updates the `inhibitAnyPolicy` skip-certs counter from the current certificate extension state.
///
/// # Arguments
///
/// * `inhibit_any_policy_skip_certs` — Running counter carried through the walk.
/// * `cert` — Certificate that may carry an `inhibitAnyPolicy` extension.
///
/// # Returns
///
/// This function returns nothing; it mutates `inhibit_any_policy_skip_certs` in place.
///
/// # Panics
///
/// This function does not panic.
fn update_inhibit_any_policy_skip_certs(
    inhibit_any_policy_skip_certs: &mut Option<u32>,
    cert: &Certificate<'_>,
) {
    if let Some(inhibit_any_policy) = cert.inhibit_any_policy_skip_certs {
        let next_value = inhibit_any_policy_skip_certs.map_or(inhibit_any_policy, |existing| {
            existing.min(inhibit_any_policy)
        });
        *inhibit_any_policy_skip_certs = Some(next_value);
    }
}

/// Applies the issuer's `policyMappings` to remap subject-domain policy OIDs back toward issuer-domain OIDs.
///
/// # Arguments
///
/// * `effective_policy_oids` — Effective policy set before issuer intersection.
/// * `issuer` — Issuer certificate whose mapping table is consulted.
///
/// # Returns
///
/// This function returns nothing; it may replace `effective_policy_oids` with a remapped vector.
///
/// # Panics
///
/// This function does not panic.
fn apply_policy_mappings_for_issuer(
    effective_policy_oids: &mut Option<Vec<Vec<u8>>>,
    issuer: &Certificate<'_>,
) {
    let Some(existing) = effective_policy_oids.as_ref() else {
        return;
    };
    if issuer.policy_mappings.is_empty() {
        return;
    }

    let mut remapped = Vec::new();
    for policy in existing {
        let mut mapped = false;
        for (issuer_policy, subject_policy) in &issuer.policy_mappings {
            // Traversal is leaf->root, so map subject-domain policy back to issuer-domain policy.
            if policy == subject_policy {
                remapped.push(issuer_policy.clone());
                mapped = true;
            }
        }
        if !mapped {
            remapped.push(policy.clone());
        }
    }
    *effective_policy_oids = Some(unique_policies(&remapped));
}

/// Deduplicates policy OID byte-vectors while preserving first-seen order.
///
/// # Arguments
///
/// * `policies` — `&[Vec<u8>]`.
///
/// # Returns
///
/// `Vec<Vec<u8>>` produced by `unique_policies` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn unique_policies(policies: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for policy in policies {
        if out.iter().all(|existing| existing != policy) {
            out.push(policy.clone());
        }
    }
    out
}

/// Finalizes the effective policy OID list and enforces explicit-policy requirements when active.
///
/// # Arguments
///
/// * `effective_policy_oids` — Optional accumulated policy set after walking the chain.
/// * `explicit_policy_skip_certs` — Remaining explicit-policy skip counter, if any.
///
/// # Returns
///
/// On success, the finalized policy OID vector (possibly empty when explicit policy is not required).
///
/// # Errors
///
/// Returns [`ValidationError::ExplicitPolicyRequired`] when explicit policy is active but no policies remain.
///
/// # Panics
///
/// This function does not panic.
fn finalize_effective_policies(
    effective_policy_oids: &Option<Vec<Vec<u8>>>,
    explicit_policy_skip_certs: Option<u32>,
) -> core::result::Result<Vec<Vec<u8>>, ValidationError> {
    let policies = effective_policy_oids.clone().unwrap_or_default();
    if explicit_policy_is_active(explicit_policy_skip_certs) && policies.is_empty() {
        return Err(ValidationError::ExplicitPolicyRequired);
    }
    Ok(policies)
}

/// Fails early when explicit-policy mode would otherwise proceed with an empty effective policy set.
///
/// # Arguments
///
/// * `effective_policy_oids` — Optional accumulated policy set.
/// * `explicit_policy_skip_certs` — Remaining explicit-policy skip counter, if any.
///
/// # Returns
///
/// `Ok(())` when explicit policy is inactive or at least one policy OID is present.
///
/// # Errors
///
/// Returns [`ValidationError::ExplicitPolicyRequired`] when explicit policy is active with no effective policies.
///
/// # Panics
///
/// This function does not panic.
fn enforce_explicit_policy_progress(
    effective_policy_oids: &Option<Vec<Vec<u8>>>,
    explicit_policy_skip_certs: Option<u32>,
) -> core::result::Result<(), ValidationError> {
    let has_effective_policies = effective_policy_oids
        .as_ref()
        .is_some_and(|value| !value.is_empty());
    if explicit_policy_is_active(explicit_policy_skip_certs) && !has_effective_policies {
        return Err(ValidationError::ExplicitPolicyRequired);
    }
    Ok(())
}

/// Updates the explicit-policy skip-certs counter using `policyConstraints.requireExplicitPolicy` from `cert`.
///
/// # Arguments
///
/// * `explicit_policy_skip_certs` — Running counter carried through the walk.
/// * `cert` — Certificate that may carry `policyConstraints`.
///
/// # Returns
///
/// This function returns nothing; it mutates `explicit_policy_skip_certs` in place.
///
/// # Panics
///
/// This function does not panic.
fn update_explicit_policy_skip_certs(
    explicit_policy_skip_certs: &mut Option<u32>,
    cert: &Certificate<'_>,
) {
    if let Some(require_explicit_policy) = cert.policy_constraints_require_explicit_policy {
        let next_value = explicit_policy_skip_certs.map_or(require_explicit_policy, |existing| {
            existing.min(require_explicit_policy)
        });
        *explicit_policy_skip_certs = Some(next_value);
    }
}

/// Decrements the explicit-policy skip-certs counter when the certificate is not self-issued.
///
/// # Arguments
///
/// * `explicit_policy_skip_certs` — Running counter carried through the walk.
/// * `cert` — Certificate whose self-issuance status gates the decrement.
///
/// # Returns
///
/// This function returns nothing; it mutates `explicit_policy_skip_certs` in place.
///
/// # Panics
///
/// This function does not panic.
fn decrement_skip_certs_counter(
    explicit_policy_skip_certs: &mut Option<u32>,
    cert: &Certificate<'_>,
) {
    if cert.subject_raw == cert.issuer_raw {
        return;
    }
    if let Some(counter) = explicit_policy_skip_certs.as_mut() {
        *counter = counter.saturating_sub(1);
    }
}

/// Returns true when explicit policy requirements are currently in force.
///
/// # Arguments
///
/// * `explicit_policy_skip_certs` — `Option<u32>`.
///
/// # Returns
///
/// `bool` produced by `explicit_policy_is_active` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn explicit_policy_is_active(explicit_policy_skip_certs: Option<u32>) -> bool {
    matches!(explicit_policy_skip_certs, Some(0))
}

/// Updates the inhibit-policy-mapping skip-certs counter using `policyConstraints.inhibitPolicyMapping`.
///
/// # Arguments
///
/// * `inhibit_policy_mapping_skip_certs` — Running counter carried through the walk.
/// * `cert` — Certificate that may carry `policyConstraints`.
///
/// # Returns
///
/// This function returns nothing; it mutates `inhibit_policy_mapping_skip_certs` in place.
///
/// # Panics
///
/// This function does not panic.
fn update_inhibit_policy_mapping_skip_certs(
    inhibit_policy_mapping_skip_certs: &mut Option<u32>,
    cert: &Certificate<'_>,
) {
    if let Some(inhibit_policy_mapping) = cert.policy_constraints_inhibit_policy_mapping {
        let next_value = inhibit_policy_mapping_skip_certs
            .map_or(inhibit_policy_mapping, |existing| {
                existing.min(inhibit_policy_mapping)
            });
        *inhibit_policy_mapping_skip_certs = Some(next_value);
    }
}

/// Rejects certificates that carry `policyMappings` when inhibit-policy-mapping is active at depth zero.
///
/// # Arguments
///
/// * `cert` — Certificate under inspection.
/// * `inhibit_policy_mapping_skip_certs` — Remaining inhibit-policy-mapping skip counter, if any.
///
/// # Returns
///
/// `Ok(())` when policy mappings are allowed or absent.
///
/// # Errors
///
/// Returns [`ValidationError::PolicyMappingInhibited`] when mappings are present while inhibition is active.
///
/// # Panics
///
/// This function does not panic.
fn enforce_policy_mapping(
    cert: &Certificate<'_>,
    inhibit_policy_mapping_skip_certs: Option<u32>,
) -> core::result::Result<(), ValidationError> {
    if matches!(inhibit_policy_mapping_skip_certs, Some(0)) && !cert.policy_mappings.is_empty() {
        return Err(ValidationError::PolicyMappingInhibited);
    }
    Ok(())
}

/// Ensures subject DNS SAN values satisfy the issuer's permitted and excluded DNS name constraints.
///
/// # Arguments
///
/// * `issuer` — Issuer certificate carrying optional `nameConstraints` DNS subtrees.
/// * `subject` — Subject certificate whose DNS SAN entries are checked.
///
/// # Returns
///
/// `Ok(())` when no DNS constraints apply, no DNS SANs are present, or every SAN matches permitted subtrees.
///
/// # Errors
///
/// Returns [`ValidationError::NameConstraintsViolation`] when a SAN matches an excluded subtree or misses permitted subtrees.
///
/// # Panics
///
/// This function does not panic.
fn validate_name_constraints(
    issuer: &Certificate<'_>,
    subject: &Certificate<'_>,
) -> core::result::Result<(), ValidationError> {
    let has_dns_constraints = !issuer.name_constraints_permitted_dns.is_empty()
        || !issuer.name_constraints_excluded_dns.is_empty();
    if !has_dns_constraints || subject.subject_alt_dns_names.is_empty() {
        return Ok(());
    }

    for dns_name in &subject.subject_alt_dns_names {
        if issuer
            .name_constraints_excluded_dns
            .iter()
            .any(|constraint| dns_name_matches_constraint(dns_name, constraint))
        {
            return Err(ValidationError::NameConstraintsViolation);
        }
        if !issuer.name_constraints_permitted_dns.is_empty()
            && issuer
                .name_constraints_permitted_dns
                .iter()
                .all(|constraint| !dns_name_matches_constraint(dns_name, constraint))
        {
            return Err(ValidationError::NameConstraintsViolation);
        }
    }
    Ok(())
}

/// Matches DNS name against a name-constraints dNSName suffix constraint.
///
/// # Arguments
///
/// * `dns_name` — `&str`.
/// * `constraint` — `&str`.
///
/// # Returns
///
/// `bool` produced by `dns_name_matches_constraint` (see implementation).
///
/// # Panics
///
/// This function does not panic unless otherwise noted.
fn dns_name_matches_constraint(dns_name: &str, constraint: &str) -> bool {
    let normalized_name = dns_name.to_ascii_lowercase();
    let normalized_constraint = constraint.trim_start_matches('.').to_ascii_lowercase();
    if normalized_constraint.is_empty() {
        return false;
    }
    normalized_name == normalized_constraint
        || normalized_name
            .strip_suffix(&normalized_constraint)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

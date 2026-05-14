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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! Shared error types, wire-format helpers, build-time profile metadata, and library configuration
//! for the NoxTLS Rust stack. Downstream crates (`noxtls-crypto`, `noxtls`, and others) depend on
//! this crate for [`Error`], [`Result`], and [`Profile`].

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

use core::fmt::{Display, Formatter};

mod config;

pub use config::{
    noxtls_compiled_allow_legacy_algorithms, noxtls_compiled_allow_sha1_signatures,
    noxtls_compiled_strict_constant_time, ConstantTimePolicy, LibraryConfig, SecurityPolicy,
};

#[cfg(all(
    feature = "feature-tls",
    not(any(
        feature = "feature-tls10",
        feature = "feature-tls11",
        feature = "feature-tls12",
        feature = "feature-tls13"
    ))
))]
compile_error!("feature-tls requires one of feature-tls10/11/12/13");

#[cfg(all(feature = "feature-cert-write", not(feature = "feature-cert")))]
compile_error!("feature-cert-write requires feature-cert");

#[cfg(all(feature = "feature-dtls", not(feature = "feature-tls")))]
compile_error!("feature-dtls requires feature-tls");

#[cfg(all(
    feature = "policy-strict-constant-time",
    feature = "policy-allow-legacy-algorithms"
))]
compile_error!("policy-strict-constant-time is incompatible with policy-allow-legacy-algorithms");

#[cfg(all(
    feature = "policy-strict-constant-time",
    feature = "policy-allow-sha1-signatures"
))]
compile_error!("policy-strict-constant-time is incompatible with policy-allow-sha1-signatures");

/// Library-wide error type for length, encoding, parse, state, crypto, and feature failures.
///
/// Each variant carries a static diagnostic string suitable for logging and user-facing output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// Buffer or value length is outside the allowed range for the operation.
    InvalidLength(&'static str),
    /// Encoding rules (for example DER or wire format) were violated.
    InvalidEncoding(&'static str),
    /// Parsing failed for structural or syntactic reasons.
    ParseFailure(&'static str),
    /// The requested capability is disabled or incompatible with current configuration.
    UnsupportedFeature(&'static str),
    /// A cryptographic primitive returned a verification or computation failure.
    CryptoFailure(&'static str),
    /// The operation is not valid in the current protocol or object state.
    StateError(&'static str),
}

impl Display for Error {
    /// Writes the embedded static message for this error variant into `f`.
    ///
    /// # Arguments
    ///
    /// * `self` — Error whose message string is written.
    /// * `f` — Formatter destination for the human-readable message.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the message is written successfully.
    ///
    /// # Errors
    ///
    /// Returns [`core::fmt::Error`] if the formatter rejects output (for example, a full buffer).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLength(msg)
            | Self::InvalidEncoding(msg)
            | Self::ParseFailure(msg)
            | Self::UnsupportedFeature(msg)
            | Self::CryptoFailure(msg)
            | Self::StateError(msg) => f.write_str(msg),
        }
    }
}

#[cfg(feature = "std")]
/// Bridges [`Error`] into [`std::error::Error`] for interoperability when the `std` feature is enabled.
impl std::error::Error for Error {}

/// Convenient [`core::result::Result`] alias using [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Named build or deployment profiles that map to coarse-grained feature sets.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Profile {
    /// Balanced client/server defaults with modern TLS and optional DTLS.
    Default,
    /// TLS client-oriented subset without DTLS exposure.
    MinimalTlsClient,
    /// TLS/DTLS server profile including certificate issuance helpers.
    TlsServerPki,
    /// Cryptographic primitives only (no TLS/DTLS or X.509 stack).
    CryptoOnly,
    /// Conservative TLS profile aimed at stricter deployment assumptions.
    FipsLike,
    /// Internal or test profile enabling the broadest compiled feature surface.
    UtAllFeatures,
}

/// Boolean feature flags describing which protocol and noxtls_algorithm areas are enabled for a [`Profile`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FeatureSet {
    /// Any TLS protocol surface is enabled.
    pub tls: bool,
    /// TLS 1.0 support flag.
    pub tls10: bool,
    /// TLS 1.1 support flag.
    pub tls11: bool,
    /// TLS 1.2 support flag.
    pub tls12: bool,
    /// TLS 1.3 support flag.
    pub tls13: bool,
    /// DTLS protocol surface is enabled.
    pub dtls: bool,
    /// X.509 certificate parsing and validation stack is enabled.
    pub cert: bool,
    /// Certificate writing / issuance helpers are enabled.
    pub cert_write: bool,
    /// Digest and hash primitives are enabled.
    pub hash: bool,
    /// Symmetric encryption algorithms are enabled.
    pub encryption: bool,
    /// DRBG and entropy-related helpers are enabled.
    pub drbg: bool,
    /// Public-key cryptography primitives are enabled.
    pub pkc: bool,
}

impl Profile {
    /// Returns the feature flags implied by this profile for documentation and tooling.
    ///
    /// # Arguments
    ///
    /// * `self` — Profile variant to expand into concrete flags.
    ///
    /// # Returns
    ///
    /// A [`FeatureSet`] describing TLS/DTLS, certificate, hash, symmetric, DRBG, and PKC availability.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn features(self) -> FeatureSet {
        match self {
            Self::Default => FeatureSet {
                tls: true,
                tls10: false,
                tls11: false,
                tls12: true,
                tls13: true,
                dtls: true,
                cert: true,
                cert_write: false,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
            Self::MinimalTlsClient => FeatureSet {
                tls: true,
                tls10: false,
                tls11: false,
                tls12: true,
                tls13: true,
                dtls: false,
                cert: true,
                cert_write: false,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
            Self::TlsServerPki => FeatureSet {
                tls: true,
                tls10: false,
                tls11: false,
                tls12: true,
                tls13: true,
                dtls: true,
                cert: true,
                cert_write: true,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
            Self::CryptoOnly => FeatureSet {
                tls: false,
                tls10: false,
                tls11: false,
                tls12: false,
                tls13: false,
                dtls: false,
                cert: false,
                cert_write: false,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
            Self::FipsLike => FeatureSet {
                tls: true,
                tls10: false,
                tls11: false,
                tls12: true,
                tls13: true,
                dtls: false,
                cert: true,
                cert_write: false,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
            Self::UtAllFeatures => FeatureSet {
                tls: true,
                tls10: true,
                tls11: true,
                tls12: true,
                tls13: true,
                dtls: true,
                cert: true,
                cert_write: true,
                hash: true,
                encryption: true,
                drbg: true,
                pkc: true,
            },
        }
    }
}

/// Reads an unsigned 16-bit big-endian integer from the start of `input`.
///
/// # Arguments
///
/// * `input` — Byte slice whose first two bytes are interpreted as big-endian `u16`.
///
/// # Returns
///
/// On success, the parsed 16-bit value; only the first two bytes are read.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `input` has fewer than two bytes.
pub fn noxtls_read_u16_be(input: &[u8]) -> Result<u16> {
    if input.len() < 2 {
        return Err(Error::InvalidLength("not enough bytes for u16"));
    }
    Ok(u16::from_be_bytes([input[0], input[1]]))
}

/// Reads an unsigned 24-bit big-endian integer from the start of `input`.
///
/// # Arguments
///
/// * `input` — Byte slice whose first three bytes are interpreted as a 24-bit big-endian integer in a `u32`.
///
/// # Returns
///
/// On success, the parsed value in the low 24 bits of the returned `u32`.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] when `input` has fewer than three bytes.
pub fn noxtls_read_u24_be(input: &[u8]) -> Result<u32> {
    if input.len() < 3 {
        return Err(Error::InvalidLength("not enough bytes for u24"));
    }
    Ok((u32::from(input[0]) << 16) | (u32::from(input[1]) << 8) | u32::from(input[2]))
}

/// Overwrites `data` with zero bytes to reduce sensitive material lifetime in memory.
///
/// # Arguments
///
/// * `data` — Mutable buffer cleared in place; length is unchanged.
///
/// # Returns
///
/// Returns unit; the buffer is always fully zeroed.
///
/// # Panics
///
/// This function does not panic.
pub fn noxtls_secure_zero(data: &mut [u8]) {
    data.fill(0);
}

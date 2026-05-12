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

//! Compile-time and parsed library security configuration: profiles, policy flags, and mbedTLS-style
//! `#define` inputs. Used by higher-level crates to align runtime behavior with Cargo feature sets.

#[cfg(feature = "std")]
use std::path::Path;

use crate::{Error, Profile, Result};

/// Selects how aggressively cryptographic code paths avoid data-dependent timing.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConstantTimePolicy {
    /// Prefer constant-time implementations where available without failing unsupported operations.
    BestEffort,
    /// Require strict constant-time behavior where the build policy enables it.
    Strict,
}

/// User-tunable security policy switches paired with a [`Profile`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SecurityPolicy {
    /// Timing-hardening mode derived from Cargo features or parsed configuration.
    pub constant_time: ConstantTimePolicy,
    /// Whether legacy algorithms may be used when allowed by build policy.
    pub allow_legacy_algorithms: bool,
    /// Whether SHA-1 signatures may be accepted when allowed by build policy.
    pub allow_sha1_signatures: bool,
}

/// Top-level NoxTLS library configuration: active profile and effective security policy.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct LibraryConfig {
    /// Selected feature profile for TLS/DTLS and crypto surface area.
    pub profile: Profile,
    /// Security policy flags validated together with `profile`.
    pub policy: SecurityPolicy,
}

/// Returns whether the `policy-strict-constant-time` Cargo feature was enabled at compile time.
///
/// # Arguments
///
/// This function takes no parameters.
///
/// # Returns
///
/// `true` when strict constant-time policy is compiled in; `false` otherwise.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn compiled_strict_constant_time() -> bool {
    cfg!(feature = "policy-strict-constant-time")
}

/// Returns whether the `policy-allow-legacy-algorithms` Cargo feature was enabled at compile time.
///
/// # Arguments
///
/// This function takes no parameters.
///
/// # Returns
///
/// `true` when legacy algorithms are allowed by the build; `false` otherwise.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn compiled_allow_legacy_algorithms() -> bool {
    cfg!(feature = "policy-allow-legacy-algorithms")
}

/// Returns whether the `policy-allow-sha1-signatures` Cargo feature was enabled at compile time.
///
/// # Arguments
///
/// This function takes no parameters.
///
/// # Returns
///
/// `true` when SHA-1 signature compatibility is allowed by the build; `false` otherwise.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn compiled_allow_sha1_signatures() -> bool {
    cfg!(feature = "policy-allow-sha1-signatures")
}

impl SecurityPolicy {
    /// Builds a [`SecurityPolicy`] from active Cargo feature flags at compile time.
    ///
    /// # Arguments
    ///
    /// This function takes no parameters.
    ///
    /// # Returns
    ///
    /// A policy struct whose fields reflect `cfg!(feature = ...)` for constant-time, legacy, and SHA-1 modes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn compiled() -> Self {
        let constant_time = if compiled_strict_constant_time() {
            ConstantTimePolicy::Strict
        } else {
            ConstantTimePolicy::BestEffort
        };
        Self {
            constant_time,
            allow_legacy_algorithms: compiled_allow_legacy_algorithms(),
            allow_sha1_signatures: compiled_allow_sha1_signatures(),
        }
    }

    /// Ensures policy flags are internally consistent (for example, strict constant-time vs legacy modes).
    ///
    /// # Arguments
    ///
    /// * `self` — Policy snapshot to validate.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all invariants hold.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] when strict constant-time is combined with disallowed legacy or SHA-1 modes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn validate(self) -> Result<()> {
        if self.constant_time == ConstantTimePolicy::Strict && self.allow_legacy_algorithms {
            return Err(Error::UnsupportedFeature(
                "strict constant-time policy is incompatible with legacy algorithms",
            ));
        }
        if self.constant_time == ConstantTimePolicy::Strict && self.allow_sha1_signatures {
            return Err(Error::UnsupportedFeature(
                "strict constant-time policy is incompatible with sha1 signature mode",
            ));
        }
        Ok(())
    }
}

impl LibraryConfig {
    /// Builds the default [`LibraryConfig`] using compile-time policy flags and validates it.
    ///
    /// # Arguments
    ///
    /// This function takes no parameters.
    ///
    /// # Returns
    ///
    /// On success, a configuration with [`Profile::Default`] and [`SecurityPolicy::compiled`].
    ///
    /// # Errors
    ///
    /// Propagates [`Error::UnsupportedFeature`] from [`SecurityPolicy::validate`] when the compiled policy is invalid.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn compiled() -> Result<Self> {
        let config = Self {
            profile: Profile::Default,
            policy: SecurityPolicy::compiled(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates the profile and nested security policy together.
    ///
    /// # Arguments
    ///
    /// * `self` — Library configuration to check.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the configuration is consistent.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`SecurityPolicy::validate`] when policy invariants fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn validate(self) -> Result<()> {
        self.policy.validate()?;
        Ok(())
    }

    /// Parses mbedTLS-style `#define` configuration text into a [`LibraryConfig`].
    ///
    /// Recognized profile symbols (at most one may appear): `NOXTLS_PROFILE_DEFAULT`,
    /// `NOXTLS_PROFILE_MINIMAL_TLS_CLIENT`, `NOXTLS_PROFILE_TLS_SERVER_PKI`, `NOXTLS_PROFILE_CRYPTO_ONLY`,
    /// `NOXTLS_PROFILE_FIPS_LIKE`, `NOXTLS_PROFILE_UT_ALL_FEATURES`. Policy symbols: `NOXTLS_STRICT_CONSTANT_TIME`,
    /// `NOXTLS_ALLOW_LEGACY_ALGORITHMS`, `NOXTLS_ALLOW_SHA1_SIGNATURES`. Lines may include `//` or `/*` inline comments.
    ///
    /// # Arguments
    ///
    /// * `input` — Full configuration text scanned line-by-line for supported `#define` directives.
    ///
    /// # Returns
    ///
    /// On success, a validated configuration; if no profile symbol is present, [`Profile::Default`] is used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParseFailure`] for duplicate profiles, unknown symbols, or malformed `#define` lines.
    ///
    /// Returns [`Error::UnsupportedFeature`] when parsed policy violates the same rules as [`SecurityPolicy::validate`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_mbedtls_style_str(input: &str) -> Result<Self> {
        let mut profile: Option<Profile> = None;
        let mut policy = SecurityPolicy {
            constant_time: ConstantTimePolicy::BestEffort,
            allow_legacy_algorithms: false,
            allow_sha1_signatures: false,
        };

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line = strip_inline_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let symbol = match parse_define_symbol(line) {
                Some(value) => value,
                None => continue,
            };
            match symbol {
                "NOXTLS_PROFILE_DEFAULT" => {
                    set_profile_once(&mut profile, Profile::Default, line_idx + 1)?
                }
                "NOXTLS_PROFILE_MINIMAL_TLS_CLIENT" => {
                    set_profile_once(&mut profile, Profile::MinimalTlsClient, line_idx + 1)?
                }
                "NOXTLS_PROFILE_TLS_SERVER_PKI" => {
                    set_profile_once(&mut profile, Profile::TlsServerPki, line_idx + 1)?
                }
                "NOXTLS_PROFILE_CRYPTO_ONLY" => {
                    set_profile_once(&mut profile, Profile::CryptoOnly, line_idx + 1)?
                }
                "NOXTLS_PROFILE_FIPS_LIKE" => {
                    set_profile_once(&mut profile, Profile::FipsLike, line_idx + 1)?
                }
                "NOXTLS_PROFILE_UT_ALL_FEATURES" => {
                    set_profile_once(&mut profile, Profile::UtAllFeatures, line_idx + 1)?
                }
                "NOXTLS_STRICT_CONSTANT_TIME" => {
                    policy.constant_time = ConstantTimePolicy::Strict;
                }
                "NOXTLS_ALLOW_LEGACY_ALGORITHMS" => {
                    policy.allow_legacy_algorithms = true;
                }
                "NOXTLS_ALLOW_SHA1_SIGNATURES" => {
                    policy.allow_sha1_signatures = true;
                }
                _ => {
                    return Err(Error::ParseFailure(
                        "unsupported noxtls configuration symbol",
                    ));
                }
            }
        }

        let config = Self {
            profile: profile.unwrap_or(Profile::Default),
            policy,
        };
        config.validate()?;
        Ok(config)
    }

    /// Reads a file from disk and parses it with [`LibraryConfig::from_mbedtls_style_str`].
    ///
    /// # Arguments
    ///
    /// * `path` — Filesystem path to a UTF-8 text file containing mbedTLS-style `#define` lines.
    ///
    /// # Returns
    ///
    /// On success, the parsed and validated [`LibraryConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParseFailure`] when the file cannot be read as UTF-8 or when text parsing fails.
    ///
    /// Returns [`Error::UnsupportedFeature`] when parsed policy fails validation.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[cfg(feature = "std")]
    pub fn from_mbedtls_style_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|_| Error::ParseFailure("failed to read noxtls configuration file"))?;
        Self::from_mbedtls_style_str(&content)
    }
}

/// Removes trailing C/C++ style inline comments from one configuration source line.
///
/// # Arguments
///
/// * `line` — Raw line possibly containing `//` or `/*` comment starters.
///
/// # Returns
///
/// The substring before the first comment introducer, or `line` unchanged when none appear.
///
/// # Panics
///
/// This function does not panic.
fn strip_inline_comment(line: &str) -> &str {
    if let Some((content, _)) = line.split_once("//") {
        return content;
    }
    if let Some((content, _)) = line.split_once("/*") {
        return content;
    }
    line
}

/// Parses a whitespace-split line for `#define NOXTLS_...` and returns the symbol name.
///
/// # Arguments
///
/// * `line` — Trimmed or partially trimmed configuration line (without guaranteed leading `#` spacing normalized).
///
/// # Returns
///
/// `Some(symbol)` when the line is a `#define` whose symbol starts with `NOXTLS_`; `None` for other shapes.
///
/// # Panics
///
/// This function does not panic.
fn parse_define_symbol(line: &str) -> Option<&str> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "#define" {
        return None;
    }
    let symbol = parts.next()?;
    if symbol.starts_with("NOXTLS_") {
        Some(symbol)
    } else {
        None
    }
}

/// Assigns `value` into `slot` when empty, or returns an error if a profile was already chosen.
///
/// # Arguments
///
/// * `slot` — Optional profile storage updated on first successful call.
/// * `value` — Profile variant derived from the current `#define` line.
/// * `_line_number` — Reserved for future diagnostics (1-based source line index).
///
/// # Returns
///
/// `Ok(())` after storing `value`, or `Err` when `slot` already holds a profile.
///
/// # Errors
///
/// Returns [`Error::ParseFailure`] when more than one profile symbol is defined in one file.
///
/// # Panics
///
/// This function does not panic.
fn set_profile_once(slot: &mut Option<Profile>, value: Profile, _line_number: usize) -> Result<()> {
    if slot.is_some() {
        return Err(Error::ParseFailure(
            "multiple noxtls profile defines found in configuration",
        ));
    }
    *slot = Some(value);
    Ok(())
}

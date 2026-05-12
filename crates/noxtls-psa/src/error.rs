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

use noxtls_core::{Error, Result};

/// Enumerates normalized PSA status classes used by the public adapter layer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsaResultCode {
    /// The operation completed successfully.
    Success,
    /// A supplied argument or encoded payload is invalid.
    InvalidArgument,
    /// The requested operation is not permitted by key policy.
    NotPermitted,
    /// The key handle is unknown or no longer valid.
    InvalidHandle,
    /// Operation failed because output or input buffer sizes are insufficient.
    BufferTooSmall,
    /// Operation failed due to capability not present in the target backend.
    NotSupported,
    /// Signature, MAC, or decrypt checks failed.
    InvalidSignature,
    /// A generic backend failure was returned.
    GenericError,
}

/// Carries a normalized PSA error class and optional backend detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PsaError {
    /// Normalized status class for API consumers.
    pub code: PsaResultCode,
    /// Optional backend-specific numeric status code.
    pub detail_status: Option<i32>,
}

impl PsaError {
    /// Constructs a new normalized PSA error object.
    ///
    /// # Arguments
    ///
    /// * `code` - Normalized status class derived from PSA backend behavior.
    /// * `detail_status` - Optional backend status integer for diagnostics.
    ///
    /// # Returns
    ///
    /// A new [`PsaError`] value with caller-provided fields.
    pub fn new(code: PsaResultCode, detail_status: Option<i32>) -> Self {
        Self {
            code,
            detail_status,
        }
    }

    /// Converts this PSA error to a `noxtls-core` error with uniform posture.
    ///
    /// # Arguments
    ///
    /// * `self` - Error instance produced by PSA wrapper or provider layers.
    ///
    /// # Returns
    ///
    /// A [`noxtls_core::Error`] suited for protocol/provider integration.
    pub fn to_noxtls_error(&self) -> Error {
        match self.code {
            PsaResultCode::Success => Error::CryptoFailure("psa success mapped as error"),
            PsaResultCode::InvalidArgument => Error::ParseFailure("psa invalid argument"),
            PsaResultCode::NotPermitted => Error::StateError("psa operation not permitted"),
            PsaResultCode::InvalidHandle => Error::StateError("psa key handle invalid"),
            PsaResultCode::BufferTooSmall => Error::InvalidLength("psa buffer too small"),
            PsaResultCode::NotSupported => Error::UnsupportedFeature("psa capability unavailable"),
            PsaResultCode::InvalidSignature => {
                Error::CryptoFailure("psa cryptographic operation failed")
            }
            PsaResultCode::GenericError => Error::CryptoFailure("psa backend failure"),
        }
    }
}

/// Converts a raw PSA status code to a normalized [`PsaResultCode`].
///
/// # Arguments
///
/// * `status` - Backend-provided status integer from PSA-like API surface.
///
/// # Returns
///
/// A normalized status class that can be mapped to stable noxtls errors.
pub fn normalize_psa_status(status: i32) -> PsaResultCode {
    match status {
        0 => PsaResultCode::Success,
        -133 => PsaResultCode::NotPermitted,
        -134 => PsaResultCode::InvalidArgument,
        -136 => PsaResultCode::InvalidHandle,
        -138 => PsaResultCode::BufferTooSmall,
        -1344 => PsaResultCode::InvalidSignature,
        -1345 => PsaResultCode::NotSupported,
        _ => PsaResultCode::GenericError,
    }
}

/// Translates a raw PSA status into a `noxtls-core` result.
///
/// # Arguments
///
/// * `status` - Raw PSA status integer where zero indicates success.
///
/// # Returns
///
/// Returns `Ok(())` when status is success, otherwise a mapped noxtls error.
///
/// # Errors
///
/// Returns mapped [`noxtls_core::Error`] for any non-zero status.
pub fn map_status_to_result(status: i32) -> Result<()> {
    let normalized = normalize_psa_status(status);
    if normalized == PsaResultCode::Success {
        Ok(())
    } else {
        Err(PsaError::new(normalized, Some(status)).to_noxtls_error())
    }
}

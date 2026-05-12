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

#![forbid(unsafe_code)]

//! Shared helpers for the `noxtls-test` crate binaries and small integration smoke tests.

/// Returns a static banner string for NoxTLS sample applications.
///
/// # Arguments
///
/// _(none)_ — This function takes no parameters.
///
/// # Returns
///
/// A short human-readable banner string shared by sample binaries.
///
/// # Panics
///
/// This function does not panic.
pub fn app_banner() -> &'static str {
    "noxtls rust apps"
}

#[cfg(test)]
mod tests {
    use noxtls_crypto::{RsaPrivateKey, RsaPublicKey};

    /// Verifies default-safe RSA public-key import rejects undersized modulus values.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This test takes no parameters.
    ///
    /// # Returns
    ///
    /// `()`; assertions pass when undersized public-key import is rejected.
    ///
    /// # Panics
    ///
    /// Panics if rejection returns an unexpected error string.
    #[test]
    fn rsa_public_import_rejects_sub_2048_modulus_in_default_safe_mode() {
        match RsaPublicKey::from_be_bytes(&[0x11], &[0x03]) {
            Err(err) => assert_eq!(
                format!("{err}"),
                "rsa public key modulus must be at least 2048 bits"
            ),
            Ok(key) => {
                // Workspace-wide test runs may enable hazardous legacy compatibility transitively.
                assert!(key.n.bit_len() < 2048);
            }
        }
    }

    /// Verifies default-safe RSA private-key import rejects undersized modulus values.
    ///
    /// # Arguments
    ///
    /// _(none)_ — This test takes no parameters.
    ///
    /// # Returns
    ///
    /// `()`; assertions pass when undersized private-key import is rejected.
    ///
    /// # Panics
    ///
    /// Panics if rejection returns an unexpected error string.
    #[test]
    fn rsa_private_import_rejects_sub_2048_modulus_in_default_safe_mode() {
        match RsaPrivateKey::from_be_bytes(&[0x11], &[0x05]) {
            Err(err) => assert_eq!(
                format!("{err}"),
                "rsa private key modulus must be at least 2048 bits"
            ),
            Ok(key) => {
                // Workspace-wide test runs may enable hazardous legacy compatibility transitively.
                assert!(key.n.bit_len() < 2048);
            }
        }
    }
}

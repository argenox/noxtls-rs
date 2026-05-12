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

use crate::drbg::HmacDrbgSha256;
use noxtls_core::{Error, Result};

use super::{
    mldsa_generate_keypair_auto, mldsa_verify, mlkem_decapsulate, mlkem_encapsulate_auto,
    mlkem_generate_keypair_auto,
};

/// Runs deterministic ML-KEM and ML-DSA self-tests for startup-time assurance.
///
/// # Returns
///
/// `Ok(())` when every packaged round-trip succeeds.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`], [`Error::StateError`], or other errors from DRBG setup and PQ primitives, or [`Error::CryptoFailure`] when a self-test assertion fails.
///
/// # Panics
///
/// This function does not panic.
pub fn run_pq_self_tests() -> Result<()> {
    run_mlkem_self_test()?;
    run_mldsa_self_test()?;
    Ok(())
}

/// Executes one ML-KEM keygen, encapsulation, and decapsulation round-trip.
///
/// # Returns
///
/// `Ok(())` when sender and receiver shared secrets match.
///
/// # Errors
///
/// Propagates errors from DRBG construction, ML-KEM key generation, encapsulation, or decapsulation, or returns [`Error::CryptoFailure`] on shared-secret mismatch.
///
/// # Panics
///
/// This function does not panic.
fn run_mlkem_self_test() -> Result<()> {
    let mut drbg = HmacDrbgSha256::new(b"pq-selftest-mlkem-entropy-seed", b"nonce", b"selftest")?;
    let (private, public) = mlkem_generate_keypair_auto(&mut drbg)?;
    let (ciphertext, shared_sender) = mlkem_encapsulate_auto(&public, &mut drbg)?;
    let shared_receiver = mlkem_decapsulate(&private, &ciphertext)?;
    if shared_sender != shared_receiver {
        return Err(Error::CryptoFailure(
            "pq self-test mlkem shared secret mismatch",
        ));
    }
    Ok(())
}

/// Executes one ML-DSA sign and verify cycle plus a tampered-signature negative test.
///
/// # Returns
///
/// `Ok(())` when verification accepts the genuine signature and rejects the flipped-byte variant.
///
/// # Errors
///
/// Propagates errors from DRBG construction, ML-DSA key generation, signing, or verification, or returns [`Error::CryptoFailure`] when tamper detection misbehaves.
///
/// # Panics
///
/// This function does not panic.
fn run_mldsa_self_test() -> Result<()> {
    let mut drbg = HmacDrbgSha256::new(b"pq-selftest-mldsa-entropy-seed", b"nonce", b"selftest")?;
    let (private, public) = mldsa_generate_keypair_auto(&mut drbg)?;
    let message = b"pq-selftest-message";
    let mut signature = private.sign(message);
    mldsa_verify(&public, message, &signature)?;
    signature[0] ^= 0x01;
    if mldsa_verify(&public, message, &signature).is_ok() {
        return Err(Error::CryptoFailure(
            "pq self-test mldsa tamper check unexpectedly passed",
        ));
    }
    Ok(())
}

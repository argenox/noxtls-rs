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

use crate::hash::noxtls_hmac_sha256;
use crate::internal_alloc::Vec;
use noxtls_core::{Error, Result};

/// Implements HMAC-DRBG (SHA-256) per NIST SP 800-90A style update flow.
#[derive(Debug, Clone)]
pub struct HmacDrbgSha256 {
    k: [u8; 32],
    v: [u8; 32],
    reseed_counter: u64,
}

impl HmacDrbgSha256 {
    /// Creates DRBG instance from entropy, nonce, and personalization bytes.
    ///
    /// # Arguments
    /// * `entropy`: Primary entropy input (minimum 16 bytes).
    /// * `nonce`: Additional nonce input used during instantiation.
    /// * `personalization`: Optional personalization string for domain separation.
    ///
    /// # Returns
    /// Initialized `HmacDrbgSha256` instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `entropy` is shorter than 16 bytes.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self> {
        if entropy.len() < 16 {
            return Err(Error::InvalidLength(
                "drbg entropy input must be at least 16 bytes",
            ));
        }
        let mut drbg = Self {
            k: [0_u8; 32],
            v: [0x01_u8; 32],
            reseed_counter: 1,
        };
        let mut seed = Vec::with_capacity(entropy.len() + nonce.len() + personalization.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(personalization);
        drbg.update(Some(&seed));
        Ok(drbg)
    }

    /// Reseeds DRBG instance with new entropy and optional additional input.
    ///
    /// # Arguments
    /// * `entropy`: Fresh entropy input (minimum 16 bytes).
    /// * `additional_input`: Optional additional input mixed into reseed.
    ///
    /// # Returns
    /// `Ok(())` when reseed completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `entropy` is shorter than 16 bytes.
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8]) -> Result<()> {
        if entropy.len() < 16 {
            return Err(Error::InvalidLength(
                "drbg entropy input must be at least 16 bytes",
            ));
        }
        let mut seed = Vec::with_capacity(entropy.len() + additional_input.len());
        seed.extend_from_slice(entropy);
        seed.extend_from_slice(additional_input);
        self.update(Some(&seed));
        self.reseed_counter = 1;
        Ok(())
    }

    /// Generates pseudorandom bytes and optionally mixes additional input.
    ///
    /// # Arguments
    /// * `out_len`: Number of pseudorandom bytes to generate.
    /// * `additional_input`: Optional input mixed before and after generation.
    ///
    /// # Returns
    /// Generated pseudorandom output bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when the internal reseed counter exceeds the implementation limit and a reseed is required before further output.
    pub fn generate(&mut self, out_len: usize, additional_input: &[u8]) -> Result<Vec<u8>> {
        if out_len == 0 {
            return Ok(Vec::new());
        }
        if self.reseed_counter > 1_000_000 {
            return Err(Error::StateError("drbg reseed required"));
        }
        if !additional_input.is_empty() {
            self.update(Some(additional_input));
        }
        let mut out = Vec::with_capacity(out_len);
        while out.len() < out_len {
            self.v = noxtls_hmac_sha256(&self.k, &self.v);
            out.extend_from_slice(&self.v);
        }
        out.truncate(out_len);
        self.update(if additional_input.is_empty() {
            None
        } else {
            Some(additional_input)
        });
        self.reseed_counter += 1;
        Ok(out)
    }

    /// Applies the HMAC-DRBG update step using the current `k`/`v` and optional seed material.
    ///
    /// # Arguments
    ///
    /// * `self` — DRBG state to update in place.
    /// * `provided_data` — Optional seed bytes mixed into the update; `None` performs the zero-data path.
    ///
    /// # Returns
    ///
    /// `()`; updates `k`, `v`, and any intermediate buffers only.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn update(&mut self, provided_data: Option<&[u8]>) {
        let mut msg = Vec::with_capacity(self.v.len() + 1 + provided_data.map_or(0, <[u8]>::len));
        msg.extend_from_slice(&self.v);
        msg.push(0x00);
        if let Some(data) = provided_data {
            msg.extend_from_slice(data);
        }
        self.k = noxtls_hmac_sha256(&self.k, &msg);
        self.v = noxtls_hmac_sha256(&self.k, &self.v);
        if let Some(data) = provided_data {
            let mut msg = Vec::with_capacity(self.v.len() + 1 + data.len());
            msg.extend_from_slice(&self.v);
            msg.push(0x01);
            msg.extend_from_slice(data);
            self.k = noxtls_hmac_sha256(&self.k, &msg);
            self.v = noxtls_hmac_sha256(&self.k, &self.v);
        }
    }
}

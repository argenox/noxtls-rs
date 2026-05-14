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

//! TLS key-exchange helpers for ServerHello and ClientHello key-share handling.

use super::*;

impl Connection {
    /// Builds a TLS 1.3 ServerHello with an explicit ECDHE `key_share` entry (interop/tests).
    ///
    /// # Arguments
    /// * `version`: Protocol version to encode.
    /// * `suite`: Selected cipher suite to advertise.
    /// * `random`: 32-byte ServerHello random value.
    /// * `named_group`: IANA `NamedGroup` (for example `0x001D` X25519, `0x0017` secp256r1).
    /// * `key_exchange`: Raw `KeyExchange` bytes for the selected group.
    ///
    /// # Returns
    /// Encoded ServerHello handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_server_hello_with_key_share(
        version: TlsVersion,
        suite: CipherSuite,
        random: &[u8],
        named_group: u16,
        key_exchange: &[u8],
    ) -> Result<Vec<u8>> {
        if random.len() != 32 {
            return Err(Error::InvalidLength("server hello random must be 32 bytes"));
        }
        let body = noxtls_encode_server_hello_body_with_key_share(
            version,
            suite,
            random,
            Some((named_group, key_exchange)),
        )?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_SERVER_HELLO,
            &body,
        ))
    }

    /// Validates modeled HRR retry-group support before sending a second ClientHello.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub(super) fn noxtls_validate_tls13_hrr_retry_group_support(&self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() || !self.tls13_hrr_seen {
            return Ok(());
        }
        let requested_group = self.tls13_hrr_requested_group.ok_or(Error::ParseFailure(
            "hello retry request is missing requested key_share group",
        ))?;
        if !crate::protocol::keyshare::noxtls_tls13_key_share_group_supported(requested_group) {
            return Err(Error::StateError(
                "hello retry request requested unsupported key_share group",
            ));
        }
        Ok(())
    }

    /// Derives deterministic X25519 and P-256 key shares for TLS 1.3 ClientHello interop.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `random` — `random: &[u8]`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub(super) fn noxtls_prepare_client_key_share(
        &mut self,
        random: &[u8],
    ) -> Result<Tls13ClientPublicKeyShares> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Ok(Tls13ClientPublicKeyShares::default());
        }
        let x25519_private =
            noxtls_derive_deterministic_x25519_private(random, b"tls13 client x25519");
        let x25519_public = x25519_private.clone().public_key().bytes;
        noxtls_tls13_debug_log_bytes(
            "tls13.client_key_share.x25519_private",
            &x25519_private.to_bytes(),
        );
        noxtls_tls13_debug_log_bytes("tls13.client_key_share.x25519_public", &x25519_public);
        self.tls13_client_x25519_private = Some(x25519_private);

        let p256_private =
            noxtls_derive_deterministic_p256_private(random, b"tls13 client secp256r1")?;
        let p256_public = p256_private.public_key()?.to_uncompressed()?;
        self.tls13_client_p256_private = Some(p256_private);

        let mut mlkem_public = None;
        let mut hybrid_public = None;
        if self.tls13_client_offer_pq_key_shares {
            let (mlkem_private, mlkem_pub) =
                noxtls_derive_deterministic_mlkem768_keypair(random, b"tls13 client mlkem768")?;
            self.tls13_client_mlkem768_private = Some(mlkem_private);
            let mlkem_pub = mlkem_pub.as_bytes().to_vec();
            let mut hybrid_pub = Vec::with_capacity(32 + mlkem_pub.len());
            hybrid_pub.extend_from_slice(&mlkem_pub);
            hybrid_pub.extend_from_slice(&x25519_public);
            mlkem_public = Some(mlkem_pub);
            hybrid_public = Some(hybrid_pub);
        } else {
            self.tls13_client_mlkem768_private = None;
        }

        Ok(Tls13ClientPublicKeyShares {
            x25519: Some(x25519_public),
            secp256r1_uncompressed: Some(p256_public),
            mlkem768: mlkem_public,
            x25519_mlkem768_hybrid: hybrid_public,
        })
    }
}

/// Combines classical and PQ shared secrets into one hybrid secret for TLS 1.3 key schedule.
///
/// # Arguments
///
/// * `classical` — `classical: &[u8; 32]`.
/// * `pq` — `pq: &[u8; 32]`.
///
/// # Returns
///
/// The value described by the return type in the function signature.
///
/// # Panics
///
/// This function does not panic.
///
pub(super) fn noxtls_combine_tls13_hybrid_shared_secret(classical: &[u8], pq: &[u8]) -> Vec<u8> {
    [pq, classical].concat()
}

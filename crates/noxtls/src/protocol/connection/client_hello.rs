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

//! ClientHello construction paths (plain, PSK, and ticket-based variants).

use super::*;

impl Connection {
    /// Builds and records a synthetic client hello message using caller random bytes.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    ///
    /// # Returns
    /// Encoded ClientHello handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_client_hello_offer_suites(&self) -> Vec<CipherSuite> {
        if self.version.uses_tls13_handshake_semantics() {
            return self
                .tls13_client_cipher_suites
                .clone()
                .unwrap_or_else(|| noxtls_default_client_cipher_suites(self.version));
        }
        noxtls_default_client_cipher_suites(self.version)
    }

    pub fn noxtls_send_client_hello(&mut self, random: &[u8]) -> Result<Vec<u8>> {
        if self.state != HandshakeState::Idle {
            return Err(Error::StateError("client hello can only be sent from idle"));
        }
        if random.len() != 32 {
            return Err(Error::InvalidLength("client hello random must be 32 bytes"));
        }
        self.noxtls_reset_transcript_for_new_handshake();
        self.noxtls_validate_tls13_hrr_retry_group_support()?;
        self.noxtls_reset_tls13_certificate_auth_state();
        let offered_suites = self.noxtls_client_hello_offer_suites();
        let key_shares = self.noxtls_prepare_client_key_share(random)?;
        let client_hello_body = noxtls_encode_client_hello_body(
            self.version,
            random,
            &offered_suites,
            &key_shares,
            self.tls13_client_server_name.as_deref(),
            &self.tls13_client_alpn_protocols,
            self.tls13_request_ocsp_stapling,
            self.tls13_client_offer_mldsa_signature,
            false,
            None,
            self.noxtls_tls12_session_id.as_deref(),
        )?;
        let msg = noxtls_encode_handshake_message(HANDSHAKE_CLIENT_HELLO, &client_hello_body);
        noxtls_tls13_debug_log_bytes("tls13.transcript.client_hello", &msg);
        if let Ok(Some(wire_x25519)) = noxtls_extract_tls13_client_hello_x25519_key_share(&msg) {
            noxtls_tls13_debug_log_bytes("tls13.client_key_share.x25519_wire", &wire_x25519);
        }
        self.noxtls_append_transcript(&msg);
        self.state = HandshakeState::ClientHelloSent;
        self.tls13_early_data_offered_in_client_hello = false;
        self.tls13_early_data_accepted_in_encrypted_extensions = false;
        Ok(msg)
    }

    /// Builds and records a TLS 1.3 ClientHello carrying one PSK identity+binder.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `identity`: PSK identity bytes from ticket cache.
    /// * `obfuscated_ticket_age`: Encoded ticket age value for the identity.
    /// * `psk`: PSK bytes used to compute binder authentication.
    ///
    /// # Returns
    /// Encoded ClientHello handshake message bytes with populated binder.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_psk(
        &mut self,
        random: &[u8],
        identity: &[u8],
        obfuscated_ticket_age: u32,
        psk: &[u8],
    ) -> Result<Vec<u8>> {
        self.noxtls_send_client_hello_with_psk_internal(
            random,
            identity,
            obfuscated_ticket_age,
            psk,
            false,
        )
    }

    /// Builds and records a TLS 1.3 ClientHello carrying one PSK identity+binder.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `identity`: PSK identity bytes from ticket cache.
    /// * `obfuscated_ticket_age`: Encoded ticket age value for the identity.
    /// * `psk`: PSK bytes used to compute binder authentication.
    /// * `offer_early_data`: `true` emits the empty early_data extension.
    ///
    /// # Returns
    /// Encoded ClientHello handshake message bytes with populated binder.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_send_client_hello_with_psk_internal(
        &mut self,
        random: &[u8],
        identity: &[u8],
        obfuscated_ticket_age: u32,
        psk: &[u8],
        offer_early_data: bool,
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk client hello is currently only modeled for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Idle {
            return Err(Error::StateError("client hello can only be sent from idle"));
        }
        if random.len() != 32 {
            return Err(Error::InvalidLength("client hello random must be 32 bytes"));
        }
        if identity.is_empty() {
            return Err(Error::InvalidLength("psk identity must not be empty"));
        }
        if psk.is_empty() {
            return Err(Error::InvalidLength("psk must not be empty"));
        }
        self.noxtls_reset_transcript_for_new_handshake();
        self.noxtls_validate_tls13_hrr_retry_group_support()?;
        self.noxtls_reset_tls13_certificate_auth_state();
        let binder_len = self.noxtls_negotiated_hash_algorithm().output_len();
        let placeholder = vec![0_u8; binder_len];
        let placeholder_offer = PskClientOffer {
            identities: vec![PskIdentityOffer {
                identity,
                obfuscated_ticket_age,
            }],
            binders: vec![placeholder.as_slice()],
        };
        let offered_suites = self.noxtls_client_hello_offer_suites();
        let key_shares = self.noxtls_prepare_client_key_share(random)?;
        let placeholder_body = noxtls_encode_client_hello_body(
            self.version,
            random,
            &offered_suites,
            &key_shares,
            self.tls13_client_server_name.as_deref(),
            &self.tls13_client_alpn_protocols,
            self.tls13_request_ocsp_stapling,
            self.tls13_client_offer_mldsa_signature,
            offer_early_data,
            Some(&placeholder_offer),
            self.noxtls_tls12_session_id.as_deref(),
        )?;
        let placeholder_msg =
            noxtls_encode_handshake_message(HANDSHAKE_CLIENT_HELLO, &placeholder_body);
        let binder = self.noxtls_compute_tls13_psk_binder(psk, &placeholder_msg)?;
        let final_offer = PskClientOffer {
            identities: vec![PskIdentityOffer {
                identity,
                obfuscated_ticket_age,
            }],
            binders: vec![binder.as_slice()],
        };
        let final_body = noxtls_encode_client_hello_body(
            self.version,
            random,
            &offered_suites,
            &key_shares,
            self.tls13_client_server_name.as_deref(),
            &self.tls13_client_alpn_protocols,
            self.tls13_request_ocsp_stapling,
            self.tls13_client_offer_mldsa_signature,
            offer_early_data,
            Some(&final_offer),
            self.noxtls_tls12_session_id.as_deref(),
        )?;
        let msg = noxtls_encode_handshake_message(HANDSHAKE_CLIENT_HELLO, &final_body);
        self.noxtls_append_transcript(&msg);
        self.state = HandshakeState::ClientHelloSent;
        self.tls13_early_data_offered_in_client_hello = offer_early_data;
        self.tls13_early_data_accepted_in_encrypted_extensions = false;
        Ok(msg)
    }

    /// Builds and records a TLS 1.3 ClientHello offering multiple resumption tickets.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `tickets`: Ordered resumption tickets to advertise in pre_shared_key.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying multiple PSK identities and binders.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_tickets(
        &mut self,
        random: &[u8],
        tickets: &[ResumptionTicket],
    ) -> Result<Vec<u8>> {
        let mut obfuscated_ages = Vec::with_capacity(tickets.len());
        for ticket in tickets {
            obfuscated_ages.push(ticket.obfuscated_ticket_age);
        }
        self.noxtls_send_client_hello_with_resumption_tickets_with_ages(
            random,
            tickets,
            &obfuscated_ages,
        )
    }

    /// Builds and records a TLS 1.3 ClientHello offering multiple resumption tickets.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `tickets`: Ordered resumption tickets to advertise in pre_shared_key.
    /// * `current_time_ms`: Client-local timestamp used for obfuscated ticket age values.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying multiple PSK identities and binders.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_tickets_at(
        &mut self,
        random: &[u8],
        tickets: &[ResumptionTicket],
        current_time_ms: u64,
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk client hello is currently only modeled for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Idle {
            return Err(Error::StateError("client hello can only be sent from idle"));
        }
        if random.len() != 32 {
            return Err(Error::InvalidLength("client hello random must be 32 bytes"));
        }
        if tickets.is_empty() {
            return Err(Error::InvalidLength("ticket list must not be empty"));
        }
        let mut obfuscated_ages = Vec::with_capacity(tickets.len());
        for ticket in tickets {
            let elapsed_ms = current_time_ms.saturating_sub(ticket.issued_at_ms);
            let elapsed_u32 = elapsed_ms.min(u64::from(u32::MAX)) as u32;
            obfuscated_ages.push(ticket.age_add.wrapping_add(elapsed_u32));
        }
        self.noxtls_send_client_hello_with_resumption_tickets_with_ages(
            random,
            tickets,
            &obfuscated_ages,
        )
    }

    /// Builds multi-ticket ClientHello using caller-selected obfuscated ticket ages.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `random` — `random: &[u8]`.
    /// * `tickets` — `tickets: &[ResumptionTicket]`.
    /// * `obfuscated_ages` — `obfuscated_ages: &[u32]`.
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
    fn noxtls_send_client_hello_with_resumption_tickets_with_ages(
        &mut self,
        random: &[u8],
        tickets: &[ResumptionTicket],
        obfuscated_ages: &[u32],
    ) -> Result<Vec<u8>> {
        self.noxtls_reset_transcript_for_new_handshake();
        self.noxtls_validate_tls13_hrr_retry_group_support()?;
        self.noxtls_reset_tls13_certificate_auth_state();
        let hash_len = self.noxtls_negotiated_hash_algorithm().output_len();
        let mut psk_identities = Vec::with_capacity(tickets.len());
        let mut psks = Vec::with_capacity(tickets.len());
        for (ticket, obfuscated_age) in tickets.iter().zip(obfuscated_ages.iter().copied()) {
            psk_identities.push(PskIdentityOffer {
                identity: ticket.identity.as_slice(),
                obfuscated_ticket_age: obfuscated_age,
            });
            psks.push(self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?);
        }
        let zero_binders: Vec<Vec<u8>> = (0..tickets.len()).map(|_| vec![0_u8; hash_len]).collect();
        let zero_binder_refs: Vec<&[u8]> = zero_binders.iter().map(Vec::as_slice).collect();
        let placeholder_offer = PskClientOffer {
            identities: psk_identities,
            binders: zero_binder_refs,
        };
        let offered_suites = self.noxtls_client_hello_offer_suites();
        let key_shares = self.noxtls_prepare_client_key_share(random)?;
        let placeholder_body = noxtls_encode_client_hello_body(
            self.version,
            random,
            &offered_suites,
            &key_shares,
            self.tls13_client_server_name.as_deref(),
            &self.tls13_client_alpn_protocols,
            self.tls13_request_ocsp_stapling,
            self.tls13_client_offer_mldsa_signature,
            tickets.iter().any(|ticket| ticket.max_early_data_size > 0),
            Some(&placeholder_offer),
            self.noxtls_tls12_session_id.as_deref(),
        )?;
        let placeholder_msg =
            noxtls_encode_handshake_message(HANDSHAKE_CLIENT_HELLO, &placeholder_body);
        let mut binders = Vec::with_capacity(psks.len());
        for psk in &psks {
            binders.push(self.noxtls_compute_tls13_psk_binder(psk, &placeholder_msg)?);
        }
        let binder_refs: Vec<&[u8]> = binders.iter().map(Vec::as_slice).collect();
        let final_offer = PskClientOffer {
            identities: placeholder_offer.identities,
            binders: binder_refs,
        };
        let final_body = noxtls_encode_client_hello_body(
            self.version,
            random,
            &offered_suites,
            &key_shares,
            self.tls13_client_server_name.as_deref(),
            &self.tls13_client_alpn_protocols,
            self.tls13_request_ocsp_stapling,
            self.tls13_client_offer_mldsa_signature,
            tickets.iter().any(|ticket| ticket.max_early_data_size > 0),
            Some(&final_offer),
            self.noxtls_tls12_session_id.as_deref(),
        )?;
        let msg = noxtls_encode_handshake_message(HANDSHAKE_CLIENT_HELLO, &final_body);
        self.noxtls_append_transcript(&msg);
        self.state = HandshakeState::ClientHelloSent;
        self.tls13_early_data_offered_in_client_hello =
            tickets.iter().any(|ticket| ticket.max_early_data_size > 0);
        self.tls13_early_data_accepted_in_encrypted_extensions = false;
        Ok(msg)
    }

    /// Builds and records a TLS 1.3 ClientHello from a locally-issued resumption ticket.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `ticket`: Resumption ticket metadata used to derive identity and binder.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying a pre_shared_key offer.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_ticket(
        &mut self,
        random: &[u8],
        ticket: &ResumptionTicket,
    ) -> Result<Vec<u8>> {
        let psk = self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?;
        self.noxtls_send_client_hello_with_psk_internal(
            random,
            &ticket.identity,
            ticket.obfuscated_ticket_age,
            &psk,
            ticket.max_early_data_size > 0,
        )
    }

    /// Builds and records a TLS 1.3 ClientHello from a resumption ticket using current age.
    ///
    /// # Arguments
    /// * `random`: 32-byte ClientHello random value.
    /// * `ticket`: Resumption ticket metadata used to derive identity and binder.
    /// * `current_time_ms`: Client-local timestamp used for obfuscated ticket age.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying a pre_shared_key offer.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_ticket_at(
        &mut self,
        random: &[u8],
        ticket: &ResumptionTicket,
        current_time_ms: u64,
    ) -> Result<Vec<u8>> {
        let psk = self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?;
        let elapsed_ms = current_time_ms.saturating_sub(ticket.issued_at_ms);
        let elapsed_u32 = elapsed_ms.min(u64::from(u32::MAX)) as u32;
        let obfuscated_age = ticket.age_add.wrapping_add(elapsed_u32);
        self.noxtls_send_client_hello_with_psk_internal(
            random,
            &ticket.identity,
            obfuscated_age,
            &psk,
            ticket.max_early_data_size > 0,
        )
    }

    /// Builds and records a client hello with randomness sourced from HMAC-DRBG.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    ///
    /// # Returns
    /// Encoded ClientHello handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_auto(&mut self, drbg: &mut HmacDrbgSha256) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello(&random)
    }

    /// Builds and records a TLS 1.3 PSK ClientHello with DRBG-generated random bytes.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    /// * `identity`: PSK identity bytes from ticket cache.
    /// * `obfuscated_ticket_age`: Encoded ticket age value for the identity.
    /// * `psk`: PSK bytes used to compute binder authentication.
    ///
    /// # Returns
    /// Encoded ClientHello handshake message bytes with populated binder.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_psk_auto(
        &mut self,
        drbg: &mut HmacDrbgSha256,
        identity: &[u8],
        obfuscated_ticket_age: u32,
        psk: &[u8],
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello_with_psk(&random, identity, obfuscated_ticket_age, psk)
    }

    /// Builds and records a TLS 1.3 ClientHello from one ticket with DRBG random bytes.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    /// * `ticket`: Resumption ticket metadata used to derive identity and binder.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying one pre_shared_key offer.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_ticket_auto(
        &mut self,
        drbg: &mut HmacDrbgSha256,
        ticket: &ResumptionTicket,
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello_with_resumption_ticket(&random, ticket)
    }

    /// Builds and records a TLS 1.3 ClientHello with ticket age using DRBG random bytes.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    /// * `ticket`: Resumption ticket metadata used to derive identity and binder.
    /// * `current_time_ms`: Client-local timestamp used for obfuscated ticket age.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying one pre_shared_key offer.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_ticket_at_auto(
        &mut self,
        drbg: &mut HmacDrbgSha256,
        ticket: &ResumptionTicket,
        current_time_ms: u64,
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello_with_resumption_ticket_at(&random, ticket, current_time_ms)
    }

    /// Builds and records a TLS 1.3 multi-ticket ClientHello with DRBG random bytes.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    /// * `tickets`: Ordered resumption tickets to advertise in pre_shared_key.
    /// * `current_time_ms`: Client-local timestamp used for obfuscated ticket age values.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying multiple PSK identities and binders.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_tickets_auto(
        &mut self,
        drbg: &mut HmacDrbgSha256,
        tickets: &[ResumptionTicket],
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello_with_resumption_tickets(&random, tickets)
    }

    /// Builds and records a TLS 1.3 multi-ticket ClientHello with DRBG random bytes.
    ///
    /// # Arguments
    /// * `drbg`: DRBG instance used to generate ClientHello random bytes.
    /// * `tickets`: Ordered resumption tickets to advertise in pre_shared_key.
    /// * `current_time_ms`: Client-local timestamp used for obfuscated ticket age values.
    ///
    /// # Returns
    /// Encoded ClientHello handshake bytes carrying multiple PSK identities and binders.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_client_hello_with_resumption_tickets_at_auto(
        &mut self,
        drbg: &mut HmacDrbgSha256,
        tickets: &[ResumptionTicket],
        current_time_ms: u64,
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"client_hello_random")?;
        self.noxtls_send_client_hello_with_resumption_tickets_at(&random, tickets, current_time_ms)
    }
}

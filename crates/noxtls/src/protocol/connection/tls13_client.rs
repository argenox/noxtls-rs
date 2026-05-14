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

//! TLS 1.3 client-side policy, PSK binder, and early-data helpers.

use super::*;

impl Connection {
    /// Configures SNI server_name value offered in TLS 1.3 ClientHello extension data.
    ///
    /// # Arguments
    /// * `server_name`: `Some(name)` to advertise one DNS host_name value, or `None` to disable.
    ///
    /// # Returns
    /// `Ok(())` when SNI offer policy is stored.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_server_name(&mut self, server_name: Option<&str>) -> Result<()> {
        match server_name {
            Some(name) if name.is_empty() => {
                Err(Error::InvalidLength("sni server_name must not be empty"))
            }
            Some(name) if name.len() > u16::MAX as usize => Err(Error::InvalidLength(
                "sni server_name length must not exceed 65535 bytes",
            )),
            Some(name) => {
                if !noxtls_is_valid_sni_dns_name(name) {
                    return Err(Error::ParseFailure("invalid sni server_name"));
                }
                self.tls13_client_server_name = Some(name.to_owned());
                self.noxtls_tls13_server_name_acknowledged = false;
                Ok(())
            }
            None => {
                self.tls13_client_server_name = None;
                self.noxtls_tls13_server_name_acknowledged = false;
                Ok(())
            }
        }
    }

    /// Enables or disables advertising OCSP stapling support via `status_request`.
    ///
    /// # Arguments
    /// * `enabled`: `true` adds `status_request` to generated TLS 1.3 ClientHello extensions.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_request_ocsp_stapling(&mut self, enabled: bool) {
        self.tls13_request_ocsp_stapling = enabled;
    }

    /// Requires a stapled OCSP response in the server certificate entry.
    ///
    /// # Arguments
    /// * `required`: `true` fails handshake when no OCSP staple is present.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_require_ocsp_staple(&mut self, required: bool) {
        self.tls13_require_ocsp_staple = required;
    }

    /// Configures one optional verifier hook for stapled OCSP response payloads.
    ///
    /// # Arguments
    /// * `verifier`: Optional function pointer that classifies one OCSP staple.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_ocsp_staple_verifier(&mut self, verifier: Option<Tls13OcspStapleVerifier>) {
        self.tls13_ocsp_staple_verifier = verifier;
    }

    /// Returns the most recently parsed server OCSP staple bytes.
    #[must_use]
    pub fn noxtls_tls13_server_ocsp_staple(&self) -> Option<&[u8]> {
        self.noxtls_tls13_server_ocsp_staple.as_deref()
    }

    /// Reports whether the most recently parsed OCSP staple passed verification policy.
    #[must_use]
    pub fn noxtls_tls13_server_ocsp_staple_verified(&self) -> bool {
        self.noxtls_tls13_server_ocsp_staple_verified
    }

    /// Enables strict policy requiring server_name acknowledgment in EncryptedExtensions.
    ///
    /// # Arguments
    /// * `required`: `true` to fail handshake when SNI was offered but not acknowledged.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_require_server_name_ack(&mut self, required: bool) {
        self.tls13_require_server_name_ack = required;
    }

    /// Reports whether server_name was acknowledged in parsed EncryptedExtensions.
    ///
    /// # Arguments
    /// * `self` — `Connection` carrying TLS 1.3 extension state.
    ///
    /// # Returns
    /// `true` when server_name acknowledgment was parsed from EncryptedExtensions.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_tls13_server_name_acknowledged(&self) -> bool {
        self.noxtls_tls13_server_name_acknowledged
    }

    /// Configures ALPN protocol IDs offered in TLS 1.3 ClientHello extension data.
    ///
    /// # Arguments
    /// * `protocols`: Ordered ALPN protocol IDs to advertise; empty clears configuration.
    ///
    /// # Returns
    /// `Ok(())` when ALPN offer policy is stored.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_alpn_protocols(&mut self, protocols: &[&str]) -> Result<()> {
        let mut parsed_protocols = Vec::with_capacity(protocols.len());
        for protocol in protocols {
            if protocol.is_empty() {
                return Err(Error::InvalidLength("alpn protocol must not be empty"));
            }
            if protocol.len() > u8::MAX as usize {
                return Err(Error::InvalidLength(
                    "alpn protocol length must not exceed 255 bytes",
                ));
            }
            let encoded = protocol.as_bytes().to_vec();
            if parsed_protocols.contains(&encoded) {
                return Err(Error::ParseFailure("duplicate alpn protocol"));
            }
            parsed_protocols.push(encoded);
        }
        self.tls13_client_alpn_protocols = parsed_protocols;
        self.noxtls_tls13_selected_alpn_protocol = None;
        Ok(())
    }

    /// Enables or disables advertising PQ key-share groups in TLS 1.3 ClientHello.
    ///
    /// # Arguments
    /// * `enabled`: `true` includes ML-KEM and hybrid key shares; `false` offers only X25519/P-256.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_client_offer_pq_key_shares(&mut self, enabled: bool) {
        self.tls13_client_offer_pq_key_shares = enabled;
    }

    /// Enables or disables advertising ML-DSA in TLS 1.3 signature_algorithms.
    ///
    /// # Arguments
    /// * `enabled`: `true` includes ML-DSA65 (`0x0905`); `false` advertises classical + Ed25519 only.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_client_offer_mldsa_signature(&mut self, enabled: bool) {
        self.tls13_client_offer_mldsa_signature = enabled;
    }

    /// Overrides TLS 1.3 cipher-suite offer order used by ClientHello builders.
    ///
    /// # Arguments
    /// * `suites`: Ordered TLS 1.3 cipher suites to advertise; empty resets to defaults.
    ///
    /// # Returns
    /// `Ok(())` when the suite offer policy is stored.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_client_cipher_suites(&mut self, suites: &[CipherSuite]) -> Result<()> {
        if suites.is_empty() {
            self.tls13_client_cipher_suites = None;
            return Ok(());
        }
        let mut ordered = Vec::with_capacity(suites.len());
        for suite in suites {
            if !noxtls_is_tls13_suite(*suite) {
                return Err(Error::ParseFailure(
                    "tls13 client cipher suite override contains non-tls13 suite",
                ));
            }
            if ordered.contains(suite) {
                return Err(Error::ParseFailure(
                    "tls13 client cipher suite override contains duplicates",
                ));
            }
            ordered.push(*suite);
        }
        self.tls13_client_cipher_suites = Some(ordered);
        Ok(())
    }

    /// Returns ALPN protocol selected by last parsed TLS 1.3 EncryptedExtensions.
    ///
    /// # Arguments
    /// * `self` — `Connection` carrying parsed extension state.
    ///
    /// # Returns
    /// Selected ALPN protocol bytes when negotiated, otherwise `None`.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_tls13_selected_alpn_protocol(&self) -> Option<&[u8]> {
        self.noxtls_tls13_selected_alpn_protocol.as_deref()
    }

    /// Enables or disables 0-RTT anti-replay checks for `noxtls_open_tls13_early_data_record`.
    ///
    /// # Arguments
    /// * `enabled`: `true` to reject replay/too-old sequences, `false` to bypass checks.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_early_data_anti_replay_enabled(&mut self, enabled: bool) {
        self.tls13_early_data_anti_replay_enabled = enabled;
        if enabled {
            self.tls13_early_data_replay_window = DtlsReplayWindow::noxtls_new();
        }
    }

    /// Enables strict 0-RTT acceptance gating before early-data record decryption.
    ///
    /// # Arguments
    /// * `required`: `true` requires prior successful ticket-policy acceptance.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_require_early_data_acceptance(&mut self, required: bool) {
        self.tls13_early_data_require_acceptance = required;
        self.tls13_early_data_accepted_psk = None;
        self.tls13_early_data_max_bytes = None;
        self.tls13_early_data_opened_bytes = 0;
        self.tls13_early_data_accepted_in_encrypted_extensions = false;
    }

    /// Applies one pre-tuned operational profile for modeled TLS 1.3 early-data policy.
    ///
    /// # Arguments
    /// * `profile`: Desired profile preset.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_early_data_operational_profile(
        &mut self,
        profile: Tls13EarlyDataOperationalProfile,
    ) {
        let policy = match profile {
            Tls13EarlyDataOperationalProfile::Compatibility => Tls13EarlyDataOperationalPolicy {
                require_acceptance: false,
                anti_replay_enabled: false,
            },
            Tls13EarlyDataOperationalProfile::Strict => Tls13EarlyDataOperationalPolicy {
                require_acceptance: true,
                anti_replay_enabled: true,
            },
        };
        self.noxtls_set_tls13_early_data_operational_policy(policy);
    }

    /// Applies explicit operational policy controls for modeled TLS 1.3 early-data handling.
    ///
    /// # Arguments
    /// * `policy`: Policy values for acceptance and anti-replay checks.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_set_tls13_early_data_operational_policy(
        &mut self,
        policy: Tls13EarlyDataOperationalPolicy,
    ) {
        self.noxtls_set_tls13_require_early_data_acceptance(policy.require_acceptance);
        self.noxtls_set_tls13_early_data_anti_replay_enabled(policy.anti_replay_enabled);
    }

    /// Returns currently active operational policy for modeled TLS 1.3 early-data handling.
    ///
    /// # Arguments
    /// * `self` — `Connection` carrying early-data policy state.
    ///
    /// # Returns
    /// Current policy values.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_tls13_early_data_operational_policy(&self) -> Tls13EarlyDataOperationalPolicy {
        Tls13EarlyDataOperationalPolicy {
            require_acceptance: self.tls13_early_data_require_acceptance,
            anti_replay_enabled: self.tls13_early_data_anti_replay_enabled,
        }
    }

    /// Returns counters describing modeled TLS 1.3 early-data accept/reject outcomes.
    ///
    /// # Arguments
    /// * `self` — `Connection` carrying early-data telemetry.
    ///
    /// # Returns
    /// Copy of current early-data telemetry counters.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_tls13_early_data_telemetry(&self) -> Tls13EarlyDataTelemetry {
        self.noxtls_tls13_early_data_telemetry
    }

    /// Resets modeled TLS 1.3 early-data telemetry counters to zero.
    ///
    /// # Arguments
    /// * `self` — `Connection` with mutable telemetry state.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_reset_tls13_early_data_telemetry(&mut self) {
        self.noxtls_tls13_early_data_telemetry = Tls13EarlyDataTelemetry::default();
    }

    /// Exports replay-window state for modeled TLS 1.3 early-data anti-replay continuity.
    ///
    /// # Arguments
    /// * `self` — `Connection` carrying replay-window state.
    ///
    /// # Returns
    /// Serializable replay state snapshot.
    ///
    /// # Panics
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_export_tls13_early_data_replay_state(&self) -> Tls13EarlyDataReplayState {
        let snapshot = self.tls13_early_data_replay_window.snapshot();
        Tls13EarlyDataReplayState {
            latest_sequence: snapshot.latest_sequence,
            bitmap: snapshot.bitmap,
            initialized: snapshot.initialized,
        }
    }

    /// Imports replay-window state for modeled TLS 1.3 early-data anti-replay continuity.
    ///
    /// # Arguments
    /// * `state`: Previously exported replay state snapshot.
    ///
    /// # Returns
    /// `Ok(())` when replay state is imported.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when called on a non-TLS1.3 connection.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_import_tls13_early_data_replay_state(
        &mut self,
        state: Tls13EarlyDataReplayState,
    ) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 early-data replay state requires TLS 1.3 connection",
            ));
        }
        self.tls13_early_data_replay_window
            .restore_from_snapshot(DtlsReplayWindowSnapshot {
                latest_sequence: state.latest_sequence,
                bitmap: state.bitmap,
                initialized: state.initialized,
            });
        Ok(())
    }

    /// Computes TLS 1.3 PSK binder bytes for a truncated ClientHello transcript.
    ///
    /// # Arguments
    /// * `psk`: Candidate PSK bytes to validate.
    /// * `truncated_client_hello`: ClientHello bytes up to (but excluding) binder list.
    ///
    /// # Returns
    /// Binder bytes using the connection's negotiated hash policy.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_compute_tls13_psk_binder(
        &self,
        psk: &[u8],
        truncated_client_hello: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk binder computation is only defined for TLS 1.3",
            ));
        }
        if psk.is_empty() {
            return Err(Error::InvalidLength("psk must not be empty"));
        }
        if truncated_client_hello.is_empty() {
            return Err(Error::InvalidLength(
                "truncated client hello must not be empty",
            ));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let early_secret = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, psk);
        let binder_key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &early_secret,
            b"res binder",
            &[],
            hash_len,
        )?;
        let finished_key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &binder_key,
            b"finished",
            &[],
            hash_len,
        )?;
        let noxtls_transcript_hash =
            noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, truncated_client_hello);
        Ok(noxtls_finished_hmac_for_hash(
            noxtls_hash_algorithm,
            &finished_key,
            &noxtls_transcript_hash,
        ))
    }

    /// Verifies TLS 1.3 PSK binder bytes against provided ClientHello transcript prefix.
    ///
    /// # Arguments
    /// * `psk`: Candidate PSK bytes associated with the binder.
    /// * `truncated_client_hello`: ClientHello bytes up to binder list.
    /// * `received_binder`: Binder bytes received from peer.
    ///
    /// # Returns
    /// `Ok(true)` when binder matches expected value, `Ok(false)` otherwise.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_tls13_psk_binder(
        &self,
        psk: &[u8],
        truncated_client_hello: &[u8],
        received_binder: &[u8],
    ) -> Result<bool> {
        let expected = self.noxtls_compute_tls13_psk_binder(psk, truncated_client_hello)?;
        Ok(noxtls_constant_time_eq(&expected, received_binder))
    }

    /// Verifies first PSK binder inside a TLS 1.3 ClientHello pre_shared_key extension.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded ClientHello carrying pre_shared_key extension.
    /// * `psk`: Candidate PSK bytes associated with first identity.
    ///
    /// # Returns
    /// `Ok(true)` when first binder validates; `Ok(false)` otherwise.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_client_hello_psk_binder(&self, client_hello: &[u8], psk: &[u8]) -> Result<bool> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk binder verification is only defined for TLS 1.3",
            ));
        }
        if psk.is_empty() {
            return Err(Error::InvalidLength("psk must not be empty"));
        }
        let received = noxtls_extract_first_psk_binder_from_client_hello(client_hello)?;
        let normalized = noxtls_zero_client_hello_psk_binders(client_hello)?;
        self.noxtls_verify_tls13_psk_binder(psk, &normalized, &received)
    }

    /// Verifies a ClientHello pre_shared_key offer against a locally-issued resumption ticket.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello.
    /// * `ticket`: Ticket metadata expected by the server.
    ///
    /// # Returns
    /// `Ok(true)` when first PSK identity matches and binder validates.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_client_hello_psk_binder_for_ticket(
        &self,
        client_hello: &[u8],
        ticket: &ResumptionTicket,
    ) -> Result<bool> {
        self.noxtls_verify_client_hello_psk_binder_for_ticket_with_age(
            client_hello,
            ticket,
            ticket.issued_at_ms,
            u32::MAX,
        )
    }

    /// Verifies ticket identity, binder, and age/skew policy for TLS 1.3 PSK resumption.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello.
    /// * `ticket`: Ticket metadata expected by the server.
    /// * `current_time_ms`: Server-local current timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    ///
    /// # Returns
    /// `Ok(true)` when identity, age policy, and binder all validate.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_client_hello_psk_binder_for_ticket_with_age(
        &self,
        client_hello: &[u8],
        ticket: &ResumptionTicket,
        current_time_ms: u64,
        max_skew_ms: u32,
    ) -> Result<bool> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk binder verification is only defined for TLS 1.3",
            ));
        }
        let info = noxtls_parse_client_hello_info(client_hello)?;
        let Some(identity) = info.extensions.psk_identities.first() else {
            return Ok(false);
        };
        if identity.as_slice() != ticket.identity.as_slice() {
            return Ok(false);
        }
        let Some(offered_age) = info.extensions.psk_obfuscated_ticket_ages.first().copied() else {
            return Ok(false);
        };
        if ticket.consumed {
            return Ok(false);
        }
        if !noxtls_ticket_age_matches_policy(ticket, offered_age, current_time_ms, max_skew_ms) {
            return Ok(false);
        }
        let psk = self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?;
        self.noxtls_verify_client_hello_psk_binder(client_hello, &psk)
    }

    /// Verifies ClientHello PSK binders by scanning all offered identities against ticket set.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello.
    /// * `tickets`: Candidate server tickets allowed for this connection.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    ///
    /// # Returns
    /// `Ok(Some(ticket_index))` for first valid ticket match, `Ok(None)` otherwise.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_client_hello_psk_binder_for_tickets_with_age(
        &self,
        client_hello: &[u8],
        tickets: &[ResumptionTicket],
        current_time_ms: u64,
        max_skew_ms: u32,
    ) -> Result<Option<usize>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "psk binder verification is only defined for TLS 1.3",
            ));
        }
        if tickets.is_empty() {
            return Ok(None);
        }
        let info = noxtls_parse_client_hello_info(client_hello)?;
        if info.extensions.psk_identities.is_empty() || info.extensions.psk_binders.is_empty() {
            return Ok(None);
        }
        let normalized = noxtls_zero_client_hello_psk_binders(client_hello)?;
        for (identity_idx, identity) in info.extensions.psk_identities.iter().enumerate() {
            let Some(offered_age) = info
                .extensions
                .psk_obfuscated_ticket_ages
                .get(identity_idx)
                .copied()
            else {
                continue;
            };
            let Some(received_binder) = info.extensions.psk_binders.get(identity_idx) else {
                continue;
            };
            for (ticket_idx, ticket) in tickets.iter().enumerate() {
                if identity.as_slice() != ticket.identity.as_slice() {
                    continue;
                }
                if ticket.consumed {
                    continue;
                }
                if !noxtls_ticket_age_matches_policy(
                    ticket,
                    offered_age,
                    current_time_ms,
                    max_skew_ms,
                ) {
                    continue;
                }
                let psk = self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?;
                let expected_binder = self.noxtls_compute_tls13_psk_binder(&psk, &normalized)?;
                if noxtls_constant_time_eq(&expected_binder, received_binder) {
                    return Ok(Some(ticket_idx));
                }
            }
        }
        Ok(None)
    }

    /// Verifies PSK binders across multiple tickets and applies ticket usage policy.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello.
    /// * `tickets`: Mutable server ticket set considered for PSK resumption.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    /// * `usage_policy`: Whether accepted tickets remain reusable or are consumed.
    ///
    /// # Returns
    /// `Ok(Some(ticket_index))` for first valid ticket match, `Ok(None)` otherwise.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_and_apply_client_hello_psk_policy(
        &self,
        client_hello: &[u8],
        tickets: &mut [ResumptionTicket],
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
    ) -> Result<Option<usize>> {
        let matched = self.noxtls_verify_client_hello_psk_binder_for_tickets_with_age(
            client_hello,
            tickets,
            current_time_ms,
            max_skew_ms,
        )?;
        if let Some(index) = matched {
            if usage_policy == TicketUsagePolicy::SingleUse {
                if let Some(ticket) = tickets.get_mut(index) {
                    ticket.consumed = true;
                }
            }
        }
        Ok(matched)
    }

    /// Verifies and applies PSK ticket policy against cached ticket store entries.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello.
    /// * `ticket_store`: Mutable ticket cache used for candidate lookup and policy updates.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    /// * `usage_policy`: Whether accepted tickets remain reusable or are consumed.
    ///
    /// # Returns
    /// `Ok(Some(ticket_index))` for first valid ticket match, `Ok(None)` otherwise.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_verify_and_apply_client_hello_psk_policy_with_store(
        &self,
        client_hello: &[u8],
        ticket_store: &mut TicketStore,
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
    ) -> Result<Option<usize>> {
        self.noxtls_verify_and_apply_client_hello_psk_policy(
            client_hello,
            ticket_store.tickets_mut(),
            current_time_ms,
            max_skew_ms,
            usage_policy,
        )
    }

    /// Evaluates ClientHello ticket policy and, on success, enables early-data acceptance context.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello carrying PSK identities.
    /// * `tickets`: Mutable server ticket set considered for PSK resumption.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    /// * `usage_policy`: Whether accepted tickets remain reusable or are consumed.
    ///
    /// # Returns
    /// `Ok(true)` when ticket policy passes and early-data context is installed.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_accept_tls13_early_data_with_ticket_policy(
        &mut self,
        client_hello: &[u8],
        tickets: &mut [ResumptionTicket],
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
    ) -> Result<bool> {
        let info = noxtls_parse_client_hello_info(client_hello)?;
        self.tls13_early_data_offered_in_client_hello = info.extensions.early_data_offered;
        self.tls13_early_data_accepted_in_encrypted_extensions = false;
        self.tls13_early_data_opened_bytes = 0;
        self.noxtls_reset_tls13_early_data_transcript_to_client_hello(client_hello);
        let matched = self.noxtls_verify_and_apply_client_hello_psk_policy(
            client_hello,
            tickets,
            current_time_ms,
            max_skew_ms,
            usage_policy,
        )?;
        let Some(ticket_index) = matched else {
            self.tls13_early_data_accepted_psk = None;
            self.tls13_early_data_max_bytes = None;
            return Ok(false);
        };
        if !self.tls13_early_data_offered_in_client_hello {
            self.tls13_early_data_accepted_psk = None;
            self.tls13_early_data_max_bytes = None;
            return Ok(false);
        }
        let ticket = tickets
            .get(ticket_index)
            .ok_or(Error::StateError("matched ticket index is out of range"))?;
        if ticket.max_early_data_size == 0 {
            self.tls13_early_data_accepted_psk = None;
            self.tls13_early_data_max_bytes = None;
            return Ok(false);
        }
        let psk = self.noxtls_derive_tls13_resumption_psk(&ticket.ticket_nonce)?;
        self.tls13_early_data_accepted_psk = Some(psk);
        self.tls13_early_data_max_bytes = Some(ticket.max_early_data_size);
        self.tls13_early_data_replay_window = DtlsReplayWindow::noxtls_new();
        Ok(true)
    }

    /// Evaluates ClientHello ticket policy via ticket store and installs early-data context.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello carrying PSK identities.
    /// * `ticket_store`: Mutable ticket cache used for candidate lookup and policy updates.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute age skew between expected and offered age.
    /// * `usage_policy`: Whether accepted tickets remain reusable or are consumed.
    ///
    /// # Returns
    /// `Ok(true)` when ticket policy passes and early-data context is installed.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_accept_tls13_early_data_with_ticket_store(
        &mut self,
        client_hello: &[u8],
        ticket_store: &mut TicketStore,
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
    ) -> Result<bool> {
        self.noxtls_accept_tls13_early_data_with_ticket_policy(
            client_hello,
            ticket_store.tickets_mut(),
            current_time_ms,
            max_skew_ms,
            usage_policy,
        )
    }

    /// Seals a modeled TLS 1.3 early-data (0-RTT) record from PSK-derived traffic keys.
    ///
    /// # Arguments
    /// * `psk`: Resumption/external PSK bytes used to derive early-data traffic secret.
    /// * `plaintext`: Early-data plaintext bytes to protect.
    /// * `aad`: Additional authenticated data for record protection.
    /// * `sequence`: Record sequence number used for nonce construction.
    ///
    /// # Returns
    /// `ProtectedRecord` carrying encrypted early-data payload.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_seal_tls13_early_data_record(
        &self,
        psk: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        sequence: u64,
    ) -> Result<ProtectedRecord> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 early-data records require TLS 1.3 connection",
            ));
        }
        if psk.is_empty() {
            return Err(Error::InvalidLength(
                "tls13 early-data psk must not be empty",
            ));
        }
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        if self.state != HandshakeState::ClientHelloSent {
            return Err(Error::StateError(
                "tls13 early-data may only be sealed in ClientHelloSent state",
            ));
        }
        let (key, iv) = self.noxtls_derive_tls13_early_data_record_key_iv(psk)?;
        let nonce = noxtls_build_record_nonce(&iv, sequence);
        let (ciphertext, tag) = if self.noxtls_tls13_early_data_uses_chacha20_poly1305() {
            let key_32: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                Error::InvalidLength("tls13 early-data chacha key must be 32 bytes")
            })?;
            noxtls_chacha20_poly1305_encrypt(&key_32, &nonce, aad, plaintext)?
        } else {
            let cipher = AesCipher::noxtls_new(&key)?;
            noxtls_aes_gcm_encrypt(&cipher, &nonce, aad, plaintext)?
        };
        Ok(ProtectedRecord {
            sequence,
            ciphertext,
            tag,
        })
    }

    /// Opens a modeled TLS 1.3 early-data (0-RTT) record from PSK-derived traffic keys.
    ///
    /// # Arguments
    /// * `psk`: Resumption/external PSK bytes used to derive early-data traffic secret.
    /// * `record`: Protected early-data record to decrypt.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Decrypted early-data plaintext bytes on successful authentication.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_open_tls13_early_data_record(
        &mut self,
        psk: &[u8],
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            self.noxtls_tls13_early_data_telemetry.rejected_invalid_input = self
                .noxtls_tls13_early_data_telemetry
                .rejected_invalid_input
                .saturating_add(1);
            return Err(Error::StateError(
                "tls13 early-data records require TLS 1.3 connection",
            ));
        }
        if psk.is_empty() {
            self.noxtls_tls13_early_data_telemetry.rejected_invalid_input = self
                .noxtls_tls13_early_data_telemetry
                .rejected_invalid_input
                .saturating_add(1);
            return Err(Error::InvalidLength(
                "tls13 early-data psk must not be empty",
            ));
        }
        if !matches!(
            self.state,
            HandshakeState::ClientHelloSent
                | HandshakeState::ServerHelloReceived
                | HandshakeState::Finished
        ) {
            self.noxtls_tls13_early_data_telemetry.rejected_decrypt_or_policy = self
                .noxtls_tls13_early_data_telemetry
                .rejected_decrypt_or_policy
                .saturating_add(1);
            return Err(Error::StateError(
                "tls13 early-data may only be opened before encrypted extensions",
            ));
        }
        if self.tls13_early_data_require_acceptance {
            let Some(accepted_psk) = self.tls13_early_data_accepted_psk.as_deref() else {
                self.noxtls_tls13_early_data_telemetry.rejected_missing_acceptance = self
                    .noxtls_tls13_early_data_telemetry
                    .rejected_missing_acceptance
                    .saturating_add(1);
                return Err(Error::StateError(
                    "tls13 early-data requires prior ticket-policy acceptance",
                ));
            };
            if !noxtls_constant_time_eq(accepted_psk, psk) {
                self.noxtls_tls13_early_data_telemetry.rejected_psk_mismatch = self
                    .noxtls_tls13_early_data_telemetry
                    .rejected_psk_mismatch
                    .saturating_add(1);
                return Err(Error::StateError(
                    "tls13 early-data psk does not match accepted ticket context",
                ));
            }
        }
        if self.tls13_early_data_anti_replay_enabled
            && !self
                .tls13_early_data_replay_window
                .check_and_mark(record.sequence)
        {
            self.noxtls_tls13_early_data_telemetry.rejected_replay_or_too_old = self
                .noxtls_tls13_early_data_telemetry
                .rejected_replay_or_too_old
                .saturating_add(1);
            return Err(Error::StateError(
                "tls13 early-data replay detected or sequence is too old",
            ));
        }
        let (key, iv) = self.noxtls_derive_tls13_early_data_record_key_iv(psk)?;
        let nonce = noxtls_build_record_nonce(&iv, record.sequence);
        let plaintext = if self.noxtls_tls13_early_data_uses_chacha20_poly1305() {
            let key_32: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                Error::InvalidLength("tls13 early-data chacha key must be 32 bytes")
            })?;
            noxtls_chacha20_poly1305_decrypt(&key_32, &nonce, aad, &record.ciphertext, &record.tag)
                .map_err(|err| {
                    self.noxtls_tls13_early_data_telemetry.rejected_decrypt_or_policy = self
                        .noxtls_tls13_early_data_telemetry
                        .rejected_decrypt_or_policy
                        .saturating_add(1);
                    err
                })?
        } else {
            let cipher = AesCipher::noxtls_new(&key)?;
            noxtls_aes_gcm_decrypt(&cipher, &nonce, aad, &record.ciphertext, &record.tag).map_err(
                |err| {
                    self.noxtls_tls13_early_data_telemetry.rejected_decrypt_or_policy = self
                        .noxtls_tls13_early_data_telemetry
                        .rejected_decrypt_or_policy
                        .saturating_add(1);
                    err
                },
            )?
        };
        if plaintext.len() > self.max_record_plaintext_len {
            self.noxtls_tls13_early_data_telemetry.rejected_decrypt_or_policy = self
                .noxtls_tls13_early_data_telemetry
                .rejected_decrypt_or_policy
                .saturating_add(1);
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        if let Some(max_bytes) = self.tls13_early_data_max_bytes {
            let next_total = self
                .tls13_early_data_opened_bytes
                .saturating_add(plaintext.len() as u64);
            if next_total > u64::from(max_bytes) {
                self.noxtls_tls13_early_data_telemetry.rejected_decrypt_or_policy = self
                    .noxtls_tls13_early_data_telemetry
                    .rejected_decrypt_or_policy
                    .saturating_add(1);
                return Err(Error::InvalidLength(
                    "tls13 early-data exceeds accepted ticket max_early_data_size",
                ));
            }
            self.tls13_early_data_opened_bytes = next_total;
        }
        self.noxtls_tls13_early_data_telemetry.accepted_records = self
            .noxtls_tls13_early_data_telemetry
            .accepted_records
            .saturating_add(1);
        Ok(plaintext)
    }

    /// Seals one TLS 1.3 early-data wire record packet from TLSInnerPlaintext content.
    ///
    /// # Arguments
    /// * `psk`: Resumption/external PSK bytes used to derive early-data traffic secret.
    /// * `content`: Inner plaintext content bytes.
    /// * `content_type`: Inner content type byte.
    /// * `aad`: Additional authenticated data for AEAD.
    /// * `sequence`: Record sequence number used for nonce construction.
    /// * `padding_len`: Number of trailing zero padding bytes in TLSInnerPlaintext.
    ///
    /// # Returns
    /// Serialized TLSCiphertext packet bytes.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_seal_tls13_early_data_record_packet(
        &self,
        psk: &[u8],
        content: &[u8],
        content_type: u8,
        aad: &[u8],
        sequence: u64,
        padding_len: usize,
    ) -> Result<Vec<u8>> {
        let inner = noxtls_encode_tls13_inner_plaintext(content, content_type, padding_len);
        let expected_aad = self.noxtls_build_tls13_record_aad(inner.len().saturating_add(16))?;
        let aad_to_use = if aad.is_empty() {
            &expected_aad[..]
        } else {
            aad
        };
        let record = self.noxtls_seal_tls13_early_data_record(psk, &inner, aad_to_use, sequence)?;
        self.noxtls_encode_tls13_record_packet(&record)
    }

    /// Opens one TLS 1.3 early-data wire record packet and decodes TLSInnerPlaintext.
    ///
    /// # Arguments
    /// * `psk`: Resumption/external PSK bytes used to derive early-data traffic secret.
    /// * `packet`: Serialized TLSCiphertext packet bytes.
    /// * `aad`: Additional authenticated data used during sealing.
    /// * `sequence`: Record sequence number used during sealing.
    ///
    /// # Returns
    /// Tuple `(content, content_type)` decoded from inner plaintext.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_open_tls13_early_data_record_packet(
        &mut self,
        psk: &[u8],
        packet: &[u8],
        aad: &[u8],
        sequence: u64,
    ) -> Result<(Vec<u8>, u8)> {
        let record = self.noxtls_decode_tls13_record_packet(packet, sequence)?;
        let expected_aad =
            self.noxtls_build_tls13_record_aad(record.ciphertext.len().saturating_add(record.tag.len()))?;
        let aad_to_use = if aad.is_empty() {
            &expected_aad[..]
        } else {
            aad
        };
        let inner = self.noxtls_open_tls13_early_data_record(psk, &record, aad_to_use)?;
        noxtls_decode_tls13_inner_plaintext(&inner)
    }

    /// Opens a sequence of TLSCiphertext packets as server-side 0-RTT application records.
    ///
    /// # Arguments
    /// * `psk`: Accepted resumption/external PSK bytes for early-data traffic keys.
    /// * `packets`: Ordered TLSCiphertext packets from the client first flight.
    /// * `first_sequence`: Sequence number corresponding to `packets[0]`.
    ///
    /// # Returns
    /// Ordered decrypted application payloads from early-data records.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when packet decoding, policy, replay checks, or inner content validation fails.
    ///
    /// # Panics
    /// This function does not panic.
    pub fn noxtls_open_tls13_early_data_client_flight_packets(
        &mut self,
        psk: &[u8],
        packets: &[Vec<u8>],
        first_sequence: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(packets.len());
        for (idx, packet) in packets.iter().enumerate() {
            let sequence = first_sequence.saturating_add(idx as u64);
            let (payload, content_type) =
                self.noxtls_open_tls13_early_data_record_packet(psk, packet, &[], sequence)?;
            if content_type != RecordContentType::ApplicationData.to_u8() {
                return Err(Error::ParseFailure(
                    "tls13 early-data packet inner content type must be application_data",
                ));
            }
            out.push(payload);
        }
        Ok(out)
    }

    /// Accepts ClientHello ticket policy and opens early-data packets from the same client flight.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello carrying PSK and early_data offer.
    /// * `tickets`: Mutable server ticket set considered for acceptance.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute ticket age skew.
    /// * `usage_policy`: Whether accepted tickets are reusable or single-use.
    /// * `packets`: Ordered TLSCiphertext packets from the client first flight.
    /// * `first_sequence`: Sequence number corresponding to `packets[0]`.
    ///
    /// # Returns
    /// Decrypted early-data payloads when accepted; empty vector when ticket policy does not accept.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when acceptance, key derivation, packet decoding, or policy checks fail.
    ///
    /// # Panics
    /// This function does not panic.
    #[allow(clippy::too_many_arguments)]
    pub fn noxtls_accept_and_open_tls13_early_data_client_flight_with_ticket_policy(
        &mut self,
        client_hello: &[u8],
        tickets: &mut [ResumptionTicket],
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
        packets: &[Vec<u8>],
        first_sequence: u64,
    ) -> Result<Vec<Vec<u8>>> {
        if !self.noxtls_accept_tls13_early_data_with_ticket_policy(
            client_hello,
            tickets,
            current_time_ms,
            max_skew_ms,
            usage_policy,
        )? {
            return Ok(Vec::new());
        }
        let accepted_psk = self
            .tls13_early_data_accepted_psk
            .clone()
            .ok_or(Error::StateError(
                "tls13 early-data accepted ticket context is not installed",
            ))?;
        self.noxtls_open_tls13_early_data_client_flight_packets(&accepted_psk, packets, first_sequence)
    }

    /// Accepts ClientHello policy from ticket store and opens early-data packets from the client flight.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded TLS 1.3 ClientHello carrying PSK and early_data offer.
    /// * `ticket_store`: Mutable server ticket store used for acceptance.
    /// * `current_time_ms`: Server-local timestamp in milliseconds.
    /// * `max_skew_ms`: Allowed absolute ticket age skew.
    /// * `usage_policy`: Whether accepted tickets are reusable or single-use.
    /// * `packets`: Ordered TLSCiphertext packets from the client first flight.
    /// * `first_sequence`: Sequence number corresponding to `packets[0]`.
    ///
    /// # Returns
    /// Decrypted early-data payloads when accepted; empty vector when ticket policy does not accept.
    ///
    /// # Errors
    /// Returns [`noxtls_core::Error`] when acceptance, key derivation, packet decoding, or policy checks fail.
    ///
    /// # Panics
    /// This function does not panic.
    #[allow(clippy::too_many_arguments)]
    pub fn noxtls_accept_and_open_tls13_early_data_client_flight_with_ticket_store(
        &mut self,
        client_hello: &[u8],
        ticket_store: &mut TicketStore,
        current_time_ms: u64,
        max_skew_ms: u32,
        usage_policy: TicketUsagePolicy,
        packets: &[Vec<u8>],
        first_sequence: u64,
    ) -> Result<Vec<Vec<u8>>> {
        if !self.noxtls_accept_tls13_early_data_with_ticket_store(
            client_hello,
            ticket_store,
            current_time_ms,
            max_skew_ms,
            usage_policy,
        )? {
            return Ok(Vec::new());
        }
        let accepted_psk = self
            .tls13_early_data_accepted_psk
            .clone()
            .ok_or(Error::StateError(
                "tls13 early-data accepted ticket context is not installed",
            ))?;
        self.noxtls_open_tls13_early_data_client_flight_packets(&accepted_psk, packets, first_sequence)
    }

    /// Returns TLS 1.3 early-data traffic-key length based on active modeled suite policy.
    ///
    /// # Arguments
    /// * `self` — `Connection` with selected cipher suite context.
    ///
    /// # Returns
    /// AES-128 uses 16 bytes; AES-256 and ChaCha20-Poly1305 use 32 bytes.
    ///
    /// # Panics
    /// This function does not panic.
    pub(super) fn noxtls_tls13_early_data_key_len(&self) -> usize {
        match self.noxtls_selected_cipher_suite {
            Some(CipherSuite::TlsAes256GcmSha384 | CipherSuite::TlsChacha20Poly1305Sha256) => 32,
            _ => 16,
        }
    }

    /// Returns whether modeled early-data record protection uses ChaCha20-Poly1305.
    ///
    /// # Arguments
    /// * `self` — `Connection` with selected cipher suite context.
    ///
    /// # Returns
    /// `true` when current modeled suite policy selects ChaCha20-Poly1305.
    ///
    /// # Panics
    /// This function does not panic.
    fn noxtls_tls13_early_data_uses_chacha20_poly1305(&self) -> bool {
        matches!(
            self.noxtls_selected_cipher_suite,
            Some(CipherSuite::TlsChacha20Poly1305Sha256)
        )
    }

    /// Resets transcript context to a single ClientHello for modeled 0-RTT server decrypt.
    ///
    /// # Arguments
    /// * `client_hello` — Encoded ClientHello message bytes to anchor early-data transcript hash.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    /// This function does not panic.
    fn noxtls_reset_tls13_early_data_transcript_to_client_hello(&mut self, client_hello: &[u8]) {
        self.transcript.clear();
        self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
        self.noxtls_append_transcript(client_hello);
    }
}

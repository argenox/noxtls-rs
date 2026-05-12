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

//! Small integration surface that maps NoxTLS [`HandshakeState`] values into telemetry-friendly events.
//!
//! Intended for tools such as Noxsight that observe modeled TLS handshakes without pulling the full
//! `noxtls` protocol crate into their core types.

use noxtls::HandshakeState;

/// Snapshot of a modeled connection handshake state for outbound telemetry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlsTelemetryEvent {
    /// Handshake state at the time the event was emitted.
    pub state: HandshakeState,
    /// Opaque connection handle assigned by the embedding application.
    pub connection_id: u64,
}

/// Creates a telemetry event snapshot for the specified connection handshake state.
///
/// # Arguments
///
/// * `connection_id` — Numeric connection identifier chosen by the caller.
/// * `state` — Current [`HandshakeState`] for that connection.
///
/// # Returns
///
/// A [`TlsTelemetryEvent`] carrying the provided fields.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn emit_state_event(connection_id: u64, state: HandshakeState) -> TlsTelemetryEvent {
    TlsTelemetryEvent {
        state,
        connection_id,
    }
}

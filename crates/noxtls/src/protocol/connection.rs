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

use super::dtls::{
    noxtls_encode_dtls12_handshake_fragments, noxtls_encode_dtls_record_packet,
    noxtls_open_dtls13_aes128gcm_record, noxtls_parse_dtls_record_packet,
    noxtls_reassemble_dtls12_handshake_fragments, noxtls_seal_dtls13_aes128gcm_record,
    DtlsEpochReplayTracker, DtlsFlightRetransmitTracker, DtlsRecordHeader, DtlsReplayWindow,
    DtlsReplayWindowSnapshot,
};
use super::handshake::{noxtls_encode_handshake_message, noxtls_parse_handshake_message};
use super::kdf::{
    noxtls_finished_hmac_for_hash, noxtls_hash_bytes_for_algorithm, noxtls_hkdf_expand_for_hash,
    noxtls_hkdf_extract_for_hash, noxtls_hkdf_extract_with_salt_for_hash,
    noxtls_tls13_expand_label_for_hash, HashAlgorithm,
};
use super::keyshare::{
    noxtls_derive_deterministic_mlkem768_keypair, noxtls_derive_deterministic_p256_private,
    noxtls_derive_deterministic_x25519_private, noxtls_derive_tls13_mlkem768_shared_secret,
    noxtls_derive_tls13_p256_shared_secret, noxtls_derive_tls13_x25519_shared_secret,
    noxtls_tls13_client_hello_offers_supported_key_exchange,
};
use super::psk::{
    noxtls_ticket_age_matches_policy, ResumptionTicket, TicketStore, TicketUsagePolicy,
};
use super::record::{
    noxtls_build_record_nonce, noxtls_decode_tls12_ciphertext_record,
    noxtls_decode_tls13_ciphertext_record, noxtls_decode_tls13_inner_plaintext,
    noxtls_encode_tls12_ciphertext_record, noxtls_encode_tls13_ciphertext_record,
    noxtls_encode_tls13_inner_plaintext,
};
use super::state::{
    AlertDescription, AlertLevel, CipherSuite, HandshakeState, RecordContentType, TlsVersion,
};
use super::tls_wire::split_tls13_handshake_payload;
#[cfg(not(feature = "std"))]
use crate::internal_alloc::ToOwned;
use crate::internal_alloc::{String, Vec};
use noxtls_core::{Error, Result};
use noxtls_crypto::{
    noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt, noxtls_chacha20_poly1305_decrypt,
    noxtls_chacha20_poly1305_encrypt, noxtls_ed25519_public_key_from_subject_public_key_info,
    noxtls_ed25519_verify, noxtls_hkdf_extract_sha256, noxtls_mldsa_verify,
    noxtls_p256_ecdsa_verify_sha256, noxtls_rsassa_pss_sha256_verify,
    noxtls_rsassa_pss_sha384_verify, noxtls_sha256, noxtls_tls12_prf_sha256,
    noxtls_tls12_prf_sha384, AesCipher, HmacDrbgSha256, MlDsaPublicKey, MlKemPrivateKey,
    P256PrivateKey, P256PublicKey, RsaPublicKey, TlsTranscriptSha256, TlsTranscriptSha384,
    X25519PrivateKey, MLKEM_CIPHERTEXT_LEN,
};
use noxtls_x509::{
    noxtls_certificate_matches_hostname, noxtls_parse_certificate, noxtls_parse_der_node,
    noxtls_parse_ecdsa_signature_der, noxtls_validate_certificate_chain, ValidationError,
};

/// Holds connection version, handshake state, and transcript bytes.
#[derive(Debug, Clone)]
pub struct Connection {
    pub version: TlsVersion,
    pub state: HandshakeState,
    noxtls_selected_cipher_suite: Option<CipherSuite>,
    tls13_client_cipher_suites: Option<Vec<CipherSuite>>,
    transcript: Vec<u8>,
    noxtls_transcript_hash: TranscriptHashState,
    handshake_secret: Option<Vec<u8>>,
    tls13_master_secret: Option<Vec<u8>>,
    tls13_client_handshake_traffic_secret: Option<Vec<u8>>,
    tls13_server_handshake_traffic_secret: Option<Vec<u8>>,
    tls13_client_application_traffic_secret: Option<Vec<u8>>,
    tls13_server_application_traffic_secret: Option<Vec<u8>>,
    tls13_exporter_master_secret: Option<Vec<u8>>,
    noxtls_tls13_resumption_master_secret: Option<Vec<u8>>,
    tls13_client_x25519_private: Option<X25519PrivateKey>,
    tls13_client_p256_private: Option<P256PrivateKey>,
    tls13_client_mlkem768_private: Option<MlKemPrivateKey>,
    tls13_shared_secret: Option<[u8; 32]>,
    tls13_hrr_requested_group: Option<u16>,
    tls13_hrr_seen: bool,
    /// Holds up to 32 bytes of AEAD key material (AES-128 uses the first 16; AES-256/ChaCha use 32).
    client_write_key: Option<[u8; 32]>,
    server_write_key: Option<[u8; 32]>,
    client_write_iv: Option<[u8; 12]>,
    server_write_iv: Option<[u8; 12]>,
    client_sequence: u64,
    server_sequence: u64,
    noxtls_tls13_peer_close_notify_received: bool,
    noxtls_tls13_local_close_notify_sent: bool,
    tls13_require_certificate_auth: bool,
    tls13_server_trust_anchors_der: Vec<Vec<u8>>,
    tls13_server_intermediates_der: Vec<Vec<u8>>,
    tls13_server_validation_time: Option<String>,
    tls13_server_expected_hostname: Option<String>,
    tls13_client_server_name: Option<String>,
    tls13_request_ocsp_stapling: bool,
    tls13_require_ocsp_staple: bool,
    tls13_ocsp_staple_verifier: Option<Tls13OcspStapleVerifier>,
    noxtls_tls13_server_ocsp_staple: Option<Vec<u8>>,
    noxtls_tls13_server_ocsp_staple_verified: bool,
    tls13_require_server_name_ack: bool,
    noxtls_tls13_server_name_acknowledged: bool,
    tls13_client_alpn_protocols: Vec<Vec<u8>>,
    noxtls_tls13_selected_alpn_protocol: Option<Vec<u8>>,
    tls13_client_offer_pq_key_shares: bool,
    tls13_client_offer_mldsa_signature: bool,
    tls13_server_leaf_public_key_der: Option<Vec<u8>>,
    tls13_server_certificate_chain_validated: bool,
    tls13_early_data_require_acceptance: bool,
    tls13_early_data_accepted_psk: Option<Vec<u8>>,
    tls13_early_data_max_bytes: Option<u32>,
    tls13_early_data_opened_bytes: u64,
    tls13_early_data_offered_in_client_hello: bool,
    tls13_early_data_accepted_in_encrypted_extensions: bool,
    tls13_early_data_anti_replay_enabled: bool,
    tls13_early_data_replay_window: DtlsReplayWindow,
    noxtls_tls13_early_data_telemetry: Tls13EarlyDataTelemetry,
    tls12_change_cipher_spec_seen: bool,
    noxtls_tls12_session_id: Option<Vec<u8>>,
    tls12_allow_legacy_record_versions: bool,
    dtls13_client_write_key: Option<[u8; 16]>,
    dtls13_client_write_iv: Option<[u8; 12]>,
    dtls13_server_write_key: Option<[u8; 16]>,
    dtls13_server_write_iv: Option<[u8; 12]>,
    dtls13_outbound_epoch: u16,
    dtls13_outbound_sequence: u64,
    dtls13_inbound_replay_tracker: DtlsEpochReplayTracker,
    dtls13_client_inbound_replay_tracker: DtlsEpochReplayTracker,
    dtls13_active_flight: Vec<(u16, u64)>,
    dtls13_active_flight_started_at_ms: Option<u64>,
    dtls13_active_flight_timeout_ms: u64,
    noxtls_dtls13_active_flight_failed: bool,
    dtls_retransmit_tracker: DtlsFlightRetransmitTracker,
    dtls_retransmit_initial_timeout_ms: u64,
    dtls_max_retransmit_attempts: u8,
    noxtls_dtls12_handshake_phase: Dtls12HandshakePhase,
    dtls12_expected_cookie: Option<Vec<u8>>,
    dtls12_anti_amplification_enforced: bool,
    dtls12_inbound_bytes: u64,
    dtls12_outbound_bytes: u64,
    max_record_plaintext_len: usize,
}

/// Represents one protected TLS record carrying ciphertext and authentication tag.
#[derive(Debug, Clone)]
pub struct ProtectedRecord {
    pub sequence: u64,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

/// Captures transport-facing DTLS retry and timeout knobs.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DtlsOperationalPolicy {
    pub retransmit_initial_timeout_ms: u64,
    pub max_retransmit_attempts: u8,
    pub active_flight_timeout_ms: u64,
}

/// Names pre-tuned DTLS operational profiles for common deployment environments.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DtlsOperationalProfile {
    Conservative,
    LanLowLatency,
    LossyNetwork,
}

/// Captures tunable policy controls for TLS 1.3 modeled early-data handling.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Tls13EarlyDataOperationalPolicy {
    pub require_acceptance: bool,
    pub anti_replay_enabled: bool,
}

/// Names pre-tuned operational profiles for TLS 1.3 modeled early-data policy.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Tls13EarlyDataOperationalProfile {
    Compatibility,
    Strict,
}

/// Tracks counters for modeled TLS 1.3 early-data accept/reject outcomes.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct Tls13EarlyDataTelemetry {
    pub accepted_records: u64,
    pub rejected_missing_acceptance: u64,
    pub rejected_psk_mismatch: u64,
    pub rejected_replay_or_too_old: u64,
    pub rejected_invalid_input: u64,
    pub rejected_decrypt_or_policy: u64,
}

/// Serializable replay-window state for carrying TLS 1.3 early-data anti-replay continuity.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct Tls13EarlyDataReplayState {
    pub latest_sequence: u64,
    pub bitmap: u64,
    pub initialized: bool,
}

/// Captures QUIC Initial secrets derived from destination connection ID.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tls13QuicInitialSecrets {
    pub initial_secret: Vec<u8>,
    pub client_initial_secret: Vec<u8>,
    pub server_initial_secret: Vec<u8>,
}

/// Captures one QUIC packet-protection keyset derived from one traffic secret.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tls13QuicPacketProtectionKeys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub header_protection_key: Vec<u8>,
}

/// Captures current QUIC handshake and 1-RTT traffic secret snapshots.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tls13QuicTrafficSecretSnapshot {
    pub client_handshake_secret: Vec<u8>,
    pub server_handshake_secret: Vec<u8>,
    pub client_application_secret: Vec<u8>,
    pub server_application_secret: Vec<u8>,
}

/// Captures next-generation QUIC 1-RTT traffic secrets derived via `quic ku`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tls13QuicNextTrafficSecrets {
    pub client_next_application_secret: Vec<u8>,
    pub server_next_application_secret: Vec<u8>,
}

/// QUIC exporter label for client 1-RTT secret derivations.
pub const TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT: &[u8] = b"EXPORTER-QUIC client 1rtt";
/// QUIC exporter label for server 1-RTT secret derivations.
pub const TLS13_QUIC_EXPORTER_LABEL_SERVER_1RTT: &[u8] = b"EXPORTER-QUIC server 1rtt";

const TLS13_QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_HELLO_VERIFY_REQUEST: u8 = 0x03;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 0x04;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
const HANDSHAKE_CERTIFICATE: u8 = 0x0B;
const HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0C;
const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 0x0D;
const HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0E;
const HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0F;
const HANDSHAKE_FINISHED: u8 = 0x14;
const HANDSHAKE_KEY_UPDATE: u8 = 0x18;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_EARLY_DATA: u16 = 0x002A;
const TLS13_KEY_SHARE_GROUP_SECP256R1: u16 = 0x0017;
const TLS13_KEY_SHARE_GROUP_X25519: u16 = 0x001D;
const TLS13_KEY_SHARE_GROUP_MLKEM768: u16 = 0x0201;
const TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID: u16 = 0x11EC;
const TLS13_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE: u8 = 0x01;
const TLS13_SIGALG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const TLS13_SIGALG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const TLS13_SIGALG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const TLS13_SIGALG_ED25519: u16 = 0x0807;
const TLS13_SIGALG_MLDSA65: u16 = 0x0905;
const TLS13_MAX_EXTENSION_VALUE_BYTES: usize = 16_384;
const TLS_MAX_RECORD_PLAINTEXT_LEN: usize = 16_384;
const DTLS_RETRANSMIT_TRACKER_MAX_RECORDS: usize = 256;
const DTLS_RETRANSMIT_INITIAL_TIMEOUT_MS: u64 = 1_000;
const DTLS_MAX_RETRANSMIT_ATTEMPTS: u8 = 4;
const DTLS13_ACTIVE_FLIGHT_TIMEOUT_MS: u64 = 10_000;
const DTLS13_MAX_SEQUENCE: u64 = (1_u64 << 48) - 1;
const DTLS12_MAX_COOKIE_LEN: usize = 255;
const DTLS12_ANTI_AMPLIFICATION_FACTOR: u64 = 3;
const TLS13_HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Captures parsed extension data from a minimally-modeled ClientHello.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ClientHelloExtensions {
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub sni_server_name: Option<String>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub status_request_ocsp: bool,
    pub psk_key_exchange_modes: Vec<u8>,
    pub psk_identity_count: usize,
    pub psk_identities: Vec<Vec<u8>>,
    pub psk_obfuscated_ticket_ages: Vec<u32>,
    pub psk_binders: Vec<Vec<u8>>,
    pub early_data_offered: bool,
}

/// Summarizes parsed suite and extension data from ClientHello.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ClientHelloInfo {
    pub offered_cipher_suites: Vec<CipherSuite>,
    pub extensions: ClientHelloExtensions,
}

/// Captures one PSK identity entry used in TLS 1.3 pre_shared_key offers.
struct PskIdentityOffer<'a> {
    identity: &'a [u8],
    obfuscated_ticket_age: u32,
}

/// Carries one or more TLS 1.3 PSK identity+binder offers for ClientHello encoding.
struct PskClientOffer<'a> {
    identities: Vec<PskIdentityOffer<'a>>,
    binders: Vec<&'a [u8]>,
}

/// Holds TLS 1.3 client `key_share` public material emitted in ClientHello.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
struct Tls13ClientPublicKeyShares {
    x25519: Option<[u8; 32]>,
    secp256r1_uncompressed: Option<[u8; 65]>,
    mlkem768: Option<Vec<u8>>,
    x25519_mlkem768_hybrid: Option<Vec<u8>>,
}

/// Parsed server `key_share` payload for TLS 1.3 ServerHello (non-HRR).
#[derive(Debug, Clone, Eq, PartialEq)]
enum Tls13ServerKeyShareParsed {
    X25519([u8; 32]),
    Secp256r1([u8; 65]),
    MlKem768(Vec<u8>),
    X25519MlKem768Hybrid { x25519: [u8; 32], mlkem768: Vec<u8> },
}

/// Summarizes parsed ServerHello/HelloRetryRequest details needed by connection flow.
struct ParsedServerHello {
    suite: CipherSuite,
    key_share: Option<Tls13ServerKeyShareParsed>,
    hello_retry_request: bool,
    requested_group: Option<u16>,
}

/// Captures parsed EncryptedExtensions values required by modeled handshake policy.
struct ParsedEncryptedExtensions {
    selected_alpn_protocol: Option<Vec<u8>>,
    server_name_acknowledged: bool,
    early_data_accepted: bool,
}

/// Captures parsed TLS 1.3 Certificate contents and optional leaf stapled OCSP bytes.
struct ParsedTls13CertificateBody {
    certificates: Vec<Vec<u8>>,
    leaf_ocsp_staple: Option<Vec<u8>>,
}

/// Describes validation outcome for one stapled OCSP response.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Tls13OcspStapleVerification {
    Good,
    Expired,
    Revoked,
}

/// Function-pointer hook used to validate one stapled OCSP response payload.
pub type Tls13OcspStapleVerifier = fn(&[u8]) -> Result<Tls13OcspStapleVerification>;

/// Models deterministic DTLS1.2 handshake progression for cookie and flight sequencing.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Dtls12HandshakePhase {
    AwaitingClientHello,
    AwaitingClientHelloWithCookie,
    AwaitingClientKeyExchange,
    AwaitingFinished,
    Connected,
}

/// Selects transcript hashing noxtls_algorithm based on protocol version profile.
#[derive(Debug, Clone)]
enum TranscriptHashState {
    Sha256(TlsTranscriptSha256),
    Sha384(TlsTranscriptSha384),
}

impl TranscriptHashState {
    /// Builds transcript hashing state aligned with connection version defaults.
    ///
    /// # Arguments
    ///
    /// * `version` — `version: TlsVersion`.
    ///
    /// # Returns
    ///
    /// A noxtls_new or updated `Self` value as constructed in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_for_version(version: TlsVersion) -> Self {
        match version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => Self::Sha384(TlsTranscriptSha384::noxtls_new()),
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                Self::Sha256(TlsTranscriptSha256::noxtls_new())
            }
        }
    }

    /// Feeds handshake bytes into the selected transcript hash implementation.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `message` — `message: &[u8]`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_update(&mut self, message: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.noxtls_update(message),
            Self::Sha384(hasher) => hasher.noxtls_update(message),
        }
    }

    /// Returns current transcript hash bytes without consuming internal state.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_snapshot_hash(&self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.noxtls_snapshot_hash().to_vec(),
            Self::Sha384(hasher) => hasher.noxtls_snapshot_hash().to_vec(),
        }
    }

    /// Returns hash noxtls_algorithm represented by this transcript state.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha384(_) => HashAlgorithm::Sha384,
        }
    }
}

impl CipherSuite {
    /// Maps wire two-byte cipher suite identifier into modeled suite variants.
    ///
    /// # Arguments
    ///
    /// * `codepoint` — `codepoint: u16`.
    ///
    /// # Returns
    ///
    /// On success, `Some` as described by the return type; see the function body for when `None` is returned.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_from_u16(codepoint: u16) -> Option<Self> {
        match codepoint {
            0x1301 => Some(Self::TlsAes128GcmSha256),
            0x1302 => Some(Self::TlsAes256GcmSha384),
            0x1303 => Some(Self::TlsChacha20Poly1305Sha256),
            0xC02F => Some(Self::TlsEcdheRsaWithAes128GcmSha256),
            0xC030 => Some(Self::TlsEcdheRsaWithAes256GcmSha384),
            _ => None,
        }
    }

    /// Returns transcript hash policy used by this suite.
    ///
    /// # Arguments
    ///
    /// * `self` — `self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_transcript_hash_state(self) -> TranscriptHashState {
        match self {
            Self::TlsAes128GcmSha256
            | Self::TlsChacha20Poly1305Sha256
            | Self::TlsEcdheRsaWithAes128GcmSha256 => {
                TranscriptHashState::Sha256(TlsTranscriptSha256::noxtls_new())
            }
            Self::TlsAes256GcmSha384 | Self::TlsEcdheRsaWithAes256GcmSha384 => {
                TranscriptHashState::Sha384(TlsTranscriptSha384::noxtls_new())
            }
        }
    }

    /// Returns key-schedule hash noxtls_algorithm policy for this suite.
    ///
    /// # Arguments
    ///
    /// * `self` — `self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_hash_algorithm(self) -> HashAlgorithm {
        match self {
            Self::TlsAes128GcmSha256
            | Self::TlsChacha20Poly1305Sha256
            | Self::TlsEcdheRsaWithAes128GcmSha256 => HashAlgorithm::Sha256,
            Self::TlsAes256GcmSha384 | Self::TlsEcdheRsaWithAes256GcmSha384 => {
                HashAlgorithm::Sha384
            }
        }
    }

    /// Returns TLS 1.3 AEAD traffic key length in bytes when applicable.
    ///
    /// # Arguments
    ///
    /// * `self` — `self`.
    ///
    /// # Returns
    ///
    /// On success, `Some` as described by the return type; see the function body for when `None` is returned.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_tls13_traffic_key_len(self) -> Option<usize> {
        match self {
            CipherSuite::TlsAes128GcmSha256 => Some(16),
            CipherSuite::TlsAes256GcmSha384 | CipherSuite::TlsChacha20Poly1305Sha256 => Some(32),
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => None,
        }
    }

    /// Returns the wire identifier for this cipher suite.
    ///
    /// # Arguments
    ///
    /// * `self` — `self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_to_u16(self) -> u16 {
        match self {
            Self::TlsAes128GcmSha256 => 0x1301,
            Self::TlsAes256GcmSha384 => 0x1302,
            Self::TlsChacha20Poly1305Sha256 => 0x1303,
            Self::TlsEcdheRsaWithAes128GcmSha256 => 0xC02F,
            Self::TlsEcdheRsaWithAes256GcmSha384 => 0xC030,
        }
    }
}

impl Connection {
    /// Creates a noxtls_new connection initialized in the `Idle` handshake state.
    ///
    /// # Arguments
    /// * `version`: Protocol version profile for this connection.
    ///
    /// # Returns
    /// Fresh `Connection` in `Idle` state.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_new(version: TlsVersion) -> Self {
        Self {
            version,
            state: HandshakeState::Idle,
            noxtls_selected_cipher_suite: None,
            tls13_client_cipher_suites: None,
            transcript: Vec::new(),
            noxtls_transcript_hash: TranscriptHashState::noxtls_for_version(version),
            handshake_secret: None,
            tls13_master_secret: None,
            tls13_client_handshake_traffic_secret: None,
            tls13_server_handshake_traffic_secret: None,
            tls13_client_application_traffic_secret: None,
            tls13_server_application_traffic_secret: None,
            tls13_exporter_master_secret: None,
            noxtls_tls13_resumption_master_secret: None,
            tls13_client_x25519_private: None,
            tls13_client_p256_private: None,
            tls13_client_mlkem768_private: None,
            tls13_shared_secret: None,
            tls13_hrr_requested_group: None,
            tls13_hrr_seen: false,
            client_write_key: None,
            server_write_key: None,
            client_write_iv: None,
            server_write_iv: None,
            client_sequence: 0,
            server_sequence: 0,
            noxtls_tls13_peer_close_notify_received: false,
            noxtls_tls13_local_close_notify_sent: false,
            tls13_require_certificate_auth: false,
            tls13_server_trust_anchors_der: Vec::new(),
            tls13_server_intermediates_der: Vec::new(),
            tls13_server_validation_time: None,
            tls13_server_expected_hostname: None,
            tls13_client_server_name: None,
            tls13_request_ocsp_stapling: false,
            tls13_require_ocsp_staple: false,
            tls13_ocsp_staple_verifier: None,
            noxtls_tls13_server_ocsp_staple: None,
            noxtls_tls13_server_ocsp_staple_verified: false,
            tls13_require_server_name_ack: false,
            noxtls_tls13_server_name_acknowledged: false,
            tls13_client_alpn_protocols: Vec::new(),
            noxtls_tls13_selected_alpn_protocol: None,
            tls13_client_offer_pq_key_shares: true,
            tls13_client_offer_mldsa_signature: true,
            tls13_server_leaf_public_key_der: None,
            tls13_server_certificate_chain_validated: false,
            tls13_early_data_require_acceptance: false,
            tls13_early_data_accepted_psk: None,
            tls13_early_data_max_bytes: None,
            tls13_early_data_opened_bytes: 0,
            tls13_early_data_offered_in_client_hello: false,
            tls13_early_data_accepted_in_encrypted_extensions: false,
            tls13_early_data_anti_replay_enabled: true,
            tls13_early_data_replay_window: DtlsReplayWindow::noxtls_new(),
            noxtls_tls13_early_data_telemetry: Tls13EarlyDataTelemetry::default(),
            tls12_change_cipher_spec_seen: false,
            noxtls_tls12_session_id: None,
            tls12_allow_legacy_record_versions: false,
            dtls13_client_write_key: None,
            dtls13_client_write_iv: None,
            dtls13_server_write_key: None,
            dtls13_server_write_iv: None,
            dtls13_outbound_epoch: 0,
            dtls13_outbound_sequence: 0,
            dtls13_inbound_replay_tracker: DtlsEpochReplayTracker::noxtls_new(),
            dtls13_client_inbound_replay_tracker: DtlsEpochReplayTracker::noxtls_new(),
            dtls13_active_flight: Vec::new(),
            dtls13_active_flight_started_at_ms: None,
            dtls13_active_flight_timeout_ms: DTLS13_ACTIVE_FLIGHT_TIMEOUT_MS,
            noxtls_dtls13_active_flight_failed: false,
            dtls_retransmit_tracker: DtlsFlightRetransmitTracker::noxtls_new(
                DTLS_RETRANSMIT_TRACKER_MAX_RECORDS,
            ),
            dtls_retransmit_initial_timeout_ms: DTLS_RETRANSMIT_INITIAL_TIMEOUT_MS,
            dtls_max_retransmit_attempts: DTLS_MAX_RETRANSMIT_ATTEMPTS,
            noxtls_dtls12_handshake_phase: Dtls12HandshakePhase::AwaitingClientHello,
            dtls12_expected_cookie: None,
            dtls12_anti_amplification_enforced: true,
            dtls12_inbound_bytes: 0,
            dtls12_outbound_bytes: 0,
            max_record_plaintext_len: TLS_MAX_RECORD_PLAINTEXT_LEN,
        }
    }

    /// Returns the currently configured DTLS retry/timeout policy for this connection.
    ///
    /// # Returns
    /// `Some(policy)` for DTLS profiles; `None` for TLS stream profiles.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, `Some` as described by the return type; see the function body for when `None` is returned.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls_operational_policy(&self) -> Option<DtlsOperationalPolicy> {
        if !self.version.is_dtls() {
            return None;
        }
        Some(DtlsOperationalPolicy {
            retransmit_initial_timeout_ms: self.dtls_retransmit_initial_timeout_ms,
            max_retransmit_attempts: self.dtls_max_retransmit_attempts,
            active_flight_timeout_ms: self.dtls13_active_flight_timeout_ms,
        })
    }

    /// Applies a full DTLS retry/timeout policy in one call.
    ///
    /// # Arguments
    /// * `policy`: DTLS timer/retry settings. Zero values are clamped to 1.
    ///
    /// # Returns
    /// Effective policy after clamping and application.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls_operational_policy(
        &mut self,
        policy: DtlsOperationalPolicy,
    ) -> Result<DtlsOperationalPolicy> {
        self.noxtls_ensure_dtls12_mode()?;
        let effective = DtlsOperationalPolicy {
            retransmit_initial_timeout_ms: policy.retransmit_initial_timeout_ms.max(1),
            max_retransmit_attempts: policy.max_retransmit_attempts.max(1),
            active_flight_timeout_ms: policy.active_flight_timeout_ms.max(1),
        };
        self.dtls_retransmit_initial_timeout_ms = effective.retransmit_initial_timeout_ms;
        self.dtls_max_retransmit_attempts = effective.max_retransmit_attempts;
        self.dtls13_active_flight_timeout_ms = effective.active_flight_timeout_ms;
        Ok(effective)
    }

    /// Applies one built-in DTLS operational profile and returns the resulting policy.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `profile`: Built-in profile tuned for a deployment environment.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_apply_dtls_operational_profile(
        &mut self,
        profile: DtlsOperationalProfile,
    ) -> Result<DtlsOperationalPolicy> {
        let policy = match profile {
            DtlsOperationalProfile::Conservative => DtlsOperationalPolicy {
                retransmit_initial_timeout_ms: DTLS_RETRANSMIT_INITIAL_TIMEOUT_MS,
                max_retransmit_attempts: DTLS_MAX_RETRANSMIT_ATTEMPTS,
                active_flight_timeout_ms: DTLS13_ACTIVE_FLIGHT_TIMEOUT_MS,
            },
            DtlsOperationalProfile::LanLowLatency => DtlsOperationalPolicy {
                retransmit_initial_timeout_ms: 250,
                max_retransmit_attempts: 3,
                active_flight_timeout_ms: 3_000,
            },
            DtlsOperationalProfile::LossyNetwork => DtlsOperationalPolicy {
                retransmit_initial_timeout_ms: 1_500,
                max_retransmit_attempts: 6,
                active_flight_timeout_ms: 20_000,
            },
        };
        self.noxtls_set_dtls_operational_policy(policy)
    }

    /// Enables or disables strict TLS 1.3 certificate-authentication enforcement.
    ///
    /// # Arguments
    /// * `required`: Whether Certificate and CertificateVerify must be validated.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_tls13_require_certificate_auth(&mut self, required: bool) {
        self.tls13_require_certificate_auth = required;
    }

    /// Configures certificate-chain material used for TLS 1.3 server auth validation.
    ///
    /// # Arguments
    /// * `trust_anchors_der`: Trusted root certificates in DER form.
    /// * `intermediates_der`: Optional intermediate certificates in DER form.
    /// * `validation_time`: Validation timestamp in canonical ASN.1 text form.
    ///
    /// # Returns
    /// `Ok(())` when configuration is stored.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_configure_tls13_server_auth(
        &mut self,
        trust_anchors_der: &[Vec<u8>],
        intermediates_der: &[Vec<u8>],
        validation_time: &str,
    ) -> Result<()> {
        if trust_anchors_der.is_empty() {
            return Err(Error::InvalidLength(
                "tls13 trust anchor list must not be empty",
            ));
        }
        if validation_time.is_empty() {
            return Err(Error::InvalidLength(
                "tls13 validation time must not be empty",
            ));
        }
        self.tls13_server_trust_anchors_der = trust_anchors_der.to_vec();
        self.tls13_server_intermediates_der = intermediates_der.to_vec();
        self.tls13_server_validation_time = Some(validation_time.to_owned());
        Ok(())
    }

    /// Sets or clears expected server hostname for TLS 1.3 certificate authentication.
    ///
    /// # Arguments
    /// * `hostname`: `Some(name)` to enforce hostname matching, or `None` to disable.
    ///
    /// # Returns
    /// `Ok(())` when hostname policy is stored.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_tls13_server_expected_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        match hostname {
            Some(value) if value.is_empty() => Err(Error::InvalidLength(
                "tls13 expected hostname must not be empty",
            )),
            Some(value) => {
                self.tls13_server_expected_hostname = Some(value.to_owned());
                Ok(())
            }
            None => {
                self.tls13_server_expected_hostname = None;
                Ok(())
            }
        }
    }

    /// Sets or clears TLS 1.2 session-id bytes used in outbound ClientHello.
    ///
    /// # Arguments
    /// * `session_id`: `Some(id)` to advertise a session-id (1..=32 bytes), or `None` to clear.
    ///
    /// # Returns
    /// `Ok(())` when the lifecycle value is stored.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when size constraints are violated.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_set_tls12_session_id(&mut self, session_id: Option<&[u8]>) -> Result<()> {
        match session_id {
            Some(value) if value.is_empty() => Err(Error::InvalidLength(
                "tls12 session id must not be empty when present",
            )),
            Some(value) if value.len() > 32 => Err(Error::InvalidLength(
                "tls12 session id must not exceed 32 bytes",
            )),
            Some(value) => {
                self.noxtls_tls12_session_id = Some(value.to_vec());
                Ok(())
            }
            None => {
                self.noxtls_tls12_session_id = None;
                Ok(())
            }
        }
    }

    /// Returns currently configured TLS 1.2 ClientHello session-id bytes.
    ///
    /// # Arguments
    ///
    /// * `self` — Connection carrying TLS 1.2 session lifecycle state.
    ///
    /// # Returns
    ///
    /// Configured session-id bytes when present.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_tls12_session_id(&self) -> Option<&[u8]> {
        self.noxtls_tls12_session_id.as_deref()
    }

    /// Enables or disables TLS 1.0/1.1 compatibility record-version acceptance in TLS 1.2 packet APIs.
    ///
    /// # Arguments
    ///
    /// * `allow` — `true` to accept legacy record versions (`0x0301`, `0x0302`) in addition to `0x0303`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_set_tls12_allow_legacy_record_versions(&mut self, allow: bool) {
        self.tls12_allow_legacy_record_versions = allow;
    }

    /// Configures SNI server_name value offered in TLS 1.3 ClientHello extension data.
    ///
    /// # Arguments
    /// * `server_name`: `Some(name)` to advertise one DNS host_name value, or `None` to disable.
    ///
    /// # Returns
    /// `Ok(())` when SNI offer policy is stored.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    ///
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
    ///
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
    ///
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
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_tls13_require_server_name_ack(&mut self, required: bool) {
        self.tls13_require_server_name_ack = required;
    }

    /// Reports whether server_name was acknowledged in parsed EncryptedExtensions.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    ///
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
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
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
    /// # Returns
    /// Selected ALPN protocol bytes when negotiated, otherwise `None`.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, `Some` as described by the return type; see the function body for when `None` is returned.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_selected_alpn_protocol(&self) -> Option<&[u8]> {
        self.noxtls_tls13_selected_alpn_protocol.as_deref()
    }

    /// Sets maximum accepted record plaintext length for seal/open operations.
    ///
    /// # Arguments
    /// * `max_len`: Plaintext limit in bytes (must be in `1..=16384`).
    ///
    /// # Returns
    /// `Ok(())` when the limit is accepted.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_max_record_plaintext_len(&mut self, max_len: usize) -> Result<()> {
        if max_len == 0 || max_len > TLS_MAX_RECORD_PLAINTEXT_LEN {
            return Err(Error::InvalidLength(
                "record plaintext limit must be between 1 and 16384 bytes",
            ));
        }
        self.max_record_plaintext_len = max_len;
        Ok(())
    }

    /// Enables or disables 0-RTT anti-replay checks for `noxtls_open_tls13_early_data_record`.
    ///
    /// # Arguments
    /// * `enabled`: `true` to reject replay/too-old sequences, `false` to bypass checks.
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    ///
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
    ///
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
    /// # Returns
    /// Current policy values.
    ///
    /// # Panics
    ///
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
    /// # Returns
    /// Copy of current early-data telemetry counters.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn noxtls_tls13_early_data_telemetry(&self) -> Tls13EarlyDataTelemetry {
        self.noxtls_tls13_early_data_telemetry
    }

    /// Resets modeled TLS 1.3 early-data telemetry counters to zero.
    ///
    /// # Returns
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_reset_tls13_early_data_telemetry(&mut self) {
        self.noxtls_tls13_early_data_telemetry = Tls13EarlyDataTelemetry::default();
    }

    /// Exports replay-window state for modeled TLS 1.3 early-data anti-replay continuity.
    ///
    /// # Returns
    /// Serializable replay state snapshot.
    ///
    /// # Panics
    ///
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
    ///
    /// Returns [`noxtls_core::Error`] when called on a non-TLS1.3 connection.
    ///
    /// # Panics
    ///
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
        self.noxtls_send_client_hello_with_resumption_tickets_with_ages(random, tickets, &obfuscated_ages)
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
        self.noxtls_send_client_hello_with_resumption_tickets_with_ages(random, tickets, &obfuscated_ages)
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

    /// Validates and records server hello bytes for transcript hashing.
    ///
    /// # Arguments
    /// * `msg`: Encoded ServerHello handshake message.
    ///
    /// # Returns
    /// `Ok(())` when ServerHello parses and state advances.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_server_hello(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err(Error::StateError(
                "server hello can only be processed after client hello",
            ));
        }
        let parsed = noxtls_parse_server_hello(msg)?;
        if parsed.hello_retry_request {
            if self.tls13_hrr_seen {
                return Err(Error::ParseFailure("duplicate hello retry request"));
            }
            self.tls13_hrr_seen = true;
            self.tls13_hrr_requested_group = parsed.requested_group;
            self.noxtls_reset_transcript_for_hrr();
            self.noxtls_append_transcript(msg);
            self.state = HandshakeState::Idle;
            return Ok(());
        }
        let selected_suite = parsed.suite;
        self.tls13_hrr_seen = false;
        self.tls13_hrr_requested_group = None;
        let server_key_share = parsed.key_share;
        if let Some(share) = server_key_share {
            self.tls13_shared_secret = Some(match share {
                Tls13ServerKeyShareParsed::X25519(peer_key_share) => {
                    noxtls_tls13_debug_log_bytes("tls13.server_hello.peer_key_share.x25519", &peer_key_share);
                    let private = self
                        .tls13_client_x25519_private
                        .clone()
                        .ok_or(Error::StateError(
                        "client x25519 key share must be available before server x25519 key share",
                    ))?;
                    let shared = noxtls_derive_tls13_x25519_shared_secret(private, &peer_key_share)?;
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::Secp256r1(peer_uncompressed) => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.secp256r1",
                        &peer_uncompressed,
                    );
                    let private = self.tls13_client_p256_private.as_ref().ok_or(
                        Error::StateError(
                            "client secp256r1 key share must be available before server secp256r1 key share",
                        ),
                    )?;
                    let shared = noxtls_derive_tls13_p256_shared_secret(private, &peer_uncompressed)?;
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::MlKem768(peer_key_share) => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.mlkem768_ciphertext",
                        &peer_key_share,
                    );
                    let private =
                        self.tls13_client_mlkem768_private
                            .as_ref()
                            .ok_or(Error::StateError(
                                "client mlkem768 key share must be available before server mlkem768 key share",
                            ))?;
                    let shared = noxtls_derive_tls13_mlkem768_shared_secret(private, &peer_key_share)?;
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
                Tls13ServerKeyShareParsed::X25519MlKem768Hybrid { x25519, mlkem768 } => {
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.hybrid.x25519",
                        &x25519,
                    );
                    noxtls_tls13_debug_log_bytes(
                        "tls13.server_hello.peer_key_share.hybrid.mlkem768_ciphertext",
                        &mlkem768,
                    );
                    let x25519_private = self
                        .tls13_client_x25519_private
                        .clone()
                        .ok_or(Error::StateError(
                        "client x25519 key share must be available before server hybrid key share",
                    ))?;
                    let x25519_shared =
                        noxtls_derive_tls13_x25519_shared_secret(x25519_private, &x25519)?;
                    let mlkem_private =
                        self.tls13_client_mlkem768_private
                            .as_ref()
                            .ok_or(Error::StateError(
                                "client mlkem768 key share must be available before server hybrid key share",
                            ))?;
                    let mlkem_shared =
                        noxtls_derive_tls13_mlkem768_shared_secret(mlkem_private, &mlkem768)?;
                    let shared =
                        noxtls_combine_tls13_hybrid_shared_secret(&x25519_shared, &mlkem_shared);
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret.classical", &x25519_shared);
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret.pq", &mlkem_shared);
                    noxtls_tls13_debug_log_bytes("tls13.shared_secret", &shared);
                    shared
                }
            });
        }
        noxtls_tls13_debug_log_bytes("tls13.transcript.server_hello", msg);
        self.noxtls_append_transcript(msg);
        self.noxtls_selected_cipher_suite = Some(selected_suite);
        self.noxtls_rebuild_transcript_hash_from_selected_suite();
        self.state = HandshakeState::ServerHelloReceived;
        Ok(())
    }

    /// Builds a TLS 1.3 HelloRetryRequest (ServerHello form) with requested group.
    ///
    /// # Arguments
    /// * `suite`: Selected cipher suite to advertise.
    /// * `requested_group`: Named group requested for retried key share.
    ///
    /// # Returns
    /// Encoded HelloRetryRequest handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_hello_retry_request(suite: CipherSuite, requested_group: u16) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&noxtls_legacy_wire_version(TlsVersion::Tls13));
        body.extend_from_slice(&TLS13_HRR_RANDOM);
        body.push(0x00); // session_id length
        body.extend_from_slice(&suite.noxtls_to_u16().to_be_bytes());
        body.push(0x00); // compression method
        let mut extensions = Vec::new();
        noxtls_push_extension(
            &mut extensions,
            EXT_KEY_SHARE,
            &requested_group.to_be_bytes(),
        );
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_SERVER_HELLO,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 EncryptedExtensions handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded EncryptedExtensions handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_encrypted_extensions(&mut self, msg: &[u8]) -> Result<()> {
        let allowed = if self.version.uses_tls13_handshake_semantics() {
            self.state == HandshakeState::ServerHelloReceived
                || self.state == HandshakeState::KeysDerived
        } else {
            self.state == HandshakeState::ServerHelloReceived
        };
        if !allowed {
            return Err(Error::StateError(
                "encrypted extensions can only be processed after server hello",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_ENCRYPTED_EXTENSIONS {
            return Err(Error::ParseFailure("invalid encrypted extensions type"));
        }
        let encrypted_extensions = noxtls_parse_encrypted_extensions_body(body)?;
        if encrypted_extensions.server_name_acknowledged && self.tls13_client_server_name.is_none()
        {
            return Err(Error::ParseFailure(
                "encrypted extensions contains unsolicited server_name acknowledgement",
            ));
        }
        if self.tls13_require_server_name_ack
            && self.tls13_client_server_name.is_some()
            && !encrypted_extensions.server_name_acknowledged
        {
            return Err(Error::ParseFailure(
                "encrypted extensions missing required server_name acknowledgement",
            ));
        }
        if encrypted_extensions.early_data_accepted
            && !self.tls13_early_data_offered_in_client_hello
        {
            return Err(Error::ParseFailure(
                "encrypted extensions contains unsolicited early_data acceptance",
            ));
        }
        self.tls13_early_data_accepted_in_encrypted_extensions =
            encrypted_extensions.early_data_accepted;
        if self.tls13_early_data_offered_in_client_hello
            && !encrypted_extensions.early_data_accepted
        {
            self.tls13_early_data_accepted_psk = None;
            self.tls13_early_data_max_bytes = None;
            self.tls13_early_data_opened_bytes = 0;
            self.tls13_early_data_replay_window = DtlsReplayWindow::noxtls_new();
        }
        self.noxtls_tls13_server_name_acknowledged = encrypted_extensions.server_name_acknowledged;
        if let Some(selected_protocol) = encrypted_extensions.selected_alpn_protocol {
            if !self.tls13_client_alpn_protocols.is_empty()
                && !self
                    .tls13_client_alpn_protocols
                    .contains(&selected_protocol)
            {
                return Err(Error::ParseFailure(
                    "encrypted extensions selected unsupported alpn protocol",
                ));
            }
            self.noxtls_tls13_selected_alpn_protocol = Some(selected_protocol);
        } else {
            self.noxtls_tls13_selected_alpn_protocol = None;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerEncryptedExtensionsReceived;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 CertificateRequest handshake message.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    /// Encoded CertificateRequest bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_request_message() -> Vec<u8> {
        // Empty request context + signature_algorithms extension.
        let mut extensions = Vec::new();
        let mut sigalgs = Vec::new();
        let requested_sigalgs = [
            TLS13_SIGALG_ECDSA_SECP256R1_SHA256,
            TLS13_SIGALG_RSA_PSS_RSAE_SHA256,
            TLS13_SIGALG_RSA_PSS_RSAE_SHA384,
            TLS13_SIGALG_ED25519,
            TLS13_SIGALG_MLDSA65,
        ];
        sigalgs.extend_from_slice(&((requested_sigalgs.len() * 2) as u16).to_be_bytes());
        for sigalg in requested_sigalgs {
            sigalgs.extend_from_slice(&sigalg.to_be_bytes());
        }
        noxtls_push_extension(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sigalgs);
        let mut body = Vec::new();
        body.push(0x00); // certificate_request_context length
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        noxtls_encode_handshake_message(HANDSHAKE_CERTIFICATE_REQUEST, &body)
    }

    /// Parses and records a TLS 1.3 CertificateRequest handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded CertificateRequest handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_certificate_request(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerEncryptedExtensionsReceived {
            return Err(Error::StateError(
                "certificate request can only be processed after encrypted extensions",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE_REQUEST {
            return Err(Error::ParseFailure("invalid certificate request type"));
        }
        noxtls_parse_certificate_request_body(body)?;
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateRequestReceived;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 EncryptedExtensions handshake message.
    ///
    /// # Arguments
    ///
    /// * _(none)_ — This function takes no parameters.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions() -> Vec<u8> {
        // Minimal empty extension block.
        Self::noxtls_build_encrypted_extensions_with_policy(None, false, false)
            .expect("empty encrypted extensions must always encode")
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with optional ALPN.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions_with_alpn(selected_alpn: Option<&[u8]>) -> Result<Vec<u8>> {
        Self::noxtls_build_encrypted_extensions_with_policy(selected_alpn, false, false)
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with optional ALPN and early_data ack.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    /// * `accept_early_data`: `true` emits empty early_data extension.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_build_encrypted_extensions_with_alpn_and_early_data(
        selected_alpn: Option<&[u8]>,
        accept_early_data: bool,
    ) -> Result<Vec<u8>> {
        Self::noxtls_build_encrypted_extensions_with_policy(selected_alpn, false, accept_early_data)
    }

    /// Builds a TLS 1.3 EncryptedExtensions handshake message with ALPN and SNI-ack policy.
    ///
    /// # Arguments
    /// * `selected_alpn`: Selected ALPN protocol bytes to advertise to client, or `None`.
    /// * `acknowledge_server_name`: `true` emits empty server_name extension as SNI acknowledgment.
    ///
    /// # Returns
    /// Encoded EncryptedExtensions bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_encrypted_extensions_with_policy(
        selected_alpn: Option<&[u8]>,
        acknowledge_server_name: bool,
        accept_early_data: bool,
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut extensions = Vec::new();
        if let Some(protocol) = selected_alpn {
            if protocol.is_empty() {
                return Err(Error::InvalidLength("alpn protocol must not be empty"));
            }
            if protocol.len() > u8::MAX as usize {
                return Err(Error::InvalidLength(
                    "alpn protocol length must not exceed 255 bytes",
                ));
            }
            let protocols = vec![protocol.to_vec()];
            let extension_data = noxtls_encode_alpn_extension_data(&protocols)?;
            noxtls_push_extension(&mut extensions, EXT_ALPN, &extension_data);
        }
        if acknowledge_server_name {
            noxtls_push_extension(&mut extensions, EXT_SERVER_NAME, &[]);
        }
        if accept_early_data {
            noxtls_push_extension(&mut extensions, EXT_EARLY_DATA, &[]);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_ENCRYPTED_EXTENSIONS,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 Certificate handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded Certificate handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_certificate(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerEncryptedExtensionsReceived
            && self.state != HandshakeState::ServerCertificateRequestReceived
        {
            return Err(Error::StateError(
                "certificate can only be processed after encrypted extensions/certificate request",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure("invalid certificate type"));
        }
        let parsed = noxtls_parse_certificate_body(body)?;
        self.noxtls_tls13_server_ocsp_staple = parsed.leaf_ocsp_staple.clone();
        self.noxtls_tls13_server_ocsp_staple_verified = false;
        if self.tls13_require_ocsp_staple && parsed.leaf_ocsp_staple.is_none() {
            return Err(Error::ParseFailure(
                "certificate message missing required ocsp staple",
            ));
        }
        if let Some(staple) = parsed.leaf_ocsp_staple.as_deref() {
            if let Some(verifier) = self.tls13_ocsp_staple_verifier {
                match verifier(staple)? {
                    Tls13OcspStapleVerification::Good => {
                        self.noxtls_tls13_server_ocsp_staple_verified = true;
                    }
                    Tls13OcspStapleVerification::Expired => {
                        return Err(Error::ParseFailure("ocsp staple expired"));
                    }
                    Tls13OcspStapleVerification::Revoked => {
                        return Err(Error::ParseFailure("ocsp staple revoked"));
                    }
                }
            } else {
                self.noxtls_tls13_server_ocsp_staple_verified = true;
            }
        }
        if self.tls13_require_certificate_auth {
            self.noxtls_validate_tls13_server_certificate_chain(&parsed.certificates)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateReceived;
        Ok(())
    }

    /// Processes a full server handshake flight in expected TLS 1.3 order.
    ///
    /// Expected sequence:
    /// * `ServerHello`
    /// * `EncryptedExtensions`
    /// * optional `CertificateRequest`
    /// * `Certificate`
    /// * `CertificateVerify`
    /// * `Finished`
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_server_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if messages.len() < 5 {
            return Err(Error::ParseFailure("server handshake flight is too short"));
        }
        let mut index = 0_usize;
        self.noxtls_recv_server_hello(&messages[index])?;
        index += 1;
        self.noxtls_derive_handshake_secret()?;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing server handshake messages",
            ));
        }
        Ok(())
    }

    /// Decrypts TLS 1.3 server post-`ServerHello` records and completes the canonical server handshake flight.
    ///
    /// Callers must have sent `ClientHello` and processed plaintext `ServerHello` so the transcript hash
    /// through `ServerHello` matches RFC 8446 handshake traffic key derivation inputs.
    ///
    /// # Arguments
    ///
    /// * `packets` — Ordered TLS 1.3 `application_data` ciphertext record bytes (one outer record per element).
    /// * `aad` — AEAD additional data for each record (often empty when integrating minimal transports).
    ///
    /// # Returns
    ///
    /// `Ok(())` when decrypted handshake messages match the strict ordering enforced by
    /// [`Connection::noxtls_process_server_handshake_flight`].
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when decryption, parsing, or handshake policy checks fail.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_process_tls13_server_encrypted_handshake_flight(
        &mut self,
        packets: &[Vec<u8>],
        aad: &[u8],
    ) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() || self.version.is_dtls() {
            return Err(Error::StateError(
                "tls13 encrypted server flight requires tls 1.3 non-dtls connection",
            ));
        }
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "tls13 encrypted server flight requires server hello received state",
            ));
        }
        self.noxtls_derive_handshake_secret()?;
        let mut messages = Vec::new();
        for packet in packets {
            let (inner, content_type) = self.noxtls_open_tls13_record_packet(packet, aad)?;
            if content_type != RecordContentType::Handshake.to_u8() {
                return Err(Error::ParseFailure(
                    "tls13 encrypted server flight inner record must be handshake",
                ));
            }
            let parts = split_tls13_handshake_payload(&inner)?;
            messages.extend(parts);
        }
        if messages.len() < 4 {
            return Err(Error::ParseFailure(
                "tls13 decrypted server handshake flight is too short",
            ));
        }
        let mut index = 0_usize;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls13 decrypted server handshake messages",
            ));
        }
        Ok(())
    }

    /// Processes TLS 1.2 server handshake flight in canonical order.
    ///
    /// Expected sequence:
    /// * `ServerHello`
    /// * `Certificate`
    /// * optional `ServerKeyExchange`
    /// * optional `CertificateRequest`
    /// * `ServerHelloDone`
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `ServerCertificateVerified`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_server_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 server flight processing requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ClientHelloSent {
            return Err(Error::StateError(
                "tls12 server flight can only be processed after client hello",
            ));
        }
        if messages.len() < 3 {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight is too short",
            ));
        }

        let mut index = 0_usize;
        self.noxtls_recv_server_hello(&messages[index])?;
        index += 1;
        let (next_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight expected certificate after server hello",
            ));
        }
        self.noxtls_recv_tls12_server_certificate(&messages[index])?;
        index += 1;

        while index < messages.len() {
            let (message_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
            if message_type == HANDSHAKE_SERVER_KEY_EXCHANGE {
                self.noxtls_recv_tls12_server_key_exchange(&messages[index])?;
                index += 1;
                continue;
            }
            if message_type == HANDSHAKE_CERTIFICATE_REQUEST {
                self.noxtls_recv_tls12_server_certificate_request(&messages[index])?;
                index += 1;
                continue;
            }
            break;
        }

        if index >= messages.len() {
            return Err(Error::ParseFailure(
                "tls12 server handshake flight missing server hello done",
            ));
        }
        self.noxtls_recv_tls12_server_hello_done(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls12 server handshake messages",
            ));
        }
        self.state = HandshakeState::ServerCertificateVerified;
        Ok(())
    }

    /// Records an inbound TLS 1.2 ChangeCipherSpec transition before client Finished.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// `Ok(())` when the transition is accepted for the current handshake phase.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_tls12_change_cipher_spec(&mut self) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 change cipher spec requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ServerCertificateVerified {
            return Err(Error::StateError(
                "tls12 change cipher spec can only be processed after server handshake flight",
            ));
        }
        self.tls12_change_cipher_spec_seen = true;
        Ok(())
    }

    /// Processes TLS 1.2 client handshake flight after server has sent `ServerHelloDone`.
    ///
    /// Expected sequence:
    /// * `ClientKeyExchange`
    /// * optional `CertificateVerify`
    /// * `Finished` (requires prior `ChangeCipherSpec` signal)
    ///
    /// # Arguments
    /// * `messages`: Ordered client handshake messages from the peer.
    ///
    /// # Returns
    /// `Ok(())` when client flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_client_handshake_flight(&mut self, messages: &[Vec<u8>]) -> Result<()> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 client flight processing requires tls1.2 connection version",
            ));
        }
        if self.state != HandshakeState::ServerCertificateVerified {
            return Err(Error::StateError(
                "tls12 client flight can only be processed after server handshake flight",
            ));
        }
        if messages.len() < 2 {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight is too short",
            ));
        }
        let mut index = 0_usize;
        let (next_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight expected client key exchange first",
            ));
        }
        self.noxtls_recv_tls12_client_key_exchange(&messages[index])?;
        index += 1;

        if index < messages.len() {
            let (message_type, _body) = noxtls_parse_handshake_message(&messages[index])?;
            if message_type == HANDSHAKE_CERTIFICATE_VERIFY {
                self.noxtls_recv_tls12_client_certificate_verify(&messages[index])?;
                index += 1;
            }
        }

        if !self.tls12_change_cipher_spec_seen {
            return Err(Error::ParseFailure(
                "tls12 expected change cipher spec before finished",
            ));
        }
        if index >= messages.len() {
            return Err(Error::ParseFailure(
                "tls12 client handshake flight missing finished message",
            ));
        }
        self.noxtls_recv_tls12_client_finished(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing tls12 client handshake messages",
            ));
        }

        self.tls12_change_cipher_spec_seen = false;
        self.state = HandshakeState::Finished;
        Ok(())
    }

    /// Processes TLS 1.2 server flight and attempts automatic alert emission on failure.
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from server.
    ///
    /// # Returns
    /// `Ok(())` on successful processing, or `Err((error, alert_packet))` where `alert_packet`
    /// contains the mapped TLS 1.2 alert packet when emission succeeds on this connection.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_server_handshake_flight_with_alert(
        &mut self,
        messages: &[Vec<u8>],
    ) -> core::result::Result<(), (Error, Option<Vec<u8>>)> {
        match self.noxtls_process_tls12_server_handshake_flight(messages) {
            Ok(()) => Ok(()),
            Err(error) => {
                let alert_packet = self.noxtls_send_tls12_alert_for_handshake_error(&error).ok();
                Err((error, alert_packet))
            }
        }
    }

    /// Processes TLS 1.2 client flight and attempts automatic alert emission on failure.
    ///
    /// # Arguments
    /// * `messages`: Ordered handshake messages from client.
    ///
    /// # Returns
    /// `Ok(())` on successful processing, or `Err((error, alert_packet))` where `alert_packet`
    /// contains the mapped TLS 1.2 alert packet when emission succeeds on this connection.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_tls12_client_handshake_flight_with_alert(
        &mut self,
        messages: &[Vec<u8>],
    ) -> core::result::Result<(), (Error, Option<Vec<u8>>)> {
        match self.noxtls_process_tls12_client_handshake_flight(messages) {
            Ok(()) => Ok(()),
            Err(error) => {
                let alert_packet = self.noxtls_send_tls12_alert_for_handshake_error(&error).ok();
                Err((error, alert_packet))
            }
        }
    }

    /// Maps a TLS 1.2 handshake processing error into a deterministic fatal alert description.
    ///
    /// # Arguments
    /// * `error`: Handshake processing error returned by TLS 1.2 sequencing/parsing helpers.
    ///
    /// # Returns
    /// `(AlertLevel::Fatal, AlertDescription)` selected for wire-level signaling policy.
    #[must_use]
    /// # Arguments
    ///
    /// * `error` — `error: &Error`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls12_alert_for_handshake_error(error: &Error) -> (AlertLevel, AlertDescription) {
        let description = match error {
            Error::StateError(message) => {
                if message.contains("can only be processed")
                    || message.contains("expected")
                    || message.contains("missing")
                {
                    AlertDescription::UnexpectedMessage
                } else {
                    AlertDescription::InternalError
                }
            }
            Error::ParseFailure(message) | Error::InvalidLength(message) => {
                if message.contains("expected")
                    || message.contains("missing")
                    || message.contains("unexpected trailing")
                    || message.contains("invalid")
                    || message.contains("malformed")
                    || message.contains("must be empty")
                    || message.contains("must not be empty")
                {
                    AlertDescription::UnexpectedMessage
                } else {
                    AlertDescription::IllegalParameter
                }
            }
            Error::InvalidEncoding(_message) => AlertDescription::IllegalParameter,
            Error::UnsupportedFeature(_message) | Error::CryptoFailure(_message) => {
                AlertDescription::HandshakeFailure
            }
        };
        (AlertLevel::Fatal, description)
    }

    /// Parses and records a TLS 1.2 Certificate handshake message with basic structure checks.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_server_certificate(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "tls12 certificate can only be processed after server hello",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE {
            return Err(Error::ParseFailure(
                "invalid tls12 certificate message type",
            ));
        }
        let certificates = noxtls_parse_tls12_certificate_list(body)?;
        if self.tls13_require_certificate_auth {
            self.noxtls_validate_tls13_server_certificate_chain(&certificates)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateReceived;
        Ok(())
    }

    /// Parses and records a TLS 1.2 ServerKeyExchange message when present.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_server_key_exchange(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 server key exchange can only be processed after certificate",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_SERVER_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "invalid tls12 server key exchange message type",
            ));
        }
        noxtls_parse_tls12_server_key_exchange_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 CertificateRequest message when server asks for client auth.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_server_certificate_request(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 certificate request can only be processed after certificate",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE_REQUEST {
            return Err(Error::ParseFailure(
                "invalid tls12 certificate request message type",
            ));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 certificate request body must not be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 ServerHelloDone message as end-of-server-flight marker.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_server_hello_done(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "tls12 server hello done can only be processed after certificate flight",
            ));
        }
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_SERVER_HELLO_DONE {
            return Err(Error::ParseFailure(
                "invalid tls12 server hello done message type",
            ));
        }
        if !body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 server hello done body must be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records a TLS 1.2 ClientKeyExchange message as client-flight entrypoint.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_client_key_exchange(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
            return Err(Error::ParseFailure(
                "invalid tls12 client key exchange message type",
            ));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure(
                "tls12 client key exchange body must not be empty",
            ));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records an optional TLS 1.2 client CertificateVerify handshake message.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_client_certificate_verify(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_CERTIFICATE_VERIFY {
            return Err(Error::ParseFailure(
                "invalid tls12 client certificate verify message type",
            ));
        }
        noxtls_parse_tls12_certificate_verify_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Parses and records TLS 1.2 client Finished handshake message shape.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `msg` — `msg: &[u8]`.
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
    fn noxtls_recv_tls12_client_finished(&mut self, msg: &[u8]) -> Result<()> {
        let (message_type, body) = noxtls_parse_handshake_message(msg)?;
        if message_type != HANDSHAKE_FINISHED {
            return Err(Error::ParseFailure("invalid tls12 finished message type"));
        }
        if body.is_empty() {
            return Err(Error::ParseFailure("tls12 finished body must not be empty"));
        }
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Builds a minimal TLS 1.3 Certificate handshake message with one certificate entry.
    ///
    /// # Arguments
    /// * `certificate_der`: DER-encoded certificate bytes.
    ///
    /// # Returns
    /// Encoded Certificate message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_message(certificate_der: &[u8]) -> Result<Vec<u8>> {
        Self::noxtls_build_certificate_message_with_ocsp_staple(certificate_der, None)
    }

    /// Builds a TLS 1.3 Certificate handshake message with optional leaf OCSP staple.
    ///
    /// # Arguments
    /// * `certificate_der`: DER-encoded certificate bytes.
    /// * `ocsp_staple`: Optional stapled OCSP response bytes for leaf certificate entry.
    ///
    /// # Returns
    /// Encoded Certificate message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    pub fn noxtls_build_certificate_message_with_ocsp_staple(
        certificate_der: &[u8],
        ocsp_staple: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if certificate_der.is_empty() {
            return Err(Error::InvalidLength("certificate der must not be empty"));
        }
        if certificate_der.len() > 0x00FF_FFFF {
            return Err(Error::InvalidLength("certificate der is too large"));
        }
        let certificate_extensions = if let Some(staple) = ocsp_staple {
            noxtls_encode_certificate_entry_status_request_extension(staple)?
        } else {
            Vec::new()
        };
        let mut body = Vec::new();
        body.push(0x00); // certificate_request_context length
        let cert_entry_len = 3 + certificate_der.len() + 2 + certificate_extensions.len();
        let list_len = cert_entry_len as u32;
        body.extend_from_slice(&list_len.to_be_bytes()[1..4]);
        let cert_len = certificate_der.len() as u32;
        body.extend_from_slice(&cert_len.to_be_bytes()[1..4]);
        body.extend_from_slice(certificate_der);
        body.extend_from_slice(&(certificate_extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&certificate_extensions);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_CERTIFICATE,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 CertificateVerify handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded CertificateVerify handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_certificate_verify(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerCertificateReceived {
            return Err(Error::StateError(
                "certificate verify can only be processed after certificate",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_CERTIFICATE_VERIFY {
            return Err(Error::ParseFailure("invalid certificate verify type"));
        }
        let (signature_scheme, signature) = noxtls_parse_certificate_verify_fields(body)?;
        if signature.is_empty() {
            return Err(Error::ParseFailure(
                "certificate verify signature must not be empty",
            ));
        }
        if !noxtls_tls13_supported_certificate_verify_signature_scheme(signature_scheme) {
            return Err(Error::UnsupportedFeature(
                "unsupported tls13 certificate verify signature scheme",
            ));
        }
        if self.tls13_require_certificate_auth {
            if !self.tls13_server_certificate_chain_validated {
                return Err(Error::StateError(
                    "certificate verify requires validated server certificate chain",
                ));
            }
            self.noxtls_verify_tls13_server_certificate_verify_signature(signature_scheme, signature)?;
        }
        self.noxtls_append_transcript(msg);
        self.state = HandshakeState::ServerCertificateVerified;
        Ok(())
    }

    /// Builds a minimal TLS 1.3 CertificateVerify handshake message.
    ///
    /// # Arguments
    /// * `signature_scheme`: Signature scheme identifier.
    /// * `signature`: Signature bytes.
    ///
    /// # Returns
    /// Encoded CertificateVerify message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_certificate_verify_message(
        signature_scheme: u16,
        signature: &[u8],
    ) -> Result<Vec<u8>> {
        if signature.is_empty() {
            return Err(Error::InvalidLength(
                "certificate verify signature must not be empty",
            ));
        }
        if signature.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidLength(
                "certificate verify signature is too large",
            ));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&signature_scheme.to_be_bytes());
        body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        body.extend_from_slice(signature);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_CERTIFICATE_VERIFY,
            &body,
        ))
    }

    /// Derives a prototype handshake secret from the selected transcript hash bytes.
    ///
    /// # Arguments
    /// * `self`: Connection with ServerHello already processed.
    ///
    /// # Returns
    /// 32-byte derived handshake secret.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_derive_handshake_secret(&mut self) -> Result<[u8; 32]> {
        if self.version.uses_tls13_handshake_semantics() {
            if self.state != HandshakeState::ServerHelloReceived {
                return Err(Error::StateError(
                    "tls13 handshake traffic keys require server hello received state",
                ));
            }
        } else if self.state != HandshakeState::ServerHelloReceived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError(
                "cannot derive handshake secret before server hello",
            ));
        }
        let noxtls_transcript_hash = self.noxtls_transcript_hash();
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        noxtls_tls13_debug_log(
            "tls13.kdf.hash_algorithm",
            noxtls_hash_algorithm_name(noxtls_hash_algorithm),
        );
        noxtls_tls13_debug_log_bytes("tls13.kdf.transcript_hash", &noxtls_transcript_hash);
        if self.version.uses_tls13_handshake_semantics() {
            if let Some(secret) = self.tls13_shared_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.shared_secret_input", secret);
            } else {
                noxtls_tls13_debug_log("tls13.kdf.shared_secret_input", "none");
            }
        }
        let secret_material = match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => noxtls_derive_tls13_handshake_secret(
                noxtls_hash_algorithm,
                self.tls13_shared_secret
                    .as_ref()
                    .map_or(&noxtls_transcript_hash, |secret| secret),
                self.noxtls_selected_cipher_suite,
            )?,
            TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let prk = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &noxtls_transcript_hash);
                noxtls_tls12_prf_for_hash(
                    noxtls_hash_algorithm,
                    &prk,
                    b"handshake secret",
                    &noxtls_transcript_hash,
                    32,
                )?
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 => {
                let prk = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &noxtls_transcript_hash);
                noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, &prk, b"handshake secret", 32)?
            }
        };
        noxtls_tls13_debug_log_bytes("tls13.kdf.handshake_secret", &secret_material);
        self.noxtls_install_traffic_keys(noxtls_hash_algorithm, &secret_material, &noxtls_transcript_hash)?;
        if self.version.uses_tls13_handshake_semantics() {
            if let Some(secret) = self.tls13_client_handshake_traffic_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.client_hs_traffic_secret", secret);
            }
            if let Some(secret) = self.tls13_server_handshake_traffic_secret.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.kdf.server_hs_traffic_secret", secret);
            }
            if let Some(key) = self.client_write_key.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.client_write_key", key);
            }
            if let Some(key) = self.server_write_key.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.server_write_key", key);
            }
            if let Some(iv) = self.client_write_iv.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.client_write_iv", iv);
            }
            if let Some(iv) = self.server_write_iv.as_ref() {
                noxtls_tls13_debug_log_bytes("tls13.record.server_write_iv", iv);
            }
        }
        self.handshake_secret = Some(secret_material.clone());
        let mut secret = [0_u8; 32];
        let copy_len = secret_material.len().min(32);
        secret[..copy_len].copy_from_slice(&secret_material[..copy_len]);
        self.state = HandshakeState::KeysDerived;
        Ok(secret)
    }

    /// Finalizes the handshake and records verify data in transcript history.
    ///
    /// # Arguments
    /// * `verify_data`: Finished verify_data bytes to validate and record.
    ///
    /// # Returns
    /// `Ok(())` when Finished verification succeeds.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_finish(&mut self, verify_data: &[u8]) -> Result<()> {
        if self.state != HandshakeState::KeysDerived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError("noxtls_finish must follow key derivation"));
        }
        let expected = self.noxtls_compute_expected_finished()?;
        if verify_data != expected.as_slice() {
            return Err(Error::CryptoFailure("finished verify_data mismatch"));
        }
        if self.version.uses_tls13_handshake_semantics() {
            let finished_message = noxtls_encode_handshake_message(HANDSHAKE_FINISHED, verify_data);
            self.noxtls_append_transcript(&finished_message);
        } else {
            self.noxtls_append_transcript(verify_data);
        }
        self.state = HandshakeState::Finished;
        Ok(())
    }

    /// Parses a TLS 1.3 Finished handshake wrapper and validates verify_data.
    ///
    /// # Arguments
    /// * `msg`: Encoded Finished handshake message.
    ///
    /// # Returns
    /// `Ok(())` when Finished verifies and state transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_finished_message(&mut self, msg: &[u8]) -> Result<()> {
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_FINISHED {
            return Err(Error::ParseFailure("invalid finished type"));
        }
        if self.state != HandshakeState::KeysDerived
            && self.state != HandshakeState::ServerCertificateVerified
        {
            return Err(Error::StateError("noxtls_finish must follow key derivation"));
        }
        let expected_len = self.noxtls_compute_expected_finished()?.len();
        if body.len() != expected_len {
            return Err(Error::ParseFailure("finished verify_data length mismatch"));
        }
        self.noxtls_finish(body)
    }

    /// Activates TLS 1.3 application traffic keys after local Finished has been sent.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when application traffic keys are installed for post-handshake records.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called outside TLS 1.3 `Finished` state or when
    /// key-schedule material is unavailable.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_activate_tls13_application_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "application traffic key activation requires TLS 1.3 connection",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "application traffic keys can only be activated in finished state",
            ));
        }
        self.noxtls_install_tls13_application_traffic_keys()
    }

    /// Builds local TLS 1.3 Finished handshake message from current transcript state.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Encoded Finished handshake message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_finished_message(&self) -> Result<Vec<u8>> {
        let verify_data = self.noxtls_compute_finished_verify_data()?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_FINISHED,
            &verify_data,
        ))
    }

    /// Builds a TLS Finished handshake message for the **peer** (e.g. server's Finished on a client `Connection`).
    ///
    /// This wraps [`Self::noxtls_compute_expected_finished`] as a handshake message. Use this when
    /// modeling inbound server Finished bytes; use [`Self::noxtls_build_finished_message`] for the
    /// local endpoint's Finished to transmit.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// Encoded `Finished` handshake message bytes.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_peer_finished_message(&self) -> Result<Vec<u8>> {
        let verify_data = self.noxtls_compute_expected_finished()?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_FINISHED,
            &verify_data,
        ))
    }

    /// Builds a minimal TLS 1.3 NewSessionTicket handshake message.
    ///
    /// # Arguments
    /// * `ticket_lifetime`: Ticket lifetime in seconds.
    /// * `ticket_age_add`: Obfuscation value for ticket age.
    /// * `ticket_nonce`: Ticket nonce bytes.
    /// * `ticket`: Opaque ticket identity bytes.
    ///
    /// # Returns
    /// Encoded NewSessionTicket message bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_new_session_ticket_message(
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: &[u8],
        ticket: &[u8],
    ) -> Result<Vec<u8>> {
        if ticket_nonce.len() > usize::from(u8::MAX) {
            return Err(Error::InvalidLength("ticket nonce is too large"));
        }
        if ticket.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidLength("ticket identity is too large"));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&ticket_lifetime.to_be_bytes());
        body.extend_from_slice(&ticket_age_add.to_be_bytes());
        body.push(ticket_nonce.len() as u8);
        body.extend_from_slice(ticket_nonce);
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        body.extend_from_slice(&0_u16.to_be_bytes()); // extensions length
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_NEW_SESSION_TICKET,
            &body,
        ))
    }

    /// Parses and records a TLS 1.3 NewSessionTicket handshake message.
    ///
    /// # Arguments
    /// * `msg`: Encoded NewSessionTicket handshake message.
    ///
    /// # Returns
    /// `Ok(())` when message type validates and transcript is updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_new_session_ticket_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "noxtls_new session ticket requires finished handshake state",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_NEW_SESSION_TICKET {
            return Err(Error::ParseFailure("invalid noxtls_new session ticket type"));
        }
        noxtls_parse_new_session_ticket_body(body)?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Builds a TLS 1.3 KeyUpdate handshake message.
    ///
    /// # Arguments
    /// * `request_update`: Whether peer should also noxtls_update its sending keys.
    ///
    /// # Returns
    /// Encoded KeyUpdate message bytes.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_key_update_message(request_update: bool) -> Vec<u8> {
        let request = if request_update { 1_u8 } else { 0_u8 };
        noxtls_encode_handshake_message(HANDSHAKE_KEY_UPDATE, &[request])
    }

    /// Parses a TLS 1.3 KeyUpdate handshake message and rotates traffic keys.
    ///
    /// # Arguments
    /// * `msg`: Encoded KeyUpdate handshake message.
    ///
    /// # Returns
    /// `Ok(())` when KeyUpdate parses and local keys rotate successfully.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_key_update_message(&mut self, msg: &[u8]) -> Result<()> {
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "key noxtls_update requires finished handshake state",
            ));
        }
        let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
        if handshake_type != HANDSHAKE_KEY_UPDATE {
            return Err(Error::ParseFailure("invalid key noxtls_update type"));
        }
        if body.len() != 1 || body[0] > 1 {
            return Err(Error::ParseFailure("invalid key noxtls_update request value"));
        }
        self.noxtls_update_tls13_traffic_keys()?;
        self.noxtls_append_transcript(msg);
        Ok(())
    }

    /// Computes the current transcript hash bytes for post-handshake key schedule use.
    ///
    /// # Returns
    /// Current transcript hash bytes from selected hash noxtls_algorithm.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_transcript_hash(&self) -> Vec<u8> {
        self.noxtls_transcript_hash.noxtls_snapshot_hash()
    }

    /// Returns currently negotiated cipher suite, if known from ServerHello.
    ///
    /// # Returns
    /// Selected cipher suite when negotiation has completed.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, `Some` as described by the return type; see the function body for when `None` is returned.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_selected_cipher_suite(&self) -> Option<CipherSuite> {
        self.noxtls_selected_cipher_suite
    }

    /// Builds a minimally-encoded TLS ServerHello handshake message.
    ///
    /// # Arguments
    /// * `version`: Protocol version to encode.
    /// * `suite`: Selected cipher suite to advertise.
    /// * `random`: 32-byte ServerHello random value.
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
    pub fn noxtls_build_server_hello(
        version: TlsVersion,
        suite: CipherSuite,
        random: &[u8],
    ) -> Result<Vec<u8>> {
        if random.len() != 32 {
            return Err(Error::InvalidLength("server hello random must be 32 bytes"));
        }
        let body = noxtls_encode_server_hello_body(version, suite, random)?;
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_SERVER_HELLO,
            &body,
        ))
    }

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

    /// Builds a TLS ServerHello with randomness sourced from HMAC-DRBG.
    ///
    /// # Arguments
    /// * `version`: Protocol version to encode.
    /// * `suite`: Selected cipher suite to advertise.
    /// * `drbg`: DRBG instance used to generate ServerHello random bytes.
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
    pub fn noxtls_build_server_hello_auto(
        version: TlsVersion,
        suite: CipherSuite,
        drbg: &mut HmacDrbgSha256,
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"server_hello_random")?;
        Self::noxtls_build_server_hello(version, suite, &random)
    }

    /// Parses a ClientHello and returns advertised cipher suites in wire order.
    ///
    /// # Arguments
    /// * `msg`: Encoded ClientHello handshake message.
    ///
    /// # Returns
    /// Supported cipher suites offered by the client.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_parse_client_hello_cipher_suites(msg: &[u8]) -> Result<Vec<CipherSuite>> {
        noxtls_parse_client_hello_info(msg).map(|hello| hello.offered_cipher_suites)
    }

    /// Parses a ClientHello into suites and selected extension metadata.
    ///
    /// # Arguments
    /// * `msg`: Encoded ClientHello handshake message.
    ///
    /// # Returns
    /// Parsed `ClientHelloInfo` with suites and extension summary.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_parse_client_hello_info(msg: &[u8]) -> Result<ClientHelloInfo> {
        noxtls_parse_client_hello_info(msg)
    }

    /// Builds TLS 1.3 server CertificateVerify signed content from transcript hash.
    ///
    /// # Arguments
    /// * `noxtls_transcript_hash`: Transcript hash bytes for the signing context.
    ///
    /// # Returns
    /// Byte vector to be signed/verified for server CertificateVerify.
    #[must_use]
    /// # Arguments
    ///
    /// * `noxtls_transcript_hash` — `noxtls_transcript_hash: &[u8]`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_server_certificate_verify_content(noxtls_transcript_hash: &[u8]) -> Vec<u8> {
        noxtls_build_tls13_server_certificate_verify_message(noxtls_transcript_hash)
    }

    /// Selects one server-preferred suite that is also offered by the client.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded ClientHello bytes.
    /// * `server_preferred`: Server preference-ordered suite list.
    /// * `version`: Protocol version context for filtering.
    ///
    /// # Returns
    /// Selected mutually-supported cipher suite.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_select_cipher_suite_from_client_hello(
        client_hello: &[u8],
        server_preferred: &[CipherSuite],
        version: TlsVersion,
    ) -> Result<CipherSuite> {
        let hello = noxtls_parse_client_hello_info(client_hello)?;
        noxtls_pick_intersection_suite(&hello, server_preferred, version)
    }

    /// Builds a ServerHello by negotiating against offered client cipher suites.
    ///
    /// # Arguments
    /// * `version`: Protocol version to encode.
    /// * `client_hello`: Encoded ClientHello bytes.
    /// * `server_random`: 32-byte ServerHello random value.
    /// * `server_preferred`: Server preference-ordered suite list.
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
    pub fn noxtls_build_server_hello_for_client(
        version: TlsVersion,
        client_hello: &[u8],
        server_random: &[u8],
        server_preferred: &[CipherSuite],
    ) -> Result<Vec<u8>> {
        let selected =
            Self::noxtls_select_cipher_suite_from_client_hello(client_hello, server_preferred, version)?;
        Self::noxtls_build_server_hello(version, selected, server_random)
    }

    /// Builds a ServerHello for a parsed ClientHello with DRBG-generated random.
    ///
    /// # Arguments
    /// * `version`: Protocol version to encode.
    /// * `client_hello`: Encoded ClientHello bytes.
    /// * `server_preferred`: Server preference-ordered suite list.
    /// * `drbg`: DRBG instance used to generate ServerHello random bytes.
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
    pub fn noxtls_build_server_hello_for_client_auto(
        version: TlsVersion,
        client_hello: &[u8],
        server_preferred: &[CipherSuite],
        drbg: &mut HmacDrbgSha256,
    ) -> Result<Vec<u8>> {
        let random = drbg.generate(32, b"server_hello_random")?;
        Self::noxtls_build_server_hello_for_client(version, client_hello, &random, server_preferred)
    }

    /// Computes TLS-style Finished verify_data from transcript hash context.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Expected Finished verify_data bytes for this connection state.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_compute_finished_verify_data(&self) -> Result<Vec<u8>> {
        let hash = self.noxtls_transcript_hash();
        match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
                let hash_len = noxtls_hash_algorithm.output_len();
                let client_hs = self
                    .tls13_client_handshake_traffic_secret
                    .as_ref()
                    .ok_or(Error::StateError(
                        "tls13 client handshake traffic secret must be installed before client finished",
                    ))?;
                let finished_key = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    client_hs,
                    b"finished",
                    &[],
                    hash_len,
                )?;
                Ok(noxtls_finished_hmac_for_hash(
                    noxtls_hash_algorithm,
                    &finished_key,
                    &hash,
                ))
            }
            _ => self.noxtls_compute_expected_finished(),
        }
    }

    /// Rolls TLS 1.3 application traffic keys to the next key-noxtls_update generation.
    ///
    /// # Arguments
    /// * `self`: Finished TLS 1.3 connection with installed application secrets.
    ///
    /// # Returns
    /// `Ok(())` when traffic secrets and record protection keys are updated.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_update_tls13_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 traffic key noxtls_update is only valid for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "tls13 traffic key noxtls_update requires finished handshake",
            ));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let client_secret = self
            .tls13_client_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application client traffic secret is not installed",
            ))?;
        let server_secret = self
            .tls13_server_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application server traffic secret is not installed",
            ))?;
        let next_client_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_secret,
            b"traffic upd",
            &[],
            hash_len,
        )?;
        let next_server_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_secret,
            b"traffic upd",
            &[],
            hash_len,
        )?;
        self.noxtls_install_tls13_record_protection_keys(
            noxtls_hash_algorithm,
            &next_client_secret,
            &next_server_secret,
        )?;
        self.tls13_client_application_traffic_secret = Some(next_client_secret);
        self.tls13_server_application_traffic_secret = Some(next_server_secret);
        self.client_sequence = 0;
        self.server_sequence = 0;
        Ok(())
    }

    /// Derives QUIC Initial secrets for QUIC v1 using the destination connection ID.
    ///
    /// # Arguments
    /// * `destination_connection_id`: QUIC destination connection ID from the client's first Initial packet.
    ///
    /// # Returns
    /// QUIC v1 initial secret bundle containing common, client, and server initial secrets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when the destination connection ID is empty, or other [`noxtls_core::Error`] values from HKDF label expansion.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_initial_secrets_v1(
        destination_connection_id: &[u8],
    ) -> Result<Tls13QuicInitialSecrets> {
        if destination_connection_id.is_empty() {
            return Err(Error::InvalidLength(
                "quic destination connection id must not be empty",
            ));
        }
        let initial_secret =
            noxtls_hkdf_extract_sha256(&TLS13_QUIC_V1_INITIAL_SALT, destination_connection_id)
                .to_vec();
        let client_initial_secret = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &initial_secret,
            b"client in",
            &[],
            32,
        )?;
        let server_initial_secret = noxtls_tls13_expand_label_for_hash(
            HashAlgorithm::Sha256,
            &initial_secret,
            b"server in",
            &[],
            32,
        )?;
        Ok(Tls13QuicInitialSecrets {
            initial_secret,
            client_initial_secret,
            server_initial_secret,
        })
    }

    /// Derives QUIC packet-protection key material from one traffic secret.
    ///
    /// # Arguments
    /// * `noxtls_hash_algorithm`: Hash profile used for TLS HKDF label expansion.
    /// * `traffic_secret`: QUIC traffic secret at a specific encryption level.
    /// * `key_len`: AEAD key length in bytes.
    /// * `header_protection_key_len`: Header-protection key length in bytes.
    ///
    /// # Returns
    /// QUIC key, IV, and header-protection key derived from `traffic_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when key lengths are zero, or other [`noxtls_core::Error`] values from HKDF label expansion.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_packet_protection_keys(
        noxtls_hash_algorithm: HashAlgorithm,
        traffic_secret: &[u8],
        key_len: usize,
        header_protection_key_len: usize,
    ) -> Result<Tls13QuicPacketProtectionKeys> {
        if key_len == 0 {
            return Err(Error::InvalidLength(
                "quic key length must be greater than zero",
            ));
        }
        if header_protection_key_len == 0 {
            return Err(Error::InvalidLength(
                "quic header protection key length must be greater than zero",
            ));
        }
        let key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic key",
            &[],
            key_len,
        )?;
        let iv = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic iv",
            &[],
            12,
        )?;
        let header_protection_key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            traffic_secret,
            b"quic hp",
            &[],
            header_protection_key_len,
        )?;
        Ok(Tls13QuicPacketProtectionKeys {
            key,
            iv,
            header_protection_key,
        })
    }

    /// Returns current QUIC handshake and 1-RTT traffic secret snapshots.
    ///
    /// # Returns
    /// Bundle containing client/server handshake and application traffic secrets.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called before corresponding TLS 1.3 secrets are installed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_tls13_quic_traffic_secret_snapshot(&self) -> Result<Tls13QuicTrafficSecretSnapshot> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "quic traffic secret snapshot is only defined for TLS 1.3",
            ));
        }
        let client_handshake_secret =
            self.tls13_client_handshake_traffic_secret
                .clone()
                .ok_or(Error::StateError(
                    "tls13 client handshake traffic secret is not installed",
                ))?;
        let server_handshake_secret =
            self.tls13_server_handshake_traffic_secret
                .clone()
                .ok_or(Error::StateError(
                    "tls13 server handshake traffic secret is not installed",
                ))?;
        let client_application_secret = self
            .tls13_client_application_traffic_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 client application traffic secret is not installed",
            ))?;
        let server_application_secret = self
            .tls13_server_application_traffic_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 server application traffic secret is not installed",
            ))?;
        Ok(Tls13QuicTrafficSecretSnapshot {
            client_handshake_secret,
            server_handshake_secret,
            client_application_secret,
            server_application_secret,
        })
    }

    /// Derives next QUIC 1-RTT traffic secrets from currently installed application secrets.
    ///
    /// # Returns
    /// Next-generation client/server application secrets derived via `quic ku`.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when called before TLS 1.3 application secrets are installed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_derive_tls13_quic_next_traffic_secrets(&self) -> Result<Tls13QuicNextTrafficSecrets> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "quic key noxtls_update secrets are only defined for TLS 1.3",
            ));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let client_secret = self
            .tls13_client_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application client traffic secret is not installed",
            ))?;
        let server_secret = self
            .tls13_server_application_traffic_secret
            .as_ref()
            .ok_or(Error::StateError(
                "tls13 application server traffic secret is not installed",
            ))?;
        let client_next_application_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_secret,
            b"quic ku",
            &[],
            hash_len,
        )?;
        let server_next_application_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_secret,
            b"quic ku",
            &[],
            hash_len,
        )?;
        Ok(Tls13QuicNextTrafficSecrets {
            client_next_application_secret,
            server_next_application_secret,
        })
    }

    /// Exports QUIC-specific keying material using `EXPORTER-QUIC ...` labels.
    ///
    /// # Arguments
    /// * `label`: QUIC exporter label, for example [`TLS13_QUIC_EXPORTER_LABEL_CLIENT_1RTT`].
    /// * `context`: Exporter context bytes.
    /// * `len`: Requested output length in bytes.
    ///
    /// # Returns
    /// Exported keying material bytes bound to transcript and QUIC exporter label.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StateError`] when label namespace is not QUIC, or other exporter errors from [`Self::noxtls_export_keying_material`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_export_quic_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        if !label.starts_with(b"EXPORTER-QUIC ") {
            return Err(Error::StateError(
                "quic exporter requires label prefix EXPORTER-QUIC ",
            ));
        }
        self.noxtls_export_keying_material(label, context, len)
    }

    /// Exports keying material from TLS 1.3 exporter secret for application protocols.
    ///
    /// # Arguments
    /// * `label`: Exporter label namespace chosen by the caller.
    /// * `context`: Application-specific exporter context bytes.
    /// * `len`: Requested output keying material length.
    ///
    /// # Returns
    /// Exported keying material bytes bound to transcript and context.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "key exporter is currently only modeled for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "key exporter requires finished handshake state",
            ));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let exporter_master =
            self.tls13_exporter_master_secret
                .as_ref()
                .ok_or(Error::StateError(
                    "tls13 exporter master secret is not installed",
                ))?;
        let context_hash = noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, context);
        let exporter_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            exporter_master,
            b"exporter",
            &context_hash,
            hash_len,
        )?;
        noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &exporter_secret,
            label,
            &context_hash,
            len,
        )
    }

    /// Returns TLS 1.3 resumption master secret snapshot for ticket/resumption plumbing.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    /// Cloned resumption master secret bytes for current handshake epoch.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_resumption_master_secret(&self) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "resumption master secret is only defined for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "resumption master secret requires finished handshake state",
            ));
        }
        self.noxtls_tls13_resumption_master_secret
            .clone()
            .ok_or(Error::StateError(
                "tls13 resumption master secret is not installed",
            ))
    }

    /// Derives a TLS 1.3 resumption PSK from resumption master secret and ticket nonce.
    ///
    /// # Arguments
    /// * `ticket_nonce`: NewSessionTicket ticket_nonce bytes.
    ///
    /// # Returns
    /// Resumption PSK bytes sized to the negotiated transcript hash output length.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_derive_tls13_resumption_psk(&self, ticket_nonce: &[u8]) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "resumption psk derivation is only defined for TLS 1.3",
            ));
        }
        if ticket_nonce.is_empty() {
            return Err(Error::InvalidLength("ticket nonce must not be empty"));
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let resumption_master =
            self.noxtls_tls13_resumption_master_secret
                .as_ref()
                .ok_or(Error::StateError(
                    "tls13 resumption master secret is not installed",
                ))?;
        noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            resumption_master,
            b"resumption",
            ticket_nonce,
            hash_len,
        )
    }

    /// Issues one local TLS 1.3 resumption ticket from current resumption master secret.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    ///
    /// # Returns
    /// `ResumptionTicket` containing identity, nonce, and age fields.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_issue_tls13_resumption_ticket(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
    ) -> Result<ResumptionTicket> {
        self.noxtls_issue_tls13_resumption_ticket_with_time(drbg, age_add, 0, u64::MAX)
    }

    /// Issues one TLS 1.3 ticket and inserts it into a mutable ticket store.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    /// * `ticket_store`: Mutable ticket cache receiving the issued ticket.
    ///
    /// # Returns
    /// Issued `ResumptionTicket` after insertion into `ticket_store`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_issue_tls13_resumption_ticket_into_store(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
        ticket_store: &mut TicketStore,
    ) -> Result<ResumptionTicket> {
        let ticket = self.noxtls_issue_tls13_resumption_ticket(drbg, age_add)?;
        ticket_store.insert(ticket.clone());
        Ok(ticket)
    }

    /// Issues one local TLS 1.3 resumption ticket with explicit issuance time and lifetime.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    /// * `issued_at_ms`: Server-local issue timestamp in milliseconds.
    /// * `lifetime_ms`: Ticket lifetime window in milliseconds.
    ///
    /// # Returns
    /// `ResumptionTicket` containing identity, nonce, and age policy fields.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_issue_tls13_resumption_ticket_with_time(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
        issued_at_ms: u64,
        lifetime_ms: u64,
    ) -> Result<ResumptionTicket> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "resumption ticket issuance is only defined for TLS 1.3",
            ));
        }
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "resumption ticket issuance requires finished handshake state",
            ));
        }
        let nonce = drbg.generate(16, b"tls13_ticket_nonce")?;
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let identity = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &self.noxtls_tls13_resumption_master_secret()?,
            b"ticket",
            &nonce,
            16,
        )?;
        Ok(ResumptionTicket {
            identity,
            ticket_nonce: nonce,
            obfuscated_ticket_age: age_add,
            age_add,
            issued_at_ms,
            lifetime_ms,
            max_early_data_size: TLS_MAX_RECORD_PLAINTEXT_LEN as u32,
            consumed: false,
        })
    }

    /// Issues one local TLS 1.3 resumption ticket with explicit early-data size allowance.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    /// * `issued_at_ms`: Server-local issue timestamp in milliseconds.
    /// * `lifetime_ms`: Ticket lifetime window in milliseconds.
    /// * `max_early_data_size`: Maximum accepted 0-RTT plaintext bytes for this ticket.
    ///
    /// # Returns
    /// `ResumptionTicket` containing identity, nonce, age policy fields, and early-data limit.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_issue_tls13_resumption_ticket_with_time_and_early_data(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
        issued_at_ms: u64,
        lifetime_ms: u64,
        max_early_data_size: u32,
    ) -> Result<ResumptionTicket> {
        let mut ticket =
            self.noxtls_issue_tls13_resumption_ticket_with_time(drbg, age_add, issued_at_ms, lifetime_ms)?;
        ticket.max_early_data_size = max_early_data_size;
        Ok(ticket)
    }

    /// Issues one timed TLS 1.3 ticket and inserts it into a mutable ticket store.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    /// * `issued_at_ms`: Server-local issue timestamp in milliseconds.
    /// * `lifetime_ms`: Ticket lifetime window in milliseconds.
    /// * `ticket_store`: Mutable ticket cache receiving the issued ticket.
    ///
    /// # Returns
    /// Issued `ResumptionTicket` after insertion into `ticket_store`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_issue_tls13_resumption_ticket_with_time_into_store(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
        issued_at_ms: u64,
        lifetime_ms: u64,
        ticket_store: &mut TicketStore,
    ) -> Result<ResumptionTicket> {
        let ticket =
            self.noxtls_issue_tls13_resumption_ticket_with_time(drbg, age_add, issued_at_ms, lifetime_ms)?;
        ticket_store.insert(ticket.clone());
        Ok(ticket)
    }

    /// Issues one timed TLS 1.3 ticket with early-data allowance and inserts it into a store.
    ///
    /// # Arguments
    /// * `drbg`: DRBG used to generate per-ticket nonce material.
    /// * `age_add`: Ticket age_add value used for obfuscated ticket age encoding.
    /// * `issued_at_ms`: Server-local issue timestamp in milliseconds.
    /// * `lifetime_ms`: Ticket lifetime window in milliseconds.
    /// * `max_early_data_size`: Maximum accepted 0-RTT plaintext bytes for this ticket.
    /// * `ticket_store`: Mutable ticket cache receiving the issued ticket.
    ///
    /// # Returns
    /// Issued `ResumptionTicket` after insertion into `ticket_store`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn noxtls_issue_tls13_resumption_ticket_with_time_and_early_data_into_store(
        &self,
        drbg: &mut HmacDrbgSha256,
        age_add: u32,
        issued_at_ms: u64,
        lifetime_ms: u64,
        max_early_data_size: u32,
        ticket_store: &mut TicketStore,
    ) -> Result<ResumptionTicket> {
        let ticket = self.noxtls_issue_tls13_resumption_ticket_with_time_and_early_data(
            drbg,
            age_add,
            issued_at_ms,
            lifetime_ms,
            max_early_data_size,
        )?;
        ticket_store.insert(ticket.clone());
        Ok(ticket)
    }

    /// Computes TLS 1.3 PSK binder bytes for a truncated ClientHello transcript.
    ///
    /// # Arguments
    /// * `psk`: Candidate PSK bytes to validate.
    /// * `truncated_client_hello`: ClientHello bytes up to (but excluding) binder list.
    ///
    /// # Returns
    /// Binder bytes using the connection's negotiated hash policy.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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

    /// Seals outbound application data using installed client traffic keys.
    ///
    /// # Arguments
    /// * `plaintext`: Application plaintext bytes to protect.
    /// * `aad`: Additional authenticated data for record protection.
    ///
    /// # Returns
    /// `ProtectedRecord` containing sequence, ciphertext, and tag.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_record(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<ProtectedRecord> {
        if self.state != HandshakeState::Finished {
            return Err(Error::StateError(
                "cannot seal record before handshake noxtls_finish",
            ));
        }
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        if self.client_sequence == u64::MAX {
            return Err(Error::StateError("client record sequence exhausted"));
        }
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before sealing records",
        ))?;
        let key = self
            .client_write_key
            .ok_or(Error::StateError("client write key is not installed"))?;
        let iv = self
            .client_write_iv
            .ok_or(Error::StateError("client write iv is not installed"))?;
        let nonce = noxtls_build_record_nonce(&iv, self.client_sequence);
        let (ciphertext, tag) = match suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => {
                noxtls_chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext)?
            }
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
                    "tls 1.3 aes suites must define traffic key length",
                ))?;
                let cipher = AesCipher::noxtls_new(&key[..key_len])?;
                noxtls_aes_gcm_encrypt(&cipher, &nonce, aad, plaintext)?
            }
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                let cipher = AesCipher::noxtls_new(&key[..16])?;
                noxtls_aes_gcm_encrypt(&cipher, &nonce, aad, plaintext)?
            }
        };
        let record = ProtectedRecord {
            sequence: self.client_sequence,
            ciphertext,
            tag,
        };
        self.client_sequence = self.client_sequence.wrapping_add(1);
        Ok(record)
    }

    /// Seals a modeled TLS 1.3 early-data (0-RTT) record from PSK-derived traffic keys.
    ///
    /// This is only allowed in [`HandshakeState::ClientHelloSent`], matching the wire protocol
    /// rule that 0-RTT application data is sent in the same flight as `ClientHello`.
    ///
    /// # Arguments
    /// * `psk`: Resumption/external PSK bytes used to derive early-data traffic secret.
    /// * `plaintext`: Early-data plaintext bytes to protect.
    /// * `aad`: Additional authenticated data for record protection.
    /// * `sequence`: Record sequence number used for nonce construction.
    ///
    /// # Returns
    /// `ProtectedRecord` carrying encrypted early-data payload.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// Inherits the same [`HandshakeState::ClientHelloSent`] requirement as [`Self::noxtls_seal_tls13_early_data_record`].
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when packet decoding, policy, replay checks, or inner content validation fails.
    ///
    /// # Panics
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when acceptance, key derivation, packet decoding, or policy checks fail.
    ///
    /// # Panics
    ///
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
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when acceptance, key derivation, packet decoding, or policy checks fail.
    ///
    /// # Panics
    ///
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

    /// Opens inbound application data using installed server traffic keys.
    ///
    /// # Arguments
    /// * `record`: Protected record to decrypt and authenticate.
    /// * `aad`: Additional authenticated data used when sealing.
    ///
    /// # Returns
    /// Decrypted plaintext bytes on successful authentication.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_record(&mut self, record: &ProtectedRecord, aad: &[u8]) -> Result<Vec<u8>> {
        let tls13_handshake_open_allowed = self.version.uses_tls13_handshake_semantics()
            && matches!(
                self.state,
                HandshakeState::KeysDerived
                    | HandshakeState::ServerEncryptedExtensionsReceived
                    | HandshakeState::ServerCertificateRequestReceived
                    | HandshakeState::ServerCertificateReceived
                    | HandshakeState::ServerCertificateVerified
            );
        if self.state != HandshakeState::Finished && !tls13_handshake_open_allowed {
            return Err(Error::StateError(
                "cannot open record before handshake noxtls_finish",
            ));
        }
        if self.server_sequence == u64::MAX {
            return Err(Error::StateError("server record sequence exhausted"));
        }
        if record.sequence != self.server_sequence {
            return Err(Error::StateError(
                "unexpected server record sequence number",
            ));
        }
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before opening records",
        ))?;
        let key = self
            .server_write_key
            .ok_or(Error::StateError("server write key is not installed"))?;
        let iv = self
            .server_write_iv
            .ok_or(Error::StateError("server write iv is not installed"))?;
        let nonce = noxtls_build_record_nonce(&iv, record.sequence);
        let plaintext = match suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => noxtls_chacha20_poly1305_decrypt(
                &key,
                &nonce,
                aad,
                &record.ciphertext,
                &record.tag,
            )?,
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
                    "tls 1.3 aes suites must define traffic key length",
                ))?;
                let cipher = AesCipher::noxtls_new(&key[..key_len])?;
                noxtls_aes_gcm_decrypt(&cipher, &nonce, aad, &record.ciphertext, &record.tag)?
            }
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                let cipher = AesCipher::noxtls_new(&key[..16])?;
                noxtls_aes_gcm_decrypt(&cipher, &nonce, aad, &record.ciphertext, &record.tag)?
            }
        };
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        self.server_sequence = self.server_sequence.wrapping_add(1);
        Ok(plaintext)
    }

    /// Opens a locally-sealed record using client traffic keys for loopback testing.
    ///
    /// # Arguments
    /// * `record`: Protected record sealed with local client keys.
    /// * `aad`: Additional authenticated data used when sealing.
    ///
    /// # Returns
    /// Decrypted plaintext bytes on successful authentication.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_own_record(&self, record: &ProtectedRecord, aad: &[u8]) -> Result<Vec<u8>> {
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before opening own records",
        ))?;
        let key = self
            .client_write_key
            .ok_or(Error::StateError("client write key is not installed"))?;
        let iv = self
            .client_write_iv
            .ok_or(Error::StateError("client write iv is not installed"))?;
        let nonce = noxtls_build_record_nonce(&iv, record.sequence);
        let plaintext = match suite {
            CipherSuite::TlsChacha20Poly1305Sha256 => noxtls_chacha20_poly1305_decrypt(
                &key,
                &nonce,
                aad,
                &record.ciphertext,
                &record.tag,
            )?,
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
                    "tls 1.3 aes suites must define traffic key length",
                ))?;
                let cipher = AesCipher::noxtls_new(&key[..key_len])?;
                noxtls_aes_gcm_decrypt(&cipher, &nonce, aad, &record.ciphertext, &record.tag)?
            }
            CipherSuite::TlsEcdheRsaWithAes128GcmSha256
            | CipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                let cipher = AesCipher::noxtls_new(&key[..16])?;
                noxtls_aes_gcm_decrypt(&cipher, &nonce, aad, &record.ciphertext, &record.tag)?
            }
        };
        if plaintext.len() > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "record plaintext exceeds configured limit",
            ));
        }
        Ok(plaintext)
    }

    /// Seals one TLS 1.2 wire record packet from plaintext and outer content type.
    ///
    /// # Arguments
    /// * `plaintext`: Application plaintext bytes to protect.
    /// * `content_type`: TLS record content type for the outer TLS 1.2 header.
    ///
    /// # Returns
    /// Serialized TLSCiphertext packet bytes (`type || version || len || ciphertext || tag`).
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_tls12_record_packet(
        &mut self,
        plaintext: &[u8],
        content_type: RecordContentType,
    ) -> Result<Vec<u8>> {
        self.noxtls_ensure_tls12_wire_mode()?;
        let sequence = self.client_sequence;
        let aad = self.noxtls_build_tls12_record_aad(sequence, content_type, plaintext.len())?;
        let record = self.noxtls_seal_record(plaintext, &aad)?;
        self.noxtls_encode_tls12_record_packet(&record, content_type)
    }

    /// Opens one inbound TLS 1.2 wire record packet using server traffic keys.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes.
    ///
    /// # Returns
    /// Tuple `(content_type, plaintext)` after successful authentication.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_tls12_record_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<(RecordContentType, Vec<u8>)> {
        self.noxtls_ensure_tls12_wire_mode()?;
        let sequence = self.server_sequence;
        let (record, content_type) = self.noxtls_decode_tls12_record_packet(packet, sequence)?;
        let aad = self.noxtls_build_tls12_record_aad(sequence, content_type, record.ciphertext.len())?;
        let plaintext = self.noxtls_open_record(&record, &aad)?;
        Ok((content_type, plaintext))
    }

    /// Opens one locally-sealed TLS 1.2 wire packet using client traffic keys.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes.
    /// * `sequence`: Record sequence number used during sealing.
    ///
    /// # Returns
    /// Tuple `(content_type, plaintext)` after successful authentication.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_own_tls12_record_packet(
        &self,
        packet: &[u8],
        sequence: u64,
    ) -> Result<(RecordContentType, Vec<u8>)> {
        self.noxtls_ensure_tls12_wire_mode()?;
        let (record, content_type) = self.noxtls_decode_tls12_record_packet(packet, sequence)?;
        let aad = self.noxtls_build_tls12_record_aad(sequence, content_type, record.ciphertext.len())?;
        let plaintext = self.noxtls_open_own_record(&record, &aad)?;
        Ok((content_type, plaintext))
    }

    /// Seals a TLS 1.2 fatal/warning alert into an encrypted TLSCiphertext packet.
    ///
    /// # Arguments
    /// * `level`: TLS alert level byte semantic.
    /// * `description`: TLS alert description codepoint semantic.
    ///
    /// # Returns
    /// Serialized TLS 1.2 alert record packet bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_tls12_alert_packet(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
    ) -> Result<Vec<u8>> {
        if self.version != TlsVersion::Tls12 {
            return Err(Error::StateError(
                "tls12 alert records require TLS 1.2 connection",
            ));
        }
        self.noxtls_seal_tls12_record_packet(
            &[level.to_u8(), description.to_u8()],
            RecordContentType::Alert,
        )
    }

    /// Maps a TLS 1.2 handshake error and seals the corresponding fatal alert packet.
    ///
    /// # Arguments
    /// * `error`: Handshake processing error to map into alert semantics.
    ///
    /// # Returns
    /// Serialized TLS 1.2 alert record packet bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_tls12_alert_for_handshake_error(&mut self, error: &Error) -> Result<Vec<u8>> {
        let (level, description) = Self::noxtls_tls12_alert_for_handshake_error(error);
        self.noxtls_send_tls12_alert_packet(level, description)
    }

    /// Opens a peer TLS 1.2 alert packet and parses `(level, description)` semantics.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes carrying alert content.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_tls12_alert_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        let (content_type, payload) = self.noxtls_open_tls12_record_packet(packet)?;
        self.noxtls_parse_tls12_alert_payload(content_type, &payload)
    }

    /// Opens a locally-sealed TLS 1.2 alert packet for deterministic loopback tests.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes from local alert sealing.
    /// * `sequence`: Sequence value used when the packet was sealed.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_own_tls12_alert_packet(
        &self,
        packet: &[u8],
        sequence: u64,
    ) -> Result<(AlertLevel, AlertDescription)> {
        let (content_type, payload) = self.noxtls_open_own_tls12_record_packet(packet, sequence)?;
        self.noxtls_parse_tls12_alert_payload(content_type, &payload)
    }

    /// Parses TLS 1.2 alert payload shape from already-authenticated TLS record plaintext bytes.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `content_type` — `content_type: RecordContentType`.
    /// * `payload` — `payload: &[u8]`.
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
    fn noxtls_parse_tls12_alert_payload(
        &self,
        content_type: RecordContentType,
        payload: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if content_type != RecordContentType::Alert {
            return Err(Error::ParseFailure("record is not an alert content type"));
        }
        if payload.len() != 2 {
            return Err(Error::ParseFailure("tls12 alert payload must be two bytes"));
        }
        let level =
            AlertLevel::from_u8(payload[0]).ok_or(Error::ParseFailure("unknown alert level"))?;
        let description = AlertDescription::from_u8(payload[1])
            .ok_or(Error::ParseFailure("unknown alert description"))?;
        Ok((level, description))
    }

    /// Encodes a DTLS1.2 datagram record packet from content type, epoch, sequence, and payload.
    ///
    /// # Arguments
    /// * `content_type`: Record content type byte to place in DTLS header.
    /// * `epoch`: DTLS epoch value.
    /// * `sequence`: 48-bit DTLS record sequence number.
    /// * `payload`: Record payload bytes.
    ///
    /// # Returns
    /// Encoded DTLS record datagram bytes (`header || payload`).
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls12_record_packet(
        &self,
        content_type: RecordContentType,
        epoch: u16,
        sequence: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 record packet builder requires DTLS1.2 connection",
            ));
        }
        noxtls_encode_dtls_record_packet(content_type, [0xFE, 0xFD], epoch, sequence, payload)
    }

    /// Parses a DTLS1.2 datagram record packet into header fields and payload bytes.
    ///
    /// # Arguments
    /// * `packet`: Encoded DTLS record datagram bytes.
    ///
    /// # Returns
    /// Tuple of parsed DTLS record header and payload bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_parse_dtls12_record_packet(&self, packet: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 record packet parser requires DTLS1.2 connection",
            ));
        }
        let (header, payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok((header, payload))
    }

    /// Fragments one DTLS1.2 handshake message into transport-sized handshake fragments.
    ///
    /// # Arguments
    /// * `handshake_type`: Handshake message type codepoint.
    /// * `message_seq`: DTLS handshake message sequence value.
    /// * `body`: Full handshake body bytes to fragment.
    /// * `max_fragment_len`: Maximum bytes per fragment payload.
    ///
    /// # Returns
    /// Ordered encoded DTLS handshake fragments.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_fragment_dtls12_handshake_message(
        &self,
        handshake_type: u8,
        message_seq: u16,
        body: &[u8],
        max_fragment_len: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake fragmentation requires DTLS1.2 connection",
            ));
        }
        noxtls_encode_dtls12_handshake_fragments(
            handshake_type,
            message_seq,
            body,
            max_fragment_len,
        )
    }

    /// Reassembles encoded DTLS1.2 handshake fragments into one complete message.
    ///
    /// # Arguments
    /// * `fragments`: Encoded handshake fragments for one message sequence.
    /// * `max_message_len`: Maximum total bytes accepted for one reassembled handshake message.
    ///
    /// # Returns
    /// Tuple of `(handshake_type, message_seq, full_handshake_body)`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_reassemble_dtls12_handshake_fragments(
        &self,
        fragments: &[Vec<u8>],
        max_message_len: usize,
    ) -> Result<(u8, u16, Vec<u8>)> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake reassembly requires DTLS1.2 connection",
            ));
        }
        noxtls_reassemble_dtls12_handshake_fragments(fragments, max_message_len)
    }

    /// Enables or disables DTLS1.2 anti-amplification transmit budget enforcement.
    ///
    /// When enabled, outbound datagrams are capped to `3x` observed inbound bytes until
    /// cookie validation succeeds.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `enforced` — `enforced: bool`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_anti_amplification_enforced(&mut self, enforced: bool) {
        self.dtls12_anti_amplification_enforced = enforced;
    }

    /// Records inbound DTLS datagram size for anti-amplification accounting.
    ///
    /// # Arguments
    /// * `bytes`: Number of bytes received from the peer datagram transport.
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_record_dtls12_inbound_datagram(&mut self, bytes: usize) {
        self.dtls12_inbound_bytes = self.dtls12_inbound_bytes.saturating_add(bytes as u64);
    }

    /// Returns true when sending a datagram of `bytes` would stay within anti-amplification budget.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `bytes` — `bytes: usize`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_can_send_datagram_bytes(&self, bytes: usize) -> bool {
        if !self.dtls12_anti_amplification_enforced {
            return true;
        }
        if matches!(
            self.noxtls_dtls12_handshake_phase,
            Dtls12HandshakePhase::AwaitingClientKeyExchange
                | Dtls12HandshakePhase::AwaitingFinished
                | Dtls12HandshakePhase::Connected
        ) {
            return true;
        }
        let budget = self
            .dtls12_inbound_bytes
            .saturating_mul(DTLS12_ANTI_AMPLIFICATION_FACTOR);
        self.dtls12_outbound_bytes.saturating_add(bytes as u64) <= budget
    }

    /// Records outbound DTLS datagram size after validating anti-amplification budget.
    ///
    /// # Arguments
    /// * `bytes`: Number of bytes intended for outbound datagram transmission.
    ///
    /// # Returns
    /// `Ok(())` when transmission is allowed and accounted.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_record_dtls12_outbound_datagram(&mut self, bytes: usize) -> Result<()> {
        if !self.noxtls_dtls12_can_send_datagram_bytes(bytes) {
            return Err(Error::StateError(
                "dtls12 anti-amplification budget exceeded before cookie validation",
            ));
        }
        self.dtls12_outbound_bytes = self.dtls12_outbound_bytes.saturating_add(bytes as u64);
        Ok(())
    }

    /// Processes first DTLS1.2 `ClientHello` and returns a cookie challenge.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded ClientHello handshake message bytes.
    /// * `cookie_secret`: Server-local secret used to derive stateless cookie bytes.
    ///
    /// # Returns
    /// Encoded `HelloVerifyRequest` carrying derived cookie.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls12_client_hello_without_cookie(
        &mut self,
        client_hello: &[u8],
        cookie_secret: &[u8],
    ) -> Result<Vec<u8>> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 cookie exchange requires DTLS1.2 connection",
            ));
        }
        if self.noxtls_dtls12_handshake_phase != Dtls12HandshakePhase::AwaitingClientHello {
            return Err(Error::StateError(
                "dtls12 cookie challenge requires initial client-hello phase",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(client_hello)?;
        if message_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::ParseFailure(
                "dtls12 cookie exchange requires client hello message",
            ));
        }
        let cookie = self.noxtls_compute_dtls12_cookie(client_hello, cookie_secret)?;
        self.dtls12_expected_cookie = Some(cookie.clone());
        self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingClientHelloWithCookie;
        self.noxtls_build_dtls12_hello_verify_request(&cookie)
    }

    /// Processes second DTLS1.2 `ClientHello` containing verified cookie bytes.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `client_hello`: Encoded retried ClientHello handshake message bytes.
    /// * `cookie`: Cookie bytes echoed by the client.
    /// * `cookie_secret`: Server-local secret used to derive expected cookie bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls12_client_hello_with_cookie(
        &mut self,
        client_hello: &[u8],
        cookie: &[u8],
        cookie_secret: &[u8],
    ) -> Result<()> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 cookie exchange requires DTLS1.2 connection",
            ));
        }
        if self.noxtls_dtls12_handshake_phase != Dtls12HandshakePhase::AwaitingClientHelloWithCookie {
            return Err(Error::StateError(
                "dtls12 cookie verification requires retry client-hello phase",
            ));
        }
        if cookie.is_empty() {
            return Err(Error::InvalidLength(
                "dtls12 client cookie must not be empty",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(client_hello)?;
        if message_type != HANDSHAKE_CLIENT_HELLO {
            return Err(Error::ParseFailure(
                "dtls12 cookie verification requires client hello message",
            ));
        }
        let expected = self.noxtls_compute_dtls12_cookie(client_hello, cookie_secret)?;
        let Some(challenge_cookie) = self.dtls12_expected_cookie.as_ref() else {
            return Err(Error::StateError(
                "dtls12 cookie challenge must be issued before verification",
            ));
        };
        if !noxtls_constant_time_eq(challenge_cookie, cookie) || !noxtls_constant_time_eq(&expected, cookie) {
            return Err(Error::ParseFailure("dtls12 client cookie mismatch"));
        }
        self.dtls12_expected_cookie = None;
        self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingClientKeyExchange;
        self.state = HandshakeState::ClientHelloSent;
        Ok(())
    }

    /// Advances deterministic DTLS1.2 client-flight sequencing after cookie verification.
    ///
    /// Allowed handshake ordering:
    /// * `ClientKeyExchange`
    /// * `Finished`
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `message` — `message: &[u8]`.
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
    pub fn noxtls_process_dtls12_client_handshake_message(&mut self, message: &[u8]) -> Result<()> {
        if self.version != TlsVersion::Dtls12 {
            return Err(Error::StateError(
                "dtls12 handshake sequencing requires DTLS1.2 connection",
            ));
        }
        let (message_type, _body) = noxtls_parse_handshake_message(message)?;
        match self.noxtls_dtls12_handshake_phase {
            Dtls12HandshakePhase::AwaitingClientKeyExchange => {
                if message_type != HANDSHAKE_CLIENT_KEY_EXCHANGE {
                    return Err(Error::ParseFailure(
                        "dtls12 expected client key exchange handshake message",
                    ));
                }
                self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::AwaitingFinished;
                Ok(())
            }
            Dtls12HandshakePhase::AwaitingFinished => {
                if message_type != HANDSHAKE_FINISHED {
                    return Err(Error::ParseFailure(
                        "dtls12 expected finished handshake message",
                    ));
                }
                self.noxtls_dtls12_handshake_phase = Dtls12HandshakePhase::Connected;
                self.state = HandshakeState::Finished;
                Ok(())
            }
            _ => Err(Error::StateError(
                "dtls12 handshake message received in invalid phase",
            )),
        }
    }

    /// Returns current deterministic DTLS1.2 handshake phase label for diagnostics/tests.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_handshake_phase(&self) -> &'static str {
        match self.noxtls_dtls12_handshake_phase {
            Dtls12HandshakePhase::AwaitingClientHello => "awaiting_client_hello",
            Dtls12HandshakePhase::AwaitingClientHelloWithCookie => {
                "awaiting_client_hello_with_cookie"
            }
            Dtls12HandshakePhase::AwaitingClientKeyExchange => "awaiting_client_key_exchange",
            Dtls12HandshakePhase::AwaitingFinished => "awaiting_finished",
            Dtls12HandshakePhase::Connected => "connected",
        }
    }

    /// Installs DTLS1.3-style traffic keys and static IVs used for protected records.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `client_key`: Outbound client write key (AES-128-GCM).
    /// * `client_iv`: Outbound client static IV.
    /// * `server_key`: Inbound server write key (AES-128-GCM).
    /// * `server_iv`: Inbound server static IV.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_install_dtls13_traffic_keys(
        &mut self,
        client_key: [u8; 16],
        client_iv: [u8; 12],
        server_key: [u8; 16],
        server_iv: [u8; 12],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.dtls13_client_write_key = Some(client_key);
        self.dtls13_client_write_iv = Some(client_iv);
        self.dtls13_server_write_key = Some(server_key);
        self.dtls13_server_write_iv = Some(server_iv);
        self.dtls13_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        self.dtls13_client_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        Ok(())
    }

    /// Returns the installed DTLS 1.3 AES-128-GCM **server** handshake write key and IV.
    ///
    /// Populated after [`Self::noxtls_derive_handshake_secret`] (or equivalent record-protection install)
    /// for TLS 1.3 / DTLS 1.3. Intended for harnesses that seal synthetic server handshake records
    /// with the same material [`Self::noxtls_open_dtls13_record`] expects.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `Ok((key, iv))` when both values are installed.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when the connection is not DTLS 1.3 or keys are absent.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls13_handshake_server_write_material(&self) -> Result<([u8; 16], [u8; 12])> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_server_write_key.ok_or(Error::StateError(
            "dtls13 server write key is not installed",
        ))?;
        let iv = self
            .dtls13_server_write_iv
            .ok_or(Error::StateError("dtls13 server write iv is not installed"))?;
        Ok((key, iv))
    }

    /// Sets the outbound DTLS epoch and resets per-epoch sequence to zero.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `epoch`: New outbound epoch value.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls13_outbound_epoch(&mut self, epoch: u16) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot change dtls13 outbound epoch while active flight is incomplete",
            ));
        }
        if epoch < self.dtls13_outbound_epoch {
            return Err(Error::StateError("dtls13 outbound epoch must be monotonic"));
        }
        self.dtls13_outbound_epoch = epoch;
        self.dtls13_outbound_sequence = 0;
        Ok(())
    }

    /// Seals one DTLS1.3 protected record with installed client traffic keys.
    ///
    /// # Arguments
    /// * `plaintext`: Payload bytes to encrypt.
    ///
    /// # Returns
    /// Serialized DTLS packet (`header || ciphertext || tag`).
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls13_mode()?;
        self.noxtls_ensure_dtls13_tx_sequence_available()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        let packet = noxtls_seal_dtls13_aes128gcm_record(
            self.dtls13_outbound_epoch,
            self.dtls13_outbound_sequence,
            &key,
            &iv,
            plaintext,
        )?;
        self.dtls13_outbound_sequence = self.dtls13_outbound_sequence.saturating_add(1);
        Ok(packet)
    }

    /// Seals one DTLS1.3 protected record and schedules it for retransmission.
    ///
    /// # Arguments
    /// * `plaintext`: Payload bytes to encrypt.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Serialized DTLS packet (`header || ciphertext || tag`) tracked in retransmit state.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record_for_flight(
        &mut self,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls13_mode()?;
        let packet = self.noxtls_seal_dtls13_record(plaintext)?;
        let (header, _payload) = noxtls_parse_dtls_record_packet(&packet)?;
        self.dtls_retransmit_tracker.track_outbound_with_schedule(
            header.epoch,
            header.sequence,
            &packet,
            now_ms,
            self.dtls_retransmit_initial_timeout_ms,
        )?;
        Ok(packet)
    }

    /// Seals a DTLS1.3 multi-record flight and schedules each packet for retransmission.
    ///
    /// # Arguments
    /// * `plaintext_records`: Ordered plaintext payloads to seal as individual DTLS packets.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Ordered serialized DTLS packets tracked in retransmit state.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_dtls13_record_flight(
        &mut self,
        plaintext_records: &[&[u8]],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if plaintext_records.is_empty() {
            return Err(Error::InvalidLength(
                "dtls13 record flight must contain at least one payload",
            ));
        }
        let mut packets = Vec::with_capacity(plaintext_records.len());
        for plaintext in plaintext_records {
            packets.push(self.noxtls_seal_dtls13_record_for_flight(plaintext, now_ms)?);
        }
        Ok(packets)
    }

    /// Starts a DTLS1.3 active flight and tracks its packet keys for completion checks.
    ///
    /// # Arguments
    /// * `plaintext_records`: Ordered plaintext payloads to seal as one active flight.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Ordered serialized DTLS packets for immediate transmission.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_start_dtls13_active_flight(
        &mut self,
        plaintext_records: &[&[u8]],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot start noxtls_new dtls13 active flight while previous flight is incomplete",
            ));
        }
        let packets = self.noxtls_seal_dtls13_record_flight(plaintext_records, now_ms)?;
        self.dtls13_active_flight.clear();
        for packet in &packets {
            self.dtls13_active_flight
                .push(self.noxtls_parse_dtls_packet_key(packet)?);
        }
        self.dtls13_active_flight_started_at_ms = Some(now_ms);
        self.noxtls_dtls13_active_flight_failed = false;
        Ok(packets)
    }

    /// Configures timeout budget for DTLS1.3 active-flight completion.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `timeout_ms`: Maximum elapsed milliseconds before active flight is considered timed out.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls13_active_flight_timeout_ms(&mut self, timeout_ms: u64) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.dtls13_active_flight_timeout_ms = timeout_ms.max(1);
        Ok(())
    }

    /// Opens one DTLS1.3 protected record with installed server traffic keys and replay checks.
    ///
    /// # Arguments
    /// * `packet`: Serialized DTLS protected record.
    ///
    /// # Returns
    /// Parsed DTLS header and decrypted plaintext bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_dtls13_record(&mut self, packet: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_server_write_key.ok_or(Error::StateError(
            "dtls13 server write key is not installed",
        ))?;
        let iv = self
            .dtls13_server_write_iv
            .ok_or(Error::StateError("dtls13 server write iv is not installed"))?;
        noxtls_open_dtls13_aes128gcm_record(
            packet,
            &key,
            &iv,
            &mut self.dtls13_inbound_replay_tracker,
        )
    }

    /// Opens one DTLS1.3 protected record using installed client traffic keys.
    ///
    /// This is intended for server-side validation of encrypted client flights.
    ///
    /// # Arguments
    /// * `packet`: Serialized DTLS protected record.
    ///
    /// # Returns
    /// Parsed DTLS header and decrypted plaintext bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_dtls13_client_record(
        &mut self,
        packet: &[u8],
    ) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        noxtls_open_dtls13_aes128gcm_record(
            packet,
            &key,
            &iv,
            &mut self.dtls13_client_inbound_replay_tracker,
        )
    }

    /// Processes encrypted DTLS server post-hello handshake flight in strict TLS1.3 message order.
    ///
    /// Expected decrypted sequence:
    /// * `EncryptedExtensions`
    /// * optional `CertificateRequest`
    /// * `Certificate`
    /// * `CertificateVerify`
    /// * `Finished`
    ///
    /// # Arguments
    /// * `packets`: Encrypted DTLS packets carrying one handshake message each.
    ///
    /// # Returns
    /// `Ok(())` when decrypted flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_encrypted_server_flight_after_hello(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(Error::StateError(
                "dtls13 encrypted server flight requires server hello state",
            ));
        }
        if packets.len() < 4 {
            return Err(Error::ParseFailure(
                "dtls13 encrypted server flight is too short",
            ));
        }
        self.noxtls_derive_handshake_secret()?;
        let mut messages = Vec::with_capacity(packets.len());
        for packet in packets {
            let (_header, plaintext) = self.noxtls_open_dtls13_record(packet)?;
            messages.push(plaintext);
        }
        let mut index = 0_usize;
        self.noxtls_recv_encrypted_extensions(&messages[index])?;
        index += 1;
        let (next_type, _) = noxtls_parse_handshake_message(&messages[index])?;
        if next_type == HANDSHAKE_CERTIFICATE_REQUEST {
            self.noxtls_recv_certificate_request(&messages[index])?;
            index += 1;
        }
        self.noxtls_recv_certificate(&messages[index])?;
        index += 1;
        self.noxtls_recv_certificate_verify(&messages[index])?;
        index += 1;
        self.noxtls_recv_finished_message(&messages[index])?;
        index += 1;
        if index != messages.len() {
            return Err(Error::ParseFailure(
                "unexpected trailing dtls13 encrypted server handshake messages",
            ));
        }
        Ok(())
    }

    /// Processes full DTLS server handshake flight from ServerHello through encrypted post-hello flight.
    ///
    /// Expected sequence:
    /// * `ServerHello` (plaintext handshake wrapper)
    /// * encrypted post-hello packets consumed by `noxtls_process_dtls13_encrypted_server_flight_after_hello`
    ///
    /// # Arguments
    /// * `server_hello`: Encoded ServerHello handshake message.
    /// * `encrypted_packets`: Encrypted DTLS packets carrying post-hello server handshake messages.
    ///
    /// # Returns
    /// `Ok(())` when the full flight validates and transitions to `Finished`.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_full_server_handshake_flight(
        &mut self,
        server_hello: &[u8],
        encrypted_packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        self.noxtls_recv_server_hello(server_hello)?;
        self.noxtls_process_dtls13_encrypted_server_flight_after_hello(encrypted_packets)
    }

    /// Processes encrypted DTLS client post-hello handshake flight with strict message ordering.
    ///
    /// Allowed decrypted sequence:
    /// * `Finished`
    /// * `Certificate`, `CertificateVerify`, `Finished`
    ///
    /// # Arguments
    /// * `packets`: Encrypted DTLS packets carrying client post-hello handshake messages.
    ///
    /// # Returns
    /// `Ok(())` when decrypted message ordering is valid.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_process_dtls13_encrypted_client_flight_after_server_hello(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<()> {
        self.noxtls_ensure_dtls13_mode()?;
        if packets.is_empty() {
            return Err(Error::ParseFailure(
                "dtls13 encrypted client flight is too short",
            ));
        }
        let mut message_types = Vec::with_capacity(packets.len());
        for packet in packets {
            let (_header, plaintext) = self.noxtls_open_dtls13_client_record(packet)?;
            let (handshake_type, _body) = noxtls_parse_handshake_message(&plaintext)?;
            message_types.push(handshake_type);
        }
        if message_types == [HANDSHAKE_FINISHED] {
            return Ok(());
        }
        if message_types
            == [
                HANDSHAKE_CERTIFICATE,
                HANDSHAKE_CERTIFICATE_VERIFY,
                HANDSHAKE_FINISHED,
            ]
        {
            return Ok(());
        }
        Err(Error::ParseFailure(
            "invalid dtls13 encrypted client flight message ordering",
        ))
    }

    /// Builds and schedules one outbound encrypted DTLS1.3 client post-hello handshake flight.
    ///
    /// Allowed plaintext message ordering:
    /// * `Finished`
    /// * `Certificate`, `CertificateVerify`, `Finished`
    ///
    /// # Arguments
    /// * `messages`: Ordered encoded handshake messages for one outbound client flight.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Encrypted DTLS packets tracked as the current active flight.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls13_encrypted_client_flight_after_server_hello(
        &mut self,
        messages: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.state != HandshakeState::ServerHelloReceived
            && self.state != HandshakeState::ServerCertificateVerified
            && self.state != HandshakeState::KeysDerived
        {
            return Err(Error::StateError(
                "dtls13 encrypted client flight requires post-server-hello state",
            ));
        }
        self.noxtls_validate_dtls13_client_post_hello_flight_order(messages)?;
        let plaintext_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        self.noxtls_start_dtls13_active_flight(&plaintext_refs, now_ms)
    }

    /// Advances outbound DTLS epoch and resets per-epoch record sequence counter.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// New outbound epoch value.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_advance_dtls13_outbound_epoch(&mut self) -> Result<u16> {
        self.noxtls_ensure_dtls13_mode()?;
        if !self.dtls13_active_flight.is_empty() && !self.noxtls_is_dtls13_active_flight_complete()? {
            return Err(Error::StateError(
                "cannot advance dtls13 outbound epoch while active flight is incomplete",
            ));
        }
        if self.dtls13_outbound_epoch == u16::MAX {
            return Err(Error::StateError("dtls13 outbound epoch exhausted"));
        }
        self.dtls13_outbound_epoch = self.dtls13_outbound_epoch.saturating_add(1);
        self.dtls13_outbound_sequence = 0;
        Ok(self.dtls13_outbound_epoch)
    }

    /// Opens a locally sealed DTLS1.3 protected record using installed client traffic keys.
    ///
    /// This loopback helper is intended for local validation paths where records were produced
    /// by `noxtls_seal_dtls13_record` on the same connection instance.
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
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
    pub fn noxtls_open_own_dtls13_record(&self, packet: &[u8]) -> Result<(DtlsRecordHeader, Vec<u8>)> {
        self.noxtls_ensure_dtls13_mode()?;
        let key = self.dtls13_client_write_key.ok_or(Error::StateError(
            "dtls13 client write key is not installed",
        ))?;
        let iv = self
            .dtls13_client_write_iv
            .ok_or(Error::StateError("dtls13 client write iv is not installed"))?;
        let mut replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        noxtls_open_dtls13_aes128gcm_record(packet, &key, &iv, &mut replay_tracker)
    }

    /// Marks a tracked DTLS outbound packet as acknowledged using parsed record header fields.
    ///
    /// # Arguments
    /// * `packet`: DTLS record packet containing epoch/sequence metadata.
    ///
    /// # Returns
    /// `true` when matching tracked packet is found and marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls13_record_acked_from_packet(&mut self, packet: &[u8]) -> Result<bool> {
        self.noxtls_ensure_dtls13_mode()?;
        let (header, _payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok(self
            .dtls_retransmit_tracker
            .mark_acked(header.epoch, header.sequence))
    }

    /// Marks every DTLS packet in one flight as acknowledged using packet headers.
    ///
    /// # Arguments
    /// * `packets`: DTLS packets that belong to one outbound flight.
    ///
    /// # Returns
    /// Count of packets that matched tracked records and were marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls13_flight_acked_from_packets(&mut self, packets: &[Vec<u8>]) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        let mut marked = 0_usize;
        for packet in packets {
            if self.noxtls_mark_dtls13_record_acked_from_packet(packet)? {
                marked = marked.saturating_add(1);
            }
        }
        Ok(marked)
    }

    /// Polls retransmit scheduler for due packets belonging to the current active flight.
    ///
    /// # Arguments
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Due packets that should be resent for active-flight completion.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_poll_dtls13_active_flight_due_packets(&mut self, now_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(Vec::new());
        }
        if self.noxtls_dtls13_active_flight_has_timed_out(now_ms) {
            let _ = self.noxtls_abort_dtls13_active_flight()?;
            return Err(Error::StateError(
                "dtls13 active flight timed out before completion",
            ));
        }
        if self.noxtls_dtls13_active_flight_missing_tracked_records() {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = true;
            return Err(Error::StateError(
                "dtls13 active flight failed after retransmit budget exhausted",
            ));
        }
        let due_packets = self.noxtls_poll_dtls12_due_retransmit_packets(now_ms)?;
        let mut filtered = Vec::new();
        for packet in due_packets {
            let key = self.noxtls_parse_dtls_packet_key(&packet)?;
            if self.dtls13_active_flight.contains(&key) {
                filtered.push(packet);
            }
        }
        if self.noxtls_dtls13_active_flight_missing_tracked_records() {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = true;
            return Err(Error::StateError(
                "dtls13 active flight failed after retransmit budget exhausted",
            ));
        }
        Ok(filtered)
    }

    /// Acknowledges packets for the current active DTLS1.3 flight and prunes acked records.
    ///
    /// # Arguments
    /// * `packets`: Acked DTLS packets for this flight.
    ///
    /// # Returns
    /// Number of active-flight packets newly marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_acknowledge_dtls13_active_flight_packets(
        &mut self,
        packets: &[Vec<u8>],
    ) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(0);
        }
        let mut marked = 0_usize;
        for packet in packets {
            let key = self.noxtls_parse_dtls_packet_key(packet)?;
            if !self.dtls13_active_flight.contains(&key) {
                continue;
            }
            if self.noxtls_mark_dtls12_record_acked(key.0, key.1)? {
                marked = marked.saturating_add(1);
            }
        }
        let _ = self.noxtls_prune_dtls12_acked_records()?;
        if self.noxtls_is_dtls13_active_flight_complete()? {
            self.dtls13_active_flight.clear();
            self.dtls13_active_flight_started_at_ms = None;
            self.noxtls_dtls13_active_flight_failed = false;
        }
        Ok(marked)
    }

    /// Aborts the current active DTLS1.3 flight and removes its retransmit obligations.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// Number of active-flight records removed from retransmit tracking.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_abort_dtls13_active_flight(&mut self) -> Result<usize> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(0);
        }
        for (epoch, sequence) in &self.dtls13_active_flight {
            let _ = self.dtls_retransmit_tracker.mark_acked(*epoch, *sequence);
        }
        let removed = self.noxtls_prune_dtls12_acked_records()?;
        self.dtls13_active_flight.clear();
        self.dtls13_active_flight_started_at_ms = None;
        self.noxtls_dtls13_active_flight_failed = false;
        Ok(removed)
    }

    /// Reports whether the most recent active DTLS1.3 flight failed due to retry budget exhaustion.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls13_active_flight_failed(&self) -> bool {
        self.noxtls_dtls13_active_flight_failed
    }

    /// Reports whether all packets from the current active DTLS1.3 flight are complete.
    ///
    /// A flight is complete when no tracked unacknowledged retransmit record remains
    /// for any packet key registered in `noxtls_start_dtls13_active_flight`.
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
    pub fn noxtls_is_dtls13_active_flight_complete(&self) -> Result<bool> {
        self.noxtls_ensure_dtls13_mode()?;
        if self.dtls13_active_flight.is_empty() {
            return Ok(true);
        }
        for (epoch, sequence) in &self.dtls13_active_flight {
            let still_pending = self.dtls_retransmit_tracker.records().iter().any(|record| {
                record.epoch == *epoch && record.sequence == *sequence && !record.acknowledged
            });
            if still_pending {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Derives bounded DTLS1.2 cookie bytes from server secret and ClientHello transcript bytes.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `client_hello` — `client_hello: &[u8]`.
    /// * `cookie_secret` — `cookie_secret: &[u8]`.
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
    fn noxtls_compute_dtls12_cookie(&self, client_hello: &[u8], cookie_secret: &[u8]) -> Result<Vec<u8>> {
        if cookie_secret.is_empty() {
            return Err(Error::InvalidLength(
                "dtls12 cookie secret must not be empty",
            ));
        }
        let mut material = Vec::with_capacity(cookie_secret.len() + client_hello.len());
        material.extend_from_slice(cookie_secret);
        material.extend_from_slice(client_hello);
        let digest = noxtls_hash_bytes_for_algorithm(HashAlgorithm::Sha256, &material);
        let cookie_len = digest.len().min(16);
        Ok(digest[..cookie_len].to_vec())
    }

    /// Encodes DTLS1.2 HelloVerifyRequest carrying one stateless cookie challenge value.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `cookie` — `cookie: &[u8]`.
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
    fn noxtls_build_dtls12_hello_verify_request(&self, cookie: &[u8]) -> Result<Vec<u8>> {
        if cookie.is_empty() {
            return Err(Error::InvalidLength("dtls12 cookie must not be empty"));
        }
        if cookie.len() > DTLS12_MAX_COOKIE_LEN {
            return Err(Error::InvalidLength(
                "dtls12 cookie exceeds 8-bit cookie length field",
            ));
        }
        let mut body = Vec::with_capacity(3 + cookie.len());
        body.extend_from_slice(&[0xFE, 0xFD]);
        body.push(cookie.len() as u8);
        body.extend_from_slice(cookie);
        Ok(noxtls_encode_handshake_message(
            HANDSHAKE_HELLO_VERIFY_REQUEST,
            &body,
        ))
    }

    /// Parses `(epoch, sequence)` key used for DTLS retransmit record correlation.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
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
    fn noxtls_parse_dtls_packet_key(&self, packet: &[u8]) -> Result<(u16, u64)> {
        let (header, _payload) = noxtls_parse_dtls_record_packet(packet)?;
        if header.version != [0xFE, 0xFD] {
            return Err(Error::ParseFailure("dtls record version mismatch"));
        }
        Ok((header.epoch, header.sequence))
    }

    /// Reports whether active-flight elapsed time exceeded configured timeout budget.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `now_ms` — `now_ms: u64`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_dtls13_active_flight_has_timed_out(&self, now_ms: u64) -> bool {
        let Some(started_at_ms) = self.dtls13_active_flight_started_at_ms else {
            return false;
        };
        now_ms.saturating_sub(started_at_ms) > self.dtls13_active_flight_timeout_ms
    }

    /// Returns true when active-flight keys no longer exist in retransmit tracker records.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_dtls13_active_flight_missing_tracked_records(&self) -> bool {
        self.dtls13_active_flight.iter().any(|(epoch, sequence)| {
            !self
                .dtls_retransmit_tracker
                .records()
                .iter()
                .any(|record| record.epoch == *epoch && record.sequence == *sequence)
        })
    }

    /// Validates allowed DTLS1.3 client post-hello flight message ordering.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `messages` — `messages: &[Vec<u8>]`.
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
    fn noxtls_validate_dtls13_client_post_hello_flight_order(&self, messages: &[Vec<u8>]) -> Result<()> {
        if messages.is_empty() {
            return Err(Error::InvalidLength(
                "dtls13 encrypted client flight must contain at least one message",
            ));
        }
        let mut message_types = Vec::with_capacity(messages.len());
        for message in messages {
            let (handshake_type, _body) = noxtls_parse_handshake_message(message)?;
            message_types.push(handshake_type);
        }
        if message_types == [HANDSHAKE_FINISHED] {
            return Ok(());
        }
        if message_types
            == [
                HANDSHAKE_CERTIFICATE,
                HANDSHAKE_CERTIFICATE_VERIFY,
                HANDSHAKE_FINISHED,
            ]
        {
            return Ok(());
        }
        Err(Error::ParseFailure(
            "invalid dtls13 client post-hello flight message ordering",
        ))
    }

    /// Builds TLS 1.2 AEAD additional authenticated data per record sequence and header fields.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `sequence` — `sequence: u64`.
    /// * `content_type` — `content_type: RecordContentType`.
    /// * `plaintext_len` — `plaintext_len: usize`.
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
    fn noxtls_build_tls12_record_aad(
        &self,
        sequence: u64,
        content_type: RecordContentType,
        plaintext_len: usize,
    ) -> Result<[u8; 13]> {
        let len = u16::try_from(plaintext_len)
            .map_err(|_| Error::InvalidLength("tls12 plaintext length exceeds 16-bit field"))?;
        let mut aad = [0_u8; 13];
        aad[..8].copy_from_slice(&sequence.to_be_bytes());
        aad[8] = content_type.to_u8();
        aad[9..11].copy_from_slice(&noxtls_legacy_wire_version(self.version));
        aad[11..13].copy_from_slice(&len.to_be_bytes());
        Ok(aad)
    }

    /// Builds TLS 1.3 AEAD additional authenticated data from TLSCiphertext header fields.
    ///
    /// # Arguments
    ///
    /// * `payload_len` — TLSCiphertext encrypted record payload length (`ciphertext || tag`) in bytes.
    ///
    /// # Returns
    ///
    /// 5-byte TLS 1.3 AAD array `(content_type, legacy_version, length)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] when `payload_len` exceeds `u16::MAX`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_build_tls13_record_aad(&self, payload_len: usize) -> Result<[u8; 5]> {
        let len = u16::try_from(payload_len)
            .map_err(|_| Error::InvalidLength("tls13 record payload length exceeds u16 range"))?;
        let mut aad = [0_u8; 5];
        aad[0] = RecordContentType::ApplicationData.to_u8();
        aad[1..3].copy_from_slice(&0x0303_u16.to_be_bytes());
        aad[3..5].copy_from_slice(&len.to_be_bytes());
        Ok(aad)
    }

    /// Encodes protected payload into TLS 1.2 wire packet with version and content type.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `record` — `record: &ProtectedRecord`.
    /// * `content_type` — `content_type: RecordContentType`.
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
    fn noxtls_encode_tls12_record_packet(
        &self,
        record: &ProtectedRecord,
        content_type: RecordContentType,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(record.ciphertext.len() + record.tag.len());
        payload.extend_from_slice(&record.ciphertext);
        payload.extend_from_slice(&record.tag);
        noxtls_encode_tls12_ciphertext_record(
            content_type.to_u8(),
            noxtls_legacy_wire_version(self.version),
            &payload,
        )
    }

    /// Decodes TLS 1.2 wire packet into protected payload at one sequence number.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
    /// * `sequence` — `sequence: u64`.
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
    fn noxtls_decode_tls12_record_packet(
        &self,
        packet: &[u8],
        sequence: u64,
    ) -> Result<(ProtectedRecord, RecordContentType)> {
        let (content_type_u8, version, payload) = noxtls_decode_tls12_ciphertext_record(packet)?;
        let strict_version = noxtls_legacy_wire_version(self.version);
        let legacy_compat_ok = self.tls12_allow_legacy_record_versions
            && (version == [0x03, 0x01] || version == [0x03, 0x02]);
        if version != strict_version && !legacy_compat_ok {
            return Err(Error::ParseFailure(
                "tls12 record has invalid legacy version",
            ));
        }
        let content_type = RecordContentType::from_u8(content_type_u8)
            .ok_or(Error::ParseFailure("unknown tls12 record content type"))?;
        if payload.len() < 16 {
            return Err(Error::ParseFailure("tls12 record payload too short"));
        }
        let tag_offset = payload.len() - 16;
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&payload[tag_offset..]);
        Ok((
            ProtectedRecord {
                sequence,
                ciphertext: payload[..tag_offset].to_vec(),
                tag,
            },
            content_type,
        ))
    }

    /// Encodes one protected record into TLS 1.3 TLSCiphertext wire format.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `record` — `record: &ProtectedRecord`.
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
    fn noxtls_encode_tls13_record_packet(&self, record: &ProtectedRecord) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(record.ciphertext.len() + record.tag.len());
        payload.extend_from_slice(&record.ciphertext);
        payload.extend_from_slice(&record.tag);
        noxtls_encode_tls13_ciphertext_record(&payload)
    }

    /// Decodes one TLS 1.3 TLSCiphertext packet into a protected record at one sequence.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `packet` — `packet: &[u8]`.
    /// * `sequence` — `sequence: u64`.
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
    fn noxtls_decode_tls13_record_packet(&self, packet: &[u8], sequence: u64) -> Result<ProtectedRecord> {
        let payload = noxtls_decode_tls13_ciphertext_record(packet)?;
        let tag_offset = payload.len() - 16;
        let mut tag = [0_u8; 16];
        tag.copy_from_slice(&payload[tag_offset..]);
        Ok(ProtectedRecord {
            sequence,
            ciphertext: payload[..tag_offset].to_vec(),
            tag,
        })
    }

    /// Ensures DTLS1.3 sealing has remaining 48-bit sequence space.
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
    fn noxtls_ensure_dtls13_tx_sequence_available(&self) -> Result<()> {
        if self.dtls13_outbound_sequence > DTLS13_MAX_SEQUENCE {
            return Err(Error::StateError(
                "dtls13 outbound record sequence exhausted",
            ));
        }
        Ok(())
    }

    /// Configures the initial DTLS retransmit timeout used for outbound flight scheduling.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `timeout_ms`: Initial resend delay in milliseconds; values below 1 are clamped.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_retransmit_initial_timeout_ms(&mut self, timeout_ms: u64) -> Result<()> {
        self.noxtls_ensure_dtls12_mode()?;
        self.dtls_retransmit_initial_timeout_ms = timeout_ms.max(1);
        Ok(())
    }

    /// Configures maximum resend attempts before a DTLS packet is dropped.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload described by the return type; see the function body for the concrete value.
    ///
    /// # Arguments
    /// * `attempts`: Number of due retransmits allowed before retirement; values below 1 are clamped.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_dtls12_max_retransmit_attempts(&mut self, attempts: u8) -> Result<()> {
        self.noxtls_ensure_dtls12_mode()?;
        self.dtls_max_retransmit_attempts = attempts.max(1);
        Ok(())
    }

    /// Builds and schedules one outbound DTLS packet for timer-driven retransmission.
    ///
    /// # Arguments
    /// * `content_type`: DTLS record content type.
    /// * `epoch`: DTLS epoch value for this packet.
    /// * `sequence`: 48-bit DTLS sequence number.
    /// * `payload`: Record payload bytes.
    /// * `now_ms`: Current monotonic timestamp in milliseconds.
    ///
    /// # Returns
    /// Serialized DTLS datagram packet ready for immediate transmission.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_build_dtls12_record_packet_for_flight(
        &mut self,
        content_type: RecordContentType,
        epoch: u16,
        sequence: u64,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.noxtls_ensure_dtls12_mode()?;
        let packet = self.noxtls_build_dtls12_record_packet(content_type, epoch, sequence, payload)?;
        self.dtls_retransmit_tracker.track_outbound_with_schedule(
            epoch,
            sequence,
            &packet,
            now_ms,
            self.dtls_retransmit_initial_timeout_ms,
        )?;
        Ok(packet)
    }

    /// Marks one DTLS outbound packet as acknowledged by `(epoch, sequence)`.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `epoch` — `epoch: u16`.
    /// * `sequence` — `sequence: u64`.
    ///
    /// # Returns
    /// `true` if a tracked packet matched and was marked acknowledged.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_mark_dtls12_record_acked(&mut self, epoch: u16, sequence: u64) -> Result<bool> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self.dtls_retransmit_tracker.mark_acked(epoch, sequence))
    }

    /// Returns due retransmit packets and updates their backoff schedule.
    ///
    /// # Arguments
    /// * `now_ms`: Current monotonic timestamp used to decide due timers.
    ///
    /// # Returns
    /// DTLS packets that should be retransmitted now.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_poll_dtls12_due_retransmit_packets(&mut self, now_ms: u64) -> Result<Vec<Vec<u8>>> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self
            .dtls_retransmit_tracker
            .collect_due_retransmit_packets(now_ms, self.dtls_max_retransmit_attempts))
    }

    /// Returns currently unacknowledged DTLS packets regardless of timer state.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_dtls12_pending_retransmit_packets(&self) -> Vec<Vec<u8>> {
        if !self.version.is_dtls() {
            return Vec::new();
        }
        self.dtls_retransmit_tracker.pending_retransmit_packets()
    }

    /// Prunes acknowledged DTLS packets from retransmit tracking.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Returns
    /// Number of pruned packet records.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_prune_dtls12_acked_records(&mut self) -> Result<usize> {
        self.noxtls_ensure_dtls12_mode()?;
        Ok(self.dtls_retransmit_tracker.prune_acked())
    }

    /// Ensures DTLS-specific packet scheduler APIs are used only for DTLS profiles.
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
    fn noxtls_ensure_dtls12_mode(&self) -> Result<()> {
        if !self.version.is_dtls() {
            return Err(Error::StateError(
                "dtls retransmit scheduler requires DTLS connection",
            ));
        }
        Ok(())
    }

    /// Ensures DTLS1.3 packet APIs are used only for DTLS profiles.
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
    fn noxtls_ensure_dtls13_mode(&self) -> Result<()> {
        if !self.version.is_dtls() {
            return Err(Error::StateError("dtls13 APIs require DTLS connection"));
        }
        Ok(())
    }

    /// Ensures TLS1.2 wire-packet APIs are used only on TLS 1.0/1.1/1.2 connections.
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
    fn noxtls_ensure_tls12_wire_mode(&self) -> Result<()> {
        if self.version == TlsVersion::Tls10
            || self.version == TlsVersion::Tls11
            || self.version == TlsVersion::Tls12
        {
            return Ok(());
        }
        Err(Error::StateError(
            "tls12 record packets require TLS 1.0/1.1/1.2 connection",
        ))
    }

    /// Seals plaintext into multiple records using caller-selected fragment size.
    ///
    /// # Arguments
    /// * `plaintext`: Full plaintext payload to fragment and seal.
    /// * `aad`: Additional authenticated data reused for each fragment.
    /// * `fragment_len`: Maximum plaintext bytes per sealed record fragment.
    ///
    /// # Returns
    /// Ordered protected-record fragments covering the full plaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_record_fragments(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
        fragment_len: usize,
    ) -> Result<Vec<ProtectedRecord>> {
        if fragment_len == 0 {
            return Err(Error::InvalidLength(
                "fragment length must be greater than zero",
            ));
        }
        if fragment_len > self.max_record_plaintext_len {
            return Err(Error::InvalidLength(
                "fragment length exceeds configured record plaintext limit",
            ));
        }
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }
        let fragment_count = plaintext.len().div_ceil(fragment_len);
        let required_sequences = u64::try_from(fragment_count)
            .map_err(|_| Error::InvalidLength("too many record fragments requested"))?;
        let highest_sequence = self
            .client_sequence
            .checked_add(required_sequences.saturating_sub(1));
        if highest_sequence.is_none() {
            return Err(Error::StateError(
                "insufficient record sequence space for all fragments",
            ));
        }

        let mut out = Vec::with_capacity(fragment_count);
        let mut offset = 0_usize;
        while offset < plaintext.len() {
            let end = (offset + fragment_len).min(plaintext.len());
            out.push(self.noxtls_seal_record(&plaintext[offset..end], aad)?);
            offset = end;
        }
        Ok(out)
    }

    /// Opens and reassembles a sequence of protected record fragments.
    ///
    /// # Arguments
    /// * `records`: Ordered record fragments to decrypt and concatenate.
    /// * `aad`: Additional authenticated data reused for each fragment.
    ///
    /// # Returns
    /// Reassembled plaintext payload.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_record_fragments(
        &mut self,
        records: &[ProtectedRecord],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let base_sequence = self.server_sequence;
        for (index, record) in records.iter().enumerate() {
            let expected_sequence = base_sequence
                .checked_add(index as u64)
                .ok_or(Error::ParseFailure("record fragment sequence overflow"))?;
            if record.sequence != expected_sequence {
                return Err(Error::ParseFailure(
                    "record fragments must be contiguous sequences",
                ));
            }
        }
        let mut out = Vec::new();
        for record in records {
            out.extend_from_slice(&self.noxtls_open_record(record, aad)?);
        }
        Ok(out)
    }

    /// Opens locally-sealed fragments with client keys and reassembles plaintext.
    ///
    /// # Arguments
    /// * `records`: Ordered local record fragments produced by `noxtls_seal_record_fragments`.
    /// * `aad`: Additional authenticated data reused for each fragment.
    ///
    /// # Returns
    /// Reassembled plaintext payload.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_own_record_fragments(
        &self,
        records: &[ProtectedRecord],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let base_sequence = records[0].sequence;
        for (index, record) in records.iter().enumerate() {
            let expected_sequence = base_sequence
                .checked_add(index as u64)
                .ok_or(Error::ParseFailure("record fragment sequence overflow"))?;
            if record.sequence != expected_sequence {
                return Err(Error::ParseFailure(
                    "record fragments must be contiguous sequences",
                ));
            }
        }
        let mut out = Vec::new();
        for record in records {
            out.extend_from_slice(&self.noxtls_open_own_record(record, aad)?);
        }
        Ok(out)
    }

    /// Seals a TLS 1.3 record by encoding TLSInnerPlaintext with content type and padding.
    ///
    /// # Arguments
    /// * `content`: Inner plaintext content bytes.
    /// * `content_type`: TLS content type byte encoded at end of inner plaintext.
    /// * `aad`: Additional authenticated data for AEAD.
    /// * `padding_len`: Number of trailing zero padding bytes.
    ///
    /// # Returns
    /// Protected record carrying encrypted TLSInnerPlaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_tls13_inner_record(
        &mut self,
        content: &[u8],
        content_type: u8,
        aad: &[u8],
        padding_len: usize,
    ) -> Result<ProtectedRecord> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 inner plaintext records require TLS 1.3 connection",
            ));
        }
        let inner = noxtls_encode_tls13_inner_plaintext(content, content_type, padding_len);
        self.noxtls_seal_record(&inner, aad)
    }

    /// Opens a TLS 1.3 record and decodes TLSInnerPlaintext into content and content type.
    ///
    /// # Arguments
    /// * `record`: Protected record sealed with peer TLS 1.3 traffic keys.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Tuple `(content, content_type)` extracted from decoded inner plaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_tls13_inner_record(
        &mut self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 inner plaintext records require TLS 1.3 connection",
            ));
        }
        let inner = self.noxtls_open_record(record, aad)?;
        noxtls_decode_tls13_inner_plaintext(&inner)
    }

    /// Opens a locally-sealed TLS 1.3 record and decodes TLSInnerPlaintext for tests.
    ///
    /// # Arguments
    /// * `record`: Protected record sealed via `noxtls_seal_tls13_inner_record`.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Tuple `(content, content_type)` extracted from decoded inner plaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_own_tls13_inner_record(
        &self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 inner plaintext records require TLS 1.3 connection",
            ));
        }
        let inner = self.noxtls_open_own_record(record, aad)?;
        noxtls_decode_tls13_inner_plaintext(&inner)
    }

    /// Seals one TLS 1.3 wire record packet from TLSInnerPlaintext content.
    ///
    /// # Arguments
    /// * `content`: Inner plaintext content bytes.
    /// * `content_type`: Inner content type byte.
    /// * `aad`: Additional authenticated data for AEAD.
    /// * `padding_len`: Number of trailing zero padding bytes.
    ///
    /// # Returns
    /// Serialized TLSCiphertext packet bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_seal_tls13_record_packet(
        &mut self,
        content: &[u8],
        content_type: u8,
        aad: &[u8],
        padding_len: usize,
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 record packets require TLS 1.3 connection",
            ));
        }
        let record = self.noxtls_seal_tls13_inner_record(content, content_type, aad, padding_len)?;
        self.noxtls_encode_tls13_record_packet(&record)
    }

    /// Opens one inbound TLS 1.3 wire record packet and decodes TLSInnerPlaintext.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Tuple `(content, content_type)` decoded from inner plaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_tls13_record_packet(&mut self, packet: &[u8], aad: &[u8]) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 record packets require TLS 1.3 connection",
            ));
        }
        let record = self.noxtls_decode_tls13_record_packet(packet, self.server_sequence)?;
        match self.noxtls_open_tls13_inner_record(&record, aad) {
            Ok(inner) => Ok(inner),
            Err(error) => {
                noxtls_tls13_debug_log("tls13.open_record.error", "failed to decrypt record");
                noxtls_tls13_debug_log_bytes("tls13.open_record.aad", aad);
                noxtls_tls13_debug_log_bytes("tls13.open_record.ciphertext", &record.ciphertext);
                noxtls_tls13_debug_log_bytes("tls13.open_record.tag", &record.tag);
                if let Some(key) = self.server_write_key.as_ref() {
                    noxtls_tls13_debug_log_bytes("tls13.open_record.server_write_key", key);
                }
                if let Some(iv) = self.server_write_iv.as_ref() {
                    noxtls_tls13_debug_log_bytes("tls13.open_record.server_write_iv", iv);
                }
                self.noxtls_debug_probe_tls13_open_record_failure(&record, aad);
                Err(error)
            }
        }
    }

    /// Opens one locally-sealed TLS 1.3 wire packet using client traffic keys.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes.
    /// * `sequence`: Record sequence number used during sealing.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Tuple `(content, content_type)` decoded from inner plaintext.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_open_own_tls13_record_packet(
        &self,
        packet: &[u8],
        sequence: u64,
        aad: &[u8],
    ) -> Result<(Vec<u8>, u8)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 record packets require TLS 1.3 connection",
            ));
        }
        let record = self.noxtls_decode_tls13_record_packet(packet, sequence)?;
        self.noxtls_open_own_tls13_inner_record(&record, aad)
    }

    /// Seals a TLS 1.3 alert as TLSInnerPlaintext with alert content type.
    ///
    /// # Arguments
    /// * `level`: Alert severity level.
    /// * `description`: Alert description codepoint.
    /// * `aad`: Additional authenticated data used for AEAD.
    ///
    /// # Returns
    /// Protected record containing encoded alert bytes.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_tls13_alert(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
        aad: &[u8],
    ) -> Result<ProtectedRecord> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let payload = [level.to_u8(), description.to_u8()];
        let record =
            self.noxtls_seal_tls13_inner_record(&payload, RecordContentType::Alert.to_u8(), aad, 0)?;
        self.noxtls_apply_tls13_alert_effects(level, description, true);
        Ok(record)
    }

    /// Seals a TLS 1.3 alert and encodes it into TLSCiphertext packet wire format.
    ///
    /// # Arguments
    /// * `level`: Alert severity level.
    /// * `description`: Alert description codepoint.
    /// * `aad`: Additional authenticated data used for AEAD.
    ///
    /// # Returns
    /// Serialized TLSCiphertext packet bytes carrying an alert inner record.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_send_tls13_alert_packet(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let record = self.noxtls_send_tls13_alert(level, description, aad)?;
        self.noxtls_encode_tls13_record_packet(&record)
    }

    /// Opens and parses a peer TLS 1.3 alert record.
    ///
    /// # Arguments
    /// * `record`: Protected record carrying peer alert payload.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_tls13_alert(
        &mut self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let (payload, content_type) = self.noxtls_open_tls13_inner_record(record, aad)?;
        self.noxtls_process_parsed_tls13_alert(payload, content_type)
    }

    /// Opens and parses a locally-sealed TLS 1.3 alert record for loopback tests.
    ///
    /// # Arguments
    /// * `record`: Protected record sealed via `noxtls_send_tls13_alert`.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_own_tls13_alert(
        &mut self,
        record: &ProtectedRecord,
        aad: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let (payload, content_type) = self.noxtls_open_own_tls13_inner_record(record, aad)?;
        self.noxtls_process_parsed_tls13_alert(payload, content_type)
    }

    /// Opens and parses a peer TLS 1.3 alert TLSCiphertext packet.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes carrying an alert inner record.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_tls13_alert_packet(
        &mut self,
        packet: &[u8],
        aad: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let (payload, content_type) = self.noxtls_open_tls13_record_packet(packet, aad)?;
        self.noxtls_process_parsed_tls13_alert(payload, content_type)
    }

    /// Opens and parses a locally-sealed TLS 1.3 alert TLSCiphertext packet for loopback tests.
    ///
    /// # Arguments
    /// * `packet`: Serialized TLSCiphertext packet bytes from local alert sealing.
    /// * `sequence`: Record sequence number used during sealing.
    /// * `aad`: Additional authenticated data used during sealing.
    ///
    /// # Returns
    /// Parsed `(AlertLevel, AlertDescription)` tuple.
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when inputs or handshake state invalidate the operation; see the function body for specific error construction sites.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_recv_own_tls13_alert_packet(
        &mut self,
        packet: &[u8],
        sequence: u64,
        aad: &[u8],
    ) -> Result<(AlertLevel, AlertDescription)> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Err(Error::StateError(
                "tls13 alert records require TLS 1.3 connection",
            ));
        }
        let (payload, content_type) = self.noxtls_open_own_tls13_record_packet(packet, sequence, aad)?;
        self.noxtls_process_parsed_tls13_alert(payload, content_type)
    }

    /// Applies decoded alert payload semantics to connection state.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `payload` — `payload: Vec<u8>`.
    /// * `content_type` — `content_type: u8`.
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
    fn noxtls_process_parsed_tls13_alert(
        &mut self,
        payload: Vec<u8>,
        content_type: u8,
    ) -> Result<(AlertLevel, AlertDescription)> {
        if RecordContentType::from_u8(content_type) != Some(RecordContentType::Alert) {
            return Err(Error::ParseFailure("record is not an alert content type"));
        }
        if payload.len() != 2 {
            return Err(Error::ParseFailure("tls13 alert payload must be two bytes"));
        }
        let level =
            AlertLevel::from_u8(payload[0]).ok_or(Error::ParseFailure("unknown alert level"))?;
        let description = AlertDescription::from_u8(payload[1])
            .ok_or(Error::ParseFailure("unknown alert description"))?;
        self.noxtls_apply_tls13_alert_effects(level, description, false);
        Ok((level, description))
    }

    /// Applies modeled TLS 1.3 alert mapping effects for local-send and peer-receive paths.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `level` — `level: AlertLevel`.
    /// * `description` — `description: AlertDescription`.
    /// * `from_local_send` — `from_local_send: bool`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_apply_tls13_alert_effects(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
        from_local_send: bool,
    ) {
        if description == AlertDescription::CloseNotify {
            if from_local_send {
                self.noxtls_tls13_local_close_notify_sent = true;
            } else {
                self.noxtls_tls13_peer_close_notify_received = true;
            }
        }
        if level == AlertLevel::Fatal {
            self.state = HandshakeState::Idle;
        }
    }

    /// Reports whether a peer close_notify alert has been processed.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_peer_close_notify_received(&self) -> bool {
        self.noxtls_tls13_peer_close_notify_received
    }

    /// Reports whether this endpoint has sent a close_notify alert.
    #[must_use]
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// `true` or `false` according to the checks in the function body.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_local_close_notify_sent(&self) -> bool {
        self.noxtls_tls13_local_close_notify_sent
    }

    /// Resets per-handshake certificate-auth tracking before a noxtls_new ClientHello.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_reset_tls13_certificate_auth_state(&mut self) {
        self.tls13_server_leaf_public_key_der = None;
        self.tls13_server_certificate_chain_validated = false;
        self.noxtls_tls13_server_name_acknowledged = false;
        self.noxtls_tls13_selected_alpn_protocol = None;
        self.noxtls_tls13_server_ocsp_staple = None;
        self.noxtls_tls13_server_ocsp_staple_verified = false;
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
    fn noxtls_validate_tls13_hrr_retry_group_support(&self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() || !self.tls13_hrr_seen {
            return Ok(());
        }
        let requested_group = self.tls13_hrr_requested_group.ok_or(Error::ParseFailure(
            "hello retry request is missing requested key_share group",
        ))?;
        if !super::keyshare::noxtls_tls13_key_share_group_supported(requested_group) {
            return Err(Error::StateError(
                "hello retry request requested unsupported key_share group",
            ));
        }
        Ok(())
    }

    /// Derives TLS 1.3 modeled client early-data record key+iv from PSK and transcript context.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `psk` — `psk: &[u8]`.
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
    fn noxtls_derive_tls13_early_data_record_key_iv(&self, psk: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let noxtls_transcript_hash = noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &self.transcript);
        let early_secret = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, psk);
        let client_early_traffic_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &early_secret,
            b"c e traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        let key_len = self.noxtls_tls13_early_data_key_len();
        let key = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &client_early_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &client_early_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 early-data iv should be 12 bytes");
        Ok((key, iv))
    }

    /// Returns TLS 1.3 early-data traffic-key length based on active modeled suite policy.
    ///
    /// # Returns
    ///
    /// AES-128 uses 16 bytes; AES-256 and ChaCha20-Poly1305 use 32 bytes.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_tls13_early_data_key_len(&self) -> usize {
        match self.noxtls_selected_cipher_suite {
            Some(CipherSuite::TlsAes256GcmSha384 | CipherSuite::TlsChacha20Poly1305Sha256) => 32,
            _ => 16,
        }
    }

    /// Returns whether modeled early-data record protection uses ChaCha20-Poly1305.
    ///
    /// # Returns
    ///
    /// `true` when current modeled suite policy selects ChaCha20-Poly1305.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_tls13_early_data_uses_chacha20_poly1305(&self) -> bool {
        matches!(
            self.noxtls_selected_cipher_suite,
            Some(CipherSuite::TlsChacha20Poly1305Sha256)
        )
    }

    /// Validates server certificate chain and caches leaf SPKI for CertificateVerify.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `certificates` — `certificates: &[Vec<u8>]`.
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
    fn noxtls_validate_tls13_server_certificate_chain(&mut self, certificates: &[Vec<u8>]) -> Result<()> {
        if certificates.is_empty() {
            return Err(Error::ParseFailure(
                "certificate list must include leaf certificate",
            ));
        }
        if self.tls13_server_trust_anchors_der.is_empty() {
            return Err(Error::StateError(
                "tls13 server trust anchors are not configured",
            ));
        }
        let validation_time =
            self.tls13_server_validation_time
                .as_deref()
                .ok_or(Error::StateError(
                    "tls13 server validation time is not configured",
                ))?;
        let leaf = noxtls_parse_certificate(&certificates[0])?;
        if let Some(expected_hostname) = self.tls13_server_expected_hostname.as_deref() {
            if !noxtls_certificate_matches_hostname(&leaf, expected_hostname) {
                return Err(Error::CryptoFailure(
                    "server certificate hostname validation failed",
                ));
            }
        }

        let mut parsed_intermediates = Vec::new();
        for der in &certificates[1..] {
            let parsed = noxtls_parse_certificate(der)?;
            parsed_intermediates.push(parsed);
        }
        for der in &self.tls13_server_intermediates_der {
            let parsed = noxtls_parse_certificate(der)?;
            parsed_intermediates.push(parsed);
        }

        let mut parsed_anchors = Vec::new();
        for der in &self.tls13_server_trust_anchors_der {
            let parsed = noxtls_parse_certificate(der)?;
            parsed_anchors.push(parsed);
        }

        noxtls_validate_certificate_chain(
            &leaf,
            &parsed_intermediates,
            &parsed_anchors,
            validation_time,
        )
        .map_err(noxtls_map_certificate_validation_error)?;
        self.tls13_server_leaf_public_key_der = Some(leaf.subject_public_key.clone());
        self.tls13_server_certificate_chain_validated = true;
        Ok(())
    }

    /// Verifies TLS 1.3 CertificateVerify signature over transcript-based context bytes.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    /// * `signature_scheme` — `signature_scheme: u16`.
    /// * `signature` — `signature: &[u8]`.
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
    fn noxtls_verify_tls13_server_certificate_verify_signature(
        &self,
        signature_scheme: u16,
        signature: &[u8],
    ) -> Result<()> {
        let leaf_spki =
            self.tls13_server_leaf_public_key_der
                .as_deref()
                .ok_or(Error::StateError(
                    "server leaf public key is unavailable for certificate verify",
                ))?;
        let signed_message = noxtls_build_tls13_server_certificate_verify_message(&self.noxtls_transcript_hash());
        match signature_scheme {
            TLS13_SIGALG_ECDSA_SECP256R1_SHA256 => {
                let public_key = P256PublicKey::from_uncompressed(leaf_spki)?;
                let (r, s) = noxtls_parse_ecdsa_signature_der(signature)?;
                noxtls_p256_ecdsa_verify_sha256(&public_key, &signed_message, &r, &s).map_err(
                    |_| {
                        Error::CryptoFailure("tls13 certificate verify signature validation failed")
                    },
                )
            }
            TLS13_SIGALG_RSA_PSS_RSAE_SHA256 => {
                let public_key = noxtls_parse_rsa_public_key_der(leaf_spki)?;
                noxtls_rsassa_pss_sha256_verify(&public_key, &signed_message, signature, 32)
                    .map_err(|_| {
                        Error::CryptoFailure("tls13 certificate verify signature validation failed")
                    })
            }
            TLS13_SIGALG_RSA_PSS_RSAE_SHA384 => {
                let public_key = noxtls_parse_rsa_public_key_der(leaf_spki)?;
                noxtls_rsassa_pss_sha384_verify(&public_key, &signed_message, signature, 48)
                    .map_err(|_| {
                        Error::CryptoFailure("tls13 certificate verify signature validation failed")
                    })
            }
            TLS13_SIGALG_ED25519 => {
                let public_key = noxtls_ed25519_public_key_from_subject_public_key_info(leaf_spki)?;
                noxtls_ed25519_verify(&public_key, &signed_message, signature).map_err(|_| {
                    Error::CryptoFailure("tls13 certificate verify signature validation failed")
                })
            }
            TLS13_SIGALG_MLDSA65 => {
                let public_key = MlDsaPublicKey::from_bytes(leaf_spki).map_err(|_| {
                    Error::ParseFailure("failed to parse mldsa server public key bytes")
                })?;
                noxtls_mldsa_verify(&public_key, &signed_message, signature).map_err(|_| {
                    Error::CryptoFailure("tls13 certificate verify signature validation failed")
                })
            }
            _ => Err(Error::UnsupportedFeature(
                "unsupported tls13 certificate verify signature scheme",
            )),
        }
    }

    /// Overrides record sequence counters for external validation harness scenarios.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `client_sequence` — `client_sequence: u64`.
    /// * `server_sequence` — `server_sequence: u64`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_record_sequences_for_test(&mut self, client_sequence: u64, server_sequence: u64) {
        self.client_sequence = client_sequence;
        self.server_sequence = server_sequence;
    }

    /// Installs CertificateVerify public-key material for validation harness testing flows.
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `leaf_spki_der` — `leaf_spki_der: Vec<u8>`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_set_tls13_certificate_verify_material_for_test(&mut self, leaf_spki_der: Vec<u8>) {
        self.tls13_server_leaf_public_key_der = Some(leaf_spki_der);
        self.tls13_server_certificate_chain_validated = true;
    }

    /// Builds TLS 1.3 server CertificateVerify transcript message bytes for external signing tests.
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    pub fn noxtls_tls13_server_certificate_verify_message_for_test(&self) -> Vec<u8> {
        noxtls_build_tls13_server_certificate_verify_message(&self.noxtls_transcript_hash())
    }

    /// Installs client/server traffic keys derived from handshake PRK.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `noxtls_hash_algorithm` — `noxtls_hash_algorithm: HashAlgorithm`.
    /// * `secret` — `secret: &[u8]`.
    /// * `noxtls_transcript_hash` — `noxtls_transcript_hash: &[u8]`.
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
    fn noxtls_install_traffic_keys(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        secret: &[u8],
        noxtls_transcript_hash: &[u8],
    ) -> Result<()> {
        let (client_key, server_key, client_iv, server_iv) = match self.version {
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let hash_len = noxtls_hash_algorithm.output_len();
                let client_hs_traffic = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    secret,
                    b"c hs traffic",
                    noxtls_transcript_hash,
                    hash_len,
                )?;
                let server_hs_traffic = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    secret,
                    b"s hs traffic",
                    noxtls_transcript_hash,
                    hash_len,
                )?;
                self.tls13_client_handshake_traffic_secret = Some(client_hs_traffic.clone());
                self.tls13_server_handshake_traffic_secret = Some(server_hs_traffic.clone());
                self.noxtls_install_tls13_record_protection_keys(
                    noxtls_hash_algorithm,
                    &client_hs_traffic,
                    &server_hs_traffic,
                )?;
                return Ok(());
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let client_key_16: [u8; 16] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"client_write_key", 16)?
                        .try_into()
                        .expect("hkdf output length should be 16");
                let server_key_16: [u8; 16] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"server_write_key", 16)?
                        .try_into()
                        .expect("hkdf output length should be 16");
                let mut client_key = [0_u8; 32];
                let mut server_key = [0_u8; 32];
                client_key[..16].copy_from_slice(&client_key_16);
                server_key[..16].copy_from_slice(&server_key_16);
                let client_iv: [u8; 12] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"client_write_iv", 12)?
                        .try_into()
                        .expect("hkdf output length should be 12");
                let server_iv: [u8; 12] =
                    noxtls_hkdf_expand_for_hash(noxtls_hash_algorithm, secret, b"server_write_iv", 12)?
                        .try_into()
                        .expect("hkdf output length should be 12");
                (client_key, server_key, client_iv, server_iv)
            }
        };
        self.client_write_key = Some(client_key);
        self.server_write_key = Some(server_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_iv = Some(server_iv);
        self.noxtls_sync_dtls13_traffic_keys_from_record_protection_state();
        Ok(())
    }

    /// Installs TLS 1.3 application traffic secrets and switches record keys to application epoch.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
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
    fn noxtls_install_tls13_application_traffic_keys(&mut self) -> Result<()> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Ok(());
        }
        let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
        let hash_len = noxtls_hash_algorithm.output_len();
        let noxtls_transcript_hash = self.noxtls_transcript_hash();
        let handshake_secret = self.handshake_secret.as_ref().ok_or(Error::StateError(
            "handshake secret must be available before tls13 application traffic keys",
        ))?;
        let derived = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            handshake_secret,
            b"derived",
            &noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &[]),
            hash_len,
        )?;
        let zero_ikm = vec![0_u8; hash_len];
        let master_secret =
            noxtls_hkdf_extract_with_salt_for_hash(noxtls_hash_algorithm, &derived, &zero_ikm);
        let client_app_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &master_secret,
            b"c ap traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        let server_app_secret = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            &master_secret,
            b"s ap traffic",
            &noxtls_transcript_hash,
            hash_len,
        )?;
        self.noxtls_install_tls13_record_protection_keys(
            noxtls_hash_algorithm,
            &client_app_secret,
            &server_app_secret,
        )?;
        self.noxtls_install_tls13_exporter_and_resumption_secrets(
            noxtls_hash_algorithm,
            &master_secret,
            &noxtls_transcript_hash,
        )?;
        self.tls13_master_secret = Some(master_secret);
        self.tls13_client_application_traffic_secret = Some(client_app_secret);
        self.tls13_server_application_traffic_secret = Some(server_app_secret);
        self.client_sequence = 0;
        self.server_sequence = 0;
        Ok(())
    }

    /// Derives TLS 1.3 exporter and resumption master secrets from current master secret.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `noxtls_hash_algorithm` — `noxtls_hash_algorithm: HashAlgorithm`.
    /// * `master_secret` — `master_secret: &[u8]`.
    /// * `noxtls_transcript_hash` — `noxtls_transcript_hash: &[u8]`.
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
    fn noxtls_install_tls13_exporter_and_resumption_secrets(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        master_secret: &[u8],
        noxtls_transcript_hash: &[u8],
    ) -> Result<()> {
        let hash_len = noxtls_hash_algorithm.output_len();
        self.tls13_exporter_master_secret = Some(noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            master_secret,
            b"exp master",
            noxtls_transcript_hash,
            hash_len,
        )?);
        self.noxtls_tls13_resumption_master_secret = Some(noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            master_secret,
            b"res master",
            noxtls_transcript_hash,
            hash_len,
        )?);
        Ok(())
    }

    /// Derives and installs TLS 1.3 record protection key/iv pairs from traffic secrets.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `noxtls_hash_algorithm` — `noxtls_hash_algorithm: HashAlgorithm`.
    /// * `client_traffic_secret` — `client_traffic_secret: &[u8]`.
    /// * `server_traffic_secret` — `server_traffic_secret: &[u8]`.
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
    fn noxtls_install_tls13_record_protection_keys(
        &mut self,
        noxtls_hash_algorithm: HashAlgorithm,
        client_traffic_secret: &[u8],
        server_traffic_secret: &[u8],
    ) -> Result<()> {
        let suite = self.noxtls_selected_cipher_suite.ok_or(Error::StateError(
            "cipher suite must be selected before tls13 record protection keys",
        ))?;
        let key_len = suite.noxtls_tls13_traffic_key_len().ok_or(Error::StateError(
            "tls 1.3 record protection requires a tls 1.3 AEAD cipher suite",
        ))?;
        let client_key_material = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let server_key_material = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_traffic_secret,
            b"key",
            &[],
            key_len,
        )?;
        let mut client_key = [0_u8; 32];
        let mut server_key = [0_u8; 32];
        client_key[..key_len].copy_from_slice(&client_key_material);
        server_key[..key_len].copy_from_slice(&server_key_material);
        let client_iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            client_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 iv length should be 12");
        let server_iv: [u8; 12] = noxtls_tls13_expand_label_for_hash(
            noxtls_hash_algorithm,
            server_traffic_secret,
            b"iv",
            &[],
            12,
        )?
        .try_into()
        .expect("tls13 iv length should be 12");
        self.client_write_key = Some(client_key);
        self.server_write_key = Some(server_key);
        self.client_write_iv = Some(client_iv);
        self.server_write_iv = Some(server_iv);
        self.noxtls_sync_dtls13_traffic_keys_from_record_protection_state();
        Ok(())
    }

    /// Mirrors installed record-protection keys into DTLS1.3 traffic state when using DTLS profile.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_sync_dtls13_traffic_keys_from_record_protection_state(&mut self) {
        if !self.version.is_dtls() {
            return;
        }
        self.dtls13_client_write_key = self.client_write_key.map(|full| {
            full[..16]
                .try_into()
                .expect("dtls13 shim copies first 16 bytes of traffic key material")
        });
        self.dtls13_client_write_iv = self.client_write_iv;
        self.dtls13_server_write_key = self.server_write_key.map(|full| {
            full[..16]
                .try_into()
                .expect("dtls13 shim copies first 16 bytes of traffic key material")
        });
        self.dtls13_server_write_iv = self.server_write_iv;
        self.dtls13_outbound_epoch = 0;
        self.dtls13_outbound_sequence = 0;
        self.dtls13_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
        self.dtls13_client_inbound_replay_tracker = DtlsEpochReplayTracker::noxtls_new();
    }

    /// Probes alternate decrypt hypotheses for TLS 1.3 record-open failures when debug is enabled.
    ///
    /// # Arguments
    ///
    /// * `record` — Decoded protected TLSCiphertext components.
    /// * `aad` — Additional authenticated data used for AEAD authentication.
    ///
    /// # Returns
    ///
    /// `()` after emitting optional debug hints.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_debug_probe_tls13_open_record_failure(&self, record: &ProtectedRecord, aad: &[u8]) {
        if !noxtls_tls13_debug_enabled() {
            return;
        }
        let Some(suite) = self.noxtls_selected_cipher_suite else {
            return;
        };
        let Some(key_len) = suite.noxtls_tls13_traffic_key_len() else {
            return;
        };
        let probe_key = |label: &str, key: &[u8; 32], iv: &[u8; 12], seq: u64| {
            let nonce = noxtls_build_record_nonce(iv, seq);
            let status = match AesCipher::noxtls_new(&key[..key_len]) {
                Ok(cipher) => noxtls_aes_gcm_decrypt(
                    &cipher,
                    &nonce,
                    aad,
                    &record.ciphertext,
                    &record.tag,
                )
                .is_ok(),
                Err(_) => false,
            };
            if status {
                noxtls_tls13_debug_log(label, "success");
            } else {
                noxtls_tls13_debug_log(label, "fail");
            }
        };
        if let (Some(key), Some(iv)) = (self.server_write_key.as_ref(), self.server_write_iv.as_ref()) {
            probe_key("tls13.open_record.probe.server_seq+1", key, iv, record.sequence.saturating_add(1));
            probe_key("tls13.open_record.probe.server_seq+2", key, iv, record.sequence.saturating_add(2));
            let mut nonce_first8_be = *iv;
            for (idx, byte) in record.sequence.to_be_bytes().iter().enumerate() {
                nonce_first8_be[idx] ^= *byte;
            }
            let first8_be_ok = match AesCipher::noxtls_new(&key[..key_len]) {
                Ok(cipher) => noxtls_aes_gcm_decrypt(
                    &cipher,
                    &nonce_first8_be,
                    aad,
                    &record.ciphertext,
                    &record.tag,
                )
                .is_ok(),
                Err(_) => false,
            };
            noxtls_tls13_debug_log(
                "tls13.open_record.probe.server_nonce_first8_be",
                if first8_be_ok { "success" } else { "fail" },
            );
            let mut nonce_last8_le = *iv;
            for (idx, byte) in record.sequence.to_le_bytes().iter().enumerate() {
                nonce_last8_le[4 + idx] ^= *byte;
            }
            let last8_le_ok = match AesCipher::noxtls_new(&key[..key_len]) {
                Ok(cipher) => noxtls_aes_gcm_decrypt(
                    &cipher,
                    &nonce_last8_le,
                    aad,
                    &record.ciphertext,
                    &record.tag,
                )
                .is_ok(),
                Err(_) => false,
            };
            noxtls_tls13_debug_log(
                "tls13.open_record.probe.server_nonce_last8_le",
                if last8_le_ok { "success" } else { "fail" },
            );
            let mut nonce_first8_le = *iv;
            for (idx, byte) in record.sequence.to_le_bytes().iter().enumerate() {
                nonce_first8_le[idx] ^= *byte;
            }
            let first8_le_ok = match AesCipher::noxtls_new(&key[..key_len]) {
                Ok(cipher) => noxtls_aes_gcm_decrypt(
                    &cipher,
                    &nonce_first8_le,
                    aad,
                    &record.ciphertext,
                    &record.tag,
                )
                .is_ok(),
                Err(_) => false,
            };
            noxtls_tls13_debug_log(
                "tls13.open_record.probe.server_nonce_first8_le",
                if first8_le_ok { "success" } else { "fail" },
            );
        }
        if let (Some(key), Some(iv)) = (self.client_write_key.as_ref(), self.client_write_iv.as_ref()) {
            probe_key("tls13.open_record.probe.client_seq+0", key, iv, record.sequence);
        }
    }

    /// Computes version-appropriate expected **peer** Finished `verify_data` bytes.
    ///
    /// For TLS 1.3 this expands the Finished key from the **server** handshake traffic
    /// secret and HMACs the current transcript hash — i.e. the value a **client**
    /// `Connection` expects from the server's `Finished` message after handshake keys
    /// are installed. TLS 1.2 uses the PRF `client finished` label over the master
    /// secret for the same peer-verification role in modeled tests.
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
    pub fn noxtls_compute_expected_finished(&self) -> Result<Vec<u8>> {
        let hash = self.noxtls_transcript_hash();
        match self.version {
            TlsVersion::Tls12 | TlsVersion::Dtls12 => {
                let secret = self.handshake_secret.as_ref().ok_or(Error::StateError(
                    "handshake secret must be available before finished",
                ))?;
                noxtls_tls12_prf_for_hash(
                    self.noxtls_negotiated_hash_algorithm(),
                    secret,
                    b"client finished",
                    &hash,
                    12,
                )
            }
            TlsVersion::Tls13 | TlsVersion::Dtls13 => {
                let noxtls_hash_algorithm = self.noxtls_negotiated_hash_algorithm();
                let hash_len = noxtls_hash_algorithm.output_len();
                let server_hs = self
                    .tls13_server_handshake_traffic_secret
                    .as_ref()
                    .ok_or(Error::StateError(
                        "tls13 server handshake traffic secret must be installed before finished verify",
                    ))?;
                let finished_key = noxtls_tls13_expand_label_for_hash(
                    noxtls_hash_algorithm,
                    server_hs,
                    b"finished",
                    &[],
                    hash_len,
                )?;
                Ok(noxtls_finished_hmac_for_hash(
                    noxtls_hash_algorithm,
                    &finished_key,
                    &hash,
                ))
            }
            TlsVersion::Tls10 | TlsVersion::Tls11 => Ok(noxtls_finished_hmac_for_hash(
                self.noxtls_negotiated_hash_algorithm(),
                b"finished",
                &hash,
            )),
        }
    }

    /// Appends bytes to transcript log and selected transcript hash context.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    /// * `message` — `message: &[u8]`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_append_transcript(&mut self, message: &[u8]) {
        self.transcript.extend_from_slice(message);
        self.noxtls_transcript_hash.noxtls_update(message);
    }

    /// Resets transcript bytes/hash for a noxtls_new handshake flight from `Idle`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_reset_transcript_for_new_handshake(&mut self) {
        self.transcript.clear();
        self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
    }

    /// Resets transcript context to a single ClientHello for modeled 0-RTT server decrypt.
    ///
    /// # Arguments
    ///
    /// * `client_hello` — Encoded ClientHello message bytes to anchor early-data transcript hash.
    ///
    /// # Returns
    ///
    /// `()`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    fn noxtls_reset_tls13_early_data_transcript_to_client_hello(&mut self, client_hello: &[u8]) {
        self.transcript.clear();
        self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
        self.noxtls_append_transcript(client_hello);
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
    fn noxtls_prepare_client_key_share(&mut self, random: &[u8]) -> Result<Tls13ClientPublicKeyShares> {
        if !self.version.uses_tls13_handshake_semantics() {
            return Ok(Tls13ClientPublicKeyShares::default());
        }
        let x25519_private =
            noxtls_derive_deterministic_x25519_private(random, b"tls13 client x25519");
        let x25519_public = x25519_private.clone().public_key().bytes;
        noxtls_tls13_debug_log_bytes("tls13.client_key_share.x25519_private", &x25519_private.to_bytes());
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
            hybrid_pub.extend_from_slice(&x25519_public);
            hybrid_pub.extend_from_slice(&mlkem_pub);
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

    /// Rebuilds transcript hash context from stored transcript bytes and selected suite policy.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_rebuild_transcript_hash_from_selected_suite(&mut self) {
        let Some(suite) = self.noxtls_selected_cipher_suite else {
            return;
        };
        self.noxtls_transcript_hash = suite.noxtls_transcript_hash_state();
        self.noxtls_transcript_hash.noxtls_update(&self.transcript);
    }

    /// Applies TLS 1.3 HRR transcript reset via synthetic message_hash entry.
    ///
    /// # Arguments
    ///
    /// * `self` — `&mut self`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_reset_transcript_for_hrr(&mut self) {
        let prior_hash = self.noxtls_transcript_hash();
        self.transcript.clear();
        if let Some(suite) = self.noxtls_selected_cipher_suite {
            self.noxtls_transcript_hash = suite.noxtls_transcript_hash_state();
        } else {
            self.noxtls_transcript_hash = TranscriptHashState::noxtls_for_version(self.version);
        }
        let message_hash = noxtls_encode_handshake_message(0xFE, &prior_hash);
        self.noxtls_append_transcript(&message_hash);
    }

    /// Resolves hash noxtls_algorithm from negotiated suite or current transcript state fallback.
    ///
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the return type in the function signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    fn noxtls_negotiated_hash_algorithm(&self) -> HashAlgorithm {
        self.noxtls_selected_cipher_suite
            .map(CipherSuite::noxtls_hash_algorithm)
            .unwrap_or_else(|| self.noxtls_transcript_hash.noxtls_algorithm())
    }
}

/// Implements TLS 1.3-style handshake secret derivation from placeholder ECDHE material.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — `noxtls_hash_algorithm: HashAlgorithm`.
/// * `shared_secret` — `shared_secret: &[u8]`.
/// * `suite` — `suite: Option<CipherSuite>`.
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
fn noxtls_derive_tls13_handshake_secret(
    noxtls_hash_algorithm: HashAlgorithm,
    shared_secret: &[u8],
    suite: Option<CipherSuite>,
) -> Result<Vec<u8>> {
    let hash_len = noxtls_hash_algorithm.output_len();
    // RFC 8446: when PSK is not in use, psk is a zero-filled Hash.length string.
    let zero_psk = vec![0_u8; hash_len];
    let early_secret = noxtls_hkdf_extract_for_hash(noxtls_hash_algorithm, &zero_psk);
    noxtls_tls13_debug_log_bytes("tls13.kdf.early_secret", &early_secret);
    let empty_hash = noxtls_hash_bytes_for_algorithm(noxtls_hash_algorithm, &[]);
    let derived = noxtls_tls13_expand_label_for_hash(
        noxtls_hash_algorithm,
        &early_secret,
        b"derived",
        &empty_hash,
        hash_len,
    )?;
    noxtls_tls13_debug_log_bytes("tls13.kdf.derived_secret", &derived);
    let mut handshake_secret =
        noxtls_hkdf_extract_with_salt_for_hash(noxtls_hash_algorithm, &derived, shared_secret);
    if let Some(selected) = suite {
        if selected.noxtls_hash_algorithm() != noxtls_hash_algorithm {
            handshake_secret = noxtls_hkdf_extract_with_salt_for_hash(
                selected.noxtls_hash_algorithm(),
                &derived,
                shared_secret,
            );
        }
    }
    Ok(handshake_secret)
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
fn noxtls_combine_tls13_hybrid_shared_secret(classical: &[u8; 32], pq: &[u8; 32]) -> [u8; 32] {
    noxtls_sha256(&[classical.as_slice(), pq.as_slice()].concat())
}

/// Routes TLS 1.2 PRF derivation through suite-selected hash policy.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — `noxtls_hash_algorithm: HashAlgorithm`.
/// * `secret` — `secret: &[u8]`.
/// * `label` — `label: &[u8]`.
/// * `seed` — `seed: &[u8]`.
/// * `len` — `len: usize`.
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
fn noxtls_tls12_prf_for_hash(
    noxtls_hash_algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => noxtls_tls12_prf_sha256(secret, label, seed, len),
        HashAlgorithm::Sha384 => noxtls_tls12_prf_sha384(secret, label, seed, len),
    }
}

/// Compares byte slices in constant-time style and returns equality result.
///
/// # Arguments
///
/// * `left` — `left: &[u8]`.
/// * `right` — `right: &[u8]`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}

/// Extracts first PSK binder value from encoded ClientHello pre_shared_key extension.
///
/// # Arguments
///
/// * `client_hello` — `client_hello: &[u8]`.
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
fn noxtls_extract_first_psk_binder_from_client_hello(client_hello: &[u8]) -> Result<Vec<u8>> {
    let info = noxtls_parse_client_hello_info(client_hello)?;
    info.extensions
        .psk_binders
        .first()
        .cloned()
        .ok_or(Error::ParseFailure(
            "client hello missing pre_shared_key binder",
        ))
}

/// Returns ClientHello copy with all pre_shared_key binder bytes replaced with zeros.
///
/// # Arguments
///
/// * `client_hello` — `client_hello: &[u8]`.
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
fn noxtls_zero_client_hello_psk_binders(client_hello: &[u8]) -> Result<Vec<u8>> {
    let (handshake_type, body) = noxtls_parse_handshake_message(client_hello)?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return Err(Error::ParseFailure("invalid client hello type"));
    }
    if body.len() < 39 {
        return Err(Error::ParseFailure("client hello body too short"));
    }
    let mut out = client_hello.to_vec();
    let session_id_len = body[34] as usize;
    let suites_len_offset = 35 + session_id_len;
    if body.len() < suites_len_offset + 2 {
        return Err(Error::ParseFailure(
            "client hello missing cipher suites length",
        ));
    }
    let suites_len =
        u16::from_be_bytes([body[suites_len_offset], body[suites_len_offset + 1]]) as usize;
    let suites_end = suites_len_offset + 2 + suites_len;
    if body.len() < suites_end + 3 {
        return Err(Error::ParseFailure(
            "client hello missing compression methods",
        ));
    }
    let compression_methods_len = body[suites_end] as usize;
    let compression_methods_end = suites_end + 1 + compression_methods_len;
    if body.len() < compression_methods_end + 2 {
        return Err(Error::ParseFailure("client hello missing extension length"));
    }
    let extensions_len = u16::from_be_bytes([
        body[compression_methods_end],
        body[compression_methods_end + 1],
    ]) as usize;
    let extensions_start_in_body = compression_methods_end + 2;
    let extensions_end_in_body = extensions_start_in_body + extensions_len;
    if body.len() < extensions_end_in_body {
        return Err(Error::ParseFailure("client hello extensions truncated"));
    }

    let body_offset = 4; // handshake header bytes in full message
    let mut ext_cursor = extensions_start_in_body;
    while ext_cursor < extensions_end_in_body {
        if extensions_end_in_body - ext_cursor < 4 {
            return Err(Error::ParseFailure(
                "client hello extension header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([body[ext_cursor], body[ext_cursor + 1]]);
        let ext_len = u16::from_be_bytes([body[ext_cursor + 2], body[ext_cursor + 3]]) as usize;
        let ext_data_start = ext_cursor + 4;
        let ext_data_end = ext_data_start + ext_len;
        if ext_data_end > extensions_end_in_body {
            return Err(Error::ParseFailure("client hello extension truncated"));
        }
        if ext_type == EXT_PRE_SHARED_KEY {
            if ext_len < 4 {
                return Err(Error::ParseFailure("pre_shared_key extension too short"));
            }
            let identities_len =
                u16::from_be_bytes([body[ext_data_start], body[ext_data_start + 1]]) as usize;
            if ext_len < 2 + identities_len + 2 {
                return Err(Error::ParseFailure("pre_shared_key identities truncated"));
            }
            let binders_len_offset = ext_data_start + 2 + identities_len;
            let binders_len =
                u16::from_be_bytes([body[binders_len_offset], body[binders_len_offset + 1]])
                    as usize;
            let mut binder_cursor = binders_len_offset + 2;
            let binders_end = binder_cursor + binders_len;
            if binders_end != ext_data_end {
                return Err(Error::ParseFailure(
                    "invalid pre_shared_key binder vector length",
                ));
            }
            while binder_cursor < binders_end {
                let binder_len = body[binder_cursor] as usize;
                binder_cursor += 1;
                if binder_cursor + binder_len > binders_end {
                    return Err(Error::ParseFailure("pre_shared_key binder bytes truncated"));
                }
                let start = body_offset + binder_cursor;
                let end = start + binder_len;
                out[start..end].fill(0);
                binder_cursor += binder_len;
            }
            return Ok(out);
        }
        ext_cursor = ext_data_end;
    }

    Err(Error::ParseFailure(
        "client hello missing pre_shared_key extension",
    ))
}

/// Returns default client-advertised suites for the current prototype version.
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
///
/// # Returns
///
/// The value described by the return type in the function signature.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_default_client_cipher_suites(version: TlsVersion) -> Vec<CipherSuite> {
    match version {
        TlsVersion::Tls13 | TlsVersion::Dtls13 => vec![
            CipherSuite::TlsAes256GcmSha384,
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsChacha20Poly1305Sha256,
        ],
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
            vec![
                CipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256,
            ]
        }
    }
}

/// Encodes a minimally structured TLS ClientHello body for prototype negotiation.
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
/// * `random` — `random: &[u8]`.
/// * `suites` — `suites: &[CipherSuite]`.
/// * `key_shares` — `key_shares: &Tls13ClientPublicKeyShares`.
/// * `sni_server_name` — `sni_server_name: Option<&str>`.
/// * `alpn_protocols` — `alpn_protocols: &[Vec<u8>]`.
/// * `offer_early_data` — `offer_early_data: bool`.
/// * `psk_offer` — `psk_offer: Option<&PskClientOffer<'_>>`.
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
#[allow(clippy::too_many_arguments)]
fn noxtls_encode_client_hello_body(
    version: TlsVersion,
    random: &[u8],
    suites: &[CipherSuite],
    key_shares: &Tls13ClientPublicKeyShares,
    sni_server_name: Option<&str>,
    alpn_protocols: &[Vec<u8>],
    request_ocsp_stapling: bool,
    offer_mldsa_signature: bool,
    offer_early_data: bool,
    psk_offer: Option<&PskClientOffer<'_>>,
    noxtls_tls12_session_id: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if random.len() != 32 {
        return Err(Error::InvalidLength("client hello random must be 32 bytes"));
    }
    if suites.is_empty() {
        return Err(Error::InvalidLength(
            "client hello suite list must not be empty",
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&noxtls_legacy_wire_version(version));
    body.extend_from_slice(random);
    if version == TlsVersion::Tls12 {
        let session_id = noxtls_tls12_session_id.unwrap_or(&[]);
        if session_id.len() > 32 {
            return Err(Error::InvalidLength(
                "tls12 session id must not exceed 32 bytes",
            ));
        }
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
    } else {
        body.push(0x00); // session_id length
    }
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for suite in suites {
        body.extend_from_slice(&suite.noxtls_to_u16().to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null
    let extensions = noxtls_build_client_hello_extensions(
        version,
        key_shares,
        sni_server_name,
        alpn_protocols,
        request_ocsp_stapling,
        offer_mldsa_signature,
        offer_early_data,
        psk_offer,
    )?;
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    Ok(body)
}

/// Encodes a minimally structured TLS ServerHello body for prototype parsing.
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
/// * `suite` — `suite: CipherSuite`.
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
fn noxtls_encode_server_hello_body(
    version: TlsVersion,
    suite: CipherSuite,
    random: &[u8],
) -> Result<Vec<u8>> {
    noxtls_encode_server_hello_body_with_key_share(version, suite, random, None)
}

/// Encodes ServerHello with optional explicit `key_share` bytes (for tests and tooling).
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
/// * `suite` — `suite: CipherSuite`.
/// * `random` — `random: &[u8]`.
/// * `key_share_override` — `key_share_override: Option<(u16, &[u8])>`.
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
fn noxtls_encode_server_hello_body_with_key_share(
    version: TlsVersion,
    suite: CipherSuite,
    random: &[u8],
    key_share_override: Option<(u16, &[u8])>,
) -> Result<Vec<u8>> {
    if random.len() != 32 {
        return Err(Error::InvalidLength("server hello random must be 32 bytes"));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&noxtls_legacy_wire_version(version));
    body.extend_from_slice(random);
    body.push(0x00); // session_id length
    body.extend_from_slice(&suite.noxtls_to_u16().to_be_bytes());
    body.push(0x00); // compression method
    let mut extensions = Vec::new();
    if version.uses_tls13_handshake_semantics() {
        noxtls_push_extension(
            &mut extensions,
            EXT_SUPPORTED_VERSIONS,
            &0x0304_u16.to_be_bytes(),
        );
        let mut key_share = Vec::new();
        if let Some((g, bytes)) = key_share_override {
            if g == TLS13_KEY_SHARE_GROUP_X25519 && bytes.len() != 32 {
                return Err(Error::ParseFailure(
                    "invalid x25519 server key_share key_exchange length",
                ));
            }
            if g == TLS13_KEY_SHARE_GROUP_SECP256R1 && bytes.len() != 65 {
                return Err(Error::ParseFailure(
                    "invalid secp256r1 server key_share key_exchange length",
                ));
            }
            if g == TLS13_KEY_SHARE_GROUP_MLKEM768 && bytes.len() != MLKEM_CIPHERTEXT_LEN {
                return Err(Error::ParseFailure(
                    "invalid mlkem768 server key_share key_exchange length",
                ));
            }
            if g == TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID
                && bytes.len() != (32 + MLKEM_CIPHERTEXT_LEN)
            {
                return Err(Error::ParseFailure(
                    "invalid x25519_mlkem768 hybrid server key_share key_exchange length",
                ));
            }
            if g != TLS13_KEY_SHARE_GROUP_X25519
                && g != TLS13_KEY_SHARE_GROUP_SECP256R1
                && g != TLS13_KEY_SHARE_GROUP_MLKEM768
                && g != TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID
            {
                return Err(Error::ParseFailure("unsupported server key_share group"));
            }
            key_share.extend_from_slice(&g.to_be_bytes());
            key_share.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            key_share.extend_from_slice(bytes);
        } else {
            let private =
                noxtls_derive_deterministic_x25519_private(random, b"tls13 server x25519");
            let public = private.public_key().bytes;
            key_share.extend_from_slice(&TLS13_KEY_SHARE_GROUP_X25519.to_be_bytes());
            key_share.extend_from_slice(&32_u16.to_be_bytes());
            key_share.extend_from_slice(&public);
        }
        noxtls_push_extension(&mut extensions, EXT_KEY_SHARE, &key_share);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    Ok(body)
}

/// Parses supported server hello encoding and extracts selected cipher suite.
///
/// # Arguments
///
/// * `msg` — `msg: &[u8]`.
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
fn noxtls_parse_server_hello(msg: &[u8]) -> Result<ParsedServerHello> {
    if msg.len() == 3 && msg.first().copied() == Some(HANDSHAKE_SERVER_HELLO) {
        let suite_id = u16::from_be_bytes([msg[1], msg[2]]);
        let suite = CipherSuite::noxtls_from_u16(suite_id)
            .ok_or(Error::ParseFailure("unsupported cipher suite"))?;
        return Ok(ParsedServerHello {
            suite,
            key_share: None,
            hello_retry_request: false,
            requested_group: None,
        });
    }

    let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
    if handshake_type != HANDSHAKE_SERVER_HELLO {
        return Err(Error::ParseFailure("invalid server hello type"));
    }
    if body.len() < 40 {
        return Err(Error::ParseFailure("server hello body too short"));
    }
    let session_id_len = body[34] as usize;
    let suite_start = 35 + session_id_len;
    let suite_end = suite_start + 2;
    if body.len() < suite_end + 3 {
        return Err(Error::ParseFailure("server hello missing cipher suite"));
    }
    let suite_id = u16::from_be_bytes([body[suite_start], body[suite_start + 1]]);
    let suite =
        CipherSuite::noxtls_from_u16(suite_id).ok_or(Error::ParseFailure("unsupported cipher suite"))?;
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    if noxtls_is_tls13_suite(suite) && legacy_version != 0x0303 && legacy_version != 0xFEFD {
        return Err(Error::ParseFailure(
            "invalid tls13 server hello legacy_version",
        ));
    }
    let compression_method = body[suite_end];
    if compression_method != 0x00 {
        return Err(Error::ParseFailure(
            "invalid server hello compression method",
        ));
    }
    let random = &body[2..34];
    let hello_retry_request = random == TLS13_HRR_RANDOM;
    let mut key_share_parsed = None;
    let mut requested_group = None;
    let mut seen_key_share_extension = false;
    let mut seen_supported_versions_extension = false;
    let mut supports_tls13 = false;
    let mut seen_extension_types = Vec::new();
    let ext_len_offset = suite_end + 1;
    let ext_len = u16::from_be_bytes([body[ext_len_offset], body[ext_len_offset + 1]]) as usize;
    let ext_start = ext_len_offset + 2;
    let ext_end = ext_start + ext_len;
    if ext_end > body.len() {
        return Err(Error::ParseFailure("server hello extensions truncated"));
    }
    let mut cursor = &body[ext_start..ext_end];
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "server hello extension header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_data_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if cursor.len() < ext_data_len {
            return Err(Error::ParseFailure("server hello extension truncated"));
        }
        if seen_extension_types.contains(&ext_type) {
            return Err(Error::ParseFailure("duplicate server hello extension type"));
        }
        seen_extension_types.push(ext_type);
        let ext_data = &cursor[..ext_data_len];
        match ext_type {
            EXT_SIGNATURE_ALGORITHMS | EXT_PSK_KEY_EXCHANGE_MODES | EXT_SERVER_NAME => {
                return Err(Error::ParseFailure(
                    "server hello contains forbidden extension type",
                ));
            }
            EXT_SUPPORTED_VERSIONS => {
                if ext_data_len != 2 {
                    return Err(Error::ParseFailure(
                        "invalid server hello supported_versions length",
                    ));
                }
                seen_supported_versions_extension = true;
                let selected_version = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                if selected_version != 0x0304 {
                    return Err(Error::ParseFailure(
                        "invalid tls13 server hello supported_versions value",
                    ));
                }
                supports_tls13 = true;
            }
            EXT_KEY_SHARE => {
                seen_key_share_extension = true;
                if hello_retry_request {
                    if ext_data_len != 2 {
                        return Err(Error::ParseFailure("invalid hrr key_share length"));
                    }
                    requested_group = Some(u16::from_be_bytes([ext_data[0], ext_data[1]]));
                } else {
                    if ext_data_len < 4 {
                        return Err(Error::ParseFailure("invalid server key_share length"));
                    }
                    let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                    if ext_data_len != 4 + key_len {
                        return Err(Error::ParseFailure("invalid server key_share length"));
                    }
                    key_share_parsed = Some(match group {
                        TLS13_KEY_SHARE_GROUP_X25519 => {
                            if key_len != 32 {
                                return Err(Error::ParseFailure(
                                    "invalid x25519 server key_share key_exchange length",
                                ));
                            }
                            let mut key = [0_u8; 32];
                            key.copy_from_slice(&ext_data[4..36]);
                            Tls13ServerKeyShareParsed::X25519(key)
                        }
                        TLS13_KEY_SHARE_GROUP_SECP256R1 => {
                            if key_len != 65 {
                                return Err(Error::ParseFailure(
                                    "invalid secp256r1 server key_share key_exchange length",
                                ));
                            }
                            let mut key = [0_u8; 65];
                            key.copy_from_slice(&ext_data[4..69]);
                            Tls13ServerKeyShareParsed::Secp256r1(key)
                        }
                        TLS13_KEY_SHARE_GROUP_MLKEM768 => {
                            if key_len != MLKEM_CIPHERTEXT_LEN {
                                return Err(Error::ParseFailure(
                                    "invalid mlkem768 server key_share key_exchange length",
                                ));
                            }
                            Tls13ServerKeyShareParsed::MlKem768(ext_data[4..].to_vec())
                        }
                        TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID => {
                            if key_len != (32 + MLKEM_CIPHERTEXT_LEN) {
                                return Err(Error::ParseFailure(
                                    "invalid x25519_mlkem768 hybrid server key_share key_exchange length",
                                ));
                            }
                            let mut x25519 = [0_u8; 32];
                            x25519.copy_from_slice(&ext_data[4..36]);
                            let mlkem768 = ext_data[36..].to_vec();
                            Tls13ServerKeyShareParsed::X25519MlKem768Hybrid { x25519, mlkem768 }
                        }
                        _ => {
                            return Err(Error::ParseFailure("unsupported server key_share"));
                        }
                    });
                }
            }
            _ => {}
        }
        cursor = &cursor[ext_data_len..];
    }
    if hello_retry_request && !seen_key_share_extension {
        return Err(Error::ParseFailure("hrr missing key_share extension"));
    }
    if !hello_retry_request
        && noxtls_is_tls13_suite(suite)
        && legacy_version == 0x0303
        && !seen_supported_versions_extension
    {
        return Err(Error::ParseFailure(
            "tls13 server hello missing supported_versions extension",
        ));
    }
    if !hello_retry_request && noxtls_is_tls13_suite(suite) && legacy_version == 0x0303 && !supports_tls13
    {
        return Err(Error::ParseFailure(
            "invalid tls13 server hello supported_versions value",
        ));
    }
    if !hello_retry_request
        && noxtls_is_tls13_suite(suite)
        && legacy_version == 0x0303
        && !seen_key_share_extension
    {
        return Err(Error::ParseFailure(
            "tls13 server hello missing key_share extension",
        ));
    }
    Ok(ParsedServerHello {
        suite,
        key_share: key_share_parsed,
        hello_retry_request,
        requested_group,
    })
}

/// Returns true when suite belongs to TLS 1.3 suite registry.
///
/// # Arguments
///
/// * `suite` — `suite: CipherSuite`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_is_tls13_suite(suite: CipherSuite) -> bool {
    matches!(
        suite,
        CipherSuite::TlsAes128GcmSha256
            | CipherSuite::TlsAes256GcmSha384
            | CipherSuite::TlsChacha20Poly1305Sha256
    )
}

/// Parses minimally-structured ClientHello and extracts suite + extension metadata.
///
/// # Arguments
///
/// * `msg` — `msg: &[u8]`.
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
fn noxtls_parse_client_hello_info(msg: &[u8]) -> Result<ClientHelloInfo> {
    let (handshake_type, body) = noxtls_parse_handshake_message(msg)?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return Err(Error::ParseFailure("invalid client hello type"));
    }
    if body.len() < 39 {
        return Err(Error::ParseFailure("client hello body too short"));
    }
    let session_id_len = body[34] as usize;
    let suites_len_offset = 35 + session_id_len;
    if body.len() < suites_len_offset + 2 {
        return Err(Error::ParseFailure(
            "client hello missing cipher suites length",
        ));
    }
    let suites_len =
        u16::from_be_bytes([body[suites_len_offset], body[suites_len_offset + 1]]) as usize;
    if suites_len == 0 || !suites_len.is_multiple_of(2) {
        return Err(Error::ParseFailure(
            "invalid client hello cipher suites length",
        ));
    }
    let suites_start = suites_len_offset + 2;
    let suites_end = suites_start + suites_len;
    if body.len() < suites_end + 3 {
        return Err(Error::ParseFailure("client hello cipher suites truncated"));
    }

    let mut suites = Vec::new();
    for chunk in body[suites_start..suites_end].chunks_exact(2) {
        let codepoint = u16::from_be_bytes([chunk[0], chunk[1]]);
        if let Some(suite) = CipherSuite::noxtls_from_u16(codepoint) {
            suites.push(suite);
        }
    }
    if suites.is_empty() {
        return Err(Error::ParseFailure(
            "client hello has no supported cipher suite",
        ));
    }

    let compression_methods_len = body[suites_end] as usize;
    let compression_methods_start = suites_end + 1;
    let compression_methods_end = compression_methods_start + compression_methods_len;
    if body.len() < compression_methods_end + 2 {
        return Err(Error::ParseFailure(
            "client hello missing compression methods",
        ));
    }
    let extensions_len = u16::from_be_bytes([
        body[compression_methods_end],
        body[compression_methods_end + 1],
    ]) as usize;
    let extensions_start = compression_methods_end + 2;
    let extensions_end = extensions_start + extensions_len;
    if body.len() < extensions_end {
        return Err(Error::ParseFailure("client hello extensions truncated"));
    }
    if body.len() != extensions_end {
        return Err(Error::ParseFailure("client hello has trailing bytes"));
    }
    let extensions = noxtls_parse_client_hello_extensions(&body[extensions_start..extensions_end])?;

    Ok(ClientHelloInfo {
        offered_cipher_suites: suites,
        extensions,
    })
}

/// Chooses the first server-preferred suite also present in client offer.
///
/// # Arguments
///
/// * `hello` — `hello: &ClientHelloInfo`.
/// * `preferred` — `preferred: &[CipherSuite]`.
/// * `version` — `version: TlsVersion`.
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
fn noxtls_pick_intersection_suite(
    hello: &ClientHelloInfo,
    preferred: &[CipherSuite],
    version: TlsVersion,
) -> Result<CipherSuite> {
    for suite in preferred {
        if !hello.offered_cipher_suites.contains(suite) {
            continue;
        }
        if !noxtls_suite_supported_by_version(*suite, version) {
            continue;
        }
        if noxtls_suite_allowed_by_extensions(*suite, version, &hello.extensions) {
            return Ok(*suite);
        }
    }
    Err(Error::ParseFailure("no mutually supported cipher suite"))
}

/// Returns true when one suite is valid for the target protocol version family.
///
/// # Arguments
///
/// * `suite` — `suite: CipherSuite`.
/// * `version` — `version: TlsVersion`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_suite_supported_by_version(suite: CipherSuite, version: TlsVersion) -> bool {
    match version {
        TlsVersion::Tls13 | TlsVersion::Dtls13 => matches!(
            suite,
            CipherSuite::TlsAes128GcmSha256
                | CipherSuite::TlsAes256GcmSha384
                | CipherSuite::TlsChacha20Poly1305Sha256
        ),
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
            matches!(
                suite,
                CipherSuite::TlsEcdheRsaWithAes128GcmSha256
                    | CipherSuite::TlsEcdheRsaWithAes256GcmSha384
            )
        }
    }
}

/// Applies extension-level checks for negotiated suite acceptance.
///
/// # Arguments
///
/// * `suite` — `suite: CipherSuite`.
/// * `version` — `version: TlsVersion`.
/// * `extensions` — `extensions: &ClientHelloExtensions`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_suite_allowed_by_extensions(
    suite: CipherSuite,
    version: TlsVersion,
    extensions: &ClientHelloExtensions,
) -> bool {
    match version {
        TlsVersion::Tls13 | TlsVersion::Dtls13 => {
            if matches!(
                suite,
                CipherSuite::TlsAes128GcmSha256
                    | CipherSuite::TlsAes256GcmSha384
                    | CipherSuite::TlsChacha20Poly1305Sha256
            ) {
                return noxtls_tls13_client_hello_offers_supported_key_exchange(
                    &extensions.supported_versions,
                    &extensions.key_share_groups,
                    &extensions.signature_algorithms,
                );
            }
            true
        }
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => true,
    }
}

/// Returns whether TLS13 debug tracing is enabled at runtime.
///
/// # Arguments
///
/// * _(none)_ — This function takes no parameters.
///
/// # Returns
///
/// `true` when environment variable `NOXTLS_TLS13_DEBUG` is present; `false` otherwise.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_tls13_debug_enabled() -> bool {
    #[cfg(feature = "std")]
    {
        std::env::var_os("NOXTLS_TLS13_DEBUG").is_some()
    }
    #[cfg(not(feature = "std"))]
    {
        false
    }
}

/// Logs one TLS13 debug key/value pair when debug tracing is enabled.
///
/// # Arguments
///
/// * `label` — Short field identifier describing the logged value.
/// * `value` — Human-readable value string to print.
///
/// # Returns
///
/// `()` after optionally emitting one debug line.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_tls13_debug_log(label: &str, value: &str) {
    if !noxtls_tls13_debug_enabled() {
        return;
    }
    #[cfg(feature = "std")]
    {
        eprintln!("tls13_debug::{label}={value}");
    }
}

/// Logs one TLS13 debug byte slice as lowercase hexadecimal.
///
/// # Arguments
///
/// * `label` — Short field identifier describing the logged bytes.
/// * `bytes` — Opaque bytes to encode in hexadecimal.
///
/// # Returns
///
/// `()` after optionally emitting one debug line.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_tls13_debug_log_bytes(label: &str, bytes: &[u8]) {
    if !noxtls_tls13_debug_enabled() {
        return;
    }
    noxtls_tls13_debug_log(label, &noxtls_encode_hex(bytes));
}

/// Formats a byte slice as lowercase hexadecimal without separators.
///
/// # Arguments
///
/// * `bytes` — Byte slice to encode.
///
/// # Returns
///
/// Lowercase hexadecimal string with length `bytes.len() * 2`.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Returns a stable display label for hash algorithms used in TLS key schedule logs.
///
/// # Arguments
///
/// * `noxtls_hash_algorithm` — Hash algorithm enum value to render.
///
/// # Returns
///
/// Static string label for the provided algorithm.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_hash_algorithm_name(noxtls_hash_algorithm: HashAlgorithm) -> &'static str {
    match noxtls_hash_algorithm {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha384 => "sha384",
    }
}

/// Extracts TLS 1.3 ClientHello X25519 key_share bytes from encoded handshake message.
///
/// # Arguments
///
/// * `message` — Encoded `ClientHello` handshake message bytes (`type || len || body`).
///
/// # Returns
///
/// `Ok(Some(key_exchange))` when one X25519 key share is present, `Ok(None)` when absent.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the handshake shape or extension encoding is malformed.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_extract_tls13_client_hello_x25519_key_share(message: &[u8]) -> Result<Option<[u8; 32]>> {
    let (handshake_type, body) = noxtls_parse_handshake_message(message)?;
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        return Err(Error::ParseFailure(
            "expected client hello while extracting x25519 key share",
        ));
    }
    if body.len() < 39 {
        return Err(Error::ParseFailure("client hello body too short"));
    }
    let mut offset = 0_usize;
    offset = offset.saturating_add(2); // legacy_version
    offset = offset.saturating_add(32); // random
    let session_id_len = body
        .get(offset)
        .copied()
        .ok_or(Error::ParseFailure("client hello missing session_id length"))?
        as usize;
    offset = offset.saturating_add(1 + session_id_len);
    if body.len().saturating_sub(offset) < 2 {
        return Err(Error::ParseFailure(
            "client hello missing cipher_suites length",
        ));
    }
    let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset = offset.saturating_add(2 + suites_len);
    if body.len().saturating_sub(offset) < 1 {
        return Err(Error::ParseFailure(
            "client hello missing compression_methods length",
        ));
    }
    let compression_len = body[offset] as usize;
    offset = offset.saturating_add(1 + compression_len);
    if body.len().saturating_sub(offset) < 2 {
        return Err(Error::ParseFailure("client hello missing extensions length"));
    }
    let extensions_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset = offset.saturating_add(2);
    if body.len().saturating_sub(offset) < extensions_len {
        return Err(Error::ParseFailure("client hello extensions truncated"));
    }
    let mut cursor = &body[offset..offset + extensions_len];
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "client hello extension header truncated",
            ));
        }
        let extension_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let extension_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if cursor.len() < extension_len {
            return Err(Error::ParseFailure("client hello extension truncated"));
        }
        let extension_data = &cursor[..extension_len];
        if extension_type == EXT_KEY_SHARE {
            if extension_data.len() < 2 {
                return Err(Error::ParseFailure(
                    "client hello key_share extension missing vector length",
                ));
            }
            let key_share_list_len =
                u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
            if extension_data.len() != key_share_list_len + 2 {
                return Err(Error::ParseFailure(
                    "client hello key_share extension length mismatch",
                ));
            }
            let mut shares = &extension_data[2..];
            while !shares.is_empty() {
                if shares.len() < 4 {
                    return Err(Error::ParseFailure("client hello key_share entry truncated"));
                }
                let group = u16::from_be_bytes([shares[0], shares[1]]);
                let key_exchange_len = u16::from_be_bytes([shares[2], shares[3]]) as usize;
                shares = &shares[4..];
                if shares.len() < key_exchange_len {
                    return Err(Error::ParseFailure(
                        "client hello key_share key_exchange truncated",
                    ));
                }
                if group == TLS13_KEY_SHARE_GROUP_X25519 {
                    if key_exchange_len != 32 {
                        return Err(Error::ParseFailure(
                            "client hello x25519 key_share length must be 32",
                        ));
                    }
                    let mut key_exchange = [0_u8; 32];
                    key_exchange.copy_from_slice(&shares[..32]);
                    return Ok(Some(key_exchange));
                }
                shares = &shares[key_exchange_len..];
            }
            return Ok(None);
        }
        cursor = &cursor[extension_len..];
    }
    Ok(None)
}

/// Builds minimally required ClientHello extensions per protocol version.
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
/// * `key_shares` — `key_shares: &Tls13ClientPublicKeyShares`.
/// * `sni_server_name` — `sni_server_name: Option<&str>`.
/// * `alpn_protocols` — `alpn_protocols: &[Vec<u8>]`.
/// * `offer_early_data` — `offer_early_data: bool`.
/// * `psk_offer` — `psk_offer: Option<&PskClientOffer<'_>>`.
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
fn noxtls_build_client_hello_extensions(
    version: TlsVersion,
    key_shares: &Tls13ClientPublicKeyShares,
    sni_server_name: Option<&str>,
    alpn_protocols: &[Vec<u8>],
    request_ocsp_stapling: bool,
    offer_mldsa_signature: bool,
    offer_early_data: bool,
    psk_offer: Option<&PskClientOffer<'_>>,
) -> Result<Vec<u8>> {
    let mut extensions = Vec::new();
    match version {
        TlsVersion::Tls13 | TlsVersion::Dtls13 => {
            // supported_versions: TLS 1.3 plus TLS 1.2 fallback marker.
            let mut supported_versions = Vec::new();
            supported_versions.push(4_u8);
            supported_versions.extend_from_slice(&0x0304_u16.to_be_bytes());
            supported_versions.extend_from_slice(&0x0303_u16.to_be_bytes());
            noxtls_push_extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &supported_versions);

            // signature_algorithms: modeled TLS 1.3 schemes aligned with verify support.
            let mut sigalgs = Vec::new();
            let mut supported_sigalgs = vec![
                TLS13_SIGALG_ECDSA_SECP256R1_SHA256,
                TLS13_SIGALG_RSA_PSS_RSAE_SHA256,
                TLS13_SIGALG_RSA_PSS_RSAE_SHA384,
                TLS13_SIGALG_ED25519,
            ];
            if offer_mldsa_signature {
                supported_sigalgs.push(TLS13_SIGALG_MLDSA65);
            }
            sigalgs.extend_from_slice(&((supported_sigalgs.len() * 2) as u16).to_be_bytes());
            for sigalg in supported_sigalgs {
                sigalgs.extend_from_slice(&sigalg.to_be_bytes());
            }
            noxtls_push_extension(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sigalgs);

            // supported_groups: advertise all groups we may select in key_share.
            let mut supported_groups = Vec::new();
            let mut supported_group_ids = Vec::new();
            if key_shares.x25519.is_some() {
                supported_group_ids.push(TLS13_KEY_SHARE_GROUP_X25519);
            }
            if key_shares.secp256r1_uncompressed.is_some() {
                supported_group_ids.push(TLS13_KEY_SHARE_GROUP_SECP256R1);
            }
            if key_shares.mlkem768.is_some() {
                supported_group_ids.push(TLS13_KEY_SHARE_GROUP_MLKEM768);
            }
            if key_shares.x25519_mlkem768_hybrid.is_some() {
                supported_group_ids.push(TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID);
            }
            if supported_group_ids.is_empty() {
                return Err(Error::InvalidLength(
                    "tls13 client hello supported_groups extension must not be empty",
                ));
            }
            supported_groups
                .extend_from_slice(&((supported_group_ids.len() * 2) as u16).to_be_bytes());
            for group in supported_group_ids {
                supported_groups.extend_from_slice(&group.to_be_bytes());
            }
            noxtls_push_extension(&mut extensions, EXT_SUPPORTED_GROUPS, &supported_groups);

            // key_share: X25519 and optional secp256r1 entries for modeled ECDHE breadth.
            let mut key_share_list = Vec::new();
            if let Some(public) = key_shares.x25519 {
                key_share_list.extend_from_slice(&TLS13_KEY_SHARE_GROUP_X25519.to_be_bytes());
                key_share_list.extend_from_slice(&32_u16.to_be_bytes());
                key_share_list.extend_from_slice(&public);
            }
            if let Some(public) = key_shares.secp256r1_uncompressed {
                key_share_list.extend_from_slice(&TLS13_KEY_SHARE_GROUP_SECP256R1.to_be_bytes());
                key_share_list.extend_from_slice(&65_u16.to_be_bytes());
                key_share_list.extend_from_slice(&public);
            }
            if let Some(public) = key_shares.mlkem768.as_ref() {
                key_share_list.extend_from_slice(&TLS13_KEY_SHARE_GROUP_MLKEM768.to_be_bytes());
                key_share_list.extend_from_slice(&(public.len() as u16).to_be_bytes());
                key_share_list.extend_from_slice(public);
            }
            if let Some(public) = key_shares.x25519_mlkem768_hybrid.as_ref() {
                key_share_list
                    .extend_from_slice(&TLS13_KEY_SHARE_GROUP_X25519_MLKEM768_HYBRID.to_be_bytes());
                key_share_list.extend_from_slice(&(public.len() as u16).to_be_bytes());
                key_share_list.extend_from_slice(public);
            }
            if key_share_list.is_empty() {
                return Err(Error::InvalidLength(
                    "tls13 client hello key_share extension must not be empty",
                ));
            }
            let mut key_share_ext = Vec::new();
            key_share_ext.extend_from_slice(&(key_share_list.len() as u16).to_be_bytes());
            key_share_ext.extend_from_slice(&key_share_list);
            noxtls_push_extension(&mut extensions, EXT_KEY_SHARE, &key_share_ext);
            if let Some(server_name) = sni_server_name {
                let server_name_extension_data = noxtls_encode_server_name_extension_data(server_name)?;
                noxtls_push_extension(
                    &mut extensions,
                    EXT_SERVER_NAME,
                    &server_name_extension_data,
                );
            }
            if request_ocsp_stapling {
                let status_request_data = noxtls_encode_status_request_ocsp_extension_data()?;
                noxtls_push_extension(&mut extensions, EXT_STATUS_REQUEST, &status_request_data);
            }
            if !alpn_protocols.is_empty() {
                let alpn_extension_data = noxtls_encode_alpn_extension_data(alpn_protocols)?;
                noxtls_push_extension(&mut extensions, EXT_ALPN, &alpn_extension_data);
            }
            if offer_early_data {
                if psk_offer.is_none() {
                    return Err(Error::StateError(
                        "tls13 early_data extension requires pre_shared_key offer",
                    ));
                }
                noxtls_push_extension(&mut extensions, EXT_EARLY_DATA, &[]);
            }
            if let Some(psk) = psk_offer {
                let psk_key_exchange_modes = [1_u8, TLS13_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE];
                noxtls_push_extension(
                    &mut extensions,
                    EXT_PSK_KEY_EXCHANGE_MODES,
                    &psk_key_exchange_modes,
                );
                let psk_extension = noxtls_encode_pre_shared_key_extension(psk)?;
                noxtls_push_extension(&mut extensions, EXT_PRE_SHARED_KEY, &psk_extension);
            }
        }
        TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 | TlsVersion::Dtls12 => {
            // signature_algorithms: placeholder vector for non-TLS1.3 paths.
            let mut sigalgs = Vec::new();
            sigalgs.extend_from_slice(&2_u16.to_be_bytes());
            sigalgs.extend_from_slice(&0x0401_u16.to_be_bytes());
            noxtls_push_extension(&mut extensions, EXT_SIGNATURE_ALGORITHMS, &sigalgs);
        }
    }
    Ok(extensions)
}

/// Appends one `Extension` (type + length + value) to output buffer.
///
/// # Arguments
///
/// * `out` — `out: &mut Vec<u8>`.
/// * `ext_type` — `ext_type: u16`.
/// * `ext_data` — `ext_data: &[u8]`.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_push_extension(out: &mut Vec<u8>, ext_type: u16, ext_data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    out.extend_from_slice(ext_data);
}

/// Parses selected ClientHello extensions needed for current prototype checks.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_client_hello_extensions(input: &[u8]) -> Result<ClientHelloExtensions> {
    let mut out = ClientHelloExtensions::default();
    let mut cursor = input;
    let mut seen_supported_versions = false;
    let mut seen_signature_algorithms = false;
    let mut seen_key_share = false;
    let mut seen_psk_key_exchange_modes = false;
    let mut seen_pre_shared_key = false;
    let mut seen_early_data = false;
    let mut seen_extension_types = Vec::new();
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "client hello extension header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if cursor.len() < ext_len {
            return Err(Error::ParseFailure("client hello extension truncated"));
        }
        let ext_data = &cursor[..ext_len];
        if seen_extension_types.contains(&ext_type) {
            return Err(Error::ParseFailure("duplicate client hello extension type"));
        }
        seen_extension_types.push(ext_type);
        if seen_pre_shared_key {
            return Err(Error::ParseFailure(
                "pre_shared_key extension must be the last extension",
            ));
        }
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if seen_supported_versions {
                    return Err(Error::ParseFailure(
                        "duplicate supported_versions extension",
                    ));
                }
                out.supported_versions = noxtls_parse_supported_versions_extension(ext_data)?;
                seen_supported_versions = true;
            }
            EXT_SIGNATURE_ALGORITHMS => {
                if seen_signature_algorithms {
                    return Err(Error::ParseFailure(
                        "duplicate signature_algorithms extension",
                    ));
                }
                out.signature_algorithms = noxtls_parse_u16_vector_with_len(ext_data)?;
                if out.signature_algorithms.is_empty() {
                    return Err(Error::ParseFailure(
                        "signature_algorithms extension must not be empty",
                    ));
                }
                seen_signature_algorithms = true;
            }
            EXT_KEY_SHARE => {
                if seen_key_share {
                    return Err(Error::ParseFailure("duplicate key_share extension"));
                }
                out.key_share_groups = noxtls_parse_key_share_groups_extension(ext_data)?;
                seen_key_share = true;
            }
            EXT_SERVER_NAME => {
                out.sni_server_name = Some(noxtls_parse_server_name_extension(ext_data)?);
            }
            EXT_ALPN => {
                out.alpn_protocols = noxtls_parse_alpn_protocol_name_list(ext_data)?;
            }
            EXT_STATUS_REQUEST => {
                out.status_request_ocsp = noxtls_parse_status_request_ocsp_extension(ext_data)?;
            }
            EXT_PSK_KEY_EXCHANGE_MODES => {
                if seen_psk_key_exchange_modes {
                    return Err(Error::ParseFailure(
                        "duplicate psk_key_exchange_modes extension",
                    ));
                }
                out.psk_key_exchange_modes = noxtls_parse_u8_vector_with_len(ext_data)?;
                if !out
                    .psk_key_exchange_modes
                    .contains(&TLS13_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE)
                {
                    return Err(Error::ParseFailure(
                        "psk_key_exchange_modes must include psk_dhe_ke",
                    ));
                }
                seen_psk_key_exchange_modes = true;
            }
            EXT_PRE_SHARED_KEY => {
                if seen_pre_shared_key {
                    return Err(Error::ParseFailure("duplicate pre_shared_key extension"));
                }
                let (identity_count, identities, obfuscated_ages, binders) =
                    noxtls_parse_pre_shared_key_extension(ext_data)?;
                out.psk_identity_count = identity_count;
                out.psk_identities = identities;
                out.psk_obfuscated_ticket_ages = obfuscated_ages;
                out.psk_binders = binders;
                seen_pre_shared_key = true;
            }
            EXT_EARLY_DATA => {
                if seen_early_data {
                    return Err(Error::ParseFailure("duplicate early_data extension"));
                }
                if !ext_data.is_empty() {
                    return Err(Error::ParseFailure(
                        "client hello early_data extension must be empty",
                    ));
                }
                out.early_data_offered = true;
                seen_early_data = true;
            }
            _ => {}
        }
        cursor = &cursor[ext_len..];
    }
    if seen_pre_shared_key && !seen_psk_key_exchange_modes {
        return Err(Error::ParseFailure(
            "pre_shared_key extension requires psk_key_exchange_modes extension",
        ));
    }
    if seen_early_data && !seen_pre_shared_key {
        return Err(Error::ParseFailure(
            "early_data extension requires pre_shared_key extension",
        ));
    }
    if seen_psk_key_exchange_modes && !seen_pre_shared_key {
        return Err(Error::ParseFailure(
            "psk_key_exchange_modes extension requires pre_shared_key extension",
        ));
    }
    if seen_key_share && out.key_share_groups.is_empty() {
        return Err(Error::ParseFailure("key_share extension must not be empty"));
    }
    let advertises_tls13 = out.supported_versions.contains(&0x0304);
    if seen_pre_shared_key && !advertises_tls13 {
        return Err(Error::ParseFailure(
            "pre_shared_key extension requires tls13 supported_versions entry",
        ));
    }
    if seen_key_share && !advertises_tls13 {
        return Err(Error::ParseFailure(
            "key_share extension requires tls13 supported_versions entry",
        ));
    }
    if advertises_tls13 && !seen_signature_algorithms {
        return Err(Error::ParseFailure(
            "tls13 supported_versions requires signature_algorithms extension",
        ));
    }
    if advertises_tls13 && !seen_key_share {
        return Err(Error::ParseFailure(
            "tls13 supported_versions requires key_share extension",
        ));
    }
    if seen_pre_shared_key && !seen_key_share {
        return Err(Error::ParseFailure(
            "pre_shared_key with psk_dhe_ke requires key_share extension",
        ));
    }
    Ok(out)
}

/// Parses `<len:u8><versions:u16...>` form used by client supported_versions extension.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_supported_versions_extension(input: &[u8]) -> Result<Vec<u16>> {
    if input.is_empty() {
        return Err(Error::ParseFailure("supported_versions extension is empty"));
    }
    let declared = input[0] as usize;
    if input.len() != declared + 1 || !declared.is_multiple_of(2) {
        return Err(Error::ParseFailure(
            "invalid supported_versions extension length",
        ));
    }
    let mut versions = Vec::new();
    for chunk in input[1..].chunks_exact(2) {
        let version = u16::from_be_bytes([chunk[0], chunk[1]]);
        if versions.contains(&version) {
            return Err(Error::ParseFailure(
                "duplicate supported_versions entry in extension body",
            ));
        }
        versions.push(version);
    }
    Ok(versions)
}

/// Validates SNI DNS host syntax used by modeled server_name extension hooks.
///
/// # Arguments
///
/// * `name` — `name: &str`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_is_valid_sni_dns_name(name: &str) -> bool {
    if name.is_empty() || !name.is_ascii() {
        return false;
    }
    let trimmed = if let Some(stripped) = name.strip_suffix('.') {
        stripped
    } else {
        name
    };
    if trimmed.is_empty() || trimmed.len() > u16::MAX as usize {
        return false;
    }
    if trimmed
        .as_bytes()
        .iter()
        .any(|byte| *byte <= 0x20 || *byte >= 0x7f)
    {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return false;
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return false;
        }
    }
    true
}

/// Parses one SNI server_name extension payload into a DNS host_name string.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_server_name_extension(input: &[u8]) -> Result<String> {
    if input.len() < 5 {
        return Err(Error::ParseFailure("server_name extension too short"));
    }
    let list_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if list_len == 0 || input.len() != list_len + 2 {
        return Err(Error::ParseFailure("invalid server_name extension length"));
    }
    if input[2] != 0x00 {
        return Err(Error::ParseFailure("unsupported server_name type"));
    }
    let name_len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if name_len == 0 || input.len() != 5 + name_len {
        return Err(Error::ParseFailure("invalid server_name host_name length"));
    }
    let name = core::str::from_utf8(&input[5..])
        .map_err(|_| Error::ParseFailure("invalid sni server_name"))?;
    if !noxtls_is_valid_sni_dns_name(name) {
        return Err(Error::ParseFailure("invalid sni server_name"));
    }
    Ok(name.to_owned())
}

/// Encodes one SNI host_name string into TLS server_name extension payload bytes.
///
/// # Arguments
///
/// * `server_name` — `server_name: &str`.
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
fn noxtls_encode_server_name_extension_data(server_name: &str) -> Result<Vec<u8>> {
    if !noxtls_is_valid_sni_dns_name(server_name) {
        return Err(Error::ParseFailure("invalid sni server_name"));
    }
    let name_bytes = server_name.as_bytes();
    let mut entry = Vec::new();
    entry.push(0x00); // host_name
    entry.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    entry.extend_from_slice(name_bytes);
    let mut out = Vec::new();
    out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry);
    Ok(out)
}

/// Encodes RFC 6066/8446 `status_request` data for OCSP stapling support.
fn noxtls_encode_status_request_ocsp_extension_data() -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(0x01); // status_type=ocsp
    out.extend_from_slice(&0_u16.to_be_bytes()); // responder_id_list length
    out.extend_from_slice(&0_u16.to_be_bytes()); // request_extensions length
    Ok(out)
}

/// Parses `status_request` extension and accepts the OCSP form.
fn noxtls_parse_status_request_ocsp_extension(input: &[u8]) -> Result<bool> {
    if input.len() != 5 {
        return Err(Error::ParseFailure(
            "invalid status_request extension length",
        ));
    }
    if input[0] != 0x01 {
        return Err(Error::ParseFailure(
            "status_request extension must use ocsp status type",
        ));
    }
    let responder_id_list_len = u16::from_be_bytes([input[1], input[2]]) as usize;
    let request_extensions_len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if responder_id_list_len != 0 || request_extensions_len != 0 {
        return Err(Error::ParseFailure(
            "status_request extension non-empty responder/request vectors are unsupported",
        ));
    }
    Ok(true)
}

/// Parses ALPN extension payload into ordered protocol-name vector.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_alpn_protocol_name_list(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    if input.len() < 2 {
        return Err(Error::ParseFailure(
            "alpn extension missing protocol_name_list",
        ));
    }
    let declared_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if declared_len == 0 || input.len() != declared_len + 2 {
        return Err(Error::ParseFailure("invalid alpn extension length"));
    }
    let mut cursor = &input[2..];
    let mut protocols = Vec::new();
    while !cursor.is_empty() {
        let protocol_len = cursor[0] as usize;
        cursor = &cursor[1..];
        if protocol_len == 0 {
            return Err(Error::ParseFailure("alpn protocol must not be empty"));
        }
        if cursor.len() < protocol_len {
            return Err(Error::ParseFailure("alpn protocol truncated"));
        }
        let protocol = cursor[..protocol_len].to_vec();
        if protocols.contains(&protocol) {
            return Err(Error::ParseFailure("duplicate alpn protocol"));
        }
        protocols.push(protocol);
        cursor = &cursor[protocol_len..];
    }
    Ok(protocols)
}

/// Encodes ordered ALPN protocol names into TLS extension payload bytes.
///
/// # Arguments
///
/// * `protocols` — `protocols: &[Vec<u8>]`.
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
fn noxtls_encode_alpn_extension_data(protocols: &[Vec<u8>]) -> Result<Vec<u8>> {
    if protocols.is_empty() {
        return Err(Error::InvalidLength(
            "alpn extension must include at least one protocol",
        ));
    }
    let mut protocol_name_list = Vec::new();
    let mut seen_protocols = Vec::new();
    for protocol in protocols {
        if protocol.is_empty() {
            return Err(Error::InvalidLength("alpn protocol must not be empty"));
        }
        if protocol.len() > u8::MAX as usize {
            return Err(Error::InvalidLength(
                "alpn protocol length must not exceed 255 bytes",
            ));
        }
        if seen_protocols.contains(protocol) {
            return Err(Error::ParseFailure("duplicate alpn protocol"));
        }
        seen_protocols.push(protocol.clone());
        protocol_name_list.push(protocol.len() as u8);
        protocol_name_list.extend_from_slice(protocol);
    }
    let mut extension_data = Vec::new();
    extension_data.extend_from_slice(&(protocol_name_list.len() as u16).to_be_bytes());
    extension_data.extend_from_slice(&protocol_name_list);
    Ok(extension_data)
}

/// Parses `<len:u16><items:u16...>` style vector and returns u16 items.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_u16_vector_with_len(input: &[u8]) -> Result<Vec<u16>> {
    if input.len() < 2 {
        return Err(Error::ParseFailure("u16 vector missing length prefix"));
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() != len + 2 || !len.is_multiple_of(2) {
        return Err(Error::ParseFailure("invalid u16 vector length"));
    }
    let mut out = Vec::new();
    for chunk in input[2..].chunks_exact(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        if out.contains(&value) {
            return Err(Error::ParseFailure("duplicate u16 vector entry"));
        }
        out.push(value);
    }
    Ok(out)
}

/// Parses `<len:u8><items:u8...>` style vector and returns u8 items.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_u8_vector_with_len(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(Error::ParseFailure("u8 vector missing length prefix"));
    }
    let len = input[0] as usize;
    if input.len() != len + 1 {
        return Err(Error::ParseFailure("invalid u8 vector length"));
    }
    if len == 0 {
        return Err(Error::ParseFailure("u8 vector must not be empty"));
    }
    let mut out = Vec::new();
    for value in &input[1..] {
        if out.contains(value) {
            return Err(Error::ParseFailure("duplicate u8 vector entry"));
        }
        out.push(*value);
    }
    Ok(out)
}

/// Parses CertificateRequest body shape used by TLS 1.3.
///
/// # Arguments
///
/// * `body` — `body: &[u8]`.
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
fn noxtls_parse_certificate_request_body(body: &[u8]) -> Result<()> {
    if body.len() < 3 {
        return Err(Error::ParseFailure("certificate request body too short"));
    }
    let context_len = body[0] as usize;
    let ext_len_offset = 1 + context_len;
    if body.len() < ext_len_offset + 2 {
        return Err(Error::ParseFailure("certificate request context truncated"));
    }
    let ext_len = u16::from_be_bytes([body[ext_len_offset], body[ext_len_offset + 1]]) as usize;
    let ext_start = ext_len_offset + 2;
    if body.len() != ext_start + ext_len {
        return Err(Error::ParseFailure(
            "certificate request extensions truncated",
        ));
    }
    noxtls_parse_certificate_request_extensions(&body[ext_start..])?;
    Ok(())
}

/// Parses CertificateRequest extensions vector and validates entry structure.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_certificate_request_extensions(input: &[u8]) -> Result<()> {
    let mut cursor = input;
    let mut seen_extension_types = Vec::new();
    let mut seen_signature_algorithms = false;
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "certificate request extension header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if seen_extension_types.contains(&ext_type) {
            return Err(Error::ParseFailure(
                "duplicate certificate request extension type",
            ));
        }
        if matches!(
            ext_type,
            EXT_SUPPORTED_VERSIONS
                | EXT_KEY_SHARE
                | EXT_PRE_SHARED_KEY
                | EXT_PSK_KEY_EXCHANGE_MODES
                | EXT_SERVER_NAME
        ) {
            return Err(Error::ParseFailure(
                "certificate request contains forbidden extension type",
            ));
        }
        seen_extension_types.push(ext_type);
        cursor = &cursor[4..];
        if cursor.len() < ext_len {
            return Err(Error::ParseFailure(
                "certificate request extension truncated",
            ));
        }
        if ext_type == EXT_SIGNATURE_ALGORITHMS {
            let signature_algorithms = noxtls_parse_u16_vector_with_len(&cursor[..ext_len])?;
            if signature_algorithms.is_empty() {
                return Err(Error::ParseFailure(
                    "certificate request signature_algorithms must not be empty",
                ));
            }
            seen_signature_algorithms = true;
        }
        cursor = &cursor[ext_len..];
    }
    if !seen_signature_algorithms {
        return Err(Error::ParseFailure(
            "certificate request missing signature_algorithms extension",
        ));
    }
    Ok(())
}

/// Parses EncryptedExtensions body and validates extension vector structure.
///
/// # Arguments
///
/// * `body` — `body: &[u8]`.
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
fn noxtls_parse_encrypted_extensions_body(body: &[u8]) -> Result<ParsedEncryptedExtensions> {
    if body.len() < 2 {
        return Err(Error::ParseFailure("encrypted extensions body too short"));
    }
    let extensions_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() != 2 + extensions_len {
        return Err(Error::ParseFailure("encrypted extensions malformed length"));
    }
    let mut cursor = &body[2..];
    let mut seen_extension_types = Vec::new();
    let mut selected_alpn_protocol = None;
    let mut server_name_acknowledged = false;
    let mut early_data_accepted = false;
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "encrypted extensions entry header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if ext_len > TLS13_MAX_EXTENSION_VALUE_BYTES {
            return Err(Error::ParseFailure(
                "encrypted extensions extension value exceeds modeled maximum",
            ));
        }
        if seen_extension_types.contains(&ext_type) {
            return Err(Error::ParseFailure("duplicate encrypted extensions type"));
        }
        seen_extension_types.push(ext_type);
        cursor = &cursor[4..];
        if cursor.len() < ext_len {
            return Err(Error::ParseFailure("encrypted extensions entry truncated"));
        }
        let ext_data = &cursor[..ext_len];
        match ext_type {
            EXT_SERVER_NAME => {
                if !ext_data.is_empty() {
                    return Err(Error::ParseFailure(
                        "encrypted extensions server_name must be empty",
                    ));
                }
                server_name_acknowledged = true;
            }
            EXT_ALPN => {
                let protocols = noxtls_parse_alpn_protocol_name_list(ext_data)?;
                if protocols.len() != 1 {
                    return Err(Error::ParseFailure(
                        "encrypted extensions alpn must select exactly one protocol",
                    ));
                }
                selected_alpn_protocol = protocols.first().cloned();
            }
            EXT_EARLY_DATA => {
                if !ext_data.is_empty() {
                    return Err(Error::ParseFailure(
                        "encrypted extensions early_data must be empty",
                    ));
                }
                early_data_accepted = true;
            }
            EXT_SUPPORTED_VERSIONS
            | EXT_KEY_SHARE
            | EXT_PRE_SHARED_KEY
            | EXT_PSK_KEY_EXCHANGE_MODES => {
                return Err(Error::ParseFailure(
                    "encrypted extensions contains forbidden extension type",
                ));
            }
            _ => {}
        }
        cursor = &cursor[ext_len..];
    }
    Ok(ParsedEncryptedExtensions {
        selected_alpn_protocol,
        server_name_acknowledged,
        early_data_accepted,
    })
}

/// Parses Certificate body shape used by TLS 1.3 and extracts certificate entries.
///
/// # Arguments
///
/// * `body` — `body: &[u8]`.
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
/// Maps X.509 chain-validation errors into stable protocol-layer failure strings.
///
/// # Arguments
///
/// * `err` — Validation error returned by `noxtls-x509`.
///
/// # Returns
///
/// `noxtls_core::Error` preserving the underlying failure category.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_map_certificate_validation_error(err: ValidationError) -> Error {
    let message = match err {
        ValidationError::InvalidNowTimeFormat => "server certificate validation time is invalid",
        ValidationError::CertificateNotYetValid => "server certificate is not yet valid",
        ValidationError::CertificateExpired => "server certificate is expired",
        ValidationError::IssuerNotFound => "server certificate issuer not found",
        ValidationError::IssuerNotCa => "server certificate issuer is not a CA",
        ValidationError::IssuerMissingKeyCertSign => {
            "server certificate issuer missing keyCertSign usage"
        }
        ValidationError::PathLenExceeded => "server certificate path length exceeded",
        ValidationError::UntrustedRoot => {
            "server certificate chain does not terminate at trust anchor"
        }
        ValidationError::ChainLoopDetected => "server certificate chain loop detected",
        ValidationError::MaxChainDepthExceeded => "server certificate chain depth exceeded",
        ValidationError::SignatureAlgorithmMismatch => {
            "server certificate signature algorithm mismatch"
        }
        ValidationError::UnsupportedSignatureAlgorithm => {
            "server certificate signature algorithm unsupported"
        }
        ValidationError::UnsupportedPublicKeyAlgorithm => {
            "server certificate issuer public key algorithm unsupported"
        }
        ValidationError::PublicKeyDecodeFailed => "server certificate issuer public key decode failed",
        ValidationError::SignatureVerificationFailed => {
            "server certificate signature verification failed"
        }
        ValidationError::MissingRequiredPolicy => {
            "server certificate missing required policy OID"
        }
        ValidationError::MissingRequiredExtendedKeyUsage => {
            "server certificate missing required extended key usage"
        }
        ValidationError::ExplicitPolicyRequired => {
            "server certificate policy set is empty under explicit policy mode"
        }
        ValidationError::PolicyMappingInhibited => {
            "server certificate policy mappings are inhibited"
        }
        ValidationError::NameConstraintsViolation => {
            "server certificate violates issuer name constraints"
        }
        ValidationError::MissingRevocationInfo => {
            "server certificate missing revocation distribution info"
        }
        ValidationError::MissingRevocationLocator => {
            "server certificate missing revocation locator"
        }
    };
    Error::CryptoFailure(message)
}

fn noxtls_parse_certificate_body(body: &[u8]) -> Result<ParsedTls13CertificateBody> {
    if body.len() < 4 {
        return Err(Error::ParseFailure("certificate body too short"));
    }
    let context_len = body[0] as usize;
    let list_len_offset = 1 + context_len;
    if body.len() < list_len_offset + 3 {
        return Err(Error::ParseFailure("certificate list length missing"));
    }
    let cert_list_len = u32::from_be_bytes([
        0x00,
        body[list_len_offset],
        body[list_len_offset + 1],
        body[list_len_offset + 2],
    ]) as usize;
    let cert_list_start = list_len_offset + 3;
    let cert_list_end = cert_list_start + cert_list_len;
    if cert_list_end > body.len() {
        return Err(Error::ParseFailure("certificate list truncated"));
    }
    let mut certificates = Vec::new();
    let mut cursor = &body[cert_list_start..cert_list_end];
    let mut leaf_ocsp_staple = None;
    while !cursor.is_empty() {
        if cursor.len() < 5 {
            return Err(Error::ParseFailure("certificate entry truncated"));
        }
        let cert_len = u32::from_be_bytes([0x00, cursor[0], cursor[1], cursor[2]]) as usize;
        let cert_end = 3 + cert_len;
        if cursor.len() < cert_end + 2 {
            return Err(Error::ParseFailure("certificate bytes truncated"));
        }
        certificates.push(cursor[3..cert_end].to_vec());
        let ext_len = u16::from_be_bytes([cursor[cert_end], cursor[cert_end + 1]]) as usize;
        let ext_end = cert_end + 2 + ext_len;
        if cursor.len() < ext_end {
            return Err(Error::ParseFailure(
                "certificate entry extensions truncated",
            ));
        }
        let parsed_staple = noxtls_parse_certificate_entry_extensions(&cursor[cert_end + 2..ext_end])?;
        if certificates.len() == 1 {
            leaf_ocsp_staple = parsed_staple;
        }
        cursor = &cursor[ext_end..];
    }
    if certificates.is_empty() {
        return Err(Error::ParseFailure("certificate list must not be empty"));
    }
    if cert_list_end != body.len() {
        return Err(Error::ParseFailure("certificate body trailing bytes"));
    }
    Ok(ParsedTls13CertificateBody {
        certificates,
        leaf_ocsp_staple,
    })
}

/// Parses a TLS 1.2 Certificate body and extracts DER certificate entries.
///
/// # Arguments
///
/// * `body` — Handshake body bytes for a TLS 1.2 `Certificate` message.
///
/// # Returns
///
/// On success, non-empty DER certificate entries in wire order (leaf first).
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] for malformed list framing, truncated entries, or trailing bytes.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_parse_tls12_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    if body.len() < 3 {
        return Err(Error::ParseFailure(
            "tls12 certificate message is malformed",
        ));
    }
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    if list_len == 0 || list_len != body.len() - 3 {
        return Err(Error::ParseFailure(
            "tls12 certificate list length is malformed",
        ));
    }
    let mut certificates = Vec::new();
    let mut cursor = &body[3..];
    while !cursor.is_empty() {
        if cursor.len() < 3 {
            return Err(Error::ParseFailure(
                "tls12 certificate entry length is truncated",
            ));
        }
        let cert_len =
            ((cursor[0] as usize) << 16) | ((cursor[1] as usize) << 8) | cursor[2] as usize;
        if cert_len == 0 {
            return Err(Error::ParseFailure(
                "tls12 certificate entry must not be empty",
            ));
        }
        if cursor.len() < 3 + cert_len {
            return Err(Error::ParseFailure("tls12 certificate entry is truncated"));
        }
        certificates.push(cursor[3..3 + cert_len].to_vec());
        cursor = &cursor[3 + cert_len..];
    }
    if certificates.is_empty() {
        return Err(Error::ParseFailure(
            "tls12 certificate list must not be empty",
        ));
    }
    Ok(certificates)
}

/// Parses TLS 1.2 ServerKeyExchange ECDHE-style body and enforces modern signature-scheme policy.
///
/// # Arguments
///
/// * `body` — Handshake body bytes for TLS 1.2 `ServerKeyExchange`.
///
/// # Returns
///
/// `Ok(())` when shape and signature-scheme policy checks pass.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when body shape is malformed or signature scheme is disallowed.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_parse_tls12_server_key_exchange_body(body: &[u8]) -> Result<()> {
    if body.len() < 8 {
        return Err(Error::ParseFailure(
            "tls12 server key exchange body must include key share and signature fields",
        ));
    }
    if body[0] != 0x03 {
        return Err(Error::ParseFailure(
            "tls12 server key exchange requires named_curve parameters",
        ));
    }
    let public_len = body[3] as usize;
    if public_len == 0 {
        return Err(Error::ParseFailure(
            "tls12 server key exchange public key must not be empty",
        ));
    }
    let signature_header_offset = 4 + public_len;
    if body.len() < signature_header_offset + 4 {
        return Err(Error::ParseFailure(
            "tls12 server key exchange signature header is truncated",
        ));
    }
    let signature_scheme = u16::from_be_bytes([
        body[signature_header_offset],
        body[signature_header_offset + 1],
    ]);
    if !noxtls_tls12_signature_scheme_is_modern(signature_scheme) {
        return Err(Error::ParseFailure(
            "tls12 server key exchange uses unsupported signature scheme",
        ));
    }
    let signature_len = u16::from_be_bytes([
        body[signature_header_offset + 2],
        body[signature_header_offset + 3],
    ]) as usize;
    if signature_len == 0 {
        return Err(Error::ParseFailure(
            "tls12 server key exchange signature must not be empty",
        ));
    }
    if body.len() != signature_header_offset + 4 + signature_len {
        return Err(Error::ParseFailure(
            "tls12 server key exchange signature length is malformed",
        ));
    }
    Ok(())
}

/// Parses TLS 1.2 CertificateVerify body and enforces modern signature-scheme policy.
///
/// # Arguments
///
/// * `body` — Handshake body bytes for TLS 1.2 `CertificateVerify`.
///
/// # Returns
///
/// `Ok(())` when shape and signature-scheme policy checks pass.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when body shape is malformed or signature scheme is disallowed.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_parse_tls12_certificate_verify_body(body: &[u8]) -> Result<()> {
    if body.len() < 4 {
        return Err(Error::ParseFailure(
            "tls12 client certificate verify body must include signature scheme and length",
        ));
    }
    let signature_scheme = u16::from_be_bytes([body[0], body[1]]);
    if !noxtls_tls12_signature_scheme_is_modern(signature_scheme) {
        return Err(Error::ParseFailure(
            "tls12 client certificate verify uses unsupported signature scheme",
        ));
    }
    let signature_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if signature_len == 0 {
        return Err(Error::ParseFailure(
            "tls12 client certificate verify signature must not be empty",
        ));
    }
    if body.len() != 4 + signature_len {
        return Err(Error::ParseFailure(
            "tls12 client certificate verify signature length is malformed",
        ));
    }
    Ok(())
}

/// Returns whether TLS 1.2 signature noxtls_algorithm is allowed by default-safe policy.
///
/// # Arguments
///
/// * `signature_scheme` — TLS SignatureScheme identifier.
///
/// # Returns
///
/// `true` for modern schemes enabled by default, `false` otherwise.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_tls12_signature_scheme_is_modern(signature_scheme: u16) -> bool {
    matches!(
        signature_scheme,
        TLS13_SIGALG_ECDSA_SECP256R1_SHA256
            | TLS13_SIGALG_RSA_PSS_RSAE_SHA256
            | TLS13_SIGALG_RSA_PSS_RSAE_SHA384
            | TLS13_SIGALG_ED25519
            | TLS13_SIGALG_MLDSA65
    )
}

/// Parses one CertificateEntry extension vector and validates structure.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_certificate_entry_extensions(input: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut cursor = input;
    let mut seen_extension_types = Vec::new();
    let mut status_request_ocsp = None;
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure(
                "certificate entry extension header truncated",
            ));
        }
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if seen_extension_types.contains(&ext_type) {
            return Err(Error::ParseFailure(
                "duplicate certificate entry extension type",
            ));
        }
        seen_extension_types.push(ext_type);
        cursor = &cursor[4..];
        if cursor.len() < ext_len {
            return Err(Error::ParseFailure("certificate entry extension truncated"));
        }
        let ext_data = &cursor[..ext_len];
        if ext_type == EXT_STATUS_REQUEST {
            if status_request_ocsp.is_some() {
                return Err(Error::ParseFailure(
                    "duplicate certificate entry status_request extension",
                ));
            }
            status_request_ocsp = Some(noxtls_parse_certificate_entry_status_request_extension(ext_data)?);
        }
        cursor = &cursor[ext_len..];
    }
    Ok(status_request_ocsp)
}

/// Encodes one CertificateEntry `status_request` extension with OCSP staple payload.
fn noxtls_encode_certificate_entry_status_request_extension(ocsp_staple: &[u8]) -> Result<Vec<u8>> {
    if ocsp_staple.is_empty() {
        return Err(Error::InvalidLength("ocsp staple must not be empty"));
    }
    if ocsp_staple.len() > 0x00FF_FFFF {
        return Err(Error::InvalidLength("ocsp staple is too large"));
    }
    let mut status_request_payload = Vec::new();
    status_request_payload.push(0x01); // status_type=ocsp
    let staple_len = ocsp_staple.len() as u32;
    status_request_payload.extend_from_slice(&staple_len.to_be_bytes()[1..4]);
    status_request_payload.extend_from_slice(ocsp_staple);

    let mut extension = Vec::new();
    extension.extend_from_slice(&EXT_STATUS_REQUEST.to_be_bytes());
    extension.extend_from_slice(&(status_request_payload.len() as u16).to_be_bytes());
    extension.extend_from_slice(&status_request_payload);
    Ok(extension)
}

/// Parses one CertificateEntry `status_request` extension and extracts OCSP staple bytes.
fn noxtls_parse_certificate_entry_status_request_extension(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < 4 {
        return Err(Error::ParseFailure(
            "certificate entry status_request extension is truncated",
        ));
    }
    if input[0] != 0x01 {
        return Err(Error::ParseFailure(
            "certificate entry status_request must use ocsp status type",
        ));
    }
    let ocsp_len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
    if ocsp_len == 0 {
        return Err(Error::ParseFailure(
            "certificate entry status_request ocsp response must not be empty",
        ));
    }
    if input.len() != 4 + ocsp_len {
        return Err(Error::ParseFailure(
            "certificate entry status_request ocsp response is truncated",
        ));
    }
    Ok(input[4..].to_vec())
}

/// Parses CertificateVerify body shape used by TLS 1.3.
///
/// # Arguments
///
/// * `body` — `body: &[u8]`.
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
fn noxtls_parse_certificate_verify_fields(body: &[u8]) -> Result<(u16, &[u8])> {
    if body.len() < 4 {
        return Err(Error::ParseFailure("certificate verify body too short"));
    }
    let signature_scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() != 4 + sig_len {
        return Err(Error::ParseFailure(
            "certificate verify signature truncated",
        ));
    }
    Ok((signature_scheme, &body[4..]))
}

/// Returns true when CertificateVerify scheme is supported by current TLS13 implementation.
///
/// # Arguments
///
/// * `signature_scheme` — `signature_scheme: u16`.
///
/// # Returns
///
/// `true` or `false` according to the checks in the function body.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_tls13_supported_certificate_verify_signature_scheme(signature_scheme: u16) -> bool {
    matches!(
        signature_scheme,
        TLS13_SIGALG_ECDSA_SECP256R1_SHA256
            | TLS13_SIGALG_RSA_PSS_RSAE_SHA256
            | TLS13_SIGALG_RSA_PSS_RSAE_SHA384
            | TLS13_SIGALG_ED25519
            | TLS13_SIGALG_MLDSA65
    )
}

/// Parses NewSessionTicket body shape used by TLS 1.3.
///
/// # Arguments
///
/// * `body` — `body: &[u8]`.
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
fn noxtls_parse_new_session_ticket_body(body: &[u8]) -> Result<()> {
    if body.len() < 11 {
        return Err(Error::ParseFailure("noxtls_new session ticket body too short"));
    }
    let nonce_len = body[8] as usize;
    let ticket_len_offset = 9 + nonce_len;
    if body.len() < ticket_len_offset + 2 {
        return Err(Error::ParseFailure("noxtls_new session ticket nonce truncated"));
    }
    let ticket_len =
        u16::from_be_bytes([body[ticket_len_offset], body[ticket_len_offset + 1]]) as usize;
    let ext_len_offset = ticket_len_offset + 2 + ticket_len;
    if body.len() < ext_len_offset + 2 {
        return Err(Error::ParseFailure("noxtls_new session ticket bytes truncated"));
    }
    let ext_len = u16::from_be_bytes([body[ext_len_offset], body[ext_len_offset + 1]]) as usize;
    if body.len() != ext_len_offset + 2 + ext_len {
        return Err(Error::ParseFailure(
            "noxtls_new session ticket extensions truncated",
        ));
    }
    Ok(())
}

/// Builds TLS 1.3 CertificateVerify signed message for server role.
///
/// # Arguments
///
/// * `noxtls_transcript_hash` — `noxtls_transcript_hash: &[u8]`.
///
/// # Returns
///
/// The value described by the return type in the function signature.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_build_tls13_server_certificate_verify_message(noxtls_transcript_hash: &[u8]) -> Vec<u8> {
    const PREFIX_LEN: usize = 64;
    const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
    let mut out = Vec::with_capacity(PREFIX_LEN + CONTEXT.len() + 1 + noxtls_transcript_hash.len());
    out.extend(core::iter::repeat_n(0x20_u8, PREFIX_LEN));
    out.extend_from_slice(CONTEXT);
    out.push(0x00);
    out.extend_from_slice(noxtls_transcript_hash);
    out
}

/// Parses DER RSAPublicKey bytes and constructs a `RsaPublicKey`.
///
/// # Arguments
///
/// * `public_key_der` — `public_key_der: &[u8]`.
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
fn noxtls_parse_rsa_public_key_der(public_key_der: &[u8]) -> Result<RsaPublicKey> {
    let (rsa_seq, rem) = noxtls_parse_der_node(public_key_der)
        .map_err(|_| Error::ParseFailure("failed to parse server RSA public key"))?;
    if rsa_seq.tag != 0x30 || !rem.is_empty() {
        return Err(Error::ParseFailure(
            "invalid server RSA public key sequence",
        ));
    }
    let (modulus_node, rest) = noxtls_parse_der_node(rsa_seq.body)
        .map_err(|_| Error::ParseFailure("failed to parse server RSA modulus"))?;
    let (exponent_node, tail) = noxtls_parse_der_node(rest)
        .map_err(|_| Error::ParseFailure("failed to parse server RSA exponent"))?;
    if modulus_node.tag != 0x02 || exponent_node.tag != 0x02 || !tail.is_empty() {
        return Err(Error::ParseFailure(
            "invalid server RSA public key integer fields",
        ));
    }
    RsaPublicKey::from_be_bytes(modulus_node.body, exponent_node.body)
        .map_err(|_| Error::CryptoFailure("failed to construct server RSA public key"))
}

/// Parses key_share extension and returns advertised key exchange group IDs.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_key_share_groups_extension(input: &[u8]) -> Result<Vec<u16>> {
    if input.len() < 2 {
        return Err(Error::ParseFailure(
            "key_share extension missing list length",
        ));
    }
    let list_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() != list_len + 2 {
        return Err(Error::ParseFailure("invalid key_share extension length"));
    }
    let mut cursor = &input[2..];
    let mut groups = Vec::new();
    while !cursor.is_empty() {
        if cursor.len() < 4 {
            return Err(Error::ParseFailure("key_share entry truncated"));
        }
        let group = u16::from_be_bytes([cursor[0], cursor[1]]);
        let key_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if groups.contains(&group) {
            return Err(Error::ParseFailure("duplicate key_share group"));
        }
        if key_len == 0 {
            return Err(Error::ParseFailure(
                "key_share key_exchange must not be empty",
            ));
        }
        cursor = &cursor[4..];
        if cursor.len() < key_len {
            return Err(Error::ParseFailure("key_share key_exchange truncated"));
        }
        groups.push(group);
        cursor = &cursor[key_len..];
    }
    Ok(groups)
}

/// Encodes TLS 1.3 pre_shared_key extension with one identity and one binder.
///
/// # Arguments
///
/// * `offer` — `offer: &PskClientOffer<'_>`.
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
fn noxtls_encode_pre_shared_key_extension(offer: &PskClientOffer<'_>) -> Result<Vec<u8>> {
    if offer.identities.is_empty() || offer.binders.is_empty() {
        return Err(Error::InvalidLength(
            "psk identity/binder list must not be empty",
        ));
    }
    if offer.identities.len() != offer.binders.len() {
        return Err(Error::InvalidLength(
            "psk identity and binder list lengths must match",
        ));
    }
    let mut identities = Vec::new();
    let mut binders = Vec::new();
    for (identity, binder) in offer.identities.iter().zip(offer.binders.iter()) {
        if identity.identity.is_empty() || binder.is_empty() {
            return Err(Error::InvalidLength(
                "psk identity and binder must not be empty",
            ));
        }
        if identity.identity.len() > u16::MAX as usize || binder.len() > u8::MAX as usize {
            return Err(Error::InvalidLength("psk identity or binder too long"));
        }
        identities.extend_from_slice(&(identity.identity.len() as u16).to_be_bytes());
        identities.extend_from_slice(identity.identity);
        identities.extend_from_slice(&identity.obfuscated_ticket_age.to_be_bytes());
        binders.push(binder.len() as u8);
        binders.extend_from_slice(binder);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(identities.len() as u16).to_be_bytes());
    out.extend_from_slice(&identities);
    out.extend_from_slice(&(binders.len() as u16).to_be_bytes());
    out.extend_from_slice(&binders);
    Ok(out)
}

/// Parses TLS 1.3 pre_shared_key extension and returns identity count and binders.
///
/// # Arguments
///
/// * `input` — `input: &[u8]`.
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
fn noxtls_parse_pre_shared_key_extension(
    input: &[u8],
) -> Result<(usize, Vec<Vec<u8>>, Vec<u32>, Vec<Vec<u8>>)> {
    if input.len() < 4 {
        return Err(Error::ParseFailure("pre_shared_key extension too short"));
    }
    let identities_len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() < 2 + identities_len + 2 {
        return Err(Error::ParseFailure("pre_shared_key identities truncated"));
    }
    let identities_end = 2 + identities_len;
    let mut id_cursor = &input[2..identities_end];
    let mut identity_count = 0_usize;
    let mut identities = Vec::new();
    let mut obfuscated_ages = Vec::new();
    while !id_cursor.is_empty() {
        if id_cursor.len() < 6 {
            return Err(Error::ParseFailure(
                "pre_shared_key identity entry truncated",
            ));
        }
        let id_len = u16::from_be_bytes([id_cursor[0], id_cursor[1]]) as usize;
        if id_len == 0 {
            return Err(Error::ParseFailure(
                "pre_shared_key identity must not be empty",
            ));
        }
        if id_cursor.len() < 2 + id_len + 4 {
            return Err(Error::ParseFailure(
                "pre_shared_key identity bytes truncated",
            ));
        }
        let identity = id_cursor[2..2 + id_len].to_vec();
        if identities.iter().any(|existing| existing == &identity) {
            return Err(Error::ParseFailure("duplicate pre_shared_key identity"));
        }
        identities.push(identity);
        obfuscated_ages.push(u32::from_be_bytes([
            id_cursor[2 + id_len],
            id_cursor[3 + id_len],
            id_cursor[4 + id_len],
            id_cursor[5 + id_len],
        ]));
        identity_count = identity_count.saturating_add(1);
        id_cursor = &id_cursor[2 + id_len + 4..];
    }

    let binders_len =
        u16::from_be_bytes([input[identities_end], input[identities_end + 1]]) as usize;
    let binders_start = identities_end + 2;
    let binders_end = binders_start + binders_len;
    if input.len() != binders_end {
        return Err(Error::ParseFailure(
            "invalid pre_shared_key binder vector length",
        ));
    }
    let mut binders = Vec::new();
    let mut binder_cursor = &input[binders_start..binders_end];
    while !binder_cursor.is_empty() {
        let binder_len = binder_cursor[0] as usize;
        if binder_len == 0 {
            return Err(Error::ParseFailure(
                "pre_shared_key binder must not be empty",
            ));
        }
        binder_cursor = &binder_cursor[1..];
        if binder_cursor.len() < binder_len {
            return Err(Error::ParseFailure("pre_shared_key binder bytes truncated"));
        }
        binders.push(binder_cursor[..binder_len].to_vec());
        binder_cursor = &binder_cursor[binder_len..];
    }
    if identity_count != binders.len() {
        return Err(Error::ParseFailure(
            "pre_shared_key identity and binder counts differ",
        ));
    }
    if identity_count == 0 {
        return Err(Error::ParseFailure(
            "pre_shared_key extension must include at least one identity",
        ));
    }
    Ok((identity_count, identities, obfuscated_ages, binders))
}

/// Returns legacy TLS version bytes used in ClientHello/ServerHello structures.
///
/// # Arguments
///
/// * `version` — `version: TlsVersion`.
///
/// # Returns
///
/// The value described by the return type in the function signature.
///
/// # Panics
///
/// This function does not panic.
///
fn noxtls_legacy_wire_version(version: TlsVersion) -> [u8; 2] {
    match version {
        TlsVersion::Tls10 => [0x03, 0x01],
        TlsVersion::Tls11 => [0x03, 0x02],
        TlsVersion::Tls12 | TlsVersion::Tls13 => [0x03, 0x03],
        TlsVersion::Dtls12 | TlsVersion::Dtls13 => [0xFE, 0xFD],
    }
}

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
    AlertDescription, AlertLevel, CipherSuite, HandshakeState, RecordContentType, TlsRole,
    TlsVersion,
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
    noxtls_p256_ecdsa_sign_sha256, noxtls_p256_ecdsa_verify_sha256, noxtls_rsassa_pss_sha256_sign,
    noxtls_rsassa_pss_sha256_verify, noxtls_rsassa_pss_sha384_verify,
    noxtls_tls12_prf_sha256, noxtls_tls12_prf_sha384, AesCipher, HmacDrbgSha256, MlDsaPublicKey, MlKemPrivateKey,
    P256PrivateKey, P256PublicKey, RsaPrivateKey, RsaPublicKey, TlsTranscriptSha256, TlsTranscriptSha384,
    X25519PrivateKey, MLKEM_CIPHERTEXT_LEN,
};
use noxtls_x509::{
    noxtls_certificate_matches_hostname, noxtls_parse_certificate, noxtls_parse_der_node,
    noxtls_parse_ecdsa_signature_der, noxtls_validate_certificate_chain, ValidationError,
};
use p384::ecdsa::{
    signature::Verifier as _, Signature as P384EcdsaSignature, VerifyingKey as P384VerifyingKey,
};

/// Holds configured TLS 1.3 server identity signing material for CertificateVerify.
#[derive(Debug, Clone)]
pub enum Tls13ServerIdentityKey {
    /// P-256 ECDSA private key used with `ecdsa_secp256r1_sha256`.
    P256(P256PrivateKey),
    /// RSA private key used with RSASSA-PSS and SHA-256.
    Rsa(RsaPrivateKey),
}

/// Holds connection version, handshake state, and transcript bytes.
#[derive(Debug, Clone)]
pub struct Connection {
    pub version: TlsVersion,
    pub tls_role: TlsRole,
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
    tls13_shared_secret: Option<Vec<u8>>,
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
    tls13_server_certificate_chain_der: Vec<Vec<u8>>,
    tls13_server_signing_key: Option<Tls13ServerIdentityKey>,
    tls13_server_preferred_cipher_suites: Vec<CipherSuite>,
    tls13_server_alpn_protocols: Vec<Vec<u8>>,
    tls13_server_x25519_private: Option<X25519PrivateKey>,
    tls13_server_p256_private: Option<P256PrivateKey>,
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
const TLS13_SIGALG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
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

mod tls12_handshake;
mod client_hello;
mod common;
mod dtls12;
mod dtls13;
mod quic;
mod record_common;
mod record_server;
mod tls_kdf;
mod tls_key_exchange;
mod tls13_client;
mod tls13_handshake;
mod tls13_server;
mod tls13_server_role;

use self::tls_kdf::{noxtls_derive_tls13_handshake_secret, noxtls_tls12_prf_for_hash};
use self::tls_key_exchange::noxtls_combine_tls13_hybrid_shared_secret;
use self::common::noxtls_constant_time_eq;

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
            tls_role: TlsRole::Client,
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
            tls13_server_certificate_chain_der: Vec::new(),
            tls13_server_signing_key: None,
            tls13_server_preferred_cipher_suites: Vec::new(),
            tls13_server_alpn_protocols: Vec::new(),
            tls13_server_x25519_private: None,
            tls13_server_p256_private: None,
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
                let (r, s) = if signature.len() == 64 {
                    let mut r = [0_u8; 32];
                    let mut s = [0_u8; 32];
                    r.copy_from_slice(&signature[..32]);
                    s.copy_from_slice(&signature[32..]);
                    (r, s)
                } else {
                    noxtls_parse_ecdsa_signature_der(signature)?
                };
                noxtls_p256_ecdsa_verify_sha256(&public_key, &signed_message, &r, &s).map_err(
                    |_| {
                        Error::CryptoFailure("tls13 certificate verify signature validation failed")
                    },
                )
            }
            TLS13_SIGALG_ECDSA_SECP384R1_SHA384 => {
                let public_key = P384VerifyingKey::from_sec1_bytes(leaf_spki)
                    .map_err(|_| Error::ParseFailure("failed to parse p384 server public key"))?;
                let ecdsa_signature = P384EcdsaSignature::from_der(signature)
                    .map_err(|_| Error::ParseFailure("failed to parse p384 ecdsa signature"))?;
                public_key
                    .verify(&signed_message, &ecdsa_signature)
                    .map_err(|_| {
                        Error::CryptoFailure("tls13 certificate verify signature validation failed")
                    })
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
    noxtls_encode_server_hello_body_with_key_share(version, suite, random, None, None)
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
    legacy_session_id_echo: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if random.len() != 32 {
        return Err(Error::InvalidLength("server hello random must be 32 bytes"));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&noxtls_legacy_wire_version(version));
    body.extend_from_slice(random);
    let session_id = legacy_session_id_echo.unwrap_or(&[]);
    if session_id.len() > 32 {
        return Err(Error::InvalidLength(
            "server hello session_id echo must not exceed 32 bytes",
        ));
    }
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
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

/// Extracts the legacy `session_id` field from a ClientHello handshake body.
///
/// # Arguments
///
/// * `body` — ClientHello handshake body bytes (without the four-byte handshake header).
///
/// # Returns
///
/// On success, the offered legacy session identifier bytes (possibly empty).
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when the body is truncated or the session id length is invalid.
///
/// # Panics
///
/// This function does not panic.
fn noxtls_extract_client_hello_legacy_session_id(body: &[u8]) -> Result<&[u8]> {
    if body.len() < 35 {
        return Err(Error::ParseFailure("client hello body too short for session_id"));
    }
    let session_id_len = body[34] as usize;
    if session_id_len > 32 {
        return Err(Error::ParseFailure(
            "client hello legacy session_id exceeds 32 bytes",
        ));
    }
    let end = 35_usize.saturating_add(session_id_len);
    if body.len() < end {
        return Err(Error::ParseFailure(
            "client hello legacy session_id bytes truncated",
        ));
    }
    Ok(&body[35..end])
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
                            let mlkem768 = ext_data[4..(4 + MLKEM_CIPHERTEXT_LEN)].to_vec();
                            let mut x25519 = [0_u8; 32];
                            x25519.copy_from_slice(&ext_data[(4 + MLKEM_CIPHERTEXT_LEN)..]);
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
                TLS13_SIGALG_ECDSA_SECP384R1_SHA384,
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
            | TLS13_SIGALG_ECDSA_SECP384R1_SHA384
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
            | TLS13_SIGALG_ECDSA_SECP384R1_SHA384
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

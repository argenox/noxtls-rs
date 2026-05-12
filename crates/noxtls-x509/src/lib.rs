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

//! X.509 certificate parsing, minimal issuance helpers, PEM/DER bridging, and chain validation for NoxTLS.
//!
//! The crate re-exports a flat API from the crate root: [`Certificate`] parsing, RSA/EC/X25519/X448 key
//! material helpers, optional strict chain validation, and small DER writers used by tests and tooling.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::cloned_ref_to_slice_refs)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

mod certs;
mod internal_alloc;

pub use certs::{
    certificate_chain_pem_to_der_blocks, certificate_der_to_pem, certificate_matches_hostname,
    certificate_pem_to_der, der_to_pem, ec_private_key_der_to_pem_sec1,
    ec_private_key_pem_to_der_sec1, ed25519_private_key_from_pem_pkcs8,
    ed25519_private_key_from_pkcs8_der, ed25519_private_key_to_pem_pkcs8,
    ed25519_private_key_to_pkcs8_der, ed25519_public_key_from_pem_spki,
    ed25519_public_key_from_spki_der, ed25519_public_key_to_pem_spki,
    ed25519_public_key_to_spki_der, mldsa_public_key_from_spki_der,
    p256_private_key_from_pem_pkcs8, p256_private_key_from_pem_sec1,
    p256_private_key_from_pkcs8_der, p256_private_key_from_sec1_der, p256_private_key_to_pem_pkcs8,
    p256_private_key_to_pkcs8_der, p256_public_key_from_pem_spki, p256_public_key_from_spki_der,
    p256_public_key_to_pem_spki, p256_public_key_to_spki_der, parse_certificate, parse_der_length,
    parse_der_node, parse_ecdsa_signature_der, parse_pkcs1_rsa_private_key_der,
    parse_pkcs1_rsa_public_key_der, parse_pkcs8_private_key_info_der,
    parse_spki_public_key_info_der, pem_to_der, pem_to_der_blocks, private_key_der_to_pem_pkcs8,
    private_key_pem_to_der_pkcs8, public_key_der_to_pem_spki, public_key_pem_to_der_spki,
    rsa_private_key_der_to_pem_pkcs1, rsa_private_key_from_pem_pkcs1,
    rsa_private_key_from_pem_pkcs8, rsa_private_key_from_pkcs1_der, rsa_private_key_from_pkcs8_der,
    rsa_private_key_pem_to_der_pkcs1, rsa_public_key_der_to_pem_pkcs1,
    rsa_public_key_from_pem_pkcs1, rsa_public_key_from_pem_spki, rsa_public_key_from_pkcs1_der,
    rsa_public_key_from_spki_der, rsa_public_key_pem_to_der_pkcs1, rsa_public_key_to_pem_pkcs1,
    rsa_public_key_to_pem_spki, rsa_public_key_to_spki_der, validate_certificate_chain,
    validate_certificate_chain_constraints_only, validate_certificate_chain_strict,
    validate_certificate_chain_with_options, verify_certificate_signature, write_csr_p256_sha256,
    write_csr_rsa_sha256, write_der_bit_string, write_der_integer, write_der_oid,
    write_der_sequence, write_minimal_certificate_der, write_self_signed_certificate_p256_sha256,
    write_self_signed_certificate_rsa_sha256, x25519_private_key_from_pem_pkcs8,
    x25519_private_key_from_pkcs8_der, x25519_private_key_to_pem_pkcs8,
    x25519_private_key_to_pkcs8_der, x25519_public_key_from_pem_spki,
    x25519_public_key_from_spki_der, x25519_public_key_to_pem_spki, x25519_public_key_to_spki_der,
    x448_private_key_from_pem_pkcs8, x448_private_key_from_pkcs8_der,
    x448_private_key_to_pem_pkcs8, x448_private_key_to_pkcs8_der, x448_public_key_from_pem_spki,
    x448_public_key_from_spki_der, x448_public_key_to_pem_spki, x448_public_key_to_spki_der,
    Certificate, DerNode, Pkcs8PrivateKeyInfoDerParts, RsaPrivateKeyDerParts, RsaPublicKeyDerParts,
    SpkiPublicKeyInfoDerParts, ValidationError, ValidationOptions, ValidationReport,
};

#[cfg(feature = "std")]
pub use certs::{
    der_to_file, der_to_pem_file, ed25519_private_key_from_pem_file_pkcs8,
    ed25519_private_key_to_pem_file_pkcs8, p256_private_key_from_pem_file_pkcs8,
    p256_private_key_to_pem_file_pkcs8, pem_file_to_der, pem_file_to_der_blocks,
    x25519_private_key_from_pem_file_pkcs8, x25519_private_key_to_pem_file_pkcs8,
    x448_private_key_from_pem_file_pkcs8, x448_private_key_to_pem_file_pkcs8,
};

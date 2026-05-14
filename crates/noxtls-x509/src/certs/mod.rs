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

//! Certificate ASN.1 helpers, key encoding, PEM interop via the `noxtls_pem` crate, and validation logic for `noxtls-x509`.

mod asn1;
mod cert_write;
mod certificate;
mod key_format;
mod validate;

pub use asn1::{noxtls_parse_der_length, noxtls_parse_der_node, DerNode};
pub use cert_write::{
    noxtls_write_csr_p256_sha256, noxtls_write_csr_rsa_sha256, noxtls_write_der_bit_string,
    noxtls_write_der_integer, noxtls_write_der_oid, noxtls_write_der_sequence,
    noxtls_write_minimal_certificate_der, noxtls_write_self_signed_certificate_p256_sha256,
    noxtls_write_self_signed_certificate_rsa_sha256,
};
pub use certificate::{noxtls_certificate_matches_hostname, noxtls_parse_certificate, Certificate};
#[cfg(feature = "std")]
pub use key_format::{
    noxtls_ed25519_private_key_from_pem_file_pkcs8, noxtls_ed25519_private_key_to_pem_file_pkcs8,
    noxtls_p256_private_key_from_pem_file_pkcs8, noxtls_p256_private_key_to_pem_file_pkcs8,
    noxtls_x25519_private_key_from_pem_file_pkcs8, noxtls_x25519_private_key_to_pem_file_pkcs8,
    noxtls_x448_private_key_from_pem_file_pkcs8, noxtls_x448_private_key_to_pem_file_pkcs8,
};
pub use key_format::{
    noxtls_ed25519_private_key_from_pem_pkcs8, noxtls_ed25519_private_key_from_pkcs8_der,
    noxtls_ed25519_private_key_to_pem_pkcs8, noxtls_ed25519_private_key_to_pkcs8_der,
    noxtls_ed25519_public_key_from_pem_spki, noxtls_ed25519_public_key_from_spki_der,
    noxtls_ed25519_public_key_to_pem_spki, noxtls_ed25519_public_key_to_spki_der,
    noxtls_mldsa_public_key_from_spki_der, noxtls_p256_private_key_from_pem_pkcs8,
    noxtls_p256_private_key_from_pem_sec1, noxtls_p256_private_key_from_pkcs8_der,
    noxtls_p256_private_key_from_sec1_der, noxtls_p256_private_key_to_pem_pkcs8,
    noxtls_p256_private_key_to_pkcs8_der, noxtls_p256_public_key_from_pem_spki,
    noxtls_p256_public_key_from_spki_der, noxtls_p256_public_key_to_pem_spki,
    noxtls_p256_public_key_to_spki_der, noxtls_parse_ecdsa_signature_der,
    noxtls_parse_pkcs1_rsa_private_key_der, noxtls_parse_pkcs1_rsa_public_key_der,
    noxtls_parse_pkcs8_private_key_info_der, noxtls_parse_spki_public_key_info_der,
    noxtls_rsa_private_key_from_pem_pkcs1, noxtls_rsa_private_key_from_pem_pkcs8,
    noxtls_rsa_private_key_from_pkcs1_der, noxtls_rsa_private_key_from_pkcs8_der,
    noxtls_rsa_public_key_from_pem_pkcs1, noxtls_rsa_public_key_from_pem_spki,
    noxtls_rsa_public_key_from_pkcs1_der, noxtls_rsa_public_key_from_spki_der,
    noxtls_rsa_public_key_to_pem_pkcs1, noxtls_rsa_public_key_to_pem_spki,
    noxtls_rsa_public_key_to_spki_der, noxtls_x25519_private_key_from_pem_pkcs8,
    noxtls_x25519_private_key_from_pkcs8_der, noxtls_x25519_private_key_to_pem_pkcs8,
    noxtls_x25519_private_key_to_pkcs8_der, noxtls_x25519_public_key_from_pem_spki,
    noxtls_x25519_public_key_from_spki_der, noxtls_x25519_public_key_to_pem_spki,
    noxtls_x25519_public_key_to_spki_der, noxtls_x448_private_key_from_pem_pkcs8,
    noxtls_x448_private_key_from_pkcs8_der, noxtls_x448_private_key_to_pem_pkcs8,
    noxtls_x448_private_key_to_pkcs8_der, noxtls_x448_public_key_from_pem_spki,
    noxtls_x448_public_key_from_spki_der, noxtls_x448_public_key_to_pem_spki,
    noxtls_x448_public_key_to_spki_der, Pkcs8PrivateKeyInfoDerParts, RsaPrivateKeyDerParts,
    RsaPublicKeyDerParts, SpkiPublicKeyInfoDerParts,
};
pub use noxtls_pem::{
    noxtls_certificate_chain_pem_to_der_blocks, noxtls_certificate_der_to_pem,
    noxtls_certificate_pem_to_der, noxtls_der_to_pem, noxtls_ec_private_key_der_to_pem_sec1,
    noxtls_ec_private_key_pem_to_der_sec1, noxtls_pem_to_der, noxtls_pem_to_der_blocks,
    noxtls_private_key_der_to_pem_pkcs8, noxtls_private_key_pem_to_der_pkcs8,
    noxtls_public_key_der_to_pem_spki, noxtls_public_key_pem_to_der_spki,
    noxtls_rsa_private_key_der_to_pem_pkcs1, noxtls_rsa_private_key_pem_to_der_pkcs1,
    noxtls_rsa_public_key_der_to_pem_pkcs1, noxtls_rsa_public_key_pem_to_der_pkcs1,
};
#[cfg(feature = "std")]
pub use noxtls_pem::{
    noxtls_der_to_file, noxtls_der_to_pem_file, noxtls_pem_file_to_der,
    noxtls_pem_file_to_der_blocks,
};
pub use validate::{
    noxtls_validate_certificate_chain, noxtls_validate_certificate_chain_constraints_only,
    noxtls_validate_certificate_chain_strict, noxtls_validate_certificate_chain_with_options,
    noxtls_verify_certificate_signature, ValidationError, ValidationOptions, ValidationReport,
};

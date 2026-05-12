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

pub use asn1::{parse_der_length, parse_der_node, DerNode};
pub use cert_write::{
    write_csr_p256_sha256, write_csr_rsa_sha256, write_der_bit_string, write_der_integer,
    write_der_oid, write_der_sequence, write_minimal_certificate_der,
    write_self_signed_certificate_p256_sha256, write_self_signed_certificate_rsa_sha256,
};
pub use certificate::{certificate_matches_hostname, parse_certificate, Certificate};
pub use key_format::{
    ed25519_private_key_from_pem_pkcs8, ed25519_private_key_from_pkcs8_der,
    ed25519_private_key_to_pem_pkcs8, ed25519_private_key_to_pkcs8_der,
    ed25519_public_key_from_pem_spki, ed25519_public_key_from_spki_der, ed25519_public_key_to_pem_spki,
    ed25519_public_key_to_spki_der, mldsa_public_key_from_spki_der, p256_private_key_from_pem_pkcs8,
    p256_private_key_from_pem_sec1, p256_private_key_from_pkcs8_der, p256_private_key_to_pem_pkcs8,
    p256_private_key_to_pkcs8_der,
    p256_private_key_from_sec1_der, p256_public_key_from_pem_spki, p256_public_key_from_spki_der,
    p256_public_key_to_pem_spki, p256_public_key_to_spki_der, parse_ecdsa_signature_der,
    parse_pkcs1_rsa_private_key_der, parse_pkcs1_rsa_public_key_der,
    parse_pkcs8_private_key_info_der, parse_spki_public_key_info_der,
    rsa_private_key_from_pem_pkcs1, rsa_private_key_from_pem_pkcs8, rsa_private_key_from_pkcs1_der,
    rsa_private_key_from_pkcs8_der, rsa_public_key_from_pem_pkcs1, rsa_public_key_from_pem_spki,
    rsa_public_key_from_pkcs1_der, rsa_public_key_from_spki_der, rsa_public_key_to_pem_pkcs1,
    rsa_public_key_to_pem_spki, rsa_public_key_to_spki_der, x25519_private_key_from_pem_pkcs8,
    x25519_private_key_from_pkcs8_der, x25519_private_key_to_pem_pkcs8,
    x25519_private_key_to_pkcs8_der, x25519_public_key_from_pem_spki,
    x25519_public_key_from_spki_der, x25519_public_key_to_pem_spki, x25519_public_key_to_spki_der,
    x448_private_key_from_pem_pkcs8, x448_private_key_from_pkcs8_der, x448_private_key_to_pem_pkcs8,
    x448_private_key_to_pkcs8_der,
    x448_public_key_from_pem_spki, x448_public_key_from_spki_der, x448_public_key_to_pem_spki,
    x448_public_key_to_spki_der, Pkcs8PrivateKeyInfoDerParts, RsaPrivateKeyDerParts,
    RsaPublicKeyDerParts, SpkiPublicKeyInfoDerParts,
};
pub use noxtls_pem::{
    certificate_chain_pem_to_der_blocks, certificate_der_to_pem, certificate_pem_to_der,
    der_to_pem, ec_private_key_der_to_pem_sec1, ec_private_key_pem_to_der_sec1, pem_to_der,
    pem_to_der_blocks, private_key_der_to_pem_pkcs8, private_key_pem_to_der_pkcs8,
    public_key_der_to_pem_spki, public_key_pem_to_der_spki, rsa_private_key_der_to_pem_pkcs1,
    rsa_private_key_pem_to_der_pkcs1, rsa_public_key_der_to_pem_pkcs1,
    rsa_public_key_pem_to_der_pkcs1,
};
#[cfg(feature = "std")]
pub use noxtls_pem::{der_to_file, der_to_pem_file, pem_file_to_der, pem_file_to_der_blocks};
#[cfg(feature = "std")]
pub use key_format::{
    ed25519_private_key_from_pem_file_pkcs8, ed25519_private_key_to_pem_file_pkcs8,
    p256_private_key_from_pem_file_pkcs8, p256_private_key_to_pem_file_pkcs8,
    x25519_private_key_from_pem_file_pkcs8, x25519_private_key_to_pem_file_pkcs8,
    x448_private_key_from_pem_file_pkcs8, x448_private_key_to_pem_file_pkcs8,
};
pub use validate::{
    validate_certificate_chain, validate_certificate_chain_constraints_only,
    validate_certificate_chain_strict, validate_certificate_chain_with_options,
    verify_certificate_signature, ValidationError, ValidationOptions, ValidationReport,
};


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

//! OpenSSL-inspired `noxtls-rs` CLI example: digests, AEAD, DRBG, keys, PKCS#8, CSR, X.509, and verify.
//!
//! Run with `cargo run -p noxtls --example noxtls_rs -- ...`. Subcommands mirror the `main` dispatch table.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use noxtls_core::{Error, Result};
#[cfg(feature = "hazardous-legacy-crypto")]
use noxtls_crypto::noxtls_x448_generate_private_key_auto;
use noxtls_crypto::{
    noxtls_aes_gcm_decrypt, noxtls_aes_gcm_encrypt, noxtls_decode_hex, noxtls_sha1, noxtls_sha256, noxtls_sha384, noxtls_sha3_256, noxtls_sha3_384,
    noxtls_sha3_512, noxtls_sha512, noxtls_x25519_generate_private_key_auto, AesCipher, HmacDrbgSha256, P256PrivateKey,
    P256PublicKey,
};
#[cfg(feature = "hazardous-legacy-crypto")]
use noxtls_x509::noxtls_x448_public_key_to_pem_spki;
use noxtls_x509::{
    noxtls_certificate_der_to_pem, noxtls_certificate_matches_hostname, noxtls_certificate_pem_to_der, noxtls_der_to_pem,
    noxtls_p256_public_key_to_pem_spki, noxtls_parse_certificate, noxtls_parse_der_node,
    noxtls_parse_pkcs8_private_key_info_der, noxtls_private_key_der_to_pem_pkcs8, noxtls_private_key_pem_to_der_pkcs8,
    noxtls_validate_certificate_chain, noxtls_write_csr_p256_sha256, noxtls_write_self_signed_certificate_p256_sha256,
    noxtls_x25519_public_key_to_pem_spki,
};

/// Runs an OpenSSL-style noxtls utility for digests, encryption, randomness, keys, and X.509.
///
/// # Arguments
///
/// * `argv` — Standard process arguments; `argv[1]` selects the subcommand (`dgst`, `enc`, `help`, …).
///
/// # Returns
///
/// `Ok(())` after the selected subcommand completes, or the `Err` value propagated from that subcommand.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "dgst" => run_dgst(&args[2..]),
        "enc" => run_enc(&args[2..]),
        "dec" => run_dec(&args[2..]),
        "rand" => run_rand(&args[2..]),
        "genpkey" => run_genpkey(&args[2..]),
        "pkcs8" => run_pkcs8(&args[2..]),
        "req" => run_req(&args[2..]),
        "x509" => run_x509(&args[2..]),
        "verify" => run_verify(&args[2..]),
        "hash" => run_hash_legacy(&args[2..]),
        "encrypt" => run_encrypt_legacy(&args[2..]),
        "decrypt" => run_decrypt_legacy(&args[2..]),
        _ => {
            print_usage();
            Ok(())
        }
    }
}

/// Prints command usage for the noxtls-rs utility.
/// # Arguments
///
/// _(none)_ — See `argv` parsing and flags in the function body.
///
/// # Returns
///
/// `()` — This function does not produce a value.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn print_usage() {
    println!("usage:");
    println!(
        "  noxtls-rs dgst --alg <sha1|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512> [--in <file> | --text <text>]"
    );
    println!(
        "  noxtls-rs enc --key <hex-16/24/32-byte-key> [--nonce <hex-12-byte>] [--aad <text>] [--in <file> | --text <text>] [--out <cipher.bin>] [--tag-out <tag.bin>]"
    );
    println!(
        "  noxtls-rs dec --key <hex-16/24/32-byte-key> --nonce <hex-12-byte> --tag <hex-16-byte> [--aad <text>] [--in <cipher.bin> | --ciphertext-hex <hex>] [--out <plain.bin>]"
    );
    println!("  noxtls-rs rand --bytes <n> [--hex] [--out <file>] [--seed-hex <hex>]");
    println!(
        "  noxtls-rs genpkey --algorithm <p256|x25519|x448> --out <private.txt> [--pubout <public.pem>] [--seed-hex <hex>]"
    );
    println!(
        "  noxtls-rs pkcs8 --topk8 --algorithm <p256|x25519|x448> --key-hex <hex> [--out <key.pem|key.der>] [--outform <pem|der>]"
    );
    println!(
        "  noxtls-rs pkcs8 --in <key.pem|key.der> [--inform <pem|der>] [--algorithm <p256|x25519|x448>] [--out <file>] [--outform <pem|der|hex>]"
    );
    println!(
        "  noxtls-rs req --new --key-hex <p256-32-byte-hex> --subj <common-name> [--out <csr.pem|csr.der>] [--outform <pem|der>]"
    );
    println!("  noxtls-rs x509 --in <cert.pem|cert.der>");
    println!(
        "  noxtls-rs x509 --selfsign --key-hex <p256-32-byte-hex> --subj <common-name> [--serial-hex <hex>] [--not-before <YYMMDDhhmmssZ>] [--not-after <YYMMDDhhmmssZ>] [--out <cert.pem|cert.der>] [--outform <pem|der>]"
    );
    println!(
        "  noxtls-rs verify --cert <leaf.pem|leaf.der> --ca <anchor.pem|anchor.der> [--hostname <dns-name>] [--time <YYMMDDhhmmssZ>]"
    );
    println!();
    println!("legacy aliases:");
    println!("  noxtls-rs hash <text>");
    println!("  noxtls-rs encrypt <hex-key> <text>");
    println!("  noxtls-rs decrypt <hex-key> <hex-ciphertext> <hex-tag>");
}

/// Runs digest hashing for text or file input.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_dgst(args: &[String]) -> Result<()> {
    let mut algorithm = "sha256";
    let mut input_file: Option<&str> = None;
    let mut input_text: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--alg" => {
                index += 1;
                algorithm = args
                    .get(index)
                    .ok_or(Error::StateError("missing digest algorithm"))?;
            }
            "--in" => {
                index += 1;
                input_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing digest input file"))?,
                );
            }
            "--text" => {
                index += 1;
                input_text = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing digest text input"))?,
                );
            }
            _ => return Err(Error::StateError("unsupported dgst flag")),
        }
        index += 1;
    }
    if input_file.is_some() == input_text.is_some() {
        return Err(Error::StateError("provide either --in or --text for dgst"));
    }
    let input = if let Some(path) = input_file {
        fs::read(path).map_err(|_| Error::StateError("failed to read digest input file"))?
    } else {
        input_text
            .ok_or(Error::StateError("missing digest input"))?
            .as_bytes()
            .to_vec()
    };
    let digest = digest_bytes(algorithm, &input)?;
    println!("{algorithm}={}", to_hex(&digest));
    Ok(())
}

/// Runs AES-GCM encryption with OpenSSL-style CLI options.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_enc(args: &[String]) -> Result<()> {
    let mut key_hex: Option<&str> = None;
    let mut nonce_hex: Option<&str> = None;
    let mut aad = "";
    let mut input_file: Option<&str> = None;
    let mut input_text: Option<&str> = None;
    let mut output_file: Option<&str> = None;
    let mut tag_output_file: Option<&str> = None;
    let mut seed_hex: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                index += 1;
                key_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing encryption key"))?,
                );
            }
            "--nonce" => {
                index += 1;
                nonce_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing nonce value"))?,
                );
            }
            "--aad" => {
                index += 1;
                aad = args
                    .get(index)
                    .ok_or(Error::StateError("missing AAD value"))?;
            }
            "--in" => {
                index += 1;
                input_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing encryption input file"))?,
                );
            }
            "--text" => {
                index += 1;
                input_text = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing plaintext text"))?,
                );
            }
            "--out" => {
                index += 1;
                output_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing encryption output file"))?,
                );
            }
            "--tag-out" => {
                index += 1;
                tag_output_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing tag output file"))?,
                );
            }
            "--seed-hex" => {
                index += 1;
                seed_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing seed-hex value"))?,
                );
            }
            _ => return Err(Error::StateError("unsupported enc flag")),
        }
        index += 1;
    }
    if input_file.is_some() == input_text.is_some() {
        return Err(Error::StateError("provide either --in or --text for enc"));
    }

    let key = noxtls_decode_hex(key_hex.ok_or(Error::StateError("missing encryption key"))?)?;
    let nonce = if let Some(explicit_nonce_hex) = nonce_hex {
        parse_fixed_hex::<12>(explicit_nonce_hex, "nonce must be 12 bytes of hex")?
    } else {
        let mut drbg = make_cli_drbg(seed_hex)?;
        let generated = drbg.generate(12, b"enc_nonce")?;
        let mut out = [0_u8; 12];
        out.copy_from_slice(&generated);
        out
    };
    let plaintext = if let Some(path) = input_file {
        fs::read(path).map_err(|_| Error::StateError("failed to read encryption input file"))?
    } else {
        input_text
            .ok_or(Error::StateError("missing encryption input"))?
            .as_bytes()
            .to_vec()
    };
    let cipher = AesCipher::new(&key)?;
    let (ciphertext, tag) = noxtls_aes_gcm_encrypt(&cipher, &nonce, aad.as_bytes(), &plaintext)?;

    if let Some(path) = output_file {
        fs::write(path, &ciphertext)
            .map_err(|_| Error::StateError("failed to write ciphertext file"))?;
    } else {
        println!("ciphertext={}", to_hex(&ciphertext));
    }
    if let Some(path) = tag_output_file {
        fs::write(path, tag).map_err(|_| Error::StateError("failed to write tag file"))?;
    } else {
        println!("tag={}", to_hex(&tag));
    }
    println!("nonce={}", to_hex(&nonce));
    println!("aad={aad}");
    Ok(())
}

/// Runs AES-GCM decryption with OpenSSL-style CLI options.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_dec(args: &[String]) -> Result<()> {
    let mut key_hex: Option<&str> = None;
    let mut nonce_hex: Option<&str> = None;
    let mut tag_hex: Option<&str> = None;
    let mut aad = "";
    let mut input_file: Option<&str> = None;
    let mut ciphertext_hex: Option<&str> = None;
    let mut output_file: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                index += 1;
                key_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing decryption key"))?,
                );
            }
            "--nonce" => {
                index += 1;
                nonce_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing nonce value"))?,
                );
            }
            "--tag" => {
                index += 1;
                tag_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing tag value"))?,
                );
            }
            "--aad" => {
                index += 1;
                aad = args
                    .get(index)
                    .ok_or(Error::StateError("missing AAD value"))?;
            }
            "--in" => {
                index += 1;
                input_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing ciphertext input file"))?,
                );
            }
            "--ciphertext-hex" => {
                index += 1;
                ciphertext_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing ciphertext hex"))?,
                );
            }
            "--out" => {
                index += 1;
                output_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing plaintext output file"))?,
                );
            }
            _ => return Err(Error::StateError("unsupported dec flag")),
        }
        index += 1;
    }
    if input_file.is_some() == ciphertext_hex.is_some() {
        return Err(Error::StateError(
            "provide either --in or --ciphertext-hex for dec",
        ));
    }

    let key = noxtls_decode_hex(key_hex.ok_or(Error::StateError("missing decryption key"))?)?;
    let nonce = parse_fixed_hex::<12>(
        nonce_hex.ok_or(Error::StateError("missing nonce value"))?,
        "nonce must be 12 bytes of hex",
    )?;
    let tag = parse_fixed_hex::<16>(
        tag_hex.ok_or(Error::StateError("missing tag value"))?,
        "tag must be 16 bytes of hex",
    )?;
    let ciphertext = if let Some(path) = input_file {
        fs::read(path).map_err(|_| Error::StateError("failed to read ciphertext file"))?
    } else {
        noxtls_decode_hex(ciphertext_hex.ok_or(Error::StateError("missing ciphertext hex"))?)?
    };
    let cipher = AesCipher::new(&key)?;
    let plaintext = noxtls_aes_gcm_decrypt(&cipher, &nonce, aad.as_bytes(), &ciphertext, &tag)?;

    if let Some(path) = output_file {
        fs::write(path, &plaintext)
            .map_err(|_| Error::StateError("failed to write plaintext file"))?;
    } else {
        println!("plaintext={}", String::from_utf8_lossy(&plaintext));
    }
    Ok(())
}

/// Generates DRBG-backed random bytes for CLI use.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_rand(args: &[String]) -> Result<()> {
    let mut bytes_len: Option<usize> = None;
    let mut output_file: Option<&str> = None;
    let mut hex_output = false;
    let mut seed_hex: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bytes" => {
                index += 1;
                let text = args
                    .get(index)
                    .ok_or(Error::StateError("missing rand bytes length"))?;
                bytes_len = Some(
                    text.parse()
                        .map_err(|_| Error::StateError("invalid rand bytes length"))?,
                );
            }
            "--out" => {
                index += 1;
                output_file = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing rand output file"))?,
                );
            }
            "--hex" => {
                hex_output = true;
            }
            "--seed-hex" => {
                index += 1;
                seed_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing seed-hex value"))?,
                );
            }
            _ => return Err(Error::StateError("unsupported rand flag")),
        }
        index += 1;
    }

    let mut drbg = make_cli_drbg(seed_hex)?;
    let bytes = drbg.generate(
        bytes_len.ok_or(Error::StateError("missing rand bytes length"))?,
        b"cli_rand",
    )?;
    if let Some(path) = output_file {
        if hex_output {
            fs::write(path, to_hex(&bytes))
                .map_err(|_| Error::StateError("failed to write rand output file"))?;
        } else {
            fs::write(path, &bytes)
                .map_err(|_| Error::StateError("failed to write rand output file"))?;
        }
    } else {
        println!("{}", to_hex(&bytes));
    }
    Ok(())
}

/// Generates asymmetric keys and writes private/public output files.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_genpkey(args: &[String]) -> Result<()> {
    let mut algorithm: Option<&str> = None;
    let mut out_path: Option<&str> = None;
    let mut pubout_path: Option<&str> = None;
    let mut seed_hex: Option<&str> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--algorithm" => {
                index += 1;
                algorithm = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing key algorithm"))?,
                );
            }
            "--out" => {
                index += 1;
                out_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing private key output path"))?,
                );
            }
            "--pubout" => {
                index += 1;
                pubout_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing public key output path"))?,
                );
            }
            "--seed-hex" => {
                index += 1;
                seed_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing seed-hex value"))?,
                );
            }
            _ => return Err(Error::StateError("unsupported genpkey flag")),
        }
        index += 1;
    }

    let algorithm = algorithm.ok_or(Error::StateError("missing key algorithm"))?;
    let out_path = out_path.ok_or(Error::StateError("missing private key output path"))?;
    let mut drbg = make_cli_drbg(seed_hex)?;
    let (private_text, public_pem) = match algorithm {
        "p256" => {
            let generated = generate_p256_private_key(&mut drbg)?;
            let public = generated.public_key()?;
            (
                format!(
                    "P256_PRIVATE_SCALAR_HEX={}\n",
                    to_hex(&generated.private_scalar())
                ),
                noxtls_p256_public_key_to_pem_spki(&public)?,
            )
        }
        "x25519" => {
            let private = noxtls_x25519_generate_private_key_auto(&mut drbg)?;
            let public = private.public_key();
            (
                format!(
                    "X25519_PRIVATE_SCALAR_HEX={}\n",
                    to_hex(&private.clamped_scalar())
                ),
                noxtls_x25519_public_key_to_pem_spki(public)?,
            )
        }
        "x448" => {
            #[cfg(feature = "hazardous-legacy-crypto")]
            {
                let private = noxtls_x448_generate_private_key_auto(&mut drbg)?;
                let public = private.public_key();
                (
                    format!(
                        "X448_PRIVATE_SCALAR_HEX={}\n",
                        to_hex(&private.clamped_scalar())
                    ),
                    noxtls_x448_public_key_to_pem_spki(public)?,
                )
            }
            #[cfg(not(feature = "hazardous-legacy-crypto"))]
            {
                return Err(Error::StateError(
                    "x448 key generation requires `hazardous-legacy-crypto` feature",
                ));
            }
        }
        _ => return Err(Error::StateError("unsupported key algorithm")),
    };

    fs::write(out_path, private_text)
        .map_err(|_| Error::StateError("failed to write private key file"))?;
    if let Some(path) = pubout_path {
        fs::write(path, public_pem)
            .map_err(|_| Error::StateError("failed to write public key file"))?;
    } else {
        println!("{public_pem}");
    }
    Ok(())
}

/// Encodes or decodes PKCS#8 private keys for interoperability.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_pkcs8(args: &[String]) -> Result<()> {
    let mut topk8 = false;
    let mut algorithm: Option<&str> = None;
    let mut key_hex: Option<&str> = None;
    let mut input_path: Option<&str> = None;
    let mut input_format: Option<&str> = None;
    let mut output_path: Option<&str> = None;
    let mut output_format = "pem";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--topk8" => {
                topk8 = true;
            }
            "--algorithm" => {
                index += 1;
                algorithm = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing pkcs8 algorithm value"))?,
                );
            }
            "--key-hex" => {
                index += 1;
                key_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing pkcs8 key-hex value"))?,
                );
            }
            "--in" => {
                index += 1;
                input_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing pkcs8 input path"))?,
                );
            }
            "--inform" => {
                index += 1;
                input_format = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing pkcs8 inform value"))?,
                );
            }
            "--out" => {
                index += 1;
                output_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing pkcs8 output path"))?,
                );
            }
            "--outform" => {
                index += 1;
                output_format = args
                    .get(index)
                    .ok_or(Error::StateError("missing pkcs8 outform value"))?;
            }
            _ => return Err(Error::StateError("unsupported pkcs8 flag")),
        }
        index += 1;
    }

    if topk8 {
        let algorithm = algorithm.ok_or(Error::StateError("missing pkcs8 algorithm value"))?;
        let key_hex = key_hex.ok_or(Error::StateError("missing pkcs8 key-hex value"))?;
        let pkcs8_der = encode_pkcs8_private_key_der(algorithm, key_hex)?;
        return emit_pkcs8_output(&pkcs8_der, output_path, output_format);
    }

    let input_path = input_path.ok_or(Error::StateError("missing pkcs8 input path"))?;
    let pkcs8_der = read_pkcs8_der(input_path, input_format)?;
    let info = noxtls_parse_pkcs8_private_key_info_der(&pkcs8_der)?;
    if let Some(expected_algorithm) = algorithm {
        validate_pkcs8_algorithm(expected_algorithm, &info.algorithm_oid)?;
    }

    match output_format {
        "pem" | "der" => emit_pkcs8_output(&pkcs8_der, output_path, output_format),
        "hex" => {
            let raw_private =
                extract_private_scalar_hex_payload(&info.algorithm_oid, &info.private_key)?;
            if let Some(path) = output_path {
                fs::write(path, &raw_private)
                    .map_err(|_| Error::StateError("failed to write pkcs8 hex output"))?;
            } else {
                println!("{raw_private}");
            }
            Ok(())
        }
        _ => Err(Error::StateError("unsupported pkcs8 outform")),
    }
}

/// Generates a PKCS#10 CSR from a user-supplied P-256 private scalar.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_req(args: &[String]) -> Result<()> {
    let mut key_hex: Option<&str> = None;
    let mut subject: Option<&str> = None;
    let mut output_path: Option<&str> = None;
    let mut output_format = "pem";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--new" => {}
            "--key-hex" => {
                index += 1;
                key_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing req key value"))?,
                );
            }
            "--subj" => {
                index += 1;
                subject = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing req subject value"))?,
                );
            }
            "--out" => {
                index += 1;
                output_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing req output path"))?,
                );
            }
            "--outform" => {
                index += 1;
                output_format = args
                    .get(index)
                    .ok_or(Error::StateError("missing req outform value"))?;
            }
            _ => return Err(Error::StateError("unsupported req flag")),
        }
        index += 1;
    }

    let private =
        parse_p256_private_key_hex(key_hex.ok_or(Error::StateError("missing req key value"))?)?;
    let public = private.public_key()?;
    let csr_der = noxtls_write_csr_p256_sha256(
        subject.ok_or(Error::StateError("missing req subject value"))?,
        &public,
        &private,
    )?;
    match output_format {
        "pem" => {
            let csr_pem = noxtls_der_to_pem(&csr_der, "CERTIFICATE REQUEST")?;
            if let Some(path) = output_path {
                fs::write(path, csr_pem)
                    .map_err(|_| Error::StateError("failed to write CSR PEM output"))?;
            } else {
                println!("{csr_pem}");
            }
        }
        "der" => {
            if let Some(path) = output_path {
                fs::write(path, &csr_der)
                    .map_err(|_| Error::StateError("failed to write CSR DER output"))?;
            } else {
                println!("{}", to_hex(&csr_der));
            }
        }
        _ => return Err(Error::StateError("unsupported req outform")),
    }
    Ok(())
}

/// Parses certificate metadata or emits a self-signed certificate.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_x509(args: &[String]) -> Result<()> {
    let mut input_path: Option<&str> = None;
    let mut selfsign = false;
    let mut key_hex: Option<&str> = None;
    let mut subject: Option<&str> = None;
    let mut serial_hex: Option<&str> = None;
    let mut not_before = "240101000000Z";
    let mut not_after = "300101000000Z";
    let mut output_path: Option<&str> = None;
    let mut output_format = "pem";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--in" => {
                index += 1;
                input_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing x509 input path"))?,
                );
            }
            "--selfsign" => {
                selfsign = true;
            }
            "--key-hex" => {
                index += 1;
                key_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing x509 key value"))?,
                );
            }
            "--subj" => {
                index += 1;
                subject = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing x509 subject value"))?,
                );
            }
            "--serial-hex" => {
                index += 1;
                serial_hex = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing x509 serial value"))?,
                );
            }
            "--not-before" => {
                index += 1;
                not_before = args
                    .get(index)
                    .ok_or(Error::StateError("missing x509 not-before value"))?;
            }
            "--not-after" => {
                index += 1;
                not_after = args
                    .get(index)
                    .ok_or(Error::StateError("missing x509 not-after value"))?;
            }
            "--out" => {
                index += 1;
                output_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing x509 output path"))?,
                );
            }
            "--outform" => {
                index += 1;
                output_format = args
                    .get(index)
                    .ok_or(Error::StateError("missing x509 outform value"))?;
            }
            _ => return Err(Error::StateError("unsupported x509 flag")),
        }
        index += 1;
    }

    if selfsign {
        let private = parse_p256_private_key_hex(
            key_hex.ok_or(Error::StateError("missing x509 key value"))?,
        )?;
        let public = private.public_key()?;
        let serial = if let Some(value) = serial_hex {
            noxtls_decode_hex(value)?
        } else {
            vec![0x01]
        };
        let cert_der = noxtls_write_self_signed_certificate_p256_sha256(
            &serial,
            subject.ok_or(Error::StateError("missing x509 subject value"))?,
            not_before,
            not_after,
            &public,
            &private,
        )?;
        match output_format {
            "pem" => {
                let cert_pem = noxtls_certificate_der_to_pem(&cert_der)?;
                if let Some(path) = output_path {
                    fs::write(path, cert_pem)
                        .map_err(|_| Error::StateError("failed to write certificate PEM output"))?;
                } else {
                    println!("{cert_pem}");
                }
            }
            "der" => {
                if let Some(path) = output_path {
                    fs::write(path, &cert_der)
                        .map_err(|_| Error::StateError("failed to write certificate DER output"))?;
                } else {
                    println!("{}", to_hex(&cert_der));
                }
            }
            _ => return Err(Error::StateError("unsupported x509 outform")),
        }
        return Ok(());
    }

    let cert_der =
        read_certificate_der(input_path.ok_or(Error::StateError("missing x509 input path"))?)?;
    let cert = noxtls_parse_certificate(&cert_der)?;
    println!("version=v{}", cert.version);
    println!("serial_len={}B", cert.serial.len());
    println!("not_before={}", cert.not_before);
    println!("not_after={}", cert.not_after);
    println!("subject_public_key_len={}B", cert.subject_public_key.len());
    println!("san_dns_count={}", cert.subject_alt_dns_names.len());
    Ok(())
}

/// Verifies a leaf certificate against one trust anchor and optional hostname.
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_verify(args: &[String]) -> Result<()> {
    let mut cert_path: Option<&str> = None;
    let mut ca_path: Option<&str> = None;
    let mut hostname: Option<&str> = None;
    let mut verify_time = "20260101000000Z";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--cert" => {
                index += 1;
                cert_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing verify leaf path"))?,
                );
            }
            "--ca" => {
                index += 1;
                ca_path = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing verify trust anchor path"))?,
                );
            }
            "--hostname" => {
                index += 1;
                hostname = Some(
                    args.get(index)
                        .ok_or(Error::StateError("missing verify hostname"))?,
                );
            }
            "--time" => {
                index += 1;
                verify_time = args
                    .get(index)
                    .ok_or(Error::StateError("missing verify time value"))?;
            }
            _ => return Err(Error::StateError("unsupported verify flag")),
        }
        index += 1;
    }

    let leaf_der =
        read_certificate_der(cert_path.ok_or(Error::StateError("missing verify leaf path"))?)?;
    let ca_der = read_certificate_der(
        ca_path.ok_or(Error::StateError("missing verify trust anchor path"))?,
    )?;
    let leaf = noxtls_parse_certificate(&leaf_der)?;
    let anchor = noxtls_parse_certificate(&ca_der)?;
    if let Some(name) = hostname {
        if !noxtls_certificate_matches_hostname(&leaf, name) {
            println!("verify_ok=false reason=hostname_mismatch");
            return Err(Error::StateError("certificate hostname mismatch"));
        }
    }
    match noxtls_validate_certificate_chain(&leaf, &[], &[anchor], verify_time) {
        Ok(report) => {
            println!("verify_ok=true chain_len={}", report.chain_len);
            println!("trust_anchor_index={}", report.trust_anchor_index);
            Ok(())
        }
        Err(err) => {
            println!("verify_ok=false reason={err}");
            Err(Error::StateError("certificate chain verification failed"))
        }
    }
}

/// Preserves legacy hash behavior (`hash <text>`).
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_hash_legacy(args: &[String]) -> Result<()> {
    let input = args
        .first()
        .ok_or(Error::StateError("missing hash input"))?;
    let digest = noxtls_sha256(input.as_bytes());
    println!("sha256={}", to_hex(&digest));
    Ok(())
}

/// Preserves legacy encrypt behavior (`encrypt <hex-key> <text>`).
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_encrypt_legacy(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(Error::StateError("missing encrypt arguments"));
    }
    run_enc(&[
        "--key".to_owned(),
        args[0].clone(),
        "--text".to_owned(),
        args[1].clone(),
        "--nonce".to_owned(),
        "000102030405060708090a0b".to_owned(),
    ])
}

/// Preserves legacy decrypt behavior (`decrypt <key> <ciphertext> <tag>`).
/// # Arguments
///
/// * `args` — `args: &[String]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn run_decrypt_legacy(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        return Err(Error::StateError("missing decrypt arguments"));
    }
    run_dec(&[
        "--key".to_owned(),
        args[0].clone(),
        "--ciphertext-hex".to_owned(),
        args[1].clone(),
        "--tag".to_owned(),
        args[2].clone(),
        "--nonce".to_owned(),
        "000102030405060708090a0b".to_owned(),
    ])
}

/// Hashes bytes using the selected digest algorithm.
/// # Arguments
///
/// * `algorithm` — `algorithm: &str`.
/// * `input` — `input: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn digest_bytes(algorithm: &str, input: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        "sha1" => Ok(noxtls_sha1(input).to_vec()),
        "sha256" => Ok(noxtls_sha256(input).to_vec()),
        "sha384" => Ok(noxtls_sha384(input).to_vec()),
        "sha512" => Ok(noxtls_sha512(input).to_vec()),
        "sha3-256" => Ok(noxtls_sha3_256(input).to_vec()),
        "sha3-384" => Ok(noxtls_sha3_384(input).to_vec()),
        "sha3-512" => Ok(noxtls_sha3_512(input).to_vec()),
        _ => Err(Error::StateError("unsupported digest algorithm")),
    }
}

/// Initializes a DRBG from optional seed input or best-effort local entropy.
/// # Arguments
///
/// * `seed_hex` — `seed_hex: Option<&str>`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn make_cli_drbg(seed_hex: Option<&str>) -> Result<HmacDrbgSha256> {
    let seed = if let Some(text) = seed_hex {
        noxtls_decode_hex(text)?
    } else {
        collect_best_effort_entropy()
    };
    if seed.len() < 16 {
        return Err(Error::StateError("seed material must be at least 16 bytes"));
    }
    let digest = noxtls_sha512(&seed);
    HmacDrbgSha256::new(&digest[0..32], &digest[32..48], &digest[48..64])
}

/// Loads a certificate file and converts PEM input into DER bytes.
/// # Arguments
///
/// * `path` — `path: &str`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn read_certificate_der(path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|_| Error::StateError("failed to read certificate file"))?;
    if bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let pem_text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::InvalidEncoding("certificate PEM must be UTF-8"))?;
        return noxtls_certificate_pem_to_der(pem_text);
    }
    Ok(bytes)
}

/// Parses a 32-byte big-endian P-256 private scalar from hex.
/// # Arguments
///
/// * `value` — `value: &str`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn parse_p256_private_key_hex(value: &str) -> Result<P256PrivateKey> {
    let scalar = parse_fixed_hex::<32>(value, "p256 private key must be 32 bytes of hex")?;
    P256PrivateKey::from_bytes(scalar)
}

/// Reads PKCS#8 key data from a file as DER bytes.
/// # Arguments
///
/// * `path` — `path: &str`.
/// * `input_format` — `input_format: Option<&str>`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn read_pkcs8_der(path: &str, input_format: Option<&str>) -> Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|_| Error::StateError("failed to read pkcs8 input file"))?;
    let chosen_format = if let Some(explicit_format) = input_format {
        explicit_format
    } else if bytes.starts_with(b"-----BEGIN PRIVATE KEY-----") {
        "pem"
    } else {
        "der"
    };
    match chosen_format {
        "pem" => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| Error::InvalidEncoding("pkcs8 PEM must be UTF-8"))?;
            noxtls_private_key_pem_to_der_pkcs8(text)
        }
        "der" => Ok(bytes),
        _ => Err(Error::StateError("unsupported pkcs8 inform")),
    }
}

/// Writes PKCS#8 DER bytes in PEM or DER output form.
/// # Arguments
///
/// * `pkcs8_der` — `pkcs8_der: &[u8]`.
/// * `output_path` — `output_path: Option<&str>`.
/// * `output_format` — `output_format: &str`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn emit_pkcs8_output(
    pkcs8_der: &[u8],
    output_path: Option<&str>,
    output_format: &str,
) -> Result<()> {
    match output_format {
        "pem" => {
            let pem = noxtls_private_key_der_to_pem_pkcs8(pkcs8_der)?;
            if let Some(path) = output_path {
                fs::write(path, pem)
                    .map_err(|_| Error::StateError("failed to write pkcs8 PEM output"))?;
            } else {
                println!("{pem}");
            }
            Ok(())
        }
        "der" => {
            if let Some(path) = output_path {
                fs::write(path, pkcs8_der)
                    .map_err(|_| Error::StateError("failed to write pkcs8 DER output"))?;
            } else {
                println!("{}", to_hex(pkcs8_der));
            }
            Ok(())
        }
        _ => Err(Error::StateError("unsupported pkcs8 outform")),
    }
}

/// Checks PKCS#8 algorithm OID against expected CLI algorithm name.
/// # Arguments
///
/// * `expected_algorithm` — `expected_algorithm: &str`.
/// * `oid` — `oid: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn validate_pkcs8_algorithm(expected_algorithm: &str, oid: &[u8]) -> Result<()> {
    let expected_oid = match expected_algorithm {
        "p256" => OID_EC_PUBLIC_KEY,
        "x25519" => OID_X25519,
        "x448" => OID_X448,
        _ => return Err(Error::StateError("unsupported pkcs8 algorithm")),
    };
    if oid != expected_oid {
        return Err(Error::StateError(
            "pkcs8 key algorithm does not match expected algorithm",
        ));
    }
    Ok(())
}

/// Encodes CLI key hex bytes into PKCS#8 DER by algorithm.
/// # Arguments
///
/// * `algorithm` — `algorithm: &str`.
/// * `key_hex` — `key_hex: &str`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_pkcs8_private_key_der(algorithm: &str, key_hex: &str) -> Result<Vec<u8>> {
    match algorithm {
        "p256" => {
            let scalar =
                parse_fixed_hex::<32>(key_hex, "p256 private key must be 32 bytes of hex")?;
            let private = P256PrivateKey::from_bytes(scalar)?;
            let public = private.public_key()?;
            encode_p256_pkcs8_private_key(scalar, &public)
        }
        "x25519" => {
            let scalar =
                parse_fixed_hex::<32>(key_hex, "x25519 private key must be 32 bytes of hex")?;
            encode_xdh_pkcs8_private_key(&scalar, OID_X25519)
        }
        "x448" => {
            let scalar =
                parse_fixed_hex::<56>(key_hex, "x448 private key must be 56 bytes of hex")?;
            encode_xdh_pkcs8_private_key(&scalar, OID_X448)
        }
        _ => Err(Error::StateError("unsupported pkcs8 algorithm")),
    }
}

/// Extracts private key payload from parsed PKCS#8 info and returns lowercase hex.
/// # Arguments
///
/// * `algorithm_oid` — `algorithm_oid: &[u8]`.
/// * `private_key_field` — `private_key_field: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn extract_private_scalar_hex_payload(
    algorithm_oid: &[u8],
    private_key_field: &[u8],
) -> Result<String> {
    if algorithm_oid == OID_EC_PUBLIC_KEY {
        let scalar = parse_p256_scalar_from_sec1(private_key_field)?;
        return Ok(to_hex(&scalar));
    }
    if algorithm_oid == OID_X25519 {
        let bytes = parse_rfc8410_private_key_bytes(private_key_field, 32)?;
        return Ok(to_hex(&bytes));
    }
    if algorithm_oid == OID_X448 {
        let bytes = parse_rfc8410_private_key_bytes(private_key_field, 56)?;
        return Ok(to_hex(&bytes));
    }
    Err(Error::UnsupportedFeature(
        "unsupported pkcs8 private key algorithm",
    ))
}

/// Parses 32-byte P-256 scalar from SEC1 ECPrivateKey DER.
/// # Arguments
///
/// * `sec1_der` — `sec1_der: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn parse_p256_scalar_from_sec1(sec1_der: &[u8]) -> Result<[u8; 32]> {
    let (sequence, tail) = noxtls_parse_der_node(sec1_der)?;
    if sequence.tag != 0x30 || !tail.is_empty() {
        return Err(Error::ParseFailure("invalid sec1 private key sequence"));
    }
    let (version, rest) = noxtls_parse_der_node(sequence.body)?;
    if version.tag != 0x02 || version.body != [0x01] {
        return Err(Error::ParseFailure("invalid sec1 private key version"));
    }
    let (private_key, _remaining) = noxtls_parse_der_node(rest)?;
    if private_key.tag != 0x04 || private_key.body.len() != 32 {
        return Err(Error::ParseFailure("invalid sec1 p256 private scalar"));
    }
    let mut scalar = [0_u8; 32];
    scalar.copy_from_slice(private_key.body);
    Ok(scalar)
}

/// Parses RFC 8410 private key payload bytes from PKCS#8 privateKey field.
/// # Arguments
///
/// * `input` — `input: &[u8]`.
/// * `expected_len` — `expected_len: usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn parse_rfc8410_private_key_bytes(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if input.len() == expected_len {
        return Ok(input.to_vec());
    }
    let (inner, tail) = noxtls_parse_der_node(input)?;
    if inner.tag != 0x04 || !tail.is_empty() || inner.body.len() != expected_len {
        return Err(Error::ParseFailure("invalid RFC8410 private key payload"));
    }
    Ok(inner.body.to_vec())
}

/// Encodes P-256 private scalar + public key into PKCS#8 DER.
/// # Arguments
///
/// * `scalar` — `scalar: [u8; 32]`.
/// * `public` — `public: &P256PublicKey`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_p256_pkcs8_private_key(scalar: [u8; 32], public: &P256PublicKey) -> Result<Vec<u8>> {
    let public_uncompressed = public.to_uncompressed()?;
    let sec1 = encode_p256_sec1_private_key(&scalar, &public_uncompressed)?;
    let algorithm_identifier = encode_der_sequence(
        &[
            encode_der_oid(OID_EC_PUBLIC_KEY)?,
            encode_der_oid(OID_PRIME256V1)?,
        ]
        .concat(),
    )?;
    let private_key = encode_der_octet_string(&sec1)?;
    encode_der_sequence(
        &[
            encode_der_integer(&[0x00])?,
            algorithm_identifier,
            private_key,
        ]
        .concat(),
    )
}

/// Encodes SEC1 ECPrivateKey DER including curve OID and public key.
/// # Arguments
///
/// * `scalar` — `scalar: &[u8; 32]`.
/// * `public_uncompressed` — `public_uncompressed: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_p256_sec1_private_key(scalar: &[u8; 32], public_uncompressed: &[u8]) -> Result<Vec<u8>> {
    let version = encode_der_integer(&[0x01])?;
    let private_key = encode_der_octet_string(scalar)?;
    let curve_oid = encode_der_oid(OID_PRIME256V1)?;
    let parameters = encode_der_context_explicit(0xA0, &curve_oid)?;
    let public_key_bits = encode_der_bit_string(public_uncompressed)?;
    let public_key = encode_der_context_explicit(0xA1, &public_key_bits)?;
    encode_der_sequence(&[version, private_key, parameters, public_key].concat())
}

/// Encodes X25519/X448 private key into PKCS#8 DER.
/// # Arguments
///
/// * `scalar` — `scalar: &[u8]`.
/// * `algorithm_oid` — `algorithm_oid: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_xdh_pkcs8_private_key(scalar: &[u8], algorithm_oid: &[u8]) -> Result<Vec<u8>> {
    let algorithm_identifier = encode_der_sequence(&encode_der_oid(algorithm_oid)?)?;
    let private_octets = encode_der_octet_string(scalar)?;
    let private_key = encode_der_octet_string(&private_octets)?;
    encode_der_sequence(
        &[
            encode_der_integer(&[0x00])?,
            algorithm_identifier,
            private_key,
        ]
        .concat(),
    )
}

/// Encodes DER INTEGER with positive-sign prefix rules.
/// # Arguments
///
/// * `value` — `value: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_integer(value: &[u8]) -> Result<Vec<u8>> {
    let mut body = if value.is_empty() {
        vec![0x00]
    } else {
        value.to_vec()
    };
    while body.len() > 1 && body[0] == 0x00 {
        body.remove(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00);
    }
    encode_der_node(0x02, &body)
}

/// Encodes DER OBJECT IDENTIFIER from raw OID bytes.
/// # Arguments
///
/// * `oid` — `oid: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_oid(oid: &[u8]) -> Result<Vec<u8>> {
    encode_der_node(0x06, oid)
}

/// Encodes DER OCTET STRING from raw payload bytes.
/// # Arguments
///
/// * `body` — `body: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_octet_string(body: &[u8]) -> Result<Vec<u8>> {
    encode_der_node(0x04, body)
}

/// Encodes DER BIT STRING with zero unused bits.
/// # Arguments
///
/// * `body` — `body: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_bit_string(body: &[u8]) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(body.len() + 1);
    payload.push(0x00);
    payload.extend_from_slice(body);
    encode_der_node(0x03, &payload)
}

/// Encodes explicit context-specific DER wrapper with provided tag.
/// # Arguments
///
/// * `tag` — `tag: u8`.
/// * `body` — `body: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_context_explicit(tag: u8, body: &[u8]) -> Result<Vec<u8>> {
    encode_der_node(tag, body)
}

/// Encodes DER SEQUENCE from concatenated child encodings.
/// # Arguments
///
/// * `children` — `children: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_sequence(children: &[u8]) -> Result<Vec<u8>> {
    encode_der_node(0x30, children)
}

/// Encodes one DER TLV node from tag and body bytes.
/// # Arguments
///
/// * `tag` — `tag: u8`.
/// * `body` — `body: &[u8]`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_node(tag: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_der_len(body.len())?);
    out.extend_from_slice(body);
    Ok(out)
}

/// Encodes DER length bytes in short/long form.
/// # Arguments
///
/// * `length` — `length: usize`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn encode_der_len(length: usize) -> Result<Vec<u8>> {
    if length < 128 {
        return Ok(vec![length as u8]);
    }
    let length_u32 =
        u32::try_from(length).map_err(|_| Error::InvalidLength("der length too large"))?;
    let bytes = length_u32.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::InvalidLength("der length must be non-zero"))?;
    let content = &bytes[first_nonzero..];
    let mut out = Vec::with_capacity(content.len() + 1);
    out.push(0x80 | (content.len() as u8));
    out.extend_from_slice(content);
    Ok(out)
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_X25519: &[u8] = &[0x2B, 0x65, 0x6E];
const OID_X448: &[u8] = &[0x2B, 0x65, 0x6F];

/// Collects best-effort local entropy material for non-deterministic CLI mode.
/// # Arguments
///
/// _(none)_ — See `argv` parsing and flags in the function body.
///
/// # Returns
///
/// The value described by the function signature return type.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn collect_best_effort_entropy() -> Vec<u8> {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |duration| duration.as_nanos());
    let mut seed = format!(
        "noxtls-rs:{}:{}:{}",
        now_nanos,
        std::process::id(),
        std::env::args().collect::<Vec<_>>().join("|")
    )
    .into_bytes();
    seed.extend_from_slice(b"noxtls-cli-best-effort-entropy");
    seed
}

/// Parses a fixed-size byte array from hex.
/// # Arguments
///
/// _(none)_ — See `argv` parsing and flags in the function body.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn parse_fixed_hex<const N: usize>(value: &str, error_message: &'static str) -> Result<[u8; N]> {
    let decoded = noxtls_decode_hex(value)?;
    if decoded.len() != N {
        return Err(Error::InvalidLength(error_message));
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Tries DRBG draws until one produces a valid P-256 private scalar.
/// # Arguments
///
/// * `drbg` — `drbg: &mut HmacDrbgSha256`.
///
/// # Returns
///
/// On success, the `Ok` payload from this helper; see the function body for concrete values.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn generate_p256_private_key(drbg: &mut HmacDrbgSha256) -> Result<GeneratedP256PrivateKey> {
    for _ in 0..64 {
        let bytes = drbg.generate(32, b"p256_private_scalar")?;
        let mut scalar = [0_u8; 32];
        scalar.copy_from_slice(&bytes);
        if let Ok(private) = P256PrivateKey::from_bytes(scalar) {
            return Ok(GeneratedP256PrivateKey { private, scalar });
        }
    }
    Err(Error::StateError(
        "failed to generate valid p256 private key",
    ))
}

/// Bundles P-256 private key material and scalar bytes for CLI output.
struct GeneratedP256PrivateKey {
    private: P256PrivateKey,
    scalar: [u8; 32],
}

impl GeneratedP256PrivateKey {
    // Returns the corresponding P-256 public key.
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// On success, the `Ok` payload from this helper; see the function body for concrete values.
    ///
    /// # Errors
    ///
    /// Returns [`noxtls_core::Error`] when parsing, I/O, or crypto operations fail; see the function body for specific variants.
    ///
    /// # Panics
    ///
    /// This function does not panic unless otherwise noted in the body.
    ///
    fn public_key(&self) -> Result<P256PublicKey> {
        self.private.public_key()
    }

    // Returns the private scalar bytes.
    /// # Arguments
    ///
    /// * `&self` — `&self`.
    ///
    /// # Returns
    ///
    /// The value described by the function signature return type.
    ///
    /// # Panics
    ///
    /// This function does not panic unless otherwise noted in the body.
    ///
    fn private_scalar(&self) -> [u8; 32] {
        self.scalar
    }
}

/// Encodes bytes into lowercase hex.
/// # Arguments
///
/// * `bytes` — `bytes: &[u8]`.
///
/// # Returns
///
/// The value described by the function signature return type.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex((byte >> 4) & 0x0f));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

/// Converts a nibble into lowercase hex.
/// # Arguments
///
/// * `nibble` — `nibble: u8`.
///
/// # Returns
///
/// The value described by the function signature return type.
///
/// # Panics
///
/// This function does not panic unless otherwise noted in the body.
///
fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + (nibble - 10)) as char,
    }
}

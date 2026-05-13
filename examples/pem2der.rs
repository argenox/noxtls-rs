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

//! Convert a certificate file between PEM and DER encodings (`cargo run -p noxtls --example pem2der -- ...`).

use std::{fs, path::Path};

use noxtls_core::{Error, Result};
use noxtls_x509::{noxtls_certificate_der_to_pem, noxtls_certificate_pem_to_der};

/// Converts a certificate file between PEM and DER encodings based on the input wire format.
///
/// # Arguments
///
/// * `argv[1]` — Input certificate path (`.pem` or raw DER).
/// * `argv[2]` — Optional explicit output path; otherwise the extension is swapped to `.der` or `.pem`.
///
/// # Returns
///
/// `Ok(())` after writing the converted file, or an error on I/O or parse failures.
///
/// # Errors
///
/// Returns [`noxtls_core::Error`] when arguments are missing, files cannot be read or written, or PEM/DER conversion fails.
///
/// # Panics
///
/// This function does not panic.
fn main() -> Result<()> {
    let (input_path, output_path_override) = read_paths_from_args()?;
    let input =
        fs::read(&input_path).map_err(|_| Error::StateError("failed to read input file"))?;

    if input.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let pem = std::str::from_utf8(&input)
            .map_err(|_| Error::InvalidEncoding("certificate PEM must be UTF-8"))?;
        let der = noxtls_certificate_pem_to_der(pem)?;
        let output_path =
            output_path_override.unwrap_or_else(|| with_extension(&input_path, "der"));
        fs::write(&output_path, der)
            .map_err(|_| Error::StateError("failed to write DER output file"))?;
        println!("converted=noxtls_certificate_pem_to_der");
        println!("input={input_path}");
        println!("output={output_path}");
    } else {
        let pem = noxtls_certificate_der_to_pem(&input)?;
        let output_path =
            output_path_override.unwrap_or_else(|| with_extension(&input_path, "pem"));
        fs::write(&output_path, pem.as_bytes())
            .map_err(|_| Error::StateError("failed to write PEM output file"))?;
        println!("converted=noxtls_certificate_der_to_pem");
        println!("input={input_path}");
        println!("output={output_path}");
    }
    Ok(())
}

/// Reads CLI arguments as `<input-path>` and optional `[output-path]`.
///
/// # Arguments
///
/// _(none)_ — Reads `std::env::args()`.
///
/// # Returns
///
/// On success, the input path and optional output override.
///
/// # Errors
///
/// Returns [`Error::StateError`] when the input path is missing.
///
/// # Panics
///
/// This function does not panic.
fn read_paths_from_args() -> Result<(String, Option<String>)> {
    let mut args = std::env::args().skip(1);
    let input_path = args.next().ok_or_else(|| {
        eprintln!(
            "usage: cargo run -p noxtls --example pem2der -- <input.pem|input.der> [output-file]"
        );
        Error::StateError("missing input path argument")
    })?;
    let output_path = args.next();
    Ok((input_path, output_path))
}

/// Replaces the file extension for default output naming.
///
/// # Arguments
///
/// * `path` — Original input path string.
/// * `extension` — New extension without a leading dot.
///
/// # Returns
///
/// A lossy path string suitable for `fs::write`.
///
/// # Panics
///
/// This function does not panic.
fn with_extension(path: &str, extension: &str) -> String {
    let mut output = Path::new(path).to_path_buf();
    output.set_extension(extension);
    output.to_string_lossy().into_owned()
}

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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
mod ffi;
mod provider;

pub use error::{noxtls_map_status_to_result, noxtls_normalize_psa_status, PsaError, PsaResultCode};
pub use ffi::FfiPsaBackend;
pub use provider::{
    AeadEncryptRequest, AeadEncryptResponse, KeyDecryptRequest, KeyDeriveRequest, KeySignRequest,
    PsaCryptoBackend, PsaDecryptAlgorithm, PsaDeriveAlgorithm, PsaExternalKeyHandle, PsaProvider,
    PsaSignAlgorithm, PsaSoftwareBackend, PsaSoftwareProvider,
};

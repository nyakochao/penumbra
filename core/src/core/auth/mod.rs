/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
#[cfg(not(feature = "no_localslakeyring"))]
mod keys;
#[cfg(not(feature = "no_localslakeyring"))]
pub mod local_keyring;
mod sla;

pub use sla::{AuthManager, SignData, SignPurpose, SignRequest, Signer};

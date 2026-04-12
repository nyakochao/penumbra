/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use anyhow::Error as AnyError;
use penumbra::error::Error as PenumbraError;

// Ugly hack to convert Penumbra Error into anyhow::Error.
// This is needed because PenumbraError does not implement std::error::Error,
#[derive(Debug)]
pub struct PError(pub PenumbraError);

impl From<PenumbraError> for PError {
    fn from(err: PenumbraError) -> Self {
        PError(err)
    }
}

impl From<PError> for AnyError {
    fn from(err: PError) -> Self {
        AnyError::new(err.0)
    }
}

/*
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy

    Derived from:
    https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Hardware/seccfg.py
    Original SPDX-License-Identifier: GPL-3.0-or-later
    Original SPDX-FileCopyrightText: 2018–2024 bkerler

    This file remains under the GPL-3.0-or-later license.
    However, as part of a larger project licensed under the AGPL-3.0-or-later,
    the combined work is subject to the networking terms of the AGPL-3.0-or-later,
    as for term 13 of the GPL-3.0-or-later license.
*/
use sha2::{Digest, Sha256};
use wincode::{Deserialize, SchemaRead, SchemaWrite};

use crate::error::{Error, Result};

const V4_MAGIC_BEGIN: u32 = 0x4D4D4D4D;
const V4_MAGIC_END: u32 = 0x45454545;

pub enum LockFlag {
    Lock,
    Unlock,
}

#[derive(Clone)]
pub enum SecCfgV4Algo {
    SW,
    HW,
    HWv3,
    HWv4,
}

#[derive(Default, SchemaRead, SchemaWrite)]
pub struct SecCfgV4 {
    start_magic: u32,
    pub seccfg_ver: u32,
    pub seccfg_size: u32,
    pub lock_state: u32,
    pub critical_lock_state: u32,
    pub sboot_runtime: u32,
    end_magic: u32,
    enc_hash: [u8; 32],
    #[wincode(skip)]
    algo: Option<SecCfgV4Algo>,
}

impl SecCfgV4 {
    pub fn new() -> Self {
        SecCfgV4 {
            start_magic: V4_MAGIC_BEGIN,
            seccfg_ver: 4,
            seccfg_size: 20,
            lock_state: 0,
            critical_lock_state: 0,
            sboot_runtime: 0,
            end_magic: V4_MAGIC_END,
            enc_hash: [0u8; 32],
            algo: None,
        }
    }

    pub fn parse_header(data: &[u8]) -> Result<SecCfgV4> {
        if data.len() < 0x20 {
            return Err(Error::penumbra("SecCfg v4 data too short"));
        }

        Ok(SecCfgV4::deserialize(data)?)
    }

    pub fn get_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(V4_MAGIC_BEGIN.to_le_bytes());
        hasher.update(self.seccfg_ver.to_le_bytes());
        hasher.update(self.seccfg_size.to_le_bytes());
        hasher.update(self.lock_state.to_le_bytes());
        hasher.update(self.critical_lock_state.to_le_bytes());
        hasher.update(self.sboot_runtime.to_le_bytes());
        hasher.update(V4_MAGIC_END.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn get_algo(&self) -> Option<SecCfgV4Algo> {
        self.algo.clone()
    }

    pub fn set_algo(&mut self, algo: SecCfgV4Algo) {
        self.algo = Some(algo);
    }

    pub fn set_encrypted_hash(&mut self, enc_hash: [u8; 32]) {
        self.enc_hash = enc_hash;
    }

    pub fn get_encrypted_hash(&self) -> [u8; 32] {
        self.enc_hash
    }

    pub fn set_lock_state(&mut self, lock_flag: LockFlag) {
        match lock_flag {
            LockFlag::Lock => {
                self.lock_state = 4;
                self.critical_lock_state = 1;
            }
            LockFlag::Unlock => {
                self.lock_state = 3;
                self.critical_lock_state = 0;
            }
        }
    }

    pub fn create(&mut self) -> Result<[u8; 512]> {
        let mut seccfg_data = [0u8; 512];

        wincode::serialize_into(&mut seccfg_data[..], self)?;

        Ok(seccfg_data)
    }
}

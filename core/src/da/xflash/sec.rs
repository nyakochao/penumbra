/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::Cursor;

use crate::core::seccfg::{SecCfgV4, SecCfgV4Algo};
use crate::core::storage::Storage;
use crate::da::xflash::exts::sej;
use crate::da::{DownloadProtocol, XFlash};

pub fn parse_seccfg(xflash: &mut XFlash) -> Option<SecCfgV4> {
    let seccfg = xflash.dev_info.get_partition("seccfg")?;
    let section = xflash.get_storage()?.get_user_part();

    let progress = |_, _| {};

    // We only need the header and padding, which is 200 bytes
    let mut seccfg_header = Vec::with_capacity(200);
    let mut cursor = Cursor::new(&mut seccfg_header);

    xflash.read_flash(seccfg.address, 200, section, progress, &mut cursor).ok()?;

    let mut parsed_seccfg = SecCfgV4::parse_header(&seccfg_header).ok()?;
    let hash = parsed_seccfg.get_encrypted_hash();
    for algo in [SecCfgV4Algo::SW, SecCfgV4Algo::HWv3, SecCfgV4Algo::HWv4, SecCfgV4Algo::HW] {
        let dec_hash = match algo {
            SecCfgV4Algo::SW => sej(xflash, &hash, false, false, false, false).ok()?,
            SecCfgV4Algo::HWv3 => sej(xflash, &hash, false, true, true, false).ok()?,
            SecCfgV4Algo::HWv4 => sej(xflash, &hash, false, false, true, false).ok()?,
            SecCfgV4Algo::HW => sej(xflash, &hash, false, false, true, true).ok()?,
        };
        if dec_hash == parsed_seccfg.get_hash() {
            parsed_seccfg.set_algo(algo);
            return Some(parsed_seccfg);
        }
    }

    None
}

pub fn write_seccfg(xflash: &mut XFlash, seccfg: &mut SecCfgV4) -> Option<[u8; 512]> {
    let seccfg_part = xflash.dev_info.get_partition("seccfg")?;
    let section = xflash.get_storage()?.get_user_part();

    let enc_hash = match seccfg.get_algo() {
        Some(SecCfgV4Algo::SW) => {
            sej(xflash, &seccfg.get_hash(), true, false, false, false).ok()?
        }
        Some(SecCfgV4Algo::HW) => sej(xflash, &seccfg.get_hash(), true, false, true, true).ok()?,
        Some(SecCfgV4Algo::HWv3) => {
            sej(xflash, &seccfg.get_hash(), true, true, true, false).ok()?
        }
        Some(SecCfgV4Algo::HWv4) => {
            sej(xflash, &seccfg.get_hash(), true, false, true, false).ok()?
        }
        _ => return None,
    };

    seccfg.set_encrypted_hash(enc_hash.try_into().unwrap_or([0u8; 32]));
    let seccfg_data = seccfg.create().ok()?;

    let progress = |_, _| {};
    let mut cursor = Cursor::new(&seccfg_data);

    xflash
        .write_flash(seccfg_part.address, seccfg_data.len(), &mut cursor, section, progress)
        .ok()?;

    Some(seccfg_data)
}

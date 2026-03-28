/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::io::Cursor;

use crate::core::seccfg::{SecCfgV4, SecCfgV4Algo};
use crate::da::xml::exts::sej;
use crate::da::{DownloadProtocol, Xml};

pub async fn parse_seccfg(xml: &mut Xml) -> Option<SecCfgV4> {
    let seccfg = xml.dev_info.get_partition("seccfg").await?;
    let mut progress = |_, _| {};

    let mut seccfg_header = Vec::with_capacity(seccfg.size);
    let mut cursor = Cursor::new(&mut seccfg_header);

    xml.upload("seccfg".to_string(), &mut cursor, &mut progress).await.ok()?;

    // Cut to 200 bytes
    seccfg_header.truncate(200);

    let mut parsed_seccfg = SecCfgV4::parse_header(&seccfg_header).ok()?;
    let hash = parsed_seccfg.get_encrypted_hash();
    for algo in [SecCfgV4Algo::SW, SecCfgV4Algo::HW, SecCfgV4Algo::HWv3, SecCfgV4Algo::HWv4] {
        let dec_hash = match algo {
            SecCfgV4Algo::SW => sej(xml, &hash, false, false, false, false).await.ok()?,
            SecCfgV4Algo::HW => sej(xml, &hash, false, false, true, true).await.ok()?,
            SecCfgV4Algo::HWv3 => sej(xml, &hash, false, true, true, false).await.ok()?,
            SecCfgV4Algo::HWv4 => sej(xml, &hash, false, false, true, false).await.ok()?,
        };
        if dec_hash == parsed_seccfg.get_hash() {
            parsed_seccfg.set_algo(algo);
            return Some(parsed_seccfg);
        }
    }

    None
}

pub async fn write_seccfg(xml: &mut Xml, seccfg: &mut SecCfgV4) -> Option<Vec<u8>> {
    let enc_hash = match seccfg.get_algo() {
        Some(SecCfgV4Algo::SW) => {
            sej(xml, &seccfg.get_hash(), true, false, false, false).await.ok()?
        }
        Some(SecCfgV4Algo::HW) => {
            sej(xml, &seccfg.get_hash(), true, false, true, true).await.ok()?
        }
        Some(SecCfgV4Algo::HWv3) => {
            sej(xml, &seccfg.get_hash(), true, true, true, false).await.ok()?
        }
        Some(SecCfgV4Algo::HWv4) => {
            sej(xml, &seccfg.get_hash(), true, false, true, false).await.ok()?
        }
        _ => return None,
    };

    seccfg.set_encrypted_hash(enc_hash);
    let seccfg_data = seccfg.create();

    let mut progress = |_, _| {};
    let mut cursor = Cursor::new(&seccfg_data);

    xml.download("seccfg".to_string(), 200, &mut cursor, &mut progress).await.ok()?;

    Some(seccfg_data)
}

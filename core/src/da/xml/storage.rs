/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::debug;

use crate::core::storage::Storage;
use crate::core::storage::emmc::EmmcStorage;
use crate::core::storage::ufs::UfsStorage;
use crate::da::xml::Xml;
use crate::da::xml::cmds::{GetHwInfo, XmlCmdLifetime};
use crate::utilities::xml::get_tag;

pub fn detect_storage(xml: &mut Xml) -> Option<Arc<dyn Storage>> {
    xmlcmd!(xml, GetHwInfo, "0").ok();

    let reponse = xml.get_upload_file_resp().ok()?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).ok()?;
    let storage_str: String = get_tag(&reponse, "storage").ok()?;

    match storage_str.as_str() {
        "EMMC" => {
            debug!("eMMC storage detected.");
            if let Ok(storage) = EmmcStorage::from_xml_response(&reponse) {
                return Some(Arc::new(storage));
            }
        }
        "UFS" => {
            debug!("UFS storage detected.");
            if let Ok(storage) = UfsStorage::from_xml_response(&reponse) {
                return Some(Arc::new(storage));
            }
        }
        _ => {}
    }

    None
}

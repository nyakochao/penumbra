/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::{BufReader, Cursor, Read, Write};

use log::{debug, error, info};

use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::devinfo::DeviceInfo;
use crate::core::seccfg::LockFlag;
use crate::core::storage::{
    Gpt,
    Partition,
    PartitionKind,
    RpmbRegion,
    Storage,
    StorageKind,
    StorageType,
};
use crate::da::protocol::{BootMode, DownloadProtocol};
use crate::da::xml::cmds::{
    BootTo,
    HOST_CMDS,
    HostSupportedCommands,
    NotifyInitHw,
    Reboot,
    SetBootMode,
    XmlCmdLifetime,
};
use crate::da::xml::flash;
#[cfg(not(feature = "no_exploits"))]
use crate::da::xml::sec::{parse_seccfg, write_seccfg};
#[cfg(not(feature = "no_exploits"))]
use crate::da::xml::{exts, patch};
use crate::da::{DA, DAEntryRegion, Xml};
use crate::error::{Error, Result};
use crate::exploit;
#[cfg(not(feature = "no_exploits"))]
use crate::exploit::{Carbonara, Exploit, HeapBait};

impl DownloadProtocol for Xml {
    fn upload_da(&mut self) -> Result<bool> {
        let da1 = self.da.get_da1().ok_or_else(|| Error::penumbra("DA1 region not found"))?;

        self.upload_stage1(da1.addr, da1.length, da1.data.clone(), da1.sig_len)
            .map_err(|e| Error::proto(format!("Failed to upload XML DA1: {e}")))?;

        exploit!(Carbonara, self);

        let (da2_addr, da2_data) = {
            let da2 = self.da.get_da2().ok_or_else(|| Error::penumbra("DA2 region not found"))?;
            let sig_len = da2.sig_len as usize;
            let data = da2.data[..da2.data.len().saturating_sub(sig_len)].to_vec();
            (da2.addr, data)
        };

        info!("Uploading and booting to XML DA2...");
        if let Err(e) = self.boot_to(da2_addr, &da2_data) {
            self.reboot(BootMode::Normal).ok();
            return Err(Error::proto(format!("Failed to upload XML DA2: {e}")));
        }

        info!("Successfully uploaded and booted to XML DA2");

        exploit!(HeapBait, self);

        // These may fail on some devices
        xmlcmd_e!(self, HostSupportedCommands, HOST_CMDS).ok();

        xmlcmd!(self, NotifyInitHw)?;
        let mut mock_progress = |_, _| {};
        self.progress_report(&mut mock_progress)?;
        self.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

        self.handle_sla()?;

        #[cfg(not(feature = "no_exploits"))]
        self.boot_extensions()?;

        Ok(true)
    }

    fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool> {
        xmlcmd!(self, BootTo, addr, addr, 0x0u64, data.len() as u64)?;

        let reader = BufReader::new(Cursor::new(data));
        let mut progress = |_, _| {};
        self.download_file(data.len(), reader, &mut progress)?;

        self.lifetime_ack(XmlCmdLifetime::CmdEnd)?;
        Ok(true)
    }

    fn send(&mut self, data: &[u8]) -> Result<bool> {
        self.send_data(&[data])
    }

    fn send_data(&mut self, data: &[&[u8]]) -> Result<bool> {
        let max_chunk_size = self.write_packet_length.unwrap_or(0x8000);

        for param in data {
            let hdr = self.generate_header(param);
            self.conn.write(&hdr)?;

            let mut pos = 0;
            while pos < param.len() {
                let end = (pos + max_chunk_size).min(param.len());
                let chunk = &param[pos..end];
                debug!("[TX] Sending chunk (0x{:X} bytes)", chunk.len());
                self.conn.write(chunk)?;
                pos = end;
            }

            debug!("[TX] Completed sending 0x{:X} bytes", param.len());
        }

        Ok(true)
    }

    /// We don't need it for XML DA
    fn get_status(&mut self) -> Result<u32> {
        Ok(0)
    }

    fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down device...");

        xmlcmd_e!(self, Reboot, "IMMEDIATE".to_string())
            .map(|_| ())
            .map_err(|e| Error::proto(format!("Failed to shutdown device: {e}")))
    }

    fn reboot(&mut self, bootmode: BootMode) -> Result<()> {
        info!("Rebooting device into {:?} mode...", bootmode);
        match bootmode {
            BootMode::Normal | BootMode::HomeScreen => self.shutdown()?,
            mode => {
                let xml_mode = mode.to_text().unwrap();
                xmlcmd_e!(self, SetBootMode, xml_mode.to_string(), "USB", "ON", "ON")?;
            }
        }

        Ok(())
    }

    fn read_flash<W, F>(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: F,
        writer: W,
    ) -> Result<()>
    where
        W: Write + Send,
        F: FnMut(usize, usize) + Send,
    {
        flash::read_flash(self, addr, size, section, writer, progress)
    }

    fn write_flash<R, F>(
        &mut self,
        addr: u64,
        size: usize,
        reader: R,
        section: PartitionKind,
        progress: F,
    ) -> Result<()>
    where
        R: Read + Send,
        F: FnMut(usize, usize) + Send,
    {
        flash::write_flash(self, addr, size, section, reader, progress)
    }

    fn erase_flash<F>(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize) + Send,
    {
        flash::erase_flash(self, addr, size, section, progress)
    }

    fn download<R, F>(
        &mut self,
        part_name: String,
        size: usize,
        mut reader: R,
        mut progress: F,
    ) -> Result<()>
    where
        R: Read + Send,
        F: FnMut(usize, usize) + Send,
    {
        flash::download(self, part_name, size, &mut reader, &mut progress)
    }

    fn upload<W, F>(&mut self, part_name: String, mut writer: W, mut progress: F) -> Result<()>
    where
        W: Write + Send,
        F: FnMut(usize, usize) + Send,
    {
        flash::upload(self, part_name, &mut writer, &mut progress)
    }

    fn format<F>(&mut self, part_name: String, mut progress: F) -> Result<()>
    where
        F: FnMut(usize, usize) + Send,
    {
        flash::format(self, part_name, &mut progress)
    }

    fn read32(&mut self, _addr: u32) -> Result<u32> {
        todo!()
    }

    fn write32(&mut self, _addr: u32, _value: u32) -> Result<()> {
        todo!()
    }

    fn get_usb_speed(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()> {
        self.conn.connection_type = conn_type;
        Ok(())
    }

    fn get_storage(&mut self) -> Option<StorageKind> {
        self.get_or_detect_storage()
    }

    fn get_storage_type(&mut self) -> StorageType {
        self.get_or_detect_storage().map_or(StorageType::Unknown, |s| s.kind())
    }

    fn get_partitions(&mut self) -> Vec<Partition> {
        let storage = match self.get_storage() {
            Some(s) => s,
            None => {
                error!("[Penumbra] Failed to get storage for partition parsing");
                return Vec::new();
            }
        };

        let storage_type = storage.kind();
        let pl_part1 = storage.get_pl_part1();
        let pl_part2 = storage.get_pl_part2();
        let user_part = storage.get_user_part();
        let pl1_size = storage.get_pl1_size() as usize;
        let pl2_size = storage.get_pl2_size() as usize;
        let user_size = storage.get_user_size() as usize;
        let gpt_size = 32 * 1024; // TODO: Change this when adding NAND support and PMT

        let mut partitions = vec![
            Partition::new("preloader", pl1_size, 0, pl_part1),
            Partition::new("preloader_backup", pl2_size, 0, pl_part2),
            Partition::new("PGPT", gpt_size, 0, user_part),
        ];

        let sgpt = Partition::new("SGPT", gpt_size, user_size as u64 - gpt_size as u64, user_part);

        let progress = |_, _| {};

        let mut pgpt_data = Vec::new();
        let mut pgpt_cursor = Cursor::new(&mut pgpt_data);
        self.upload("PGPT".into(), &mut pgpt_cursor, progress).ok();
        let parsed_gpt_parts =
            Gpt::parse(&pgpt_data, storage_type).map(|g| g.partitions()).unwrap_or_default();

        let mut gpt_parts = if !parsed_gpt_parts.is_empty() {
            parsed_gpt_parts
        } else {
            let mut sgpt_data = Vec::new();
            let mut sgpt_cursor = Cursor::new(&mut sgpt_data);
            self.upload("SGPT".into(), &mut sgpt_cursor, progress).ok();
            Gpt::parse(&sgpt_data, storage_type).map(|g| g.partitions()).unwrap_or_default()
        };

        partitions.append(&mut gpt_parts);
        partitions.push(sgpt);

        partitions
    }

    #[cfg(not(feature = "no_exploits"))]
    fn set_seccfg_lock_state(&mut self, locked: LockFlag) -> Option<[u8; 512]> {
        let mut seccfg = match parse_seccfg(self) {
            Some(s) => s,
            None => {
                error!("[Penumbra] Failed to parse seccfg, cannot set lock state");
                return None;
            }
        };

        seccfg.set_lock_state(locked);
        write_seccfg(self, &mut seccfg)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn peek<W, F>(&mut self, addr: u32, length: usize, mut writer: W, mut progress: F) -> Result<()>
    where
        W: Write + Send,
        F: FnMut(usize, usize) + Send,
    {
        exts::peek(self, addr, length, &mut writer, &mut progress)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn poke<R, F>(&mut self, addr: u32, length: usize, mut reader: R, mut progress: F) -> Result<()>
    where
        R: Read + Send,
        F: FnMut(usize, usize) + Send,
    {
        exts::poke(self, addr, length, &mut reader, &mut progress)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn read_rpmb<W, F>(
        &mut self,
        region: RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        mut writer: W,
        mut progress: F,
    ) -> Result<()>
    where
        W: Write + Send,
        F: FnMut(usize, usize) + Send,
    {
        exts::read_rpmb(self, region, start_sector, sectors_count, &mut writer, &mut progress)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn write_rpmb<R, F>(
        &mut self,
        region: RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        mut reader: R,
        mut progress: F,
    ) -> Result<()>
    where
        R: Read + Send,
        F: FnMut(usize, usize) + Send,
    {
        exts::write_rpmb(self, region, start_sector, sectors_count, &mut reader, &mut progress)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn auth_rpmb(&mut self, region: RpmbRegion, key: &[u8]) -> Result<()> {
        exts::auth_rpmb(self, region, key)
    }

    #[cfg(not(feature = "no_exploits"))]
    fn patch_da(&mut self) -> Option<DA> {
        patch::patch_da(self).ok()
    }

    #[cfg(not(feature = "no_exploits"))]
    fn patch_da1(&mut self) -> Option<DAEntryRegion> {
        patch::patch_da1(self).ok()
    }

    #[cfg(not(feature = "no_exploits"))]
    fn patch_da2(&mut self) -> Option<DAEntryRegion> {
        patch::patch_da2(self).ok()
    }

    fn get_devinfo(&self) -> DeviceInfo {
        self.dev_info.clone()
    }

    fn get_da(&self) -> &DA {
        &self.da
    }
}

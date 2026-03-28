/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use downcast_rs::{DowncastSend, impl_downcast};
use enum_dispatch::enum_dispatch;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::DeviceLog;
use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::chip::ChipInfo;
use crate::core::devinfo::DeviceInfo;
use crate::core::seccfg::LockFlag;
use crate::core::storage::{Partition, PartitionKind, RpmbRegion, Storage, StorageType};
use crate::da::{DA, DAEntryRegion, XFlash, Xml};
use crate::error::Result;

/// MAGIC value for V5/V6 packets.
pub const MAGIC: u32 = 0xFEEEEEEF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Normal,
    HomeScreen,
    Fastboot,
    Test,
    Meta,
}

impl BootMode {
    pub fn to_text(&self) -> Option<&'static str> {
        match self {
            BootMode::Fastboot => Some("FASTBOOT"),
            BootMode::Meta => Some("META"),
            BootMode::Test => Some("ANDROID-TEST-MODE"),
            BootMode::Normal | BootMode::HomeScreen => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DataType {
    Flow = 0x1,
    Message = 0x2,
}

impl DataType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x1 => Some(DataType::Flow),
            0x2 => Some(DataType::Message),
            _ => None,
        }
    }
}

/// 12 byte packet header shared by all packet types.
///
/// Format:
/// ```text
/// [0..4]   magic      (must be 0xFEEEEEEF)
/// [4..8]   data_type  (1 = Flow, 2 = Message)
/// [8..12]  length     (byte count of the payload that follows)
/// ```
///
/// For `Message` packets, the payload starts with a 4 byte priority
/// field followed by the actual message body.
/// The length of a `Message` packet also includes the 4 byte from priority.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub magic: u32,
    pub data_type: DataType,
    pub length: u32,
}

impl PacketHeader {
    pub const SIZE: usize = 12;

    pub fn new(length: u32) -> Self {
        Self { magic: MAGIC, data_type: DataType::Flow, length }
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        if magic != MAGIC {
            return None;
        }
        let data_type = DataType::from_u32(u32::from_le_bytes(raw[4..8].try_into().unwrap()))?;
        let length = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        Some(Self { magic, data_type, length })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&(self.data_type as u32).to_le_bytes());
        buf[8..12].copy_from_slice(&self.length.to_le_bytes());
        buf
    }
}

pub struct DAProtocolParams {
    pub da: DA,
    pub devinfo: DeviceInfo,
    pub device_log: DeviceLog,
    pub verbose: bool,
    pub usb_log_channel: bool,
    pub preloader: Option<Vec<u8>>, // TODO: Switch to Preloader type
}

#[enum_dispatch(DownloadProtocol)]
pub enum DAProtocol {
    V5(XFlash),
    V6(Xml),
}

#[async_trait::async_trait]
#[enum_dispatch]
pub trait DownloadProtocol: DowncastSend {
    // Main helpers
    async fn upload_da(&mut self) -> Result<bool>;
    async fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool>;
    async fn send(&mut self, data: &[u8]) -> Result<bool>;
    async fn send_data(&mut self, data: &[&[u8]]) -> Result<bool>;
    async fn get_status(&mut self) -> Result<u32>;
    async fn shutdown(&mut self) -> Result<()>;
    async fn reboot(&mut self, bootmode: BootMode) -> Result<()>;
    // FLASH operations
    // fn read_partition(&mut self, name: &str) -> Result<Vec<u8>, Error>;
    async fn read_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<()>;

    async fn write_flash(
        &mut self,
        addr: u64,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn erase_flash(
        &mut self,
        addr: u64,
        size: usize,
        section: PartitionKind,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn download(
        &mut self,
        part_name: String,
        size: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn upload(
        &mut self,
        part_name: String,
        reader: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    async fn format(
        &mut self,
        part_name: String,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    // Memory
    async fn read32(&mut self, addr: u32) -> Result<u32>;
    async fn write32(&mut self, addr: u32, value: u32) -> Result<()>;

    async fn get_usb_speed(&mut self) -> Result<u32>;
    // fn set_usb_speed(&mut self, speed: u32) -> Result<(), Error>;

    // Connection
    fn get_connection(&mut self) -> &mut Connection;
    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()>;

    async fn get_storage(&mut self) -> Option<Arc<dyn Storage>>;
    async fn get_storage_type(&mut self) -> StorageType;
    async fn get_partitions(&mut self) -> Vec<Partition>;

    // DevInfo helpers
    fn get_devinfo(&self) -> &DeviceInfo;
    fn get_da(&self) -> &DA;

    fn chip(&self) -> &'static ChipInfo {
        self.get_devinfo().chip()
    }

    /* EXTENSIONS / EXPLOITS
     * These functions won't be included if the "no_exploits" feature is enabled
     */

    // Sec
    #[cfg(not(feature = "no_exploits"))]
    async fn set_seccfg_lock_state(&mut self, locked: LockFlag) -> Option<Vec<u8>>;

    #[cfg(not(feature = "no_exploits"))]
    async fn peek(
        &mut self,
        addr: u32,
        length: usize,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    #[cfg(not(feature = "no_exploits"))]
    async fn poke(
        &mut self,
        addr: u32,
        length: usize,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    #[cfg(not(feature = "no_exploits"))]
    async fn read_rpmb(
        &mut self,
        region: RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        writer: &mut (dyn AsyncWrite + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    #[cfg(not(feature = "no_exploits"))]
    async fn write_rpmb(
        &mut self,
        region: RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>;

    #[cfg(not(feature = "no_exploits"))]
    async fn auth_rpmb(&mut self, region: RpmbRegion, key: &[u8]) -> Result<()>;

    // DA Patching utils. These *must* be protocol specific, as different protocols
    // have different DA implementations
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da(&mut self) -> Option<DA>;
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da1(&mut self) -> Option<DAEntryRegion>;
    #[cfg(not(feature = "no_exploits"))]
    fn patch_da2(&mut self) -> Option<DAEntryRegion>;
}

impl_downcast!(DownloadProtocol);

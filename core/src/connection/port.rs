/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use std::fmt::Debug;

use crate::connection::backend::*;
use crate::error::Result;

/// List of all ports available for connecting and what mode they refer to.
/// Add more entries here for vendor specific ports
#[rustfmt::skip]
pub const KNOWN_PORTS: &[(u16, u16, ConnectionType)] = &[
    (0x0E8D, 0x0003, ConnectionType::Brom),      // Mediatek USB Port (BROM)
    (0x0E8D, 0x6000, ConnectionType::Preloader), // Mediatek USB Port (Preloader)
    (0x0E8D, 0x2000, ConnectionType::Preloader), // Mediatek USB Port (Preloader)
    (0x0E8D, 0x2001, ConnectionType::Da),        // Mediatek USB Port (DA)
    (0x0E8D, 0x20FF, ConnectionType::Preloader), // Mediatek USB Port (Preloader)
    (0x0E8D, 0x3000, ConnectionType::Preloader), // Mediatek USB Port (Preloader)
    (0x1004, 0x6000, ConnectionType::Preloader), // LG USB Port (Preloader)
    (0x22D9, 0x0006, ConnectionType::Preloader), // OPPO USB Port (Preloader)
    (0x0FCE, 0xF200, ConnectionType::Brom),      // Sony USB Port (BROM)
    (0x0FCE, 0xD1E9, ConnectionType::Brom),      // Sony USB Port (BROM XA1)
    (0x0FCE, 0xD1E2, ConnectionType::Brom),      // Sony USB Port (BROM)
    (0x0FCE, 0xD1EC, ConnectionType::Brom),      // Sony USB Port (BROM L1)
    (0x0FCE, 0xD1DD, ConnectionType::Brom),      // Sony USB Port (BROM F3111)
];

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ConnectionType {
    Brom,
    Preloader,
    Da,
}

pub trait MTKPort: Send + Debug {
    fn open(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;

    fn handshake(&mut self) -> Result<()>;
    fn get_connection_type(&self) -> ConnectionType;
    fn get_baudrate(&self) -> u32;
    fn get_port_name(&self) -> String;

    fn find_device() -> Result<Option<Self>>
    where
        Self: Sized;

    // Only for USB ports
    fn ctrl_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()>;
    fn ctrl_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        len: usize,
    ) -> Result<Vec<u8>>;
}

pub fn find_mtk_port() -> Option<Box<dyn MTKPort>> {
    // Default NUSB backend
    #[cfg(not(any(feature = "libusb", feature = "serial")))]
    let port = UsbMTKPort::find_device();

    // LibUSB backend
    #[cfg(feature = "libusb")]
    let port = UsbMTKPort::find_device();

    // Serial backend, not ideal since some features (i.e. linecoding) aren't available.
    #[cfg(feature = "serial")]
    let port = SerialMTKPort::find_device();

    match port {
        Ok(Some(mut port)) => {
            if port.open().is_ok() {
                Some(Box::new(port))
            } else {
                None
            }
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

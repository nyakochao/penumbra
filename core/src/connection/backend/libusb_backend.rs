/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use std::thread::sleep;
use std::time::Duration;

use log::{debug, info};
use rusb::{Context, Device, DeviceHandle, Direction, Recipient, RequestType, UsbContext};

use crate::connection::port::{ConnectionType, KNOWN_PORTS, MTKPort};
use crate::error::{Error, Result};

#[derive(Debug)]
pub struct UsbMTKPort {
    handle: DeviceHandle<Context>,
    baudrate: u32,
    connection_type: ConnectionType,
    is_open: bool,
    port_name: String,
    in_endpoint: u8,
    out_endpoint: u8,
}

impl UsbMTKPort {
    pub fn new(
        handle: DeviceHandle<Context>,
        connection_type: ConnectionType,
        port_name: String,
        baudrate: u32,
        in_endpoint: u8,
        out_endpoint: u8,
    ) -> Self {
        Self {
            handle,
            baudrate,
            connection_type,
            is_open: false,
            port_name,
            in_endpoint,
            out_endpoint,
        }
    }

    fn find_bulk_endpoints(device: &Device<Context>) -> Option<(u8, usize, u8, usize)> {
        let config = device.active_config_descriptor().ok()?;
        let mut in_ep = None;
        let mut in_sz = None;
        let mut out_ep = None;
        let mut out_sz = None;

        for interface in config.interfaces() {
            for interface_desc in interface.descriptors() {
                for endpoint in interface_desc.endpoint_descriptors() {
                    if endpoint.transfer_type() == rusb::TransferType::Bulk {
                        match endpoint.direction() {
                            rusb::Direction::In if in_ep.is_none() => {
                                in_ep = Some(endpoint.address());
                                in_sz = Some(endpoint.max_packet_size() as usize);
                            }
                            rusb::Direction::Out if out_ep.is_none() => {
                                out_ep = Some(endpoint.address());
                                out_sz = Some(endpoint.max_packet_size() as usize);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Some((in_ep?, in_sz?, out_ep?, out_sz?))
    }

    pub fn setup_cdc(&mut self) -> Result<()> {
        const CDC_INTERFACE: u16 = 1;
        const SET_LINE_CODING: u8 = 0x20;
        const SET_CONTROL_LINE_STATE: u8 = 0x22;
        const LINE_CODING: [u8; 7] = [0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x08];
        const CONTROL_LINE_STATE: u16 = 0x03;

        let request_type =
            rusb::request_type(Direction::Out, RequestType::Class, Recipient::Interface);

        self.handle
            .write_control(
                request_type,
                SET_LINE_CODING,
                0,
                CDC_INTERFACE,
                &LINE_CODING,
                Duration::from_millis(100),
            )
            .ok();

        self.handle
            .write_control(
                request_type,
                SET_CONTROL_LINE_STATE,
                CONTROL_LINE_STATE,
                CDC_INTERFACE,
                &[],
                Duration::from_millis(100),
            )
            .ok();

        Ok(())
    }

    pub fn from_device(device: Device<Context>) -> Option<Self> {
        let descriptor = device.device_descriptor().ok()?;
        let (vid, pid) = (descriptor.vendor_id(), descriptor.product_id());

        let connection_type = KNOWN_PORTS
            .iter()
            .find(|&&(kvid, kpid, _)| kvid == vid && kpid == pid)
            .map(|&(_, _, ct)| ct)?;

        let baudrate = match connection_type {
            ConnectionType::Brom => 115_200,
            ConnectionType::Preloader | ConnectionType::Da => 921_600,
        };

        let port_name = format!("USB {:04x}:{:04x}", vid, pid);

        let handle = device.open().ok()?;

        let (in_endpoint, _, out_endpoint, _) = Self::find_bulk_endpoints(&device)?;

        Some(Self::new(handle, connection_type, port_name, baudrate, in_endpoint, out_endpoint))
    }
}

impl MTKPort for UsbMTKPort {
    fn open(&mut self) -> Result<()> {
        if self.is_open {
            return Ok(());
        }

        let port_name = self.port_name.clone();

        for interface in 0..=1 {
            #[cfg(not(target_os = "windows"))]
            {
                match self.handle.kernel_driver_active(interface) {
                    Ok(true) => {
                        self.handle.detach_kernel_driver(interface)?;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        return Err(Error::io("Kernel driver check failed (USB)"));
                    }
                }
            }

            self.handle.claim_interface(interface)?
        }

        // CDC setup is needed for preloader and DA modes
        if self.connection_type != ConnectionType::Brom
            && let Err(e) = self.setup_cdc()
        {
            debug!("CDC Setup failed (may be ok): {:?}", e);
        }

        self.is_open = true;
        info!("Opened USB MTK port: {}", port_name);

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if !self.is_open {
            return Ok(());
        }

        for iface in 0..=1 {
            if let Err(e) = self.handle.release_interface(iface) {
                debug!("Could not release interface {}: {:?}", iface, e);
            }
            // NOTE: attach_kernel_driver is intentionally skipped.
            // On macOS/Darwin, libusb's attach_kernel_driver calls
            // darwin_reenumerate_device which segfaults if the device
            // has already physically disconnected (e.g. after reboot).
            // The kernel reclaims the interface automatically on handle drop.
        }

        self.is_open = false;
        info!("Closed USB MTK port: {}", self.port_name);

        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        let endpoint = self.in_endpoint;
        let timeout = Duration::from_millis(5000);

        let mut total_read = 0;
        while total_read < buf.len() {
            let to_read = buf.len() - total_read;
            let mut temp_buf = vec![0u8; to_read];
            let n = match self.handle.read_bulk(endpoint, &mut temp_buf, timeout) {
                Ok(n) => n,
                Err(rusb::Error::Timeout) => return Err(Error::Timeout),
                Err(e) => return Err(Error::io(e.to_string())),
            };
            if n == 0 {
                continue;
            }
            buf[total_read..total_read + n].copy_from_slice(&temp_buf[..n]);
            total_read += n;
        }
        Ok(total_read)
    }

    fn handshake(&mut self) -> Result<()> {
        let startcmd = [0xA0u8, 0x0A, 0x50, 0x05];
        let mut i = 0;

        while i < startcmd.len() {
            self.write_all(&[startcmd[i]])?;

            let endpoint = self.in_endpoint;
            let timeout = Duration::from_millis(5000);

            let mut response = vec![0u8; 5];
            let n = match self.handle.read_bulk(endpoint, &mut response, timeout) {
                Ok(count) => count,
                Err(e) => return Err(Error::io(format!("Bulk read failed: {:?}", e))),
            };

            if n == 0 {
                return Err(Error::io("USB returned 0 bytes"));
            }

            let expected = !startcmd[i];
            let handshake_byte = response[n - 1];

            if handshake_byte == startcmd[0] {
                // Already handshaken, return early
                break;
            }

            if handshake_byte == expected {
                i += 1;
            } else {
                i = 0;
                sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let endpoint = self.out_endpoint;
        let timeout = Duration::from_millis(5000);
        let data = buf.to_vec();

        if let Err(e) = self.handle.write_bulk(endpoint, &data, timeout) {
            // Penumbra has its own timeout error type to "commonize" all
            // backends. While we could just use std::io::ErrorKind::TimedOut,
            // I rather have my own error type to have more control of the timeout
            // type, since I only use this error for some specific parts.
            if e == rusb::Error::Timeout {
                return Err(Error::Timeout);
            }
            return Err(e.into());
        };

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    fn get_baudrate(&self) -> u32 {
        self.baudrate
    }

    fn get_port_name(&self) -> String {
        self.port_name.clone()
    }

    fn find_device() -> Result<Option<Self>> {
        let context = Context::new()?;
        let devices = context.devices()?;
        let devices: Vec<_> = devices.iter().collect();

        for device in devices {
            let descriptor = match device.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };

            let vid = descriptor.vendor_id();
            let pid = descriptor.product_id();

            if KNOWN_PORTS.iter().any(|(kvid, kpid, _)| *kvid == vid && *kpid == pid)
                && let Some(port) = UsbMTKPort::from_device(device)
            {
                return Ok(Some(port));
            }
        }

        Ok(None)
    }

    fn ctrl_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()> {
        self.handle.write_control(
            request_type,
            request,
            value,
            index,
            data,
            Duration::from_secs(1),
        )?;

        Ok(())
    }

    fn ctrl_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];

        let n = self.handle.read_control(
            request_type,
            request,
            value,
            index,
            &mut buf,
            Duration::from_secs(1),
        )?;

        buf.truncate(n);
        Ok(buf)
    }
}

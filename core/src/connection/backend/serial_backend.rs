/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::io::{Read, Write};
use std::time::Duration;

use log::{error, info};
use serialport::{SerialPort, SerialPortInfo, SerialPortType};

use crate::connection::port::{ConnectionType, KNOWN_PORTS, MAX_TIMEOUT, MTKPort};
use crate::error::{Error, Result};

#[derive(Debug)]
pub struct SerialMTKPort {
    port: Option<Box<dyn SerialPort>>,
    port_info: SerialPortInfo,
    baudrate: u32,
    connection_type: ConnectionType,
    is_open: bool,
}

impl SerialMTKPort {
    pub fn new(port_info: SerialPortInfo, baudrate: u32, connection_type: ConnectionType) -> Self {
        Self { port: None, port_info, baudrate, connection_type, is_open: false }
    }

    pub fn from_port_info(port_info: SerialPortInfo) -> Option<Self> {
        let SerialPortType::UsbPort(usb_info) = &port_info.port_type else {
            error!("Not a USB serial port");
            return None;
        };

        let connection_type = KNOWN_PORTS
            .iter()
            .find(|&&(vid, pid, _)| vid == usb_info.vid && pid == usb_info.pid)
            .map(|&(_, _, ct)| ct);

        let connection_type = match connection_type {
            Some(ct) => ct,
            None => {
                error!("Unknown MTK port type: {:04x}:{:04x}", usb_info.vid, usb_info.pid);
                return None;
            }
        };

        let baudrate = match connection_type {
            ConnectionType::Brom => 115_200,
            ConnectionType::Preloader | ConnectionType::Da => 921_600,
        };

        Some(SerialMTKPort::new(port_info, baudrate, connection_type))
    }
}

impl MTKPort for SerialMTKPort {
    fn open(&mut self) -> Result<()> {
        if !self.is_open {
            let port = serialport::new(&self.port_info.port_name, self.baudrate)
                .timeout(Duration::from_millis(1000))
                .open()
                .map_err(|e| Error::io(e.to_string()))?;
            self.port = Some(port);
            self.is_open = true;
            info!(
                "Opened MTK serial port: {} with baudrate {}",
                self.port_info.port_name, self.baudrate
            );
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if self.is_open {
            self.port.take();
            self.is_open = false;
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(port) = &mut self.port {
            let mut total_read = 0;
            while total_read < buf.len() {
                match port.read(&mut buf[total_read..]) {
                    Ok(0) => continue,
                    Ok(n) => total_read += n,
                    Err(e) => return Err(Error::Io(e.to_string())),
                }
            }
            Ok(total_read)
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if let Some(port) = &mut self.port {
            let mut written = 0;
            while written < buf.len() {
                match port.write(&buf[written..]) {
                    Ok(0) => continue,
                    Ok(n) => written += n,
                    Err(e) => return Err(Error::Io(e.to_string())),
                }
            }
            Ok(())
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(port) = &mut self.port {
            port.clear(serialport::ClearBuffer::Input).map_err(|e| Error::Io(e.to_string()))?;
            Ok(())
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    fn handshake(&mut self) -> Result<()> {
        let mut port = match self.port.take() {
            Some(port) => port,
            None => return Err(Error::io("Port is not open")),
        };

        let startcmd = [0xA0u8, 0x0A, 0x50, 0x05];
        let mut i = 0;

        while i < startcmd.len() {
            port.write_all(&[startcmd[i]]).map_err(|e| Error::Io(e.to_string()))?;

            let mut response = [0u8; 5];
            let n = match port.read(&mut response) {
                Ok(count) => count,
                Err(e) => return Err(Error::io(format!("Serial read failed: {:?}", e))),
            };

            if n == 0 {
                continue;
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
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        self.port = Some(port);
        Ok(())
    }

    fn get_connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    fn get_baudrate(&self) -> u32 {
        self.baudrate
    }

    fn get_port_name(&self) -> String {
        self.port_info.port_name.clone()
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        let new_timeout = timeout.unwrap_or(MAX_TIMEOUT);

        if let Some(port) = &mut self.port {
            port.set_timeout(new_timeout).map_err(|e| Error::Io(e.to_string()))?;
        } else {
            return Err(Error::io("Port is not open"));
        }

        Ok(())
    }

    fn find_device() -> Result<Option<Self>> {
        use serialport::{SerialPortType, available_ports};

        let serial_ports = match available_ports() {
            Ok(ports) => ports
                .into_iter()
                .filter(|p| match &p.port_type {
                    SerialPortType::UsbPort(usb_info) => KNOWN_PORTS
                        .iter()
                        .any(|(vid, pid, _)| usb_info.vid == *vid && usb_info.pid == *pid),
                    _ => false,
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!("Error listing serial ports: {}", e);
                vec![]
            }
        };

        for port_info in serial_ports {
            if let Some(port) = SerialMTKPort::from_port_info(port_info) {
                return Ok(Some(port));
            }
        }

        Ok(None)
    }

    fn ctrl_out(
        &mut self,
        _request_type: u8,
        _request: u8,
        _value: u16,
        _index: u16,
        _data: &[u8],
    ) -> Result<()> {
        Err(Error::io("Control transfer OUT not supported on serial connections"))
    }

    fn ctrl_in(
        &mut self,
        _request_type: u8,
        _request: u8,
        _value: u16,
        _index: u16,
        _len: usize,
    ) -> Result<Vec<u8>> {
        Err(Error::io("Control transfer IN not supported on serial connections"))
    }
}

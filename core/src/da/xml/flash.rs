/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::io::{Read, Write};

use crate::core::storage::{PartitionKind, is_pl_part};
use crate::da::Xml;
use crate::da::xml::cmds::{
    ErasePartition,
    FileSystemOp,
    ReadPartition,
    WritePartition,
    XmlCmdLifetime,
};
use crate::da::xml::{EraseFlash, ReadFlash, WriteFlash};
use crate::error::Result;

pub fn upload<F, W>(xml: &mut Xml, part_name: String, mut writer: W, mut progress: F) -> Result<()>
where
    W: Write,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, ReadPartition, &part_name, &part_name)?;

    xml.upload_file(&mut writer, &mut progress)?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

pub fn read_flash<F, W>(
    xml: &mut Xml,
    addr: u64,
    size: usize,
    section: PartitionKind,
    mut writer: W,
    mut progress: F,
) -> Result<()>
where
    W: Write,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, ReadFlash, section.as_str(), section.as_str(), size, addr)?;
    xml.upload_file(&mut writer, &mut progress)?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

pub fn download<F, R>(
    xml: &mut Xml,
    part_name: String,
    size: usize,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: Read,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, WritePartition, &part_name, &part_name)?;
    // Progress report is not needed for PL partitions,
    // because the DA skips the erase process for them.
    if !is_pl_part(&part_name) {
        let mut mock_progress = |_: usize, _: usize| {};
        xml.progress_report(&mut mock_progress)?;
    }

    xml.file_system_op(FileSystemOp::Exists)?;
    xml.file_system_op(FileSystemOp::Exists)?;

    xml.download_file(size, &mut reader, &mut progress)?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

pub fn write_flash<F, R>(
    xml: &mut Xml,
    addr: u64,
    size: usize,
    section: PartitionKind,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: Read,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, WriteFlash, section.as_str(), size, addr)?;

    xml.file_system_op(FileSystemOp::FileSize(size))?;
    xml.progress_report(&mut |_, _| {})?; // Pre-erase
    xml.download_file(size, &mut reader, &mut progress)?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

pub fn format<F>(xml: &mut Xml, part_name: String, mut progress: F) -> Result<()>
where
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, ErasePartition, &part_name)?;
    xml.progress_report(&mut progress)?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

pub fn erase_flash<F>(
    xml: &mut Xml,
    addr: u64,
    size: usize,
    section: PartitionKind,
    mut progress: F,
) -> Result<()>
where
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, EraseFlash, section.as_str(), size, addr)?;
    xml.progress_report(&mut progress)?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd)?;

    Ok(())
}

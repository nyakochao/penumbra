/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use crc32fast::hash as crc32;
use uuid::Uuid;
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

use crate::core::storage::{Partition, Storage, StorageKind, is_pl_part};
use crate::error::{Error, Result};

const EFI_PART_SIGNATURE: &[u8; 8] = b"EFI PART";
const FIRST_USABLE_LBA: u64 = 34;
const GPT_ENTRY_SIZE: u32 = 120;
const GPT_SIZE: usize = 32 * 1024; // 32KB
const MAX_GPT_PARTS: usize = 128;
const BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptType {
    Pgpt,
    Sgpt,
}

#[derive(SchemaRead, SchemaWrite, Debug, Clone)]
struct EfiGuid([u8; 16]);

#[repr(C)]
#[derive(SchemaRead, SchemaWrite, Debug, Clone)]
pub struct GptHeader {
    signature: [u8; 8],
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: EfiGuid,
    part_entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    part_array_crc32: u32,
    #[wincode(skip)]
    sector_size: usize,
}

#[derive(SchemaRead, SchemaWrite, Debug)]
pub struct GptEntry {
    part_type_guid: EfiGuid,
    unique_guid: EfiGuid,
    start_lba: u64,
    end_lba: u64,
    attributes: u64,
    name_raw: [u16; 32],
    #[wincode(skip)]
    name: String,
}

#[derive(Debug)]
pub struct Gpt {
    gpt_type: GptType,
    header: GptHeader,
    entries: Vec<GptEntry>,
}

impl Gpt {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (gpt_type, header_offset) =
            Self::detect_type(data).ok_or(Error::penumbra("No valid GPT header found!"))?;

        let mut header = GptHeader::deserialize(&data[header_offset..])?;
        header.sector_size = header_offset;

        let num_entries = header.num_entries as usize;
        let entry_size = header.entry_size as usize;

        let len = num_entries * entry_size;

        let entries_data = match gpt_type {
            GptType::Pgpt => {
                let start = header.part_entry_lba as usize * header_offset;
                data.get(start..start + len)
                    .ok_or_else(|| Error::ParseError("Partition array out of bounds".into()))?
            }
            GptType::Sgpt => {
                if data.len() < header_offset || header_offset < len {
                    return Err(Error::ParseError("SGPT buffer too small for entries".into()));
                }
                &data[0..len]
            }
        };

        let mut entries = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let off = i * entry_size;
            if off + entry_size > entries_data.len() {
                return Err(Error::io("Partition entry out of bounds"));
            }

            let mut entry = GptEntry::deserialize(&entries_data[off..off + entry_size])?;
            if entry.start_lba == 0 {
                break;
            }

            entry.name = String::from_utf16_lossy(&entry.name_raw).trim_end_matches('\0').into();

            entries.push(entry);
        }

        Ok(Self { gpt_type, header, entries })
    }

    fn detect_type(data: &[u8]) -> Option<(GptType, usize)> {
        let end = data.len();
        let sector_sizes = [512, 1024, 2048, 4096, 8192];

        for &sector_size in &sector_sizes {
            if end >= sector_size + 8
                && &data[end - sector_size..end - sector_size + 8] == EFI_PART_SIGNATURE
            {
                return Some((GptType::Sgpt, end - sector_size));
            }
        }

        for &sector_size in &sector_sizes {
            if data.len() >= sector_size + 8
                && &data[sector_size..sector_size + 8] == EFI_PART_SIGNATURE
            {
                return Some((GptType::Pgpt, sector_size));
            }
        }

        None
    }

    pub fn to_partitions(gpt: Option<&Self>, storage: &StorageKind) -> Vec<Partition> {
        let user_section = storage.get_user_part();
        let user_size = storage.get_user_size();

        let gpt_size = GPT_SIZE;

        let pgpt = Partition::new("PGPT", gpt_size, 0, user_section);

        let sgpt = Partition::new("SGPT", gpt_size, user_size - gpt_size as u64, user_section);

        let mut partitions = Vec::new();
        partitions.push(pgpt);

        if let Some(gpt) = gpt {
            for entry in &gpt.entries {
                let part_size = (entry.end_lba as usize - entry.start_lba as usize + 1)
                    * gpt.header.sector_size;

                partitions.push(Partition::new(
                    &entry.name,
                    part_size,
                    entry.start_lba * gpt.header.sector_size as u64,
                    user_section,
                ));
            }
        }

        // SGPT at the end looks cleaner!
        partitions.push(sgpt);

        partitions
    }

    pub fn is_valid(&self) -> bool {
        let mut tmp_hdr = self.header.clone();
        tmp_hdr.header_crc32 = 0;

        let Ok(buf) = GptHeader::serialize(&tmp_hdr) else {
            return false;
        };

        let crc = crc32(&buf);

        self.header.header_crc32 == crc
    }

    pub fn from_partitions(
        value: Vec<Partition>,
        block_size: u32,
        gpt_type: GptType,
    ) -> Option<Self> {
        let mut gpt_entries = Vec::with_capacity(MAX_GPT_PARTS);

        for part in value {
            if is_pl_part(&part.name) || ["PGPT", "SGPT"].contains(&part.name.as_str()) {
                continue;
            }

            let uuid = Uuid::new_v4().into_bytes();

            let start_lba = part.address / block_size as u64;
            let end_lba = (part.size as u64 / block_size as u64) + start_lba - 1;
            let mut name_raw = [0u16; 32];

            for (dest, src) in name_raw.iter_mut().zip(part.name.encode_utf16()) {
                *dest = src;
            }

            let entry = GptEntry {
                part_type_guid: EfiGuid(BASIC_DATA_GUID),
                unique_guid: EfiGuid(uuid),
                start_lba,
                end_lba,
                attributes: 0,
                name_raw,
                name: part.name,
            };

            gpt_entries.push(entry);
        }

        let last_lba = gpt_entries.last()?.end_lba;

        let (current_lba, backup_lba, part_lba) = match gpt_type {
            GptType::Pgpt => (1, last_lba + 1, 2),
            GptType::Sgpt => (last_lba + (GPT_SIZE / 512) as u64 - 1, 1, last_lba + 1),
        };

        let mut header = GptHeader {
            signature: EFI_PART_SIGNATURE.to_owned(),
            revision: 0x10000, // Seem to be constant?
            header_size: 92,
            header_crc32: 0,
            reserved: 0,
            current_lba,
            backup_lba,
            first_usable_lba: FIRST_USABLE_LBA,
            last_usable_lba: last_lba,
            disk_guid: EfiGuid([0u8; 16]),
            part_entry_lba: part_lba,
            num_entries: MAX_GPT_PARTS as u32,
            entry_size: GPT_ENTRY_SIZE,
            part_array_crc32: 0,
            sector_size: block_size as usize,
        };

        let buf = GptHeader::serialize(&header).ok()?;

        let header_crc = crc32(&buf);

        let mut part_array = [0u8; MAX_GPT_PARTS * GPT_ENTRY_SIZE as usize];

        for (i, entry) in gpt_entries.iter().enumerate() {
            let offset = i * GPT_ENTRY_SIZE as usize;
            let bytes = GptEntry::serialize(entry).ok()?;

            part_array[offset..offset + GPT_ENTRY_SIZE as usize].copy_from_slice(&bytes);
        }

        let part_array_crc = crc32(&part_array);

        header.header_crc32 = header_crc;
        header.part_array_crc32 = part_array_crc;

        Some(Self { gpt_type, header, entries: gpt_entries })
    }

    pub fn as_bytes(&self) -> Option<[u8; GPT_SIZE]> {
        let header_bytes = GptHeader::serialize(&self.header).ok()?;

        let mut part_array = [0u8; MAX_GPT_PARTS * GPT_ENTRY_SIZE as usize];
        for (i, entry) in self.entries.iter().enumerate() {
            let offset = i * GPT_ENTRY_SIZE as usize;
            let bytes = GptEntry::serialize(entry).ok()?;

            part_array[offset..offset + GPT_ENTRY_SIZE as usize].copy_from_slice(&bytes);
        }

        let block_size = self.header.sector_size;
        let mut gpt = [0u8; GPT_SIZE];

        match self.gpt_type {
            GptType::Pgpt => {
                /* TODO: ADD MBR to offset 0 */
                gpt[block_size..].copy_from_slice(&header_bytes);
                gpt[block_size * 2..].copy_from_slice(&part_array);
            }
            GptType::Sgpt => {
                gpt[0..].copy_from_slice(&part_array);
                gpt[..GPT_SIZE - block_size].copy_from_slice(&header_bytes);
            }
        }

        Some(gpt)
    }
}

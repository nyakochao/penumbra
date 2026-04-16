/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use bilge::prelude::{Bitsized, Integer, u1, u3, u4, u7};
use bilge::{self, DebugBits, FromBits, bitsize};
use crc32fast::Hasher as Crc32Hasher;
use wincode::{Deserialize, SchemaRead, SchemaWrite};

pub const OFFSET_SLOT_SUFFIX: usize = 0x800; // 2048
pub const BOOTCTRL_MAGIC: u32 = 0x42414342;
pub const BOOTCTRL_MAX_RETRY: u3 = u3::from_u8(7);
pub const BOOTCTRL_MAX_PRIORITY: u4 = u4::from_u8(15);
pub const BOOTCTRL_DEFAULT_SLOT_COUNT: u3 = u3::from_u8(2);
pub const BOOTCTRL_SLOT_A_SUFFIX: &str = "_a";
pub const BOOTCTRL_SLOT_B_SUFFIX: &str = "_b";

#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub enum BootPartition {
    A = 1,
    B = 2,
}

/// Metadata of a Slot.
/// Slots are used to determine which
/// partitions will get used during boot
/// for A/B devices.
#[bitsize(16)]
#[derive(Clone, Copy, DebugBits, PartialEq, Eq, SchemaRead, SchemaWrite, FromBits)]
pub struct SlotMetadata {
    /// How much priority this slot has over
    /// the other. Max is 15 (0b1111)
    pub priority: u4,
    /// Boot tries remaining on this slot before
    /// it gets marked as unbootable
    pub tries_remaining: u3,
    /// Whether the slot has booted successfully
    pub successful_boot: u1,
    /// Whether DM-Verity is corrupted on this slot
    pub verity_corrupted: u1,
    reserved: u7,
}

impl Default for SlotMetadata {
    fn default() -> Self {
        SlotMetadata::new(BOOTCTRL_MAX_PRIORITY, BOOTCTRL_MAX_RETRY, u1::new(0), u1::new(0))
    }
}

#[bitsize(16)]
#[derive(Default, DebugBits, Clone, Copy, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct BootControlInfo {
    /// Number of slot managed by BootControl.
    /// Up to 4 slots, but seem to always be 2.
    pub slot_count: u3,
    /// Tries before booting to recovery.
    /// Unused
    pub recovery_tries_remaining: u3,
    pub merge_status: u3,
    reserved: u7,
}

/// BootControl configuration.
/// This struct is used to manage the A/B metadata for devices
/// supporting multiple slots.
/// https://source.android.com/docs/core/ota/ab/ab_implement
#[derive(Debug, Clone, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct BootControl {
    /// The suffix of the current active slot
    /// Either `_a` or `_b`
    pub suffix: [u8; 4],
    /// Always 0x42414342
    pub magic: u32,
    /// Version of BootControl API.
    /// Seem to always be 1.
    pub version: u8,
    /// Bit Field (u16) containing general
    /// info about the slots (slot count)
    pub control_info: BootControlInfo,
    /// MediaTek put padding here for alignment
    pad: u8,
    /// Specific info for each slot
    pub slots: [SlotMetadata; 4],
    reserved: [u8; 8],
    /// CRC32 of the previous data
    pub crc: u32,
    /// Partition name of where bootctrl
    /// was found. New devices use `misc`, old one
    /// might use `para`
    #[wincode(skip)]
    pub bctrl_part: String,
}

impl Default for BootControl {
    fn default() -> Self {
        let mut control_info = BootControlInfo::default();
        control_info.set_slot_count(BOOTCTRL_DEFAULT_SLOT_COUNT);

        let mut bootctrl = Self {
            suffix: b"_a\0\0".to_owned(),
            magic: BOOTCTRL_MAGIC,
            version: 1,
            control_info,
            pad: 0,
            slots: [
                SlotMetadata::default(),
                SlotMetadata::default(),
                SlotMetadata::from(0u16),
                SlotMetadata::from(0u16),
            ],
            reserved: [0; 8],
            crc: 0,
            bctrl_part: "misc".into(),
        };

        bootctrl.crc = bootctrl.compute_crc();

        bootctrl
    }
}

impl BootControl {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let bctrl = BootControl::deserialize(data).ok()?;
        if bctrl.is_valid() { Some(bctrl) } else { None }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == BOOTCTRL_MAGIC && self.compute_crc() == self.crc
    }

    fn compute_crc(&self) -> u32 {
        let mut data = [0u8; 32];
        wincode::serialize_into(&mut data[..], self).unwrap();

        let mut hasher = Crc32Hasher::new();
        hasher.update(&data[..28]);
        hasher.finalize()
    }

    fn update_crc(&mut self) {
        self.crc = self.compute_crc();
    }

    pub fn get_slot(&self, slot: BootPartition) -> &SlotMetadata {
        match slot {
            BootPartition::A => &self.slots[0],
            BootPartition::B => &self.slots[1],
        }
    }

    pub fn get_active_slot(&self) -> BootPartition {
        let slot_a = &self.slots[0];
        let slot_b = &self.slots[1];

        if slot_a.priority() >= slot_b.priority() { BootPartition::A } else { BootPartition::B }
    }

    pub fn set_active_slot(&mut self, slot: BootPartition) {
        let (active, other) = match slot {
            BootPartition::A => (0, 1),
            BootPartition::B => (1, 0),
        };

        let active_slot = &mut self.slots[active];
        active_slot.set_priority(BOOTCTRL_MAX_PRIORITY);
        active_slot.set_tries_remaining(BOOTCTRL_MAX_RETRY);
        active_slot.set_successful_boot(u1::new(0));
        active_slot.set_verity_corrupted(u1::new(0));

        // Active slot always gets max priority
        self.slots[other].set_priority(BOOTCTRL_MAX_PRIORITY - u4::new(1));

        self.suffix = match slot {
            BootPartition::A => b"_a\0\0".to_owned(),
            BootPartition::B => b"_b\0\0".to_owned(),
        };

        self.update_crc();
    }

    pub fn get_current_suffix(&self) -> Option<&str> {
        let suffix_str = std::str::from_utf8(&self.suffix).ok()?;
        if suffix_str.starts_with(BOOTCTRL_SLOT_A_SUFFIX) {
            Some(BOOTCTRL_SLOT_A_SUFFIX)
        } else if suffix_str.starts_with(BOOTCTRL_SLOT_B_SUFFIX) {
            Some(BOOTCTRL_SLOT_B_SUFFIX)
        } else {
            None
        }
    }
}

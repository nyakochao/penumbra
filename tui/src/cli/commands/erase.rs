/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::Device;

use crate::cli::MtkCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct EraseArgs {
    /// The partition to erase
    pub partition: String,
}

impl CommandMetadata for EraseArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["e"]
    }

    fn about() -> &'static str {
        "Erase a partition on the device."
    }

    fn long_about() -> &'static str {
        "Erase the specified partition on the device."
    }
}

impl MtkCommand for EraseArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let partition = match dev.dev_info.get_partition(&self.partition) {
            Some(p) => p,
            None => {
                info!("Partition '{}' not found on device.", self.partition);
                return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
            }
        };

        let pb = AntumbraProgress::new(partition.size as u64);

        let mut progress_callback = {
            let pb = &pb;
            move |written: usize, total: usize| {
                pb.update(written as u64, "Erasing...");

                if written >= total {
                    pb.finish("Erase complete!");
                }
            }
        };

        info!("Erasing partition '{}'...", self.partition);

        match dev.erase_partition(&self.partition, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Erase failed!");
                return Err(e)?;
            }
        };

        info!("Partition '{}' erase completed.", self.partition);

        Ok(())
    }
}

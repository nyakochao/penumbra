/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
#[macro_use]
mod macros;

#[cfg(feature = "tui")]
mod app;
#[cfg(feature = "tui")]
mod components;
#[cfg(feature = "tui")]
mod pages;
#[cfg(feature = "tui")]
mod themes;

mod cli;
mod config;
mod error;
mod logger;

use anyhow::Result;
use clap::Parser;
use cli::{CliArgs, run_cli};
use logger::init_logger;

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();

    let cli_mode = args.cli || args.command.is_some() || !cfg!(feature = "tui");
    let tui_mode = !cli_mode;

    init_logger(tui_mode, args.verbose);

    if cli_mode {
        return run_cli(&args).await;
    }

    #[cfg(feature = "tui")]
    {
        use app::App;

        let mut terminal = ratatui::init();
        let mut app = App::new(&args);

        let app_result = app.run(&mut terminal).await;

        ratatui::restore();
        return app_result;
    }

    unreachable!()
}

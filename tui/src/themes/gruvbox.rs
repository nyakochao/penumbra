/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use ratatui::style::Color;

use crate::themes::Theme;

pub fn gruvbox_light() -> Theme {
    Theme {
        name: "Gruvbox",
        id: "gruvbox_light",
        is_dark: false,
        // #fbf1c7
        background: Color::Rgb(251, 241, 199),
        // #3c3836
        foreground: Color::Rgb(60, 56, 54),
        // #ebdbb2
        highlight: Color::Rgb(235, 219, 178),
        // #3c3836
        text: Color::Rgb(60, 56, 54),
        // #d65d0e
        accent: Color::Rgb(204, 36, 29),
        // #9d0006
        error: Color::Rgb(157, 0, 6),
        // #d79921
        warning: Color::Rgb(215, 153, 33),
        // #458588
        info: Color::Rgb(69, 133, 136),
        // #98971a
        success: Color::Rgb(152, 151, 26),
        // #a89984
        muted: Color::Rgb(168, 153, 132),
    }
}

pub fn gruvbox_dark() -> Theme {
    Theme {
        name: "Gruvbox Dark",
        id: "gruvbox_dark",
        is_dark: true,
        // #282828
        background: Color::Rgb(40, 40, 40),
        // #ebdbb2
        foreground: Color::Rgb(235, 219, 178),
        // #3c3836
        highlight: Color::Rgb(60, 56, 54),
        // #ebdbb2
        text: Color::Rgb(235, 219, 178),
        // #d65d0e
        accent: Color::Rgb(204, 36, 29),
        // #9d0006
        error: Color::Rgb(157, 0, 6),
        // #d79921
        warning: Color::Rgb(215, 153, 33),
        // #458588
        info: Color::Rgb(69, 133, 136),
        // #98971a
        success: Color::Rgb(152, 151, 26),
        // #a89984
        muted: Color::Rgb(168, 153, 132),
    }
}

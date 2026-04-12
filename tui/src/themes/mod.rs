/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::collections::HashMap;

use ratatui::style::Color;

// Themes
mod gruvbox;
mod rose_pine;

pub type ThemeConstructor = fn() -> Theme;
pub type ThemeRegistry = HashMap<&'static str, ThemeConstructor>;

pub struct Theme {
    pub name: &'static str,
    pub id: &'static str,
    pub is_dark: bool,
    pub background: Color,
    pub foreground: Color,
    pub highlight: Color,
    pub text: Color,
    pub accent: Color,
    pub error: Color,
    pub warning: Color,
    pub info: Color,
    pub success: Color,
    pub muted: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            name: "System",
            id: "system",
            is_dark: true,
            background: Color::Reset,
            foreground: Color::Gray,
            highlight: Color::Black,
            text: Color::Reset,
            accent: Color::Cyan,
            error: Color::Red,
            warning: Color::Yellow,
            info: Color::LightBlue,
            success: Color::LightGreen,
            muted: Color::DarkGray,
        }
    }
}

pub fn load_themes() -> ThemeRegistry {
    let mut themes: ThemeRegistry = HashMap::new();

    themes.insert("system", Theme::default);
    themes.insert("rose_pine_moon", rose_pine::rose_pine_moon);
    themes.insert("gruvbox_light", gruvbox::gruvbox_light);
    themes.insert("gruvbox_dark", gruvbox::gruvbox_dark);

    themes
}

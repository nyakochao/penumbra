/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::time::Instant;

use human_bytes::human_bytes;
use ratatui::prelude::{Buffer, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, WidgetRef};

use crate::components::ThemedWidgetRef;
use crate::themes::Theme;

#[derive(Debug, Clone)]
pub enum ProgressMode {
    Idle,
    Active,
}

pub struct ProgressBar {
    mode: ProgressMode,
    total_bytes: u64,
    written_bytes: u64,
    message: String,
    start_time: Option<Instant>,
}

impl ProgressBar {
    pub fn new() -> Self {
        Self {
            mode: ProgressMode::Idle,
            total_bytes: 0,
            written_bytes: 0,
            message: String::from("No active operation"),
            start_time: None,
        }
    }

    pub fn start(&mut self, total_bytes: u64, message: impl Into<String>) {
        self.mode = ProgressMode::Active;
        self.total_bytes = total_bytes;
        self.written_bytes = 0;
        self.message = message.into();
        self.start_time = Some(Instant::now());
    }

    /// Update written bytes
    pub fn set_written(&mut self, bytes: u64) {
        if matches!(self.mode, ProgressMode::Active) {
            self.written_bytes = bytes.min(self.total_bytes);
        }
    }

    /// Update message
    pub fn set_message(&mut self, message: impl Into<String>) {
        if matches!(self.mode, ProgressMode::Active) {
            self.message = message.into();
        }
    }

    pub fn finish(&mut self) {
        self.mode = ProgressMode::Idle;
        self.total_bytes = 0;
        self.written_bytes = 0;
        self.message = String::from("No active operation");
        self.start_time = None;
    }

    fn ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.written_bytes as f64 / self.total_bytes as f64
        }
    }

    fn speed(&self) -> f64 {
        match self.start_time {
            Some(start) => {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 { self.written_bytes as f64 / elapsed } else { 0.0 }
            }
            None => 0.0,
        }
    }
}

impl ThemedWidgetRef for ProgressBar {
    fn render_ref(&self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        if area.height < 3 {
            return;
        }

        let style = match self.mode {
            ProgressMode::Idle => Style::default().fg(theme.muted).add_modifier(Modifier::ITALIC),
            ProgressMode::Active => Style::default().fg(theme.accent),
        };

        match self.mode {
            ProgressMode::Idle => {
                let lines = vec![
                    Line::from(Span::styled("No active operation", style)),
                    Line::from(Span::raw("")),
                    Line::from(Span::raw("")),
                ];

                Paragraph::new(lines).render_ref(area, buf);
            }

            ProgressMode::Active => {
                let bar_width = area.width.saturating_sub(6) as usize;
                let filled = (self.ratio() * bar_width as f64).round() as usize;
                let empty = bar_width.saturating_sub(filled);
                let percent = (self.ratio() * 100.0).round() as u8;

                let bar = format!("{}{} {:>3}%", "█".repeat(filled), "░".repeat(empty), percent);

                let written = human_bytes(self.written_bytes as f64);
                let total = human_bytes(self.total_bytes as f64);
                let speed = human_bytes(self.speed());

                let lines = vec![
                    Line::from(Span::styled(&self.message, style)),
                    Line::from(Span::styled(bar, style)),
                    Line::from(vec![
                        Span::raw(format!("{written} / {total}")),
                        Span::raw("  •  "),
                        Span::raw(format!("{speed}/s")),
                    ]),
                ];

                Paragraph::new(lines).render_ref(area, buf);
            }
        }
    }
}

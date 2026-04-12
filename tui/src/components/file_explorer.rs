/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::Buffer;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Widget, WidgetRef};
use ratatui_explorer::{FileExplorer as Inner, Theme as ExplorerTheme};

use crate::themes::Theme;

#[derive(Debug, Clone, PartialEq)]
pub enum ExplorerResult {
    Selected(PathBuf),
    Cancelled,
    Pending,
}

pub struct FileExplorer {
    inner: Inner,
    title: String,
    extensions: Option<Vec<String>>,
    directories_only: bool,
    search_buffer: String,
    last_input_time: Instant,
}

impl FileExplorer {
    pub fn new(title: impl Into<String>) -> Result<Self> {
        let theme = ExplorerTheme::default()
            .with_dir_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .with_highlight_item_style(
                Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD),
            );

        Ok(Self {
            inner: Inner::with_theme(theme)?,
            title: title.into(),
            extensions: None,
            directories_only: false,
            search_buffer: String::new(),
            last_input_time: Instant::now(),
        })
    }

    /// A list of allowed file extensions
    pub fn extensions(mut self, ext: &[&str]) -> Self {
        self.extensions = Some(ext.iter().map(|s| s.to_lowercase()).collect());
        self
    }

    /// Whether to allow only directory in the view/selection
    pub fn directories_only(mut self) -> Self {
        self.directories_only = true;
        self
    }

    /// The starting directory path
    pub fn start_dir(mut self, path: impl Into<PathBuf>) -> Result<Self> {
        self.inner.set_cwd(path)?;
        Ok(self)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> ExplorerResult {
        match key.code {
            KeyCode::Esc => return ExplorerResult::Cancelled,

            KeyCode::Char(c) if self.is_searchable_char(c) => {
                self.handle_search_input(c);
                return ExplorerResult::Pending;
            }

            // Since Enter is used for entering inside directories,
            // we gotta * adapt *
            KeyCode::Char(' ') if self.directories_only => {
                return ExplorerResult::Selected(self.inner.cwd().clone());
            }

            KeyCode::Enter => {
                let current = self.inner.current();
                let path = current.path().clone();

                if current.is_dir() {
                    let _ = self.inner.handle(&Event::Key(key));
                    self.search_buffer.clear();
                } else {
                    log::debug!("Selected file: {:?}", &path);
                    return self.try_select_file(&path);
                }

                return ExplorerResult::Pending;
            }

            KeyCode::Backspace | KeyCode::Delete => {
                self.search_buffer.clear();
            }

            _ => {
                if matches!(
                    key.code,
                    KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::Home
                        | KeyCode::End
                        | KeyCode::PageUp
                        | KeyCode::PageDown
                ) {
                    self.search_buffer.clear();
                }
                let _ = self.inner.handle(&Event::Key(key));
            }
        }

        ExplorerResult::Pending
    }

    fn is_searchable_char(&self, c: char) -> bool {
        c.is_alphanumeric() || c == '.' || c == '_' || c == '-'
    }

    fn handle_search_input(&mut self, c: char) {
        if self.last_input_time.elapsed() > Duration::from_millis(500) {
            self.search_buffer.clear();
        }

        self.search_buffer.push(c);
        self.last_input_time = Instant::now();
        self.jump_to_match();
    }

    fn try_select_file(&self, path: &Path) -> ExplorerResult {
        if self.directories_only {
            return ExplorerResult::Pending;
        }

        if let Some(ref allowed) = self.extensions {
            let ext = path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());

            match ext {
                Some(e) if allowed.contains(&e) => ExplorerResult::Selected(path.to_path_buf()),
                _ => ExplorerResult::Pending,
            }
        } else {
            log::debug!("No extension filtering applied.");
            ExplorerResult::Selected(path.to_path_buf())
        }
    }

    fn jump_to_match(&mut self) {
        if self.search_buffer.is_empty() {
            return;
        }

        let files = self.inner.files();
        if files.is_empty() {
            return;
        }

        let current_idx = self.inner.selected_idx();
        let query = self.search_buffer.to_lowercase();

        let mut target_idx = None;

        for (i, file) in files.iter().enumerate().skip(current_idx) {
            if file.name().to_lowercase().starts_with(&query) {
                target_idx = Some(i);
                break;
            }
        }

        if target_idx.is_none() {
            for (i, file) in files.iter().enumerate().take(current_idx) {
                if file.name().to_lowercase().starts_with(&query) {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(target) = target_idx {
            self.navigate_to(target, current_idx);
        }
    }

    fn navigate_to(&mut self, target: usize, current: usize) {
        if target == current {
            return;
        }

        if target > current {
            for _ in 0..(target - current) {
                let _ = self.inner.handle(&Event::Key(KeyCode::Down.into()));
            }
        } else {
            for _ in 0..(current - target) {
                let _ = self.inner.handle(&Event::Key(KeyEvent::from(KeyCode::Up)));
            }
        }
    }

    #[allow(dead_code)]
    pub fn render(&self, area: Rect, frame: &mut Frame, _theme: &Theme) {
        frame.render_widget(&self.inner.widget(), area);
    }

    pub fn render_modal(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let width = (area.width * 70) / 100;
        let height = (area.height * 70) / 100;
        let x = area.x + (area.width - width) / 2;
        let y = area.y + (area.height - height) / 2;
        let modal_area = Rect::new(x, y, width, height);

        Clear.render(modal_area, buf);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(theme.accent))
            .title(self.title.as_str())
            .style(Style::default().bg(theme.highlight));

        block.clone().render(modal_area, buf);
        let inner_area = block.inner(modal_area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)])
            .split(inner_area);

        let path_str = self.inner.cwd().display().to_string();
        let header = Paragraph::new(format!(" 📂 {path_str} "))
            .style(Style::default().fg(theme.accent).add_modifier(Modifier::BOLD));

        header.render(chunks[0], buf);
        self.inner.set_theme(
            ExplorerTheme::default()
                .with_dir_style(Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
                .with_highlight_item_style(
                    Style::default()
                        .bg(theme.accent)
                        .fg(theme.background)
                        .add_modifier(Modifier::BOLD),
                )
                .with_item_style(Style::default().fg(theme.text))
                .with_highlight_dir_style(
                    Style::default()
                        .bg(theme.accent)
                        .fg(theme.background)
                        .add_modifier(Modifier::BOLD),
                )
                .with_style(Style::default().fg(theme.text)), // Inner border
        );
        self.inner.widget().render_ref(chunks[1], buf);

        let help_text = if self.directories_only {
            " [↑/↓] Nav • [Space] Select Dir • [Esc] Cancel "
        } else {
            " [↑/↓] Nav • [Enter] Select • [Esc] Cancel "
        };

        let help = Paragraph::new(help_text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(theme.muted));
        help.render(chunks[2], buf);
    }
}

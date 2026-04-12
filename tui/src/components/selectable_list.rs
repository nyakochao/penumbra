/*
 *    SPDX-License-Identifier: AGPL-3.0-or-later
 *    SPDX-FileCopyrightText: 2025-2026 DiabloSat
 *    SPDX-FileCopyrightText: 2025-2026 Shomy
 */

use derive_builder::Builder;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, StatefulWidgetRef};

use crate::components::ThemedWidgetMut;
use crate::themes::Theme;

#[derive(PartialEq, Builder, Clone, Default)]
pub struct ListItemEntry {
    pub label: String,
    // Optional value used to identify the item
    #[builder(default, setter(strip_option))]
    pub value: Option<String>,
    #[builder(default, setter(strip_option))]
    pub icon: Option<char>,
    #[builder(default, setter(strip_option))]
    pub style: Option<Style>,
    #[builder(private, default)]
    toggle: bool,
}

impl ListItemEntry {
    pub fn is_toggled(&self) -> bool {
        self.toggle
    }
}

#[derive(Builder, Clone, Default)]
pub struct SelectableList {
    #[builder(default)]
    pub items: Vec<ListItemEntry>,
    #[builder(default = "{
        let mut s = ListState::default();
        s.select(Some(0));
        s
    }")]
    pub state: ListState,
    #[builder(setter(custom))]
    pub highlight_symbol: String,
    #[builder(default)]
    pub toggled: bool,
    #[builder(default)]
    pub borders: Borders,
    #[builder(default)]
    pub block_title: String,
}

impl ThemedWidgetMut for SelectableList {
    fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let list_items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let mut style = item.style.unwrap_or_else(|| Style::default().fg(theme.text));

                if Some(i) == self.selected_index() {
                    style = style.fg(theme.accent).add_modifier(Modifier::BOLD)
                }

                let label = {
                    let mut parts = Vec::new();

                    if self.toggled {
                        parts.push(if item.toggle { "[x]" } else { "[ ]" }.to_string());
                    }

                    if let Some(icon) = &item.icon {
                        parts.push(icon.to_string());
                    }

                    parts.push(item.label.clone());
                    parts.join(" ")
                };

                ListItem::new(label).style(style)
            })
            .collect();

        let block = Block::default().title(self.block_title.as_str()).borders(self.borders);

        let list = List::new(list_items).block(block).highlight_symbol(&self.highlight_symbol);

        list.render_ref(area, buf, &mut self.state);
    }
}

impl SelectableList {
    pub fn next(&mut self) {
        if !self.items.is_empty() {
            let i = self.state.selected().unwrap_or(0);
            let next = (i + 1) % self.items.len();
            self.state.select(Some(next));
        }
    }

    pub fn previous(&mut self) {
        if !self.items.is_empty() {
            let i = self.state.selected().unwrap_or(0);
            let prev = if i == 0 { self.items.len() - 1 } else { i - 1 };
            self.state.select(Some(prev));
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.state.selected()
    }

    pub fn selected_item(&self) -> Option<&ListItemEntry> {
        if let Some(i) = self.selected_index() { self.items.get(i) } else { None }
    }
}

impl SelectableList {
    /// Select the currently highlighted item
    pub fn toggle_selected(&mut self) {
        if self.toggled
            && let Some(i) = self.selected_index()
            && let Some(item) = self.items.get_mut(i)
        {
            item.toggle = !item.toggle;
        }
    }

    pub fn clear_selections(&mut self) {
        for item in &mut self.items {
            item.toggle = false;
        }
    }

    pub fn checked_items(&self) -> Vec<&ListItemEntry> {
        self.items.iter().filter(|item| item.toggle).collect()
    }
}

impl SelectableListBuilder {
    pub fn highlight_symbol(&mut self, s: impl Into<String>) -> &mut Self {
        self.highlight_symbol = Some(format!("{} ", s.into().trim_end()));
        self
    }
}

impl ListItemEntryBuilder {
    pub fn new(label: impl Into<String>) -> Self {
        let mut builder = ListItemEntryBuilder::default();
        builder.label(label.into());
        builder
    }
}

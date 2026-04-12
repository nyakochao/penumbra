/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

// Simple info dialog
macro_rules! info_dialog {
    ($ctx:expr, $message:expr) => {
        $ctx.dialog = Some(DialogBuilder::info($message).build().unwrap())
    };
    ($ctx:expr, $message:expr, $($buttons:expr),*) => {
        $ctx.dialog = Some({
            let mut builder = DialogBuilder::info($message);
            $(builder.button($buttons);)*
            builder.build().unwrap()
        })
    };
}

// Simple error dialog
macro_rules! error_dialog {
    ($ctx:expr, $message:expr) => {
        $ctx.dialog = Some({
            let mut builder = crate::components::DialogBuilder::error($message, &$ctx.theme);
            let button = crate::components::DialogButton::new("OK", || {});
            builder.button(button);
            builder.build().unwrap()
        })
    };
    ($ctx:expr, $message:expr, $($buttons:expr),*) => {
        $ctx.dialog = Some({
            let mut builder = crate::components::DialogBuilder::error($message);
            $(builder.button($buttons);)*
            builder.build().unwrap()
        })
    };
}

// Simple dialog with custom type
macro_rules! dialog {
    ($ctx:expr, $message:expr) => {
        $ctx.dialog = Some(DialogBuilder::other($message).build().unwrap())
    };
    ($ctx:expr, $message:expr, $($buttons:expr),*) => {
        $ctx.dialog = Some({
            let mut builder = DialogBuilder::other($message);
            $(builder.button($buttons);)*
            builder.build().unwrap()
        })
    };
}

// Quick OK-only dialog
macro_rules! ok_dialog {
    ($ctx:expr, $dialog_type:ident, $message:expr) => {
        $ctx.dialog = Some($dialog_type!($ctx, $message, DialogButton::new("OK", || {})))
    };
}

// Quick confirmation dialog
macro_rules! confirm_dialog {
    ($ctx:expr, $message:expr, $on_confirm:expr) => {
        confirm_dialog!($ctx, $message, $on_confirm, || {})
    };
    ($ctx:expr, $message:expr, $on_confirm:expr, $on_cancel:expr) => {
        $ctx.dialog = Some({
            let mut builder = DialogBuilder::info($message);
            builder.button(DialogButton::new("OK", $on_confirm));
            builder.button(DialogButton::new("Cancel", $on_cancel));
            builder.build().unwrap()
        })
    };
}

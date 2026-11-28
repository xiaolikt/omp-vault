//! User-facing strings, English by default, Chinese with `AI_VAULT_LANG=zh`
//! (or a `zh_*` locale). Rust-side texts: dialogs, prompts, notices, errors.
//!
//! The rule: a message that a human reads is English unless they asked for
//! Chinese. Strings that a *host* parses (exit codes, `needs-ui:`,
//! `no such entry`, the JSON keys) never change.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

static LANG: OnceLock<Lang> = OnceLock::new();

pub fn lang() -> Lang {
    *LANG.get_or_init(detect)
}

fn detect() -> Lang {
    let explicit = std::env::var("AI_VAULT_LANG").unwrap_or_default().to_lowercase();
    if explicit.starts_with("zh") {
        return Lang::Zh;
    }
    if explicit == "en" || !explicit.is_empty() {
        return Lang::En;
    }
    let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .unwrap_or_default()
        .to_lowercase();
    if locale.starts_with("zh") {
        Lang::Zh
    } else {
        Lang::En
    }
}

/// Pick the English or the Chinese text.
pub fn tr(en: &'static str, zh: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// The same with owned strings (formatted text).
pub fn tr_owned(en: String, zh: String) -> String {
    match lang() {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

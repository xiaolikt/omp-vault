//! Machine-wide settings: when the vault asks for its master password, when
//! the Bitwarden side asks, and whether a Bitwarden hit may be imported
//! without asking.
//!
//! Stored in `<dir>/config.json` (0600, written atomically). A missing or
//! broken file means the defaults: ask once per session, offer imports.

use serde::{Deserialize, Serialize};
use std::fs;

use crate::crypto;
use crate::paths::Paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnlockMode {
    /// Never ask again: the key lives in the store directory, readable by this
    /// user, so agents can read secrets without any window.
    Never,
    /// Ask again after `hours`, counted from the unlock (not from the last use).
    Time,
    /// Ask once per agent session; the token dies when the session ends.
    Session,
}

impl UnlockMode {
    pub fn parse(text: &str) -> Option<UnlockMode> {
        match text.trim().to_lowercase().as_str() {
            "never" | "no-password" | "none" | "off" => Some(UnlockMode::Never),
            "time" | "hours" => Some(UnlockMode::Time),
            "session" | "on" => Some(UnlockMode::Session),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            UnlockMode::Never => "never",
            UnlockMode::Time => "time",
            UnlockMode::Session => "session",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportPolicy {
    /// Show the Bitwarden hit, read it once, then ask whether to import it.
    Ask,
    /// Import whatever is found and hand it back: no window at all.
    Always,
    /// Never write a Bitwarden entry into the store; read one-offs only.
    Never,
}

impl ImportPolicy {
    pub fn parse(text: &str) -> Option<ImportPolicy> {
        match text.trim().to_lowercase().as_str() {
            "ask" | "confirm" => Some(ImportPolicy::Ask),
            "always" | "auto" | "yes" => Some(ImportPolicy::Always),
            "never" | "no" | "off" => Some(ImportPolicy::Never),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ImportPolicy::Ask => "ask",
            ImportPolicy::Always => "always",
            ImportPolicy::Never => "never",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UnlockPolicy {
    pub mode: UnlockMode,
    /// `Time` mode only: hours between password prompts.
    #[serde(default = "default_hours")]
    pub hours: i64,
}

fn default_hours() -> i64 {
    8
}

impl Default for UnlockPolicy {
    fn default() -> Self {
        UnlockPolicy { mode: UnlockMode::Session, hours: default_hours() }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BitwardenPolicy {
    /// `never` keeps the `bw` session key in the store directory, so no
    /// Bitwarden master password is asked; `time` does the same with a
    /// deadline; `session` (default) keeps it in the agent's memory only.
    #[serde(default = "default_bw_mode")]
    pub unlock: UnlockMode,
    #[serde(default = "default_hours")]
    pub hours: i64,
    #[serde(default = "default_import")]
    pub import: ImportPolicy,
}

fn default_bw_mode() -> UnlockMode {
    UnlockMode::Session
}

fn default_import() -> ImportPolicy {
    ImportPolicy::Ask
}

impl Default for BitwardenPolicy {
    fn default() -> Self {
        BitwardenPolicy { unlock: default_bw_mode(), hours: default_hours(), import: default_import() }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub unlock: UnlockPolicy,
    #[serde(default)]
    pub bitwarden: BitwardenPolicy,
}

/// A missing or unreadable config means the defaults. A broken file must not
/// lock anyone out of their vault.
pub fn load(paths: &Paths) -> Config {
    match fs::read_to_string(paths.config()) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

pub fn save(paths: &Paths, config: &Config) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| format!("cannot serialize config: {e}"))?;
    crypto::write_atomic(&paths.config(), &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aliases() {
        assert_eq!(UnlockMode::parse("no-password"), Some(UnlockMode::Never));
        assert_eq!(UnlockMode::parse("SESSION"), Some(UnlockMode::Session));
        assert_eq!(UnlockMode::parse("2h"), None);
        assert_eq!(ImportPolicy::parse("auto"), Some(ImportPolicy::Always));
        assert_eq!(ImportPolicy::parse("off"), Some(ImportPolicy::Never));
    }

    #[test]
    fn defaults_are_the_cautious_ones() {
        let config = Config::default();
        assert_eq!(config.unlock.mode, UnlockMode::Session);
        assert_eq!(config.bitwarden.unlock, UnlockMode::Session);
        assert_eq!(config.bitwarden.import, ImportPolicy::Ask);
    }

    #[test]
    fn old_configs_still_load() {
        // A config written by the previous version had only `unlock`.
        let parsed: Config = serde_json::from_str(r#"{"unlock":{"mode":"time","hours":4}}"#).unwrap();
        assert_eq!(parsed.unlock.mode, UnlockMode::Time);
        assert_eq!(parsed.bitwarden.import, ImportPolicy::Ask);
        assert_eq!(parsed.bitwarden.hours, 8);
    }
}

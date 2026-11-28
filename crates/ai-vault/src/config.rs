//! Machine-wide unlock policy: how often the vault asks for the master
//! password. Switching the mode always re-verifies the master password.

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub unlock: UnlockPolicy,
}

/// A missing or unreadable config means the default policy: ask once per
/// session. A broken file must not lock anyone out of their vault.
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

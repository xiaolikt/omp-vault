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
    /// Whether each read of an entry opens a confirm window while the session
    /// is unlocked. On by default. Off means "the master password I just typed
    /// is enough" — reads are still audited, entry by entry.
    #[serde(default = "default_confirm")]
    pub confirm: bool,
}

fn default_confirm() -> bool {
    true
}

fn default_hours() -> i64 {
    8
}

impl Default for UnlockPolicy {
    fn default() -> Self {
        UnlockPolicy { mode: UnlockMode::Session, hours: default_hours(), confirm: default_confirm() }
    }
}

/// How a third-party CLI's credential is kept on disk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StorePolicy {
    /// `never` keeps the credential in the store directory (sealed), so the
    /// CLI needs no keychain or password; `time` does the same with a
    /// deadline; `session` (default) leaves it in the CLI's own keychain.
    #[serde(default = "default_bw_mode")]
    pub unlock: UnlockMode,
    #[serde(default = "default_hours")]
    pub hours: i64,
}

impl Default for StorePolicy {
    fn default() -> Self {
        StorePolicy { unlock: default_bw_mode(), hours: default_hours() }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BitwardenPolicy {
    #[serde(flatten)]
    pub store: StorePolicy,
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
        BitwardenPolicy { store: StorePolicy::default(), import: default_import() }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub unlock: UnlockPolicy,
    #[serde(default)]
    pub bitwarden: BitwardenPolicy,
    /// Ente's `ENTE_CLI_VAULT_KEY`: `session` leaves it to the OS keychain,
    /// `never`/`time` keep it sealed next to the store.
    #[serde(default)]
    pub ente: StorePolicy,
}

/// The settings are inside the store's ciphertext (see `crypto::Payload`), so
/// they can only be read or changed with the store's key: a password, or a
/// session that was opened with one. There is no file to edit.
//
// Callers hold either a `Session` (its key opens the store) or a freshly
// derived key. Both go through `read_with` / `write_with`.
pub fn write_with(
    store: &crate::crypto::StoreFile,
    key: &[u8; 32],
    config: &Config,
) -> Result<crate::crypto::StoreFile, String> {
    let payload = crypto::open_with_key(store, key).map_err(|e| e.to_string())?;
    let salt = crypto::hex_to_bytes(&store.salt).ok_or_else(|| "vault salt is corrupt".to_string())?;
    crypto::seal(&salt, store.kdf(), key, &payload.items, config)
}

/// A legacy plaintext config.json from before the settings moved inside the
/// store. Returned once so the next unlock can carry it in; then the file
/// is removed. Only the *defaults-safe* keys migrate; the two that lower
/// protection (`vault.unlock = never`, `vault.confirm = false`) do not, so
/// an edit made while the file was still plain text grants nothing.
pub fn take_legacy(paths: &Paths) -> Option<Config> {
    let text = fs::read_to_string(paths.config()).ok()?;
    let _ = fs::remove_file(paths.config());
    let Ok(parsed) = serde_json::from_str::<Config>(&text) else { return None };
    let mut config = parsed;
    if config.unlock.mode == UnlockMode::Never {
        config.unlock.mode = UnlockMode::Session;
    }
    config.unlock.confirm = true;
    Some(config)
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
        assert_eq!(config.bitwarden.store.unlock, UnlockMode::Session);
        assert_eq!(config.ente.unlock, UnlockMode::Session);
        assert_eq!(config.bitwarden.import, ImportPolicy::Ask);
    }

    #[test]
    fn old_configs_still_load() {
        // A config written by the previous version had only `unlock`.
        let parsed: Config = serde_json::from_str(r#"{"unlock":{"mode":"time","hours":4}}"#).unwrap();
        assert_eq!(parsed.unlock.mode, UnlockMode::Time);
        assert_eq!(parsed.unlock.confirm, true, "a config from before the switch keeps confirming");
        assert_eq!(parsed.bitwarden.import, ImportPolicy::Ask);
        assert_eq!(parsed.bitwarden.store.hours, 8);
    }
}

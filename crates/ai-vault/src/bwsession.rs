//! The `bw` session key, persisted for `bitwarden.unlock = never | time`.
//!
//! `bw unlock` hands back a bearer key; keeping it on disk is what makes the
//! Bitwarden side password-free, exactly like the vault's own `never` mode.
//! It is never printed unless `bw-session get` is asked for it.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};

use crate::config::{self, UnlockMode};
use crate::crypto;
use crate::paths::Paths;
use crate::session::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    #[serde(rename = "savedAt")]
    pub saved_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expiresAt")]
    pub expires_at: Option<i64>,
    pub key: String,
}

impl Stored {
    pub fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|deadline| now >= deadline)
    }
}

/// Store a key, honouring the current `bitwarden.unlock` policy. `session`
/// means "do not persist": the caller keeps it in memory instead.
pub fn save(paths: &Paths, key: &str) -> Result<Option<i64>, String> {
    let policy = config::load(paths).bitwarden;
    if policy.mode_is_session() {
        clear(paths);
        return Err("bitwarden.unlock is \"session\": the key is kept in the agent, not on disk".into());
    }
    let now = now_ms();
    let expires_at = match policy.unlock {
        UnlockMode::Never => None,
        UnlockMode::Time => Some(now + policy.hours.clamp(1, 24 * 90) * 3_600_000),
        UnlockMode::Session => None,
    };
    let stored = Stored { saved_at: now, expires_at, key: key.to_string() };
    let bytes = serde_json::to_vec(&stored).map_err(|e| format!("cannot serialize session: {e}"))?;
    crypto::write_atomic(&paths.bw_session(), &bytes)?;
    let _ = fs::set_permissions(paths.bw_session(), fs::Permissions::from_mode(0o600));
    Ok(expires_at)
}

pub fn load(paths: &Paths) -> Result<Option<Stored>, String> {
    let path = paths.bw_session();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let stored: Stored = match serde_json::from_str(&text) {
        Ok(stored) => stored,
        Err(_) => {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
    };
    if stored.expired(now_ms()) {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    Ok(Some(stored))
}

pub fn clear(paths: &Paths) -> bool {
    fs::remove_file(paths.bw_session()).is_ok()
}

impl config::BitwardenPolicy {
    pub fn mode_is_session(&self) -> bool {
        self.unlock == UnlockMode::Session
    }
}

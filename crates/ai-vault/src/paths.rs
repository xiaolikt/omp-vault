//! Where the store, its sessions and its audit log live.

use std::env;
use std::path::{Path, PathBuf};

/// Idle time after which a session token stops working.
pub const IDLE_MS_DEFAULT: i64 = 10 * 60 * 1000;
/// Default lifetime of a read grant.
pub const GRANT_MS_DEFAULT: i64 = 5 * 60 * 1000;
/// Longest grant a caller may ask for.
pub const GRANT_MS_MAX: i64 = 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    /// `--dir`, else `$AI_VAULT_DIR`, else `~/.ai-vault`.
    pub fn resolve(dir: Option<PathBuf>) -> Self {
        let dir = dir
            .or_else(|| env::var_os("AI_VAULT_DIR").map(PathBuf::from))
            .unwrap_or_else(|| home().join(".ai-vault"));
        Paths { dir }
    }

    pub fn store(&self) -> PathBuf {
        self.dir.join("store.json")
    }

    pub fn audit(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    /// Shared advisory lock for read-modify-write of the store file.
    pub fn store_lock(&self) -> PathBuf {
        self.dir.join("store.lock")
    }

    /// Session tokens hold key material, so they prefer tmpfs when there is one:
    /// they vanish at logout instead of lying on disk.
    pub fn sessions(&self) -> PathBuf {
        match env::var_os("XDG_RUNTIME_DIR") {
            Some(runtime) if !runtime.is_empty() && self.dir == Paths::resolve(None).dir => {
                PathBuf::from(runtime).join("ai-vault").join("sessions")
            }
            _ => self.dir.join("sessions"),
        }
    }

    pub fn session_file(&self, token: &str) -> PathBuf {
        self.sessions().join(format!("{token}.json"))
    }
}

pub fn home() -> PathBuf {
    env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| Path::new(".").to_path_buf())
}

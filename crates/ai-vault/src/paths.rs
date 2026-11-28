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

    /// Unlock policy (mode and, for `time`, the number of hours).
    pub fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    /// The machine-wide token `never` mode keeps, so no prompt is ever needed.
    pub fn auto_session(&self) -> PathBuf {
        self.dir.join("agent.session.json")
    }

    /// Random 256-bit key that seals the Bitwarden session at rest, so that
    /// file alone is not a bearer token. Same exposure as the store itself.
    pub fn wrap_key(&self) -> PathBuf {
        self.dir.join(".wrap")
    }

    /// Shared advisory lock for read-modify-write of the store file.
    pub fn store_lock(&self) -> PathBuf {
        self.dir.join("store.lock")
    }

    /// Session tokens hold key material, so they prefer a tmpfs when there is
    /// one: they vanish at logout instead of lying on disk.
    ///
    ///   Linux   $XDG_RUNTIME_DIR (a tmpfs)
    ///   macOS   $TMPDIR (per-user, cleaned by the OS)
    ///   Windows %TEMP% (per-user)
    pub fn sessions(&self) -> PathBuf {
        if self.dir != Paths::resolve(None).dir {
            return self.dir.join("sessions");
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
                return PathBuf::from(runtime).join("ai-vault").join("sessions");
            }
            return self.dir.join("sessions");
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            env::temp_dir().join("ai-vault").join("sessions")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.dir.join("sessions")
        }
    }

    pub fn session_file(&self, token: &str) -> PathBuf {
        self.sessions().join(format!("{token}.json"))
    }
}

pub fn home() -> PathBuf {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    env::var_os(key)
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| Path::new(".").to_path_buf())
}

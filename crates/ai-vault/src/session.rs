//! Session tokens: how a caller keeps the store open without ever holding the
//! master password.
//!
//! `ai-vault unlock` derives the key, writes a token file (0600, under tmpfs
//! when there is one) and prints the token. Every later call presents the
//! token; the key is read from that file, never from the command line. A token
//! dies on `lock`, after `idleMs` without use, or when the store file changes
//! underneath it.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Kdf};
use crate::paths::Paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    #[serde(default)]
    pub requester: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "lastActive")]
    pub last_active: i64,
    #[serde(rename = "idleMs")]
    pub idle_ms: i64,
    #[serde(rename = "storeId")]
    pub store_id: String,
    pub salt: String,
    #[serde(default)]
    pub kdf: Option<Kdf>,
    pub key: String,
    /// entry name (lowercase) -> grant expiry epoch ms
    #[serde(default)]
    pub grants: BTreeMap<String, i64>,
}

impl Session {
    pub fn new(requester: &str, idle_ms: i64, store: &crypto::StoreFile, key: &[u8; 32]) -> Self {
        let now = now_ms();
        Session {
            token: crate::store::random_id() + &crate::store::random_id(),
            requester: requester.to_string(),
            created_at: now,
            last_active: now,
            idle_ms,
            store_id: crypto::store_id(store),
            salt: store.salt.clone(),
            kdf: Some(store.kdf()),
            key: B64.encode(key),
            grants: BTreeMap::new(),
        }
    }

    pub fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        let raw = B64.decode(self.key.as_bytes()).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw);
        Some(key)
    }

    pub fn expired(&self, now: i64) -> bool {
        now.saturating_sub(self.last_active) >= self.idle_ms
    }

    pub fn expires_at(&self) -> i64 {
        self.last_active + self.idle_ms
    }

    /// Drop grants that ran out. Returns true when anything was removed.
    pub fn prune_grants(&mut self, now: i64) -> bool {
        let before = self.grants.len();
        self.grants.retain(|_, until| *until > now);
        before != self.grants.len()
    }

    pub fn grant(&self, name: &str, now: i64) -> Option<i64> {
        self.grants
            .get(&name.to_lowercase())
            .copied()
            .filter(|until| *until > now)
    }

    pub fn save(&self, paths: &Paths) -> Result<(), String> {
        let dir = paths.sessions();
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        let text = serde_json::to_vec(self).map_err(|e| format!("cannot serialize session: {e}"))?;
        crypto::write_atomic(&paths.session_file(&self.token), &text)
    }
}

/// Load a token for the given store. Missing, expired, or stale tokens are
/// removed and reported as locked so the caller unlocks again.
pub fn load(paths: &Paths, token: &str) -> Result<Session, String> {
    let path = paths.session_file(token);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("vault is locked (no unlock in this session)".into())
        }
        Err(e) => return Err(format!("cannot read session {}: {e}", path.display())),
    };
    let session: Session = serde_json::from_str(&text)
        .map_err(|_| "session token is corrupt — unlock again".to_string())?;
    let now = now_ms();
    if session.expired(now) {
        let _ = fs::remove_file(&path);
        return Err("vault locked itself after 10 minutes idle — unlock again".into());
    }
    let store = crypto::read_store(&paths.store())?.ok_or_else(|| "vault is not initialized".to_string())?;
    if crypto::store_id(&store) != session.store_id || session.key().is_none() {
        let _ = fs::remove_file(&path);
        return Err("the store changed since this session unlocked — unlock again".into());
    }
    Ok(session)
}

pub fn delete(paths: &Paths, token: &str) -> bool {
    fs::remove_file(paths.session_file(token)).is_ok()
}

pub fn delete_all(paths: &Paths) -> usize {
    let dir = paths.sessions();
    let mut removed = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Remove tokens that already expired, so a tmpfs-less machine does not keep
/// dead keys around. Called on unlock and lock.
pub fn sweep(paths: &Paths) -> usize {
    let dir = paths.sessions();
    let mut removed = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stale = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Session>(&text).ok())
                .map(|s| s.expired(now_ms()))
                .unwrap_or(true);
            if stale && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn ensure_session_dir(paths: &Paths) -> Result<(), String> {
    fs::create_dir_all(&paths.dir).map_err(|e| format!("cannot create {}: {e}", paths.dir.display()))?;
    let dir = paths.sessions();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let _ = fs::set_permissions(&paths.dir, fs::Permissions::from_mode(0o700));
    Ok(())
}

/// Held for the duration of a read-modify-write so two agents cannot overwrite
/// each other's entries. Never held across a dialog.
pub struct StoreLock {
    file: fs::File,
    path: std::path::PathBuf,
}

impl StoreLock {
    pub fn acquire(paths: &Paths) -> Result<Self, String> {
        ensure_session_dir(paths)?;
        let path = paths.store_lock();
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(format!("cannot lock {}: {}", path.display(), std::io::Error::last_os_error()));
            }
        }
        Ok(StoreLock { file, path })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        let _ = &self.path;
    }
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreLock({})", self.path.display())
    }
}

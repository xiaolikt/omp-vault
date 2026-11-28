//! Session tokens: how a caller keeps the store open without ever holding the
//! master password.
//!
//! `ai-vault unlock` derives the key, writes a token file (0600, under tmpfs
//! when there is one) and prints the token. Every later call presents the
//! token; the key is read from that file, never from the command line. A token
//! dies on `lock`, after `idleMs` without use, or when the store file changes
//! underneath it.
//!
//! Two things a same-user process must NOT be able to do by editing these
//! files: mint a grant, and change who the confirm window says is asking.
//! Every session file therefore carries an HMAC over its whole body, keyed
//! with a secret that lives in the host process only (`hostSecret`, handed
//! back once at unlock time, never written to disk). A file that fails the
//! check is deleted and reported as locked.

use std::collections::BTreeMap;
use std::fs;

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
    /// Absolute deadline, ms epoch. `None` means "no deadline": the token lives
    /// until it is locked, its idle window passes, or the store changes.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expiresAt")]
    pub expires_at: Option<i64>,
    #[serde(rename = "storeId")]
    pub store_id: String,
    pub salt: String,
    #[serde(default)]
    pub kdf: Option<Kdf>,
    pub key: String,
    /// entry name (lowercase) -> grant expiry epoch ms
    #[serde(default)]
    pub grants: BTreeMap<String, i64>,
    /// HMAC-SHA256 over every field above (canonical JSON), keyed with the
    /// host secret. Absent only for the machine-wide `never` session, which is
    /// by definition not protected from this user.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mac")]
    pub mac: Option<String>,
    /// Which key signed `mac`: "host" (the extension's in-memory secret) or
    /// "wrap" (the store's key, for a human at a terminal). Verification uses
    /// the key actually named here, never whichever one happens to be in the
    /// environment — so a token created one way is not voided by a call made
    /// the other way.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "signedBy")]
    pub signed_by: Option<String>,
}


/// Who signs a session file: the host process's in-memory secret, or the
/// store's wrap key when a human runs `ai-vault` by hand.
pub enum Signer {
    Host(String),
    Wrap(String),
}

impl Signer {
    fn label(&self) -> &'static str {
        match self {
            Signer::Host(_) => "host",
            Signer::Wrap(_) => "wrap",
        }
    }

    fn hmac(&self, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        let key = match self {
            Signer::Host(k) | Signer::Wrap(k) => k.as_str(),
        };
        let mut hasher = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
        hasher.update(body);
        hasher.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn mac_body(session: &Session) -> Vec<u8> {
    // Same struct, `mac` blanked, canonical key order: serde_json::Value sorts
    // object keys, so the encoding is stable across runs.
    let mut value = serde_json::to_value(session).expect("session serializes");
    if let Some(record) = value.as_object_mut() {
        record.remove("mac");
    }
    value.to_string().into_bytes()
}

impl Session {
    pub fn new(requester: &str, idle_ms: i64, expires_at: Option<i64>, store: &crypto::StoreFile, key: &[u8; 32]) -> Self {
        let now = now_ms();
        Session {
            token: crate::store::random_id() + &crate::store::random_id(),
            requester: requester.to_string(),
            created_at: now,
            last_active: now,
            idle_ms,
            expires_at,
            store_id: crypto::store_id(store),
            salt: store.salt.clone(),
            kdf: Some(store.kdf()),
            key: B64.encode(key),
            grants: BTreeMap::new(),
            mac: None,
            signed_by: None,
        }
    }

    /// (Re)sign this session and record who signed it. Called before every save.
    pub fn sign(&mut self, signer: &Signer) {
        self.signed_by = Some(signer.label().to_string());
        let body = mac_body(self);
        self.mac = Some(signer.hmac(&body));
    }

    /// True when the file was written by whoever it says signed it, checked
    /// with *that* key — never whichever one happens to be in the environment.
    pub fn verifies(&self, host_secret: Option<&str>, wrap_key: Option<&str>) -> bool {
        let Some(mac) = self.mac.as_deref() else {
            // The only legitimate unsigned session is the machine-wide one,
            // which is protected by the directory instead.
            return host_secret.is_none() && wrap_key.is_none();
        };
        let key: &str = match self.signed_by.as_deref() {
            Some("host") => match host_secret {
                Some(k) => k,
                None => return false,
            },
            Some("wrap") => match wrap_key {
                Some(k) => k,
                None => return false,
            },
            // A file from before `signedBy`: accept whichever key fits.
            _ => match host_secret.or(wrap_key) {
                Some(k) => k,
                None => return false,
            },
        };
        use hmac::{Hmac, Mac};
        let Ok(mut hasher) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key.as_bytes()) else {
            return false;
        };
        hasher.update(&mac_body(self));
        let expected: String = hasher.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        expected.len() == mac.len()
            && expected.bytes().zip(mac.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
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

    /// A deadline beats the idle window; `idleMs: 0` with no deadline means
    /// "never expires on its own".
    pub fn expired(&self, now: i64) -> bool {
        if let Some(deadline) = self.expires_at {
            return now >= deadline;
        }
        self.idle_ms > 0 && now.saturating_sub(self.last_active) >= self.idle_ms
    }

    /// When this token stops working, if it does.
    pub fn expiry(&self) -> Option<i64> {
        self.expires_at.or_else(|| (self.idle_ms > 0).then_some(self.last_active + self.idle_ms))
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

    pub fn save(&self, paths: &Paths, signer: &Signer) -> Result<(), String> {
        let mut signed = self.clone();
        signed.sign(signer);
        let dir = paths.sessions();
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        crate::perms::restrict_dir(&dir);
        let text = serde_json::to_vec(&signed).map_err(|e| format!("cannot serialize session: {e}"))?;
        crypto::write_atomic(&paths.session_file(&signed.token), &text)
    }
}

/// Load a token for the given store. Missing, expired, or stale tokens are
/// removed and reported as locked so the caller unlocks again.
pub fn load(paths: &Paths, token: &str, host_secret: Option<&str>, wrap_key: Option<&str>) -> Result<Session, String> {
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
        return Err("this session expired — unlock again".into());
    }
    // Edited on disk (a grant minted, a requester renamed): treat as a break-in
    // attempt, say so, and drop it.
    // Only a file this caller holds a key for is judged; one signed under a
    // key the caller does not have is simply not theirs to use (and is left
    // alone for whoever does hold that key).
    let has_key_for_it = match session.signed_by.as_deref() {
        Some("host") => host_secret.is_some(),
        Some("wrap") => wrap_key.is_some(),
        _ => host_secret.is_some() || wrap_key.is_some(),
    };
    if !has_key_for_it {
        return Err("this session belongs to another caller — unlock again".into());
    }
    if !session.verifies(host_secret, wrap_key) {
        let _ = fs::remove_file(&path);
        return Err("session file was modified outside ai-vault — unlock again".into());
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

/// Remove token files **of this store** that can no longer open anything:
/// expired, corrupt, or unsigned. Files naming another store are left alone:
/// several stores may share the sessions directory (two agents, two `--dir`s),
/// and one store's housekeeping must not lock the other's agents out.
pub fn sweep(paths: &Paths) -> usize {
    let Some(current) = crypto::read_store(&paths.store()).ok().flatten().map(|store| crypto::store_id(&store)) else {
        return 0;
    };
    let dir = paths.sessions();
    let mut removed = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let dead = match fs::read_to_string(&path).ok().and_then(|text| serde_json::from_str::<Session>(&text).ok()) {
                // Unparseable junk opens nothing; drop it.
                None => true,
                // Only this store's files are ours to judge. Another store's
                // live token is none of our business.
                Some(session) => {
                    session.store_id == current && (session.expired(now_ms()) || session.mac.is_none())
                }
            };
            if dead && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// The machine-wide token used by `never` mode: no deadline, stored next to
/// the store so it survives reboots. Any process running as this user can read
/// it — that is the whole point of the mode.
pub fn load_auto(paths: &Paths) -> Result<Option<Session>, String> {
    let path = paths.auto_session();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let session: Session = match serde_json::from_str(&text) {
        Ok(session) => session,
        Err(_) => {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
    };
    if session.expired(now_ms()) {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    if session.key().is_none() {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    Ok(Some(session))
}

pub fn save_auto(paths: &Paths, session: &Session) -> Result<(), String> {
    fs::create_dir_all(&paths.dir).map_err(|e| format!("cannot create {}: {e}", paths.dir.display()))?;
    crate::perms::restrict_dir(&paths.dir);
    let bytes = serde_json::to_vec(session).map_err(|e| format!("cannot serialize session: {e}"))?;
    crypto::write_atomic(&paths.auto_session(), &bytes)
}

pub fn delete_auto(paths: &Paths) -> bool {
    fs::remove_file(paths.auto_session()).is_ok()
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn ensure_session_dir(paths: &Paths) -> Result<(), String> {
    fs::create_dir_all(&paths.dir).map_err(|e| format!("cannot create {}: {e}", paths.dir.display()))?;
    let dir = paths.sessions();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    crate::perms::restrict_dir(&dir);
    crate::perms::restrict_dir(&paths.dir);
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
            .open(&path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        crate::perms::restrict_file(&path);
        // fs4 takes an OS lock on Unix (flock), Windows (LockFileEx) and macOS.
        <fs::File as fs4::fs_std::FileExt>::lock_exclusive(&file)
            .map_err(|e| format!("cannot lock {}: {e}", path.display()))?;
        Ok(StoreLock { file, path })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = <fs::File as fs4::fs_std::FileExt>::unlock(&self.file);
        let _ = &self.path;
    }
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StoreLock({})", self.path.display())
    }
}

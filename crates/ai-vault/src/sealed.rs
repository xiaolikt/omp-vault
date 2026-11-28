//! Secrets kept on disk for `*.unlock = never | time`: the `bw` session key
//! and Ente's `ENTE_CLI_VAULT_KEY`.
//!
//! `bw unlock` hands back a bearer key for the *whole* Bitwarden vault, so the
//! file is sealed: ChaCha20-Poly1305 under a random 256-bit key in
//! `<dir>/.wrap` (0600, same directory and owner as the store). Copying the
//! session file away therefore yields nothing; it opens only together with
//! the directory that already holds the ai-vault store. It is never printed
//! unless `bw-session get` is asked for it.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};

use crate::config::{self, UnlockMode};
use crate::crypto;
use crate::paths::Paths;
use crate::session::now_ms;

/// Which secret this file holds. They are sealed the same way but carry
/// different names and different policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bitwarden,
    Ente,
}

impl Kind {
    fn file(self) -> &'static str {
        match self {
            Kind::Bitwarden => "bitwarden.session.json",
            Kind::Ente => "ente.session.json",
        }
    }

    fn policy(self, config: &config::Config) -> config::StorePolicy {
        match self {
            Kind::Bitwarden => config.bitwarden.store,
            Kind::Ente => config.ente,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    #[serde(rename = "savedAt")]
    pub saved_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expiresAt")]
    pub expires_at: Option<i64>,
    /// base64(iv(12) || ciphertext || tag(16)) of the key, under the wrap key.
    pub sealed: String,
}

/// Load the wrap key, creating it on first use. It is a plain random file:
/// its protection is the directory (0700) and the owner, like the store.
fn wrap_key(paths: &Paths) -> Result<crypto::Key, String> {
    let path = paths.wrap_key();
    match fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = crypto::Key::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        Ok(_) => {
            // Wrong size: corrupt or foreign. Replace rather than fail; the
            // only thing it protects is a session that can be re-unlocked.
            let _ = fs::remove_file(&path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    }
    let fresh = crypto::random_bytes::<32>();
    fs::create_dir_all(&paths.dir).map_err(|e| format!("cannot create {}: {e}", paths.dir.display()))?;
    let _ = fs::set_permissions(&paths.dir, fs::Permissions::from_mode(0o700));
    crypto::write_atomic(&path, &fresh)?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(crypto::Key::new(fresh))
}

/// The wrap key as hex, for signing a non-host session file.
pub fn wrap_key_hex(paths: &Paths) -> Result<String, String> {
    let key = wrap_key(paths)?;
    Ok(key.iter().map(|b| format!("{b:02x}")).collect())
}

fn seal(wrap: &crypto::Key, plain: &str) -> Result<String, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let iv = crypto::random_bytes::<12>();
    let cipher = ChaCha20Poly1305::new_from_slice(wrap.as_ref()).map_err(|e| format!("wrap key: {e}"))?;
    let body = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_bytes())
        .map_err(|_| "cannot seal session".to_string())?;
    let mut blob = Vec::with_capacity(12 + body.len());
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&body);
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

fn unseal(wrap: &crypto::Key, sealed: &str) -> Result<String, String> {
    use base64::Engine as _;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    let blob = base64::engine::general_purpose::STANDARD
        .decode(sealed.as_bytes())
        .map_err(|_| "sealed session is not base64".to_string())?;
    if blob.len() < 12 + 16 {
        return Err("sealed session is truncated".into());
    }
    let (iv, body) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(wrap.as_ref()).map_err(|e| format!("wrap key: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(iv), body)
        .map_err(|_| "sealed session does not open under the wrap key".to_string())
        .and_then(|plain| String::from_utf8(plain).map_err(|_| "sealed session is not UTF-8".to_string()))
}

impl Stored {
    pub fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|deadline| now >= deadline)
    }
}

/// Store a key, honouring the current `bitwarden.unlock` policy. `session`
/// means "do not persist": the caller keeps it in memory instead.
pub fn save(paths: &Paths, kind: Kind, secret: &str) -> Result<Option<i64>, String> {
    let config = config::load(paths);
    let policy = kind.policy(&config);
    if policy.unlock == UnlockMode::Session {
        clear(paths, kind);
        return Err(format!(
            "{}.unlock is \"session\": nothing is kept on disk",
            match kind {
                Kind::Bitwarden => "bitwarden",
                Kind::Ente => "ente",
            }
        ));
    }
    let now = now_ms();
    let expires_at = match policy.unlock {
        UnlockMode::Never => None,
        UnlockMode::Time => Some(now + policy.hours.clamp(1, 24 * 90) * 3_600_000),
        UnlockMode::Session => None,
    };
    let wrap = wrap_key(paths)?;
    let stored = Stored { saved_at: now, expires_at, sealed: seal(&wrap, secret)? };
    let bytes = serde_json::to_vec(&stored).map_err(|e| format!("cannot serialize session: {e}"))?;
    let path = paths.dir.join(kind.file());
    crypto::write_atomic(&path, &bytes)?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(expires_at)
}

pub fn load(paths: &Paths, kind: Kind) -> Result<Option<Stored>, String> {
    let path = paths.dir.join(kind.file());
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

/// The session key itself, or an error naming why it cannot be opened.
pub fn key(paths: &Paths, kind: Kind) -> Result<Option<String>, String> {
    match load(paths, kind)? {
        None => Ok(None),
        Some(stored) => {
            let wrap = wrap_key(paths)?;
            unseal(&wrap, &stored.sealed).map(Some)
        }
    }
}

pub fn clear(paths: &Paths, kind: Kind) -> bool {
    fs::remove_file(paths.dir.join(kind.file())).is_ok()
}

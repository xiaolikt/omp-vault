//! Encryption at rest and the on-disk store format.
//!
//! store.json:
//!   { "v": 1, "salt": "<hex>", "kdf": { "N", "r", "p" },
//!     "ct": "<base64 iv(12) || ciphertext || tag(16)>" }
//!
//! Sealed with ChaCha20-Poly1305 (RFC 8439) after scrypt(passphrase, salt).
//! Identical to the format the TypeScript release used, so an existing store
//! opens without a migration step.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::store::Item;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Kdf {
    #[serde(rename = "N")]
    pub n: u32,
    pub r: u32,
    pub p: u32,
}

impl Default for Kdf {
    /// 128 MiB of scrypt memory per guess. Files written before this carried
    /// N=2^15 (32 MiB); they open unchanged because the parameters travel in
    /// the file header, and `ai-vault rekey` moves them up.
    fn default() -> Self {
        Kdf { n: 1 << 17, r: 8, p: 1 }
    }
}

/// The weakest KDF a file may carry and still be accepted: the old default.
/// Anything below it is a downgrade, not a legacy file.
pub const KDF_FLOOR: Kdf = Kdf { n: 1 << 15, r: 8, p: 1 };

fn at_or_above_floor(kdf: Kdf) -> bool {
    kdf.n >= KDF_FLOOR.n && kdf.r >= KDF_FLOOR.r && kdf.p >= KDF_FLOOR.p
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreFile {
    pub v: u32,
    pub salt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    pub ct: String,
}

impl StoreFile {
    pub fn kdf(&self) -> Kdf {
        self.kdf.unwrap_or_default()
    }
}

#[derive(Debug)]
pub enum OpenError {
    /// Wrong master password (the AEAD tag did not verify).
    WrongPassword,
    /// Right password, but the file is not a store this version understands.
    Broken(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::WrongPassword => write!(f, "wrong master password"),
            OpenError::Broken(msg) => write!(f, "{msg}"),
        }
    }
}

pub type Key = Zeroizing<[u8; 32]>;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("the OS random generator must work");
    buf
}

/// scrypt(passphrase, salt, N/r/p) -> 32-byte key.
pub fn derive_key(passphrase: &str, salt: &[u8], kdf: Kdf) -> Result<Key, OpenError> {
    if !at_or_above_floor(kdf) {
        return Err(OpenError::Broken("vault KDF parameters are below the supported minimum".into()));
    }
    let log_n = u8::try_from(kdf.n.trailing_zeros()).map_err(|_| OpenError::Broken("bad KDF parameters".into()))?;
    if kdf.n == 0 || (1u32 << log_n) != kdf.n {
        return Err(OpenError::Broken("bad KDF parameters".into()));
    }
    let params = scrypt::Params::new(log_n, kdf.r, kdf.p, 32)
        .map_err(|e| OpenError::Broken(format!("bad KDF parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, key.as_mut())
        .map_err(|e| OpenError::Broken(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Fingerprint of the store's salt: it changes only when the vault is
/// re-created, so a session token from before that is rejected instead of
/// decrypting garbage. (It must not cover the ciphertext: every save rewrites
/// that.)
pub fn store_id(store: &StoreFile) -> String {
    let mut hasher = Sha256::new();
    hasher.update(store.salt.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(12).map(|b| format!("{b:02x}")).collect()
}

pub fn seal(salt: &[u8], kdf: Kdf, key: &[u8; 32], items: &[Item]) -> Result<StoreFile, String> {
    let plaintext = serde_json::to_vec(items).map_err(|e| format!("cannot serialize vault: {e}"))?;
    let iv = random_bytes::<12>();
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("bad key: {e}"))?;
    let body = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_ref())
        .map_err(|_| "encryption failed".to_string())?;
    let mut blob = Vec::with_capacity(12 + body.len());
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&body);
    Ok(StoreFile {
        v: 1,
        salt: salt.iter().map(|b| format!("{b:02x}")).collect(),
        kdf: Some(kdf),
        ct: B64.encode(blob),
    })
}

pub fn open_with_key(store: &StoreFile, key: &[u8; 32]) -> Result<Vec<Item>, OpenError> {
    if store.v != 1 {
        return Err(OpenError::Broken("unsupported vault format".into()));
    }
    let blob = B64
        .decode(store.ct.as_bytes())
        .map_err(|_| OpenError::Broken("vault file is not valid base64".into()))?;
    if blob.len() < 12 + 16 {
        return Err(OpenError::Broken("vault file is truncated".into()));
    }
    let (iv, body) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| OpenError::Broken("bad key".into()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(iv), body)
        .map_err(|_| OpenError::WrongPassword)?;
    serde_json::from_slice(&plaintext).map_err(|_| OpenError::Broken("vault contents are not a list of entries".into()))
}

pub fn open_with_passphrase(store: &StoreFile, passphrase: &str) -> Result<(Vec<Item>, Key), OpenError> {
    let salt = hex_to_bytes(&store.salt).ok_or_else(|| OpenError::Broken("vault salt is not hex".into()))?;
    let key = derive_key(passphrase, &salt, store.kdf())?;
    let items = open_with_key(store, &key)?;
    Ok((items, key))
}

pub fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

pub fn read_store(path: &Path) -> Result<Option<StoreFile>, String> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("cannot parse {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Write through a temp file, fsync it, rename, then fsync the directory.
/// Mode is 0600 from the moment the temp file exists.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    crate::perms::restrict_dir(dir);

    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("store.json"),
        std::process::id(),
        B64.encode(random_bytes::<6>()).replace(['/', '+', '='], "")
    ));
    let mut file = crate::perms::open_private(&tmp)
        .map_err(|e| format!("cannot create a temp file next to {}: {e}", path.display()))?;
    let outcome = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = outcome {
        let _ = fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", path.display()));
    }
    crate::perms::sync_dir(dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Draft;

    fn sample() -> Vec<Item> {
        let mut items = Vec::new();
        crate::store::apply(
            &mut items,
            Draft {
                name: "GitHub".into(),
                username: Some("octo".into()),
                password: "hunter2".into(),
                uris: Some(vec!["https://github.com".into()]),
                ..Default::default()
            },
            "2026-01-01T00:00:00.000Z",
        );
        items
    }

    /// The old cost, so the tests below stay fast; correctness is the same.
    fn fast() -> Kdf {
        KDF_FLOOR
    }

    #[test]
    fn round_trip() {
        let salt = random_bytes::<16>();
        let kdf = fast();
        let key = derive_key("correct horse", &salt, kdf).unwrap();
        let sealed = seal(&salt, kdf, &key, &sample()).unwrap();
        let opened = open_with_key(&sealed, &key).unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].password, "hunter2");
        let (again, _) = open_with_passphrase(&sealed, "correct horse").unwrap();
        assert_eq!(again[0].username.as_deref(), Some("octo"));
    }

    #[test]
    fn wrong_password_is_distinguishable() {
        let salt = random_bytes::<16>();
        let kdf = fast();
        let key = derive_key("right", &salt, kdf).unwrap();
        let sealed = seal(&salt, kdf, &key, &sample()).unwrap();
        assert!(matches!(open_with_passphrase(&sealed, "wrong"), Err(OpenError::WrongPassword)));
    }

    #[test]
    fn each_seal_uses_a_fresh_iv() {
        let salt = random_bytes::<16>();
        let key = derive_key("pw", &salt, fast()).unwrap();
        let a = seal(&salt, fast(), &key, &sample()).unwrap();
        let b = seal(&salt, fast(), &key, &sample()).unwrap();
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn refuses_a_downgraded_kdf() {
        let weak = Kdf { n: 1 << 12, r: 8, p: 1 };
        assert!(matches!(derive_key("pw", &random_bytes::<16>(), weak), Err(OpenError::Broken(_))));
        assert_eq!(Kdf::default().n, 1 << 17);
    }

    #[test]
    fn parses_the_typescript_format() {
        // Written by the TS release, with the default KDF.
        let salt = "00112233445566778899aabbccddeeff";
        let key = derive_key("pw", &hex_to_bytes(salt).unwrap(), fast()).unwrap();
        let sealed = seal(&hex_to_bytes(salt).unwrap(), fast(), &key, &sample()).unwrap();
        let json = serde_json::json!({ "v": 1, "salt": salt, "kdf": { "N": 32768, "r": 8, "p": 1 }, "ct": sealed.ct });
        let store: StoreFile = serde_json::from_value(json).unwrap();
        assert_eq!(open_with_passphrase(&store, "pw").unwrap().0[0].name, "GitHub");
    }
}

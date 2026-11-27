//! Append-only JSONL audit log, rotated at 1 MiB.
//!
//! Records who asked for what, never a value. A full or read-only disk is not
//! allowed to break the operation being audited.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub session: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub fn append(path: &Path, session: &str, event: &str, item: Option<&str>, reason: Option<&str>) -> bool {
    let entry = Entry {
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        session: session.to_string(),
        event: event.to_string(),
        item: item.map(|s| s.to_string()),
        reason: reason.map(|s| s.to_string()),
    };
    let line = match serde_json::to_string(&entry) {
        Ok(line) => line,
        Err(_) => return false,
    };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() > MAX_BYTES {
            let _ = fs::rename(path, path.with_extension("log.1"));
        }
    }
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            file.write_all(format!("{line}\n").as_bytes())
        });
    result.is_ok()
}

/// The last `limit` parseable entries, oldest first.
pub fn read(path: &Path, limit: usize) -> Vec<Entry> {
    if limit == 0 {
        return Vec::new();
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    let mut entries: Vec<Entry> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    if entries.len() > limit {
        entries = entries.split_off(entries.len() - limit);
    }
    entries
}

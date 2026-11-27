//! The decrypted contents of the store: a plain array of entries, in the same
//! shape the TypeScript version used, so an existing store.json still reads.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Source {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default)]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uris: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

/// Metadata only: what `list` shows. The password is left out.
#[derive(Debug, Serialize)]
pub struct ItemSummary {
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        ItemSummary {
            name: item.name.clone(),
            username: item.username.clone(),
            uris: item.uris.clone().unwrap_or_default(),
            updated_at: item.updated_at.clone(),
        }
    }
}

/// One entry to insert or merge, from `ai-vault add`, `save`, or an import.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub uris: Option<Vec<String>>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub source: Option<Source>,
}

pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn random_id() -> String {
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn find<'a>(items: &'a [Item], name: &str) -> Option<&'a Item> {
    let lower = name.to_lowercase();
    items.iter().find(|i| i.name.to_lowercase() == lower)
}

pub fn remove(items: &mut Vec<Item>, name: &str) -> bool {
    let lower = name.to_lowercase();
    match items.iter().position(|i| i.name.to_lowercase() == lower) {
        Some(idx) => {
            items.remove(idx);
            true
        }
        None => false,
    }
}

/// An entry is matched by local id, else by its import source, else by name.
/// Returns `true` when a new entry was pushed.
pub fn apply(items: &mut Vec<Item>, draft: Draft, now: &str) -> bool {
    let lower = draft.name.to_lowercase();
    let existing_idx = if let Some(id) = draft.id.as_deref() {
        items.iter().position(|i| i.id == id)
    } else {
        let by_source = draft.source.as_ref().and_then(|source| {
            items
                .iter()
                .position(|i| i.source.as_ref().is_some_and(|s| s.kind == source.kind && s.id == source.id))
        });
        by_source.or_else(|| items.iter().position(|i| i.name.to_lowercase() == lower))
    };

    if let Some(idx) = existing_idx {
        let before = items[idx].name.clone();
        // Matched by source under a new name: keep the old one if another
        // entry already carries the new name.
        let keep_old_name = before != draft.name
            && items.iter().enumerate().any(|(i, other)| i != idx && other.name.to_lowercase() == lower);
        let item = &mut items[idx];
        item.name = draft.name.clone();
        if draft.username.is_some() {
            item.username = draft.username.clone();
        }
        if !draft.password.is_empty() {
            item.password = draft.password.clone();
        }
        if draft.uris.is_some() {
            item.uris = draft.uris.clone();
        }
        if draft.notes.is_some() {
            item.notes = draft.notes.clone();
        }
        if draft.source.is_some() {
            item.source = draft.source.clone();
        }
        if keep_old_name {
            item.name = before;
        }
        item.updated_at = now.to_string();
        return false;
    }

    items.push(Item {
        id: draft.id.unwrap_or_else(random_id),
        name: draft.name,
        username: draft.username,
        password: draft.password,
        uris: draft.uris,
        notes: draft.notes,
        source: draft.source,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(name: &str, password: &str) -> Draft {
        Draft {
            name: name.into(),
            password: password.into(),
            ..Default::default()
        }
    }

    #[test]
    fn inserts_and_updates_by_name() {
        let mut items = Vec::new();
        assert!(apply(&mut items, draft("GitHub", "a"), "t1"));
        assert!(!apply(&mut items, draft("github", "b"), "t2"));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].password, "b");
        assert_eq!(items[0].created_at, "t1");
        assert_eq!(items[0].updated_at, "t2");
    }

    #[test]
    fn updates_by_source_after_a_rename() {
        let mut items = Vec::new();
        let mut first = draft("GitHub", "a");
        first.source = Some(Source { kind: "bitwarden".into(), id: "abc".into() });
        apply(&mut items, first, "t1");
        let mut renamed = draft("GitHub Personal", "a2");
        renamed.source = Some(Source { kind: "bitwarden".into(), id: "abc".into() });
        assert!(!apply(&mut items, renamed, "t2"));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "GitHub Personal");
        assert_eq!(items[0].password, "a2");
    }

    #[test]
    fn rename_does_not_steal_another_entrys_name() {
        let mut items = Vec::new();
        apply(&mut items, draft("A", "1"), "t");
        let mut second = draft("B", "2");
        second.source = Some(Source { kind: "bitwarden".into(), id: "x".into() });
        apply(&mut items, second, "t");
        let mut renamed = draft("A", "3");
        renamed.source = Some(Source { kind: "bitwarden".into(), id: "x".into() });
        apply(&mut items, renamed, "t");
        let names: Vec<_> = items.iter().map(|i| i.name.clone()).collect();
        assert_eq!(names, vec!["A", "B"]);
        assert_eq!(items[1].password, "3");
    }

    #[test]
    fn matches_case_insensitively() {
        let mut items = Vec::new();
        apply(&mut items, draft("GitHub", "a"), "t");
        assert!(find(&items, "github").is_some());
        assert!(remove(&mut items, "GITHUB"));
        assert!(items.is_empty());
    }
}

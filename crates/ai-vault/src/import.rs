//! Turning external payloads into entries: Bitwarden JSON exports and the
//! draft array the pi/omp extension sends after reading `bw`.

use serde_json::Value;

use crate::store::{Draft, Source};

const MAX_NAME: usize = 200;

fn as_uris(login: &serde_json::Map<String, Value>) -> Vec<String> {
    match login.get("uris").and_then(|u| u.as_array()) {
        Some(list) => list
            .iter()
            .filter_map(|entry| entry.get("uri").and_then(|u| u.as_str()))
            .filter(|uri| !uri.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    }
}

fn sanitized_name(raw: &str) -> String {
    let cleaned = raw.replace(['\r', '\n'], " ");
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return "unnamed".to_string();
    }
    cleaned.chars().take(MAX_NAME).collect()
}

/// Bitwarden export (array or `{ "items": [...] }`) -> drafts. Login items
/// without a password are skipped; names are sorted, then made unique with
/// `Name (2)`, `Name (3)`, … Each draft keeps its Bitwarden id so a re-import
/// updates the same row after a rename.
pub fn from_bitwarden(raw: &Value) -> Result<Vec<Draft>, String> {
    let items = match raw {
        Value::Array(items) => items,
        Value::Object(rec) => {
            if rec.get("encrypted").and_then(Value::as_bool) == Some(true) {
                return Err("This is an encrypted Bitwarden export. Use `bw export --format json` (unencrypted) or /vault import-bw.".into());
            }
            match rec.get("items") {
                Some(Value::Array(items)) => items,
                _ => return Err("Not a Bitwarden export: expected an array of items or an object with `items`.".into()),
            }
        }
        _ => return Err("Not a Bitwarden export: expected an array of items or an object with `items`.".into()),
    };

    let mut drafts: Vec<Draft> = Vec::new();
    for item in items {
        let Some(rec) = item.as_object() else { continue };
        let Some(login) = rec.get("login").and_then(Value::as_object) else { continue };
        let password = login.get("password").and_then(Value::as_str).unwrap_or("");
        if password.is_empty() {
            continue;
        }
        let username = rec
            .get("login")
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty())
            .map(str::to_string);
        let notes = rec
            .get("notes")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .map(str::to_string);
        let source = rec
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| Source { kind: "bitwarden".into(), id: id.to_string() });
        drafts.push(Draft {
            id: None,
            name: sanitized_name(rec.get("name").and_then(Value::as_str).unwrap_or("")),
            username,
            password: password.to_string(),
            uris: Some(as_uris(login)),
            notes,
            source,
        });
    }

    drafts.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.username.clone().unwrap_or_default().to_lowercase().cmp(&b.username.clone().unwrap_or_default().to_lowercase()))
            .then_with(|| {
                let ax = a.uris.as_ref().and_then(|u| u.first()).cloned().unwrap_or_default().to_lowercase();
                let bx = b.uris.as_ref().and_then(|u| u.first()).cloned().unwrap_or_default().to_lowercase();
                ax.cmp(&bx)
            })
    });
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in &mut drafts {
        let count = seen.entry(item.name.to_lowercase()).or_insert(0);
        *count += 1;
        if *count > 1 {
            item.name = format!("{} ({count})", item.name);
        }
    }
    Ok(drafts)
}

pub fn parse_bitwarden_json(text: &str) -> Result<Vec<Draft>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    from_bitwarden(&value)
}

/// The `save` payload: an array of drafts, or `{ "items": [...] }`.
pub fn parse_drafts(text: &str) -> Result<Vec<Draft>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let items = match value {
        Value::Array(items) => items,
        Value::Object(rec) => match rec.get("items") {
            Some(Value::Array(items)) => items.clone(),
            _ => return Err("expected a JSON array of entries".into()),
        },
        _ => return Err("expected a JSON array of entries".into()),
    };
    let mut drafts = Vec::with_capacity(items.len());
    for item in items {
        let draft: Draft = serde_json::from_value(item).map_err(|e| format!("bad entry: {e}"))?;
        if draft.name.trim().is_empty() {
            return Err("every entry needs a name".into());
        }
        drafts.push(draft);
    }
    Ok(drafts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_logins_without_a_password() {
        let raw = serde_json::json!([
            { "id": "1", "name": "Good", "login": { "username": "u", "password": "p", "uris": [{ "uri": "https://a" }] } },
            { "id": "2", "name": "NoPw", "login": { "username": "u" } },
            { "id": "3", "name": "Note only", "notes": "x" }
        ]);
        let drafts = from_bitwarden(&raw).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].name, "Good");
        assert_eq!(drafts[0].uris.as_ref().unwrap()[0], "https://a");
        assert_eq!(drafts[0].source.as_ref().unwrap().id, "1");
    }

    #[test]
    fn renames_duplicates_and_sorts() {
        let raw = serde_json::json!([
            { "name": "b", "login": { "password": "1" } },
            { "name": "b", "login": { "password": "2" } },
            { "name": "a", "login": { "password": "3" } }
        ]);
        let names: Vec<_> = from_bitwarden(&raw).unwrap().into_iter().map(|d| d.name).collect();
        assert_eq!(names, vec!["a", "b", "b (2)"]);
    }

    #[test]
    fn rejects_encrypted_exports() {
        let raw = serde_json::json!({ "encrypted": true, "data": "..." });
        assert!(from_bitwarden(&raw).unwrap_err().contains("encrypted"));
    }

    #[test]
    fn parses_draft_payloads() {
        let drafts = parse_drafts(r#"[{"name":"x","username":"u","password":"p","uris":["https://x"],"source":{"kind":"bitwarden","id":"9"}}]"#).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].source.as_ref().unwrap().id, "9");
    }
}

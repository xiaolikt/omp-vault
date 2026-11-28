//! Turning external payloads into entries: Bitwarden JSON exports and the
//! draft array the pi/omp extension sends after reading `bw`.

use serde_json::Value;

use crate::store::{Draft, Field, ItemType, Source};

const MAX_NAME: usize = 200;


fn sanitized_name(raw: &str) -> String {
    let cleaned = raw.replace(['\r', '\n'], " ");
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return "unnamed".to_string();
    }
    cleaned.chars().take(MAX_NAME).collect()
}

/// Bitwarden export (array or `{ "items": [...] }`) -> drafts, for every
/// item type, field for field. Login items without a password are still
/// imported (a PIN-only or passkey-only login is a login); a `name` is the
/// only thing an item must have. Names are sorted, then made unique with
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
        let kind = ItemType::from_code(rec.get("type").and_then(Value::as_u64).unwrap_or(1) as u8)
            .ok_or_else(|| format!("unsupported item type {}", rec.get("type").and_then(Value::as_u64).unwrap_or(0)))?;
        let source = rec
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| Source { kind: "bitwarden".into(), id: id.to_string() });

        // The type's own block, by Bitwarden's key and field names; unknown
        // keys are kept rather than dropped, so a newer CLI loses nothing.
        let mut data = serde_json::Map::new();
        if let Some(block) = rec.get(kind.data_key()).and_then(Value::as_object) {
            for (field, value) in block {
                if field == "uris" || field == "totp" && value.is_null() {
                    continue;
                }
                match value {
                    Value::String(text) if !text.is_empty() => {
                        data.insert(field.clone(), Value::String(text.clone()));
                    }
                    Value::Null => {}
                    other => {
                        data.insert(field.clone(), other.clone());
                    }
                }
            }
        }
        let uris = rec
            .get(kind.data_key())
            .and_then(|b| b.get("uris"))
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| entry.get("uri").and_then(Value::as_str))
                    .filter(|uri| !uri.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|list: &Vec<String>| !list.is_empty());

        let fields = rec.get("fields").and_then(Value::as_array).map(|list| {
            list.iter()
                .filter_map(|f| f.as_object())
                .map(|f| Field {
                    name: f.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
                    value: f.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
                    r#type: f.get("type").and_then(Value::as_u64).unwrap_or(0) as u8,
                    linked_id: f.get("linkedId").and_then(Value::as_u64).map(|n| n.to_string()),
                })
                .collect::<Vec<_>>()
        });

        let (username, password) = if kind == ItemType::Login {
            (
                data.get("username").and_then(Value::as_str).map(str::to_string),
                data.get("password").and_then(Value::as_str).unwrap_or("").to_string(),
            )
        } else {
            (None, String::new())
        };

        drafts.push(Draft {
            id: None,
            name: sanitized_name(rec.get("name").and_then(Value::as_str).unwrap_or("")),
            r#type: kind,
            username,
            password,
            uris,
            data: if data.is_empty() { None } else { Some(data) },
            notes: rec.get("notes").and_then(Value::as_str).filter(|n| !n.is_empty()).map(str::to_string),
            fields: fields.filter(|f: &Vec<Field>| !f.is_empty()),
            source,
        });
    }

    drafts.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.r#type.cmp(&b.r#type))
            .then_with(|| a.username.clone().unwrap_or_default().to_lowercase().cmp(&b.username.clone().unwrap_or_default().to_lowercase()))
    });
    let mut seen: std::collections::HashMap<(String, ItemType), usize> = std::collections::HashMap::new();
    for item in &mut drafts {
        let count = seen.entry((item.name.to_lowercase(), item.r#type)).or_insert(0);
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
    fn imports_every_item_including_passwordless_logins() {
        let raw = serde_json::json!([
            { "id": "1", "name": "Good", "login": { "username": "u", "password": "p", "uris": [{ "uri": "https://a" }] } },
            { "id": "2", "name": "PasskeyOnly", "type": 1, "login": { "username": "u" } },
            { "id": "3", "name": "Just a note", "type": 2, "secureNote": {}, "notes": "x" }
        ]);
        let mut drafts = from_bitwarden(&raw).unwrap();
        drafts.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(drafts.len(), 3, "a login without a password is still a login");
        let good = drafts.iter().find(|d| d.name == "Good").unwrap();
        assert_eq!(good.uris.as_ref().unwrap()[0], "https://a");
        assert_eq!(good.source.as_ref().unwrap().id, "1");
        let passkey = drafts.iter().find(|d| d.name == "PasskeyOnly").unwrap();
        assert_eq!(passkey.r#type, ItemType::Login);
        assert!(passkey.password.is_empty());
        let note = drafts.iter().find(|d| d.name == "Just a note").unwrap();
        assert_eq!(note.r#type, ItemType::SecureNote);
        assert_eq!(note.notes.as_deref(), Some("x"));
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

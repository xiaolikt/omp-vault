//! The decrypted contents of the store: a plain array of entries, in the same
//! shape the TypeScript version used, so an existing store.json still reads.

use serde::{Deserialize, Serialize};

/// The item types, numbered exactly as Bitwarden numbers them, so an import is
/// a copy and a manual entry is the same shape. `login` is what the store held
/// before types existed; a file without `type` is read as all-login.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemType {
    #[default]
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    /// Behind Bitwarden's "new item types" flag; stored the same way.
    BankAccount,
    DriversLicense,
    Passport,
}

impl ItemType {
    /// Bitwarden's `.type` number.
    pub fn code(self) -> u8 {
        match self {
            ItemType::Login => 1,
            ItemType::SecureNote => 2,
            ItemType::Card => 3,
            ItemType::Identity => 4,
            ItemType::SshKey => 5,
            ItemType::BankAccount => 6,
            ItemType::DriversLicense => 7,
            ItemType::Passport => 8,
        }
    }

    pub fn from_code(code: u8) -> Option<ItemType> {
        Some(match code {
            1 => ItemType::Login,
            2 => ItemType::SecureNote,
            3 => ItemType::Card,
            4 => ItemType::Identity,
            5 => ItemType::SshKey,
            6 => ItemType::BankAccount,
            7 => ItemType::DriversLicense,
            8 => ItemType::Passport,
            _ => return None,
        })
    }

    /// The key Bitwarden puts the type's own fields under.
    pub fn data_key(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::SecureNote => "secureNote",
            ItemType::Card => "card",
            ItemType::Identity => "identity",
            ItemType::SshKey => "sshKey",
            ItemType::BankAccount => "bankAccount",
            ItemType::DriversLicense => "driversLicense",
            ItemType::Passport => "passport",
        }
    }

    /// Every field of this type, in Bitwarden's order. A secure note has none
    /// of its own: its content is the item's `notes`.
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            ItemType::Login => &["username", "password", "totp"],
            ItemType::SecureNote => &[],
            ItemType::Card => &["cardholderName", "brand", "number", "expMonth", "expYear", "code"],
            ItemType::Identity => &[
                "title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city",
                "state", "postalCode", "country", "company", "email", "phone", "ssn", "username",
                "passportNumber", "licenseNumber",
            ],
            ItemType::SshKey => &["privateKey", "publicKey", "keyFingerprint"],
            ItemType::BankAccount => &[
                "bankName", "nameOnAccount", "accountType", "accountNumber", "routingNumber",
                "branchNumber", "pin", "swiftCode", "iban", "bankContactPhone",
            ],
            ItemType::DriversLicense => &[
                "firstName", "middleName", "lastName", "dateOfBirth", "licenseNumber", "issuingCountry",
                "issuingState", "issueDate", "expirationDate", "issuingAuthority", "licenseClass",
            ],
            ItemType::Passport => &[
                "surname", "givenName", "dateOfBirth", "sex", "birthPlace", "nationality", "issuingCountry",
                "passportNumber", "passportType", "nationalIdentificationNumber", "issuingAuthority",
                "issueDate", "expirationDate",
            ],
        }
    }

    /// The one field a human means by "the secret" of this type, when they
    /// read one entry with `get` or add one by hand. The others are in `data`.
    pub fn primary_field(self) -> Option<&'static str> {
        match self {
            ItemType::Login => Some("password"),
            ItemType::Card => Some("code"),
            ItemType::SshKey => Some("privateKey"),
            ItemType::BankAccount => Some("pin"),
            // A secure note's secret is its body; an identity's and a document's
            // are spread over many fields, so there is no single one to pick.
            _ => None,
        }
    }
}

/// A custom field, as Bitwarden stores it: 0 text, 1 hidden, 2 boolean, 3 linked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub r#type: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Source {
    pub kind: String,
    pub id: String,
}

/// One entry. The top of the struct is Bitwarden's item envelope; the type's
/// own fields live in `data`, and `notes` / `fields` are shared by every type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub name: String,
    #[serde(default = "default_item_type")]
    pub r#type: ItemType,
    /// Login only, kept at the top level too so `vault_get` and the old
    /// flat format agree; it mirrors `data.username`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Login only, same as `data.password`; empty for the other types.
    #[serde(default)]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uris: Option<Vec<String>>,
    /// The type's own fields, by Bitwarden's names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn default_item_type() -> ItemType {
    ItemType::Login
}

impl Item {
    /// Read one of the type's own fields.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.data.as_ref()?.get(name).and_then(|v| v.as_str())
    }

    /// Keep the flat login mirrors and the typed block in step.
    pub fn sync_login_mirrors(&mut self) {
        if self.r#type == ItemType::Login {
            let data = self.data.get_or_insert_with(serde_json::Map::new);
            if let Some(user) = &self.username {
                data.insert("username".into(), serde_json::Value::String(user.clone()));
            } else {
                data.remove("username");
            }
            data.insert("password".into(), serde_json::Value::String(self.password.clone()));
        } else {
            self.username = None;
            self.password = String::new();
        }
    }
}

/// Metadata only: what `list` shows. Every secret is left out: passwords,
/// card numbers and codes, keys, PINs, SSNs, and the value of any custom
/// field marked hidden. A secure note shows no body (the body *is* the secret).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ItemType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub uris: Vec<String>,
    /// Non-secret fields of the type, shown so a card or an identity can be
    /// told apart in a listing (cardholder, brand, expiry; name, email…).
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_notes: Option<bool>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        let mut fields = serde_json::Map::new();
        if let Some(data) = &item.data {
            for (key, value) in data {
                if !crate::cli::is_secret_field(item.r#type, key) && key != "username" && key != "password" {
                    if let Some(text) = value.as_str().filter(|t| !t.is_empty()) {
                        fields.insert(key.clone(), serde_json::Value::String(crate::dialog::for_dialog(text, 80)));
                    }
                }
            }
        }
        if let Some(custom) = &item.fields {
            for field in custom {
                // 1 = hidden in Bitwarden's field types
                if field.r#type != 1 && !field.value.is_empty() {
                    fields.insert(field.name.clone(), serde_json::Value::String(crate::dialog::for_dialog(&field.value, 80)));
                }
            }
        }
        ItemSummary {
            name: item.name.clone(),
            kind: item.r#type,
            username: item.username.clone(),
            uris: item.uris.clone().unwrap_or_default(),
            fields,
            has_notes: item.notes.as_ref().filter(|n| !n.is_empty()).map(|_| true),
            updated_at: item.updated_at.clone(),
        }
    }
}

/// One entry to insert or merge, from `ai-vault add`, `save`, or an import.
/// The same envelope as [`Item`]; a missing `type` means a login, which is
/// also how files written before types existed are read.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub r#type: ItemType,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub uris: Option<Vec<String>>,
    #[serde(default)]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
    #[serde(default)]
    pub source: Option<Source>,
}

impl Draft {
    /// Fill `data` from the flat login mirrors when a caller (the old `add`
    /// path, an old JSON payload) gave only `username`/`password`.
    pub fn normalise(mut self) -> Draft {
        if self.r#type == ItemType::Login {
            let data = self.data.get_or_insert_with(serde_json::Map::new);
            if let Some(user) = &self.username {
                data.entry("username").or_insert_with(|| serde_json::Value::String(user.clone()));
            }
            if !self.password.is_empty() {
                data.insert("password".into(), serde_json::Value::String(self.password.clone()));
            }
            if let Some(password) = data.get("password").and_then(|v| v.as_str()) {
                self.password = password.to_string();
            }
            if let Some(user) = data.get("username").and_then(|v| v.as_str()) {
                self.username = Some(user.to_string());
            }
        } else {
            // Only a login has the flat mirrors; for the rest the secret is in `data`.
            self.username = None;
            self.password = String::new();
        }
        self
    }

    /// The one value "the secret of this entry" means for its type, if there is one.
    pub fn primary_secret(&self) -> Option<String> {
        let field = self.r#type.primary_field()?;
        self.data.as_ref()?.get(field)?.as_str().map(str::to_string)
    }
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
    let draft = draft.normalise();
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
        item.r#type = draft.r#type;
        // A field the draft does not mention keeps its stored value; one it
        // mentions as null clears it. An empty `password` means "unchanged".
        if let Some(incoming) = draft.data {
            let data = item.data.get_or_insert_with(serde_json::Map::new);
            for (key, value) in incoming {
                if key == "password" && value.as_str() == Some("") {
                    continue;
                }
                if value.is_null() {
                    data.remove(&key);
                } else {
                    data.insert(key, value);
                }
            }
        }
        if draft.username.is_some() || draft.r#type != ItemType::Login {
            item.username = draft.username.clone();
        }
        if !draft.password.is_empty() || draft.r#type != ItemType::Login {
            item.password = draft.password.clone();
        }
        if draft.uris.is_some() {
            item.uris = draft.uris.clone();
        }
        if draft.notes.is_some() {
            item.notes = draft.notes.clone();
        }
        if draft.fields.is_some() {
            item.fields = draft.fields.clone();
        }
        if draft.source.is_some() {
            item.source = draft.source.clone();
        }
        if keep_old_name {
            item.name = before;
        }
        item.sync_login_mirrors();
        item.updated_at = now.to_string();
        return false;
    }

    let mut item = Item {
        id: draft.id.unwrap_or_else(random_id),
        name: draft.name,
        r#type: draft.r#type,
        username: draft.username,
        password: draft.password,
        uris: draft.uris,
        data: draft.data,
        notes: draft.notes,
        fields: draft.fields,
        source: draft.source,
        created_at: now.to_string(),
        updated_at: now.to_string(),
    };
    item.sync_login_mirrors();
    items.push(item);
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

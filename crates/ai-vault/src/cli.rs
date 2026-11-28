//! Command line surface. Every subcommand is one process: read the store,
//! prove the session token, do one thing, exit. The pi/omp extension calls
//! these commands and never links against the encryption itself.

use std::io::{self, BufRead, Read};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::sealed::{self, Kind};
use crate::config::{self, ImportPolicy, UnlockMode, UnlockPolicy};
use crate::crypto::{self, Kdf};
use crate::dialog::{self, Answer};
use crate::i18n::{tr, tr_owned};
use crate::import;
use crate::paths::{Paths, GRANT_MS_DEFAULT, GRANT_MS_MAX, IDLE_MS_DEFAULT};
use crate::session::{self, Session, StoreLock};
use crate::store::{Draft, Item, ItemType, self};
use crate::{audit, store::ItemSummary};

#[derive(Parser, Debug)]
#[command(
    name = "ai-vault",
    version,
    about = "Machine-wide encrypted secret store shared by AI coding agents",
    long_about = "One encrypted store per machine (~/.ai-vault), shared by every agent.\n\
                  The master password goes through a desktop dialog, never through the\n\
                  conversation. `unlock` returns a short-lived token; later calls pass it\n\
                  back with --token (or AI_VAULT_TOKEN)."
)]
struct Cli {
    /// Store directory (default: $AI_VAULT_DIR or ~/.ai-vault)
    #[arg(long, global = true, env = "AI_VAULT_DIR", value_name = "DIR")]
    dir: Option<PathBuf>,
    /// Machine-readable JSON on stdout
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print the store directory
    Path,
    /// Create the store and a fresh session (prompts for a new master password)
    Init {
        /// Read the password from stdin instead of a dialog
        #[arg(long)]
        password_stdin: bool,
        /// Who is unlocking (written to the audit log)
        #[arg(long, default_value = "cli")]
        requester: String,
        /// Idle minutes before the session locks itself
        #[arg(long, value_name = "MIN")]
        idle_min: Option<i64>,
    },
    /// Unlock the store and print a session token
    Unlock {
        /// Read the password from stdin instead of a dialog
        #[arg(long)]
        password_stdin: bool,
        /// Who is unlocking (written to the audit log and the confirm window)
        #[arg(long, default_value = "cli")]
        requester: String,
        /// Idle minutes before the session locks itself
        #[arg(long, value_name = "MIN")]
        idle_min: Option<i64>,
    },
    /// Show or change machine-wide settings
    Settings {
        /// Dotted key (vault.unlock, vault.hours, vault.confirm,
        /// bitwarden.unlock, bitwarden.hours, bitwarden.import, ente.*); omit
        /// to print everything
        key: Option<String>,
        /// New value; omit to print the current one
        value: Option<String>,
        /// Read the vault master password from stdin (for the changes that need it)
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// The persisted `bw` session key (bitwarden.unlock = never | time)
    BwSession {
        /// get | put | clear
        action: String,
        /// `put` reads the policy from the store, so it needs an unlocked session
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Ente's `ENTE_CLI_VAULT_KEY` (ente.unlock = never | time)
    EnteSession {
        /// get | put | clear
        action: String,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Show or change how often the master password is asked for
    Mode {
        /// "get" or "set"
        #[arg(default_value = "get")]
        action: String,
        /// never | time | session (for `set`)
        value: Option<String>,
        /// Hours between prompts in `time` mode
        #[arg(long, value_name = "HOURS")]
        hours: Option<i64>,
        /// Read the master password from stdin (changing the mode needs it)
        #[arg(long)]
        password_stdin: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Session state, item count, and remaining read grants
    Status {
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Drop one session token, or every session with --all
    Lock {
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Entry metadata only (name, username, URIs) — no passwords
    List {
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Read one entry; the user approves a window unless a grant is live
    Get {
        name: String,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
        /// Why the secret is needed (shown in the confirm window)
        #[arg(long)]
        reason: Option<String>,
        /// Read the approve/deny answer from stdin (host UI already asked).
        /// Requires AI_VAULT_HOST=1 and a matching --approval.
        #[arg(long)]
        answer_stdin: bool,
        /// HMAC-SHA256(hex) of "allow:<token>:<entry>:y|n" under the host
        /// secret, proving a host that holds the secret relayed the answer.
        #[arg(long, value_name = "HEX")]
        approval: Option<String>,
    },
    /// Create or update an entry of any type; the secret is typed in a dialog
    Add {
        #[arg(long)]
        name: String,
        /// login (default) | note | card | identity | sshkey | bankaccount | driverslicense | passport
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        uri: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// A field of the type, NAME=VALUE; repeatable. A field given as NAME
        /// alone, or any hidden field left out, is typed in a dialog (or sent
        /// on stdin for the primary one with --password-stdin).
        #[arg(long = "field", value_name = "NAME[=VALUE]")]
        fields: Vec<String>,
        /// A hidden field supplied by a host that already asked the user for
        /// it, NAME=VALUE; repeatable. Never printed, never in a window.
        #[arg(long = "secret", value_name = "NAME=VALUE")]
        secrets: Vec<String>,
        /// Read the secret from stdin instead of a dialog
        #[arg(long)]
        password_stdin: bool,
        /// Skip the "save this?" confirm window (the user already approved)
        #[arg(long)]
        yes: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Insert or update many entries from a JSON array on stdin (or --file)
    Save {
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
        #[arg(long, value_name = "FILE")]
        file: Option<PathBuf>,
        /// The caller already approved this write in its own UI
        #[arg(long)]
        yes: bool,
    },
    /// Delete one entry
    Remove {
        name: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Allow reads of one entry without a window for a while
    Grant {
        name: String,
        #[arg(long, value_name = "MIN")]
        minutes: Option<i64>,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// End grants for one entry, or all of them
    Revoke {
        name: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Recent audit lines (who asked for what)
    Audit {
        #[arg(default_value_t = 30)]
        n: usize,
    },
    /// Import a Bitwarden JSON export (array or { items: [...] })
    Import {
        file: PathBuf,
        #[arg(long)]
        yes: bool,
        #[arg(long, env = "AI_VAULT_TOKEN")]
        token: Option<String>,
    },
    /// Re-encrypt the store under the current default KDF (asks the master password)
    Rekey {
        #[arg(long)]
        password_stdin: bool,
    },
    /// Diagnose paths, session directory and desktop availability
    Doctor,
}

#[derive(Debug)]
enum Fault {
    Error(String),
    Usage(String),
    /// No desktop window could be opened; the host must supply the value.
    NeedsUi(&'static str),
    /// The same, for one named hidden field of a typed entry.
    NeedsUiField(String),
    Denied(String),
    Auth(String),
}

impl Fault {
    fn exit_code(&self) -> i32 {
        match self {
            Fault::Error(_) => 1,
            Fault::Usage(_) => 2,
            Fault::NeedsUi(_) | Fault::NeedsUiField(_) => 3,
            Fault::Denied(_) => 4,
            Fault::Auth(_) => 5,
        }
    }
}

impl From<String> for Fault {
    fn from(message: String) -> Self {
        Fault::Error(message)
    }
}

type Outcome = Result<(), Fault>;

pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    let paths = Paths::resolve(cli.dir.clone());
    migrate_legacy(&paths);
    // Dead token files (expired, unsigned, from an older store) carry keys
    // that open nothing; drop them on sight rather than after a week.
    if paths.sessions().is_dir() {
        session::sweep(&paths);
    }
    let json = cli.json;
    match dispatch(cli.cmd, &paths, json) {
        Ok(()) => 0,
        Err(fault) => {
            match &fault {
                Fault::NeedsUi(step) => {
                    eprintln!("needs-ui: {step}");
                    eprintln!("no desktop window is available; the host must supply this value");
                }
                Fault::NeedsUiField(field) => {
                    eprintln!("needs-ui: password field={field}");
                    eprintln!("no desktop window is available; the host must supply this value");
                }
                // (NeedsUi with a detail is printed by `needs_ui` below)
                Fault::Usage(message) => eprintln!("ai-vault: {message}"),
                Fault::Error(message) | Fault::Denied(message) | Fault::Auth(message) => {
                    eprintln!("ai-vault: {message}")
                }
            }
            fault.exit_code()
        }
    }
}

/// One-time move from the per-agent directory the TypeScript release used
/// (~/.omp/vault). The old file is copied, not removed: rolling back to that
/// extension still works.
fn migrate_legacy(paths: &Paths) {
    // Only the real default directory: AI_VAULT_DIR is an explicit choice and
    // must never inherit another location's store.
    if paths.store().exists() || paths.dir != crate::paths::home().join(".ai-vault") {
        return;
    }
    let legacy = crate::paths::home().join(".omp").join("vault");
    let legacy_store = legacy.join("store.json");
    if !legacy_store.exists() {
        return;
    }
    if std::fs::create_dir_all(&paths.dir).is_err() {
        return;
    }
    if std::fs::copy(&legacy_store, paths.store()).is_err() {
        return;
    }
    crate::perms::restrict_file(&paths.store());
    if legacy.join("audit.log").exists() && !paths.audit().exists() {
        let _ = std::fs::copy(legacy.join("audit.log"), paths.audit());
    }
    eprintln!(
        "ai-vault: 已把共享库从 {} 复制到 {}（旧文件保留）",
        legacy.display(),
        paths.dir.display()
    );
}

fn dispatch(cmd: Cmd, paths: &Paths, json: bool) -> Outcome {
    let out = Out { json };
    match cmd {
        Cmd::Path => {
            out.json_value(json!({ "path": paths.store(), "dir": paths.dir, "sessions": paths.sessions() }));
            out.text(paths.store().display().to_string());
            Ok(())
        }
        Cmd::Rekey { password_stdin } => rekey(paths, &out, password_stdin),
        Cmd::Doctor => doctor(paths, &out),
        Cmd::Init { password_stdin, requester, idle_min } => {
            init(paths, &out, password_stdin, &requester, idle_min)
        }
        Cmd::Unlock { password_stdin, requester, idle_min } => {
            unlock(paths, &out, password_stdin, &requester, idle_min)
        }
        Cmd::Settings { key, value, password_stdin, token } => {
            settings(paths, &out, token.as_deref(), key.as_deref(), value.as_deref(), None, password_stdin)
        }
        Cmd::BwSession { action, token } => sealed_session(paths, &out, Kind::Bitwarden, &action, token.as_deref()),
        Cmd::EnteSession { action, token } => sealed_session(paths, &out, Kind::Ente, &action, token.as_deref()),
        Cmd::Mode { action, value, hours, password_stdin, token } => {
            mode(paths, &out, token.as_deref(), &action, value.as_deref(), hours, password_stdin)
        }
        Cmd::Status { token } => status(paths, &out, token),
        Cmd::Lock { token, all } => lock(paths, &out, token, all),
        Cmd::List { token } => list(paths, &out, token),
        Cmd::Get { name, token, reason, answer_stdin, approval } => {
            get(paths, &out, token, &name, reason.as_deref(), answer_stdin, approval)
        }
        Cmd::Add { name, r#type, username, uri, notes, fields, secrets, password_stdin, yes, token } => {
            add(paths, &out, token, AddRequest { name, r#type, username, uri, notes, fields, secrets, password_stdin, yes })
        }
        Cmd::Save { token, file, yes } => save(paths, &out, token, file, yes),
        Cmd::Remove { name, yes, token } => remove(paths, &out, token, &name, yes),
        Cmd::Grant { name, minutes, token } => grant(paths, &out, token, &name, minutes),
        Cmd::Revoke { name, all, token } => revoke(paths, &out, token, name.as_deref(), all),
        Cmd::Audit { n } => audit_entries(paths, &out, n),
        Cmd::Import { file, yes, token } => import_file(paths, &out, token, &file, yes),
    }
}

struct Out {
    json: bool,
}

impl Out {
    fn json_value(&self, value: serde_json::Value) {
        if self.json {
            println!("{}", serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()));
        }
    }

    fn text(&self, text: impl AsRef<str>) {
        if !self.json {
            println!("{}", text.as_ref());
        }
    }

    fn value(&self, value: serde_json::Value, human: impl FnOnce() -> String) {
        if self.json {
            self.json_value(value);
        } else {
            self.text(human());
        }
    }
}

fn idle_ms(minutes: Option<i64>) -> i64 {
    minutes.map(|m| m.clamp(1, 600) * 60_000).unwrap_or(IDLE_MS_DEFAULT)
}

/// How long a token made now stays valid. `--idle-min` keeps the old
/// idle-based behaviour; otherwise the machine's mode decides:
///   never   -> no deadline (and the token is stored machine-wide)
///   time    -> absolute deadline, `hours` from now
///   session -> no deadline, with a 7-day ceiling in case an agent dies
///              without locking
fn policy(idle_min: Option<i64>, config: &config::Config) -> (i64, Option<i64>, UnlockPolicy) {
    let policy = config.unlock;
    if let Some(minutes) = idle_min {
        return (idle_ms(Some(minutes)), None, policy);
    }
    let now = session::now_ms();
    match policy.mode {
        UnlockMode::Never => (0, None, policy),
        UnlockMode::Time => (0, Some(now + policy.hours.clamp(1, 24 * 90) * 3_600_000), policy),
        UnlockMode::Session => (0, Some(now + 7 * 24 * 3_600_000), policy),
    }
}

// ---------------------------------------------------------------- input

fn read_password() -> Result<String, Fault> {
    let line = read_line()?;
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        return Err(Fault::Usage("empty password on stdin".into()));
    }
    Ok(password)
}

fn read_line() -> Result<String, Fault> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Fault::Error(format!("cannot read stdin: {e}")))?;
    Ok(line)
}

fn read_stdin_text() -> Result<String, Fault> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| Fault::Error(format!("cannot read stdin: {e}")))?;
    Ok(text)
}

/// A yes/no answer from stdin, used when the host UI already asked the user.
/// The answer a host relays is bound to this token, this entry and this
/// yes/no, under the host secret: a replay against another entry, or a
/// flipped answer, fails.
fn approval_ok(secret: &str, token: &str, entry: &str, answer: bool, hex_mac: &str) -> bool {
    use hmac::{Hmac, Mac};
    let message = format!("allow:{token}:{}:{}", entry.to_lowercase(), if answer { "y" } else { "n" });
    let Ok(mut hasher) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    hasher.update(message.as_bytes());
    let expected: String = hasher.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    expected.len() == hex_mac.len()
        && expected.bytes().zip(hex_mac.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

fn read_approval() -> Result<bool, Fault> {
    let answer = read_line()?.trim().to_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes" | "allow" | "允许" | "1" | "true"))
}

fn ask_password(title: &str, label: &str) -> Result<String, Fault> {
    match dialog::prompt_secret(title, label) {
        Answer::Value(value) => Ok(value),
        Answer::Cancelled => Err(Fault::Denied("cancelled: no password entered".into())),
        Answer::NoUi => Err(Fault::NeedsUi("password")),
    }
}

/// The same, naming the field on the `needs-ui` line so a host can title its
/// own dialog and send the value back as `--secret NAME=VALUE`.
/// The same, but when no window can open the `needs-ui` line names the field,
/// so a host can title its own dialog and send the answer back as `--secret`.
/// The field is reported in the error's text, which the host reads after the
/// `needs-ui: password` line.
fn ask_field_password(field: &str, title: &str, label: &str) -> Result<String, Fault> {
    match dialog::prompt_secret(title, label) {
        Answer::Value(value) => Ok(value),
        Answer::Cancelled => Err(Fault::Denied("cancelled: no password entered".into())),
        Answer::NoUi => Err(Fault::NeedsUiField(field.to_string())),
    }
}

// ---------------------------------------------------------------- store access

fn open_store(paths: &Paths) -> Result<crypto::StoreFile, Fault> {
    crypto::read_store(&paths.store())?.ok_or_else(|| {
        Fault::Error(format!("vault is not initialized — run `ai-vault init` (store: {})", paths.store().display()))
    })
}

fn items_with(session: &Session, store: &crypto::StoreFile) -> Result<Vec<Item>, Fault> {
    Ok(payload_with(session, store)?.items)
}

fn payload_with(session: &Session, store: &crypto::StoreFile) -> Result<crypto::Payload, Fault> {
    let key = session
        .key()
        .ok_or_else(|| Fault::Auth("session token has no usable key — unlock again".into()))?;
    crypto::open_with_key(store, &key).map_err(|e| match e {
        crypto::OpenError::WrongPassword => Fault::Auth("the store does not open with this session — unlock again".into()),
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })
}

/// Write the settings back into the store under this session's key.
fn config_write(paths: &Paths, session: &Session, config: &config::Config) -> Result<(), Fault> {
    let _guard = StoreLock::acquire(paths)?;
    let store = open_store(paths)?;
    let key = session
        .key()
        .ok_or_else(|| Fault::Auth("session token has no usable key — unlock again".into()))?;
    let sealed = config::write_with(&store, &key, config)?;
    let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
    crypto::write_atomic(&paths.store(), &bytes)?;
    Ok(())
}

/// The secret the host process (pi/omp extension) holds and passes to each
/// CLI call through the environment. A bare `ai-vault` typed by a human has
/// none, which is fine: that caller never needs to relay an approval.
fn host_secret() -> Option<String> {
    std::env::var("AI_VAULT_HOST_SECRET").ok().filter(|s| !s.is_empty())
}

/// What a session file is signed with: the host's memory-only secret when
/// the caller presented one, else the store's wrap key (a human at a terminal).
fn signer(paths: &Paths) -> Result<session::Signer, String> {
    match host_secret() {
        Some(secret) => Ok(session::Signer::Host(secret)),
        None => sealed::wrap_key_hex(paths).map(session::Signer::Wrap),
    }
}

/// Both keys, for checking a file against whichever one signed it.
fn signing_keys(paths: &Paths) -> Result<(Option<String>, Option<String>), String> {
    Ok((host_secret(), Some(sealed::wrap_key_hex(paths)?)))
}

/// The host integration (the extension) is recognised by the secret it
/// presents: `AI_VAULT_HOST=1` alone only says "I would like to be a host"
/// and is treated like a human caller until it has a secret to sign with.
/// This keeps a half-configured host from getting a session it can neither
/// verify nor relay for.
fn secret_kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Bitwarden => "bitwarden",
        Kind::Ente => "ente",
    }
}

fn is_host() -> bool {
    std::env::var_os("AI_VAULT_HOST").is_some_and(|v| v == "1") && host_secret().is_some()
}

/// The auto session is the `never` mode token: no deadline, no password, and
/// it belongs to the machine rather than to one agent.
fn auto_session(paths: &Paths) -> Option<Session> {
    let session = session::load_auto(paths).ok().flatten()?;
    let store = crypto::read_store(&paths.store()).ok().flatten()?;
    if crypto::store_id(&store) != session.store_id {
        session::delete_auto(paths);
        return None;
    }
    Some(session)
}

/// An explicit token, else the machine-wide auto session.
fn load_session(paths: &Paths, token: Option<&str>) -> Result<Session, Fault> {
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        let (host, wrap) = signing_keys(paths)?;
        return session::load(paths, token, host.as_deref(), wrap.as_deref()).map_err(Fault::Auth);
    }
    auto_session(paths).ok_or_else(|| {
        Fault::Auth("vault is locked (no session token) — unlock first".into())
    })
}

/// Write a session back where it came from: auto sessions stay machine-wide,
/// the others stay in the per-agent token file.
fn persist(paths: &Paths, session: &Session) {
    let auto = session::load_auto(paths)
        .ok()
        .flatten()
        .is_some_and(|saved| saved.token == session.token);
    let _ = if auto {
        session::save_auto(paths, session)
    } else {
        // Best-effort like the rest of this helper; a failed sign means the
        // next call simply asks to unlock again.
        match signer(paths) {
            Ok(signer) => session.save(paths, &signer),
            Err(e) => Err(e),
        }
    };
}

fn touch(paths: &Paths, session: &mut Session) {
    session.last_active = session::now_ms();
    let _ = session.prune_grants(session.last_active);
    persist(paths, session);
}

/// Read-modify-write under one advisory lock. The closure never opens a dialog
/// (that would block every other agent for minutes).
fn mutate<F>(paths: &Paths, session: &Session, f: F) -> Result<(), Fault>
where
    F: FnOnce(&mut Vec<Item>, &str) -> Result<(), Fault>,
{
    let _guard = StoreLock::acquire(paths)?;
    let store = open_store(paths)?;
    let mut payload = payload_with(session, &store)?;
    let now = store::now_iso();
    f(&mut payload.items, &now)?;
    let key = session
        .key()
        .ok_or_else(|| Fault::Auth("session token has no usable key — unlock again".into()))?;
    let salt = crypto::hex_to_bytes(&session.salt).ok_or_else(|| Fault::Error("session salt is corrupt".into()))?;
    let sealed = crypto::seal(&salt, session.kdf.unwrap_or_default(), &key, &payload.items, &payload.config)?;
    let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
    crypto::write_atomic(&paths.store(), &bytes)?;
    Ok(())
}

// ---------------------------------------------------------------- commands

/// Bring an older store up to the current KDF cost. Re-derives the key from
/// the password under the new parameters and re-seals; a `never`-mode
/// machine session, which holds the old key, is re-minted.
fn rekey(paths: &Paths, out: &Out, password_stdin: bool) -> Outcome {
    let store = open_store(paths)?;
    let password = if password_stdin {
        read_password()?
    } else {
        ask_password(tr("ai-vault · upgrade key parameters", "ai-vault · 升级密钥参数"), tr("master password", "主密码"))?
    };
    let (payload, _old_key) = crypto::open_with_passphrase(&store, &password).map_err(|e| match e {
        crypto::OpenError::WrongPassword => Fault::Auth("wrong master password".into()),
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })?;
    let salt = crypto::hex_to_bytes(&store.salt).ok_or_else(|| Fault::Error("vault salt is corrupt".into()))?;
    let kdf = Kdf::default();
    let new_key = crypto::derive_key(&password, &salt, kdf).map_err(|e| Fault::Error(e.to_string()))?;
    let sealed = crypto::seal(&salt, kdf, &new_key, &payload.items, &payload.config)?;
    {
        let _guard = StoreLock::acquire(paths)?;
        let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
        crypto::write_atomic(&paths.store(), &bytes)?;
    }
    // Other live sessions hold the old key; they cannot open the new file and
    // will be told to unlock again. The machine session is simply re-minted.
    let _ = session::delete_auto(paths);
    if payload.config.unlock.mode == UnlockMode::Never {
        let auto = Session::new("rekey", 0, None, &sealed, &new_key);
        session::save_auto(paths, &auto)?;
    }
    audit::append(&paths.audit(), "cli", "rekey", None, Some(&format!("N={}", kdf.n)));
    let value = json!({ "ok": true, "kdf": { "N": kdf.n, "r": kdf.r, "p": kdf.p }, "was": { "N": store.kdf().n, "r": store.kdf().r, "p": store.kdf().p } });
    out.value(value, || format!("rekeyed: scrypt N {} -> {}", store.kdf().n, kdf.n));
    Ok(())
}

fn doctor(paths: &Paths, out: &Out) -> Outcome {
    session::ensure_session_dir(paths)?;
    let value = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "dir": paths.dir,
        "store": paths.store(),
        "initialized": paths.store().exists(),
        "sessions": paths.sessions(),
        "audit": paths.audit(),
        "display": dialog::has_display(),
        "zenity": which("zenity"),
        "auto": paths.auto_session().exists(),
        "kdf": crypto::read_store(&paths.store()).ok().flatten().map(|s| s.kdf().n),
    });
    out.value(value.clone(), || {
        let mut lines = Vec::new();
        for (key, item) in value.as_object().into_iter().flatten() {
            lines.push(format!("{key}: {}", item.as_str().map(str::to_string).unwrap_or_else(|| item.to_string())));
        }
        lines.join("\n")
    });
    Ok(())
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
    })
}

fn init(paths: &Paths, out: &Out, password_stdin: bool, requester: &str, idle_min: Option<i64>) -> Outcome {
    if paths.store().exists() {
        return Err(Fault::Error(format!(
            "vault already initialized — {}",
            paths.store().display()
        )));
    }
    let password = if password_stdin {
        read_password()?
    } else {
        let first = ask_password(tr("ai-vault · set master password", "ai-vault · 创建主密码"), tr("at least 8 characters", "至少 8 位"))?;
        if first.len() < 8 {
            return Err(Fault::Usage("the master password must be at least 8 characters".into()));
        }
        let again = ask_password(tr("ai-vault · confirm master password", "ai-vault · 确认主密码"), tr("type it again", "再输入一次"))?;
        if again != first {
            return Err(Fault::Denied("the two passwords do not match".into()));
        }
        first
    };
    if password.len() < 8 {
        return Err(Fault::Usage("the master password must be at least 8 characters".into()));
    }

    let salt = crypto::random_bytes::<16>();
    let kdf = Kdf::default();
    let key = crypto::derive_key(&password, &salt, kdf).map_err(|e| Fault::Error(e.to_string()))?;
    let mut config = config::Config::default();
    if let Some(legacy) = config::take_legacy(paths) {
        config = legacy;
    }
    let sealed = crypto::seal(&salt, kdf, &key, &[], &config)?;
    {
        let _guard = StoreLock::acquire(paths)?;
        if paths.store().exists() {
            return Err(Fault::Error("vault already initialized".into()));
        }
        let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
        crypto::write_atomic(&paths.store(), &bytes)?;
    }
    session::ensure_session_dir(paths)?;
    let (idle, deadline, policy) = policy(idle_min, &config);
    let session = Session::new(requester, idle, deadline, &sealed, &key);
    if policy.mode == UnlockMode::Never {
        session::save_auto(paths, &session)?;
    } else {
        let signer = signer(paths)?;
        session.save(paths, &signer)?;
    }
    audit::append(&paths.audit(), requester, "init", None, None);
    let value = json!({
        "ok": true,
        "path": paths.store(),
        "token": session.token,
        "hostSecret": if policy.mode == UnlockMode::Never || !is_host() { None } else { host_secret() },
        "expiresAt": session.expiry(),
        "items": 0,
        "mode": policy.mode.as_str(),
        "auto": policy.mode == UnlockMode::Never,
    });
    out.value(value, || format!("created {}", paths.store().display()));
    Ok(())
}

fn unlock(paths: &Paths, out: &Out, password_stdin: bool, requester: &str, idle_min: Option<i64>) -> Outcome {
    let store = open_store(paths)?;
    let password = if password_stdin {
        read_password()?
    } else {
        ask_password(tr("ai-vault · unlock", "ai-vault · 解锁"), tr("local store master password", "本地库主密码"))?
    };
    let (mut payload, key) = crypto::open_with_passphrase(&store, &password).map_err(|e| match e {
        crypto::OpenError::WrongPassword => {
            audit::append(&paths.audit(), requester, "unlock_failed", None, Some("bad-password"));
            Fault::Auth("wrong master password".into())
        }
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })?;
    let items = payload.items;
    // A plaintext config.json from an older version is brought inside the
    // store now that the password has been verified — minus anything that
    // lowers protection, which a file edit must never grant.
    let migrated = config::take_legacy(paths).map(|legacy| {
        payload.config = legacy;
        true
    });
    if migrated == Some(true) {
        let salt = crypto::hex_to_bytes(&store.salt).ok_or_else(|| Fault::Error("vault salt is corrupt".into()))?;
        let sealed = crypto::seal(&salt, store.kdf(), &key, &items, &payload.config)?;
        let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
        crypto::write_atomic(&paths.store(), &bytes)?;
    }
    session::ensure_session_dir(paths)?;
    session::sweep(paths);
    let (idle, deadline, policy) = policy(idle_min, &payload.config);
    // The host brings its own secret (so the same process can sign later
    // calls); everyone else is signed with the wrap key.
    let session = Session::new(requester, idle, deadline, &store, &key);
    if policy.mode == UnlockMode::Never {
        session::save_auto(paths, &session)?;
    } else {
        let signer = signer(paths)?;
        session.save(paths, &signer)?;
    }
    audit::append(&paths.audit(), requester, "unlock", None, Some(policy.mode.as_str()));
    let value = json!({
        "ok": true,
        "token": session.token,
        "hostSecret": if policy.mode == UnlockMode::Never || !is_host() { None } else { host_secret() },
        "expiresAt": session.expiry(),
        "items": items.len(),
        "requester": requester,
        "mode": policy.mode.as_str(),
        "auto": policy.mode == UnlockMode::Never,
        "path": paths.store(),
    });
    out.value(value, || format!("unlocked {} ({} entries)", paths.store().display(), items.len()));
    Ok(())
}

/// Dotted setting names, with the aliases a human is likely to type.
fn setting_key(raw: &str) -> Option<&'static str> {
    match raw.trim().to_lowercase().as_str() {
        "vault.unlock" | "vault.mode" | "unlock" | "mode" => Some("vault.unlock"),
        "vault.hours" | "hours" => Some("vault.hours"),
        "vault.confirm" | "confirm" => Some("vault.confirm"),
        "bitwarden.unlock" | "bitwarden.mode" | "bw.unlock" | "bw.mode" => Some("bitwarden.unlock"),
        "bitwarden.hours" | "bw.hours" => Some("bitwarden.hours"),
        "bitwarden.import" | "bw.import" | "import" => Some("bitwarden.import"),
        "ente.unlock" | "ente.mode" => Some("ente.unlock"),
        "ente.hours" => Some("ente.hours"),
        _ => None,
    }
}

fn settings_value(config: &config::Config, paths: &Paths) -> serde_json::Value {
    let bw_saved = sealed::load(paths, Kind::Bitwarden).ok().flatten();
    let ente_saved = sealed::load(paths, Kind::Ente).ok().flatten();
    json!({
        "ok": true,
        "vault": {
            "unlock": config.unlock.mode.as_str(),
            "hours": config.unlock.hours,
            "confirm": config.unlock.confirm,
            "auto": paths.auto_session().exists(),
        },
        "bitwarden": {
            "unlock": config.bitwarden.store.unlock.as_str(),
            "hours": config.bitwarden.store.hours,
            "import": config.bitwarden.import.as_str(),
            "persisted": bw_saved.is_some(),
            "expiresAt": bw_saved.as_ref().and_then(|s| s.expires_at),
        },
        "ente": {
            "unlock": config.ente.unlock.as_str(),
            "hours": config.ente.hours,
            "persisted": ente_saved.is_some(),
            "expiresAt": ente_saved.as_ref().and_then(|s| s.expires_at),
        },
    })
}

fn settings_human(config: &config::Config, paths: &Paths) -> String {
    let yes_no = |yes: bool| tr(if yes { "yes" } else { "no" }, if yes { "有" } else { "无" });
    [
        format!("vault.unlock: {}   (never | time | session)", config.unlock.mode.as_str()),
        format!("vault.hours: {}{}", config.unlock.hours, tr("   (time mode)", "   (time 模式)")),
        format!(
            "vault.confirm: {}{}",
            config.unlock.confirm,
            tr("   (a window per read while unlocked)", "   （解锁后每次读取弹确认窗）")
        ),
        format!("{} {}", tr("vault machine-wide session:", "vault 机器级会话:"), if paths.auto_session().exists() { tr("yes (no password)", "有（免密）") } else { tr("no", "无") }),
        format!("bitwarden.unlock: {}   (never | time | session)", config.bitwarden.store.unlock.as_str()),
        format!("bitwarden.hours: {}", config.bitwarden.store.hours),
        format!("bitwarden.import: {}   (ask | always | never)", config.bitwarden.import.as_str()),
        {
            let bw = match sealed::load(paths, Kind::Bitwarden).ok().flatten() {
                Some(saved) => match saved.expires_at {
                    Some(at) => tr_owned(
                        format!("yes (expires in {} min)", ((at - session::now_ms()) / 60_000).max(0)),
                        format!("有（{} 分钟后过期）", ((at - session::now_ms()) / 60_000).max(0)),
                    ),
                    None => tr("yes (no expiry)", "有（不过期）").to_string(),
                },
                None => tr("no", "无").to_string(),
            };
            format!("{} {}", tr("bitwarden persisted session:", "bitwarden 已落盘的会话:"), bw)
        },
        format!("ente.unlock: {}   (never | time | session)", config.ente.unlock.as_str()),
        format!("ente.hours: {}", config.ente.hours),
        format!("{} {}", tr("ente persisted key:", "ente 已落盘的密钥:"), yes_no(sealed::load(paths, Kind::Ente).ok().flatten().is_some())),
    ]
    .join("\n")
}

fn settings(
    paths: &Paths,
    out: &Out,
    token: Option<&str>,
    key: Option<&str>,
    value: Option<&str>,
    hours: Option<i64>,
    password_stdin: bool,
) -> Outcome {
    // The settings live inside the store's ciphertext: reading them needs the
    // store's key, i.e. an unlocked session. That is the whole point — there
    // is no file an agent could edit.
    let session = load_session(paths, token)?;
    let store = open_store(paths)?;
    let mut config = payload_with(&session, &store)?.config;

    let Some(raw_key) = key.filter(|k| !k.trim().is_empty()) else {
        let value = settings_value(&config, paths);
        out.value(value, || settings_human(&config, paths));
        return Ok(());
    };
    let key = setting_key(raw_key).ok_or_else(|| {
        Fault::Usage(format!(
            "unknown setting \"{raw_key}\" — vault.unlock, vault.hours, bitwarden.unlock, bitwarden.hours, bitwarden.import"
        ))
    })?;

    let Some(raw_value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        let shown = match key {
            "vault.unlock" => config.unlock.mode.as_str().to_string(),
            "vault.hours" => config.unlock.hours.to_string(),
            "vault.confirm" => config.unlock.confirm.to_string(),
            "bitwarden.unlock" => config.bitwarden.store.unlock.as_str().to_string(),
            "bitwarden.hours" => config.bitwarden.store.hours.to_string(),
            "ente.unlock" => config.ente.unlock.as_str().to_string(),
            "ente.hours" => config.ente.hours.to_string(),
            _ => config.bitwarden.import.as_str().to_string(),
        };
        out.value(json!({ "ok": true, "key": key, "value": shown }), || format!("{key}: {shown}"));
        return Ok(());
    };

    match key {
        "vault.unlock" => {
            let mode = UnlockMode::parse(raw_value)
                .ok_or_else(|| Fault::Usage(format!("unknown mode \"{raw_value}\" — never, time or session")))?;
            // Changing when the vault opens is a security decision: always verify.
            let (payload, vault_key) = verify_master(paths, &store, password_stdin, tr("switching the unlock policy", "切换解锁模式"))?;
            config.unlock.mode = mode;
            if let Some(hours) = hours {
                config.unlock.hours = hours.clamp(1, 24 * 90);
            }
            config_write(paths, &session, &config)?;
            session::ensure_session_dir(paths)?;
            if mode == UnlockMode::Never {
                let auto = Session::new("mode", 0, None, &store, &vault_key);
                session::save_auto(paths, &auto)?;
            } else {
                session::delete_auto(paths);
            }
            let _ = payload;
            audit::append(&paths.audit(), "cli", "mode", None, Some(mode.as_str()));
        }
        "vault.hours" => {
            let hours: i64 = raw_value
                .parse()
                .map_err(|_| Fault::Usage(format!("\"{raw_value}\" is not a number of hours")))?;
            config.unlock.hours = hours.clamp(1, 24 * 90);
            config_write(paths, &session, &config)?;
        }
        "vault.confirm" => {
            // Turning the per-read window off is a security decision, priced
            // like the unlock policy: the master password.
            let on = matches!(raw_value, "true" | "1" | "yes" | "on" | "ask")
                || if matches!(raw_value, "false" | "0" | "no" | "off") {
                    false
                } else {
                    return Err(Fault::Usage(format!("\"{raw_value}\" is not true or false")));
                };
            if !on {
                verify_master(paths, &store, password_stdin, tr("turn off the per-read confirmation", "关闭每次读取的确认窗"))?;
            }
            config.unlock.confirm = on;
            config_write(paths, &session, &config)?;
            audit::append(&paths.audit(), "cli", "settings", None, Some(if on { "confirm=on" } else { "confirm=off" }));
        }
        "bitwarden.unlock" => {
            let mode = UnlockMode::parse(raw_value)
                .ok_or_else(|| Fault::Usage(format!("unknown mode \"{raw_value}\" — never, time or session")))?;
            // Keeping the bw session key on disk is a downgrade of its own.
            if mode != UnlockMode::Session {
                verify_master(paths, &store, password_stdin, tr("keeping the Bitwarden session on disk", "把 Bitwarden 会话落盘"))?;
            }
            config.bitwarden.store.unlock = mode;
            if let Some(hours) = hours {
                config.bitwarden.store.hours = hours.clamp(1, 24 * 90);
            }
            config_write(paths, &session, &config)?;
            // Going back to per-session must not leave a key on disk.
            if mode == UnlockMode::Session {
                sealed::clear(paths, Kind::Bitwarden);
            }
        }
        "bitwarden.hours" => {
            let hours: i64 = raw_value
                .parse()
                .map_err(|_| Fault::Usage(format!("\"{raw_value}\" is not a number of hours")))?;
            config.bitwarden.store.hours = hours.clamp(1, 24 * 90);
            config_write(paths, &session, &config)?;
        }
        "ente.unlock" => {
            let mode = UnlockMode::parse(raw_value)
                .ok_or_else(|| Fault::Usage(format!("unknown mode \"{raw_value}\" — never, time or session")))?;
            if mode != UnlockMode::Session {
                verify_master(paths, &store, password_stdin, tr("keeping the Ente key on disk", "把 Ente 密钥落盘"))?;
            }
            config.ente.unlock = mode;
            if let Some(hours) = hours {
                config.ente.hours = hours.clamp(1, 24 * 90);
            }
            config_write(paths, &session, &config)?;
            if mode == UnlockMode::Session {
                sealed::clear(paths, Kind::Ente);
            }
        }
        "ente.hours" => {
            let hours: i64 = raw_value
                .parse()
                .map_err(|_| Fault::Usage(format!("\"{raw_value}\" is not a number of hours")))?;
            config.ente.hours = hours.clamp(1, 24 * 90);
            config_write(paths, &session, &config)?;
        }
        _ => {
            let import = ImportPolicy::parse(raw_value).ok_or_else(|| {
                Fault::Usage(format!("unknown import policy \"{raw_value}\" — ask, always or never"))
            })?;
            // "always" imports a Bitwarden hit with no window: a downgrade.
            if import == ImportPolicy::Always {
                verify_master(paths, &store, password_stdin, tr("importing Bitwarden hits without asking", "不询问就导入 Bitwarden 条目"))?;
            }
            config.bitwarden.import = import;
            config_write(paths, &session, &config)?;
        }
    }

    let value = settings_value(&config, paths);
    out.value(value, || settings_human(&config, paths));
    Ok(())
}

/// Ask for the master password and prove it against the store. Used for
/// every change that lowers protection. Returns the opened payload and the
/// key, for the one caller that mints the machine-wide session.
fn verify_master(
    paths: &Paths,
    store: &crypto::StoreFile,
    password_stdin: bool,
    why: &str,
) -> Result<(crypto::Payload, crypto::Key), Fault> {
    let password = if password_stdin {
        read_password()?
    } else {
        ask_password(tr("ai-vault · master password", "ai-vault · 主密码"), why)?
    };
    crypto::open_with_passphrase(store, &password).map_err(|e| match e {
        crypto::OpenError::WrongPassword => {
            audit::append(&paths.audit(), "cli", "settings", None, Some("denied=bad-password"));
            Fault::Auth("wrong master password".into())
        }
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })
}

/// `/vault mode` is a shortcut for the `vault.unlock` setting.
fn mode(
    paths: &Paths,
    out: &Out,
    token: Option<&str>,
    action: &str,
    value: Option<&str>,
    hours: Option<i64>,
    password_stdin: bool,
) -> Outcome {
    match action.trim() {
        "" | "get" | "status" => settings(paths, out, token, Some("vault.unlock"), None, None, password_stdin),
        "set" => settings(paths, out, token, Some("vault.unlock"), value, hours, password_stdin),
        other => Err(Fault::Usage(format!("unknown mode action \"{other}\""))),
    }
}

fn sealed_session(paths: &Paths, out: &Out, kind: Kind, action: &str, token: Option<&str>) -> Outcome {
    match action.trim() {
        "" | "get" => {
            let stored = sealed::load(paths, kind)?
                .ok_or_else(|| Fault::Auth(format!("no persisted {} secret — save one first", secret_kind_label(kind))))?;
            let key = sealed::key(paths, kind)?
                .ok_or_else(|| Fault::Auth(format!("no persisted {} secret", secret_kind_label(kind))))?;
            out.value(
                json!({ "ok": true, "key": key, "savedAt": stored.saved_at, "expiresAt": stored.expires_at }),
                || key,
            );
            Ok(())
        }
        "put" | "save" => {
            let key = read_stdin_text()?.trim().to_string();
            if key.is_empty() {
                return Err(Fault::Usage("bw-session put expects the session key on stdin".into()));
            }
            let session = load_session(paths, token)?;
            let store = open_store(paths)?;
            let payload = payload_with(&session, &store)?;
            let policy = match kind {
                Kind::Bitwarden => payload.config.bitwarden.store,
                Kind::Ente => payload.config.ente,
            };
            let expires_at = sealed::save(paths, kind, &key, policy)?;
            audit::append(&paths.audit(), "cli", "sealed", None, Some(secret_kind_label(kind)));
            out.value(json!({ "ok": true, "expiresAt": expires_at }), || {
                match expires_at {
                    Some(at) => format!("saved (expires in {} min)", ((at - session::now_ms()) / 60_000).max(0)),
                    None => "saved (no expiry)".to_string(),
                }
            });
            Ok(())
        }
        "clear" | "delete" => {
            let removed = sealed::clear(paths, kind);
            audit::append(&paths.audit(), "cli", "sealed", None, Some(secret_kind_label(kind)));
            out.value(json!({ "ok": true, "removed": removed }), || {
                if removed { "cleared".to_string() } else { "nothing stored".to_string() }
            });
            Ok(())
        }
        other => Err(Fault::Usage(format!("unknown session action \"{other}\" (get, put, clear)"))),
    }
}

fn status(paths: &Paths, out: &Out, token: Option<String>) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    let now = session::now_ms();
    session.prune_grants(now);
    session.last_active = now;
    persist(paths, &session);
    let grants: serde_json::Map<String, serde_json::Value> = session
        .grants
        .iter()
        .map(|(name, until)| (name.clone(), json!({ "expiresAt": until, "leftMs": until - now })))
        .collect();
    let policy = payload_with(&session, &store)?.config.unlock;
    let auto = session::load_auto(paths)
        .ok()
        .flatten()
        .is_some_and(|saved| saved.token == session.token);
    let value = json!({
        "ok": true,
        "unlocked": true,
        "items": items.len(),
        "requester": session.requester,
        "idleMs": session.idle_ms,
        "expiresAt": session.expiry(),
        "mode": policy.mode.as_str(),
        "hours": policy.hours,
        "confirm": policy.confirm,
        "auto": auto,
        "store": paths.store(),
        "grants": grants,
    });
    out.value(value.clone(), || {
        let expiry = match session.expiry() {
            Some(at) => format!("in {}s", ((at - now) / 1000).max(0)),
            None => "never".to_string(),
        };
        let mut lines = vec![
            format!("store: {}", paths.store().display()),
            format!("requester: {}", session.requester),
            "state: unlocked".to_string(),
            format!("mode: {}{}", policy.mode.as_str(), if auto { " (machine-wide)" } else { "" }),
            format!("items: {}", items.len()),
            format!("expires: {expiry}"),
        ];
        for (name, until) in &session.grants {
            lines.push(format!("grant: {name} ({}s left)", ((until - now) / 1000).max(0)));
        }
        lines.join("\n")
    });
    Ok(())
}

fn lock(paths: &Paths, out: &Out, token: Option<String>, all: bool) -> Outcome {
    let mut count = 0;
    let mut auto = false;
    if all {
        count = session::delete_all(paths);
        auto = session::delete_auto(paths);
    } else if let Some(token) = token.filter(|t| !t.is_empty()) {
        if session::delete(paths, &token) {
            count = 1;
        }
    } else {
        // No token: the only thing to lock here is the machine-wide session.
        auto = session::delete_auto(paths);
        if !auto {
            return Err(Fault::Usage("pass --token or --all".into()));
        }
    }
    if auto {
        count += 1;
    }
    audit::append(&paths.audit(), "cli", "lock", None, Some(if all { "all" } else { "token" }));
    out.value(json!({ "ok": true, "removed": count, "auto": auto }), || format!("locked {count} session(s)"));
    Ok(())
}

fn list(paths: &Paths, out: &Out, token: Option<String>) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    let summaries: Vec<ItemSummary> = items.iter().map(ItemSummary::from).collect();
    touch(paths, &mut session);
    audit::append(&paths.audit(), &session.requester, "list", None, None);
    out.value(json!({ "ok": true, "count": summaries.len(), "items": summaries }), || {
        if items.is_empty() {
            return "(empty)".to_string();
        }
        items
            .iter()
            .map(|i| {
                format!(
                    "{}\t{}\t{}\t{}",
                    i.name,
                    kind_label(i.r#type),
                    i.username.clone().unwrap_or_default(),
                    i.uris.as_ref().and_then(|u| u.first()).cloned().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(())
}

fn get(
    paths: &Paths,
    out: &Out,
    token: Option<String>,
    name: &str,
    reason: Option<&str>,
    answer_stdin: bool,
    approval: Option<String>,
) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    let payload = payload_with(&session, &store)?;
    let items = payload.items;
    let item = store::find(&items, name).cloned().ok_or_else(|| {
        let names = items.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(", ");
        Fault::Error(format!("no such entry: \"{name}\". available: {}", if names.is_empty() { "(empty)" } else { &names }))
    })?;

    let now = session::now_ms();
    // `never` mode is the "the agent may use these freely" mode: the machine-wide
    // session is the authorization, so no window opens on each read.
    let auto = token.as_deref().map_or(true, |t| t.trim().is_empty());
    // `vault.confirm = false`: the master password that opened this session is
    // the approval. Safe for exactly that reason — a session the extension
    // opened can only exist because the user typed the password (a token the
    // model finds on disk is useless without the host secret). Every read is
    // still written to the audit log, entry by entry.
    let no_confirm = payload.config.unlock.confirm == false;
    let via = if auto {
        "no-password"
    } else if no_confirm {
        audit::append(&paths.audit(), &session.requester, "read_allow", Some(&item.name), Some("confirm-off"));
        "unlocked-no-confirm"
    } else if session.grant(&item.name, now).is_some() {
        "existing-grant"
    } else {
        // The window is what the user approves: no caller-supplied text may
        // break out of its own line here.
        let message = format!(
            "{} {}\n{} {}\n{} {}\n\n{}",
            tr("Entry:", "条目:"),
            format!("{} ({})", dialog::for_dialog(&item.name, 80), kind_label(item.r#type)),
            tr("Requester:", "请求方:"),
            dialog::for_dialog(&session.requester, 40),
            tr("Reason:", "原因:"),
            dialog::for_dialog(reason.unwrap_or(&tr("(none given)", "(未说明)").to_string()), 120),
            tr(
                "Allowing lets the same requester read it again for 5 minutes. The password enters the conversation.",
                "允许后 5 分钟内同一请求方可再次读取。密码会进入对话。"
            )
        );
        let approved = if answer_stdin {
            // Relaying an answer is a host privilege: it must be signed with the
            // host secret, so the model's own bash cannot answer "y" for the user.
            let Some(secret) = host_secret().filter(|_| is_host()) else {
                audit::append(&paths.audit(), &session.requester, "read_deny", Some(&item.name), Some("unsigned-relay"));
                return Err(Fault::Usage(
                    "--answer-stdin is only for a host that holds AI_VAULT_HOST_SECRET and signs the answer with --approval".into(),
                ));
            };
            let answer = read_approval()?;
            let Some(approval) = approval else {
                return Err(Fault::Usage("--answer-stdin needs --approval <hmac of the answer>".into()));
            };
            if !approval_ok(&secret, &session.token, &item.name, answer, &approval) {
                audit::append(&paths.audit(), &session.requester, "read_deny", Some(&item.name), Some("bad-approval"));
                return Err(Fault::Denied(format!("approval signature mismatch for \"{}\"", item.name)));
            }
            answer
        } else {
            match dialog::confirm(tr("ai-vault · read local password", "ai-vault · 读取本地密码"), &message) {
                Answer::Value(ok) => ok,
                Answer::Cancelled => false,
                Answer::NoUi => {
                    audit::append(&paths.audit(), &session.requester, "read_deny", Some(&item.name), Some("no-ui"));
                    return Err(Fault::NeedsUi("confirm"));
                }
            }
        };
        if !approved {
            audit::append(&paths.audit(), &session.requester, "read_deny", Some(&item.name), reason);
            return Err(Fault::Denied(format!("user denied access to \"{}\" — do not retry, ask the user instead", item.name)));
        }
        // The window may have outlived the idle lock or overlapped a write.
        session = load_session(paths, token.as_deref())?;
        let store = open_store(paths)?;
        let items = items_with(&session, &store)?;
        if store::find(&items, &item.name).is_none() {
            return Err(Fault::Error(format!("\"{}\" was removed while the window was open", item.name)));
        }
        session.grants.insert(item.name.to_lowercase(), session::now_ms() + GRANT_MS_DEFAULT);
        audit::append(&paths.audit(), &session.requester, "grant", Some(&item.name), Some("interactive"));
        "interactive-grant"
    };

    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "read_allow", Some(&item.name), reason);

    let mut value = serde_json::to_value(&item).map_err(|e| Fault::Error(e.to_string()))?;
    if let Some(record) = value.as_object_mut() {
        record.insert("via".into(), json!(via));
    }
    out.value(value.clone(), || serde_json::to_string_pretty(&value).unwrap_or_default());
    Ok(())
}

struct AddRequest {
    name: String,
    r#type: Option<String>,
    username: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
    fields: Vec<String>,
    secrets: Vec<String>,
    password_stdin: bool,
    yes: bool,
}

/// Parse a type name the way a human writes it: login, note, secure-note,
/// ssh key, "SSH key", drivers licence …
fn parse_item_type(raw: &str) -> Option<ItemType> {
    let key: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    Some(match key.as_str() {
        "login" | "password" | "" => ItemType::Login,
        "note" | "securenote" => ItemType::SecureNote,
        "card" | "creditcard" => ItemType::Card,
        "identity" | "person" => ItemType::Identity,
        "sshkey" | "ssh" | "key" => ItemType::SshKey,
        "bankaccount" | "bank" => ItemType::BankAccount,
        "driverslicense" | "driverlicense" | "license" | "drivinglicence" => ItemType::DriversLicense,
        "passport" => ItemType::Passport,
        _ => return None,
    })
}

fn add(paths: &Paths, out: &Out, token: Option<String>, req: AddRequest) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(Fault::Usage("an entry needs a name".into()));
    }
    let kind = match req.r#type.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        None => ItemType::Login,
        Some(raw) => parse_item_type(raw).ok_or_else(|| {
            Fault::Usage(format!(
                "unknown type \"{raw}\" — login, note, card, identity, sshkey, bankaccount, driverslicense, passport"
            ))
        })?,
    };
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    let existing = store::find(&items, &name).cloned();
    // Updating an entry of another type replaces its data block: say so in the window.
    let type_changes = existing.as_ref().is_some_and(|item| item.r#type != kind);

    // --field NAME=VALUE pairs, by the type's own field names.
    let mut data: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut to_type: Vec<String> = Vec::new();
    for raw in &req.fields {
        let (field, value) = match raw.split_once('=') {
            Some((f, v)) => (f.trim().to_string(), Some(v.to_string())),
            None => (raw.trim().to_string(), None),
        };
        let field = resolve_field_name(kind, &field)
            .ok_or_else(|| Fault::Usage(format!("\"{field}\" is not a field of a {}", kind_label(kind))))?;
        match value {
            Some(v) => {
                data.insert(field, serde_json::Value::String(v));
            }
            None => to_type.push(field),
        }
    }
    // Host-supplied hidden fields (the host asked the user in its own UI).
    for raw in &req.secrets {
        let (field, value) = raw.split_once('=').ok_or_else(|| Fault::Usage("--secret expects NAME=VALUE".into()))?;
        let field = resolve_field_name(kind, field.trim())
            .ok_or_else(|| Fault::Usage(format!("\"{}\" is not a field of a {}", field.trim(), kind_label(kind))))?;
        if !is_secret_field(kind, &field) {
            return Err(Fault::Usage(format!("--secret is for hidden fields; \"{field}\" can go in --field")));
        }
        data.insert(field, serde_json::Value::String(value.to_string()));
    }
    // The conventional flags feed the login fields and the shared notes.
    if kind == ItemType::Login {
        if let Some(user) = req.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            data.insert("username".into(), serde_json::Value::String(user.to_string()));
        }
    }
    let notes = req.notes.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());

    if !req.yes {
        let mut meta = Vec::new();
        let shown = dialog::for_dialog(&name, 80);
        let action = match &existing {
            Some(_) if type_changes => tr_owned(
                format!("Replace \"{shown}\" with a {} entry.", kind_label(kind)),
                format!("把「{shown}」改成{}条目。", kind_label(kind)),
            ),
            Some(_) => tr_owned(format!("Update the existing entry \"{shown}\"."), format!("更新已有条目「{shown}」。")),
            None => tr_owned(format!("Create a {} entry \"{shown}\".", kind_label(kind)), format!("新建{}条目「{shown}」。", kind_label(kind))),
        };
        for (field, value) in &data {
            let secret = is_secret_field(kind, field);
            meta.push(format!(
                "{} {}",
                field,
                if secret { "••••".to_string() } else { dialog::for_dialog(value.as_str().unwrap_or(""), 120) }
            ));
        }
        for field in &to_type {
            meta.push(format!("{field} ••••"));
        }
        if let Some(user) = req.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            if kind != ItemType::Login {
                meta.push(format!("{} {}", tr("Username:", "用户名:"), dialog::for_dialog(user, 60)));
            }
        }
        if let Some(uri) = req.uri.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            meta.push(format!("URI: {}", dialog::for_dialog(uri, 120)));
        }
        if let Some(notes) = notes.as_deref() {
            meta.push(format!("{} {}", tr("Notes:", "备注:"), dialog::for_dialog(notes, 120)));
        }
        let message = format!(
            "{action}{}\n{}",
            if meta.is_empty() { String::new() } else { format!("\n{}", meta.join("\n")) },
            tr(
                "A window opens next for each hidden field. Nothing enters the conversation.",
                "接下来每个隐藏字段弹一个窗口。密码不会进入对话。"
            )
        );
        match dialog::confirm(tr("ai-vault · save to local store", "ai-vault · 保存到本地库"), &message) {
            Answer::Value(true) => {}
            Answer::Value(false) | Answer::Cancelled => return Err(Fault::Denied(format!("user denied saving \"{name}\""))),
            Answer::NoUi => return Err(Fault::NeedsUi("confirm")),
        }
    }

    // Hidden fields: typed in a dialog (or read from stdin for the primary one).
    // On an update, a secret the caller did not mention is left as stored; only
    // a new entry (or a type change) needs every secret typed.
    let primary = kind.primary_field();
    let fresh = existing.as_ref().map_or(true, |item| item.r#type != kind);
    let mut secret_fields: Vec<String> = to_type;
    if fresh {
        if let Some(field) = primary {
            if !data.contains_key(field) {
                secret_fields.push(field.to_string());
            }
        }
    } else if let Some(item) = &existing {
        // Carry over the stored data block so `apply` does not read the absent
        // fields as "clear"; the draft's own values still win.
        for (field, value) in item.data.clone().unwrap_or_default() {
            data.entry(field).or_insert(value);
        }
    }
    for field in secret_fields {
        let password = if req.password_stdin && Some(field.as_str()) == primary {
            read_password()?
        } else {
            ask_field_password(&field, tr("ai-vault · password", "ai-vault · 密码"), &format!("{name} · {field}"))?
        };
        if password.is_empty() {
            return Err(Fault::Denied("cancelled: no password entered".into()));
        }
        data.insert(field, serde_json::Value::String(password));
    }
    if kind == ItemType::SecureNote && notes.is_none() && data.is_empty() {
        // A secure note is its notes; a dialog for the body when none was given.
        let body = match dialog::prompt_text(tr("ai-vault · note", "ai-vault · 备注"), tr("the note's contents", "备注内容")) {
            Answer::Value(text) => text,
            Answer::Cancelled => return Err(Fault::Denied("cancelled".into())),
            Answer::NoUi => return Err(Fault::NeedsUi("text")),
        };
        if body.trim().is_empty() {
            return Err(Fault::Usage("a note needs contents (--notes)".into()));
        }
        let notes = Some(body);
        return finish_add(paths, out, &mut session, Draft {
            name: name.clone(),
            r#type: kind,
            notes,
            data: None,
            ..Default::default()
        }, &name);
    }

    let uris = req.uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).map(|u| vec![u]);
    let draft = Draft {
        name: name.clone(),
        r#type: kind,
        username: if kind == ItemType::Login { req.username.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) } else { None },
        password: String::new(),
        uris,
        data: if data.is_empty() { None } else { Some(data) },
        notes,
        ..Default::default()
    };
    finish_add(paths, out, &mut session, draft, &name)
}

fn finish_add(paths: &Paths, out: &Out, session: &mut Session, draft: Draft, name: &str) -> Outcome {
    let mut inserted = false;
    let kind = draft.r#type;
    mutate(paths, session, |items, now| {
        inserted = store::apply(items, draft, now);
        Ok(())
    })?;
    session.last_active = session::now_ms();
    persist(paths, session);
    audit::append(&paths.audit(), &session.requester, "add", Some(name), Some(kind_label(kind)));
    let mut value = json!({ "ok": true, "item": name, "type": kind_label(kind), "created": inserted });
    if let Some(record) = value.as_object_mut() {
        record.insert("fields".into(), json!(kind.fields()));
    }
    out.value(value, || {
        format!(
            "saved \"{name}\" as a {} (hidden fields typed in the dialog, not shown)",
            kind_label(kind)
        )
    });
    Ok(())
}

/// A type's field by the name a human typed (case- and separator-insensitive).
fn resolve_field_name(kind: ItemType, raw: &str) -> Option<String> {
    let key: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    kind.fields()
        .iter()
        .find(|f| f.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase() == key)
        .map(|f| f.to_string())
}

/// Fields whose value must never be printed in a window or in `list`.
pub(crate) fn is_secret_field(kind: ItemType, field: &str) -> bool {
    matches!(
        (kind, field),
        (_, "password")
            | (_, "privateKey")
            | (ItemType::Card, "code")
            | (ItemType::Card, "number")
            | (ItemType::BankAccount, "pin")
            | (ItemType::BankAccount, "accountNumber")
            | (ItemType::BankAccount, "routingNumber")
            | (_, "ssn")
            | (_, "licenseNumber")
            | (_, "passportNumber")
            | (ItemType::Passport, "nationalIdentificationNumber")
            | (_, "totp")
    )
}

fn kind_label(kind: ItemType) -> &'static str {
    match kind {
        ItemType::Login => "login",
        ItemType::SecureNote => "note",
        ItemType::Card => "card",
        ItemType::Identity => "identity",
        ItemType::SshKey => "SSH key",
        ItemType::BankAccount => "bank account",
        ItemType::DriversLicense => "driver's licence",
        ItemType::Passport => "passport",
    }
}

fn save(paths: &Paths, out: &Out, token: Option<String>, file: Option<PathBuf>, yes: bool) -> Outcome {
    if !yes {
        return Err(Fault::Usage("save needs --yes: the caller must confirm the write with the user".into()));
    }
    let mut session = load_session(paths, token.as_deref())?;
    let text = match file {
        Some(path) => std::fs::read_to_string(&path)
            .map_err(|e| Fault::Error(format!("cannot read {}: {e}", path.display())))?,
        None => read_stdin_text()?,
    };
    let drafts = import::parse_drafts(&text)?;
    if drafts.is_empty() {
        out.value(json!({ "ok": true, "count": 0, "names": [] }), || "nothing to save".to_string());
        return Ok(());
    }
    let names: Vec<String> = drafts.iter().map(|d| d.name.clone()).collect();
    let mut count = 0;
    mutate(paths, &session, |items, now| {
        for draft in drafts {
            store::apply(items, draft, now);
            count += 1;
        }
        Ok(())
    })?;
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "import", Some(&format!("drafts:{count}")), None);
    out.value(json!({ "ok": true, "count": count, "names": names }), || format!("saved {count} entries"));
    Ok(())
}

fn remove(paths: &Paths, out: &Out, token: Option<String>, name: &str, yes: bool) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    if store::find(&items, name).is_none() {
        return Err(Fault::Error(format!("no such entry: \"{name}\"")));
    }
    if !yes {
        match dialog::confirm(tr("ai-vault · delete entry", "ai-vault · 删除条目"), &tr_owned(format!("Delete \"{}\"? This cannot be undone.", dialog::for_dialog(name, 80)), format!("删除「{}」？删除后无法恢复。", dialog::for_dialog(name, 80)))) {
            Answer::Value(true) => {}
            Answer::Value(false) | Answer::Cancelled => return Err(Fault::Denied("cancelled".into())),
            Answer::NoUi => return Err(Fault::NeedsUi("confirm")),
        }
    }
    let mut removed = false;
    mutate(paths, &session, |items, _now| {
        removed = store::remove(items, name);
        Ok(())
    })?;
    session.grants.remove(&name.to_lowercase());
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "remove", Some(name), None);
    out.value(json!({ "ok": true, "removed": removed }), || if removed { "removed".to_string() } else { "not found".to_string() });
    Ok(())
}

/// A grant is "no window for N minutes": it is a standing approval, so it
/// costs the master password — the same as changing the unlock mode. The
/// interactive `/vault grant` asks through the window; a non-host caller
/// without the password cannot mint one.
fn grant(paths: &Paths, out: &Out, token: Option<String>, name: &str, minutes: Option<i64>) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    {
        // Only the host may use --password-stdin here (it just asked the user);
        // anyone else gets the window.
        let password = if is_host() {
            read_password()?
        } else {
            ask_password(tr("ai-vault · grant read", "ai-vault · 授权读取"), tr("master password (lets one entry be read without confirmation)", "主密码（给一条条目免确认读取）"))?
        };
        if let Err(e) = crypto::open_with_passphrase(&store, &password) {
            return Err(match e {
                crypto::OpenError::WrongPassword => Fault::Auth("wrong master password".into()),
                crypto::OpenError::Broken(message) => Fault::Error(message),
            });
        }
    }
    let items = items_with(&session, &store)?;
    let item = store::find(&items, name).ok_or_else(|| Fault::Error(format!("no such entry: \"{name}\"")))?;
    let minutes = minutes.unwrap_or(GRANT_MS_DEFAULT / 60_000).clamp(1, GRANT_MS_MAX / 60_000);
    let until = session::now_ms() + minutes * 60_000;
    session.grants.insert(item.name.to_lowercase(), until);
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "grant", Some(&item.name), Some("manual"));
    out.value(json!({ "ok": true, "name": item.name, "minutes": minutes, "expiresAt": until }), || {
        format!("granted \"{}\" for {minutes}m", item.name)
    });
    Ok(())
}

fn revoke(paths: &Paths, out: &Out, token: Option<String>, name: Option<&str>, all: bool) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    if all {
        session.grants.clear();
    } else if let Some(name) = name.filter(|n| !n.is_empty()) {
        session.grants.remove(&name.to_lowercase());
    } else {
        return Err(Fault::Usage("pass an entry name or --all".into()));
    }
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "revoke", name, Some(if all { "all" } else { "entry" }));
    out.value(json!({ "ok": true }), || "revoked".to_string());
    Ok(())
}

fn audit_entries(paths: &Paths, out: &Out, n: usize) -> Outcome {
    let limit = n.clamp(1, 1000);
    let entries = audit::read(&paths.audit(), limit);
    out.value(json!({ "ok": true, "entries": entries }), || {
        entries
            .iter()
            .map(|e| {
                format!(
                    "{} {} {}{}{}",
                    e.ts,
                    e.session,
                    e.event,
                    e.item.as_ref().map(|i| format!(" {i}")).unwrap_or_default(),
                    e.reason.as_ref().map(|r| format!(" ({r})")).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(())
}

fn import_file(paths: &Paths, out: &Out, token: Option<String>, file: &PathBuf, yes: bool) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let text = std::fs::read_to_string(file)
        .map_err(|e| Fault::Error(format!("cannot read {}: {e}", file.display())))?;
    let drafts = import::parse_bitwarden_json(&text)?;
    if drafts.is_empty() {
        return Err(Fault::Error("no login items with a password in that export".into()));
    }
    if !yes {
        let shown = drafts
            .iter()
            .take(15)
            .map(|d| {
                format!(
                    "• {}{}",
                    dialog::for_dialog(&d.name, 80),
                    d.username.as_ref().map(|u| format!("  user:{}", dialog::for_dialog(u, 40))).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let more = if drafts.len() > 15 { tr_owned(format!("\n… {} more", drafts.len() - 15), format!("\n… 还有 {} 条", drafts.len() - 15)) } else { String::new() };
        let message = format!(
            "{} {} {}\n\n{shown}{more}\n\n{}",
        tr("Matched", "匹配"),
        drafts.len(),
        tr("items. Login items with a password are written to the local encrypted store; same-name entries are updated. Import?", "条。其中带密码的登录项会写入本地加密库，同名条目会被更新。允许导入？"),
            drafts.len()
        );
        match dialog::confirm(tr("ai-vault · import from Bitwarden", "ai-vault · 从 Bitwarden 导入"), &message) {
            Answer::Value(true) => {}
            Answer::Value(false) | Answer::Cancelled => return Err(Fault::Denied("user denied the Bitwarden import".into())),
            Answer::NoUi => return Err(Fault::NeedsUi("confirm")),
        }
    }
    let names: Vec<String> = drafts.iter().map(|d| d.name.clone()).collect();
    let mut count = 0;
    mutate(paths, &session, |items, now| {
        for draft in drafts {
            store::apply(items, draft, now);
            count += 1;
        }
        Ok(())
    })?;
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "import", Some(&format!("json:{count}")), None);
    out.value(json!({ "ok": true, "count": count, "names": names }), || format!("imported {count} login items"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(Fault::Error("x".into()).exit_code(), 1);
        assert_eq!(Fault::Usage("x".into()).exit_code(), 2);
        assert_eq!(Fault::NeedsUi("password").exit_code(), 3);
        assert_eq!(Fault::Denied("x".into()).exit_code(), 4);
        assert_eq!(Fault::Auth("x".into()).exit_code(), 5);
    }

    #[test]
    fn idle_is_clamped() {
        assert_eq!(idle_ms(None), IDLE_MS_DEFAULT);
        assert_eq!(idle_ms(Some(0)), 60_000);
        assert_eq!(idle_ms(Some(1000)), 600 * 60_000);
    }
}

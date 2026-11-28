//! Command line surface. Every subcommand is one process: read the store,
//! prove the session token, do one thing, exit. The pi/omp extension calls
//! these commands and never links against the encryption itself.

use std::io::{self, BufRead, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::config::{self, UnlockMode, UnlockPolicy};
use crate::crypto::{self, Kdf};
use crate::dialog::{self, Answer};
use crate::import;
use crate::paths::{Paths, GRANT_MS_DEFAULT, GRANT_MS_MAX, IDLE_MS_DEFAULT};
use crate::session::{self, Session, StoreLock};
use crate::store::{self, Draft, Item};
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
        /// Read the approve/deny answer from stdin (host UI already asked)
        #[arg(long)]
        answer_stdin: bool,
    },
    /// Create or update an entry; the password is typed in a dialog
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        uri: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Read the password from stdin instead of a dialog
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
    /// Diagnose paths, session directory and desktop availability
    Doctor,
}

#[derive(Debug)]
enum Fault {
    Error(String),
    Usage(String),
    /// No desktop window could be opened; the host must supply the value.
    NeedsUi(&'static str),
    Denied(String),
    Auth(String),
}

impl Fault {
    fn exit_code(&self) -> i32 {
        match self {
            Fault::Error(_) => 1,
            Fault::Usage(_) => 2,
            Fault::NeedsUi(_) => 3,
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
    let json = cli.json;
    match dispatch(cli.cmd, &paths, json) {
        Ok(()) => 0,
        Err(fault) => {
            match &fault {
                Fault::NeedsUi(step) => {
                    eprintln!("needs-ui: {step}");
                    eprintln!("no desktop window is available; the host must supply this value");
                }
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
    let _ = std::fs::set_permissions(&paths.store(), std::fs::Permissions::from_mode(0o600));
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
        Cmd::Doctor => doctor(paths, &out),
        Cmd::Init { password_stdin, requester, idle_min } => {
            init(paths, &out, password_stdin, &requester, idle_min)
        }
        Cmd::Unlock { password_stdin, requester, idle_min } => {
            unlock(paths, &out, password_stdin, &requester, idle_min)
        }
        Cmd::Mode { action, value, hours, password_stdin } => {
            mode(paths, &out, &action, value.as_deref(), hours, password_stdin)
        }
        Cmd::Status { token } => status(paths, &out, token),
        Cmd::Lock { token, all } => lock(paths, &out, token, all),
        Cmd::List { token } => list(paths, &out, token),
        Cmd::Get { name, token, reason, answer_stdin } => {
            get(paths, &out, token, &name, reason.as_deref(), answer_stdin)
        }
        Cmd::Add { name, username, uri, notes, password_stdin, yes, token } => {
            add(paths, &out, token, AddRequest { name, username, uri, notes, password_stdin, yes })
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
fn policy(paths: &Paths, idle_min: Option<i64>) -> (i64, Option<i64>, UnlockPolicy) {
    let policy = config::load(paths).unlock;
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

fn ask_text(title: &str, label: &str) -> Result<String, Fault> {
    match dialog::prompt_text(title, label) {
        Answer::Value(value) => Ok(value),
        Answer::Cancelled => Err(Fault::Denied("cancelled".into())),
        Answer::NoUi => Err(Fault::NeedsUi("text")),
    }
}

// ---------------------------------------------------------------- store access

fn open_store(paths: &Paths) -> Result<crypto::StoreFile, Fault> {
    crypto::read_store(&paths.store())?.ok_or_else(|| {
        Fault::Error(format!("vault is not initialized — run `ai-vault init` (store: {})", paths.store().display()))
    })
}

fn items_with(session: &Session, store: &crypto::StoreFile) -> Result<Vec<Item>, Fault> {
    let key = session
        .key()
        .ok_or_else(|| Fault::Auth("session token has no usable key — unlock again".into()))?;
    crypto::open_with_key(store, &key).map_err(|e| match e {
        crypto::OpenError::WrongPassword => Fault::Auth("the store does not open with this session — unlock again".into()),
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })
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
        return session::load(paths, token).map_err(Fault::Auth);
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
    let _ = if auto { session::save_auto(paths, session) } else { session.save(paths) };
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
    let mut items = items_with(session, &store)?;
    let now = store::now_iso();
    f(&mut items, &now)?;
    let key = session
        .key()
        .ok_or_else(|| Fault::Auth("session token has no usable key — unlock again".into()))?;
    let salt = crypto::hex_to_bytes(&session.salt).ok_or_else(|| Fault::Error("session salt is corrupt".into()))?;
    let sealed = crypto::seal(&salt, session.kdf.unwrap_or_default(), &key, &items)?;
    let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
    crypto::write_atomic(&paths.store(), &bytes)?;
    Ok(())
}

// ---------------------------------------------------------------- commands

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
        "mode": config::load(paths).unlock.mode.as_str(),
        "auto": paths.auto_session().exists(),
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
        let first = ask_password("ai-vault · 创建主密码", "至少 8 位")?;
        if first.len() < 8 {
            return Err(Fault::Usage("the master password must be at least 8 characters".into()));
        }
        let again = ask_password("ai-vault · 确认主密码", "再输入一次")?;
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
    let sealed = crypto::seal(&salt, kdf, &key, &[])?;
    {
        let _guard = StoreLock::acquire(paths)?;
        if paths.store().exists() {
            return Err(Fault::Error("vault already initialized".into()));
        }
        let bytes = serde_json::to_vec(&sealed).map_err(|e| Fault::Error(format!("cannot serialize store: {e}")))?;
        crypto::write_atomic(&paths.store(), &bytes)?;
    }
    session::ensure_session_dir(paths)?;
    let (idle, deadline, policy) = policy(paths, idle_min);
    let session = Session::new(requester, idle, deadline, &sealed, &key);
    if policy.mode == UnlockMode::Never {
        session::save_auto(paths, &session)?;
    } else {
        session.save(paths)?;
    }
    audit::append(&paths.audit(), requester, "init", None, None);
    let value = json!({
        "ok": true,
        "path": paths.store(),
        "token": session.token,
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
        ask_password("ai-vault · 解锁", "本地库主密码")?
    };
    let (items, key) = crypto::open_with_passphrase(&store, &password).map_err(|e| match e {
        crypto::OpenError::WrongPassword => {
            audit::append(&paths.audit(), requester, "unlock_failed", None, Some("bad-password"));
            Fault::Auth("wrong master password".into())
        }
        crypto::OpenError::Broken(message) => Fault::Error(message),
    })?;
    session::ensure_session_dir(paths)?;
    session::sweep(paths);
    let (idle, deadline, policy) = policy(paths, idle_min);
    let session = Session::new(requester, idle, deadline, &store, &key);
    if policy.mode == UnlockMode::Never {
        session::save_auto(paths, &session)?;
    } else {
        session.save(paths)?;
    }
    audit::append(&paths.audit(), requester, "unlock", None, Some(policy.mode.as_str()));
    let value = json!({
        "ok": true,
        "token": session.token,
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

/// Show or change the password policy. Changing it always costs the master
/// password: `never` writes the key to disk, so it must not be a drive-by act.
fn mode(
    paths: &Paths,
    out: &Out,
    action: &str,
    value: Option<&str>,
    hours: Option<i64>,
    password_stdin: bool,
) -> Outcome {
    match action.trim() {
        "" | "get" | "status" => {
            let policy = config::load(paths).unlock;
            let auto = paths.auto_session().exists();
            out.value(
                json!({
                    "ok": true,
                    "mode": policy.mode.as_str(),
                    "hours": policy.hours,
                    "auto": auto,
                    "store": paths.store(),
                }),
                || {
                    format!(
                        "mode: {}\nhours: {}\nmachine-wide session: {}",
                        policy.mode.as_str(),
                        policy.hours,
                        if auto { "yes (no password needed)" } else { "no" }
                    )
                },
            );
            Ok(())
        }
        "set" => {
            let value = value.ok_or_else(|| {
                Fault::Usage("usage: ai-vault mode set never|time|session [--hours N]".into())
            })?;
            let mode = UnlockMode::parse(value)
                .ok_or_else(|| Fault::Usage(format!("unknown mode \"{value}\" — use never, time or session")))?;
            let store = open_store(paths)?;
            let password = if password_stdin {
                read_password()?
            } else {
                ask_password("ai-vault · 主密码", "切换解锁模式")?
            };
            let (_, key) = crypto::open_with_passphrase(&store, &password).map_err(|e| match e {
                crypto::OpenError::WrongPassword => Fault::Auth("wrong master password".into()),
                crypto::OpenError::Broken(message) => Fault::Error(message),
            })?;
            let hours = hours.unwrap_or(config::load(paths).unlock.hours).clamp(1, 24 * 90);
            config::save(paths, &config::Config { unlock: UnlockPolicy { mode, hours } })?;
            session::ensure_session_dir(paths)?;
            let auto = if mode == UnlockMode::Never {
                let session = Session::new("mode", 0, None, &store, &key);
                session::save_auto(paths, &session)?;
                true
            } else {
                session::delete_auto(paths);
                false
            };
            audit::append(&paths.audit(), "cli", "mode", None, Some(mode.as_str()));
            let warn = if mode == UnlockMode::Never {
                "\n注意: 密钥已写到磁盘（0600）。任何能读你文件的程序/人都能读出库里的密码。"
            } else {
                ""
            };
            out.value(
                json!({ "ok": true, "mode": mode.as_str(), "hours": hours, "auto": auto }),
                || {
                    format!(
                        "mode set to {}{}",
                        mode.as_str(),
                        if auto { " — no password needed from now on" } else { "" }
                    ) + warn
                },
            );
            Ok(())
        }
        other => Err(Fault::Usage(format!("unknown mode action \"{other}\""))),
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
    let policy = config::load(paths).unlock;
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
            .map(|i| format!("{}\t{}\t{}", i.name, i.username.clone().unwrap_or_default(), i.uris.as_ref().and_then(|u| u.first()).cloned().unwrap_or_default()))
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
) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    let item = store::find(&items, name).cloned().ok_or_else(|| {
        let names = items.iter().map(|i| i.name.clone()).collect::<Vec<_>>().join(", ");
        Fault::Error(format!("no such entry: \"{name}\". available: {}", if names.is_empty() { "(empty)" } else { &names }))
    })?;

    let now = session::now_ms();
    // `never` mode is the "the agent may use these freely" mode: the machine-wide
    // session is the authorization, so no window opens on each read.
    let auto = token.as_deref().map_or(true, |t| t.trim().is_empty());
    let via = if auto {
        "no-password"
    } else if session.grant(&item.name, now).is_some() {
        "existing-grant"
    } else {
        let message = format!(
            "条目: {}\n请求方: {}\n原因: {}\n\n允许后 5 分钟内同一请求方可再次读取。密码会进入对话。",
            item.name,
            session.requester,
            reason.unwrap_or("(未说明)")
        );
        let approved = if answer_stdin {
            read_approval()?
        } else {
            match dialog::confirm("ai-vault · 读取本地密码", &message) {
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
    username: Option<String>,
    uri: Option<String>,
    notes: Option<String>,
    password_stdin: bool,
    yes: bool,
}

fn add(paths: &Paths, out: &Out, token: Option<String>, req: AddRequest) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(Fault::Usage("an entry needs a name".into()));
    }
    let store = open_store(paths)?;
    let items = items_with(&session, &store)?;
    let existing = store::find(&items, &name).cloned();

    if !req.yes {
        let mut meta = Vec::new();
        if let Some(user) = req.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            meta.push(format!("用户名: {user}"));
        }
        if let Some(uri) = req.uri.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            meta.push(format!("URI: {uri}"));
        }
        if let Some(notes) = req.notes.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            meta.push(format!("备注: {notes}"));
        }
        let action = if existing.is_some() {
            format!("更新已有条目「{name}」。")
        } else {
            format!("新建条目「{name}」。")
        };
        let message = format!(
            "{action}{}\n下一步会弹出窗口，由你输入密码。密码不会进入对话。",
            if meta.is_empty() { String::new() } else { format!("\n{}", meta.join("\n")) }
        );
        match dialog::confirm("ai-vault · 保存到本地库", &message) {
            Answer::Value(true) => {}
            Answer::Value(false) | Answer::Cancelled => return Err(Fault::Denied(format!("user denied saving \"{name}\""))),
            Answer::NoUi => return Err(Fault::NeedsUi("confirm")),
        }
    }

    let username = match req.username {
        Some(user) => user,
        None => {
            let hint = if existing.as_ref().and_then(|i| i.username.as_ref()).is_some() {
                "用户名（留空保持不变）"
            } else {
                "用户名（可留空）"
            };
            ask_text(&format!("ai-vault · {name}"), hint)?
        }
    };
    let password = if req.password_stdin {
        read_password()?
    } else {
        ask_password("ai-vault · 密码", &name)?
    };
    if password.is_empty() {
        return Err(Fault::Denied("cancelled: no password entered".into()));
    }

    let user = username.trim().to_string();
    let uri = req.uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
    let notes = req.notes.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    let draft = Draft {
        id: None,
        name: name.clone(),
        username: if user.is_empty() { None } else { Some(user) },
        password,
        uris: uri.map(|u| vec![u]),
        notes,
        source: None,
    };
    let mut inserted = false;
    mutate(paths, &session, |items, now| {
        inserted = store::apply(items, draft, now);
        Ok(())
    })?;
    session.last_active = session::now_ms();
    persist(paths, &session);
    audit::append(&paths.audit(), &session.requester, "add", Some(&name), None);
    out.value(json!({ "ok": true, "item": name, "created": inserted }), || {
        format!("saved \"{name}\" (password entered in the dialog, not shown)")
    });
    Ok(())
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
        match dialog::confirm("ai-vault · 删除条目", &format!("删除「{name}」？删除后无法恢复。")) {
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

fn grant(paths: &Paths, out: &Out, token: Option<String>, name: &str, minutes: Option<i64>) -> Outcome {
    let mut session = load_session(paths, token.as_deref())?;
    let store = open_store(paths)?;
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
            .map(|d| format!("• {}{}", d.name, d.username.as_ref().map(|u| format!("  user:{u}")).unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n");
        let more = if drafts.len() > 15 { format!("\n… 还有 {} 条", drafts.len() - 15) } else { String::new() };
        let message = format!(
            "匹配 {} 条。其中带密码的登录项会写入本地加密库，同名条目会被更新。\n\n{shown}{more}\n\n允许导入？",
            drafts.len()
        );
        match dialog::confirm("ai-vault · 从 Bitwarden 导入", &message) {
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

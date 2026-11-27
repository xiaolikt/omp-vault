//! Desktop dialogs, the same zenity windows the TypeScript release opened.
//!
//! When a display exists but zenity cannot run, the caller gets `NoUi` and
//! falls back to its host UI (pi/omp prompt). Cancel and our own timeout end
//! the prompt here: they never turn into a second prompt.

use std::env;
use std::path::Path;
use std::process::{Command, Stdio};

const DIALOG_SECONDS: u32 = 600;

pub enum Answer<T> {
    /// The user answered.
    Value(T),
    /// The user cancelled, or the window timed out.
    Cancelled,
    /// No window could be opened at all; ask the host UI instead.
    NoUi,
}

pub fn has_display() -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| env::var_os(name).is_some_and(|v| !v.is_empty()))
}

struct Zenity {
    /// False when the process could not be started at all (zenity missing).
    spawned: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

fn zenity(args: &[String]) -> Zenity {
    match Command::new("zenity")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(out) => Zenity {
            spawned: true,
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(_) => Zenity { spawned: false, code: 127, stdout: String::new(), stderr: String::new() },
    }
}

fn arg(text: impl Into<String>) -> String {
    text.into()
}

fn timeout_arg() -> String {
    format!("--timeout={DIALOG_SECONDS}")
}

fn trim_newline(text: &str) -> String {
    text.trim_end_matches(['\r', '\n']).to_string()
}

/// True when the configured display looks usable. Only consulted when zenity
/// exits 1 with no output at all: a cancel on a live display, or a silent
/// start failure on a dead one.
fn display_reachable() -> bool {
    if let Some(wl) = env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()) {
        let runtime = match env::var_os("XDG_RUNTIME_DIR") {
            Some(dir) if !dir.is_empty() => dir,
            _ => return false,
        };
        return Path::new(&runtime).join(&wl).exists();
    }
    if env::var_os("DISPLAY").is_none_or(|v| v.is_empty()) {
        return false;
    }
    match Command::new("xdpyinfo")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        // If the probe itself cannot run, do not turn a normal cancel into a
        // second prompt.
        Err(_) => true,
    }
}

/// True when no dialog ran. Exit 1 is ambiguous on some zenity builds (cancel
/// and a failed start both use it), so stderr decides: GTK's own diagnostics
/// carry a `(zenity:PID): Gtk-WARNING` prefix; any other line, or a display
/// failure, means the window never opened.
fn failed_to_open(z: &Zenity) -> bool {
    if !z.spawned {
        return true;
    }
    // 0 = answered, 5 = --timeout elapsed.
    if z.code == 0 || z.code == 5 {
        return false;
    }
    if z.code == 1 && z.stdout.is_empty() && z.stderr.is_empty() {
        return !display_reachable();
    }
    let lower = z.stderr.to_lowercase();
    if lower.contains("cannot open display") || lower.contains("unable to open") || lower.contains("unable to init")
        || lower.contains("failed to open") || lower.contains("failed to init")
    {
        return true;
    }
    z.stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| !is_gtk_diagnostic(line))
}

fn is_gtk_diagnostic(line: &str) -> bool {
    // (zenity:1234): Gtk-WARNING **: ...
    let line = line.trim_start_matches('*');
    let Some(rest) = line.strip_prefix('(') else { return false };
    let Some((program, rest)) = rest.split_once(')') else { return false };
    if !program.contains(':') {
        return false;
    }
    let rest = rest.trim_start_matches(':').trim_start();
    rest.starts_with("Gtk-") || rest.starts_with("Gdk-") || rest.starts_with("GLib-")
}

/// Secret entry. Empty and cancel are both "no value".
pub fn prompt_secret(title: &str, label: &str) -> Answer<String> {
    if !has_display() {
        return Answer::NoUi;
    }
    let z = zenity(&[
        arg("--password"),
        arg(format!("--title={title} — {label}")),
        arg("--width=420"),
        timeout_arg(),
    ]);
    if failed_to_open(&z) {
        return Answer::NoUi;
    }
    let value = trim_newline(&z.stdout);
    if z.code == 0 && !value.is_empty() {
        Answer::Value(value)
    } else {
        Answer::Cancelled
    }
}

/// Plain text entry. Cancel is `Cancelled`; confirming an empty field is `""`.
pub fn prompt_text(title: &str, label: &str) -> Answer<String> {
    if !has_display() {
        return Answer::NoUi;
    }
    let z = zenity(&[
        arg("--entry"),
        arg(format!("--title={title}")),
        arg(format!("--text={label}")),
        arg("--width=480"),
        arg("--no-markup"),
        timeout_arg(),
    ]);
    if failed_to_open(&z) {
        return Answer::NoUi;
    }
    if z.code == 0 {
        Answer::Value(trim_newline(&z.stdout))
    } else {
        Answer::Cancelled
    }
}

/// Yes/no window. Deny and timeout are false and do not fall through.
pub fn confirm(title: &str, message: &str) -> Answer<bool> {
    if !has_display() {
        return Answer::NoUi;
    }
    let z = zenity(&[
        arg("--question"),
        arg(format!("--title={title}")),
        arg("--text"),
        arg(message),
        arg("--no-markup"),
        arg("--width=520"),
        arg("--default-cancel"),
        arg("--ok-label=允许"),
        arg("--cancel-label=拒绝"),
        timeout_arg(),
    ]);
    if failed_to_open(&z) {
        return Answer::NoUi;
    }
    Answer::Value(z.code == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtk_diagnostics_are_not_failures() {
        assert!(is_gtk_diagnostic("(zenity:1234): Gtk-WARNING **: cannot open display"));
        assert!(!is_gtk_diagnostic("zenity: command not found"));
        assert!(!is_gtk_diagnostic("Aborted (core dumped)"));
    }

    #[test]
    fn failed_spawn_and_dead_display_are_no_ui() {
        let missing = Zenity { spawned: false, code: 127, stdout: String::new(), stderr: String::new() };
        assert!(failed_to_open(&missing));
        let cancel = Zenity { spawned: true, code: 1, stdout: String::new(), stderr: String::new() };
        // No display in the test environment: the same exit is a start failure.
        assert_eq!(failed_to_open(&cancel), !display_reachable());
        let timeout = Zenity { spawned: true, code: 5, stdout: String::new(), stderr: String::new() };
        assert!(!failed_to_open(&timeout));
    }
}

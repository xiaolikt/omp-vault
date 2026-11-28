//! Desktop dialogs.
//!
//!   Linux    zenity (X11 or Wayland)
//!   macOS    osascript (a native dialog, hidden answer for secrets)
//!   Windows  PowerShell + WinForms (a native dialog, PasswordChar for secrets)
//!
//! When no window can open at all, the caller gets `NoUi` and the host UI
//! (pi/omp prompt) takes over. Cancel and our own timeout end the prompt here:
//! they never turn into a second prompt.

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use std::env;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use std::path::Path;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
    #[cfg(target_os = "linux")]
    {
        return ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|name| env::var_os(name).is_some_and(|v| !v.is_empty()));
    }
    // macOS and Windows always have a window server for an interactive user.
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

// ---------------------------------------------------------------- macOS

#[cfg(target_os = "macos")]
mod mac {
    use super::{Answer, DIALOG_SECONDS};
    use std::process::{Command, Stdio};

    /// Escape a value for AppleScript's double-quoted string literals.
    fn quote(text: &str) -> String {
        text.replace('\\', "\\\\").replace('"', "\\\"")
    }

    struct Out {
        spawned: bool,
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn osascript(script: &str) -> Out {
        match Command::new("osascript")
            .args(["-e", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(out) => Out {
                spawned: true,
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            },
            Err(_) => Out { spawned: false, code: 127, stdout: String::new(), stderr: String::new() },
        }
    }

    fn failed(out: &Out) -> bool {
        !out.spawned
            || {
                let e = out.stderr.to_lowercase();
                e.contains("not allowed") || e.contains("application isn")
            }
    }

    pub fn prompt_secret(title: &str, label: &str) -> Answer<String> {
        let script = format!(
            "tell application \"System Events\" to display dialog \"{}\" with title \"{}\" default answer \"\" with hidden answer buttons {{\"{}\", \"OK\"}} default button \"OK\" giving up after {}",
            quote(label),
            quote(title),
            crate::i18n::tr("Cancel", "取消"),
            DIALOG_SECONDS
        );
        let out = osascript(&script);
        if failed(&out) {
            return Answer::NoUi;
        }
        if !out.stdout.contains("text returned:") {
            return Answer::Cancelled;
        }
        let value = out
            .stdout
            .split("text returned:")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        if value.is_empty() {
            Answer::Cancelled
        } else {
            Answer::Value(value)
        }
    }

    pub fn prompt_text(title: &str, label: &str) -> Answer<String> {
        let script = format!(
            "tell application \"System Events\" to display dialog \"{}\" with title \"{}\" default answer \"\" buttons {{\"{}\", \"OK\"}} default button \"OK\" giving up after {}",
            quote(label),
            quote(title),
            crate::i18n::tr("Cancel", "取消"),
            DIALOG_SECONDS
        );
        let out = osascript(&script);
        if failed(&out) {
            return Answer::NoUi;
        }
        if !out.stdout.contains("text returned:") {
            return Answer::Cancelled;
        }
        Answer::Value(
            out.stdout
                .split("text returned:")
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string(),
        )
    }

    pub fn confirm(title: &str, message: &str) -> Answer<bool> {
        let script = format!(
            "tell application \"System Events\" to display dialog \"{}\" with title \"{}\" buttons {{\"{}\", \"{}\"}} default button \"{}\" giving up after {}",
            quote(message),
            quote(title),
            crate::i18n::tr("Deny", "拒绝"),
            crate::i18n::tr("Allow", "允许"),
            crate::i18n::tr("Deny", "拒绝"),
            DIALOG_SECONDS
        );
        let out = osascript(&script);
        if failed(&out) {
            return Answer::NoUi;
        }
        let allow = crate::i18n::tr("Allow", "允许");
        Answer::Value(out.code == 0 && out.stdout.contains(&format!("button returned:{allow}")))
    }
}

// -------------------------------------------------------------- Windows

#[cfg(target_os = "windows")]
mod win {
    use super::{Answer, DIALOG_SECONDS};
    use std::process::{Command, Stdio};

    // WinForms from PowerShell: no extra dependency, and PasswordChar can hide
    // the input. Exit 0 = OK (value on stdout), 1 = cancel, 2 = no window.
    const PREAMBLE: &str = r#"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$f = New-Object System.Windows.Forms.Form
$f.Text = $env:AI_VAULT_DLG_TITLE
$f.Width = 480; $f.Height = 200; $f.StartPosition = 'CenterScreen'
$f.TopMost = $true; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false
$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = $env:AI_VAULT_DLG_TEXT; $lbl.Left = 12; $lbl.Top = 12; $lbl.Width = 440; $lbl.Height = 60
$f.Controls.Add($lbl)
$box = New-Object System.Windows.Forms.TextBox
$box.Left = 12; $box.Top = 80; $box.Width = 440
if ($env:AI_VAULT_DLG_SECRET -eq '1') { $box.UseSystemPasswordChar = $true }
$f.Controls.Add($box)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'OK'; $ok.DialogResult = 'OK'; $ok.Left = 280; $ok.Top = 115; $f.AcceptButton = $ok
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = $env:AI_VAULT_DLG_CANCEL; $cancel.DialogResult = 'Cancel'; $cancel.Left = 370; $cancel.Top = 115; $f.CancelButton = $cancel
$f.Controls.Add($ok); $f.Controls.Add($cancel)
$f.Add_Shown({ $box.Focus() })
if ($f.ShowDialog() -eq 'OK') { [Console]::Out.Write($box.Text); exit 0 } else { exit 1 }
"#;

    const CONFIRM: &str = r#"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$msg = $env:AI_VAULT_DLG_TEXT
$r = [System.Windows.Forms.MessageBox]::Show($msg, $env:AI_VAULT_DLG_TITLE, 'YesNo', 'Warning', 'Button2')
if ($r -eq 'Yes') { exit 0 } else { exit 1 }
"#;

    struct Out {
        spawned: bool,
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn powershell(script: &str, title: &str, text: &str, secret: bool) -> Out {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-STA", "-Command", script])
            .env("AI_VAULT_DLG_TITLE", title)
            .env("AI_VAULT_DLG_TEXT", text)
            .env("AI_VAULT_DLG_SECRET", if secret { "1" } else { "0" })
            .env("AI_VAULT_DLG_CANCEL", crate::i18n::tr("Cancel", "取消"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let _ = DIALOG_SECONDS; // the dialog is modal for the user, not us
        match cmd.output() {
            Ok(out) => Out {
                spawned: true,
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            },
            Err(_) => Out { spawned: false, code: 127, stdout: String::new(), stderr: String::new() },
        }
    }

    fn failed(out: &Out) -> bool {
        !out.spawned || (out.code != 0 && out.code != 1)
    }

    pub fn prompt_secret(title: &str, label: &str) -> Answer<String> {
        let out = powershell(PREAMBLE, title, label, true);
        if failed(&out) {
            return Answer::NoUi;
        }
        if out.code != 0 || out.stdout.is_empty() {
            return Answer::Cancelled;
        }
        Answer::Value(out.stdout)
    }

    pub fn prompt_text(title: &str, label: &str) -> Answer<String> {
        let out = powershell(PREAMBLE, title, label, false);
        if failed(&out) {
            return Answer::NoUi;
        }
        if out.code != 0 {
            return Answer::Cancelled;
        }
        Answer::Value(out.stdout)
    }

    pub fn confirm(title: &str, message: &str) -> Answer<bool> {
        let out = powershell(CONFIRM, title, message, false);
        if failed(&out) {
            return Answer::NoUi;
        }
        Answer::Value(out.code == 0)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
struct Zenity {
    /// False when the process could not be started at all (zenity missing).
    spawned: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn arg(text: impl Into<String>) -> String {
    text.into()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn timeout_arg() -> String {
    format!("--timeout={DIALOG_SECONDS}")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn trim_newline(text: &str) -> String {
    text.trim_end_matches(['\r', '\n']).to_string()
}

/// True when the configured display looks usable. Only consulted when zenity
/// exits 1 with no output at all: a cancel on a live display, or a silent
/// start failure on a dead one.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

/// Make a caller-supplied value safe to put in a window: one line, bounded,
/// no control characters. A name or reason that carries newlines could
/// otherwise forge a second message inside the confirm dialog.
pub fn for_dialog(value: &str, max: usize) -> String {
    let flat: String = value
        .chars()
        .map(|c| if c.is_control() || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(flat.len());
    let mut last_space = false;
    for c in flat.chars() {
        let is_space = c.is_whitespace();
        if is_space {
            if !last_space && !out.is_empty() {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
        last_space = is_space;
    }
    let trimmed = out.trim();
    if trimmed.chars().count() > max {
        let mut cut: String = trimmed.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    } else {
        trimmed.to_string()
    }
}

/// Secret entry. Empty and cancel are both "no value".
pub fn prompt_secret(title: &str, label: &str) -> Answer<String> {
    #[cfg(target_os = "macos")]
    {
        return mac::prompt_secret(title, label);
    }
    #[cfg(target_os = "windows")]
    {
        return win::prompt_secret(title, label);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    prompt_secret_zenity(title, label)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn prompt_secret_zenity(title: &str, label: &str) -> Answer<String> {
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
    #[cfg(target_os = "macos")]
    {
        return mac::prompt_text(title, label);
    }
    #[cfg(target_os = "windows")]
    {
        return win::prompt_text(title, label);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    prompt_text_zenity(title, label)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn prompt_text_zenity(title: &str, label: &str) -> Answer<String> {
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
    #[cfg(target_os = "macos")]
    {
        return mac::confirm(title, message);
    }
    #[cfg(target_os = "windows")]
    {
        return win::confirm(title, message);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    confirm_zenity(title, message)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn confirm_zenity(title: &str, message: &str) -> Answer<bool> {
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
        arg(format!("--ok-label={}", crate::i18n::tr("Allow", "允许"))),
        arg(format!("--cancel-label={}", crate::i18n::tr("Deny", "拒绝"))),
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
    fn dialog_text_cannot_forge_a_second_line() {
        let forged = "github\n\n条目: nothing\n请求方: 主会话\n（已授权）";
        let clean = for_dialog(forged, 80);
        assert!(!clean.contains('\n'));
        assert!(clean.starts_with("github 条目: nothing"));
        assert_eq!(clean.chars().filter(|c| *c == '…').count(), 0);
        assert_eq!(for_dialog("   a   b  ", 80), "a b");
        let long = "x".repeat(100);
        let cut = for_dialog(&long, 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with('…'));
    }

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

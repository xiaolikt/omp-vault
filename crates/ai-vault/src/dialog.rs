//! Desktop dialogs.
//!
//!   Linux    zenity (X11 or Wayland)
//!   macOS    osascript (a native dialog, hidden answer for secrets)
//!   Windows  PowerShell + WinForms (a native dialog, PasswordChar for secrets)
//!
//! When no window can open at all, the caller gets `NoUi` and the host UI
//! (pi/omp prompt) takes over. Cancel and our own timeout end the prompt here:
//! they never turn into a second prompt. Every platform answers the value as
//! UTF-8, whatever the terminal's code page is.

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
    // macOS always has a window server for an interactive user.
    #[cfg(target_os = "macos")]
    {
        true
    }
    // Only the interactive session on Windows has a desktop anyone can see.
    #[cfg(target_os = "windows")]
    {
        win::has_display()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    // WinForms from PowerShell: no extra dependency, and the windows can be
    // laid out to match the display. Exit 0 = OK (value on stdout), 1 = cancel,
    // 2 = no window.
    //
    // Three things matter on a real Windows desktop:
    //   * `[Console]::Out.Write` encodes with the console's code page (936 on a
    //     Chinese Windows), so a password typed in Chinese arrived as mojibake
    //     and keyed a store no other machine could open. The value leaves as
    //     UTF-8 bytes through the raw stream instead.
    //   * Any error (a policy that forbids Add-Type, WinForms that will not
    //     load) used to make PowerShell exit 1, which reads as "the user
    //     cancelled": the host was told not to retry. The scripts trap into
    //     exit 2, and an exit 1 that printed an error counts the same.
    //   * Windows turns the IME off in a password edit control (so that a
    //     candidate window cannot show what is typed), and a Chinese password
    //     could not be entered at all. The field is an ordinary text box whose
    //     text is hidden by colour; a bullet per character shows underneath.
    const PRELUDE: &str = r#"
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Crisp text on a scaled display: a process that is not DPI-aware is
    # stretched as a bitmap by the system. Once this one is, a point laid out
    # for 96 DPI is AppliedDPI / 96 pixels here, which is what Px() scales.
    $scale = 1.0
    try {
        $dpi = [int](Get-ItemProperty 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name AppliedDPI -ErrorAction Stop).AppliedDPI
        if ($dpi -gt 96) {
            Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class AiVaultDpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
            if ([AiVaultDpi]::SetProcessDPIAware()) { $scale = $dpi / 96.0 }
        }
    } catch { }
    function Px([double]$v) { [int][Math]::Round($v * $scale) }

    # One typeface for Latin and Chinese where there is one; the system's otherwise.
    $families = [System.Drawing.FontFamily]::Families | ForEach-Object { $_.Name }
    $ui = 'Segoe UI'
    foreach ($name in 'Microsoft YaHei UI', 'Microsoft YaHei') {
        if ($families -contains $name) { $ui = $name; break }
    }
    function New-Font([double]$size, [System.Drawing.FontStyle]$style = [System.Drawing.FontStyle]::Regular) {
        [System.Drawing.Font]::new($ui, [single]$size, $style, [System.Drawing.GraphicsUnit]::Point)
    }

    $ink = [System.Drawing.Color]::FromArgb(26, 26, 26)
    $muted = [System.Drawing.Color]::FromArgb(96, 96, 96)
    $accent = [System.Drawing.Color]::FromArgb(0, 99, 192)
    $accentHover = [System.Drawing.Color]::FromArgb(23, 118, 210)
    $paper = [System.Drawing.Color]::FromArgb(249, 249, 249)
    $line = [System.Drawing.Color]::FromArgb(209, 209, 209)
    $white = [System.Drawing.Color]::White

    function New-Window([string]$title) {
        $w = [System.Windows.Forms.Form]::new()
        $w.Text = $title
        $w.FormBorderStyle = 'FixedDialog'; $w.MaximizeBox = $false; $w.MinimizeBox = $false
        $w.AutoScaleMode = 'None'
        $w.StartPosition = 'CenterScreen'; $w.TopMost = $true
        $w.BackColor = $paper
        $w.Icon = [System.Drawing.Icon]::new([System.Drawing.SystemIcons]::Shield, (Px 16), (Px 16))
        $w.ClientSize = [System.Drawing.Size]::new((Px 480), 0)
        return $w
    }

    # The shield, the title in bold, and the line under it when there is one.
    function Add-Heading($w, [string]$text) {
        $icon = [System.Windows.Forms.PictureBox]::new()
        $icon.Image = [System.Drawing.Icon]::new([System.Drawing.SystemIcons]::Shield, (Px 32), (Px 32)).ToBitmap()
        $icon.SizeMode = 'CenterImage'
        $icon.Bounds = [System.Drawing.Rectangle]::new((Px 20), (Px 18), (Px 32), (Px 32))
        $head = [System.Windows.Forms.Label]::new()
        $head.Text = $w.Text; $head.Font = New-Font 12 ([System.Drawing.FontStyle]::Bold); $head.ForeColor = $ink
        $head.Bounds = [System.Drawing.Rectangle]::new((Px 62), (Px 18), (Px 398), (Px 28))
        $w.Controls.Add($icon); $w.Controls.Add($head)
        if ($text) {
            $lbl = [System.Windows.Forms.Label]::new()
            $lbl.Text = $text; $lbl.Font = New-Font 10; $lbl.ForeColor = $muted
            $lbl.Bounds = [System.Drawing.Rectangle]::new((Px 62), (Px 50), (Px 398), (Px 40))
            $w.Controls.Add($lbl)
        }
    }

    function New-Button($w, [string]$text, [string]$result, [bool]$primary) {
        $b = [System.Windows.Forms.Button]::new()
        $b.Text = $text; $b.DialogResult = $result; $b.FlatStyle = 'Flat'
        $b.Size = [System.Drawing.Size]::new((Px 100), (Px 34))
        if ($primary) {
            $b.FlatAppearance.BorderColor = $accent; $b.BackColor = $accent; $b.ForeColor = $white
            $b.Font = New-Font 10 ([System.Drawing.FontStyle]::Bold)
        } else {
            $b.FlatAppearance.BorderColor = $line; $b.BackColor = $white; $b.ForeColor = $ink
            $b.Font = New-Font 10
        }
        $w.Controls.Add($b)
        return $b
    }

    # A row at the bottom, flush right; the last button is the rightmost one.
    function Add-Buttons($w, $buttons) {
        $x = $w.ClientSize.Width - (Px 20)
        foreach ($b in $buttons) {
            $b.Left = $x - $b.Width
            $b.Top = $w.ClientSize.Height - (Px 20) - $b.Height
            $x = $b.Left - (Px 8)
        }
    }
"#;

    const PREAMBLE: &str = r#"
    $f = New-Window $env:AI_VAULT_DLG_TITLE
    Add-Heading $f $env:AI_VAULT_DLG_TEXT
    $secret = $env:AI_VAULT_DLG_SECRET -eq '1'

    # The field: the panel draws a border that scales with the display and
    # turns blue while the field has the focus; the text box fills it.
    $box = [System.Windows.Forms.TextBox]::new()
    $box.Font = New-Font 11
    $box.BorderStyle = 'None'; $box.AutoSize = $false; $box.Dock = 'Fill'
    if ($secret) { $box.ForeColor = $box.BackColor }
    $field = [System.Windows.Forms.Panel]::new()
    $field.BackColor = $line
    $field.Padding = [System.Windows.Forms.Padding]::new((Px 1))
    $field.Left = Px 62; $field.Top = Px 94; $field.Width = Px 398
    $field.Height = $box.PreferredHeight + 2 * (Px 1)
    $field.Controls.Add($box)
    $f.Controls.Add($field)

    # Over the box, a label with one bullet per typed character and a caret of
    # its own: the box keeps its text (and the IME), and shows none of it.
    $mask = [System.Windows.Forms.Label]::new()
    $mask.BackColor = $white; $mask.Font = New-Font 11; $mask.ForeColor = $muted
    $mask.Dock = 'Fill'; $mask.TextAlign = 'MiddleLeft'
    $mask.Padding = [System.Windows.Forms.Padding]::new((Px 10), 0, 0, 0)
    $mask.Visible = $secret
    $caret = [System.Windows.Forms.Label]::new()
    $caret.BackColor = $ink; $caret.Width = [Math]::Max(1, (Px 1)); $caret.Height = Px 18
    $caret.Visible = $false
    if ($secret) { $field.Controls.Add($mask); $field.Controls.Add($caret) }

    $show = [System.Windows.Forms.CheckBox]::new()
    $show.Text = $env:AI_VAULT_DLG_SHOW
    $show.Font = New-Font 9; $show.ForeColor = $muted
    $show.Left = Px 366; $show.Top = $field.Bottom + (Px 8); $show.Width = Px 94
    $show.Visible = $secret
    $f.Controls.Add($show)
    $f.ClientSize = [System.Drawing.Size]::new((Px 480), $field.Bottom + (Px 92))

    function Update-Mask {
        $mask.Text = ('● ' * $box.TextLength).TrimEnd()
        $typed = if ($mask.Text) { $mask.Text + ' ' } else { '' }
        $width = [System.Windows.Forms.TextRenderer]::MeasureText($typed, $mask.Font).Width
        $caret.Left = [Math]::Min($mask.Padding.Left + $width, $mask.Width - $caret.Width)
        $caret.Top = [int](($mask.Height - $caret.Height) / 2)
    }
    $box.Add_TextChanged({ Update-Mask })
    $box.Add_GotFocus({ $caret.Visible = $secret; $field.BackColor = $accent })
    $box.Add_LostFocus({ $caret.Visible = $false; $field.BackColor = $line })
    $mask.Add_Click({ $box.Focus() })
    $show.Add_CheckedChanged({
        if ($show.Checked) { $box.ForeColor = $ink; $mask.Visible = $false }
        else { $box.ForeColor = $box.BackColor; $mask.Visible = $true; $caret.Visible = $box.Focused }
    })
    $blink = [System.Windows.Forms.Timer]::new(); $blink.Interval = 530
    $blink.Add_Tick({ if ($box.Focused -and $secret -and -not $show.Checked) { $caret.Visible = -not $caret.Visible } })
    $blink.Start()
    Update-Mask
    $f.Add_Shown({ $box.Focus() })

    $cancel = New-Button $f $env:AI_VAULT_DLG_CANCEL 'Cancel' $false
    $ok = New-Button $f $env:AI_VAULT_DLG_OK 'OK' $true
    Add-Buttons $f @($cancel, $ok)
    $f.AcceptButton = $ok; $f.CancelButton = $cancel
    $ok.Add_MouseEnter({ $ok.BackColor = $accentHover }); $ok.Add_MouseLeave({ $ok.BackColor = $accent })

    if ($f.ShowDialog() -eq 'OK') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($box.Text)
        $stdout = [Console]::OpenStandardOutput()
        $stdout.Write($bytes, 0, $bytes.Length); $stdout.Flush()
        exit 0
    }
    exit 1
} catch {
    [Console]::Error.Write($_)
    exit 2
}
"#;

    // A window of its own rather than a MessageBox: the buttons then say
    // Allow and Deny in the user's language, and it matches the other one.
    // Enter is the safe answer from wherever the focus is: Deny is both the
    // accept and the cancel button. Allow takes a click, or Tab and Enter.
    const CONFIRM: &str = r#"
    $f = New-Window $env:AI_VAULT_DLG_TITLE
    Add-Heading $f ''

    $msg = [System.Windows.Forms.Label]::new()
    $msg.Text = $env:AI_VAULT_DLG_TEXT
    $msg.Font = New-Font 10; $msg.ForeColor = $ink
    $msg.Left = Px 62; $msg.Top = Px 54; $msg.Width = Px 398
    $g = $f.CreateGraphics()
    $msg.Height = [int]($g.MeasureString($msg.Text, $msg.Font, $msg.Width).Height) + (Px 4)
    $g.Dispose()
    $f.Controls.Add($msg)
    $f.ClientSize = [System.Drawing.Size]::new((Px 480), $msg.Bottom + (Px 66))

    $deny = New-Button $f $env:AI_VAULT_DLG_DENY 'Cancel' $false
    $allow = New-Button $f $env:AI_VAULT_DLG_ALLOW 'OK' $true
    Add-Buttons $f @($deny, $allow)
    $f.AcceptButton = $deny
    $f.CancelButton = $deny
    $f.Add_Shown({ $deny.Focus() })
    $allow.Add_MouseEnter({ $allow.BackColor = $accentHover }); $allow.Add_MouseLeave({ $allow.BackColor = $accent })

    if ($f.ShowDialog() -eq 'OK') { exit 0 }
    exit 1
} catch {
    [Console]::Error.Write($_)
    exit 2
}
"#;

    /// Windows PowerShell by its full path. The window takes the master
    /// password, so the bare name is not left for a PATH entry or a working
    /// directory to answer to.
    fn powershell_exe() -> PathBuf {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .map(|root| root.join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe"))
            .unwrap_or_else(|| PathBuf::from("powershell"))
    }

    struct Out {
        spawned: bool,
        code: i32,
        stdout: String,
        stderr: String,
    }

    /// Read a pipe to its end on its own thread: a chatty start must not block
    /// on a full pipe while the window is open.
    fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<String> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    }

    fn powershell(body: &str, title: &str, text: &str, secret: bool) -> Out {
        let script = format!("{PRELUDE}{body}");
        let mut cmd = Command::new(powershell_exe());
        cmd.args(["-NoProfile", "-NonInteractive", "-STA", "-Command", &script])
            .env("AI_VAULT_DLG_TITLE", title)
            .env("AI_VAULT_DLG_TEXT", text)
            .env("AI_VAULT_DLG_SECRET", if secret { "1" } else { "0" })
            .env("AI_VAULT_DLG_OK", crate::i18n::tr("OK", "确定"))
            .env("AI_VAULT_DLG_CANCEL", crate::i18n::tr("Cancel", "取消"))
            .env("AI_VAULT_DLG_SHOW", crate::i18n::tr("Show", "显示"))
            .env("AI_VAULT_DLG_ALLOW", crate::i18n::tr("Allow", "允许"))
            .env("AI_VAULT_DLG_DENY", crate::i18n::tr("Deny", "拒绝"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let unspawned = || Out {
            spawned: false,
            code: 127,
            stdout: String::new(),
            stderr: String::new(),
        };
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(_) => return unspawned(),
        };
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());
        // A window nobody answers must not hold the caller forever, exactly as
        // zenity's --timeout does not: after DIALOG_SECONDS it is ours to close,
        // and closing it is a cancel. (Windows has no `giving up after`.)
        let deadline = Instant::now() + Duration::from_secs(DIALOG_SECONDS as u64);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let stdout = stdout.join().unwrap_or_default();
        let stderr = stderr.join().unwrap_or_default();
        match status {
            None => Out { spawned: true, code: 1, stdout, stderr },
            Some(status) => Out { spawned: true, code: status.code().unwrap_or(-1), stdout, stderr },
        }
    }

    /// Exit 1 with nothing on stderr is the user's cancel. Anything else means
    /// no answer came out of a window: our own exit 2, a script PowerShell
    /// could not even parse (exit 1, with the error on stderr), or a crash.
    fn failed(out: &Out) -> bool {
        !out.spawned || (out.code != 0 && out.code != 1) || (out.code == 1 && !out.stderr.trim().is_empty())
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

    /// Whether this process may show a window at all. Only the interactive
    /// session's window station (`WinSta0`) is visible; a service, a scheduled
    /// task that runs without a logged-on user, or an sshd session gets a
    /// `Service-0x0-…` station instead, where a dialog would open onto a
    /// desktop nobody sees and never be answered.
    pub fn has_display() -> bool {
        // USEROBJECTFLAGS, as user32 lays it out: two BOOLs and a DWORD.
        #[repr(C)]
        #[derive(Default)]
        struct UserObjectFlags {
            f_inherit: i32,
            f_reserved: i32,
            dw_flags: u32,
        }
        const UOI_FLAGS: i32 = 1;
        const WSF_VISIBLE: u32 = 0x0001;
        #[link(name = "user32")]
        extern "system" {
            fn GetProcessWindowStation() -> *mut core::ffi::c_void;
            fn GetUserObjectInformationW(
                hobj: *mut core::ffi::c_void,
                index: i32,
                info: *mut core::ffi::c_void,
                len: u32,
                needed: *mut u32,
            ) -> i32;
        }
        // SAFETY: two Win32 queries against the calling process's own window
        // station; every pointer is either handed out by the OS or a live local.
        unsafe {
            let station = GetProcessWindowStation();
            if station.is_null() {
                return false;
            }
            let mut flags = UserObjectFlags::default();
            let mut needed: u32 = 0;
            let ok = GetUserObjectInformationW(
                station,
                UOI_FLAGS,
                &mut flags as *mut UserObjectFlags as *mut core::ffi::c_void,
                std::mem::size_of::<UserObjectFlags>() as u32,
                &mut needed,
            );
            ok != 0 && flags.dw_flags & WSF_VISIBLE != 0
        }
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

    // The rest of this file's helpers exist only where zenity does.
    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn gtk_diagnostics_are_not_failures() {
        assert!(is_gtk_diagnostic("(zenity:1234): Gtk-WARNING **: cannot open display"));
        assert!(!is_gtk_diagnostic("zenity: command not found"));
        assert!(!is_gtk_diagnostic("Aborted (core dumped)"));
    }

    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

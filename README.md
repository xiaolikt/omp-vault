# ai-vault

[中文版](README.zh.md)

One encrypted secret store per machine. `ai-vault` is a Rust CLI that owns the
store, the cryptography and the desktop dialogs; the pi/omp extension is only a
client of it, so agents no longer keep a copy each.

```
~/.ai-vault/store.json      ChaCha20-Poly1305 + scrypt, 0600
~/.ai-vault/audit.log       who read what and when; never a value
~/.ai-vault/store.lock      file lock for read-modify-write across processes
$XDG_RUNTIME_DIR/ai-vault/sessions/<token>.json   unlock tokens (0600, tmpfs)
%TEMP%\ai-vault\sessions\<token>.json             the same on Windows: a regular file under the user's profile
```

Because the location is fixed and owned by the CLI, pi, omp, scripts and any
other agent on the machine see the same imported passwords. No more "this agent
imported it, that one didn't".

## Why a CLI plus an extension

- **One implementation of the cryptography** (Rust). The extension holds no key,
  no crypto code and no second store.
- **Sessions do not live in the agent process.** `ai-vault unlock` derives the
  key and writes a short token file; the extension only holds the token id. If
  the agent crashes, reloads or switches session, the key expires with the token.
- **One dialog implementation.** With a desktop the CLI opens its own window;
  without one it exits with code `3` and only then does the extension use its
  host's prompt. Two windows never compete for input.
- **Easy to add a host.** Any new agent, in any language, uses the same store if
  it can run `ai-vault get <name> --json`.

## Language

Documentation is English by default; [README.zh.md](README.zh.md) is the Chinese
edition. The CLI and the extension show English in dialogs, prompts and
messages unless `AI_VAULT_LANG=zh` is set (or the locale is `zh_*`); the
extension passes the language down to the CLI so both halves agree. Texts a
host parses — exit codes, `needs-ui:`, error patterns — never change.

## Install

### npm

Three packages:

| Package | Contents | Who installs it |
|---|---|---|
| `@xiaolikt/ai-vault` | the `bin/ai-vault.cjs` dispatcher + Rust sources | anyone who wants just the CLI |
| `@xiaolikt/ai-vault-<os>-<arch>` | the prebuilt binary, `os`/`cpu` gated | pulled in by the above |
| **`pi-ai-vault`** | the pi/omp extension (`vault_*` + `bw_*` + `ente_*` tools) | pi or omp; depends on the above |

```bash
npm i -g @xiaolikt/ai-vault      # just the CLI
pi install npm:pi-ai-vault       # the extension (brings the CLI along)
omp plugin install npm:pi-ai-vault
```

The extension is a pi extension manifest; omp is a pi-compatible fork, so
**one package serves both hosts**: omp gets `bw_run`, pi additionally gets
`bw_inject`. The only differences are feature-detected at runtime in `src/host.ts`.

The bare name `ai-vault` is taken on npm (3.5.1), hence the scope. `bin/ai-vault.cjs`
is only a forwarder: it finds the real binary in `@xiaolikt/ai-vault-<os>-<arch>`
and hands over argv, stdio and **the exit code** (3/4/5 are the host contract and
must not be rewritten).

### Platforms

| Platform | Status |
|---|---|
| Linux x64 / arm64 | ✅ published (`@xiaolikt/ai-vault-linux-x64` / `-linux-arm64`) |
| Windows x64 | ✅ published (`@xiaolikt/ai-vault-win32-x64`); dialogs via Windows PowerShell + WinForms, both built in |
| macOS arm64 / x64 | 🔧 compiles (`cargo check --target aarch64-apple-darwin` passes); the binary needs the Apple SDK, so `.github/workflows/build.yml` builds it on a macOS runner |

What is portable:
- **Crypto/storage**: pure Rust (chacha20poly1305, scrypt, hmac, sha2, base64, zeroize)
- **File locks**: `fs4` (flock on Linux/macOS, LockFileEx on Windows)
- **Permissions**: 0600/0700 on Unix; Windows has no mode bits and relies on the
  `%USERPROFILE%\.ai-vault` ACL
- **Session directory**: `$XDG_RUNTIME_DIR` (Linux), `$TMPDIR` (macOS), `%TEMP%`
  (Windows) — per-user; tmpfs on Linux, and on Windows a regular folder that the
  next `ai-vault` run sweeps of expired tokens
- **Dialogs**: zenity / osascript / PowerShell+WinForms behind one `Answer`
  contract (`NoUi` is what falls back to the host prompt)

Cross-compile yourself (no Mac or Windows machine needed):

```bash
cargo install cargo-zigbuild
rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-gnu
cargo zigbuild --release --target aarch64-unknown-linux-gnu
cargo zigbuild --release --target x86_64-pc-windows-gnu
./scripts/stage-npm.sh linux-arm64 --from target/aarch64-unknown-linux-gnu/release/ai-vault
./scripts/stage-npm.sh win32-x64  --from target/x86_64-pc-windows-gnu/release/ai-vault.exe
```

`stage-npm.sh` accepts either an npm platform name (`darwin-arm64`) or a Rust
triple (`aarch64-apple-darwin`). macOS binaries can only be linked with the
Apple SDK, so CI does that (build + publish on a `v*` tag). The darwin packages
are already listed under `optionalDependencies`; npm skips an optional
dependency that is not published yet, so the list can precede them.
`--from` refuses a binary older than the last version bump, and one that can run
here must also report the version being published.

### Windows

- **The extension starts `ai-vault.exe` itself.** Node will not run npm's
  `.cmd`/`.ps1` wrappers without a shell, so the plugin resolves the binary of
  `@xiaolikt/ai-vault-win32-x64` directly and, where only a wrapper exists, reads
  it and starts what it names with its own Node.
- **A dialog needs an interactive session.** Services, scheduled tasks that run
  without a logged-on user and sshd sessions have no visible desktop; there the
  CLI answers exit code 3 (`needs-ui`) and the host prompt is used. A window
  nobody answers closes after the same 600 s as on Linux, and counts as a cancel.
- **What is typed in a dialog is UTF-8**, whatever the console's code page is
  (936 on a Chinese Windows). A dialog that fails to open is reported as
  `needs-ui`, never as a cancel.
- **`bw` installed with npm works** (`bw.cmd` is unwrapped the same way).
  `bw_run` needs Git for Windows: `bash.exe` is looked up next to the `git.exe`
  on PATH. The clipboard goes through Windows PowerShell, as UTF-8 on stdin and
  stdout.
- The store is `%USERPROFILE%\.ai-vault`, protected by the profile's ACL.

### From source / git

```bash
# 1. Build the CLI and put it on PATH (~/.local/bin/ai-vault)
./install.sh

# 2. The extension (the repo root has a pi manifest pointing at
#    packages/pi-ai-vault, so git installs keep working)
pi install git:github.com/xiaolikt/ai-vault
omp plugin install git+ssh://git@github.com/xiaolikt/ai-vault.git

# 3. Create the store (a dialog asks for the master password, twice)
/vault init
```

Requires Rust (`cargo`) to build; at runtime `zenity` for dialogs (the host
prompt is the fallback).

**Do not install `omp-vault` or `pi-bitwarden` alongside ai-vault**: they
register the same `vault_*` / `bw_*` tools and you get duplicates. Both are
archived; see *Migrating*.

### Migrating

- **From `omp-vault`** (the TypeScript predecessor): the first time `ai-vault`
  runs and `~/.ai-vault/store.json` is absent while `~/.omp/vault/store.json`
  exists, the CLI **copies** (never deletes) the store and audit log across.
  The master password is unchanged — the file format is the same, only the
  location moved. The old files stay for as long as you want a way back.
- **From `pi-bitwarden`** (archived): every tool it had is here under the same
  name. `pi remove git:github.com/xiaolikt/pi-bitwarden` first, then install
  `pi-ai-vault`.

## CLI

```text
ai-vault [--dir DIR] [--json] <command>
```

| Command | What it does |
|---|---|
| `path` | print the store and session locations |
| `doctor` | paths, whether initialised, desktop/zenity availability, KDF, version |
| `init [--password-stdin]` | create the store (a dialog sets the password twice); prints a token |
| `unlock [--password-stdin] [--requester ID]` | unlock under the current policy; prints a token |
| `mode [get]` / `mode set never\|time\|session [--hours N]` | show / switch the unlock policy (switching needs the master password) |
| `settings [key] [value]` | every setting: `vault.*` `bitwarden.*` `ente.*` |
| `bw-session get\|put\|clear` | the persisted `bw` session key (used when `bitwarden.unlock != session`; sealed at rest) |
| `ente-session get\|put\|clear` | Ente's `ENTE_CLI_VAULT_KEY` (used when `ente.unlock != session`; sealed the same way) |
| `rekey` | raise an old store's scrypt parameters to the current default (needs the master password) |
| `status --token T` | item count, expiry, live read grants |
| `lock --token T \| --all` | drop a token (`--all` ends every session on the machine) |
| `list --token T` | entry metadata (name/username/URI); no passwords |
| `get <name> [--reason R] [--answer-stdin]` | read one entry; a confirm window opens unless a grant is live |
| `add --name N [--type TYPE] [--field NAME[=VALUE]]… [--secret NAME=VALUE]… [--username U] [--uri U] [--notes N] [--password-stdin] [--yes]` | create/update any type; a hidden field left out is typed in a dialog (`--secret` is for a host that already asked) |
| `save --yes [--file F]` | read an array of entries as JSON and write them (the import path) |
| `remove <name> [--yes]` | delete (quote names with spaces) |
| `grant <name> [--minutes N]` / `revoke <name\|--all>` | a standing read grant (default 5 min, max 60); `grant` costs the master password |
| `audit [n]` | the last n audit lines (default 30) |
| `import <bitwarden.json> [--yes]` | import an unencrypted Bitwarden export, every item type |

The token can also come from `AI_VAULT_TOKEN`. The store directory is `--dir`,
then `AI_VAULT_DIR`, then `~/.ai-vault`.

### Exit codes (the host contract)

| Code | Meaning | What a host does |
|---|---|---|
| 0 | success | stdout is the result (JSON with `--json`) |
| 1 | error | show the first stderr line to the user |
| 2 | usage error | same |
| 3 | needs UI | stderr says `needs-ui: password\|text\|confirm`; the host prompts itself and sends the value back on stdin with the matching flag |
| 4 | user denied / cancelled | **do not retry**; ask the user |
| 5 | locked / wrong password | `unlock` again, or report the wrong password |

So a headless machine works too: `unlock --password-stdin`, `add --password-stdin --yes`
and `save --yes` need no window at all.

**Relaying a confirmation is a host privilege** and needs all three of:

```bash
AI_VAULT_HOST=1 \
AI_VAULT_HOST_SECRET=<the secret the host minted> \
ai-vault get <entry> --token <T> --answer-stdin --approval <hex> <<< 'y'
# approval = HMAC-SHA256(hostSecret, "allow:<T>:<entry lowercased>:y")
```

`unlock`/`init` only echo a `hostSecret` back to a caller that already presented
one. It exists only in the host process's memory; the CLI signs session files
with it and checks relays against it. Missing any one of the three, `--answer-stdin`
is exit code 2. That is why the model's `bash`, even with a token in hand,
cannot sign an "allow".

## Extension tools

| Tool | What it does | Tier | Model sees the secret? |
|---|---|---|---|
| `vault_list` | local store metadata | read | no |
| `vault_get` | read one, any type: **local store first, Bitwarden second**; a Bitwarden hit follows `bitwarden.import` (ask / import / read once) | exec | yes, user-approved on the spot |
| `vault_add` | store one, any type; secret fields are typed in a dialog | write | no |
| `vault_import` | copy Bitwarden items of every type into the local store, field for field (asks first) | write | no |
| `bw_list` | live Bitwarden metadata | read | no |
| `bw_run` | run one command with `$VAULT_SECRET` in its env; output scrubbed | exec | no |
| `bw_inject` | inject into the bash env (**pi only**) | exec | no |
| `bw_clipboard` | copy to the clipboard, cleared after a delay | write | no |
| `bw_reveal` | plain text (off by default, confirmed per call) | exec | yes, user-approved on the spot |
| `ente_list` | Ente Auth entry metadata (name/issuer/account/type) | read | no |
| `ente_code` | one current TOTP/Steam code, confirmed per call | write | yes, user-approved on the spot |

Ente's login is managed by `ente` itself (once); `ente.unlock` only decides
whether ai-vault keeps `ENTE_CLI_VAULT_KEY` sealed for it.

Field selector: `password` (default) · `totp` (seed) · `code` (rotating code) ·
`notes` · `field:<custom field name>`.

### Item types

ai-vault stores the same item types Bitwarden does, with the same field names,
so an import is a copy and a manual entry is the same shape:

| Type | `--type` | Its own fields (`data`) | Secret field |
|---|---|---|---|
| Login | `login` (default) | `username`, `password`, `totp` + `uris` | `password` |
| Secure note | `note` | none — the content is `notes` | — |
| Card | `card` | `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code` | `number`, `code` |
| Identity | `identity` | `title`, `firstName`, `middleName`, `lastName`, `address1–3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber` | `ssn`, document numbers |
| SSH key | `sshkey` | `privateKey`, `publicKey`, `keyFingerprint` | `privateKey` |
| Bank account | `bankaccount` | `bankName`, `nameOnAccount`, `accountType`, `accountNumber`, `routingNumber`, `branchNumber`, `pin`, `swiftCode`, `iban`, `bankContactPhone` | `accountNumber`, `routingNumber`, `pin` |
| Driver's licence | `driverslicense` | `firstName`, `middleName`, `lastName`, `dateOfBirth`, `licenseNumber`, `issuingCountry`, `issuingState`, `issueDate`, `expirationDate`, `issuingAuthority`, `licenseClass` | `licenseNumber` |
| Passport | `passport` | `surname`, `givenName`, `dateOfBirth`, `sex`, `birthPlace`, `nationality`, `issuingCountry`, `passportNumber`, `passportType`, `nationalIdentificationNumber`, `issuingAuthority`, `issueDate`, `expirationDate` | `passportNumber`, `nationalIdentificationNumber` |

The last three are behind Bitwarden's "new item types" flag; the CLI stores
them the same way. Every type also carries `notes` and custom `fields[]`
(`type`: 0 text · 1 hidden · 2 boolean · 3 linked, as in Bitwarden). A hidden
custom field is treated as a secret everywhere.

```bash
# by hand: non-secret fields on the line, the secret typed in a window
ai-vault add --name Visa --type card --field cardholderName="Li Jun" --field brand=Visa --field expYear=2029
ai-vault add --name "Wifi" --type note --notes "guest network: …"
ai-vault add --name server --type sshkey --field publicKey="ssh-ed25519 AAAA"   # private key typed
```

`list` shows the type and the non-secret fields (cardholder, brand, expiry,
a person's name, the key's fingerprint…); it never shows a password, card
number or code, private key, PIN, account or document number, a hidden custom
field, a TOTP seed, or a secure note's body. `get` returns the whole entry.

The `vault_add` tool takes `type` and `fields` the same way. A secret field the
model fills in itself is refused: those are typed by the user in a dialog, one
window per field.

### Lookup order: local first, Bitwarden as fallback

`vault_get` asks `ai-vault` (the store this machine shares) first and only
searches Bitwarden on a miss:

```
vault_get "github"
  ├─ in ai-vault     → returned (the unlock policy decides whether a window opens)
  └─ not in ai-vault → search Bitwarden
       ├─ no hit  → "not local, not in Bitwarden"
       └─ hit      → ① show you the entry (name/user), ask whether to read it
                     ② after reading, ask: import into ai-vault, or use once?
```

That keeps the two apart: **only the passwords you approve for import ever
enter ai-vault**, and ai-vault is the set "the agent may use freely". Everything
else stays in Bitwarden and asks every time.

### Unlock policies

When `ai-vault` asks for its master password is a per-machine setting
(`~/.ai-vault/config.json`):

| Mode | Behaviour | For |
|---|---|---|
| `never` | never asks. The key lives in `~/.ai-vault/agent.session.json` (0600) and **reads open no window either** | handing the agent a set of "use freely" passwords |
| `time` | asks again N hours after the unlock (default 8, `--hours`) | long bounded tasks |
| `session` | once per session; dies with it (default) | everyday |

```bash
ai-vault mode                      # show
ai-vault mode set never            # switching needs the master password
ai-vault mode set time --hours 4
ai-vault mode set session
```
In the extension: `/vault mode`, `/vault mode time 4`. **Switching always costs
the master password** — especially into `never`, because that writes the key to disk.

`never` is not "a bit safer"; it is explicitly giving up this layer: any process
that can read your home directory can read every password in the store. Its point
is to separate "the AI may use these" from "ask me every time".

### Bitwarden has the same three modes (set separately)

| Setting | Value | Behaviour |
|---|---|---|
| `bitwarden.unlock` | `never` | the `bw` session key is kept on disk (`~/.ai-vault/bitwarden.session.json`, 0600, sealed); **no Bitwarden master password is asked** |
| | `time` | the same, but it expires after `bitwarden.hours` and the password is asked again |
| | `session` | the key stays in the agent's memory; asked once per session (default) |
| `bitwarden.import` | `ask` | local miss → show the Bitwarden hit → read once → ask whether to import (default) |
| | `always` | import on a hit and return it, **no window at all** (fully automatic; use with care) |
| | `never` | read once, ask once, never write to the local store |

```bash
ai-vault settings                                   # everything
ai-vault settings bitwarden.unlock never
ai-vault settings bitwarden.import always
ai-vault settings bitwarden.hours 24
```
In the extension: `/vault settings`, `/vault settings bitwarden.import always`.

> `bitwarden.import = always` together with `bitwarden.unlock = never` means
> "anything in Bitwarden that gets asked for is imported automatically and read
> without a password from then on". Fastest and least guarded combination; only
> with an agent you fully trust.

`bw-session put/get/clear` is the handle for that persisted key: the extension
writes it after a successful master-password unlock, it is cleared when the
policy goes back to `session`, and `/bw lock` clears it too.

## Extension commands

```
/vault init                        create the local store (dialog sets the master password)
/vault add card:Visa brand=Visa code   type:name, fields on the line, a bare field typed in a dialog
/vault unlock | lock               unlock / lock this session
/vault mode [never|time|session]   show / switch the unlock policy (switching needs the password)
/vault settings [key value]        show / change settings (bitwarden.*, ente.*)
/vault ente-key                    save Ente's ENTE_CLI_VAULT_KEY (no keychain, no login)
/vault status                      state, expiry, grants left
/vault list                        entry metadata
/vault add [type:]name [field=value|field]…   add any type; a bare field is typed in a dialog
/vault remove <name>               delete (quote names like "GitHub (2)")
/vault grant <name> [minutes]      a standing read grant (needs the master password)
/vault revoke <name|all>           revoke grants
/vault audit [n]                   the last n audit lines
/vault import <bitwarden.json>     import an unencrypted export
/vault import-bw [search]          import logins straight from bw
/bw status|unlock|lock|clear       the live Bitwarden session
```

## Sessions and isolation

- Every binding (a session, or a subagent) runs its own `ai-vault unlock` on
  first use and gets **its own token**. A subagent cannot inherit the parent's
  unlock or grants; the confirm window says "requester: subagent 0-Explore".
- Token lifetime follows the unlock policy (above): `session` up to 24 hours,
  `time` until N hours, `never` never. `/new`, `/fork` and quitting make the
  extension drop its own token; `/resume` keeps it. Expired, tampered or
  old-store token files are swept on **every** CLI call.
- Read grants live in the token, so they are isolated per requester by
  construction; `/vault grant` and `/vault revoke` change exactly that.
- The store file itself is shared: read-modify-write holds a file lock, so two
  agents writing at once do not lose updates.

## Bitwarden

Requires `bw` (run `bw login` first). The first use asks for the master password
in a window; after that each call only needs "allow" in the confirm window.

- To run a command without the secret entering the conversation: `bw_run`. The
  value is in the child's environment and gone when the command ends; the raw
  value and its base64/base64url/URL/hex forms (including `base64`'s 76-column
  wrapping and `xxd`'s spaced hex) are replaced in stdout/stderr with
  `[BW_SCRUBBED:VAR]`. Output is capped at 8 MiB; the excess is dropped and marked.
- On pi, `bw_inject` puts it in the bash environment for several commands.
- Values copied by `bw_clipboard` join the scrub list too: reading the
  clipboard back with `pbpaste` / `xclip -o` / `wl-paste` is scrubbed as well.
- The confirm window shows the **entry actually matched** (name + username), not
  the reference the model gave.
- `/bw lock` only drops the current binding's session key; a global `bw lock`
  runs only when the last binding in the process releases its key.
- The Bitwarden session key lives in the agent process's memory only, unless
  `bitwarden.unlock` is `never`/`time`, in which case it is sealed at rest
  (see *Security*).

## Ente (Auth codes)

`ente` is Ente's official terminal client (0.4+). It **logs in once**:

```bash
ente account login --app auth        # email + password (+ a 2FA code)
ente auth code list                  # never asks for the password again
```

The session lives in `$XDG_DATA_HOME/ente-cli` (`~/.local/share/ente-cli` on
Linux) and the database key in the OS keychain by default. For a machine
without a desktop or keychain:

```bash
ente vault key generate              # prints a key; generate it once
/vault ente-key                      # paste it into the dialog; ai-vault seals it
/vault settings ente.unlock never    # ente children get it automatically
```

So in the everyday `session` form, **looking up a code never asks for your
password** — at most one keychain unlock.

`ente.unlock` is the same three-way switch as `bitwarden.unlock`
(`never`/`time`/`session`); `ente-session get|put|clear` is its CLI handle. The
key is sealed under the store directory's wrap key (0600); copying
`ente.session.json` away yields nothing. The extension never passes an
`ENTE_CLI_VAULT_KEY` exported in your shell to a child — only its own sealed copy.

pi-ai-vault is only a client of that CLI and keeps no Ente key of its own:

| Tool | What it does |
|---|---|
| `ente_list` | list entries (name / issuer / accountName / type); **no codes** |
| `ente_code <name>` | show the entry actually matched in a window; on allow, return the current code and its expiry |

Same rules as `bw_*`: listing is metadata only; reading a code is confirmed
every time; a deny is final; both outcomes are audited (`~/.bw/pi-extension/audit.log`,
`ente.code` events, never the code itself); names and issuers are flattened to one
line before they reach a window.

The bash the extension starts strips `ENTE_CLI_VAULT_KEY` / `ENTE_CLI_PASSWORD`,
so an unattended key you exported does not leak into the model's own commands.
**Note**: the `ente` binary is on PATH, so the model running `ente auth code view`
directly still bypasses this extension's confirm window. Tightening that means
`ENTE_CLI_VAULT_KEY` plus pointing the model's `ENTE_CLI_HOME` elsewhere — or not
giving the agent a shell.

## Security

### Threat model: who can do what

Everything runs as **your user**, so the boundary is not "you vs other users" but
**you (the human) vs the agents running under your account**. The goal: the agent
may *use* passwords but cannot *get around you* to take them.

| Role | Can | Cannot |
|---|---|---|
| **You** (typing `ai-vault` in a terminal) | everything | — |
| **The host** (the pi/omp extension process; `AI_VAULT_HOST=1` + a secret in memory) | relay your confirmations (signed), change settings | learn the master password unless you type it |
| **The agent** (the model's `bash`, same user, can read `~/.ai-vault`) | read a token file (but a session the extension opened is useless without the secret — first use is refused) | **forge a read confirmation, mint a grant on a token, change the requester shown in a window, `list` an extension session, get the Bitwarden master password, change any setting by editing a file** |
| **Another user / someone with the files offline** | read ciphertext | decrypt (scrypt + ChaCha20-Poly1305) |

### How

- **The confirm window cannot be bypassed.** `vault_get`'s confirmation is
  either the CLI's own window or an answer relayed by the host. A relayed
  answer must carry `--approval`: an HMAC under the **host process's in-memory
  secret** over `allow:<token>:<entry>:<y|n>`. The model's bash can find the
  token file but not the secret, so it cannot sign; a signature for another
  entry, or with `n` flipped to `y`, does not match.
- **Token files cannot be edited.** Every session file carries an HMAC (host
  sessions under the host secret, hand-typed CLI sessions under the store's wrap
  key). Change `grants`, change `requester`, change one byte: the CLI reports
  `session file was modified outside ai-vault` and deletes the file.
- **`grant` is no longer free.** "No window for N minutes" on an entry is a
  standing approval and now costs the master password, like a policy change.
- **`never` mode is giving up the above on purpose.** The key is written to
  `~/.ai-vault/agent.session.json` and reads open no window. Its point is to
  separate "the AI may use these" from "ask me every time". Turning it on means
  trusting the agent's output channel, not just the agent.
- **Sealed Bitwarden session.** With `bitwarden.unlock = never|time` the `bw`
  session key is sealed with ChaCha20-Poly1305 under `~/.ai-vault/.wrap` (0600)
  into `~/.ai-vault/bitwarden.session.json`. Copying that file alone opens
  nothing. A `bw unlock --raw` session key is read access to your **entire**
  Bitwarden vault, so that file is at least as sensitive as the store itself.
  Ente's vault key gets the same treatment.
- **The text in a confirm window is not written by the model.** Entry names,
  reasons, usernames and URIs are flattened to one line, control characters
  removed, truncated to 80–120 characters before they reach a window, so a
  newline in a name cannot forge a second "approved" block.
- **KDF.** New stores use scrypt `N=2^17` (128 MiB); the parameters travel in the
  file header, so an old store (`N=2^15`) opens unchanged and `ai-vault rekey`
  upgrades it. Anything below `2^15` is refused as a downgrade.
- **The master password** only passes through a dialog or the host prompt; the
  key `unlock` derives only goes into the token file (0600, tmpfs when there is
  one; on Windows a regular file under `%TEMP%`, protected by the profile's ACL,
  which a reboot leaves in place until the next `ai-vault` run removes it once
  expired). `BW_*` is stripped from every child environment.
- **Audit**: `~/.ai-vault/audit.log` records sessions, entries, allow/deny with
  the reason, and attempts such as `unsigned-relay`, `bad-approval`,
  `modified-outside`; never a value. Rotated at 1 MiB.
- **Atomic writes + file lock**: temp file (0600) → fsync → rename → directory
  fsync; a file lock around read-modify-write. Expired, tampered and old-store
  token files are swept on every call.
- `bw_reveal` is off by default; the scrubber only engages for values ≥ 6
  characters and cannot stop exfiltration over the network or one-way hashes —
  `bw_run` / `bw_inject` are about keeping values out of the conversation, not
  about stopping an agent that has been injected.
- `notes` appear only in `get` (after approval); `list` never prints them.

### Known limits

- In `session` mode the model's bash **can** read a token file, but it does it
  no good: a session the extension opened is signed under the host's in-memory
  secret, and without that secret the first use is judged "modified" and voided
  (no `list` either; the file is deleted). Only a session **you** opened by
  typing `ai-vault unlock` in a terminal (signed under the wrap key) can be
  `list`ed by a same-user process — that session had no window to bypass in
  the first place. This is the inherent exposure of "same user"; really
  tightening it needs a different user or a container.
- A caller with `AI_VAULT_HOST=1` but no secret is treated as a human: it gets
  no secret and cannot relay.
- `bitwarden.import = always` + `bitwarden.unlock = never` means "anything in
  Bitwarden that gets asked for is imported automatically". Not recommended; it
  can be turned on.
- The title bar of a zenity window belongs to the window manager; a full-screen
  fake window is out of scope.

## Developing

```bash
cargo test                  # Rust unit tests (store, crypto format, import mapping)
npm test                    # builds the CLI, then runs the extension tests (real CLI + mock zenity/ente)
npm run test:npm            # pack tarballs, install into a throwaway prefix, run the shim and exit codes
npm run test:cli            # the binary alone: headless exit-code contract, encryption at rest, audit
npm run typecheck
bash test/smoke.sh pi       # smoke on a real host (needs model credentials)
```

Layout:

```
crates/ai-vault/src/   main.rs cli.rs crypto.rs store.rs session.rs sealed.rs dialog.rs import.rs audit.rs paths.rs perms.rs config.rs
bin/ai-vault.cjs       npm entry: find the platform package, forward argv/stdio/exit code
scripts/stage-npm.sh   turn a release binary into an npm platform package
packages/pi-ai-vault/  the npm package pi-ai-vault: src/ = index.ts (tools/commands) cli.ts (CLI client)
                       settings.ts ente.ts bitwarden.ts prompt.ts host.ts import-map.ts scrub.ts
test/cli.sh            binary-level integration tests
test/npm.sh            npm pack/install/forwarding tests
```

## License

MIT

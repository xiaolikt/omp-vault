# pi-ai-vault

[中文版](README.zh.md)

The pi extension for [ai-vault](https://www.npmjs.com/package/@xiaolikt/ai-vault) — **omp installs the same package** (omp is a pi-compatible fork; the manifest and tool API are identical, and the only differences are feature-detected at runtime in `src/host.ts`).

It hands one machine-wide encrypted secret store to your agent: `~/.ai-vault`, shared by every agent on the machine. The extension does no cryptography itself; it only holds a session token.

## Install

```bash
pi install npm:pi-ai-vault          # pi; brings the ai-vault CLI along
omp plugin install npm:pi-ai-vault   # omp; the same package
```

Then, in that host's session:

```
/vault init
```

(A dialog asks for the master password, twice. With a desktop it is the CLI's own window; without one, the host's prompt.)

You can also install straight from the repository: `pi install git:github.com/xiaolikt/ai-vault`.

Do not install `pi-bitwarden` or `omp-vault` as well: they register the same `bw_*` / `vault_*` tools. Both are archived.

## Tools

| Tool | What it does | Model sees the secret? |
|---|---|---|
| `vault_list` | local store metadata | no |
| `vault_get` | read one: local store first, then Bitwarden; a Bitwarden hit follows `bitwarden.import` (ask / import / read once) | yes, user-approved on the spot |
| `vault_add` | store one, any Bitwarden type (login, note, card, identity, sshkey, bankaccount, driverslicense, passport); secret fields are typed in a dialog | no |
| `vault_import` | copy Bitwarden logins into the local store (asks first) | no |
| `bw_list` / `bw_run` / `bw_clipboard` / `bw_reveal` | live Bitwarden through the `bw` CLI | no (`bw_reveal` excepted) |
| `bw_inject` | inject into the bash env (**pi only**; omp does not register it) | no |
| `ente_list` | Ente Auth entry metadata | no |
| `ente_code` | one current TOTP/Steam code, confirmed per call | yes, user-approved on the spot |

## Commands

```
/vault init | unlock | lock | status | list | add | remove
/vault mode [never|time|session]      unlock policy (switching needs the master password)
/vault settings [key value]           bitwarden.*, ente.*
/vault ente-key                       save Ente's ENTE_CLI_VAULT_KEY
/vault grant <name> [minutes] | revoke <name|all> | audit [n]
/vault import <bitwarden.json> | import-bw [search]
/bw status|unlock|lock|clear
```

## Unlock policies

When the local store asks for its master password is a per-machine setting (`/vault mode`, switching needs the password):

| Mode | Behaviour |
|---|---|
| `never` | never asks, and reads open no window — the "the agent may use these freely" passwords |
| `time` | asks again N hours after the unlock (default 8) |
| `session` | once per session, dies with it (default) |

`vault_get` searches Bitwarden on a local miss; a hit is shown to you, then read once, then — following `bitwarden.import` — offered for import into ai-vault (so it never touches Bitwarden again) or used just this once. So **only the passwords you approve for import ever enter ai-vault**.

Bitwarden's own master-password prompts follow their own switch (`bitwarden.unlock`), and Ente's keychain is bypassed by `ente.unlock` — see `/vault settings`.

## Ente

The `ente` CLI logs in once (`ente account login --app auth`); the extension is only its client: `ente_list` is metadata, `ente_code` confirms every time.

To skip the keychain entirely: `ente vault key generate` → `/vault ente-key` → `/vault settings ente.unlock never`. The key is sealed by ai-vault.

## Security boundary, in one paragraph

The model's `bash` can find a session token and even `list` with one you opened by hand — but it **cannot sign a read confirmation** (the signing secret lives only in the extension process), **cannot edit a token file** (HMAC'd; an edit voids it), and **cannot get a free `grant`** (that costs the master password). Full details in the repository README, *Security*.

MIT

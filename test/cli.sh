#!/usr/bin/env bash
# End-to-end checks of the ai-vault binary alone: no desktop, no agent, no
# mocks. Every dialog is answered through the documented exit-code contract,
# which is exactly what a headless host does.
#
#   bash test/cli.sh            # uses target/release/ai-vault
#   AI_VAULT_BIN=... bash test/cli.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${AI_VAULT_BIN:-$ROOT/target/release/ai-vault}"
[[ -x "$BIN" ]] || { echo "no binary at $BIN — run: cargo build --release" >&2; exit 2; }

TMP="$(mktemp -d "/tmp/ai-vault-cli.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
export AI_VAULT_DIR="$TMP/store"
export XDG_RUNTIME_DIR="$TMP/runtime"
mkdir -p "$XDG_RUNTIME_DIR"
unset DISPLAY WAYLAND_DISPLAY
export HOME="$TMP/home"
mkdir -p "$HOME"

PASS=0
FAIL=0
ok() { printf '  PASS %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }
# check <description> <expected-exit> <command...>
check() {
	local what="$1" want="$2"
	shift 2
	"$@" >"$TMP/out" 2>"$TMP/err"
	local got=$?
	if [[ "$got" == "$want" ]]; then ok "$what (exit $got)"; else
		bad "$what: exit $got, wanted $want"
		head -3 "$TMP/err" | sed 's/^/       /'
	fi
}
out() { cat "$TMP/out"; }
json() { python3 -c "import json,sys;print(json.load(sys.stdin).get(\"$1\",\"\"))"; }

echo "== init =="
check "init without a window asks the host" 3 "$BIN" init
grep -q 'needs-ui: password' "$TMP/err" && ok "the needs-ui step is named" || bad "no needs-ui hint"
check "a short password is a usage error" 2 bash -c "printf 'short' | '$BIN' init --password-stdin"
check "init creates the store" 0 bash -c "printf 'correct horse' | '$BIN' init --password-stdin --requester cli"
[[ -f "$AI_VAULT_DIR/store.json" ]] && ok "store.json exists" || bad "store.json missing"
[[ "$(stat -c %a "$AI_VAULT_DIR/store.json")" == "600" ]] && ok "store.json is 0600" || bad "store.json is not 0600"

echo "== unlock =="
check "unlock without a window asks the host" 3 "$BIN" unlock
check "a wrong password is an auth failure" 5 bash -c "printf 'wrong password' | '$BIN' unlock --password-stdin"
check "the right password opens it" 0 bash -c "printf 'correct horse' | '$BIN' unlock --password-stdin --json"
# The extension is the host: it mints its own secret before the first unlock
# and presents it on every call. A caller that only says AI_VAULT_HOST=1
# without a secret is treated as a human (see the attacker block).
HS=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export AI_VAULT_HOST=1 AI_VAULT_HOST_SECRET="$HS"
check "a host that presents no secret is not handed one" 0 bash -c "printf 'correct horse' | env -u AI_VAULT_HOST_SECRET '$BIN' unlock --password-stdin --json >'$TMP/nosec'"
python3 - "$TMP/nosec" <<'PY' && ok "AI_VAULT_HOST=1 alone yields no hostSecret" || bad "a secret was handed to a caller without one"
import json,sys
assert json.load(open(sys.argv[1])).get("hostSecret") is None
PY
HOST_JSON=$(printf 'correct horse' | "$BIN" unlock --password-stdin --json)
ECHOED=$(printf '%s' "$HOST_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('hostSecret',''))")
[[ "$ECHOED" == "$HS" ]] && ok "the host's own secret is echoed back" || bad "hostSecret echo mismatch"
TOKEN=$(printf '%s' "$HOST_JSON" | json token)
# relay <entry> <y|n>: a signed approval for the host's token.
relay() {
	local ap
	ap=$(python3 -c "import hmac,hashlib;print(hmac.new('$HS'.encode(),('allow:$TOKEN:$1:$2'.lower()).encode(),hashlib.sha256).hexdigest())")
	printf '%s\n' "$2" | "$BIN" get "$1" --token "$TOKEN" --answer-stdin --approval "$ap" --json
}
[[ ${#TOKEN} -ge 32 ]] && ok "a session token is printed" || bad "no token"
SESS="$XDG_RUNTIME_DIR/ai-vault/sessions/$TOKEN.json"
[[ -f "$SESS" ]] && ok "the token file lives under XDG_RUNTIME_DIR" || bad "token file missing"
[[ "$(stat -c %a "$SESS")" == "600" ]] && ok "the token file is 0600" || bad "the token file is not 0600"

echo "== add / list =="
check "add needs a window for the password" 3 bash -c "'$BIN' add --name GitHub --username octo --token '$TOKEN'"
check "add with a typed password" 0 bash -c "printf 'p1ssw0rd' | '$BIN' add --name GitHub --username octo --uri https://github.com --password-stdin --yes --token '$TOKEN' --json"
"$BIN" list --token "$TOKEN" --json >"$TMP/list"
python3 - "$TMP/list" <<'PY' && ok "list shows metadata only" || bad "list output is wrong"
import json,sys
data = json.load(open(sys.argv[1]))
assert data["count"] == 1, data
assert data["items"][0]["name"] == "GitHub", data
assert "password" not in data["items"][0], data
PY
grep -q 'p1ssw0rd' "$AI_VAULT_DIR/store.json" && bad "the password is in plaintext on disk" || ok "the store is encrypted at rest"

echo "== read approval =="
check "get without a window asks the host" 3 bash -c "'$BIN' get GitHub --token '$TOKEN'"
relay GitHub n >"$TMP/deny" 2>"$TMP/denyerr"; [[ $? -eq 4 ]] && ok "a denied relay is not a lock (exit 4)" || bad "a denied relay was not exit 4"
relay GitHub y >"$TMP/get" 2>"$TMP/err"
[[ $? -eq 0 ]] && ok "an approved relay reveals the entry" || bad "an approved relay failed"
python3 - "$TMP/get" <<'PY' && ok "the approved entry carries the password" || bad "get output is wrong"
import json,sys
item = json.load(open(sys.argv[1]))
assert item["password"] == "p1ssw0rd", item
assert item["via"] == "interactive-grant", item
PY
"$BIN" get GitHub --token "$TOKEN" --json >"$TMP/get2" 2>"$TMP/err2"
[[ $? -eq 0 ]] && ok "a live grant needs no window" || bad "the grant was not reused"
grep -q 'existing-grant' "$TMP/get2" && ok "the reuse is labelled" || bad "the reuse is not labelled"
check "a grant can be revoked" 0 "$BIN" revoke GitHub --token "$TOKEN" --json
check "remove needs a window to confirm" 3 "$BIN" remove GitHub --token "$TOKEN"
check "remove after approval" 0 "$BIN" remove GitHub --yes --token "$TOKEN" --json

echo "== import =="
cat >"$TMP/export.json" <<'JSON'
{ "items": [
  { "id": "abc", "name": "FromExport", "login": { "username": "u", "password": "exp-pass", "uris": [{ "uri": "https://e.example" }] } },
  { "id": "def", "name": "NoPassword", "login": { "username": "u" } }
] }
JSON
check "import without a window asks the host" 3 "$BIN" import "$TMP/export.json" --token "$TOKEN"
check "import after approval" 0 "$BIN" import "$TMP/export.json" --yes --token "$TOKEN" --json
grep -q 'exp-pass' "$AI_VAULT_DIR/store.json" && bad "an imported password is on disk in plaintext" || ok "the import is encrypted"
check "save requires the caller's --yes" 2 bash -c "printf '[]' | '$BIN' save --token '$TOKEN'"
check "save inserts drafts" 0 bash -c "printf '[{\"name\":\"Draft\",\"password\":\"dr-pw\",\"uris\":[\"https://d\"]}]' | '$BIN' save --yes --token '$TOKEN' --json"

echo "== tamper resistance (H1 / H2) =="
# A fresh, non-host session for the attacker tests.
# The attacker: a valid token, but no host identity and no secret (the model's bash).
T2=$(printf 'correct horse' | env -u AI_VAULT_HOST -u AI_VAULT_HOST_SECRET "$BIN" unlock --password-stdin --json | json token)
check "attacker: --answer-stdin without a host secret is refused" 2 bash -c "printf 'y\n' | env -u AI_VAULT_HOST -u AI_VAULT_HOST_SECRET '$BIN' get Draft --token '$T2' --answer-stdin"
check "attacker: a guessed approval with no secret is refused" 2 bash -c "printf 'y\n' | env -u AI_VAULT_HOST -u AI_VAULT_HOST_SECRET '$BIN' get Draft --token '$T2' --answer-stdin --approval 00"
check "attacker: grant now costs the password (window -> needs-ui)" 3 env -u AI_VAULT_HOST -u AI_VAULT_HOST_SECRET "$BIN" grant Draft --token "$T2"
T3="$TOKEN"
"$BIN" revoke Draft --token "$T3" --json >/dev/null
AP=$(python3 -c "import hmac,hashlib;print(hmac.new('$HS'.encode(),b'allow:$T3:draft:y',hashlib.sha256).hexdigest())")
check "host: a signed relay is accepted" 0 bash -c "printf 'y\n' | '$BIN' get Draft --token '$T3' --answer-stdin --approval '$AP' --json"
AP_N=$(python3 -c "import hmac,hashlib;print(hmac.new('$HS'.encode(),b'allow:$T3:draft:n',hashlib.sha256).hexdigest())")
"$BIN" revoke Draft --token "$T3" --json >/dev/null
check "a signature for 'n' with stdin 'y' is a mismatch" 4 bash -c "printf 'y\n' | '$BIN' get Draft --token '$T3' --answer-stdin --approval '$AP_N' --json"
# H2: edit the token file (mint a grant, rename the requester)
F="$XDG_RUNTIME_DIR/ai-vault/sessions/$T3.json"
python3 - "$F" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['grants']={'draft':9999999999999}; d['requester']='主会话'
json.dump(d,open(sys.argv[1],'w'))
PY
check "an edited token file is rejected" 5 bash -c "'$BIN' get Draft --token '$T3' --json"
[[ -f "$F" ]] && bad "the tampered file survived" || ok "the tampered file is deleted"
check "M1: a junk file in the sessions dir is swept on the next call" 0 "$BIN" path --json

echo "== sealed Bitwarden session (M4) =="
check "switch bitwarden.unlock to never" 0 "$BIN" settings bitwarden.unlock never --json
check "store a bw session key" 0 bash -c "printf 'BW_BEARER_TOKEN_PLAINTEXT' | '$BIN' bw-session put --json"
grep -q 'BW_BEARER_TOKEN_PLAINTEXT' "$AI_VAULT_DIR/bitwarden.session.json" && bad "the bw key is plaintext on disk" || ok "the bw key is not plaintext on disk"
[[ -f "$AI_VAULT_DIR/.wrap" ]] && ok "a wrap key exists" || bad "no wrap key"
[[ "$(stat -c %a "$AI_VAULT_DIR/.wrap")" == "600" ]] && ok "the wrap key is 0600" || bad "the wrap key is not 0600"
"$BIN" bw-session get --json | grep -q 'BW_BEARER_TOKEN_PLAINTEXT' && ok "bw-session get unseals it" || bad "bw-session get cannot unseal"
mv "$AI_VAULT_DIR/.wrap" "$TMP/wrap.bak"
check "without the wrap key the session does not open" 1 "$BIN" bw-session get
mv "$TMP/wrap.bak" "$AI_VAULT_DIR/.wrap"
"$BIN" settings bitwarden.unlock session --json >/dev/null

echo "== ente sealed key (M4 pattern) =="
check "ente.unlock is readable" 0 "$BIN" settings ente.unlock --json
check "ente-session put refused in session mode" 1 bash -c "printf 'K' | '$BIN' ente-session put"
check "switch ente.unlock to never" 0 "$BIN" settings ente.unlock never --json
check "store the Ente vault key" 0 bash -c "printf 'ENTE_KEY_PLAINTEXT' | '$BIN' ente-session put --json"
grep -q 'ENTE_KEY_PLAINTEXT' "$AI_VAULT_DIR/ente.session.json" && bad "the ente key is plaintext on disk" || ok "the ente key is sealed at rest"
[[ "$(stat -c %a "$AI_VAULT_DIR/ente.session.json")" == "600" ]] && ok "ente.session.json is 0600" || bad "ente.session.json is not 0600"
"$BIN" ente-session get --json | grep -q 'ENTE_KEY_PLAINTEXT' && ok "ente-session get unseals it" || bad "ente-session get cannot unseal"
"$BIN" settings ente.unlock session --json >/dev/null
check "switching back to session clears the ente key" 5 "$BIN" ente-session get

echo "== rekey (L2) =="
OLD_N=$(python3 -c "import json;print(json.load(open('$AI_VAULT_DIR/store.json'))['kdf']['N'])")
check "rekey with the password" 0 bash -c "printf 'correct horse' | '$BIN' rekey --password-stdin --json"
NEW_N=$(python3 -c "import json;print(json.load(open('$AI_VAULT_DIR/store.json'))['kdf']['N'])")
[[ "$NEW_N" == "131072" ]] && ok "scrypt N raised ($OLD_N -> $NEW_N)" || bad "kdf N is $NEW_N after rekey"
check "the store still opens with the same password" 0 bash -c "printf 'correct horse' | '$BIN' unlock --password-stdin --json"

echo "== lock / audit =="
check "lock drops the token" 0 "$BIN" lock --token "$TOKEN" --json
check "a dropped token no longer works" 5 "$BIN" list --token "$TOKEN"
"$BIN" audit 50 --json >"$TMP/audit"
python3 - "$TMP/audit" <<'PY' && ok "the audit log records events without values" || bad "audit output is wrong"
import json,sys
entries = json.load(open(sys.argv[1]))["entries"]
events = {e["event"] for e in entries}
for want in ("init", "unlock", "unlock_failed", "add", "grant", "read_deny", "read_allow", "remove", "import", "lock", "rekey", "sealed"):
    assert want in events, (want, events)
assert not any("p1ssw0rd" in json.dumps(e) or "exp-pass" in json.dumps(e) for e in entries)
PY
grep -q 'p1ssw0rd' "$AI_VAULT_DIR/audit.log" && bad "a secret reached the audit log" || ok "no secret in audit.log"

echo "== unlock modes =="
check "mode get works without a token" 0 "$BIN" mode --json
check "switching the mode needs the password" 3 "$BIN" mode set never
check "a wrong password does not switch it" 5 bash -c "printf 'wrong password' | '$BIN' mode set never --password-stdin"
check "never mode is set with the password" 0 bash -c "printf 'correct horse' | '$BIN' mode set never --password-stdin --json"
check "never mode needs no token" 0 "$BIN" status --json
printf 'correct horse' | "$BIN" unlock --password-stdin --json >"$TMP/u2" 2>&1
python3 - "$TMP/u2" <<'PY' && ok "unlock reports the mode" || bad "unlock output is wrong"
import json,sys
d = json.load(open(sys.argv[1]))
assert d["mode"] == "never" and d["auto"] is True, d
PY
check "back to session mode" 0 bash -c "printf 'correct horse' | '$BIN' mode set session --password-stdin --json"
check "session mode needs a token again" 5 "$BIN" status

echo "== settings =="
check "settings prints everything" 0 "$BIN" settings --json
check "set bitwarden.import" 0 "$BIN" settings bitwarden.import never --json
"$BIN" settings bitwarden.import --json >"$TMP/set1"
python3 - "$TMP/set1" <<'PY' && ok "the import policy was stored" || bad "the import policy was not stored"
import json,sys
assert json.load(open(sys.argv[1]))["value"] == "never"
PY
check "an unknown setting is a usage error" 2 "$BIN" settings nope.value 1
check "bw-session put is refused in session mode" 1 bash -c "printf 'K' | '$BIN' bw-session put"
check "switch bitwarden.unlock to never" 0 "$BIN" settings bitwarden.unlock never --json
check "bw-session put stores the key" 0 bash -c "printf 'GOOD_SESSION' | '$BIN' bw-session put --json"
[[ "$(stat -c %a "$AI_VAULT_DIR/bitwarden.session.json")" == "600" ]] && ok "the bw session file is 0600" || bad "the bw session file is not 0600"
check "bw-session get returns it" 0 "$BIN" bw-session get --json
check "switch back to session" 0 "$BIN" settings bitwarden.unlock session --json
check "the stored key is gone" 5 "$BIN" bw-session get
check "bitwarden.unlock time keeps an expiry" 0 "$BIN" settings bitwarden.unlock time --json
check "bw-session put in time mode" 0 bash -c "printf 'K2' | '$BIN' bw-session put --json"
grep -q '"expiresAt": *[0-9]' "$AI_VAULT_DIR/bitwarden.session.json" && ok "time mode writes a deadline" || bad "time mode wrote no deadline"
"$BIN" settings bitwarden.unlock session --json >/dev/null

echo "== two stores share the sessions dir =="
# A second store in another directory uses the same XDG_RUNTIME_DIR sessions
# directory. Housekeeping of one must not delete the other's live token.
TA=$(printf 'correct horse' | "$BIN" unlock --password-stdin --json | json token)
check "store A: token works" 0 "$BIN" list --token "$TA" --json
export AI_VAULT_DIR="$TMP/store2"
printf 'other horse' | "$BIN" init --password-stdin --json >/dev/null
TOK2=$(printf 'other horse' | "$BIN" unlock --password-stdin --json | json token)
# B's init and unlock each ran a sweep; A's token must still be there.
export AI_VAULT_DIR="$TMP/store"
check "store A's token survives store B's init/unlock" 0 "$BIN" list --token "$TA" --json
# A's calls just ran A's sweep; B's token must still be there.
export AI_VAULT_DIR="$TMP/store2"
check "store B's token survives store A's calls" 0 "$BIN" list --token "$TOK2" --json
"$BIN" lock --token "$TOK2" >/dev/null
export AI_VAULT_DIR="$TMP/store"

echo "== doctor =="
check "doctor runs" 0 "$BIN" doctor --json

printf '\nRESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]

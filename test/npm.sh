#!/usr/bin/env bash
# Verify the npm packaging the way a user would consume it: pack both
# tarballs, install them into a throwaway prefix (no registry access), then
# run the installed `ai-vault` shim.
#
#   bash test/npm.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "/tmp/ai-vault-npm.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
# AI_VAULT_DIR below keeps the real ~/.ai-vault (and its migration) out of reach.

PASS=0
FAIL=0
ok() { printf '  PASS %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }

echo "== stage the platform package =="
bash "$ROOT/scripts/stage-npm.sh" >"$TMP/stage" 2>&1 || { cat "$TMP/stage"; exit 1; }
PLATFORM="$(cd "$ROOT/npm" && ls -d */ | head -1 | tr -d /)"
[[ -f "$ROOT/npm/$PLATFORM/bin/ai-vault" ]] && ok "staged $PLATFORM" || bad "nothing staged"

echo "== pack =="
mkdir -p "$TMP/tarballs"
(cd "$ROOT/npm/$PLATFORM" && npm pack --pack-destination "$TMP/tarballs" --silent >/dev/null) || bad "packing the platform package failed"
(cd "$ROOT" && npm pack --pack-destination "$TMP/tarballs" --silent >/dev/null) || bad "packing the root package failed"
ls "$TMP"/tarballs/*.tgz >/dev/null 2>&1 || { echo "no tarballs"; exit 1; }
PLATFORM_TGZ="$(ls "$TMP"/tarballs/*ai-vault-"$PLATFORM"*.tgz)"
ROOT_TGZ="$(ls "$TMP"/tarballs/*ai-vault-0*.tgz | grep -v -- "-$PLATFORM-" | head -1)"
[[ -n "$PLATFORM_TGZ" && -n "$ROOT_TGZ" ]] && ok "both tarballs exist" || bad "tarball names are wrong: $(ls "$TMP"/tarballs)"

# The platform package must not drag the JS extension along, and the root
# package must not drag a binary for every platform.
tar -tzf "$PLATFORM_TGZ" >"$TMP/platform.list"
tar -tzf "$ROOT_TGZ" >"$TMP/root.list"
grep -qx 'package/bin/ai-vault' "$TMP/platform.list" && ok "the platform tarball carries the binary" || bad "no binary in the platform tarball"
grep -q '^package/src/' "$TMP/platform.list" && bad "the platform tarball carries the extension" || ok "the platform tarball is binary-only"
grep -qx 'package/bin/ai-vault.cjs' "$TMP/root.list" && ok "the root tarball carries the shim" || bad "no shim in the root tarball"

echo "== install into a throwaway prefix =="
PREFIX="$TMP/prefix"
mkdir -p "$PREFIX"
if npm install -g --prefix "$PREFIX" --legacy-peer-deps --no-audit --no-fund "$ROOT_TGZ" "$PLATFORM_TGZ" >"$TMP/install" 2>&1; then
	ok "npm install -g succeeded with both tarballs"
else
	bad "npm install -g failed"
	sed 's/^/       /' "$TMP/install" | tail -20
fi

BIN="$PREFIX/bin/ai-vault"
[[ -x "$BIN" ]] && ok "the shim is linked as ai-vault" || bad "no $BIN"

echo "== run through the shim =="
[[ "$("$BIN" --version 2>/dev/null)" == ai-vault* ]] && ok "the shim runs the real binary (--version)" || bad "the shim did not run the binary"

export AI_VAULT_DIR="$TMP/store"
export XDG_RUNTIME_DIR="$TMP/runtime"
mkdir -p "$XDG_RUNTIME_DIR"
unset DISPLAY WAYLAND_DISPLAY
"$BIN" init >"$TMP/out" 2>"$TMP/err"
[[ $? -eq 3 ]] && ok "exit code 3 (needs-ui) survives the shim" || bad "the shim rewrote the exit code"
grep -q 'needs-ui: password' "$TMP/err" && ok "stderr is passed through untouched" || bad "stderr was not passed through"
printf 'correct horse' | "$BIN" init --password-stdin --json >"$TMP/init" 2>&1
[[ $? -eq 0 ]] && ok "init works through the shim" || { bad "init failed through the shim"; cat "$TMP/init"; }
printf 'wrong password' | "$BIN" unlock --password-stdin >/dev/null 2>&1
[[ $? -eq 5 ]] && ok "exit code 5 (auth) survives the shim" || bad "auth exit code was lost"
[[ -f "$AI_VAULT_DIR/store.json" ]] && ok "the store landed in AI_VAULT_DIR" || bad "no store file"

printf '\nRESULT: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]

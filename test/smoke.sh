#!/usr/bin/env bash
# Manual, model-driven smoke check on a real host. `npm test` drives the tools
# through a fake host; this runs the extension inside an actual omp or pi
# session with the mock bw CLI, so host wiring is exercised too.
#
#   OMP_MODEL=<provider/model> bash test/smoke.sh omp
#   PI_MODEL=<provider/model>  bash test/smoke.sh pi
#
# The host keeps the real HOME because it needs its own model credentials; the
# Bitwarden state (config + audit) is redirected into the throwaway directory
# instead, so nothing touches your real vault or logs.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-omp}"
STATE="$(mktemp -d "/tmp/omp-vault-$HOST.XXXXXX")"
mkdir -p "$STATE/cwd" "$STATE/sessions" "$STATE/bw"
export BW_MOCK_DIR="$STATE"
export OMP_VAULT_MOCK="$STATE"
export OMP_VAULT_DIR="$STATE/vault"
export OMP_VAULT_BW_DIR="$STATE/bw"
export PATH="$ROOT/tests/mocks/bin:$PATH"
# The mock zenity still needs a display to be asked at all; it never opens a window.
export DISPLAY="${DISPLAY:-:99}"

PASS=0
FAIL=0
ok() { printf '  PASS %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL + 1)); }

PROMPT='Call the bw_run tool with item TestService, field password, and exactly this command (do not shorten it): echo LEN=${#VAULT_SECRET}; printf %s "$VAULT_SECRET" | base64; printenv VAULT_SECRET'

case "$HOST" in
	omp)
		MODEL_ARGS=()
		[[ -n "${OMP_MODEL:-}" ]] && MODEL_ARGS=(--model "$OMP_MODEL")
		(cd "$STATE/cwd" && timeout 300 omp --session-dir "$STATE/sessions" --no-extensions \
			-e "$ROOT/src/index.ts" "${MODEL_ARGS[@]}" --auto-approve --mode json -p "$PROMPT" 2>&1) >"$STATE/events"
		;;
	pi)
		MODEL_ARGS=()
		[[ -n "${PI_MODEL:-}" ]] && MODEL_ARGS=(--model "$PI_MODEL")
		(cd "$STATE/cwd" && timeout 300 pi --no-session --no-extensions \
			-e "$ROOT/src/index.ts" "${MODEL_ARGS[@]}" --mode json -p "$PROMPT" 2>&1) >"$STATE/events"
		;;
	*)
		echo "usage: $0 [omp|pi]" >&2
		exit 2
		;;
esac

if grep -q 'LEN=21' "$STATE/events"; then
	ok "$HOST: bw_run saw the secret in the command environment (LEN=21)"
	if grep -q 'c3VwZXJzZWNyZXQ' "$STATE/events"; then
		bad "$HOST: the base64 form leaked"
	elif grep -q 'BW_SCRUBBED-B64:VAULT_SECRET' "$STATE/events"; then
		ok "$HOST: the base64 form was scrubbed"
	else
		printf '  INCONCLUSIVE: the model did not run base64; check %s/events\n' "$STATE"
	fi
else
	printf '  INCONCLUSIVE: bw_run did not run; events are in %s/events\n' "$STATE"
fi
if grep '"type":"tool_execution_end"' "$STATE/events" | grep -q 'supersecret-value-123'; then
	bad "$HOST: the raw secret appeared in a final tool result"
else
	ok "$HOST: the raw secret is absent from tool results"
fi
if grep -rqs 'supersecret-value-123' "$STATE/sessions" "$STATE/bw" "$STATE/vault" 2>/dev/null; then
	bad "$HOST: the raw secret was written to disk"
else
	ok "$HOST: the raw secret is absent from the session, the vault, and the audit log"
fi

printf '\nRESULT (%s): %d passed, %d failed (advisory)\n' "$HOST" "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || echo "state kept for inspection: $STATE"
exit 0

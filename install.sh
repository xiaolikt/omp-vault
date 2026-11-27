#!/usr/bin/env bash
# Build the ai-vault CLI and put it on PATH. The extension only calls this
# binary, so one install serves pi, omp, and anything else on the machine.
#
#   ./install.sh                 -> ~/.local/bin/ai-vault
#   ./install.sh /usr/local/bin   -> another directory
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/.local/bin}"

command -v cargo >/dev/null || { echo "cargo is required (https://rustup.rs)" >&2; exit 1; }
cargo build --release --manifest-path "$ROOT/Cargo.toml"

mkdir -p "$DEST"
install -m 755 "$ROOT/target/release/ai-vault" "$DEST/ai-vault"
echo "installed $("$DEST/ai-vault" --version) -> $DEST/ai-vault"

case ":$PATH:" in
	*":$DEST:"*) ;;
	*) echo "note: $DEST is not on PATH; add it so the pi/omp extension can find ai-vault" >&2 ;;
esac

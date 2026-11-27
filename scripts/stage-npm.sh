#!/usr/bin/env bash
# Build the release binary and stage it as the npm platform package.
#
#   ./scripts/stage-npm.sh                # current platform
#   ./scripts/stage-npm.sh linux-x64      # cross-built binary, caller supplies it
#   ./scripts/stage-npm.sh linux-x64 --from path/to/ai-vault
#
# Afterwards:
#   npm publish npm/<platform> --access public
#   npm publish --access public
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(node -p "require('$ROOT/package.json').version")"
PACKAGE="$(node -p "require('$ROOT/package.json').name")"

detect() {
	case "$(uname -s)" in
		Linux) OS=linux ;;
		Darwin) OS=darwin ;;
		*) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
	esac
	case "$(uname -m)" in
		x86_64|amd64) ARCH=x64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		*) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
	esac
	echo "$OS-$ARCH"
}

TARGET="${1:-$(detect)}"
shift || true
SOURCE="$ROOT/target/release/ai-vault"
if [[ "${1:-}" == "--from" ]]; then
	SOURCE="${2:?--from needs a path}"
	shift 2
	[[ -x "$SOURCE" ]] || { echo "no binary at $SOURCE" >&2; exit 1; }
else
	# A stale target/release would ship a binary with the wrong --version.
	cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi

OS="${TARGET%%-*}"
ARCH="${TARGET##*-}"
OUT="$ROOT/npm/$TARGET"
EXE="ai-vault"
[[ "$OS" == "win32" ]] && EXE="ai-vault.exe"
mkdir -p "$OUT/bin"
install -m 755 "$SOURCE" "$OUT/bin/$EXE"

cat >"$OUT/package.json" <<JSON
{
	"name": "$PACKAGE-$TARGET",
	"version": "$VERSION",
	"description": "Prebuilt ai-vault binary for $TARGET.",
	"license": "MIT",
	"repository": {
		"type": "git",
		"url": "git+https://github.com/xiaolikt/ai-vault.git"
	},
	"os": ["$OS"],
	"cpu": ["$ARCH"],
	"files": ["bin"]
}
JSON

echo "staged $PACKAGE-$TARGET@$VERSION -> npm/$TARGET/bin/$EXE"
echo "publish:  npm publish npm/$TARGET --access public"
echo "then:     npm publish --access public"

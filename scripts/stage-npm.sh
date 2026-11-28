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
# Read the manifest from inside the repository: `pwd` under Git Bash (the
# Windows runner) is an MSYS path that Node cannot open.
VERSION="$(cd "$ROOT" && node -p "require('./package.json').version")"
PACKAGE="$(cd "$ROOT" && node -p "require('./package.json').name")"

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
	# A cross build is not rebuilt here, so it must at least be newer than the
	# last version bump: 0.9.1 shipped a Windows exe that answered `--version`
	# with 0.9.0, because it was linked before the bump and staged after it.
	for manifest in "$ROOT/package.json" "$ROOT/crates/ai-vault/Cargo.toml"; do
		if [[ "$SOURCE" -ot "$manifest" ]]; then
			echo "refusing: $SOURCE predates $manifest — rebuild it since the version was bumped" >&2
			exit 1
		fi
	done
else
	# A stale target/release would ship a binary with the wrong --version.
	cargo build --release --manifest-path "$ROOT/Cargo.toml"
fi

# Where the binary can run here (a native build), it must carry the version
# being published. A cross build for another OS or CPU cannot run, and only
# the check above applies to it.
if said="$("$SOURCE" --version 2>/dev/null)"; then
	if [[ "$said" != "ai-vault $VERSION" ]]; then
		echo "refusing: $SOURCE says '$said', the package is $VERSION" >&2
		exit 1
	fi
fi

# Accept a plain npm platform (darwin-arm64) or a Rust triple
# (aarch64-apple-darwin) — the latter comes straight from cargo zigbuild.
case "$TARGET" in
	*-unknown-linux-gnu) OS=linux; ARCH="${TARGET%%-*}"; ARCH="${ARCH/x86_64/x64}" ;;
	*-unknown-linux-musl) OS=linux; ARCH="${TARGET%%-*}"; ARCH="${ARCH/x86_64/x64}" ;;
	*aarch64-unknown-linux-*) OS=linux; ARCH=arm64 ;;
	*-pc-windows-gnu|*-pc-windows-msvc) OS=win32; ARCH="${TARGET%%-*}"; ARCH="${ARCH/x86_64/x64}" ;;
	*aarch64-pc-windows-*) OS=win32; ARCH=arm64 ;;
	*x86_64-apple-darwin) OS=darwin; ARCH=x64 ;;
	*aarch64-apple-darwin) OS=darwin; ARCH=arm64 ;;
	*) OS="${TARGET%%-*}"; ARCH="${TARGET##*-}" ;;
esac
TARGET="$OS-$ARCH"
[[ "$ARCH" == "amd64" ]] && ARCH=x64
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

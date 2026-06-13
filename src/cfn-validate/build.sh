#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$WORKSPACE/release"
TARGET_RELEASE="$WORKSPACE/target/release"

ARCH="$(uname -m)"
case "$ARCH" in
    arm64|aarch64)  ARCH="aarch64" ;;
    x86_64|amd64)   ARCH="x64"     ;;
esac

case "$(uname -s)" in
    Darwin*)              OS="darwin"; SRC_BIN="cfn-validate"; OUT_BIN="cfn-validate-${OS}-${ARCH}"     ;;
    Linux*)               OS="linux";  SRC_BIN="cfn-validate"; OUT_BIN="cfn-validate-${OS}-${ARCH}"     ;;
    MINGW*|MSYS*|CYGWIN*) OS="win32";  SRC_BIN="cfn-validate.exe"; OUT_BIN="cfn-validate-${OS}-${ARCH}.exe" ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

OUT_PATH="$RELEASE_DIR/$OUT_BIN"

cat <<EOF
Build directories:
  SCRIPT_DIR     = $SCRIPT_DIR
  WORKSPACE      = $WORKSPACE
  RELEASE_DIR    = $RELEASE_DIR
  TARGET_RELEASE = $TARGET_RELEASE
  OUT_PATH       = $OUT_PATH
  OS             = $OS
  ARCH           = $ARCH
EOF

RUSTC_PATH="$(rustup which rustc 2>/dev/null || true)"
if [ -n "$RUSTC_PATH" ]; then
    export PATH="$(dirname "$RUSTC_PATH"):$PATH"
fi

mkdir -p "$RELEASE_DIR"
rm -f "$OUT_PATH"

cd "$WORKSPACE"
cargo build --locked --release -p cfn-validate --bin cfn-validate

cp "$TARGET_RELEASE/$SRC_BIN" "$OUT_PATH"

BIN_SIZE=$(du -sh "$OUT_PATH" | cut -f1)
echo ""
echo "Build complete: $OUT_PATH ($BIN_SIZE)"

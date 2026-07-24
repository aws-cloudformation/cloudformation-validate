#!/usr/bin/env bash
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$WORKSPACE/target/release"
GO_DIR="$SCRIPT_DIR/go"
GENERATED_PKG="$GO_DIR/internal/bindings_go"

ARCH="$(uname -m)"
# Normalize to the same resource-prefix arch tokens the other bindings use
case "$ARCH" in
    arm64)        ARCH="aarch64" ;;
    x86_64|amd64) ARCH="x86-64"  ;;
esac

# On Windows the build targets the GNU toolchain: cgo links with MinGW, which
# cannot consume the MSVC toolchain's .lib static libraries.
CARGO_TARGET=""
case "$(uname -s)" in
    Darwin*) LIB_NAME="libbindings_go.a"; DYLIB_NAME="libbindings_go.dylib"; OS="darwin" ;;
    Linux*)  LIB_NAME="libbindings_go.a"; DYLIB_NAME="libbindings_go.so";    OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*)
        LIB_NAME="libbindings_go.a"; DYLIB_NAME="bindings_go.dll"; OS="win32"
        CARGO_TARGET="x86_64-pc-windows-gnu"
        RELEASE_DIR="$WORKSPACE/target/$CARGO_TARGET/release"
        ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

LIBS_DIR="$GO_DIR/libs/${OS}-${ARCH}"

cat <<EOF
Build directories:
  SCRIPT_DIR    = $SCRIPT_DIR
  WORKSPACE     = $WORKSPACE
  RELEASE_DIR   = $RELEASE_DIR
  GO_DIR        = $GO_DIR
  LIBS_DIR      = $LIBS_DIR
EOF

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v go &>/dev/null || { echo "Error: go not found on PATH" >&2; exit 1; }
command -v uniffi-bindgen-go &>/dev/null || {
    echo "Error: uniffi-bindgen-go not found on PATH." >&2
    echo "Install with: cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0" >&2
    exit 1
}
if [ -n "$CARGO_TARGET" ] && ! rustup target list --installed 2>/dev/null | grep -qx "$CARGO_TARGET"; then
    echo "Error: Rust target $CARGO_TARGET is not installed (required on Windows: cgo links with MinGW)." >&2
    echo "Install with: rustup target add $CARGO_TARGET" >&2
    exit 1
fi

# ── Clean ─────────────────────────────────────────────────────────────────────
echo "Cleaning previous build..."
rm -rf "$GO_DIR/internal" "$GO_DIR/libs"

# ── Build native library ─────────────────────────────────────────────────────
# Built in isolation (-p bindings-go) so cargo feature unification cannot pull
# the other bindings' uniffi scaffolding into this library's metadata.
echo "Building native library..."
cd "$WORKSPACE"
cargo build --locked -p bindings-go --release ${CARGO_TARGET:+--target "$CARGO_TARGET"}

# ── Generate Go bindings ─────────────────────────────────────────────────────
echo "Generating Go bindings..."
uniffi-bindgen-go "$RELEASE_DIR/$DYLIB_NAME" --out-dir "$GO_DIR/internal"

# Copy the hand-maintained cgo link directives into the generated package.
cp "$SCRIPT_DIR/native/link.go" "$GENERATED_PKG/link.go"

# ── Stage native library ────────────────────────────────────────────────────
echo "Staging native library..."
mkdir -p "$LIBS_DIR"
cp "$RELEASE_DIR/$LIB_NAME" "$LIBS_DIR/"
LOCAL_LIBRARY_COUNT=$(find "$GO_DIR/libs" -type f -name 'libbindings_go.a' | wc -l | tr -d ' ')
if [ "$LOCAL_LIBRARY_COUNT" -ne 1 ] || [ ! -f "$LIBS_DIR/$LIB_NAME" ]; then
    echo "Error: local build must contain exactly the host static library at $LIBS_DIR/$LIB_NAME" >&2
    exit 1
fi

# ── Package metadata ──────────────────────────────────────────────────────────
echo "Staging license and readme metadata..."
cp "$WORKSPACE/../LICENSE" "$GO_DIR/LICENSE"
cp "$SCRIPT_DIR/README.md" "$GO_DIR/README.md"
cp "$SCRIPT_DIR/THIRD-PARTY-LICENSES.txt" "$GO_DIR/THIRD-PARTY-LICENSES.txt"

# ── Verify the module compiles ────────────────────────────────────────────────
echo "Compiling Go module..."
cd "$GO_DIR"
gofmt -l . | { ! grep -v '^internal/'; } || { echo "Error: gofmt found unformatted files (above)" >&2; exit 1; }
go vet .
go build ./...

# ── Summary ───────────────────────────────────────────────────────────────────
LIB_SIZE=$(du -sh "$LIBS_DIR/$LIB_NAME" | cut -f1)
echo ""
echo "Build complete: $GO_DIR"
echo "  Generated package: internal/bindings_go"
echo "  Static library:    $LIB_SIZE ($LIB_NAME, ${OS}-${ARCH})"

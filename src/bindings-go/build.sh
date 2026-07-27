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
    arm64|aarch64) ARCH="aarch64" ;;
    x86_64|amd64)  ARCH="x86-64"  ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

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

# native/link.go carries a cgo link directive per bundled platform; a host outside
# that set has no library to link against, so stop before the build instead of
# failing at link time with missing symbols.
case "${OS}-${ARCH}" in
    linux-x86-64|darwin-aarch64|win32-x86-64) ;;
    *)
        echo "Error: unsupported host platform ${OS}-${ARCH}" >&2
        echo "Supported: linux-x86-64, darwin-aarch64, win32-x86-64" >&2
        exit 1
        ;;
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
if [ -n "$CARGO_TARGET" ]; then
    HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
    if [ "$HOST_TRIPLE" != "$CARGO_TARGET" ]; then
        # A GNU host is required so build scripts run as GNU; an MSVC host aborts because
        # msvc_spectre_libs looks for cl.exe for the GNU target. The workspace's
        # rust-toolchain.toml pins a host-less channel, so rustup resolves it against the
        # machine's default host (MSVC on Windows) — that override outranks the rustup
        # default, so even an installed GNU-host toolchain is not the active one here.
        # Re-pin to the same channel on the GNU host via RUSTUP_TOOLCHAIN, which outranks
        # rust-toolchain.toml, so cargo and every build script run on the GNU host.
        RUST_CHANNEL="$(rustc -vV | sed -n 's/^release: //p' | tr -d '\r')"
        GNU_TOOLCHAIN="${RUST_CHANNEL}-${CARGO_TARGET}"
        if ! rustup run "$GNU_TOOLCHAIN" rustc --version &>/dev/null; then
            echo "Error: building the Windows Go bindings requires the '$GNU_TOOLCHAIN' host toolchain, but it is not installed (active host is '${HOST_TRIPLE:-unknown}')." >&2
            echo "A GNU host is required so build scripts run as GNU; an MSVC host aborts because msvc_spectre_libs looks for cl.exe for the GNU target." >&2
            echo "Install it with: rustup toolchain install $GNU_TOOLCHAIN" >&2
            exit 1
        fi
        export RUSTUP_TOOLCHAIN="$GNU_TOOLCHAIN"
        echo "Pinned RUSTUP_TOOLCHAIN=$GNU_TOOLCHAIN so cargo and build scripts run on the GNU host (overrides rust-toolchain.toml)."
    fi
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
# Static archives never go through a link step, so the debug sections of
# prebuilt standard-library members survive into the archive. Strip them from
# the staged copy — consumers only need the symbol table and machine code.
command -v strip &>/dev/null || { echo "Error: strip not found on PATH" >&2; exit 1; }
case "$OS" in
    darwin) strip -S "$LIBS_DIR/$LIB_NAME" ;;
    *)      strip --strip-debug "$LIBS_DIR/$LIB_NAME" ;;
esac
LOCAL_LIBRARY_COUNT=$(find "$GO_DIR/libs" -type f -name 'libbindings_go.a' | wc -l | tr -d ' ')
if [ "$LOCAL_LIBRARY_COUNT" -ne 1 ] || [ ! -f "$LIBS_DIR/$LIB_NAME" ]; then
    echo "Error: local build must contain exactly the host static library at $LIBS_DIR/$LIB_NAME" >&2
    exit 1
fi

# ── Package metadata ──────────────────────────────────────────────────────────
echo "Staging license and readme metadata..."
cp "$WORKSPACE/../LICENSE" "$GO_DIR/LICENSE"
cp "$SCRIPT_DIR/README.md" "$GO_DIR/README.md"

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

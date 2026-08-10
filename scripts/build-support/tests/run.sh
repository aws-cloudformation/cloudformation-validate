#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHITECTURE_SCRIPT="$SCRIPT_DIR/../rust-host-architecture.sh"
TEST_ROOT="$(mktemp -d)"
FAKE_BIN_DIR="$TEST_ROOT/bin"
ORIGINAL_PATH="$PATH"
trap 'rm -rf "$TEST_ROOT"' EXIT

mkdir -p "$FAKE_BIN_DIR"
cat > "$FAKE_BIN_DIR/rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" != "-vV" ]; then
    echo "unexpected rustc arguments: $*" >&2
    exit 2
fi

printf 'rustc 1.96.0 (test)\n'
if [ -n "${FAKE_RUST_HOST:-}" ]; then
    printf 'host: %s\n' "$FAKE_RUST_HOST"
fi
printf 'release: 1.96.0\n'
EOF
chmod +x "$FAKE_BIN_DIR/rustc"

assert_architecture() {
    local host_triple="$1"
    local expected_architecture="$2"
    local detected_architecture

    detected_architecture="$(FAKE_RUST_HOST="$host_triple" PATH="$FAKE_BIN_DIR:$ORIGINAL_PATH" bash "$ARCHITECTURE_SCRIPT")"
    if [ "$detected_architecture" != "$expected_architecture" ]; then
        echo "Expected $host_triple to map to $expected_architecture, found $detected_architecture" >&2
        exit 1
    fi
}

assert_failure() {
    local host_triple="$1"
    local expected_error="$2"
    local stdout_file="$TEST_ROOT/stdout"
    local stderr_file="$TEST_ROOT/stderr"

    if FAKE_RUST_HOST="$host_triple" PATH="$FAKE_BIN_DIR:$ORIGINAL_PATH" bash "$ARCHITECTURE_SCRIPT" > "$stdout_file" 2> "$stderr_file"; then
        echo "Expected architecture detection to fail for '$host_triple'" >&2
        exit 1
    fi
    if ! grep -Fq "$expected_error" "$stderr_file"; then
        echo "Expected error '$expected_error', found:" >&2
        cat "$stderr_file" >&2
        exit 1
    fi
}

assert_architecture "aarch64-pc-windows-msvc" "aarch64"
assert_architecture "aarch64-apple-darwin" "aarch64"
assert_architecture "x86_64-pc-windows-msvc" "x86_64"
assert_architecture "x86_64-unknown-linux-gnu" "x86_64"
assert_failure "powerpc64le-unknown-linux-gnu" "Error: unsupported Rust host architecture: powerpc64le-unknown-linux-gnu"
assert_failure "" "Error: rustc did not report a host target"

echo "Build architecture detection tests passed."

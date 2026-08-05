#!/usr/bin/env bash
set -euo pipefail

command -v rustc &>/dev/null || { echo "Error: rustc not found on PATH" >&2; exit 1; }

RUST_HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
if [ -z "$RUST_HOST_TRIPLE" ]; then
    echo "Error: rustc did not report a host target" >&2
    exit 1
fi

case "$RUST_HOST_TRIPLE" in
    aarch64-*) echo "aarch64" ;;
    x86_64-*)  echo "x86_64"  ;;
    *) echo "Error: unsupported Rust host architecture: $RUST_HOST_TRIPLE" >&2; exit 1 ;;
esac

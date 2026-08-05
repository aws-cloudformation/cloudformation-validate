#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDINGS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GO_DIR="$BINDINGS_DIR/go"

[ -d "$GO_DIR/internal/bindings_go" ] && compgen -G "$GO_DIR/libs/*/libbindings_go.a" >/dev/null \
    || { echo "Error: generated bindings or static library missing — run build.sh first" >&2; exit 1; }

echo "Running smoke tests with coverage..."
cd "$GO_DIR"
go test -v -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

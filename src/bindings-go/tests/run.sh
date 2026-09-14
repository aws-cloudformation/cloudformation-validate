#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDINGS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GO_DIR="$BINDINGS_DIR/go"
GO_MODULE="github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"

[ -d "$GO_DIR/internal/bindings_go" ] && compgen -G "$GO_DIR/libs/*/libbindings_go.a" >/dev/null \
    || { echo "Error: generated bindings or static library missing - run build.sh first" >&2; exit 1; }

echo "Running Go module unit tests..."
(cd "$GO_DIR" && go test ./...)

echo "Running smoke tests with coverage..."
cd "$SCRIPT_DIR"
go test -v -covermode=atomic -coverpkg="$GO_MODULE" -coverprofile="$SCRIPT_DIR/coverage.out" ./...
go tool cover -func="$SCRIPT_DIR/coverage.out"

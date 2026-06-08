#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDINGS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KOTLIN_DIR="$SCRIPT_DIR/kotlin"

echo "Running Kotlin smoke tests..."
cd "$KOTLIN_DIR"
gradle test --no-daemon --rerun-tasks

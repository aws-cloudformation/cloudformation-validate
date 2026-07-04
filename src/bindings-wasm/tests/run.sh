#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDINGS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Running smoke tests..."
cd "$SCRIPT_DIR"
npm install --silent
npm run test:coverage

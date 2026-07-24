#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDINGS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WHEEL_DIR="$BINDINGS_DIR/generated/dist"
VENV_DIR="$SCRIPT_DIR/.venv"

WHEEL_FILE=$(ls "$WHEEL_DIR"/cloudformation_validate-*.whl 2>/dev/null) \
    || { echo "Error: no wheel in $WHEEL_DIR — run build.sh first" >&2; exit 1; }

# Install the wheel into a fresh venv so the tests exercise the artifact
# consumers install, not the loose build tree.
echo "Installing $(basename "$WHEEL_FILE") into test venv..."
rm -rf "$VENV_DIR"
python3 -m venv "$VENV_DIR"
if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
else
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"   # Windows venv layout
fi
"$VENV_PYTHON" -m pip install --quiet --force-reinstall "$WHEEL_FILE"
"$VENV_PYTHON" -m pip install --quiet coverage

echo "Running smoke tests with coverage..."
cd "$SCRIPT_DIR"
"$VENV_PYTHON" -m coverage run --source cloudformation_validate -m unittest discover --start-directory "$SCRIPT_DIR" --pattern '*_test.py' --verbose
"$VENV_PYTHON" -m coverage report
"$VENV_PYTHON" -m coverage xml -o coverage.xml

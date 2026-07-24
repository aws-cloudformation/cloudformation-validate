#!/usr/bin/env bash
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"
RELEASE_DIR="$WORKSPACE/target/release"
PYTHON_SRC="$SCRIPT_DIR/python/cloudformation_validate"
PACKAGE_DIR="$GENERATED_DIR/cloudformation_validate"
WHEEL_DIR="$GENERATED_DIR/dist"

ARCH="$(uname -m)"
# Normalize to the same resource-prefix arch tokens the JVM natives use
case "$ARCH" in
    arm64)        ARCH="aarch64" ;;
    x86_64|amd64) ARCH="x86-64"  ;;
esac

case "$(uname -s)" in
    Darwin*) LIB_NAME="libbindings_python.dylib"; OS="darwin" ;;
    Linux*)  LIB_NAME="libbindings_python.so";    OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*) LIB_NAME="bindings_python.dll"; OS="win32" ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

NATIVES_DIR="$PACKAGE_DIR/natives/${OS}-${ARCH}"

cat <<EOF
Build directories:
  SCRIPT_DIR    = $SCRIPT_DIR
  WORKSPACE     = $WORKSPACE
  GENERATED_DIR = $GENERATED_DIR
  RELEASE_DIR   = $RELEASE_DIR
  PYTHON_SRC    = $PYTHON_SRC
  NATIVES_DIR   = $NATIVES_DIR
EOF

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v python3 &>/dev/null || { echo "Error: python3 not found on PATH" >&2; exit 1; }
command -v unzip &>/dev/null || { echo "Error: unzip not found on PATH" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || { echo "Error: Python 3.12+ required, found $(python3 --version)" >&2; exit 1; }
python3 -c 'import setuptools' 2>/dev/null \
    || { echo "Error: setuptools not available in python3 environment" >&2; exit 1; }

# ── Clean ─────────────────────────────────────────────────────────────────────
echo "Cleaning previous build..."
rm -rf "$GENERATED_DIR"
mkdir -p "$PACKAGE_DIR"

# ── Build native library ─────────────────────────────────────────────────────
echo "Building native library..."
cd "$WORKSPACE"
cargo build --locked -p bindings-python --release
# uniffi-bindgen is component-agnostic; reuse the workspace's single copy
# (defined in bindings-jvm) rather than duplicating the binary target.
cargo build --locked -p bindings-jvm --release --bin uniffi-bindgen

# ── Generate Python bindings ─────────────────────────────────────────────────
echo "Generating Python bindings..."
"$RELEASE_DIR/uniffi-bindgen" generate \
    --library "$RELEASE_DIR/$LIB_NAME" \
    --language python \
    --out-dir "$PACKAGE_DIR"

# ── Patch native loading + normalize generated modules ───────────────────────
# Two transforms, both applied identically on every host so the generated Python
# is byte-for-byte reproducible across platforms (the all-platform wheel merge
# keeps one shared copy and requires every platform's to match):
#   1. The generated modules load the cdylib from the package root; redirect them
#      to _native.py's per-platform natives/<os>-<arch>/ directory so a single
#      wheel can bundle every platform. Fails loudly if the uniffi template changes.
#   2. uniffi emits sibling-module imports ("from . import <name>") in the order it
#      discovers external types while walking the library's symbols — an order that
#      is not stable across hosts (Mach-O vs ELF symbol ordering), so the same
#      module differs per platform. Sort each contiguous import block into a
#      canonical order; these bindings are order-independent, so this is safe.
echo "Patching native loader and normalizing generated modules..."
python3 - "$PACKAGE_DIR" <<'EOF'
import pathlib
import re
import sys

package_dir = pathlib.Path(sys.argv[1])
OLD = "    path = os.path.join(os.path.dirname(__file__), libname)\n"
NEW = (
    "    from ._native import native_library_dir\n"
    "    path = os.path.join(native_library_dir(), os.path.basename(libname))\n"
)
RELATIVE_IMPORT = re.compile(r"^from \. import [A-Za-z_][A-Za-z0-9_]*$")


def sort_relative_imports(text: str) -> str:
    lines = text.split("\n")
    result = []
    index = 0
    while index < len(lines):
        if RELATIVE_IMPORT.match(lines[index]):
            end = index
            while end < len(lines) and RELATIVE_IMPORT.match(lines[end]):
                end += 1
            result.extend(sorted(lines[index:end]))
            index = end
        else:
            result.append(lines[index])
            index += 1
    return "\n".join(result)


modules = sorted(package_dir.glob("*.py"))
if not modules:
    sys.exit(f"error: no generated modules found in {package_dir}")
for module in modules:
    text = module.read_text(encoding="utf-8")
    if OLD not in text:
        sys.exit(f"error: expected loader line not found in {module.name} — did the uniffi template change?")
    module.write_text(sort_relative_imports(text.replace(OLD, NEW)), encoding="utf-8")
print(f"  patched {len(modules)} modules")
EOF

# Copy the hand-maintained public API (convenience wrappers, re-exports,
# platform dispatch) so it ships alongside the uniffi-generated modules.
echo "Copying hand-maintained Python sources..."
cp -R "$PYTHON_SRC"/. "$PACKAGE_DIR/"

# ── Stage native library ────────────────────────────────────────────────────
echo "Staging native library..."
mkdir -p "$NATIVES_DIR"
cp "$RELEASE_DIR/$LIB_NAME" "$NATIVES_DIR/"

# ── Package metadata ──────────────────────────────────────────────────────────
VERSION=$(grep '^version' "$WORKSPACE/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
sed "s/^version = \"0.0.0\"/version = \"$VERSION\"/" "$SCRIPT_DIR/pyproject.toml" > "$GENERATED_DIR/pyproject.toml"
cp "$WORKSPACE/../LICENSE" "$GENERATED_DIR/LICENSE"
# Scoped to this binding's dependencies; the Build Artifacts workflow
# refreshes it before invoking this script.
cp "$SCRIPT_DIR/THIRD-PARTY-LICENSES.txt" "$GENERATED_DIR/THIRD-PARTY-LICENSES.txt"
cp "$SCRIPT_DIR/README.md" "$GENERATED_DIR/README.md"
cp "$SCRIPT_DIR/README.md" "$PACKAGE_DIR/README.md"

# ── Build wheel ───────────────────────────────────────────────────────────────
echo "Building wheel..."
cd "$GENERATED_DIR"
python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir "$WHEEL_DIR" . --quiet

WHEEL_FILE=$(ls "$WHEEL_DIR"/cloudformation_validate-*.whl)

# ── Verify the wheel carries host code and publication metadata ──────────────
WHEEL_ENTRIES=$(unzip -Z1 "$WHEEL_FILE")
PY_COUNT=$(grep -cE '^cloudformation_validate/.*\.py$' <<<"$WHEEL_ENTRIES" || true)
LIB_COUNT=$(grep -cE '^cloudformation_validate/natives/[^/]+/[^/]+\.(dylib|so|dll)$' <<<"$WHEEL_ENTRIES" || true)
HOST_NATIVE="cloudformation_validate/natives/${OS}-${ARCH}/${LIB_NAME}"
if [ "$PY_COUNT" -eq 0 ] || [ "$LIB_COUNT" -ne 1 ] || ! grep -Fxq "$HOST_NATIVE" <<<"$WHEEL_ENTRIES"; then
    echo "Error: local wheel must contain Python modules and exactly the host native at $HOST_NATIVE" >&2
    exit 1
fi
if ! grep -Fxq 'cloudformation_validate/README.md' <<<"$WHEEL_ENTRIES" \
    || ! grep -Eq '^cloudformation_validate-[^/]+\.dist-info/licenses/LICENSE$' <<<"$WHEEL_ENTRIES" \
    || ! grep -Eq '^cloudformation_validate-[^/]+\.dist-info/licenses/THIRD-PARTY-LICENSES\.txt$' <<<"$WHEEL_ENTRIES"; then
    echo "Error: wheel is missing README.md, LICENSE, or THIRD-PARTY-LICENSES.txt" >&2
    exit 1
fi
case "$WHEEL_FILE" in
    *py3-none-any*) ;;
    *) echo "Error: wheel must be tagged py3-none-any (platform dispatch happens at import time): $WHEEL_FILE" >&2; exit 1 ;;
esac

# ── Summary ───────────────────────────────────────────────────────────────────
LIB_SIZE=$(du -sh "$RELEASE_DIR/$LIB_NAME" | cut -f1)
WHEEL_SIZE=$(du -sh "$WHEEL_FILE" | cut -f1)

echo ""
echo "Build complete: $GENERATED_DIR"
echo "  Python modules:   $PY_COUNT .py files bundled"
echo "  Host native:      $LIB_SIZE ($LIB_NAME)"
echo "  Wheel:            $WHEEL_SIZE ($(basename "$WHEEL_FILE"))"
echo "  Bundled platforms:"
unzip -l "$WHEEL_FILE" | grep -oE 'cloudformation_validate/natives/[^/]+/[^ ]+' | sed 's/^/    /'

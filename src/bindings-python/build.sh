#!/usr/bin/env bash
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOSITORY_ROOT="$(cd "$WORKSPACE/.." && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"
RELEASE_DIR="$WORKSPACE/target/release"
PYTHON_SRC="$SCRIPT_DIR/python/cloudformation_validate"
PACKAGE_DIR="$GENERATED_DIR/cloudformation_validate"
WHEEL_DIR="$GENERATED_DIR/dist"
PYTHON="${PYTHON:-python3}"

ARCH="$(bash "$REPOSITORY_ROOT/scripts/build-support/rust-host-architecture.sh")"
case "$ARCH" in
    aarch64) ARCH="aarch64" ;;
    x86_64)  ARCH="x86-64"  ;;
esac

case "$(uname -s)" in
    Darwin*) LIB_NAME="libbindings_python.dylib"; OS="darwin" ;;
    Linux*)  LIB_NAME="libbindings_python.so";    OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*) LIB_NAME="bindings_python.dll"; OS="win32" ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

case "${OS}-${ARCH}" in
    linux-x86-64|linux-aarch64|darwin-x86-64|darwin-aarch64|win32-x86-64|win32-aarch64) ;;
    *)
        echo "Error: unsupported host platform ${OS}-${ARCH}" >&2
        echo "Supported: Linux, macOS, and Windows on x86-64 and aarch64" >&2
        exit 1
        ;;
esac

MACOS_WHEEL_ARCH=""
if [ "$OS" = "darwin" ]; then
    case "$ARCH" in
        aarch64)
            MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
            MACOS_WHEEL_ARCH="arm64"
            ;;
        x86-64)
            MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-10.12}"
            MACOS_WHEEL_ARCH="x86_64"
            ;;
    esac
    if [[ ! "$MACOSX_DEPLOYMENT_TARGET" =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "Error: MACOSX_DEPLOYMENT_TARGET must be major.minor, found '$MACOSX_DEPLOYMENT_TARGET'" >&2
        exit 1
    fi
    export MACOSX_DEPLOYMENT_TARGET
fi

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
command -v "$PYTHON" &>/dev/null || { echo "Error: $PYTHON not found on PATH" >&2; exit 1; }
command -v unzip &>/dev/null || { echo "Error: unzip not found on PATH" >&2; exit 1; }
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || { echo "Error: Python 3.9+ required, found $("$PYTHON" --version)" >&2; exit 1; }
"$PYTHON" -m pip --version &>/dev/null \
    || { echo "Error: pip not available ($PYTHON -m pip failed)" >&2; exit 1; }

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
# Two transforms applied to the uniffi-generated modules:
#   1. The generated modules load the cdylib from the package root; redirect them
#      to _native.py's natives/<os>-<arch>/ directory so the wheel keeps a stable
#      resource layout across platforms. Fails loudly if the uniffi template changes.
#   2. uniffi emits sibling-module imports ("from . import <name>") in the order it
#      discovers external types while walking the library's symbols - an order that
#      is not stable across hosts. Sort each contiguous import block so the
#      generated code is deterministic regardless of build host; these bindings
#      are order-independent, so this is safe.
echo "Patching native loader and normalizing generated modules..."
"$PYTHON" - "$PACKAGE_DIR" <<'EOF'
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
        sys.exit(f"error: expected loader line not found in {module.name} - did the uniffi template change?")
    with module.open("w", encoding="utf-8", newline="\n") as output:
        output.write(sort_relative_imports(text.replace(OLD, NEW)))
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
cp "$WORKSPACE/../NOTICE" "$GENERATED_DIR/NOTICE"
# Scoped to this binding's dependencies; the Build Artifacts workflow
# refreshes it before invoking this script.
cp "$SCRIPT_DIR/THIRD-PARTY-LICENSES.txt" "$GENERATED_DIR/THIRD-PARTY-LICENSES.txt"
cp "$SCRIPT_DIR/README.md" "$GENERATED_DIR/README.md"
cp "$SCRIPT_DIR/README.md" "$PACKAGE_DIR/README.md"

# ── Build wheel ───────────────────────────────────────────────────────────────
echo "Building wheel..."
cd "$GENERATED_DIR"
"$PYTHON" -m pip wheel --no-deps --wheel-dir "$WHEEL_DIR" . --quiet

# ── Retag wheel with the host platform ───────────────────────────────────────
case "$OS" in
    darwin) PLATFORM_TAG="macosx_${MACOSX_DEPLOYMENT_TARGET//./_}_${MACOS_WHEEL_ARCH}" ;;
    win32)
        case "$ARCH" in
            x86-64)  PLATFORM_TAG="win_amd64" ;;
            aarch64) PLATFORM_TAG="win_arm64" ;;
        esac
        ;;
    linux)
        command -v readelf &>/dev/null || { echo "Error: readelf not found on PATH (required to compute the manylinux tag)" >&2; exit 1; }
        while IFS= read -r needed; do
            case "$needed" in
                libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libgcc_s.so.*|libutil.so.*|ld-linux-*.so.*) ;;
                *) echo "Error: $LIB_NAME links a library outside the manylinux-permitted set: $needed" >&2; exit 1 ;;
            esac
        done < <(readelf -d "$RELEASE_DIR/$LIB_NAME" | awk '/\(NEEDED\)/ { gsub(/[][]/, "", $NF); print $NF }')
        GLIBC_FLOOR=$( { readelf --dyn-syms "$RELEASE_DIR/$LIB_NAME" | grep -o 'GLIBC_[0-9]*\.[0-9]*' | sed 's/GLIBC_//' | sort -uV | tail -1; } || true)
        [ -n "$GLIBC_FLOOR" ] || { echo "Error: could not determine the glibc floor of $LIB_NAME" >&2; exit 1; }
        PLATFORM_TAG="manylinux_${GLIBC_FLOOR%%.*}_${GLIBC_FLOOR##*.}_$(uname -m)"
        ;;
esac
echo "Retagging wheel as py3-none-${PLATFORM_TAG}..."
"$PYTHON" - "$WHEEL_DIR" "$PLATFORM_TAG" <<'EOF'
import base64
import csv
import hashlib
import io
import pathlib
import sys
import zipfile

wheel_dir = pathlib.Path(sys.argv[1])
platform_tag = sys.argv[2]

wheels = sorted(wheel_dir.glob("*.whl"))
if len(wheels) != 1:
    sys.exit(f"error: expected exactly one wheel in {wheel_dir}, found {len(wheels)}")
source = wheels[0]
if not source.name.endswith("-py3-none-any.whl"):
    sys.exit(f"error: expected a py3-none-any wheel to retag, found {source.name}")

with zipfile.ZipFile(source) as archive:
    entries = {e.filename: (e, archive.read(e)) for e in archive.infolist() if not e.is_dir()}

record_paths = [n for n in entries if n.endswith(".dist-info/RECORD")]
wheel_paths = [n for n in entries if n.endswith(".dist-info/WHEEL")]
if len(record_paths) != 1 or len(wheel_paths) != 1:
    sys.exit("error: wheel must contain exactly one .dist-info/RECORD and one .dist-info/WHEEL")
record_path, wheel_path = record_paths[0], wheel_paths[0]

info, content = entries[wheel_path]
text = content.decode("utf-8")
if "Tag: py3-none-any\n" not in text or "Root-Is-Purelib: true\n" not in text:
    sys.exit("error: unexpected WHEEL metadata - did the wheel builder change?")
text = text.replace("Root-Is-Purelib: true\n", "Root-Is-Purelib: false\n")
text = text.replace("Tag: py3-none-any\n", f"Tag: py3-none-{platform_tag}\n")
entries[wheel_path] = (info, text.encode("utf-8"))

record_info = entries.pop(record_path)[0]
rows = io.StringIO(newline="")
writer = csv.writer(rows, lineterminator="\n")
for name in sorted(entries):
    data = entries[name][1]
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    writer.writerow((name, f"sha256={digest}", len(data)))
writer.writerow((record_path, "", ""))
entries[record_path] = (record_info, rows.getvalue().encode("utf-8"))

target = source.with_name(source.name.replace("-any.whl", f"-{platform_tag}.whl"))
with zipfile.ZipFile(target, "w") as archive:
    for name in sorted(entries):
        entry_info, data = entries[name]
        archive.writestr(entry_info, data)
source.unlink()
print(f"  {target.name}")
EOF

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
    || ! grep -Eq '^cloudformation_validate-[^/]+\.dist-info/licenses/NOTICE$' <<<"$WHEEL_ENTRIES" \
    || ! grep -Eq '^cloudformation_validate-[^/]+\.dist-info/licenses/THIRD-PARTY-LICENSES.txt$' <<<"$WHEEL_ENTRIES"; then
    echo "Error: wheel is missing README.md, LICENSE, NOTICE, or THIRD-PARTY-LICENSES.txt" >&2
    exit 1
fi
case "$WHEEL_FILE" in
    *-py3-none-"${PLATFORM_TAG}".whl) ;;
    *) echo "Error: wheel must be tagged py3-none-${PLATFORM_TAG} (a real platform tag so pip rejects unsupported platforms at install time): $WHEEL_FILE" >&2; exit 1 ;;
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

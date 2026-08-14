#!/usr/bin/env bash
set -euo pipefail

ANALYZE=false
for arg in "$@"; do
    case "$arg" in
        --analyze) ANALYZE=true ;;
    esac
done

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
REPOSITORY_ROOT="$(cd "$WORKSPACE/.." && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"
RELEASE_DIR="$WORKSPACE/target/release"
KOTLIN_SRC="$SCRIPT_DIR/src/main/kotlin"

ARCH="$(bash "$REPOSITORY_ROOT/scripts/build-support/rust-host-architecture.sh")"
# Normalize to JNA's resource-prefix arch tokens (its canonical form)
case "$ARCH" in
    aarch64) ARCH="aarch64" ;;
    x86_64)  ARCH="x86-64"  ;;
esac

case "$(uname -s)" in
    Darwin*) LIB_NAME="libbindings_jvm.dylib"; OS="darwin" ;;
    Linux*)  LIB_NAME="libbindings_jvm.so";    OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*) LIB_NAME="bindings_jvm.dll"; OS="win32" ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

NATIVES_DIR="$GENERATED_DIR/natives/${OS}-${ARCH}"
JAR_FILE="$GENERATED_DIR/cloudformation-validate.jar"

cat <<EOF
Build directories:
  SCRIPT_DIR    = $SCRIPT_DIR
  WORKSPACE     = $WORKSPACE
  GENERATED_DIR = $GENERATED_DIR
  RELEASE_DIR   = $RELEASE_DIR
  KOTLIN_SRC    = $KOTLIN_SRC
  NATIVES_DIR   = $NATIVES_DIR
EOF

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v ktlint &>/dev/null || { echo "Error: ktlint not found on PATH" >&2; exit 1; }
command -v gradle &>/dev/null || { echo "Error: gradle not found on PATH" >&2; exit 1; }

if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA_BIN="$JAVA_HOME/bin/java"
else
    JAVA_BIN="java"
fi
JAVA_VERSION=$("$JAVA_BIN" -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')
if [ "$JAVA_VERSION" -lt 21 ]; then
    echo "Error: JDK 21+ required, found JDK $JAVA_VERSION (from $JAVA_BIN)" >&2; exit 1
fi

# ── Clean ─────────────────────────────────────────────────────────────────────
echo "Cleaning previous build..."
rm -rf "$GENERATED_DIR"
mkdir -p "$GENERATED_DIR"

# ── Build native library ─────────────────────────────────────────────────────
echo "Building native library..."
cd "$WORKSPACE"
cargo build --locked -p bindings-jvm --release

# ── Generate Kotlin bindings ─────────────────────────────────────────────────
echo "Generating Kotlin bindings..."
"$RELEASE_DIR/uniffi-bindgen" generate \
    --library "$RELEASE_DIR/$LIB_NAME" \
    --language kotlin \
    --out-dir "$GENERATED_DIR"

# Copy hand-maintained Kotlin extensions (default constructors, convenience overloads)
# into the generated directory so they compile alongside the UniFFI-generated code.
if [ -d "$KOTLIN_SRC" ]; then
    echo "Copying hand-maintained Kotlin sources..."
    cp -R "$KOTLIN_SRC"/* "$GENERATED_DIR/"
fi


# ── Format ────────────────────────────────────────────────────────────────────
echo "Formatting Kotlin sources..."
cd "$SCRIPT_DIR"
ktlint --format "generated/**/*.kt"

# ── Stage native library ──────────────────────────────────────────────────────
# Place the host native at the JNA auto-extract path generated/natives/<os>-<arch>/
# so the Gradle jar task bundles it. In CI, merge-jars.sh later grafts the other
# platforms' natives into the committed all-platform jar.
echo "Staging native library..."
rm -rf "$GENERATED_DIR/natives"
mkdir -p "$NATIVES_DIR"
cp "$RELEASE_DIR/$LIB_NAME" "$NATIVES_DIR/"

# ── Generate version.properties ────────────────────────────────────────────────
"$SCRIPT_DIR/generate-version-properties.sh"
JNA_VERSION=$(grep '^jnaVersion=' "$SCRIPT_DIR/version.properties" | cut -d= -f2)
GSON_VERSION=$(grep '^gsonVersion=' "$SCRIPT_DIR/version.properties" | cut -d= -f2)
KOTLIN_VERSION=$(grep '^kotlinVersion=' "$SCRIPT_DIR/version.properties" | cut -d= -f2)

# ── Compile + package JAR via Gradle ───────────────────────────────────────────
# Gradle compiles the generated Kotlin (resolving JNA/Gson), bundles the .kt sources,
# the staged native, and the license/readme metadata, and writes the jar to
# generated/cloudformation-validate.jar. Gradle is the single compiler + packager so
# the Maven publication and the GitHub-released jar are the same build.
echo "Compiling and packaging JAR via Gradle..."
gradle --no-daemon --console=plain jar

# ── Verify the JAR carries compiled classes and sources ──────────────────────
# A jar that bundles the .kt sources but not the compiled .class output (e.g. a
# Gradle source-set regression that drops the compilation output) still packages,
# uploads, and publishes successfully, then fails every consumer at class-load time.
# Assert both are present so that failure surfaces here rather than downstream.
# There are no .java entries by design - the bindings are Kotlin-only.
CLASS_COUNT=$(jar tf "$JAR_FILE" | grep -c '\.class$' || true)
KT_COUNT=$(jar tf "$JAR_FILE" | grep -c '\.kt$' || true)
if [ "$CLASS_COUNT" -eq 0 ] || [ "$KT_COUNT" -eq 0 ]; then
    echo "Error: $JAR_FILE is missing compiled output - $CLASS_COUNT .class and $KT_COUNT .kt entries (both must be non-zero)." >&2
    exit 1
fi
for required_metadata in LICENSE NOTICE README.md THIRD-PARTY-LICENSES.txt; do
    if ! jar tf "$JAR_FILE" | grep -Fxq "META-INF/$required_metadata"; then
        echo "Error: $JAR_FILE is missing META-INF/$required_metadata" >&2
        exit 1
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
KT_SIZE=$(find "$GENERATED_DIR" -name '*.kt' -type f -exec cat {} + | wc -c | awk '{printf "%.1fM", $1/1048576}')
LIB_SIZE=$(du -sh "$RELEASE_DIR/$LIB_NAME" | cut -f1)
JAR_SIZE=$(du -sh "$JAR_FILE" | cut -f1)

echo ""
echo "Build complete: $GENERATED_DIR"
echo "  Kotlin sources: $KT_SIZE ($KT_COUNT .kt files bundled)"
echo "  Compiled classes: $CLASS_COUNT .class entries bundled"
echo "  Native library: $LIB_SIZE ($LIB_NAME, bundled in jar)"
echo "  JAR:            $JAR_SIZE ($(basename "$JAR_FILE"))"
echo ""
echo "Consumer dependencies: net.java.dev.jna:jna:${JNA_VERSION}, com.google.code.gson:gson:${GSON_VERSION}, org.jetbrains.kotlin:kotlin-stdlib:${KOTLIN_VERSION}"
find "$GENERATED_DIR" -name '*.kt' -type f | sed 's/^/  /'

# ── Analyze JAR (optional) ───────────────────────────────────────────────────
if [ "$ANALYZE" = true ]; then
    echo ""
    echo "=== JAR Analysis ==="
    echo "Manifest:"
    unzip -p "$JAR_FILE" META-INF/MANIFEST.MF | sed 's/^/  /'
    echo "Tree:"
    jar tf "$JAR_FILE" | grep -v -E '(Uniffi|FfiConverter|ForeignBytes|RustBuffer|NoHandle|InternalException|IntegrityChecking|Disposable|JavaLangRef|\$Companion\.class|Kt\.class|kotlin_module)' | sort | awk -F/ '{
        depth = NF - 1
        name = $NF
        if (name == "") { depth--; name = $(NF-1) "/" }
        indent = ""
        for (i = 0; i < depth; i++) indent = indent "  "
        print "  " indent name
    }'
fi

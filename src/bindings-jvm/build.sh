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
GENERATED_DIR="$SCRIPT_DIR/generated"
BUILD_DIR="$SCRIPT_DIR/build"
RELEASE_DIR="$WORKSPACE/target/release"
KOTLIN_SRC="$SCRIPT_DIR/src/main/kotlin"

JNA_VERSION="5.19.1"
JNA_MAVEN_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"

GSON_VERSION="2.14.0"
GSON_MAVEN_URL="https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON_VERSION}/gson-${GSON_VERSION}.jar"

ARCH="$(uname -m)"
# Normalize to JNA's resource-prefix arch tokens (its canonical form)
case "$ARCH" in
    arm64)        ARCH="aarch64" ;;
    x86_64|amd64) ARCH="x86-64"  ;;
esac

case "$(uname -s)" in
    Darwin*) LIB_NAME="libbindings_jvm.dylib"; OS="darwin" ;;
    Linux*)  LIB_NAME="libbindings_jvm.so";    OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*) LIB_NAME="bindings_jvm.dll"; OS="win32" ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

NATIVES_DIR="$BUILD_DIR/classes/${OS}-${ARCH}"
JAR_FILE="$GENERATED_DIR/cloudformation-validate.jar"

cat <<EOF
Build directories:
  SCRIPT_DIR    = $SCRIPT_DIR
  WORKSPACE     = $WORKSPACE
  GENERATED_DIR = $GENERATED_DIR
  BUILD_DIR     = $BUILD_DIR
  RELEASE_DIR   = $RELEASE_DIR
  KOTLIN_SRC    = $KOTLIN_SRC
  NATIVES_DIR   = $NATIVES_DIR
EOF

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v ktlint &>/dev/null || { echo "Error: ktlint not found on PATH" >&2; exit 1; }
command -v kotlinc &>/dev/null || { echo "Error: kotlinc not found on PATH" >&2; exit 1; }
command -v jar &>/dev/null || { echo "Error: jar not found on PATH" >&2; exit 1; }

JAVA_VERSION=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')
if [ "$JAVA_VERSION" -lt 21 ]; then
    echo "Error: JDK 21+ required, found JDK $JAVA_VERSION" >&2; exit 1
fi

# ── Clean ─────────────────────────────────────────────────────────────────────
echo "Cleaning previous build..."
rm -rf "$GENERATED_DIR" "$BUILD_DIR"
mkdir -p "$GENERATED_DIR" "$BUILD_DIR/classes"

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

# ── Download JNA jar ─────────────────────────────────────────────────────────
echo "Downloading JNA ${JNA_VERSION}..."
JNA_JAR="$BUILD_DIR/jna-${JNA_VERSION}.jar"
curl -sfL "$JNA_MAVEN_URL" -o "$JNA_JAR"

# ── Download Gson jar ────────────────────────────────────────────────────────
echo "Downloading Gson ${GSON_VERSION}..."
GSON_JAR="$BUILD_DIR/gson-${GSON_VERSION}.jar"
curl -sfL "$GSON_MAVEN_URL" -o "$GSON_JAR"

# ── Compile Kotlin sources ───────────────────────────────────────────────────
echo "Compiling Kotlin bindings..."
find "$GENERATED_DIR" -name '*.kt' -type f -print0 \
    | xargs -0 kotlinc -classpath "$JNA_JAR:$GSON_JAR" -d "$BUILD_DIR/classes" -nowarn

# ── Package JAR ──────────────────────────────────────────────────────────────
# Bundle native library at the JNA auto-extract path: <os>-<arch>/<libname>
mkdir -p "$NATIVES_DIR"
cp "$RELEASE_DIR/$LIB_NAME" "$NATIVES_DIR/"

# Bundle Kotlin sources for IDE navigation
find "$GENERATED_DIR" -name '*.kt' -type f | while read -r kt; do
    REL="${kt#"$GENERATED_DIR/"}"
    mkdir -p "$BUILD_DIR/classes/$(dirname "$REL")"
    cp "$kt" "$BUILD_DIR/classes/$REL"
done

mkdir -p "$BUILD_DIR/classes/META-INF"
cp "$WORKSPACE/../LICENSE" "$BUILD_DIR/classes/META-INF/LICENSE"
cp "$SCRIPT_DIR/README.md" "$BUILD_DIR/classes/META-INF/README.md"
cp "$SCRIPT_DIR/THIRD-PARTY-LICENSES.txt" "$BUILD_DIR/classes/META-INF/THIRD-PARTY-LICENSES.txt"

# Create manifest with version and dependency info
VERSION=$(grep '^version' "$WORKSPACE/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
cat > "$BUILD_DIR/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Implementation-Title: cloudformation-validate-jvm
Implementation-Version: ${VERSION}
Implementation-Vendor: Amazon Web Services (AWS)
License: Apache-2.0
Requires: net.java.dev.jna:jna:${JNA_VERSION}, com.google.code.gson:gson:${GSON_VERSION}
EOF

echo "Packaging JAR..."
jar cfm "$JAR_FILE" "$BUILD_DIR/MANIFEST.MF" -C "$BUILD_DIR/classes" .

rm -rf "$BUILD_DIR"

echo "Generating version.properties..."
cat > "$SCRIPT_DIR/version.properties" <<EOF
# Generated by build.sh — do not edit manually. Version from Cargo.toml; dep versions from build.sh.
publishVersion=${VERSION}
jnaVersion=${JNA_VERSION}
gsonVersion=${GSON_VERSION}
EOF

# ── Summary ───────────────────────────────────────────────────────────────────
KT_SIZE=$(find "$GENERATED_DIR" -name '*.kt' -type f -exec cat {} + | wc -c | awk '{printf "%.1fM", $1/1048576}')
LIB_SIZE=$(du -sh "$RELEASE_DIR/$LIB_NAME" | cut -f1)
JAR_SIZE=$(du -sh "$JAR_FILE" | cut -f1)

echo ""
echo "Build complete: $GENERATED_DIR"
echo "  Kotlin sources: $KT_SIZE"
echo "  Native library: $LIB_SIZE ($LIB_NAME, bundled in jar)"
echo "  JAR:            $JAR_SIZE ($(basename "$JAR_FILE"))"
echo ""
echo "Consumer dependency: net.java.dev.jna:jna:${JNA_VERSION}, com.google.code.gson:gson:${GSON_VERSION}"
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

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"

RUSTC_PATH="$(rustup which rustc 2>/dev/null || true)"
if [ -n "$RUSTC_PATH" ]; then
    export PATH="$(dirname "$RUSTC_PATH"):$PATH"
fi

cat <<EOF
Build directories:
  SCRIPT_DIR    = $SCRIPT_DIR
  WORKSPACE     = $WORKSPACE
  DIST_DIR      = $DIST_DIR
EOF

rm -rf "$DIST_DIR"

cd "$WORKSPACE"
RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+simd128,+bulk-memory' \
    wasm-pack build --target nodejs --release --out-dir dist bindings-wasm -- --locked
rm -f "$DIST_DIR/.gitignore" "$DIST_DIR/package.json" "$DIST_DIR/README.md"

WASM_DTS="$DIST_DIR/bindings_wasm.d.ts"
if [ -f "$WASM_DTS" ] && ! grep -q "^export type JsonValue" "$WASM_DTS"; then
    JSON_VALUE_TYPE='export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };'
    printf '%s\n' "$JSON_VALUE_TYPE" | cat - "$WASM_DTS" > "$WASM_DTS.tmp"
    mv "$WASM_DTS.tmp" "$WASM_DTS"
fi

cd "$SCRIPT_DIR"
npm ci --silent 2>/dev/null
npm run build:ts

# ── Package metadata ──────────────────────────────────────────────────────────
VERSION=$(grep '^version' "$WORKSPACE/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')

PKG_VERSION="$VERSION" node -e "
  const pkg = require('./package.json');
  const dist = {
    name: pkg.name,
    version: process.env.PKG_VERSION,
    description: pkg.description,
    author: pkg.author,
    license: pkg.license,
    engines: pkg.engines,
    repository: pkg.repository,
    homepage: pkg.homepage,
    publishConfig: pkg.publishConfig,
    main: 'index.js',
    types: 'index.d.ts',
  };
  require('fs').writeFileSync('$DIST_DIR/package.json', JSON.stringify(dist, null, 4) + '\n');
"
# ── Format ────────────────────────────────────────────────────────────────────
echo "Formatting TypeScript/JavaScript sources..."
npx prettier --write "$DIST_DIR"/*.{js,ts,json}

for f in "$DIST_DIR/index.js" "$DIST_DIR/index.d.ts"; do
    sed -i.bak "s|'../dist/bindings_wasm'|'./bindings_wasm'|g" "$f"
    rm -f "$f.bak"
done

cp "$WORKSPACE/../LICENSE" "$DIST_DIR/LICENSE"
cp "$SCRIPT_DIR/README.md" "$DIST_DIR/README.md"

echo "Build complete: $DIST_DIR ($(du -sh "$DIST_DIR" | cut -f1))"

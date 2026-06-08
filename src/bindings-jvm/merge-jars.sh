#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <output.jar> <input.jar> [<input.jar> ...]" >&2
    exit 1
fi

command -v unzip &>/dev/null || { echo "Error: unzip not found on PATH" >&2; exit 1; }
command -v zip &>/dev/null || { echo "Error: zip not found on PATH" >&2; exit 1; }

OUT_JAR="$1"; shift
OUT_DIR="$(cd "$(dirname "$OUT_JAR")" && pwd)"
OUT_JAR="$OUT_DIR/$(basename "$OUT_JAR")"

BASE_JAR="$1"; shift
echo "Base jar (classes + sources + native): $BASE_JAR"
cp "$BASE_JAR" "$OUT_JAR"

for jar_file in "$@"; do
    natives="$(unzip -Z1 "$jar_file" | grep -E '\.(dylib|so|dll)$' || true)"
    if [ -z "$natives" ]; then
        echo "WARNING: no native library found in $jar_file, skipping" >&2
        continue
    fi
    tmp="$(mktemp -d)"
    while IFS= read -r entry; do
        echo "  + $entry  (from $(basename "$jar_file"))"
        unzip -oq "$jar_file" "$entry" -d "$tmp"
    done <<< "$natives"
    ( cd "$tmp" && zip -rqX "$OUT_JAR" . )
    rm -rf "$tmp"
done

echo ""
echo "Merged jar: $OUT_JAR"
echo "Bundled native libraries:"
unzip -Z1 "$OUT_JAR" | grep -E '\.(dylib|so|dll)$' | sed 's/^/  /'

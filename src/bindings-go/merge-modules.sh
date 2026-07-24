#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <output-dir> <base-module-dir> <module-dir> [<module-dir> ...]" >&2
    exit 1
fi

OUTPUT_DIR="$1"
shift
BASE_DIR="$1"
shift

[ -f "$BASE_DIR/go.mod" ] || { echo "Error: base module has no go.mod: $BASE_DIR" >&2; exit 1; }

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cp -R "$BASE_DIR"/. "$OUTPUT_DIR"/

LIST_DIR="$(mktemp -d)"
trap 'rm -rf "$LIST_DIR"' EXIT
BASE_SHARED_LIST="$LIST_DIR/base-shared"
(
    cd "$BASE_DIR"
    find . -type f ! -path './libs/*' -print | sort
) > "$BASE_SHARED_LIST"

BASE_LIBRARY_LIST="$LIST_DIR/base-libraries"
find "$BASE_DIR/libs" -mindepth 2 -maxdepth 2 -type f -name 'libbindings_go.a' -print | sort > "$BASE_LIBRARY_LIST"
BASE_LIBRARY_COUNT=$(wc -l < "$BASE_LIBRARY_LIST" | tr -d ' ')
if [ "$BASE_LIBRARY_COUNT" -ne 1 ]; then
    echo "Error: expected exactly one host static library in $BASE_DIR, found $BASE_LIBRARY_COUNT" >&2
    exit 1
fi

MODULE_INDEX=0
for MODULE_DIR in "$@"; do
    MODULE_INDEX=$((MODULE_INDEX + 1))
    [ -f "$MODULE_DIR/go.mod" ] || { echo "Error: input module has no go.mod: $MODULE_DIR" >&2; exit 1; }

    MODULE_SHARED_LIST="$LIST_DIR/module-$MODULE_INDEX-shared"
    (
        cd "$MODULE_DIR"
        find . -type f ! -path './libs/*' -print | sort
    ) > "$MODULE_SHARED_LIST"
    if ! cmp -s "$BASE_SHARED_LIST" "$MODULE_SHARED_LIST"; then
        echo "Error: shared module file set differs in $MODULE_DIR" >&2
        diff "$BASE_SHARED_LIST" "$MODULE_SHARED_LIST" || true
        exit 1
    fi

    while IFS= read -r RELATIVE_PATH; do
        if ! cmp -s "$BASE_DIR/$RELATIVE_PATH" "$MODULE_DIR/$RELATIVE_PATH"; then
            echo "Error: shared module file differs: $MODULE_DIR/$RELATIVE_PATH" >&2
            exit 1
        fi
    done < "$BASE_SHARED_LIST"

    STATIC_LIBRARY_LIST="$LIST_DIR/module-$MODULE_INDEX-libraries"
    find "$MODULE_DIR/libs" -mindepth 2 -maxdepth 2 -type f -name 'libbindings_go.a' -print | sort > "$STATIC_LIBRARY_LIST"
    STATIC_LIBRARY_COUNT=$(wc -l < "$STATIC_LIBRARY_LIST" | tr -d ' ')
    if [ "$STATIC_LIBRARY_COUNT" -ne 1 ]; then
        echo "Error: expected exactly one host static library in $MODULE_DIR, found $STATIC_LIBRARY_COUNT" >&2
        exit 1
    fi

    IFS= read -r STATIC_LIBRARY < "$STATIC_LIBRARY_LIST"
    PLATFORM="$(basename "$(dirname "$STATIC_LIBRARY")")"
    DESTINATION="$OUTPUT_DIR/libs/$PLATFORM/libbindings_go.a"
    if [ -e "$DESTINATION" ]; then
        echo "Error: duplicate static library for $PLATFORM" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$DESTINATION")"
    cp "$STATIC_LIBRARY" "$DESTINATION"
done

for REQUIRED_FILE in go.mod README.md LICENSE THIRD-PARTY-LICENSES.txt internal/bindings_go/bindings_go.go; do
    [ -f "$OUTPUT_DIR/$REQUIRED_FILE" ] || { echo "Error: merged module is missing $REQUIRED_FILE" >&2; exit 1; }
done

echo "Merged Go module: $OUTPUT_DIR"
find "$OUTPUT_DIR/libs" -mindepth 2 -maxdepth 2 -type f -name 'libbindings_go.a' -print | sort | sed 's/^/  /'

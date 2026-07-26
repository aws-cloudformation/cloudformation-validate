#!/usr/bin/env python3
"""Merge host-specific binding wheels into one all-platform wheel.

The first (base) wheel provides all shared content; every other wheel
contributes only its platform native library.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import pathlib
import sys
import zipfile

PACKAGE_PREFIX = "cloudformation_validate/"
NATIVES_PREFIX = f"{PACKAGE_PREFIX}natives/"


class WheelContents:
    def __init__(self, path: pathlib.Path):
        self.path = path
        with zipfile.ZipFile(path) as archive:
            self.entries = {
                entry.filename: (entry, archive.read(entry))
                for entry in archive.infolist()
                if not entry.is_dir()
            }

        record_paths = [name for name in self.entries if name.endswith(".dist-info/RECORD")]
        if len(record_paths) != 1:
            raise ValueError(f"{path}: expected exactly one .dist-info/RECORD, found {len(record_paths)}")
        self.record_path = record_paths[0]

        self.native_paths = sorted(name for name in self.entries if name.startswith(NATIVES_PREFIX))
        if len(self.native_paths) != 1:
            raise ValueError(f"{path}: expected exactly one host native, found {len(self.native_paths)}")

        native_parts = pathlib.PurePosixPath(self.native_paths[0]).parts
        if len(native_parts) != 4:
            raise ValueError(f"{path}: malformed native path {self.native_paths[0]!r}")
        self.platform = native_parts[2]


def record_content(entries: dict[str, tuple[zipfile.ZipInfo, bytes]], record_path: str) -> bytes:
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for name in sorted(entries):
        content = entries[name][1]
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, f"sha256={digest}", len(content)))
    writer.writerow((record_path, "", ""))
    return text.getvalue().encode("utf-8")


def merge_wheels(output_path: pathlib.Path, input_paths: list[pathlib.Path]) -> None:
    if len(input_paths) < 2:
        raise ValueError("at least two host-specific wheels are required")

    wheels = [WheelContents(path) for path in input_paths]
    base = wheels[0]
    if len({wheel.record_path for wheel in wheels}) != 1:
        raise ValueError("input wheels use different .dist-info directories")

    # The base wheel provides every shared entry and the other wheels
    # contribute only their platform native. Shared entries are not
    # byte-compared across wheels — build hosts produce benign differences
    # (line endings, emission order) — and the generated code verifies its API
    # checksums against whichever native it loads at import time, so real ABI
    # drift still fails loudly on every platform.
    merged_entries = {
        name: entry
        for name, entry in base.entries.items()
        if name != base.record_path
    }
    platforms = {base.platform}

    for wheel in wheels[1:]:
        if wheel.platform in platforms:
            raise ValueError(f"duplicate native platform {wheel.platform!r} from {wheel.path}")
        platforms.add(wheel.platform)
        native_path = wheel.native_paths[0]
        merged_entries[native_path] = wheel.entries[native_path]

    record_info = base.entries[base.record_path][0]
    merged_entries[base.record_path] = (record_info, record_content(merged_entries, base.record_path))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    with zipfile.ZipFile(output_path, "w") as archive:
        for name in sorted(merged_entries):
            entry, content = merged_entries[name]
            archive.writestr(entry, content)

    print(f"Merged wheel: {output_path}")
    for platform in sorted(platforms):
        print(f"  {platform}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge host-specific cloudformation-validate wheels into one all-platform wheel."
    )
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("inputs", type=pathlib.Path, nargs="+")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        merge_wheels(args.output, args.inputs)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

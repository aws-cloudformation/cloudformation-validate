#!/usr/bin/env python3
"""Merge host-specific binding wheels into one all-platform wheel.

The first (base) wheel provides all shared content; every other wheel
contributes only its platform native library. Each input wheel carries a real
platform tag, and the merged wheel carries the compressed tag set of all of
them, so pip refuses installation on platforms with no bundled native.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import pathlib
import re
import sys
import zipfile

PACKAGE_PREFIX = "cloudformation_validate/"
NATIVES_PREFIX = f"{PACKAGE_PREFIX}natives/"
TAG_PATTERN = re.compile(r"^Tag: py3-none-(?P<platform>\S+)$", re.MULTILINE)

# Native directory token -> the platform tag family it must be published under.
NATIVE_PLATFORM_TAGS = {
    "linux-x86-64": re.compile(r"^manylinux_\d+_\d+_x86_64$"),
    "darwin-aarch64": re.compile(r"^macosx_\d+_\d+_arm64$"),
    "win32-x86-64": re.compile(r"^win_amd64$"),
}


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

        wheel_paths = [name for name in self.entries if name.endswith(".dist-info/WHEEL")]
        if len(wheel_paths) != 1:
            raise ValueError(f"{path}: expected exactly one .dist-info/WHEEL, found {len(wheel_paths)}")
        self.wheel_path = wheel_paths[0]

        wheel_text = self.entries[self.wheel_path][1].decode("utf-8")
        tags = TAG_PATTERN.findall(wheel_text)
        if len(tags) != 1:
            raise ValueError(f"{path}: expected exactly one py3-none platform tag, found {tags}")
        self.platform_tag = tags[0]
        if "Root-Is-Purelib: false" not in wheel_text:
            raise ValueError(f"{path}: wheel bundles a native library but is not marked Root-Is-Purelib: false")

        self.native_paths = sorted(name for name in self.entries if name.startswith(NATIVES_PREFIX))
        if len(self.native_paths) != 1:
            raise ValueError(f"{path}: expected exactly one host native, found {len(self.native_paths)}")

        native_parts = pathlib.PurePosixPath(self.native_paths[0]).parts
        if len(native_parts) != 4:
            raise ValueError(f"{path}: malformed native path {self.native_paths[0]!r}")
        self.platform = native_parts[2]

        expected_tag = NATIVE_PLATFORM_TAGS.get(self.platform)
        if expected_tag is None:
            raise ValueError(f"{path}: no platform tag family is defined for native {self.platform!r}")
        if not expected_tag.match(self.platform_tag):
            raise ValueError(
                f"{path}: platform tag {self.platform_tag!r} does not match the bundled native {self.platform!r}"
            )


def record_content(entries: dict[str, tuple[zipfile.ZipInfo, bytes]], record_path: str) -> bytes:
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for name in sorted(entries):
        content = entries[name][1]
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, f"sha256={digest}", len(content)))
    writer.writerow((record_path, "", ""))
    return text.getvalue().encode("utf-8")


def merge_wheels(output_dir: pathlib.Path, input_paths: list[pathlib.Path]) -> None:
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
    platform_tags = {base.platform_tag}

    for wheel in wheels[1:]:
        if wheel.platform in platforms:
            raise ValueError(f"duplicate native platform {wheel.platform!r} from {wheel.path}")
        platforms.add(wheel.platform)
        platform_tags.add(wheel.platform_tag)
        native_path = wheel.native_paths[0]
        merged_entries[native_path] = wheel.entries[native_path]

    # The merged wheel carries every input's platform tag: one Tag line per
    # platform in WHEEL, and the compressed tag set in the filename, so pip
    # installs it only on platforms with a bundled native. WHEEL is an
    # email-header block, so the Tag lines are appended to the existing
    # headers with no blank line in between.
    sorted_tags = sorted(platform_tags)
    wheel_info, wheel_content = base.entries[base.wheel_path]
    header_lines = [
        line
        for line in wheel_content.decode("utf-8").splitlines()
        if line and not TAG_PATTERN.match(line)
    ]
    header_lines.extend(f"Tag: py3-none-{tag}" for tag in sorted_tags)
    merged_wheel_text = "\n".join(header_lines) + "\n"
    merged_entries[base.wheel_path] = (wheel_info, merged_wheel_text.encode("utf-8"))

    record_info = base.entries[base.record_path][0]
    merged_entries[base.record_path] = (record_info, record_content(merged_entries, base.record_path))

    dist_info = base.record_path.rsplit("/", 1)[0]
    name_and_version = dist_info.removesuffix(".dist-info")
    output_path = output_dir / f"{name_and_version}-py3-none-{'.'.join(sorted_tags)}.whl"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    with zipfile.ZipFile(output_path, "w") as archive:
        for name in sorted(merged_entries):
            entry, content = merged_entries[name]
            archive.writestr(entry, content)

    print(f"Merged wheel: {output_path}")
    for tag in sorted_tags:
        print(f"  {tag}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge host-specific cloudformation-validate wheels into one all-platform wheel."
    )
    parser.add_argument("output_dir", type=pathlib.Path, help="directory to write the merged wheel into")
    parser.add_argument("inputs", type=pathlib.Path, nargs="+")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        merge_wheels(args.output_dir, args.inputs)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

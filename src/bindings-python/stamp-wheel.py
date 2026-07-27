#!/usr/bin/env python3
"""Stamp a built wheel with a release version.

The version appears in the filename, the `.dist-info` directory name, and the
`Version` field of METADATA, and every path is hashed in RECORD, so all four are
rewritten. Stamping the version already in the wheel is a no-op, so the caller
can invoke this unconditionally.
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

DIST_INFO_SUFFIX = ".dist-info"
VERSION_PATTERN = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?$")
METADATA_VERSION_PATTERN = re.compile(r"^Version: .*$", re.MULTILINE)


class Wheel:
    def __init__(self, path: pathlib.Path):
        self.path = path
        with zipfile.ZipFile(path) as archive:
            self.entries = {
                entry.filename: (entry, archive.read(entry))
                for entry in archive.infolist()
                if not entry.is_dir()
            }

        dist_infos = {
            name.split("/", 1)[0] for name in self.entries if name.split("/", 1)[0].endswith(DIST_INFO_SUFFIX)
        }
        if len(dist_infos) != 1:
            raise ValueError(f"{path}: expected exactly one .dist-info directory, found {sorted(dist_infos)}")
        self.dist_info = dist_infos.pop()

        self.record_path = f"{self.dist_info}/RECORD"
        self.metadata_path = f"{self.dist_info}/METADATA"
        for required in (self.record_path, self.metadata_path):
            if required not in self.entries:
                raise ValueError(f"{path}: wheel is missing {required}")

        stem = self.dist_info[: -len(DIST_INFO_SUFFIX)]
        if "-" not in stem:
            raise ValueError(f"{path}: malformed .dist-info name {self.dist_info!r}")
        self.name, self.version = stem.rsplit("-", 1)

        prefix = f"{self.name}-{self.version}-"
        if not path.name.startswith(prefix) or not path.name.endswith(".whl"):
            raise ValueError(f"{path.name}: filename does not match the packaged distribution {prefix}*.whl")


def record_content(entries: dict[str, tuple[zipfile.ZipInfo, bytes]], record_path: str) -> bytes:
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for name in sorted(entries):
        content = entries[name][1]
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name, f"sha256={digest}", len(content)))
    writer.writerow((record_path, "", ""))
    return text.getvalue().encode("utf-8")


def renamed_entry(entry: zipfile.ZipInfo, filename: str) -> zipfile.ZipInfo:
    """Copies a zip entry under a new name, preserving its archive attributes."""
    if entry.filename == filename:
        return entry
    moved = zipfile.ZipInfo(filename=filename, date_time=entry.date_time)
    moved.compress_type = entry.compress_type
    moved.comment = entry.comment
    moved.extra = entry.extra
    moved.create_system = entry.create_system
    moved.create_version = entry.create_version
    moved.extract_version = entry.extract_version
    moved.flag_bits = entry.flag_bits
    moved.internal_attr = entry.internal_attr
    moved.external_attr = entry.external_attr
    return moved


def stamp_wheel(output_dir: pathlib.Path, wheel_path: pathlib.Path, version: str) -> pathlib.Path:
    if not VERSION_PATTERN.match(version):
        raise ValueError(f"{version!r} is not a supported version (e.g. 1.6.0 or 1.6.0b0)")

    wheel = Wheel(wheel_path)
    new_dist_info = f"{wheel.name}-{version}{DIST_INFO_SUFFIX}"

    entries: dict[str, tuple[zipfile.ZipInfo, bytes]] = {}
    for name, (entry, content) in wheel.entries.items():
        if name.startswith(f"{wheel.dist_info}/"):
            name = f"{new_dist_info}/{name.split('/', 1)[1]}"
        entries[name] = (renamed_entry(entry, name), content)

    metadata_path = f"{new_dist_info}/METADATA"
    metadata_info, metadata_content = entries[metadata_path]
    metadata_text = metadata_content.decode("utf-8")
    if len(METADATA_VERSION_PATTERN.findall(metadata_text)) != 1:
        raise ValueError(f"{wheel_path}: METADATA must contain exactly one Version field")
    metadata_text = METADATA_VERSION_PATTERN.sub(f"Version: {version}", metadata_text)
    entries[metadata_path] = (metadata_info, metadata_text.encode("utf-8"))

    record_path = f"{new_dist_info}/RECORD"
    record_info = entries.pop(record_path)[0]
    entries[record_path] = (record_info, record_content(entries, record_path))

    tags = wheel_path.name[len(f"{wheel.name}-{wheel.version}-") :]
    output_path = output_dir / f"{wheel.name}-{version}-{tags}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    with zipfile.ZipFile(output_path, "w") as archive:
        for name in sorted(entries):
            entry, content = entries[name]
            archive.writestr(entry, content)

    print(f"Stamped wheel: {output_path} ({wheel.version} -> {version})")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stamp a cloudformation-validate wheel with a release version.")
    parser.add_argument("output_dir", type=pathlib.Path, help="directory to write the stamped wheel into")
    parser.add_argument("wheel", type=pathlib.Path, help="wheel to stamp")
    parser.add_argument("version", help="version to stamp, such as 1.6.0 or 1.6.0b0")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        stamp_wheel(args.output_dir, args.wheel, args.version)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate THIRD-PARTY-LICENSES.txt for each distribution target.

Runs cargo-about to collect Rust dependency licenses, sorts entries
alphabetically by crate name, and writes one file per target:

  src/THIRD-PARTY-LICENSES.txt                         (native Rust binary)
  src/bindings-jvm/generated/THIRD-PARTY-LICENSES.txt  (JVM JAR)
  src/bindings-wasm/dist/THIRD-PARTY-LICENSES.txt      (WASM npm package)

The JVM file additionally includes Java runtime dependencies (JNA, Gson)
that are not tracked by Cargo.

Usage:
    python3 scripts/generate_licenses.py          # all targets
    python3 scripts/generate_licenses.py native   # native Rust only
    python3 scripts/generate_licenses.py jvm      # JVM only
    python3 scripts/generate_licenses.py wasm     # WASM only
    python3 scripts/generate_licenses.py jvm wasm # multiple targets
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WORKSPACE = PROJECT_ROOT / "src"

SEPARATOR = "\n\n******************************\n\n"

# Workspace crates are internal — exclude from third-party license files
WORKSPACE_CRATES = {
    "bindings-jvm", "bindings-wasm", "cel-engine", "cfn-validate",
    "data-source", "diagnostics", "guard-translator", "rego-engine",
    "rules", "schema-validator", "template-model", "validation-engine",
}

# Java runtime dependencies required by bindings-jvm consumers (not in Cargo)
JVM_EXTRA_DEPS = [
    {
        "name": "com.google.code.gson:gson",
        "version": "2.14.0",
        "url": "https://github.com/google/gson",
        "license": "Apache-2.0",
        "text": (
            "                                 Apache License\n"
            "                           Version 2.0, January 2004\n"
            "                        http://www.apache.org/licenses/\n\n"
            "   See full text in the Apache License 2.0 entries above."
        ),
    },
    {
        "name": "net.java.dev.jna:jna",
        "version": "5.18.1",
        "url": "https://github.com/java-native-access/jna",
        "license": "Apache-2.0",
        "text": (
            "                                 Apache License\n"
            "                           Version 2.0, January 2004\n"
            "                        http://www.apache.org/licenses/\n\n"
            "   See full text in the Apache License 2.0 entries above."
        ),
    },
]


def run_cargo_about(manifest_flag: str) -> dict:
    """Run cargo-about and return parsed JSON."""
    cmd = ["cargo", "about", "generate", "-c", "about.toml", *manifest_flag.split(), "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=WORKSPACE)
    if result.returncode != 0:
        print(f"cargo-about failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def extract_entries(data: dict) -> list[tuple[str, str, str, str]]:
    """Extract (name, version, url, license_text) from cargo-about JSON, excluding workspace crates."""
    entries = []
    for lic in data["licenses"]:
        for used in lic["used_by"]:
            crate = used["crate"]
            if crate["name"] in WORKSPACE_CRATES:
                continue
            url = crate.get("repository") or crate.get("homepage") or _url_from_source(
                crate) or f"https://crates.io/crates/{crate['name']}"
            entries.append((crate["name"], crate["version"], url, lic["text"]))
    return entries


def _url_from_source(crate: dict) -> str | None:
    """Extract a git URL from the cargo source field (e.g. 'git+https://...?branch=x#commit')."""
    source = crate.get("source") or ""
    if source.startswith("git+"):
        url = source[4:]
        # Strip ?branch=...#commit suffix
        for sep in ("?", "#"):
            url = url.split(sep)[0]
        return url
    return None


def format_output(entries: list[tuple[str, str, str, str]]) -> str:
    """Sort entries by name and format as plain text."""
    entries.sort(key=lambda e: e[0].lower())
    sections = [f"{name}\n{version} <{url}>\n{text}" for name, version, url, text in entries]
    return SEPARATOR.join(sections) + "\n"


def generate(label: str, manifest_flag: str, output_path: Path, extra_deps: list[dict] | None = None):
    """Generate a single THIRD-PARTY-LICENSES.txt."""
    print(f"Generating {label}...")
    data = run_cargo_about(manifest_flag)
    entries = extract_entries(data)

    if extra_deps:
        for dep in extra_deps:
            entries.append((dep["name"], dep["version"], dep["url"], dep["text"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(format_output(entries))
    print(f"  → {output_path.relative_to(PROJECT_ROOT)} ({len(entries)} packages)")


VALID_TARGETS = {"native", "jvm", "wasm", "all"}


def main():
    parser = argparse.ArgumentParser(description="Generate THIRD-PARTY-LICENSES.txt")
    parser.add_argument(
        "targets", nargs="*", default=["all"],
        help="Targets to generate: native, jvm, wasm, all (default: all)",
    )
    args = parser.parse_args()
    targets = set(args.targets)
    if not targets.issubset(VALID_TARGETS):
        parser.error(f"invalid targets: {targets - VALID_TARGETS}. Choose from: {sorted(VALID_TARGETS)}")
    if "all" in targets:
        targets = {"native", "jvm", "wasm"}

    if "native" in targets:
        generate(
            "native Rust",
            "--workspace",
            WORKSPACE / "THIRD-PARTY-LICENSES.txt",
        )
    if "jvm" in targets:
        generate(
            "bindings-jvm",
            "-m bindings-jvm/Cargo.toml",
            WORKSPACE / "bindings-jvm" / "THIRD-PARTY-LICENSES.txt",
            extra_deps=JVM_EXTRA_DEPS,
        )
    if "wasm" in targets:
        generate(
            "bindings-wasm",
            "-m bindings-wasm/Cargo.toml",
            WORKSPACE / "bindings-wasm" / "THIRD-PARTY-LICENSES.txt",
        )
    print("Done.")


if __name__ == "__main__":
    main()

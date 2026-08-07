#!/usr/bin/env python3
"""Generate THIRD-PARTY-LICENSES.txt for each distribution target.

Usage:
    python3 scripts/generate_licenses.py            # all targets
    python3 scripts/generate_licenses.py native     # native Rust only
    python3 scripts/generate_licenses.py jvm        # JVM only
    python3 scripts/generate_licenses.py wasm       # WASM only
    python3 scripts/generate_licenses.py python     # Python only
    python3 scripts/generate_licenses.py go         # Go only
    python3 scripts/generate_licenses.py jvm wasm   # multiple targets
"""

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WORKSPACE = PROJECT_ROOT / "src"

SEPARATOR = "\n\n******************************\n\n"

# Workspace crates - exclude from third-party license files.
WORKSPACE_CRATES = {
    "bindings-go",
    "bindings-jvm",
    "bindings-python",
    "bindings-wasm",
    "cel-engine",
    "cfn-validate",
    "data-source",
    "diagnostics",
    "guard-translator",
    "rego-engine",
    "resources",
    "rules",
    "schema-validator",
    "template-model",
    "validation-engine",
}

APACHE_LICENSE_REFERENCE = (
    "                                 Apache License\n"
    "                           Version 2.0, January 2004\n"
    "                        http://www.apache.org/licenses/\n\n"
    "   See full text in any Apache License 2.0 entry in this file."
)

# Maven dependencies the JVM JAR consumers need on their classpath.
JVM_EXTRA_DEPS = [
    {
        "name": "com.google.code.gson:gson",
        "version": "2.14.0",
        "url": "https://github.com/google/gson",
        "license": "Apache-2.0",
        "text": APACHE_LICENSE_REFERENCE,
    },
    {
        "name": "net.java.dev.jna:jna",
        "version": "5.19.1",
        "url": "https://github.com/java-native-access/jna",
        "license": "Apache-2.0",
        "text": APACHE_LICENSE_REFERENCE,
    },
    {
        "name": "org.jetbrains.kotlin:kotlin-stdlib",
        "version": "2.4.0",
        "url": "https://github.com/JetBrains/kotlin",
        "license": "Apache-2.0",
        "text": APACHE_LICENSE_REFERENCE,
    },
]

# Substrings that mark cargo-about's SPDX template fallback (no real copyright holder).
PLACEHOLDER_MARKERS = (
    "Copyright (c) <year>",
    "<copyright holders>",
    "<owner>",
    "[year] [name",
)

# Crates whose tarball doesn't ship a usable LICENSE. Each entry pins an
# upstream URL fetched at generation time and substituted in place of
# cargo-about's SPDX-template fallback.
CRATE_EXTRA_ATTRIBUTIONS = {
    ("cel-interpreter", "0.10.0"): {
        "license_name": "MIT License",
        "license_url": "https://raw.githubusercontent.com/cel-rust/cel-rust/cel-v0.10.0/LICENSE",
    },
    ("cel-parser", "0.10.1"): {
        "license_name": "MIT License",
        "license_url": "https://raw.githubusercontent.com/cel-rust/cel-rust/cel-parser-v0.10.1/LICENSE",
    },
    # chrislearn/cruet redirects to taidge/cruet (the active fork).
    ("cruet", "0.14.0"): {
        "license_name": "BSD-2-Clause License",
        "license_url": "https://raw.githubusercontent.com/taidge/cruet/v0.14.0/LICENSE.md",
    },
    # Tarball LICENSE.txt copyright doesn't match upstream; pinned to the
    # commit tagged for this crate release.
    ("antlr4rust", "0.3.0-rc2"): {
        "license_url": "https://raw.githubusercontent.com/antlr4rust/antlr4/9d34cea8de/LICENSE.txt",
    },
}


def has_placeholder(text: str) -> bool:
    return any(m in text for m in PLACEHOLDER_MARKERS)


_license_cache: dict[str, str] = {}


def fetch_license_text(url: str) -> str:
    """Fetch a LICENSE file from a pinned HTTPS URL, cached per invocation."""
    if url in _license_cache:
        return _license_cache[url]
    print(f"  fetching {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "cloudformation-validate-license-gen"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"failed to fetch {url}: {e}", file=sys.stderr)
        sys.exit(1)
    text = text.rstrip() + "\n"
    _license_cache[url] = text
    return text


def run_cargo_about(manifest_args: list[str], targets: list[str]) -> dict:
    """Run cargo-about and return parsed JSON. Empty `targets` disables target filtering."""
    cmd = ["cargo", "about", "generate", "-c", "about.toml", *manifest_args, "--format", "json"]
    for t in targets:
        cmd.extend(["--target", t])
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=WORKSPACE)
    if result.returncode != 0:
        print(f"cargo-about failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def extract_entries(data: dict) -> list[tuple[str, str, str, str]]:
    """Extract (name, version, url, license_text) excluding workspace crates."""
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
    """Extract a git URL from cargo's source field (e.g. 'git+https://...?branch=x#commit')."""
    source = crate.get("source") or ""
    if source.startswith("git+"):
        url = source[4:]
        for sep in ("?", "#"):
            url = url.split(sep)[0]
        return url
    return None


def dedup_entries(entries: list[tuple[str, str, str, str]]) -> list[tuple[str, str, str, str]]:
    """Per (name, version): drop placeholder-text entries when a real-text entry exists.

    Preserves multiple distinct real-text entries (multi-licensed crates).
    Keeps one placeholder if all entries are placeholders.
    """
    groups: dict[tuple[str, str], list[tuple[str, str, str, str]]] = defaultdict(list)
    for e in entries:
        groups[(e[0], e[1])].append(e)
    result = []
    for entries_in_group in groups.values():
        real = [e for e in entries_in_group if not has_placeholder(e[3])]
        result.extend(real if real else [entries_in_group[0]])
    return result


def apply_attribution_overrides(
    entries: list[tuple[str, str, str, str]],
) -> list[tuple[str, str, str, str]]:
    """Replace placeholder text with the upstream LICENSE for crates in CRATE_EXTRA_ATTRIBUTIONS."""
    result = []
    for name, ver, url, text in entries:
        override = CRATE_EXTRA_ATTRIBUTIONS.get((name, ver))
        if override and has_placeholder(text):
            text = fetch_license_text(override["license_url"])
            if "license_name" in override:
                text = f"{override['license_name']}\n\n{text}"
        result.append((name, ver, url, text))
    return result


def format_output(entries: list[tuple[str, str, str, str]]) -> str:
    """Sort entries by name and format as plain text."""
    entries.sort(key=lambda e: e[0].lower())
    sections = [f"{name}\n{version} <{url}>\n{text}" for name, version, url, text in entries]
    return SEPARATOR.join(sections) + "\n"


def generate(
    label: str,
    manifest_args: list[str],
    output_path: Path,
    targets: list[str] | None = None,
    extra_deps: list[dict] | None = None,
):
    """Generate a single THIRD-PARTY-LICENSES.txt."""
    print(f"Generating {label}...")
    data = run_cargo_about(manifest_args, targets or [])
    entries = extract_entries(data)
    entries = dedup_entries(entries)
    entries = apply_attribution_overrides(entries)

    if extra_deps:
        for dep in extra_deps:
            entries.append((dep["name"], dep["version"], dep["url"], dep["text"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(format_output(entries))
    print(f"  → {output_path.relative_to(PROJECT_ROOT)} ({len(entries)} packages)")


VALID_TARGETS = {"native", "jvm", "wasm", "python", "go", "all"}


def main():
    parser = argparse.ArgumentParser(description="Generate THIRD-PARTY-LICENSES.txt")
    parser.add_argument(
        "targets", nargs="*", default=["all"],
        help="Targets to generate: native, jvm, wasm, python, go, all (default: all)",
    )
    args = parser.parse_args()
    targets = set(args.targets)
    if not targets.issubset(VALID_TARGETS):
        parser.error(f"invalid targets: {targets - VALID_TARGETS}. Choose from: {sorted(VALID_TARGETS)}")
    if "all" in targets:
        targets = {"native", "jvm", "wasm", "python", "go"}

    if "native" in targets:
        generate(
            "native Rust",
            ["--workspace"],
            WORKSPACE / "THIRD-PARTY-LICENSES.txt",
        )
    if "jvm" in targets:
        # https://doc.rust-lang.org/rustc/platform-support.html
        generate(
            "bindings-jvm",
            ["-m", "bindings-jvm/Cargo.toml"],
            WORKSPACE / "bindings-jvm" / "THIRD-PARTY-LICENSES.txt",
            targets=[
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
                "aarch64-pc-windows-msvc",
            ],
            extra_deps=JVM_EXTRA_DEPS,
        )
    if "wasm" in targets:
        generate(
            "bindings-wasm",
            ["-m", "bindings-wasm/Cargo.toml"],
            WORKSPACE / "bindings-wasm" / "THIRD-PARTY-LICENSES.txt",
            targets=["wasm32-unknown-unknown"],
        )
    if "python" in targets:
        generate(
            "bindings-python",
            ["-m", "bindings-python/Cargo.toml"],
            WORKSPACE / "bindings-python" / "THIRD-PARTY-LICENSES.txt",
            targets=[
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
                "aarch64-pc-windows-msvc",
            ],
        )
    if "go" in targets:
        # The Go static library is built with the GNU toolchain on Windows
        # (cgo links with MinGW), so the windows targets here are the GNU
        # flavors (gnullvm is the aarch64 MinGW-style target).
        generate(
            "bindings-go",
            ["-m", "bindings-go/Cargo.toml"],
            WORKSPACE / "bindings-go" / "go" / "THIRD-PARTY-LICENSES.txt",
            targets=[
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-gnu",
                "aarch64-pc-windows-gnullvm",
            ],
        )
    print("Done.")


if __name__ == "__main__":
    main()

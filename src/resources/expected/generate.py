#!/usr/bin/env python3
"""Regenerate the golden JSON file from cfn-validate --format detailed output.

Runs BOTH engines (rego and cel) on every template and verifies they produce
identical diagnostics. Fails loudly on any divergence or missing output.

Run from the workspace root:
    python3 resources/expected/generate.py

Requires the release binary:
    cargo build --release -p cfn-validate --bin cfn-validate
"""

import json
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path

TEMPLATE_DIRS = ["bad", "cdk", "good", "integration", "issues", "lsp", "public", "quickstart"]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
RESOURCES_DIR = WORKSPACE_ROOT / "resources" / "templates"
EXPECTED_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = EXPECTED_DIR / "all_templates.json"
CFN_VALIDATE = WORKSPACE_ROOT / "target" / "release" / "cfn-validate"

# Fields that differ between engines (timing, engine name, internal counts) — stripped before comparison
IGNORED_FIELDS = {"engine", "performance", "benchmarkMetrics", "suppressed"}


def discover_templates() -> list[str]:
    templates = []
    for subdir in TEMPLATE_DIRS:
        dir_path = RESOURCES_DIR / subdir
        if not dir_path.is_dir():
            continue
        for path in sorted(dir_path.rglob("*")):
            if path.suffix in (".yaml", ".yml", ".json") and path.is_file():
                templates.append(str(path.relative_to(RESOURCES_DIR)))
    templates.sort()
    return templates


def zero_durations(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "durationMs":
                obj[k] = 0.0
            else:
                zero_durations(v)
    elif isinstance(obj, list):
        for item in obj:
            zero_durations(item)


def strip_engine_fields(obj):
    """Remove fields that legitimately differ between engines."""
    if isinstance(obj, dict):
        return OrderedDict(
            (k, strip_engine_fields(v)) for k, v in obj.items() if k not in IGNORED_FIELDS
        )
    if isinstance(obj, list):
        return [strip_engine_fields(item) for item in obj]
    return obj


def run_cfn_validate(template_rel: str, engine: str) -> OrderedDict:
    result = subprocess.run(
        [str(CFN_VALIDATE), template_rel, "--format", "detailed", "--level", "debug", "--engine", engine],
        cwd=RESOURCES_DIR,
        capture_output=True,
        text=True,
    )
    if not result.stdout.strip():
        print(f"  FATAL: {engine} produced no output for {template_rel}", file=sys.stderr)
        print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
        sys.exit(1)
    try:
        report = json.loads(result.stdout, object_pairs_hook=OrderedDict)
    except json.JSONDecodeError as e:
        print(f"  FATAL: {engine} produced invalid JSON for {template_rel}: {e}", file=sys.stderr)
        sys.exit(1)
    zero_durations(report)
    return report


def main():
    if not CFN_VALIDATE.exists():
        print(f"ERROR: {CFN_VALIDATE} not found", file=sys.stderr)
        print("Run: cargo build --release -p cfn-validate --bin cfn-validate", file=sys.stderr)
        sys.exit(1)

    templates = discover_templates()
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Discovered {len(templates)} templates")
    print(f"Running both engines (rego + cel) on each template...\n")

    all_data = OrderedDict()
    parity_failures = []

    for template in templates:
        print(f"  {template}")
        rego_report = run_cfn_validate(template, "rego")
        cel_report = run_cfn_validate(template, "cel")

        rego_comparable = strip_engine_fields(rego_report)
        cel_comparable = strip_engine_fields(cel_report)

        if json.dumps(rego_comparable, sort_keys=True) != json.dumps(cel_comparable, sort_keys=True):
            parity_failures.append(template)
            print(f"    !! PARITY FAILURE: rego and cel differ", file=sys.stderr)
            rego_diags = [(d["ruleId"], d["severity"]) for d in rego_comparable.get("diagnostics", [])]
            cel_diags = [(d["ruleId"], d["severity"]) for d in cel_comparable.get("diagnostics", [])]
            print(f"    rego: {rego_diags}", file=sys.stderr)
            print(f"    cel:  {cel_diags}", file=sys.stderr)
            sys.exit(1)

        all_data[template] = rego_report

    if parity_failures:
        print(f"\nFATAL: {len(parity_failures)} template(s) have engine parity failures:", file=sys.stderr)
        for t in parity_failures:
            print(f"  - {t}", file=sys.stderr)
        sys.exit(1)

    OUTPUT_FILE.write_text(json.dumps(all_data, indent=2) + "\n")
    print(f"\nWrote {len(all_data)} template results to {OUTPUT_FILE.name}")
    print(f"Engine parity verified: rego == cel on all {len(all_data)} templates")


if __name__ == "__main__":
    main()

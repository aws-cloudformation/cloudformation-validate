#!/usr/bin/env python3
"""Benchmark for the W9100 missing-context diagnostic.

Runs cfn-validate against every (nocontext, context) fixture pair in the
CfnCloudContextPOCs repo and measures whether the diagnostic discriminates:

* nocontext fixtures should emit >= 1 W9100 per resource (high counts)
* context fixtures should emit 0 W9100

Output mirrors the CfnCloudContextPOCs bench harness style: a markdown
report with overall scores, per-fixture breakdown, and a methodology section.
The report is deterministic — given the same fixtures, two runs produce
identical output.

Usage:
  python3 bench_w9100.py \\
    --cfn-validate /Volumes/workplace/nv/src/target/debug/cfn-validate \\
    --fixtures /Volumes/workplace/context/src/CfnCloudContextPOCs/fixtures \\
    --out out_w9100/

The script exits non-zero if any context fixture emits W9100 (false positive)
or if any nocontext fixture emits zero W9100 (false negative).
"""
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

RULE_ID = "W9100"


@dataclass
class FixtureResult:
    scenario: str          # paired stem, e.g. "respect-constraint"
    variant: str           # "nocontext" | "context"
    fixture_path: str
    resources_scanned: int
    w9100_count: int
    status: str            # "ok" | "error"
    error_message: str = ""


def discover_pairs(fixtures_dir: Path) -> dict[str, dict[str, Path]]:
    """Find every fixture with a -nocontext.yaml or -context.yaml suffix and
    pair them by scenario stem.

    Returns: { scenario_stem: { "nocontext": Path, "context": Path } }
    Only complete pairs (both variants present) are returned.
    """
    pairs: dict[str, dict[str, Path]] = defaultdict(dict)
    for path in sorted(fixtures_dir.glob("*.yaml")):
        name = path.stem
        for variant in ("nocontext", "context"):
            suffix = f"-{variant}"
            if name.endswith(suffix):
                scenario = name[: -len(suffix)]
                pairs[scenario][variant] = path
                break
    return {s: v for s, v in pairs.items() if "nocontext" in v and "context" in v}


def run_cfn_validate(cfn_validate: Path, fixture: Path) -> FixtureResult:
    """Invoke cfn-validate on a single fixture, count W9100 diagnostics."""
    cmd = [str(cfn_validate), str(fixture), "--include-ids", RULE_ID, "--format", "standard"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return FixtureResult(
            scenario="", variant="", fixture_path=str(fixture),
            resources_scanned=0, w9100_count=0, status="error",
            error_message="timeout after 60s",
        )
    if proc.returncode not in (0, 1):
        # 0 = clean, 1 = warnings/errors found, 2 = usage error
        return FixtureResult(
            scenario="", variant="", fixture_path=str(fixture),
            resources_scanned=0, w9100_count=0, status="error",
            error_message=f"exit {proc.returncode}: {proc.stderr.strip()[:200]}",
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return FixtureResult(
            scenario="", variant="", fixture_path=str(fixture),
            resources_scanned=0, w9100_count=0, status="error",
            error_message=f"invalid JSON output: {e}",
        )
    diagnostics = report.get("diagnostics", [])
    count = sum(1 for d in diagnostics if d.get("ruleId") == RULE_ID)
    return FixtureResult(
        scenario="", variant="", fixture_path=str(fixture),
        resources_scanned=int(report.get("metadata", {}).get("resourcesScanned", 0)),
        w9100_count=count, status="ok",
    )


def fmt_pct(num: float) -> str:
    return f"{num * 100:.2f}%"


def write_report(out_dir: Path, results: list[FixtureResult]) -> tuple[int, int]:
    """Render the benchmark report. Returns (false_negatives, false_positives).

    The W9100 diagnostic is per-template — at most one finding per fixture.
    Discrimination is therefore measured at the fixture level:
    - nocontext fixture should emit 1 W9100
    - context fixture should emit 0 W9100
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    by_scenario: dict[str, dict[str, FixtureResult]] = defaultdict(dict)
    for r in results:
        by_scenario[r.scenario][r.variant] = r

    nocontext_results = [r for r in results if r.variant == "nocontext" and r.status == "ok"]
    context_results = [r for r in results if r.variant == "context" and r.status == "ok"]

    def fixture_flag_rate(rs: list[FixtureResult]) -> float:
        if not rs:
            return 0.0
        flagged = sum(1 for r in rs if r.w9100_count > 0)
        return flagged / len(rs)

    nocontext_rate = fixture_flag_rate(nocontext_results)
    context_rate = fixture_flag_rate(context_results)
    discrimination_delta = nocontext_rate - context_rate

    # The W9100 diagnostic now fires at the template level (max 1 per fixture).
    # - false_negative: nocontext fixture emits 0 W9100 (missed a context-less template)
    # - false_positive: context fixture emits >=1 W9100 (flagged a template that has context)
    false_negatives = sum(1 for r in nocontext_results if r.w9100_count == 0)
    false_positives = sum(1 for r in context_results if r.w9100_count > 0)

    lines: list[str] = []
    lines.append("# W9100 Missing-Context Diagnostic Benchmark\n")
    lines.append("## Overall Discrimination\n")
    lines.append("| Variant | Fixtures | Fixtures Flagged | Flag Rate |")
    lines.append("|---------|----------|------------------|-----------|")
    nocontext_flagged = sum(1 for r in nocontext_results if r.w9100_count > 0)
    context_flagged = sum(1 for r in context_results if r.w9100_count > 0)
    lines.append(
        f"| nocontext | {len(nocontext_results)} | {nocontext_flagged} | "
        f"{fmt_pct(nocontext_rate)} |"
    )
    lines.append(
        f"| context | {len(context_results)} | {context_flagged} | "
        f"{fmt_pct(context_rate)} |"
    )
    lines.append("")
    lines.append(f"**Discrimination delta:** {fmt_pct(discrimination_delta)} (nocontext flag rate − context flag rate)")
    lines.append("")

    lines.append("## Correctness\n")
    lines.append(f"- False negatives (nocontext fixture emits 0 W9100): **{false_negatives}** — must be 0")
    lines.append(f"- False positives (context fixture emits W9100): **{false_positives}** — must be 0; context at the template level OR on any resource satisfies the check")
    lines.append("")
    if false_negatives == 0 and false_positives == 0:
        lines.append("✅ Diagnostic discriminates perfectly across all fixture pairs.")
    else:
        lines.append("❌ Diagnostic does not discriminate cleanly — see per-fixture breakdown.")
    lines.append("")

    lines.append("## Per-Scenario Breakdown\n")
    lines.append("| Scenario | nocontext W9100 | context W9100 | Discriminates |")
    lines.append("|----------|-----------------|---------------|---------------|")
    for scenario in sorted(by_scenario.keys()):
        nc = by_scenario[scenario].get("nocontext")
        ct = by_scenario[scenario].get("context")
        nc_count = f"{nc.w9100_count}" if nc and nc.status == "ok" else "ERR"
        ct_count = f"{ct.w9100_count}" if ct and ct.status == "ok" else "ERR"
        discriminates = "✓" if (
            nc and ct and nc.status == "ok" and ct.status == "ok"
            and nc.w9100_count >= 1 and ct.w9100_count == 0
        ) else "✗"
        lines.append(
            f"| {scenario} | {nc_count} | {ct_count} | {discriminates} |"
        )
    lines.append("")

    lines.append("## Methodology\n")
    lines.append(
        "Every fixture pair `<scenario>-nocontext.yaml` / `<scenario>-context.yaml` "
        "is run through the cfn-validate CLI with `--include-ids W9100` so only the "
        "missing-context diagnostic is reported. The diagnostic fires at most once "
        "per template: it emits a single W9100 warning when neither the top-level "
        "`Metadata.Context` block nor any resource's `Metadata.Context` carries "
        "design intent (`why`, `decisions`, `constraints`, `mutability`, or "
        "`metricsGuidance` with a non-empty value)."
    )
    lines.append("")
    lines.append(
        "**Expected behavior.** A fixture in the nocontext arm has no Metadata.Context "
        "anywhere, so the diagnostic should fire exactly once. A fixture in the "
        "context arm has Metadata.Context at the template level, on at least one "
        "resource, or both — so the diagnostic should not fire at all. Clean "
        "discrimination is `100% (nocontext) → 0% (context)`."
    )
    lines.append("")
    lines.append(
        "**What this benchmark does NOT measure.** This is a static-correctness check "
        "on the diagnostic itself — not an agent-behavior benchmark. It answers "
        "\"does the diagnostic distinguish present-vs-absent context?\", not \"does "
        "the diagnostic feedback cause downstream tooling to add context?\". The "
        "latter requires running the CfnCloudContextPOCs harness with a "
        "validation-feedback loop wired in."
    )
    lines.append("")

    lines.append("## Errors\n")
    error_results = [r for r in results if r.status != "ok"]
    if not error_results:
        lines.append("No fixture failed to validate.\n")
    else:
        lines.append("| Fixture | Error |")
        lines.append("|---------|-------|")
        for r in error_results:
            lines.append(f"| {r.fixture_path} | {r.error_message} |")
        lines.append("")

    report_path = out_dir / "report.md"
    report_path.write_text("\n".join(lines))

    raw = [
        {
            "scenario": r.scenario, "variant": r.variant,
            "fixture_path": r.fixture_path,
            "resources_scanned": r.resources_scanned,
            "w9100_count": r.w9100_count,
            "status": r.status,
            "error_message": r.error_message,
        }
        for r in results
    ]
    (out_dir / "results.json").write_text(json.dumps(raw, indent=2, sort_keys=True))

    return false_negatives, false_positives


def main():
    parser = argparse.ArgumentParser(description="W9100 missing-context diagnostic benchmark")
    parser.add_argument("--cfn-validate", required=True, type=Path, help="Path to cfn-validate binary")
    parser.add_argument("--fixtures", required=True, type=Path, help="Directory of CFN fixtures (paired -nocontext/-context)")
    parser.add_argument("--out", default=Path("out_w9100"), type=Path, help="Output directory")
    args = parser.parse_args()

    if not args.cfn_validate.exists():
        print(f"ERROR: cfn-validate binary not found at {args.cfn_validate}", file=sys.stderr)
        sys.exit(2)
    if not args.fixtures.is_dir():
        print(f"ERROR: fixtures dir not found at {args.fixtures}", file=sys.stderr)
        sys.exit(2)

    pairs = discover_pairs(args.fixtures)
    if not pairs:
        print(f"ERROR: no -nocontext/-context fixture pairs in {args.fixtures}", file=sys.stderr)
        sys.exit(2)
    print(f"Discovered {len(pairs)} fixture pairs.")

    results: list[FixtureResult] = []
    for scenario in sorted(pairs.keys()):
        for variant in ("nocontext", "context"):
            fixture = pairs[scenario][variant]
            print(f"  RUN {scenario}/{variant}...", end=" ", flush=True)
            r = run_cfn_validate(args.cfn_validate, fixture)
            r.scenario = scenario
            r.variant = variant
            results.append(r)
            print(f"resources={r.resources_scanned} W9100={r.w9100_count} [{r.status}]")

    fn_count, fp_count = write_report(args.out, results)
    print(f"\nReport written to {args.out / 'report.md'}")
    print(f"False negatives: {fn_count} | False positives: {fp_count}")
    sys.exit(0 if (fn_count == 0 and fp_count == 0) else 1)


if __name__ == "__main__":
    main()

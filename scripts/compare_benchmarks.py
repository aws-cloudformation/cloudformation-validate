#!/usr/bin/env python3
"""Runs benchmarks for every engine × binding and writes a comparison report.

Steady-state distributions are per-template medians of iterations 2..N (the
"warmup-excluded" window).  Throughput uses all timed validate() calls
(iterations 1..N × templates_ok) divided by the aggregate measured wall time.
When N=1 (single iteration), steady state falls back to the first (and only)
sample — there is no discard.

This script can also load per-template detailed JSON reports (--report-only)
produced by each binding harness and validate them for cross-binding
consistency before generating paired engine comparisons.
"""

import argparse
import json
import math
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"

ENGINES = ["rego", "cel"]
FORMATS = ["detailed"]
ALL_BINDINGS = [
    ("native", "Native Rust"),
    ("wasm", "WASM (Node.js)"),
    ("jvm", "JVM (JNI)"),
    ("python", "Python (UniFFI)"),
    ("go", "Go (UniFFI)"),
]
DEFAULT_ITERATIONS = 50
DEFAULT_TEMPLATE_DIR = SRC_DIR / "resources" / "templates"
DEFAULT_TOP_SLOWEST = 10

# median/p99/max: median is the typical cost, p99 the tail, max the worst case.
STATS = ["median", "p99", "max"]

# Rust-internal phase timers surfaced in every binding (apples-to-apples).
PHASE_ROWS = [
    ("model build",         "model_build_ms"),
    ("schema validate",     "schema_validate_ms"),
    ("rule evaluation",     "rule_evaluation_ms"),
    ("diagnostic finalize", "diagnostic_finalize_ms"),
]

# Metrics required in per-template detailed reports (steadyState object).
REQUIRED_STEADY_METRICS = [
    "hostModelMs", "modelBuildMs", "schemaValidateMs",
    "ruleEvaluationMs", "diagnosticFinalizeMs", "engineInternalMs", "wallClockMs",
]

# Paired comparison: ratio threshold for classifying a template as meaningfully
# faster/slower.  A ratio of slower/faster >= this value means the difference is
# practically significant.  Below this threshold the pair is "within noise".
PAIRED_RATIO_THRESHOLD = 1.05

# Below this floor (ms) both engines are trivially fast and ratio-based
# classification is unreliable due to timer granularity.  Such pairs are always
# classified as "within noise" regardless of ratio.
PAIRED_FLOOR_MS = 0.01

# Valid top-level aggregate labels (binding identifiers).
VALID_BINDINGS = {"native", "wasm", "jvm", "python", "go"}

# Valid engine labels.
VALID_ENGINES = {"rego", "cel"}


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run benchmarks for every engine × binding and write a comparison report.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building artifacts (assume they already exist).",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing aggregate files without running benchmarks.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Iterations per template (positive integer, default {DEFAULT_ITERATIONS}).",
    )
    parser.add_argument(
        "--template-dir",
        type=Path,
        default=DEFAULT_TEMPLATE_DIR,
        help="Path to the template corpus directory.",
    )
    parser.add_argument(
        "--bindings",
        nargs="+",
        choices=[b for b, _ in ALL_BINDINGS],
        default=None,
        help="Subset of bindings to benchmark (default: all).",
    )
    parser.add_argument(
        "--engines",
        nargs="+",
        choices=ENGINES,
        default=None,
        help="Subset of engines to benchmark (default: all).",
    )
    parser.add_argument(
        "--top-slowest",
        type=int,
        default=DEFAULT_TOP_SLOWEST,
        help=f"Number of slowest templates to show per engine×binding (positive integer, default {DEFAULT_TOP_SLOWEST}).",
    )
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be a positive integer")
    if args.top_slowest < 1:
        parser.error("--top-slowest must be a positive integer")
    if not args.template_dir.is_dir():
        parser.error(f"--template-dir is not a directory: {args.template_dir}")
    args.template_dir = args.template_dir.resolve()
    return args


# ──────────────────────────────────────────────────────────────────────────────
# Deterministic run-plan: pairs engines per binding, alternates AB/BA
# ──────────────────────────────────────────────────────────────────────────────

def build_run_plan(engines, bindings):
    """Pair selected engines per binding and alternate canonical AB/BA order.

    Alternation is based on each binding's position in ``ALL_BINDINGS``, not its
    position in a filtered subset. Thus WASM remains BA even when it is the only
    selected binding, and repeated subset runs retain the same positional bias
    mitigation as the full run.
    """
    if not engines or not bindings:
        return []

    canonical_positions = {binding: index for index, (binding, _) in enumerate(ALL_BINDINGS)}
    plan = []
    for selected_index, (binding, _label) in enumerate(bindings):
        position = canonical_positions.get(binding, selected_index)
        ordered_engines = engines if position % 2 == 0 else reversed(engines)
        plan.extend((binding, engine) for engine in ordered_engines)
    return plan


# ──────────────────────────────────────────────────────────────────────────────
# Build / Run helpers
# ──────────────────────────────────────────────────────────────────────────────

def run_cmd(cmd, cwd, label):
    print(f"  $ {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, cwd=str(cwd))
    if result.returncode != 0:
        sys.exit(f"{label} failed (exit {result.returncode})")


def build_all(bindings):
    """Build artifacts for the selected bindings using existing build.sh scripts."""
    binding_ids = {b for b, _ in bindings}

    if "native" in binding_ids:
        print("=== Building native Rust (release) ===", file=sys.stderr)
        run_cmd(["cargo", "build", "--locked", "--release", "--workspace"], SRC_DIR, "cargo build")

    if "wasm" in binding_ids:
        print("=== Building WASM package ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-wasm" / "build.sh")],
                SRC_DIR / "bindings-wasm", "WASM build")
        bench_dir = SRC_DIR / "bindings-wasm" / "bench"
        if (bench_dir / "package-lock.json").exists():
            run_cmd(["npm", "ci", "--silent"], bench_dir, "npm ci (bench)")
        else:
            run_cmd(["npm", "install", "--silent"], bench_dir, "npm install (bench)")

    if "jvm" in binding_ids:
        print("=== Building JVM native library + bindings ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-jvm" / "build.sh")],
                SRC_DIR / "bindings-jvm", "JVM build")

    if "python" in binding_ids:
        print("=== Building Python wheel ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-python" / "build.sh")],
                SRC_DIR / "bindings-python", "Python build")
        bench_dir = SRC_DIR / "bindings-python" / "bench"
        bench_dir.mkdir(parents=True, exist_ok=True)
        venv_dir = bench_dir / ".venv"
        if not venv_dir.exists():
            run_cmd(["python3", "-m", "venv", str(venv_dir)], bench_dir, "create bench venv")
        venv_pip = str(venv_dir / "bin" / "pip")
        wheel_dir = SRC_DIR / "bindings-python" / "generated" / "dist"
        wheels = sorted(wheel_dir.glob("*.whl"))
        if not wheels:
            sys.exit(f"No wheel found in {wheel_dir}")
        run_cmd([venv_pip, "install", "--force-reinstall", "--quiet", str(wheels[-1])],
                bench_dir, "install wheel into bench venv")

    if "go" in binding_ids:
        print("=== Building Go native library + bindings ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-go" / "build.sh")],
                SRC_DIR / "bindings-go", "Go build")


def run_benchmark(binding, engine, iterations, template_dir):
    print(f"=== {binding} benchmark (engine={engine}) ===", file=sys.stderr)
    if binding == "native":
        bench_bin = SRC_DIR / "target" / "release" / "cfn-benchmark"
        if not bench_bin.exists():
            sys.exit(f"cfn-benchmark not found at {bench_bin}")
        run_cmd([str(bench_bin), str(template_dir), "--engine", engine,
                 "--iterations", str(iterations)], SRC_DIR, "native benchmark")
    elif binding == "wasm":
        run_cmd(["npx", "ts-node", "benchmark.ts", str(template_dir), "--engine", engine,
                 "--iterations", str(iterations)],
                SRC_DIR / "bindings-wasm" / "bench", "wasm benchmark")
    elif binding == "jvm":
        bench_dir = SRC_DIR / "bindings-jvm" / "bench"
        gradle = str(bench_dir / "gradlew") if (bench_dir / "gradlew").exists() else "gradle"
        run_cmd([gradle, "run", "--no-daemon",
                 f"--args={template_dir} --engine {engine} --iterations {iterations}"],
                bench_dir, "jvm benchmark")
    elif binding == "python":
        bench_dir = SRC_DIR / "bindings-python" / "bench"
        venv_python = str(bench_dir / ".venv" / "bin" / "python")
        bench_script = str(bench_dir / "benchmark.py")
        if not Path(bench_script).exists():
            sys.exit(f"Python benchmark script not found at {bench_script}")
        run_cmd([venv_python, bench_script, str(template_dir), "--engine", engine,
                 "--iterations", str(iterations)],
                bench_dir, "python benchmark")
    elif binding == "go":
        run_cmd(["go", "run", ".", str(template_dir), "--engine", engine,
                 "--iterations", str(iterations)],
                SRC_DIR / "bindings-go" / "bench", "go benchmark")
    else:
        sys.exit(f"unknown binding: {binding}")


# ──────────────────────────────────────────────────────────────────────────────
# Aggregate loading and validation
# ──────────────────────────────────────────────────────────────────────────────

def aggregate_path(engine, fmt, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / f"aggregate_{fmt}.json"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / f"aggregate_{fmt}.json"


def _is_finite_number(val):
    """True if val is a finite int or float, excluding booleans."""
    if isinstance(val, bool):
        return False
    if not isinstance(val, (int, float)):
        return False
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return False
    return True


def _validate_aggregate_structure(data, path):
    """Validate top-level structure of an aggregate JSON file.

    Checks:
    - Root must be a dict (not list, null, scalar).
    - Must have nonempty string 'binding' in VALID_BINDINGS.
    - Must have nonempty string 'engine' in VALID_ENGINES.
    - Must have 'templates_total' as a finite non-bool integer >= 0.
    - Must have 'templates_ok' as a finite non-bool integer >= 0.
    - Must have 'corpus_fingerprint' as a nonempty string.
    """
    if not isinstance(data, dict):
        sys.exit(f"aggregate {path}: root is not a JSON object (got {type(data).__name__})")

    binding = data.get("binding")
    if not isinstance(binding, str) or not binding:
        sys.exit(f"aggregate {path}: missing or empty 'binding'")
    if binding not in VALID_BINDINGS:
        sys.exit(f"aggregate {path}: binding='{binding}' not in {sorted(VALID_BINDINGS)}")

    engine = data.get("engine")
    if not isinstance(engine, str) or not engine:
        sys.exit(f"aggregate {path}: missing or empty 'engine'")
    if engine not in VALID_ENGINES:
        sys.exit(f"aggregate {path}: engine='{engine}' not in {sorted(VALID_ENGINES)}")

    for field in ("templates_total", "templates_ok"):
        val = data.get(field)
        if not _is_finite_number(val) or not isinstance(val, int) or val < 0:
            sys.exit(
                f"aggregate {path}: '{field}' must be a non-negative integer "
                f"(got {val!r})"
            )

    fp = data.get("corpus_fingerprint")
    if not isinstance(fp, str) or not fp:
        sys.exit(f"aggregate {path}: missing or empty 'corpus_fingerprint'")


def load_aggregate(path, run_start_epoch):
    if not path.exists():
        sys.exit(f"expected aggregate not found: {path}")
    if run_start_epoch > 0:
        mtime = path.stat().st_mtime
        if mtime < run_start_epoch - 1:
            sys.exit(f"stale aggregate {path} (mtime={mtime} < run_start={run_start_epoch})")
    with open(path) as f:
        data = json.load(f)
    _validate_aggregate_structure(data, path)
    return data


def enforce_corpus_parity(all_loaded, bindings):
    """Every binding of every engine must have scanned the same bytes."""
    fps = {}
    for engine, by_binding in all_loaded.items():
        for binding, agg in by_binding.items():
            fp = agg.get("corpus_fingerprint")
            if not fp:
                sys.exit(f"{engine}/{binding}: aggregate missing corpus_fingerprint. "
                         f"Rebuild + rerun benchmarks against current harness.")
            fps.setdefault(fp, []).append(f"{engine}/{binding}")
    if len(fps) > 1:
        lines = [f"  {fp}: {', '.join(who)}" for fp, who in fps.items()]
        sys.exit("corpus fingerprint mismatch across bindings - cannot compare:\n"
                 + "\n".join(lines))


def enforce_run_metadata_parity(all_loaded, bindings):
    """Every selected run must agree on iteration count, detail level, corpus totals,
    and failure lists."""
    reference_key = None
    reference_meta = None
    for engine, by_binding in all_loaded.items():
        for binding, agg in by_binding.items():
            meta = {
                "iterations_per_template": agg.get("iterations_per_template"),
                "detail_level": agg.get("detail_level"),
                "corpus_fingerprint": agg.get("corpus_fingerprint"),
                "templates_total": agg.get("templates_total"),
                "templates_ok": agg.get("templates_ok"),
                "templates_failed": agg.get("templates_failed"),
                "failures": sorted(
                    [(f.get("file"), f.get("status")) for f in (agg.get("failures") or [])],
                ),
            }
            key = f"{engine}/{binding}"
            if reference_meta is None:
                reference_meta = meta
                reference_key = key
            elif meta != reference_meta:
                diffs = []
                for field in meta:
                    if meta[field] != reference_meta[field]:
                        diffs.append(
                            f"  {field}: {reference_key}={reference_meta[field]!r}, "
                            f"{key}={meta[field]!r}"
                        )
                sys.exit(
                    f"run metadata mismatch between {reference_key} and {key} "
                    f"- cannot compare:\n" + "\n".join(diffs)
                )


# ──────────────────────────────────────────────────────────────────────────────
# Per-template detailed report loading and validation
# ──────────────────────────────────────────────────────────────────────────────

def _per_template_dir(engine, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / "json_detailed"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / "json_detailed"


def load_and_validate_detailed_reports(engines, bindings):
    """Load per-template detailed JSON reports for all engine×binding pairs.

    Each report is loaded exactly once and indexed by filePath.  Validation rules:
    1. Directory must exist and be nonempty.
    2. Root must be a JSON object with engine/binding labels matching the expected pair.
    3. filePath must be a nonempty string, unique within each engine×binding directory.
    4. steadyState must contain all REQUIRED_STEADY_METRICS as finite numeric
       (non-bool) values.
    5. Template path sets must be identical across all engine×binding pairs.

    Returns: dict[engine][binding] -> dict[filePath -> report_data] or exits on error.
    """
    all_detailed = {}
    all_path_sets = {}
    errors = []

    for engine in engines:
        all_detailed[engine] = {}
        for binding, label in bindings:
            d = _per_template_dir(engine, binding)
            key = f"{engine}/{label}"

            # Rule 1: nonempty directory
            if not d.exists() or not d.is_dir():
                errors.append(f"{key}: directory missing — {d}")
                continue
            json_files = sorted(d.glob("*.json"))
            if not json_files:
                errors.append(f"{key}: directory empty — {d}")
                continue

            reports = {}
            seen_paths = set()
            for json_file in json_files:
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    errors.append(f"{key}: failed to read {json_file.name}: {e}")
                    continue

                # Rule 2: must be a dict with correct engine/binding labels
                if not isinstance(data, dict):
                    errors.append(
                        f"{key}: {json_file.name} root is not a JSON object"
                    )
                    continue

                file_engine = data.get("engine", "")
                file_binding = data.get("binding", "")
                if file_engine != engine:
                    errors.append(
                        f"{key}: {json_file.name} engine='{file_engine}' expected '{engine}'"
                    )
                if file_binding != binding:
                    errors.append(
                        f"{key}: {json_file.name} binding='{file_binding}' expected '{binding}'"
                    )

                # Rule 3: unique nonempty string filePath
                file_path = data.get("filePath")
                if not isinstance(file_path, str) or not file_path:
                    errors.append(f"{key}: {json_file.name} has empty/missing/non-string filePath")
                    continue
                if file_path in seen_paths:
                    errors.append(f"{key}: duplicate filePath '{file_path}' in {json_file.name}")
                    continue
                seen_paths.add(file_path)

                # Rule 4: finite numeric (non-bool) required steady metrics
                metrics = data.get("benchmarkMetrics", {})
                steady = metrics.get("steadyState", {}) if isinstance(metrics, dict) else {}
                for metric_name in REQUIRED_STEADY_METRICS:
                    val = steady.get(metric_name)
                    if not _is_finite_number(val):
                        errors.append(
                            f"{key}: {json_file.name} steadyState.{metric_name} "
                            f"is not a finite number (got {val!r})"
                        )

                diagnostics = data.get("diagnostics")
                if not isinstance(diagnostics, list) or not all(
                    isinstance(diagnostic, dict) for diagnostic in diagnostics
                ):
                    errors.append(
                        f"{key}: {json_file.name} diagnostics must be an array of objects"
                    )

                reports[file_path] = data

            all_detailed[engine][binding] = reports
            all_path_sets[key] = set(reports.keys())

    if errors:
        sys.exit(
            "Detailed report validation failed:\n" +
            "\n".join(f"  • {e}" for e in errors[:30]) +
            (f"\n  … and {len(errors) - 30} more" if len(errors) > 30 else "")
        )

    # Rule 5: identical template path sets across all pairs
    if all_path_sets:
        path_sets_list = list(all_path_sets.items())
        ref_key, ref_set = path_sets_list[0]
        mismatches = []
        for other_key, other_set in path_sets_list[1:]:
            if other_set != ref_set:
                only_in_ref = ref_set - other_set
                only_in_other = other_set - ref_set
                parts = []
                if only_in_ref:
                    parts.append(f"only in {ref_key}: {sorted(only_in_ref)[:5]}")
                if only_in_other:
                    parts.append(f"only in {other_key}: {sorted(only_in_other)[:5]}")
                mismatches.append(f"  {other_key} vs {ref_key}: {'; '.join(parts)}")
        if mismatches:
            sys.exit(
                "Template path sets differ across engine×binding pairs:\n" +
                "\n".join(mismatches[:10])
            )

    return all_detailed


def validate_detailed_counts(all_detailed, all_loaded, engines, bindings):
    """Detailed file count must equal aggregate templates_total.

    templates_total includes all corpus reports (successful validations AND parse
    failures), not just templates_ok.  Every template that was attempted gets a
    per-template report regardless of whether parsing succeeded.
    """
    errors = []
    for engine in engines:
        for binding, label in bindings:
            agg = all_loaded[engine][binding]
            expected_count = agg.get("templates_total", 0)
            actual_count = len(all_detailed.get(engine, {}).get(binding, {}))
            if actual_count != expected_count:
                errors.append(
                    f"{engine}/{label}: detailed has {actual_count} reports, "
                    f"aggregate says templates_total={expected_count}"
                )
    if errors:
        sys.exit(
            "Detailed count vs aggregate templates_total mismatch:\n" +
            "\n".join(f"  • {e}" for e in errors)
        )


# ──────────────────────────────────────────────────────────────────────────────
# Statistics helpers
# ──────────────────────────────────────────────────────────────────────────────

PCT_FLOOR_MS = 0.01


def stat(stats_dict, key):
    """Return (value, present). Present=False means the key was absent."""
    if isinstance(stats_dict, dict) and key in stats_dict:
        return float(stats_dict[key]), True
    return 0.0, False


def ms(val, present=True, digits=4):
    return f"{val:.{digits}f}" if present else "-"


def pct(base, base_present, v, v_present):
    if not (base_present and v_present) or base < PCT_FLOOR_MS:
        return "-"
    p = ((v - base) / base) * 100
    return f"{'+' if p >= 0 else ''}{p:.1f}%"


def get(d, *path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def table(header, rows):
    return (["| " + " | ".join(header) + " |",
             "|" + "|".join(["---"] * len(header)) + "|"]
            + ["| " + " | ".join(r) + " |" for r in rows])


def recomputed_throughput(agg):
    """(ok × iterations) / (wall_ms / 1000). Use measured_validation_wall_ms if
    present (newer harness), fall back to total_wall_ms (older reports)."""
    wall = get(agg, "performance", "measured_validation_wall_ms", default=None)
    if wall is None or wall <= 0:
        wall = get(agg, "performance", "total_wall_ms", default=0.0) or 0.0
    iters = int(agg.get("iterations_per_template", 0) or 0)
    ok = int(agg.get("templates_ok", 0) or 0)
    if wall <= 0 or iters <= 0 or ok <= 0:
        return 0.0
    return (ok * iters) / (wall / 1000.0)


def stat_cols(d, stats=STATS):
    """Render one metric's median/p99/max cells from a stats dict."""
    return [ms(*stat(d, s)) for s in stats]


# ──────────────────────────────────────────────────────────────────────────────
# Paired 5% classification helper
# ──────────────────────────────────────────────────────────────────────────────

def classify_paired(rego_wall, cel_wall):
    """Classify a paired Rego/CEL comparison for one template.

    Uses a ratio-based threshold: slower / faster >= PAIRED_RATIO_THRESHOLD means
    the difference is practically significant.  Below PAIRED_FLOOR_MS both values
    are trivially fast and classified as noise regardless of ratio.

    Returns one of: "rego_faster", "cel_faster", "within_noise".
    """
    faster = min(rego_wall, cel_wall)
    slower = max(rego_wall, cel_wall)

    # Both below floor: timer granularity dominates
    if slower < PAIRED_FLOOR_MS:
        return "within_noise"

    # Avoid division by zero when faster == 0 but slower > floor
    if faster <= 0:
        # One is zero, the other is above floor → the nonzero one is slower
        if rego_wall < cel_wall:
            return "rego_faster"
        elif cel_wall < rego_wall:
            return "cel_faster"
        return "within_noise"

    ratio = slower / faster
    if ratio >= PAIRED_RATIO_THRESHOLD:
        if rego_wall < cel_wall:
            return "rego_faster"
        else:
            return "cel_faster"

    return "within_noise"


# ──────────────────────────────────────────────────────────────────────────────
# Top-N slowest tables (per engine × binding)
# ──────────────────────────────────────────────────────────────────────────────

def top_slowest_section(all_detailed, engines, bindings, top_n):
    """Generate top-N slowest template tables for each engine × binding.

    Each table shows wall, rule, schema, and model steady-state metrics,
    sorted descending by steady-state wallClockMs.

    This section is mandatory when detailed reports are available.  Missing or
    empty report data for any selected pair is a hard error.
    """
    # Validate that all selected pairs have data
    missing = []
    for engine in engines:
        for binding, label in bindings:
            reports = all_detailed.get(engine, {}).get(binding, {})
            if not reports:
                missing.append(f"{engine}/{label}")
    if missing:
        sys.exit(
            f"top-slowest section requires valid detailed reports for all selected "
            f"pairs, but these are missing/empty: {', '.join(missing)}"
        )

    lines = [
        f"## Top-{top_n} Slowest Templates (steady-state wall clock)", "",
        "Per engine × binding: templates with the highest steady-state "
        "`wallClockMs` (median of iterations 2..N; N=1 uses the single sample). "
        "Columns: wall (total validate), rule (rule evaluation), schema "
        "(schema validation), model (model build) — all in milliseconds.", "",
    ]

    for engine in engines:
        lines.append(f"### {engine.upper()}")
        lines.append("")
        for binding, label in bindings:
            reports = all_detailed[engine][binding]

            # Extract steady-state metrics per template
            template_metrics = []
            for file_path, data in reports.items():
                steady = get(data, "benchmarkMetrics", "steadyState", default={})
                wall = steady.get("wallClockMs", 0.0)
                rule = steady.get("ruleEvaluationMs", 0.0)
                schema = steady.get("schemaValidateMs", 0.0)
                model = steady.get("modelBuildMs", 0.0)
                template_metrics.append((file_path, wall, rule, schema, model))

            # Sort descending by wall clock, take top N
            template_metrics.sort(key=lambda x: x[1], reverse=True)
            top = template_metrics[:top_n]

            header = ["#", "Template", "Wall (ms)", "Rule (ms)", "Schema (ms)", "Model (ms)"]
            rows = []
            for i, (fp, wall, rule, schema, model) in enumerate(top, 1):
                # Truncate long paths for display
                display_path = fp if len(fp) <= 60 else "…" + fp[-57:]
                rows.append([
                    str(i), display_path,
                    f"{wall:.4f}", f"{rule:.4f}", f"{schema:.4f}", f"{model:.4f}",
                ])

            lines.append(f"**{label}**")
            lines.append("")
            lines += table(header, rows)
            lines.append("")

    return lines


# ──────────────────────────────────────────────────────────────────────────────
# Paired Rego-vs-CEL comparison per binding
# ──────────────────────────────────────────────────────────────────────────────

def paired_engine_comparison(all_detailed, bindings):
    """Paired Rego-vs-CEL analysis per binding.

    For each binding, computes:
    - Representative corpus-pass sums (sum of per-template steady-state wallClockMs
      medians — a representative total, not a measured elapsed time or throughput).
    - Clear direction ratios (Rego/CEL and CEL/Rego)
    - Ratio-based 5% practical threshold counts (templates where slower/faster ≥ 1.05)
    - Rule evaluation comparison
    - Largest paired deltas (templates with biggest absolute difference)

    Note on corpus-pass sums vs throughput: the corpus-pass sum is the sum of
    per-template medians.  It represents typical per-template cost aggregated
    across the corpus but is NOT the same as measured elapsed time or throughput.
    Tail outliers (high p99/max) can make throughput figures close even when
    typical (median) costs differ noticeably between engines.
    """
    if "rego" not in all_detailed or "cel" not in all_detailed:
        return ["## Paired Engine Comparison (Rego vs CEL)", "",
                "_Requires both rego and cel engines to be present._", ""]

    lines = [
        "## Paired Engine Comparison (Rego vs CEL)", "",
        "Per-binding paired analysis using steady-state per-template metrics. "
        "Each template is compared across engines using the same binding, so "
        "differences reflect engine behavior rather than binding overhead.", "",
        "**Metric definitions:**", "",
        "- **Corpus-pass sum**: representative sum of per-template steady-state "
        "`wallClockMs` medians across all templates — the total typical validation "
        "work for one full corpus pass. This is a sum of medians, not a measured "
        "elapsed time or throughput. Tail outliers (high p99/max) can make "
        "throughput figures close even when typical (median) per-template costs "
        "differ noticeably between engines.",
        "- **Direction ratio**: `sum(Rego steady wall) / sum(CEL steady wall)` — "
        "values >1.0 mean Rego is slower overall.",
        f"- **{int((PAIRED_RATIO_THRESHOLD - 1) * 100)}% threshold**: count of templates where "
        f"`slower / faster ≥ {PAIRED_RATIO_THRESHOLD}` (ratio-based practical significance "
        f"threshold). Templates where both engines are below {PAIRED_FLOOR_MS} ms "
        "are always classified as noise regardless of ratio (timer granularity "
        "dominates at trivially-fast latencies).",
        "- **Rule comparison**: ratio of `ruleEvaluationMs` sums — isolates the "
        "pure rule-engine cost from shared model/schema work.", "",
    ]

    for binding, label in bindings:
        rego_reports = all_detailed.get("rego", {}).get(binding, {})
        cel_reports = all_detailed.get("cel", {}).get(binding, {})
        if not rego_reports or not cel_reports:
            continue

        # Only compare templates present in both
        common_paths = set(rego_reports.keys()) & set(cel_reports.keys())
        if not common_paths:
            continue

        rego_wall_sum = 0.0
        cel_wall_sum = 0.0
        rego_rule_sum = 0.0
        cel_rule_sum = 0.0
        rego_faster_5pct = 0
        cel_faster_5pct = 0
        within_noise = 0
        deltas = []  # (path, rego_wall, cel_wall, abs_diff, direction)

        for fp in sorted(common_paths):
            rego_steady = get(rego_reports[fp], "benchmarkMetrics", "steadyState", default={})
            cel_steady = get(cel_reports[fp], "benchmarkMetrics", "steadyState", default={})

            rw = rego_steady.get("wallClockMs", 0.0)
            cw = cel_steady.get("wallClockMs", 0.0)
            rr = rego_steady.get("ruleEvaluationMs", 0.0)
            cr = cel_steady.get("ruleEvaluationMs", 0.0)

            rego_wall_sum += rw
            cel_wall_sum += cw
            rego_rule_sum += rr
            cel_rule_sum += cr

            # Ratio-based 5% threshold classification
            classification = classify_paired(rw, cw)
            if classification == "rego_faster":
                rego_faster_5pct += 1
            elif classification == "cel_faster":
                cel_faster_5pct += 1
            else:
                within_noise += 1

            abs_diff = abs(rw - cw)
            direction = "Rego faster" if rw < cw else "CEL faster" if cw < rw else "equal"
            deltas.append((fp, rw, cw, abs_diff, direction))

        # Sort by absolute delta descending for largest paired deltas
        deltas.sort(key=lambda x: x[3], reverse=True)

        # Compute ratios
        direction_ratio = (rego_wall_sum / cel_wall_sum) if cel_wall_sum > 0 else float("inf")
        rule_ratio = (rego_rule_sum / cel_rule_sum) if cel_rule_sum > 0 else float("inf")

        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"**Templates compared:** {len(common_paths)}")
        lines.append("")

        summary_header = ["Metric", "Value"]
        summary_rows = [
            ["Rego corpus-pass sum (ms)", f"{rego_wall_sum:.2f}"],
            ["CEL corpus-pass sum (ms)", f"{cel_wall_sum:.2f}"],
            ["Direction ratio (Rego/CEL)", f"{direction_ratio:.4f}"],
            ["Rego rule sum (ms)", f"{rego_rule_sum:.2f}"],
            ["CEL rule sum (ms)", f"{cel_rule_sum:.2f}"],
            ["Rule ratio (Rego/CEL)", f"{rule_ratio:.4f}"],
            ["Rego faster by ≥5%", str(rego_faster_5pct)],
            ["CEL faster by ≥5%", str(cel_faster_5pct)],
            ["Within 5% (practical parity)", str(within_noise)],
        ]
        lines += table(summary_header, summary_rows)
        lines.append("")

        # Top-5 largest paired deltas
        top_deltas = deltas[:5]
        if top_deltas:
            lines.append("**Largest paired deltas (top 5):**")
            lines.append("")
            delta_header = ["Template", "Rego (ms)", "CEL (ms)", "Δ (ms)", "Direction"]
            delta_rows = []
            for fp, rw, cw, diff, direction in top_deltas:
                display_path = fp if len(fp) <= 50 else "…" + fp[-47:]
                delta_rows.append([
                    display_path,
                    f"{rw:.4f}", f"{cw:.4f}", f"{diff:.4f}", direction,
                ])
            lines += table(delta_header, delta_rows)
            lines.append("")

    return lines


# ──────────────────────────────────────────────────────────────────────────────
# Report sections (aggregate-based, same as original)
# ──────────────────────────────────────────────────────────────────────────────

def _first_steady_tables(all_loaded, engine, key_prefix, bindings):
    """First-measured/steady-state tables for a single engine (per-template phases)."""
    def build(mode, mode_key):
        header = ["Binding"] + [s for s in STATS]
        rows = []
        for b, lbl in bindings:
            d = get(all_loaded[engine][b], "performance", f"{mode_key}_{key_prefix}_ms", default={})
            rows.append([lbl] + stat_cols(d))
        return table(header, rows)

    lines = [
        "**First measured (after harness warmup)** - first per-template sample (ms)", "",
    ]
    lines += build("first", "cold")
    lines += [
        "",
        "**Steady state** - subsequent iterations per template (ms)", "",
    ]
    lines += build("steady", "warm")
    lines += [""]
    return lines


def _cold_warm_tables_init(all_loaded, engine, bindings):
    header = ["Binding"] + [s for s in STATS]
    warm_rows = []
    for b, lbl in bindings:
        d = get(all_loaded[engine][b], "performance", "warm_init_ms", default={})
        warm_rows.append([lbl] + stat_cols(d))
    return table(header, warm_rows)


def headline_section(all_loaded, engine, bindings):
    """Validation = full validate() call for one engine."""
    lines = ["### Validation - full `validate()` call (wall_clock per template, ms)", "",
             "Host-timer around the full `validate()` call - the latency a consumer sees.", ""]
    lines += _first_steady_tables(all_loaded, engine, "wall_clock", bindings)
    header = ["Binding", "Throughput (val/sec)"]
    rows = []
    for b, lbl in bindings:
        rows.append([lbl, ms(recomputed_throughput(all_loaded[engine][b]), True, 2)])
    lines += ["**Throughput** (recomputed = ok × iterations / wall_time)", ""]
    lines += table(header, rows) + [""]
    return lines


def executive_summary(all_loaded, engines, bindings):
    """Top-of-report one-glance table per engine."""
    lines = ["## Executive Summary - p99 per phase (ms)", "",
            "One-glance view. **Init** shows the cold (first) construction cost - paid once "
            "per process; includes WASM module instantiation / JNI library load / Python "
            "cdylib FFI load for non-native bindings (Go is statically linked: "
            "module_load_ms = 0). **Model** and **Validate** show steady-state "
            "p99 - the consumer-visible latency after the global harness warmup. "
            "Steady state is the median of iterations 2..N; when N=1 it falls "
            "back to the sole first-measured sample. "
            "Detailed breakdowns are in the per-engine sections below.", ""]
    header = ["Binding", "Module Load (ms)", "Init cold (ms)", "Model steady p99 (ms)",
              "Validate steady p99 (ms)", "Throughput"]
    for engine in engines:
        rows = []
        for b, lbl in bindings:
            agg = all_loaded[engine][b]
            mod_load = get(agg, "performance", "module_load_ms", default=0.0)
            init_cold = get(agg, "performance", "cold_init_ms")
            model = get(agg, "performance", "warm_host_model_ms", default={})
            validate = get(agg, "performance", "warm_wall_clock_ms", default={})
            rows.append([
                lbl,
                ms(mod_load or 0.0),
                ms(init_cold or 0.0, init_cold is not None),
                ms(*stat(model, "p99")),
                ms(*stat(validate, "p99")),
                ms(recomputed_throughput(agg), True, 2),
            ])
        lines += [f"### {engine.upper()}", ""] + table(header, rows) + [""]
    return lines


def model_section(all_loaded, engine, bindings):
    """Template modeling for one engine."""
    lines = ["### Template Modeling - host-timed `SemanticModel::parse` (ms)", "",
             "Host timer around `SemanticModel::parse` (bytes → resolved model). "
             "Standalone measurement; does not include the re-parse inside `validate()`.", ""]
    lines += _first_steady_tables(all_loaded, engine, "host_model", bindings)
    return lines


def init_section(all_loaded, engine, bindings):
    """Initialization for one engine."""
    cold_header = ["Binding", "Module Load (ms)", "Cold init_ms (ms)"]
    component_header = ["Binding", "Schema median", "Schema p99", "Engine median", "Engine p99"]

    lines = ["### Initialization - consumer-visible setup cost (ms)", "",
             "**init_ms** is the actual validation setup a consumer constructs before "
             "calling `validate()`. What it measures differs by binding:", "",
             "- **Native:** standalone `SchemaValidator` construction + standalone engine "
             "construction (two separate objects the consumer creates).",
             "- **FFI bindings (WASM / JVM / Python / Go):** engine constructor only - "
             "the FFI engine constructors already embed schema initialization internally, "
             "so `init_ms` is the single engine constructor call the consumer makes.", "",
             "**Module Load** is the one-time cost of loading the native library (JNI / "
             "Python cdylib) or WASM module (V8 compile + `#[start]`). Native = 0; "
             "Go = 0 (statically linked via cgo, no dynamic module load). "
             "**Cold** = module load + first `init_ms` - the total first-use cost a "
             "consumer pays. **Warm** = subsequent constructions.", "",
             "**Component timing** below shows `schema_init_ms` and `engine_init_ms` as "
             "standalone component measurements. For FFI bindings, `schema_init_ms` is "
             "already embedded inside `engine_init_ms` - these are independent timers, "
             "not additive components of `init_ms`.", ""]

    cold_rows = []
    warm_rows = []
    component_rows = []
    for b, lbl in bindings:
        agg = all_loaded[engine][b]
        mod_v = get(agg, "performance", "module_load_ms", default=0.0)
        cold_v = get(agg, "performance", "cold_init_ms")
        cold_rows.append([lbl, ms(mod_v or 0.0), ms(cold_v or 0.0, cold_v is not None)])
        warm = get(agg, "performance", "warm_init_ms", default={})
        warm_rows.append([lbl] + stat_cols(warm))
        si = get(agg, "performance", "schema_init_ms", default={})
        ei = get(agg, "performance", "engine_init_ms", default={})
        component_rows.append([
            lbl,
            ms(*stat(si, "median")), ms(*stat(si, "p99")),
            ms(*stat(ei, "median")), ms(*stat(ei, "p99")),
        ])
    lines += ["**Cold** - first construction (ms)", ""] + table(cold_header, cold_rows)
    warm_header = ["Binding"] + [s for s in STATS]
    lines += ["", "**Warm** - subsequent constructions (ms)", ""] + table(warm_header, warm_rows)
    lines += ["", "**Component timing** - schema_init_ms / engine_init_ms (ms)", "",
              "Standalone component measurements. For native, these are the two separate "
              "objects the consumer constructs. For FFI bindings, schema is already embedded "
              "in the engine constructor - `schema_init_ms` must not be added to "
              "`engine_init_ms`.", ""]
    lines += table(component_header, component_rows)
    lines += [""]
    return lines


def phase_table(all_loaded, engine, bindings):
    """Per-engine sub-phase breakdown."""
    lines = ["### Sub-phases (per-template medians across iterations, ms)", ""]
    header = ["Phase"]
    for _, lbl in bindings:
        header += [f"{lbl} {s}" for s in STATS]
    rows = []
    for label, key in [("engine_internal (total)", "engine_internal_ms"),
                       ("wall_clock (total)",      "wall_clock_ms")] + PHASE_ROWS:
        row = [label]
        for b, _ in bindings:
            d = get(all_loaded[engine][b], "performance", key, default={})
            row += stat_cols(d)
        rows.append(row)
    return lines + table(header, rows) + [""]


def overhead_table(all_loaded, engine, bindings):
    """Binding overhead = wall_clock − engine_internal per iteration."""
    header = ["Binding"] + list(STATS)
    rows = []
    for b, lbl in bindings:
        d = get(all_loaded[engine][b], "performance", "binding_overhead_ms", default={})
        if d:
            rows.append([lbl] + stat_cols(d))
    if not rows:
        return []
    return ["### Binding overhead (wall_clock − engine_internal, ms)", "",
            "Median of per-call differences (`wall_clock_i − engine_internal_i` for each "
            "iteration). Native ≈ 0.", ""] \
        + table(header, rows) + [""]


def _diag_sort_key(d):
    """Stable ordering for pairing diagnostics between binding outputs."""
    entity = d.get("entity") or {}
    return (
        d.get("ruleId") or "",
        d.get("startLine") or 0,
        d.get("startColumn") or 0,
        d.get("endLine") or 0,
        d.get("endColumn") or 0,
        entity.get("logicalId") or "",
        d.get("propertyPath") or "",
        d.get("message") or "",
    )


def _field_diff(a, b):
    """Return {field: (a_val, b_val)} for every top-level field that differs."""
    keys = set(a.keys()) | set(b.keys())
    return {k: (a.get(k, "<missing>"), b.get(k, "<missing>")) for k in keys if a.get(k) != b.get(k)}


def diagnostics_parity(all_loaded, engine, bindings, all_detailed=None):
    """Full parity check across all binding pairs.

    If all_detailed is provided (already loaded per-template reports keyed by
    filePath), diagnostics are read from there without re-opening files.
    Otherwise falls back to reading from disk.

    Returns (lines, passed).
    """
    labels = {bid: lbl for bid, lbl in bindings}
    levels = ["total_fatal", "total_errors", "total_warnings", "total_informational"]
    total_mismatches = []
    for lvl in levels:
        vals = {b: get(all_loaded[engine][b], "diagnostics", lvl) for b, _ in bindings}
        if len({v for v in vals.values() if v is not None}) > 1:
            total_mismatches.append((lvl, vals))

    pairs = [(a, b) for i, (a, _) in enumerate(bindings) for (b, _) in bindings[i + 1:]]
    per_pair_diffs = {pair: [] for pair in pairs}
    field_freq = {}
    template_count = 0

    # Use pre-loaded detailed reports if available
    if all_detailed and engine in all_detailed:
        # Consume from all_detailed by filePath
        engine_detailed = all_detailed[engine]
        # Get the union of all filePaths across bindings
        all_paths = set()
        for binding, _ in bindings:
            if binding in engine_detailed:
                all_paths.update(engine_detailed[binding].keys())
        templates = sorted(all_paths)
        template_count = len(templates)

        for fp in templates:
            loaded = {}
            for b, _ in bindings:
                report = engine_detailed.get(b, {}).get(fp)
                if report is None:
                    loaded[b] = ("missing", None)
                else:
                    loaded[b] = ("ok", report.get("diagnostics", []))

            for (a, b) in pairs:
                sa, da = loaded[a]
                sb, db = loaded[b]
                if sa != "ok" or sb != "ok":
                    reason = f"{a}={sa if sa != 'ok' else 'ok'}, {b}={sb if sb != 'ok' else 'ok'}"
                    per_pair_diffs[(a, b)].append((fp, reason, []))
                    continue
                da_sorted = sorted(da, key=_diag_sort_key)
                db_sorted = sorted(db, key=_diag_sort_key)
                if len(da_sorted) != len(db_sorted):
                    per_pair_diffs[(a, b)].append((fp,
                        f"count differs: {a}={len(da_sorted)}, {b}={len(db_sorted)}", []))
                    continue
                examples = []
                for nd, od in zip(da_sorted, db_sorted):
                    if nd != od:
                        fdiff = _field_diff(nd, od)
                        examples.append((nd, od, fdiff))
                        for fname, (nv, ov) in fdiff.items():
                            key = (a, b, fname)
                            if key not in field_freq:
                                field_freq[key] = [0, nv, ov]
                            field_freq[key][0] += 1
                if examples:
                    per_pair_diffs[(a, b)].append((fp,
                        f"{len(examples)}/{len(da_sorted)} diagnostics have field-level differences",
                        examples))
    else:
        # Fallback: read from disk
        dirs = {b: _per_template_dir(engine, b) for b, _ in bindings}

        missing_dirs = []
        for b, lbl in bindings:
            d = dirs[b]
            if not d.exists():
                missing_dirs.append(f"{lbl} ({b}): directory missing - {d}")
            elif not any(d.glob("*.json")):
                missing_dirs.append(f"{lbl} ({b}): directory empty - {d}")

        if missing_dirs:
            lines = [
                f"**{engine.upper()} diagnostic parity:** ❌ FAILED - missing/empty report dirs:",
                "",
            ]
            for msg in missing_dirs:
                lines.append(f"- {msg}")
            lines.append("")
            lines.append(
                "Per-template comparison cannot proceed without complete report data "
                "for all bindings. Rebuild the missing binding(s) and rerun."
            )
            lines.append("")
            return lines, False

        all_templates = set()
        for d in dirs.values():
            if d.exists():
                all_templates.update(p.name for p in d.glob("*.json"))
        templates = sorted(all_templates)
        template_count = len(templates)

        for tpl in templates:
            loaded = {}
            for b, d in dirs.items():
                p = d / tpl
                if not p.exists():
                    loaded[b] = ("missing", None)
                    continue
                try:
                    with open(p) as f:
                        loaded[b] = ("ok", json.load(f).get("diagnostics", []))
                except Exception as e:
                    loaded[b] = (f"read error: {e}", None)

            for (a, b) in pairs:
                sa, da = loaded[a]
                sb, db = loaded[b]
                if sa != "ok" or sb != "ok":
                    reason = f"{a}={sa if sa != 'ok' else 'ok'}, {b}={sb if sb != 'ok' else 'ok'}"
                    per_pair_diffs[(a, b)].append((tpl, reason, []))
                    continue
                da_sorted = sorted(da, key=_diag_sort_key)
                db_sorted = sorted(db, key=_diag_sort_key)
                if len(da_sorted) != len(db_sorted):
                    per_pair_diffs[(a, b)].append((tpl,
                        f"count differs: {a}={len(da_sorted)}, {b}={len(db_sorted)}", []))
                    continue
                examples = []
                for nd, od in zip(da_sorted, db_sorted):
                    if nd != od:
                        fdiff = _field_diff(nd, od)
                        examples.append((nd, od, fdiff))
                        for fname, (nv, ov) in fdiff.items():
                            key = (a, b, fname)
                            if key not in field_freq:
                                field_freq[key] = [0, nv, ov]
                            field_freq[key][0] += 1
                if examples:
                    per_pair_diffs[(a, b)].append((tpl,
                        f"{len(examples)}/{len(da_sorted)} diagnostics have field-level differences",
                        examples))

    totals = get(all_loaded[engine][bindings[0][0]], "diagnostics", default={})
    counts = " / ".join(f"{lvl.replace('total_', '')}={totals.get(lvl, '-')}" for lvl in levels)

    any_diffs = total_mismatches or any(per_pair_diffs.values())
    if not any_diffs:
        return [
            f"**{engine.upper()} diagnostic parity:** ✅ identical across all "
            f"{len(bindings)} bindings "
            f"(aggregate {counts}; {template_count} templates compared field-by-field "
            f"across {len(pairs)} binding pair(s))",
            "",
        ], True

    lines = [f"**{engine.upper()} diagnostic parity:** ❌ MISMATCH - parity bug:", ""]
    if total_mismatches:
        lines.append("**Aggregate totals differ:**")
        for lvl, vals in total_mismatches:
            lines.append(f"- `{lvl}`: " + ", ".join(
                f"{labels[b]}={v}" for b, v in vals.items()))
        lines.append("")

    if field_freq:
        lines.append(
            "**Systemic field divergences (aggregated across all mismatched diagnostics):**"
        )
        lines.append("")
        for (a, b, fname), (count, nv, ov) in sorted(
            field_freq.items(), key=lambda x: -x[1][0]
        ):
            nv_s = repr(nv) if nv != "<missing>" else "(absent)"
            ov_s = repr(ov) if ov != "<missing>" else "(absent)"
            lines.append(
                f"- `{fname}`: {labels[a]}={nv_s} vs {labels[b]}={ov_s} "
                f"- {count} occurrence(s)"
            )
        lines.append("")

    for (a, b), diffs in per_pair_diffs.items():
        if not diffs:
            continue
        lines.append(
            f"**{labels[a]} vs {labels[b]}: {len(diffs)} template(s) differ** (first 5):"
        )
        lines.append("")
        for tpl, summary, examples in diffs[:5]:
            lines.append(f"- `{tpl}`: {summary}")
            for nd, od, fdiff in examples[:1]:
                rid = nd.get("ruleId", "?")
                line = nd.get("startLine", "?")
                lines.append(f"  - example: `{rid}` @ L{line}")
                for fname, (nv, ov) in fdiff.items():
                    nv_s = repr(nv) if nv != "<missing>" else "(absent)"
                    ov_s = repr(ov) if ov != "<missing>" else "(absent)"
                    lines.append(f"    - `{fname}`: {a}={nv_s}, {b}={ov_s}")
        lines.append("")

    return lines, False


def data_sources_section(all_loaded, engines, bindings):
    lines = ["## Data Sources", ""]
    for engine in engines:
        for b, lbl in bindings:
            p = aggregate_path(engine, FORMATS[0], b)
            lines.append(f"- {engine}/{lbl}: `{p.relative_to(PROJECT_ROOT)}`")
    lines.append("")
    return lines


def host_metadata():
    def ver(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
            out = (r.stdout or r.stderr).strip().splitlines()
            return out[0] if out else "unknown"
        except Exception:
            return "not installed"

    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "rustc": ver(["rustc", "--version"]),
        "node": ver(["node", "--version"]),
        "java": ver(["java", "-version"]),
        "go": ver(["go", "version"]),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main(argv=None):
    args = parse_args(argv)

    engines = args.engines if args.engines else ENGINES
    bindings = (
        [(b, lbl) for b, lbl in ALL_BINDINGS if b in args.bindings]
        if args.bindings
        else ALL_BINDINGS
    )
    iterations = args.iterations
    template_dir = args.template_dir
    top_slowest = args.top_slowest

    if args.report_only:
        print("Report-only mode - using existing aggregate files", file=sys.stderr)
    elif not args.skip_build:
        build_all(bindings)
    else:
        print("Skipping builds (--skip-build)", file=sys.stderr)

    run_start_epoch = time.time() if not args.report_only else 0

    if not args.report_only:
        # Execute benchmarks in deterministic AB/BA alternating order per binding.
        # This distributes runner warm-up and load drift evenly so neither engine
        # is systematically favored by position in the run.
        plan = build_run_plan(engines, bindings)
        for binding, engine in plan:
            run_benchmark(binding, engine, iterations, template_dir)

    all_loaded = {
        e: {b: load_aggregate(aggregate_path(e, FORMATS[0], b), run_start_epoch)
            for b, _ in bindings}
        for e in engines
    }

    enforce_corpus_parity(all_loaded, bindings)
    enforce_run_metadata_parity(all_loaded, bindings)
    corpus_fp = all_loaded[engines[0]][bindings[0][0]].get("corpus_fingerprint")
    corpus_file_count = all_loaded[engines[0]][bindings[0][0]].get("corpus_file_count")

    # Detailed reports are part of the comparison contract: load every selected
    # engine × binding report exactly once, then share the in-memory data across
    # parity, top-slowest, and paired-engine sections.
    all_detailed = load_and_validate_detailed_reports(engines, bindings)
    validate_detailed_counts(all_detailed, all_loaded, engines, bindings)

    host = host_metadata()
    lines = [
        "# Benchmark Comparison",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Host", "",
        *[f"- **{k}**: {v}" for k, v in host.items()],
        f"- **iterations/template**: {iterations}",
        f"- **corpus fingerprint**: `{corpus_fp}` ({corpus_file_count} files)",
        f"- **bindings**: {', '.join(lbl for _, lbl in bindings)} ({len(bindings)} total)",
        f"- **engines**: {', '.join(e.upper() for e in engines)}",
        "",
        "## Methodology Notes", "",
        "### Steady-state vs throughput", "",
        "**Steady-state distributions** are per-template medians of iterations 2..N "
        "(the \"warmup-excluded\" window). The first iteration (iteration 1) is reported "
        "separately as \"first measured\" since it may include JIT compilation, cache "
        "population, or branch-predictor training. When N=1 (single iteration), steady "
        "state falls back to the first (and only) sample — there is no discard.", "",
        "**Throughput** uses all timed `validate()` calls (iterations 1..N × templates_ok) "
        "divided by the aggregate `measured_validation_wall_ms`. This includes the first "
        "iteration because throughput measures sustained real-world processing rate, not "
        "per-template latency percentiles.", "",
        "**Corpus-pass sums** (in the Paired Engine Comparison) are representative sums "
        "of per-template steady-state medians — not a measured elapsed time or measured "
        "throughput. They represent the total typical per-template cost aggregated across "
        "the corpus. Tail outliers (high p99/max values) can make measured throughput "
        "figures close even when typical (median) per-template costs differ noticeably "
        "between engines.", "",
        "### Shared-runner temporal noise", "",
        "CI benchmarks run on shared GitHub Actions runners (`ubuntu-latest`) where "
        "neighboring workloads, CPU frequency scaling, NUMA topology, and memory "
        "pressure introduce temporal noise. Intra-run relative comparisons "
        "(engine-vs-engine, binding-vs-binding) are more useful than cross-run "
        "absolute numbers, but are still noisy — they reflect a single snapshot of "
        "runner conditions. The workflow mitigates "
        "this by pairing engines per binding and alternating run order (AB/BA) across "
        "bindings, distributing warm-up and load drift so neither engine is "
        "systematically favored. AB/BA mitigates positional bias but does not "
        "eliminate it; results should be interpreted as directional indicators, "
        "not precise measurements.", "",
        "### New in this version", "",
        "- **Deterministic run plan**: `build_run_plan()` pairs engines per binding "
        "and alternates AB/BA across bindings (native rego/cel, wasm cel/rego, "
        "jvm rego/cel, python cel/rego, go rego/cel).",
        "- **Single-load detailed reports**: per-template reports are loaded exactly "
        "once and consumed by diagnostics parity, top-slowest, and paired comparison.",
        "- **Ratio-based 5% classification**: paired comparison uses "
        f"`slower/faster ≥ {PAIRED_RATIO_THRESHOLD}` (not percentage-of-max) with a "
        f"{PAIRED_FLOOR_MS} ms floor for trivially-fast templates.",
        "",
        "Five bindings are measured with the host language's own clock so numbers are "
        "directly comparable across native / wasm / jvm / python / go:",
        "1. **Init** - load native module (WASM/JNI/cdylib; Go is statically linked, "
        "no module load) + construct the validation setup a consumer creates. "
        "Native: standalone `SchemaValidator` + standalone engine (two objects). "
        "FFI bindings: engine constructor only (schema is already embedded inside "
        "the FFI engine constructor).",
        "2. **Template Modeling** - `SemanticModel::parse(bytes)` (standalone parse of "
        "one template).",
        "3. **Validate** - full `validate(bytes)` call (everything - re-parses + schema "
        "+ rules + finalize).",
        "",
        "Each phase reports first measured (after one global harness warmup) and "
        "steady state (subsequent iterations). Init retains cold/warm since cold "
        "init is a true first-ever construction with no prior warmup. The "
        "Rust-internal sub-phase breakdown inside validate (model_build / "
        "schema_validate / rule_evaluation / diagnostic_finalize) is surfaced under "
        "Per-Engine Detail. `engine_internal` is the Rust-internal total (identical "
        "across bindings); `wall_clock` is the host-timed validate total; "
        "`binding_overhead` is the median of per-call differences "
        "(`wall_clock_i − engine_internal_i`).",
        "",
    ]

    # Table of contents
    engine_anchors = [f"- [{e.upper()} Engine](#{e}-engine)" for e in engines]
    toc_items = [
        "- [Executive Summary](#executive-summary--p99-per-phase-ms)",
        "- [Methodology Notes](#methodology-notes)",
        *engine_anchors,
    ]
    toc_items.append(
        f"- [Top-{top_slowest} Slowest Templates](#top-{top_slowest}-slowest-templates-steady-state-wall-clock)"
    )
    if len(engines) == 2 and "rego" in engines and "cel" in engines:
        toc_items.append(
            "- [Paired Engine Comparison](#paired-engine-comparison-rego-vs-cel)"
        )
    toc_items.append("- [Data Sources](#data-sources)")

    lines += ["## Table of Contents", "", *toc_items, ""]
    lines += executive_summary(all_loaded, engines, bindings)

    # Track parity results
    parity_all_passed = True

    for engine in engines:
        lines += [f"## {engine.upper()} Engine", ""]
        lines += init_section(all_loaded, engine, bindings)
        lines += model_section(all_loaded, engine, bindings)
        lines += headline_section(all_loaded, engine, bindings)
        lines += phase_table(all_loaded, engine, bindings)
        lines += overhead_table(all_loaded, engine, bindings)
        parity_lines, parity_passed = diagnostics_parity(
            all_loaded, engine, bindings, all_detailed=all_detailed
        )
        lines += parity_lines
        if not parity_passed:
            parity_all_passed = False

    lines += top_slowest_section(all_detailed, engines, bindings, top_slowest)
    if len(engines) == 2 and "rego" in engines and "cel" in engines:
        lines += paired_engine_comparison(all_detailed, bindings)

    lines += data_sources_section(all_loaded, engines, bindings)

    out_dir = SCRIPT_DIR / "snapshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / "benchmark_comparison.md"
    output_path.write_text("\n".join(lines) + "\n")
    print(f"\nComparison written to {output_path}", file=sys.stderr)

    if not parity_all_passed:
        print(
            "\n❌ Diagnostics parity check FAILED - see report for details.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

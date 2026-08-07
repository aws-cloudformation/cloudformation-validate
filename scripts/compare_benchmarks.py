#!/usr/bin/env python3
"""Runs benchmarks for every engine × binding and writes a comparison report."""

import argparse
import json
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

# median/p99/max: median is the typical cost, p99 the tail, max the worst case.
STATS = ["median", "p99", "max"]

# Rust-internal phase timers surfaced in every binding (apples-to-apples).
PHASE_ROWS = [
    ("model build",         "model_build_ms"),
    ("schema validate",     "schema_validate_ms"),
    ("rule evaluation",     "rule_evaluation_ms"),
    ("diagnostic finalize", "diagnostic_finalize_ms"),
]



def parse_args():
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
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be a positive integer")
    if not args.template_dir.is_dir():
        parser.error(f"--template-dir is not a directory: {args.template_dir}")
    args.template_dir = args.template_dir.resolve()
    return args



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
        # Deterministic install via npm ci (requires package-lock.json)
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
        # Install wheel into bench venv for isolated benchmarking
        bench_dir = SRC_DIR / "bindings-python" / "bench"
        bench_dir.mkdir(parents=True, exist_ok=True)
        venv_dir = bench_dir / ".venv"
        if not venv_dir.exists():
            run_cmd(["python3", "-m", "venv", str(venv_dir)], bench_dir, "create bench venv")
        venv_pip = str(venv_dir / "bin" / "pip")
        # Find the built wheel
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
        run_cmd(["go", "run", "./bench", str(template_dir), "--engine", engine,
                 "--iterations", str(iterations)],
                SRC_DIR / "bindings-go" / "go", "go benchmark")
    else:
        sys.exit(f"unknown binding: {binding}")



def aggregate_path(engine, fmt, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / f"aggregate_{fmt}.json"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / f"aggregate_{fmt}.json"


def load_aggregate(path, run_start_epoch):
    if not path.exists():
        sys.exit(f"expected aggregate not found: {path}")
    # Reject aggregates older than the current run - prevents comparing stale numbers.
    mtime = path.stat().st_mtime
    if mtime < run_start_epoch - 1:
        sys.exit(f"stale aggregate {path} (mtime={mtime} < run_start={run_start_epoch})")
    with open(path) as f:
        return json.load(f)


def enforce_corpus_parity(all_loaded, bindings):
    """Every binding of every engine must have scanned the same bytes.
    If fingerprints differ, the downstream comparison is meaningless - abort."""
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
    and failure lists. Differences indicate non-comparable runs - abort."""
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


def _first_steady_tables(all_loaded, engine, key_prefix, bindings):
    """First-measured/steady-state tables for a single engine (per-template phases).
    The first sample occurs after one global harness warmup iteration, so it is
    not a cold start - label it accordingly. Subsequent samples are steady state."""
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
    """Cold/warm tables specifically for initialization (retains cold/warm naming
    since init cold is a true first-ever construction, not after a warmup)."""
    # warm_init_ms is the subsequent constructions stat dict
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
    """Top-of-report one-glance table per engine: p99 per phase per binding."""
    iterations = all_loaded[engines[0]][bindings[0][0]].get("iterations_per_template", "?")
    lines = ["## Executive Summary - p99 per phase (ms)", "",
            "One-glance view. **Init** shows the cold (first) construction cost - paid once "
            "per process; includes WASM module instantiation / JNI library load / Python "
            "cdylib FFI load for non-native bindings (Go is statically linked: "
            "module_load_ms = 0). **Model** and **Validate** show steady-state "
            "p99 - the consumer-visible latency after the global harness warmup "
            f"(first measured == steady state when iterations={iterations}). "
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
    """Per-engine sub-phase breakdown. Rows = phase, columns = binding × median/p99/max.
    Single stat-mode per table (no first/steady split for sub-phases - they're Rust-internal
    timers aggregated across all iterations)."""
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
    """Binding overhead = wall_clock − engine_internal per iteration. Native ~0."""
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


def _per_template_dir(engine, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / "json_detailed"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / "json_detailed"


def _diag_sort_key(d):
    """Stable ordering for pairing diagnostics between binding outputs - identity
    that should be binding-invariant (rule id + source span + message)."""
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
    """Return {field: (native_val, other_val)} for every top-level field that
    differs - including presence/absence and case (e.g. 'Error' vs 'ERROR')."""
    keys = set(a.keys()) | set(b.keys())
    return {k: (a.get(k, "<missing>"), b.get(k, "<missing>")) for k in keys if a.get(k) != b.get(k)}


def diagnostics_parity(all_loaded, engine, bindings):
    """Full parity check across all binding pairs - covers every pair among all
    selected bindings, so any field divergence surfaces even when two bindings
    happen to agree:
      1. Aggregate diagnostic totals across all bindings.
      2. Per-template, per-diagnostic full-dict equality across every binding pair.
    Every JSON field is compared - including case ('Error' vs 'ERROR') and
    absence-vs-empty ('' vs missing). Reports are NOT coerced; what each
    binding actually emits is what gets compared.

    Missing or empty per-template report directories are flagged as failures
    rather than silently passing.

    Returns (lines, passed): lines is the report section, passed is True only
    when parity holds perfectly."""
    labels = {bid: lbl for bid, lbl in bindings}
    levels = ["total_fatal", "total_errors", "total_warnings", "total_informational"]
    total_mismatches = []
    for lvl in levels:
        vals = {b: get(all_loaded[engine][b], "diagnostics", lvl) for b, _ in bindings}
        if len({v for v in vals.values() if v is not None}) > 1:
            total_mismatches.append((lvl, vals))

    pairs = [(a, b) for i, (a, _) in enumerate(bindings) for (b, _) in bindings[i + 1:]]
    per_pair_diffs = {pair: [] for pair in pairs}
    # Aggregate field-diff frequency across all pairs - surfaces systemic patterns.
    field_freq = {}
    template_count = 0

    dirs = {b: _per_template_dir(engine, b) for b, _ in bindings}

    # Flag missing or empty per-template report directories
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

    # Union of templates across bindings so we catch templates missing from one
    # binding but present in others.
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


def main():
    args = parse_args()

    engines = args.engines if args.engines else ENGINES
    bindings = (
        [(b, lbl) for b, lbl in ALL_BINDINGS if b in args.bindings]
        if args.bindings
        else ALL_BINDINGS
    )
    iterations = args.iterations
    template_dir = args.template_dir

    if args.report_only:
        print("Report-only mode - using existing aggregate files", file=sys.stderr)
    elif not args.skip_build:
        build_all(bindings)
    else:
        print("Skipping builds (--skip-build)", file=sys.stderr)

    run_start_epoch = time.time() if not args.report_only else 0

    if not args.report_only:
        for engine in engines:
            for binding, _ in bindings:
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
    lines += [
        "## Table of Contents", "",
        "- [Executive Summary](#executive-summary--p99-per-phase-ms)",
        *engine_anchors,
        "- [Data Sources](#data-sources)",
        "",
    ]

    lines += executive_summary(all_loaded, engines, bindings)

    # Track parity results - exit nonzero after writing report if any fail
    parity_all_passed = True

    for engine in engines:
        lines += [f"## {engine.upper()} Engine", ""]
        lines += init_section(all_loaded, engine, bindings)
        lines += model_section(all_loaded, engine, bindings)
        lines += headline_section(all_loaded, engine, bindings)
        lines += phase_table(all_loaded, engine, bindings)
        lines += overhead_table(all_loaded, engine, bindings)
        parity_lines, parity_passed = diagnostics_parity(all_loaded, engine, bindings)
        lines += parity_lines
        if not parity_passed:
            parity_all_passed = False

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

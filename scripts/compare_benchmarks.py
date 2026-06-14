#!/usr/bin/env python3
"""Runs benchmarks for every engine × binding and writes a comparison report."""

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
BINDINGS = [("native", "Native Rust"), ("wasm", "WASM (Node.js)"), ("jvm", "JVM (JNI)")]
ITERATIONS = 50
TEMPLATE_DIR = SRC_DIR / "resources" / "templates"

# median/p99/max: median is the typical cost, p99 the tail, max the worst case.
STATS = ["median", "p99", "max"]

# Rust-internal phase timers surfaced in every binding (apples-to-apples).
PHASE_ROWS = [
    ("model build",         "model_build_ms"),
    ("schema validate",     "schema_validate_ms"),
    ("rule evaluation",     "rule_evaluation_ms"),
    ("diagnostic finalize", "diagnostic_finalize_ms"),
]



def run_cmd(cmd, cwd, label):
    print(f"  $ {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, cwd=str(cwd))
    if result.returncode != 0:
        sys.exit(f"{label} failed (exit {result.returncode})")



def build_all():
    print("=== Building native Rust (release) ===", file=sys.stderr)
    run_cmd(["cargo", "build", "--locked", "--release", "--workspace"], SRC_DIR, "cargo build")

    print("=== Building WASM package ===", file=sys.stderr)
    run_cmd(["bash", str(SRC_DIR / "bindings-wasm" / "build.sh")],
            SRC_DIR / "bindings-wasm", "WASM build")
    bench_dir = SRC_DIR / "bindings-wasm" / "bench"
    if not (bench_dir / "node_modules").exists():
        run_cmd(["npm", "install", "--silent"], bench_dir, "npm install (bench)")

    print("=== Building JVM native library + bindings ===", file=sys.stderr)
    run_cmd(["bash", str(SRC_DIR / "bindings-jvm" / "build.sh")],
            SRC_DIR / "bindings-jvm", "JVM build")



def run_benchmark(binding, engine):
    print(f"=== {binding} benchmark (engine={engine}) ===", file=sys.stderr)
    if binding == "native":
        bench_bin = SRC_DIR / "target" / "release" / "cfn-benchmark"
        if not bench_bin.exists():
            sys.exit(f"cfn-benchmark not found at {bench_bin}")
        run_cmd([str(bench_bin), str(TEMPLATE_DIR), "--engine", engine,
                 "--iterations", str(ITERATIONS)], SRC_DIR, "native benchmark")
    elif binding == "wasm":
        run_cmd(["npx", "ts-node", "benchmark.ts", str(TEMPLATE_DIR), "--engine", engine,
                 "--iterations", str(ITERATIONS)],
                SRC_DIR / "bindings-wasm" / "bench", "wasm benchmark")
    elif binding == "jvm":
        bench_dir = SRC_DIR / "bindings-jvm" / "bench"
        gradle = str(bench_dir / "gradlew") if (bench_dir / "gradlew").exists() else "gradle"
        run_cmd([gradle, "run", "--no-daemon",
                 f"--args={TEMPLATE_DIR} --engine {engine} --iterations {ITERATIONS}"],
                bench_dir, "jvm benchmark")
    else:
        sys.exit(f"unknown binding: {binding}")



def aggregate_path(engine, fmt, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / f"aggregate_{fmt}.json"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / f"aggregate_{fmt}.json"


def load_aggregate(path, run_start_epoch):
    if not path.exists():
        sys.exit(f"expected aggregate not found: {path}")
    # Reject aggregates older than the current run — prevents comparing stale numbers.
    mtime = path.stat().st_mtime
    if mtime < run_start_epoch - 1:
        sys.exit(f"stale aggregate {path} (mtime={mtime} < run_start={run_start_epoch})")
    with open(path) as f:
        return json.load(f)


def enforce_corpus_parity(all_loaded):
    """Every binding of every engine must have scanned the same bytes.
    If fingerprints differ, the downstream comparison is meaningless — abort."""
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
        sys.exit("corpus fingerprint mismatch across bindings — cannot compare:\n"
                 + "\n".join(lines))



PCT_FLOOR_MS = 0.01


def stat(stats_dict, key):
    """Return (value, present). Present=False means the key was absent."""
    if isinstance(stats_dict, dict) and key in stats_dict:
        return float(stats_dict[key]), True
    return 0.0, False


def ms(val, present=True, digits=4):
    return f"{val:.{digits}f}" if present else "—"


def pct(base, base_present, v, v_present):
    if not (base_present and v_present) or base < PCT_FLOOR_MS:
        return "—"
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
    """(ok × iterations) / (wall_ms / 1000). Do not trust stored field —
    different harness versions wrote different formulas there."""
    wall = get(agg, "performance", "total_wall_ms", default=0.0) or 0.0
    iters = int(agg.get("iterations_per_template", 0) or 0)
    ok = int(agg.get("templates_ok", 0) or 0)
    if wall <= 0 or iters <= 0 or ok <= 0:
        return 0.0
    return (ok * iters) / (wall / 1000.0)



LABELS = {bid: lbl for bid, lbl in BINDINGS}


def stat_cols(d, stats=STATS):
    """Render one metric's avg/p99/max cells from a stats dict."""
    return [ms(*stat(d, s)) for s in stats]


def _cold_warm_tables(all_loaded, engine, key_prefix):
    """Cold/warm tables for a single engine."""
    def build(mode):
        header = ["Binding"] + [s for s in STATS]
        rows = []
        for b, lbl in BINDINGS:
            d = get(all_loaded[engine][b], "performance", f"{mode}_{key_prefix}_ms", default={})
            rows.append([lbl] + stat_cols(d))
        return table(header, rows)

    lines = [f"**Cold** — first iteration per template (ms)", ""]
    lines += build("cold")
    lines += ["", f"**Warm** — subsequent iterations per template (ms)", ""]
    lines += build("warm")
    lines += [""]
    return lines


def headline_section(all_loaded, engine):
    """Validation = full validate() call for one engine."""
    lines = ["### Validation — full `validate()` call (wall_clock per template, ms)", "",
             "Host-timer around the full `validate()` call — the latency a consumer sees.", ""]
    lines += _cold_warm_tables(all_loaded, engine, "wall_clock")
    header = ["Binding", "Throughput (val/sec)"]
    rows = []
    for b, lbl in BINDINGS:
        rows.append([lbl, ms(recomputed_throughput(all_loaded[engine][b]), True, 2)])
    lines += ["**Throughput** (recomputed = ok × iterations / wall_time)", ""]
    lines += table(header, rows) + [""]
    return lines


def executive_summary(all_loaded):
    """Top-of-report one-glance table per engine: p99 per phase per binding."""
    lines = ["## Executive Summary — p99 per phase (ms)", "",
            "One-glance view. **Init** shows the cold (first) construction cost — paid once "
            "per process; includes WASM module instantiation / JNI library load for non-native "
            "bindings. **Model** and **Validate** show warm p99 — the steady-state "
            f"consumer-visible latency (warm == cold when iterations={ITERATIONS}). "
            "Detailed breakdowns are in the per-engine sections below.", ""]
    header = ["Binding", "Module Load (ms)", "Init cold (ms)", "Model warm p99 (ms)", "Validate warm p99 (ms)", "Throughput"]
    for engine in ENGINES:
        rows = []
        for b, lbl in BINDINGS:
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


def model_section(all_loaded, engine):
    """Template modeling for one engine."""
    lines = ["### Template Modeling — host-timed `SemanticModel::parse` (ms)", "",
             "Host timer around `SemanticModel::parse` (bytes → resolved model). "
             "Standalone measurement; does not include the re-parse inside `validate()`.", ""]
    lines += _cold_warm_tables(all_loaded, engine, "host_model")
    return lines


def init_section(all_loaded, engine):
    """Initialization for one engine."""
    cold_header = ["Binding", "Module Load (ms)", "Cold (ms)"]
    warm_header = ["Binding"] + [s for s in STATS]
    breakdown_header = ["Binding", "Schema median", "Schema p99", "Engine median", "Engine p99"]

    lines = ["### Initialization — module load + schema + engine construction (ms)", "",
             "**Module Load** is the one-time cost of loading the native library (JNI) or "
             "WASM module (V8 compile + `#[start]`). Native = 0. "
             "**Cold** = module load + first schema init + first engine init — the total "
             "first-use cost a consumer pays. **Warm** = subsequent constructions.", ""]

    cold_rows = []
    warm_rows = []
    breakdown_rows = []
    for b, lbl in BINDINGS:
        agg = all_loaded[engine][b]
        mod_v = get(agg, "performance", "module_load_ms", default=0.0)
        cold_v = get(agg, "performance", "cold_init_ms")
        cold_rows.append([lbl, ms(mod_v or 0.0), ms(cold_v or 0.0, cold_v is not None)])
        warm = get(agg, "performance", "warm_init_ms", default={})
        warm_rows.append([lbl] + stat_cols(warm))
        si = get(agg, "performance", "schema_init_ms", default={})
        ei = get(agg, "performance", "engine_init_ms", default={})
        breakdown_rows.append([
            lbl,
            ms(*stat(si, "median")), ms(*stat(si, "p99")),
            ms(*stat(ei, "median")), ms(*stat(ei, "p99")),
        ])
    lines += [f"**Cold** — first construction (ms)", ""] + table(cold_header, cold_rows)
    lines += ["", f"**Warm** — subsequent constructions (ms)", ""] + table(warm_header, warm_rows)
    lines += ["", f"**Breakdown** — schema init vs engine init (ms)", ""] + table(breakdown_header, breakdown_rows)
    lines += [""]
    return lines


def phase_table(all_loaded, engine, fmt):
    """Per-engine sub-phase breakdown. Rows = phase, columns = binding × avg/p99/max.
    Single stat-mode per table (no cold/warm split for sub-phases — they're Rust-internal
    timers aggregated across all iterations)."""
    lines = [f"### Sub-phases (per-template medians across iterations, ms)", ""]
    header = ["Phase"]
    for _, lbl in BINDINGS:
        header += [f"{lbl} {s}" for s in STATS]
    rows = []
    for label, key in [("engine_internal (total)", "engine_internal_ms"),
                       ("wall_clock (total)",      "wall_clock_ms")] + PHASE_ROWS:
        row = [label]
        for b, _ in BINDINGS:
            d = get(all_loaded[engine][b], "performance", key, default={})
            row += stat_cols(d)
        rows.append(row)
    return lines + table(header, rows) + [""]


def overhead_table(all_loaded, engine):
    """Binding overhead = wall_clock − engine_internal per iteration. Native ~0."""
    header = ["Binding"] + list(STATS)
    rows = []
    for b, lbl in BINDINGS:
        d = get(all_loaded[engine][b], "performance", "binding_overhead_ms", default={})
        if d:
            rows.append([lbl] + stat_cols(d))
    if not rows:
        return []
    return [f"### Binding overhead (wall_clock − engine_internal, ms)", ""] \
        + table(header, rows) + [""]


def _per_template_dir(engine, fmt, binding):
    if binding == "native":
        return SRC_DIR / "cfn-validate" / "reports" / engine / f"json_{fmt}"
    return SRC_DIR / f"bindings-{binding}" / "reports" / engine / f"json_{fmt}"


def _diag_sort_key(d):
    """Stable ordering for pairing diagnostics between binding outputs — identity
    that should be binding-invariant (rule id + source span + message)."""
    return (
        d.get("ruleId") or "",
        d.get("startLine") or 0,
        d.get("startColumn") or 0,
        d.get("endLine") or 0,
        d.get("endColumn") or 0,
        d.get("resourceId") or "",
        d.get("propertyPath") or "",
        d.get("message") or "",
    )


def _field_diff(a, b):
    """Return {field: (native_val, other_val)} for every top-level field that
    differs — including presence/absence and case (e.g. 'Error' vs 'ERROR')."""
    keys = set(a.keys()) | set(b.keys())
    return {k: (a.get(k, "<missing>"), b.get(k, "<missing>")) for k in keys if a.get(k) != b.get(k)}


def diagnostics_parity(all_loaded, engine):
    """Full triad parity check — covers every pair among native/wasm/jvm, so any
    field divergence surfaces even when two bindings happen to agree:
      1. Aggregate diagnostic totals across all bindings.
      2. Per-template, per-diagnostic full-dict equality across every binding pair.
    Every JSON field is compared — including case ('Error' vs 'ERROR') and
    absence-vs-empty ('' vs missing). Reports are NOT coerced; what each
    binding actually emits is what gets compared."""
    levels = ["total_fatal", "total_errors", "total_warnings", "total_informational"]
    total_mismatches = []
    for lvl in levels:
        vals = {b: get(all_loaded[engine][b], "diagnostics", lvl) for b, _ in BINDINGS}
        if len({v for v in vals.values() if v is not None}) > 1:
            total_mismatches.append((lvl, vals))

    pairs = [(a, b) for i, (a, _) in enumerate(BINDINGS) for (b, _) in BINDINGS[i + 1:]]
    per_pair_diffs = {pair: [] for pair in pairs}  # (tpl, summary, examples)
    # Aggregate field-diff frequency across all pairs — surfaces systemic patterns.
    # Key: (binding_a, binding_b, field) → [count, sample_a_val, sample_b_val]
    field_freq = {}
    template_count = 0

    dirs = {b: _per_template_dir(engine, "detailed", b) for b, _ in BINDINGS}
    # Union of templates across bindings (not just native pivot) so we catch
    # templates missing from one binding but present in others.
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
                reason = f"{a}={sa if sa!='ok' else 'ok'}, {b}={sb if sb!='ok' else 'ok'}"
                if sa != "ok" or sb != "ok":
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

    totals = get(all_loaded[engine]["native"], "diagnostics", default={})
    counts = " / ".join(f"{lvl.replace('total_','')}={totals.get(lvl, '—')}" for lvl in levels)

    any_diffs = total_mismatches or any(per_pair_diffs.values())
    if not any_diffs:
        return [
            f"**{engine.upper()} diagnostic parity:** ✅ identical across all "
            f"{len(BINDINGS)} bindings "
            f"(aggregate {counts}; {template_count} templates compared field-by-field "
            f"across {len(pairs)} binding pair(s))",
            "",
        ]

    lines = [f"**{engine.upper()} diagnostic parity:** ⚠️ MISMATCH — parity bug:", ""]
    if total_mismatches:
        lines.append("**Aggregate totals differ:**")
        for lvl, vals in total_mismatches:
            lines.append(f"- `{lvl}`: " + ", ".join(f"{LABELS[b]}={v}" for b, v in vals.items()))
        lines.append("")

    if field_freq:
        lines.append("**Systemic field divergences (aggregated across all mismatched diagnostics):**")
        lines.append("")
        for (a, b, fname), (count, nv, ov) in sorted(field_freq.items(), key=lambda x: -x[1][0]):
            nv_s = repr(nv) if nv != "<missing>" else "(absent)"
            ov_s = repr(ov) if ov != "<missing>" else "(absent)"
            lines.append(
                f"- `{fname}`: {LABELS[a]}={nv_s} vs {LABELS[b]}={ov_s} — {count} occurrence(s)"
            )
        lines.append("")

    for (a, b), diffs in per_pair_diffs.items():
        if not diffs:
            continue
        lines.append(f"**{LABELS[a]} vs {LABELS[b]}: {len(diffs)} template(s) differ** (first 5):")
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

    return lines


def data_sources_section(all_loaded):
    lines = ["## Data Sources", ""]
    for engine in ENGINES:
        for fmt in FORMATS:
            for b, lbl in BINDINGS:
                p = aggregate_path(engine, fmt, b)
                lines.append(f"- {engine}/{lbl}: `{p.relative_to(PROJECT_ROOT)}`")
    lines.append("")
    return lines


def host_metadata():
    def ver(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
            out = (r.stdout or r.stderr).strip().splitlines()
            return out[0] if out else "unknown"
        except Exception as e:
            sys.exit(f"failed to read toolchain version ({' '.join(cmd)}): {e}")
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "rustc": ver(["rustc", "--version"]),
        "node": ver(["node", "--version"]),
        "java": ver(["java", "-version"]),
    }


def main():
    known_flags = {"--skip-build", "--report-only"}
    skip_build = "--skip-build" in sys.argv[1:]
    report_only = "--report-only" in sys.argv[1:]
    extra = [a for a in sys.argv[1:] if a not in known_flags]
    if extra:
        sys.exit(f"unrecognized arguments: {extra}. Supported: --skip-build, --report-only")

    if report_only:
        print("Report-only mode — using existing aggregate files", file=sys.stderr)
    elif not skip_build:
        build_all()
    else:
        print("Skipping builds (--skip-build)", file=sys.stderr)

    run_start_epoch = time.time() if not report_only else 0

    if not report_only:
        for engine in ENGINES:
            for binding, _ in BINDINGS:
                run_benchmark(binding, engine)

    all_loaded = {
        e: {b: load_aggregate(aggregate_path(e, FORMATS[0], b), run_start_epoch)
            for b, _ in BINDINGS}
        for e in ENGINES
    }

    enforce_corpus_parity(all_loaded)
    corpus_fp = all_loaded[ENGINES[0]][BINDINGS[0][0]].get("corpus_fingerprint")
    corpus_file_count = all_loaded[ENGINES[0]][BINDINGS[0][0]].get("corpus_file_count")

    host = host_metadata()
    lines = [
        "# Benchmark Comparison",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Host", "",
        *[f"- **{k}**: {v}" for k, v in host.items()],
        f"- **iterations/template**: {ITERATIONS}",
        f"- **corpus fingerprint**: `{corpus_fp}` ({corpus_file_count} files)",
        "",
        "Three phases are measured with the host language's own clock so numbers are "
        "directly comparable across native / wasm / jvm:",
        "1. **Init** — load native module (WASM/JNI) + construct `SchemaValidator + engine` (one-time setup).",
        "2. **Template Modeling** — `SemanticModel::parse(bytes)` (standalone parse of one template).",
        "3. **Validate** — full `validate(bytes)` call (everything — re-parses + schema + rules + finalize).",
        "",
        "Each phase reports cold (first iteration per template) and warm (subsequent iterations). "
        "The Rust-internal sub-phase breakdown inside validate (model_build / schema_validate / "
        "rule_evaluation / diagnostic_finalize) is surfaced under Per-Engine Detail. "
        "`engine_internal` is the Rust-internal total (identical across bindings); "
        "`wall_clock` is the host-timed validate total; `binding_overhead = wall_clock − engine_internal`.",
        "",
    ]

    # Table of contents
    engine_anchors = [f"- [{e.upper()} Engine](#{e}-engine)" for e in ENGINES]
    lines += [
        "## Table of Contents", "",
        "- [Executive Summary](#executive-summary--p99-per-phase-ms)",
        *engine_anchors,
        "- [Data Sources](#data-sources)",
        "",
    ]

    lines += executive_summary(all_loaded)

    for engine in ENGINES:
        lines += [f"## {engine.upper()} Engine", ""]
        lines += init_section(all_loaded, engine)
        lines += model_section(all_loaded, engine)
        lines += headline_section(all_loaded, engine)
        lines += phase_table(all_loaded, engine, FORMATS[0])
        lines += overhead_table(all_loaded, engine)
        lines += diagnostics_parity(all_loaded, engine)

    lines += data_sources_section(all_loaded)

    out_dir = SCRIPT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"benchmark_comparison.md"
    output_path.write_text("\n".join(lines) + "\n")
    print(f"\nComparison written to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()

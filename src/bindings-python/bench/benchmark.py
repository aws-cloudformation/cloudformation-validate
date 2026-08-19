"""Python benchmark harness for cloudformation-validate.

Mirrors the aggregate/per-template JSON contract of the native
cfn-validate benchmark (src/cfn-validate/src/benchmark.rs) with
binding='python'. Exercises the wheel-installed package through both
Rego and CEL engines at DETAILED/DEBUG level.

Usage:
    python -m bench.benchmark [TEMPLATE|DIR] --engine rego|cel --iterations N
"""

from __future__ import annotations

import argparse
import datetime
import enum
import hashlib
import json
import math
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_BENCH_DIR = Path(__file__).resolve().parent
_BINDINGS_DIR = _BENCH_DIR.parent
_WORKSPACE = _BINDINGS_DIR.parent
_DEFAULT_TEMPLATE_DIR = _WORKSPACE / "resources" / "templates"

_TEMPLATE_EXTENSIONS = frozenset((".yaml", ".yml", ".json"))

_CAMEL_RE = re.compile(r"_([a-z0-9])")


def _camel_case(name: str) -> str:
    """Convert snake_case field name to camelCase."""
    return _CAMEL_RE.sub(lambda m: m.group(1).upper(), name)


# ---------------------------------------------------------------------------
# Serde-compatible JSON serialization (mirrors tests/snapshot_test.py exactly)
#
# The cloudformation_validate types (JsonValue, EntityType) are imported lazily
# inside main(). These functions reference them via module globals that are set
# after import, so they remain usable without a top-level import.
# ---------------------------------------------------------------------------
# Populated in main() after the cloudformation_validate import.
_JsonValue: Any = None
_EntityType: Any = None


def _unwrap_json_value(value: Any) -> Any:
    if isinstance(value, _JsonValue.NULL):
        return None
    if isinstance(value, (_JsonValue.BOOL, _JsonValue.INT, _JsonValue.FLOAT, _JsonValue.STRING)):
        return value.value
    if isinstance(value, _JsonValue.ARRAY):
        return [_unwrap_json_value(item) for item in value.items]
    if isinstance(value, _JsonValue.OBJECT):
        return {key: _unwrap_json_value(entry) for key, entry in value.entries.items()}
    raise ValueError(f"unhandled JsonValue variant: {value!r}")


def to_jsonable(obj: Any) -> Any:
    """Converts a UniFFI record tree into serde's serialized JSON shape."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, _EntityType):
        return "".join(word.capitalize() for word in obj.name.split("_"))
    if isinstance(obj, enum.Enum):
        return obj.name
    if isinstance(obj, _JsonValue):
        return _unwrap_json_value(obj)
    if isinstance(obj, list):
        return [to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_jsonable(value) for key, value in obj.items()}
    return {
        _camel_case(field): to_jsonable(value)
        for field, value in vars(obj).items()
        if value is not None
    }


# ---------------------------------------------------------------------------
# Statistics helpers (mirrors native round4, stats_json, etc.)
# ---------------------------------------------------------------------------
def _round4(v: float) -> float:
    return round(v * 10000.0) / 10000.0


def _min(vals: List[float]) -> float:
    return min(vals) if vals else 0.0


def _max(vals: List[float]) -> float:
    return max(vals) if vals else 0.0


def _avg(vals: List[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _median(vals: List[float]) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    n = len(s)
    if n % 2 == 0:
        return (s[n // 2 - 1] + s[n // 2]) / 2.0
    return s[n // 2]


def _percentile(vals: List[float], pct: int) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    rank = (pct / 100.0) * (len(s) - 1)
    lo = int(math.floor(rank))
    hi = min(int(math.ceil(rank)), len(s) - 1)
    frac = rank - lo
    return s[lo] + frac * (s[hi] - s[lo])


def _stddev(vals: List[float]) -> float:
    if len(vals) < 2:
        return 0.0
    mean = _avg(vals)
    variance = sum((v - mean) ** 2 for v in vals) / (len(vals) - 1)
    return math.sqrt(variance)


def _stats_json(vals: List[float]) -> Dict[str, float]:
    return {
        "min": _round4(_min(vals)),
        "avg": _round4(_avg(vals)),
        "stddev": _round4(_stddev(vals)),
        "median": _round4(_median(vals)),
        "p90": _round4(_percentile(vals, 90)),
        "p95": _round4(_percentile(vals, 95)),
        "p99": _round4(_percentile(vals, 99)),
        "max": _round4(_max(vals)),
        "total": _round4(sum(vals)),
    }


# ---------------------------------------------------------------------------
# Relative-path helper (single source of truth for fingerprinting and
# template loading, matching Rust/JVM/WASM/Go harnesses).
# ---------------------------------------------------------------------------
def _relative_key(root: Path, filepath: Path) -> str:
    """Return a normalized relative path key for a template file.

    When *root* is a file (single-file corpus) or the relative result is '.'
    or empty, returns the basename of *filepath*. Otherwise returns the
    forward-slash-normalized relative path.  This matches the behavior of
    the Rust, JVM, WASM, and Go benchmark harnesses so that corpus
    fingerprints and per-template report keys are identical across bindings.
    """
    if root.is_file():
        return filepath.name
    try:
        rel = filepath.relative_to(root)
    except ValueError:
        return filepath.name
    rel_str = str(rel).replace(os.sep, "/")
    if not rel_str or rel_str == ".":
        return filepath.name
    return rel_str


# ---------------------------------------------------------------------------
# SHA-256 fingerprinting (matches native to_hex / compute_corpus_fingerprint)
# ---------------------------------------------------------------------------
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compute_corpus_fingerprint(root: Path, files: List[Path]) -> Tuple[str, int]:
    """Deterministic corpus fingerprint matching the native harness."""
    relative_and_absolute: List[Tuple[str, Path]] = []
    for f in files:
        rel_str = _relative_key(root, f)
        relative_and_absolute.append((rel_str, f))

    relative_and_absolute.sort(key=lambda x: x[0])

    outer = hashlib.sha256()
    for rel, abs_path in relative_and_absolute:
        content = abs_path.read_bytes()
        file_hash = _sha256_hex(content)
        outer.update(f"{rel}\t{file_hash}\n".encode())
    return outer.hexdigest(), len(relative_and_absolute)


def _run_fingerprint(corpus_fp: str, engine: str, fmt: str, iterations: int) -> str:
    data = f"{corpus_fp}|{engine}|{fmt}|{iterations}"
    return _sha256_hex(data.encode())


# ---------------------------------------------------------------------------
# Error-result helper - single source of truth for failed-template entries.
# ---------------------------------------------------------------------------
def _error_result(rel_path: str, size_bytes: int, status: str, error_msg: str) -> Dict[str, Any]:
    """Construct a result entry for a template that could not be benchmarked."""
    return {
        "file": rel_path,
        "status": status,
        "size_bytes": size_bytes,
        "resources": 0,
        "fatal": 0,
        "errors": 0,
        "warnings": 0,
        "informational": 0,
        "diag_count": 0,
        "host_model_ms": 0.0,
        "cold_host_model_ms": 0.0,
        "warm_host_model_ms": 0.0,
        "engine_internal_ms": 0.0,
        "cold_engine_internal_ms": 0.0,
        "warm_engine_internal_ms": 0.0,
        "wall_clock_ms": 0.0,
        "cold_wall_clock_ms": 0.0,
        "warm_wall_clock_ms": 0.0,
        "binding_overhead_ms": 0.0,
        "model_build_ms": 0.0,
        "schema_validate_ms": 0.0,
        "rule_eval_ms": 0.0,
        "diagnostic_finalize_ms": 0.0,
        "error_msg": error_msg,
    }


def _zero_benchmark_metrics() -> Dict[str, Any]:
    def zero_iteration() -> Dict[str, float]:
        return {
            "hostModelMs": 0.0,
            "modelBuildMs": 0.0,
            "schemaValidateMs": 0.0,
            "ruleEvaluationMs": 0.0,
            "diagnosticFinalizeMs": 0.0,
            "engineInternalMs": 0.0,
            "wallClockMs": 0.0,
        }

    return {
        "iterations": 0,
        "firstIteration": zero_iteration(),
        "steadyState": zero_iteration(),
        "bindingOverheadMs": 0.0,
    }


def _normalize_parse_failure_report(report: Any) -> Any:
    report.diagnostics = []
    counts = report.metadata.counts
    counts.fatal = 0
    counts.errors = 0
    counts.warnings = 0
    counts.informational = 0
    counts.debug = 0
    performance = report.performance
    for phase_name in (
        "schema_init",
        "engine_init",
        "model_build",
        "schema_validate",
        "rule_evaluation",
        "diagnostic_finalize",
        "validate_total",
    ):
        getattr(performance, phase_name).duration_ms = 0.0
    return report


def _report_path(json_dir: Path, rel_path: str) -> Path:
    stem = rel_path.replace("/", "_")
    for extension, replacement in (
        (".yaml", "_yaml"),
        (".yml", "_yml"),
        (".json", "_json"),
    ):
        if stem.endswith(extension):
            stem = f"{stem[:-len(extension)]}{replacement}"
            break
    return json_dir / f"{stem}.json"


# ---------------------------------------------------------------------------
# File discovery (sorted .yaml/.yml/.json, recursive)
# ---------------------------------------------------------------------------
def _collect_files(root: Path) -> List[Path]:
    """Recursively collects template files, sorted by normalized forward-slash path."""
    if root.is_file():
        return [root]
    results: List[Path] = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix in _TEMPLATE_EXTENSIONS:
                results.append(p)
    # Sort by string representation with forward slashes for cross-platform consistency.
    results.sort(key=lambda p: str(p).replace(os.sep, "/"))
    return results


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="Python benchmark harness for cloudformation-validate",
    )
    parser.add_argument(
        "template_dir",
        nargs="?",
        default=str(_DEFAULT_TEMPLATE_DIR),
        metavar="TEMPLATE|DIR",
        help="Template file or directory to benchmark (default: src/resources/templates)",
    )
    parser.add_argument(
        "--engine",
        required=True,
        choices=["rego", "cel"],
        help="Validation engine to use",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        required=True,
        help="Number of iterations per template (must be positive)",
    )
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be a positive integer")
    return args


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------
def main() -> None:
    args = _parse_args()

    engine_name: str = args.engine
    iterations: int = args.iterations
    template_dir = Path(args.template_dir).resolve()

    # -----------------------------------------------------------------------
    # Module load timing - measure import + native library load.
    # -----------------------------------------------------------------------
    import_start = time.perf_counter()

    from cloudformation_validate import (  # noqa: E402
        CelEngine,
        EntityType,
        JsonValue,
        RegoEngine,
        SchemaValidator,
        Severity,
        TemplateModel,
        ValidateConfig,
    )

    import_elapsed_ms = (time.perf_counter() - import_start) * 1000.0

    # Set module-level type references for to_jsonable serialization.
    global _JsonValue, _EntityType
    _JsonValue = JsonValue
    _EntityType = EntityType

    # Output directory: src/bindings-python/reports/{engine}
    output_dir = _BINDINGS_DIR / "reports" / engine_name
    output_dir.mkdir(parents=True, exist_ok=True)

    json_dir = output_dir / "json_detailed"
    # Clean json_detailed before run.
    if json_dir.exists():
        shutil.rmtree(json_dir)
    json_dir.mkdir(parents=True, exist_ok=True)

    # Discover templates.
    templates = _collect_files(template_dir)
    if not templates:
        print(f"No templates found in {template_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(templates)} templates in {template_dir}", file=sys.stderr)

    # -----------------------------------------------------------------------
    # Init timing.
    #
    # The Python engine constructor (RegoEngine/CelEngine) already embeds a
    # SchemaValidator internally, so the actual consumer setup cost is just the
    # engine constructor - that is what init_samples measures.
    #
    # schema_init_samples is measured separately as a standalone SchemaValidator
    # construction to give visibility into schema decompression cost in
    # isolation. It is NOT additive with engine_init_samples: the schema work
    # is already included inside the engine constructor. Summing them would
    # double-count schema initialization.
    #
    # cold_init = module load (import_elapsed_ms) + first engine constructor.
    # warm_init = subsequent engine constructors (excluding the first).
    # -----------------------------------------------------------------------
    EngineClass = RegoEngine if engine_name == "rego" else CelEngine

    schema_init_samples_ms: List[float] = []
    engine_init_samples_ms: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        sv = SchemaValidator()
        schema_init_samples_ms.append((time.perf_counter() - t0) * 1000.0)
        del sv

        t1 = time.perf_counter()
        eng = EngineClass()
        engine_init_samples_ms.append((time.perf_counter() - t1) * 1000.0)
        del eng

    # init_samples equals engine_init_samples - the engine constructor IS the
    # consumer validation setup (it embeds schema validation internally).
    init_samples_ms = list(engine_init_samples_ms)
    cold_init_ms = import_elapsed_ms + init_samples_ms[0]
    warm_init_samples_ms = init_samples_ms[1:] if len(init_samples_ms) > 1 else list(init_samples_ms)

    # Construct the engine for validation runs.
    engine = EngineClass()

    # Benchmark config: DETAILED + DEBUG severity to capture all diagnostics.
    benchmark_config = ValidateConfig(severity_level=Severity.DEBUG)

    # -----------------------------------------------------------------------
    # Pre-read all template bytes (excluded from timing).
    # Templates that fail to read are recorded as read_error rather than
    # aborting the entire benchmark.
    # -----------------------------------------------------------------------
    template_data: List[Tuple[str, bytes]] = []
    read_errors: List[Dict[str, Any]] = []
    for tpath in templates:
        rel_str = _relative_key(template_dir, tpath)
        try:
            content = tpath.read_bytes()
        except OSError as exc:
            read_errors.append(_error_result(rel_str, 0, "read_error", str(exc)))
            print(f"  {rel_str} READ_ERROR: {exc}", file=sys.stderr)
            continue
        template_data.append((rel_str, content))

    # -----------------------------------------------------------------------
    # Warmup: amortize first-call costs for both TemplateModel and validate.
    # Warmup exceptions are intentionally ignored - they do not affect the
    # benchmark results; some templates may legitimately fail to parse.
    # -----------------------------------------------------------------------
    if template_data:
        first_rel, first_bytes = template_data[0]
        try:
            model = TemplateModel(first_bytes)
            del model
        except Exception:
            pass
        try:
            warmup_report = engine._inner.validate_detailed(
                first_bytes, benchmark_config, first_rel
            )
            del warmup_report
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Main benchmark loop.
    # -----------------------------------------------------------------------
    results: List[Dict[str, Any]] = list(read_errors)
    deferred_writes: List[Tuple[Path, str, Any, Dict[str, Any]]] = []

    bench_start = time.perf_counter()

    for rel_path, template_bytes in template_data:
        sys.stderr.write(f"  {rel_path}")
        size_bytes = len(template_bytes)
        json_path = _report_path(json_dir, rel_path)

        iter_host_model_ms: List[float] = []
        iter_host_validate_ms: List[float] = []
        iter_model_build_ms: List[float] = []
        iter_schema_validate_ms: List[float] = []
        iter_rule_eval_ms: List[float] = []
        iter_finalize_ms: List[float] = []
        iter_engine_internal_ms: List[float] = []
        last_report = None
        failed = False

        for i in range(iterations):
            # Standalone model parse - classify failures as parse_error,
            # record one result, and skip validation for this template.
            tm0 = time.perf_counter()
            try:
                model = TemplateModel(template_bytes)
            except Exception as exc:
                parse_failure_report = engine._inner.validate_detailed(
                    template_bytes, benchmark_config, rel_path
                )
                deferred_writes.append(
                    (
                        json_path,
                        rel_path,
                        _normalize_parse_failure_report(parse_failure_report),
                        _zero_benchmark_metrics(),
                    )
                )
                results.append(_error_result(rel_path, 0, "parse_error", str(exc)))
                print(f" PARSE_ERROR: {exc}", file=sys.stderr)
                failed = True
                break
            host_model_ms = (time.perf_counter() - tm0) * 1000.0
            del model
            iter_host_model_ms.append(host_model_ms)

            # Host validate timing: full validation including schema + rules.
            t0 = time.perf_counter()
            try:
                report = engine._inner.validate_detailed(
                    template_bytes, benchmark_config, rel_path
                )
            except Exception as exc:
                print(f" FAILED: {exc}", file=sys.stderr)
                results.append(_error_result(rel_path, size_bytes, "error", str(exc)))
                failed = True
                break
            host_validate_ms = (time.perf_counter() - t0) * 1000.0
            iter_host_validate_ms.append(host_validate_ms)

            # Collect engine-internal phase timings from this iteration.
            perf = report.performance
            iter_model_build_ms.append(perf.model_build.duration_ms)
            iter_schema_validate_ms.append(perf.schema_validate.duration_ms)
            iter_rule_eval_ms.append(perf.rule_evaluation.duration_ms)
            iter_finalize_ms.append(perf.diagnostic_finalize.duration_ms)
            iter_engine_internal_ms.append(perf.validate_total.duration_ms)

            # Release the report reference for all but the final iteration.
            if i < iterations - 1:
                del report
            else:
                last_report = report

        if failed:
            continue

        report = last_report

        # Compute per-template stats.
        cold_host_model_ms = iter_host_model_ms[0]
        warm_host_model_ms = _median(iter_host_model_ms[1:]) if iterations > 1 else cold_host_model_ms
        median_host_model_ms = _median(iter_host_model_ms)

        cold_engine_internal_ms = iter_engine_internal_ms[0]
        warm_engine_internal_ms = (
            _median(iter_engine_internal_ms[1:]) if iterations > 1 else cold_engine_internal_ms
        )
        median_engine_internal_ms = _median(iter_engine_internal_ms)

        cold_wall_clock_ms = iter_host_validate_ms[0]
        warm_wall_clock_ms = _median(iter_host_validate_ms[1:]) if iterations > 1 else cold_wall_clock_ms
        median_wall_clock_ms = _median(iter_host_validate_ms)

        # binding_overhead_ms: median of per-iteration (wall - engine_internal)
        # differences. This captures the overhead that the Python/FFI binding
        # layer adds on top of the Rust engine for each validation call.
        per_iter_overhead = [
            wall - internal
            for wall, internal in zip(iter_host_validate_ms, iter_engine_internal_ms)
        ]
        binding_overhead_ms = _round4(_median(per_iter_overhead))

        # Report metadata.
        metadata = report.metadata
        report_resources = metadata.resources_scanned
        counts = metadata.counts
        report_fatal = counts.fatal
        report_errors = counts.errors
        report_warnings = counts.warnings
        report_informational = counts.informational
        report_diag_count = len(report.diagnostics)

        # Benchmark metrics for the per-template JSON.
        benchmark_metrics = {
            "iterations": iterations,
            "firstIteration": {
                "hostModelMs": _round4(iter_host_model_ms[0]),
                "modelBuildMs": _round4(iter_model_build_ms[0]),
                "schemaValidateMs": _round4(iter_schema_validate_ms[0]),
                "ruleEvaluationMs": _round4(iter_rule_eval_ms[0]),
                "diagnosticFinalizeMs": _round4(iter_finalize_ms[0]),
                "engineInternalMs": _round4(cold_engine_internal_ms),
                "wallClockMs": _round4(cold_wall_clock_ms),
            },
            "steadyState": {
                "hostModelMs": _round4(warm_host_model_ms),
                "modelBuildMs": _round4(
                    _median(iter_model_build_ms[1:]) if iterations > 1 else iter_model_build_ms[0]
                ),
                "schemaValidateMs": _round4(
                    _median(iter_schema_validate_ms[1:]) if iterations > 1 else iter_schema_validate_ms[0]
                ),
                "ruleEvaluationMs": _round4(
                    _median(iter_rule_eval_ms[1:]) if iterations > 1 else iter_rule_eval_ms[0]
                ),
                "diagnosticFinalizeMs": _round4(
                    _median(iter_finalize_ms[1:]) if iterations > 1 else iter_finalize_ms[0]
                ),
                "engineInternalMs": _round4(warm_engine_internal_ms),
                "wallClockMs": _round4(warm_wall_clock_ms),
            },
            "bindingOverheadMs": binding_overhead_ms,
        }

        deferred_writes.append((json_path, rel_path, report, benchmark_metrics))

        template_result = {
            "file": rel_path,
            "status": "ok",
            "size_bytes": size_bytes,
            "resources": report_resources,
            "fatal": report_fatal,
            "errors": report_errors,
            "warnings": report_warnings,
            "informational": report_informational,
            "diag_count": report_diag_count,
            "host_model_ms": _round4(median_host_model_ms),
            "cold_host_model_ms": _round4(cold_host_model_ms),
            "warm_host_model_ms": _round4(warm_host_model_ms),
            "model_build_ms": _round4(_median(iter_model_build_ms)),
            "schema_validate_ms": _round4(_median(iter_schema_validate_ms)),
            "rule_eval_ms": _round4(_median(iter_rule_eval_ms)),
            "diagnostic_finalize_ms": _round4(_median(iter_finalize_ms)),
            "engine_internal_ms": _round4(median_engine_internal_ms),
            "cold_engine_internal_ms": _round4(cold_engine_internal_ms),
            "warm_engine_internal_ms": _round4(warm_engine_internal_ms),
            "wall_clock_ms": _round4(median_wall_clock_ms),
            "cold_wall_clock_ms": _round4(cold_wall_clock_ms),
            "warm_wall_clock_ms": _round4(warm_wall_clock_ms),
            "binding_overhead_ms": binding_overhead_ms,
            "error_msg": None,
            # Internal: total wall-clock time across all iterations for this
            # template. Used to derive measured_validation_wall_ms in the
            # aggregate report; excluded from serialized per-template output.
            "_wall_clock_total_ms": sum(iter_host_validate_ms),
        }
        print(
            f"  model={median_host_model_ms:.4f}ms"
            f"  engine={median_engine_internal_ms:.4f}ms"
            f"  wall={median_wall_clock_ms:.4f}ms"
            f"  {report_errors}E {report_warnings}W {report_informational}I",
            file=sys.stderr,
        )
        results.append(template_result)
        del report, last_report

    total_wall_ms = (time.perf_counter() - bench_start) * 1000.0

    # -----------------------------------------------------------------------
    # Deferred writes: per-template JSON (after timed loop).
    # All write failures are reported explicitly and exit nonzero.
    # -----------------------------------------------------------------------
    for json_path, rel_path, report, benchmark_metrics in deferred_writes:
        try:
            template_json = to_jsonable(report)
            template_json["engine"] = engine_name
            template_json["binding"] = "python"
            template_json["detailLevel"] = "DETAILED"
            template_json["benchmarkMetrics"] = benchmark_metrics
            serialized = json.dumps(template_json, indent=2)
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(serialized)
        except (OSError, TypeError, ValueError) as exc:
            print(
                f"ERROR: failed to write per-template report {json_path} "
                f"(template: {rel_path}): {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Aggregate report.
    # -----------------------------------------------------------------------
    successful_results = [r for r in results if r["status"] == "ok"]
    failed_results = [r for r in results if r["status"] != "ok"]

    # Throughput based ONLY on the sum of timed successful validate calls.
    # Computed from per-template totals - excludes partial iterations from
    # templates that eventually failed.
    total_measured_validation_ms = sum(
        r["_wall_clock_total_ms"] for r in successful_results
    )
    throughput_per_sec = (
        (len(successful_results) * iterations) / (total_measured_validation_ms / 1000.0)
        if total_measured_validation_ms > 0
        else 0.0
    )

    # Collect per-template vectors for aggregate stats.
    model_build_vec = [r["model_build_ms"] for r in successful_results]
    schema_validate_vec = [r["schema_validate_ms"] for r in successful_results]
    rule_eval_vec = [r["rule_eval_ms"] for r in successful_results]
    finalize_vec = [r["diagnostic_finalize_ms"] for r in successful_results]
    engine_internal_vec = [r["engine_internal_ms"] for r in successful_results]
    cold_engine_internal_vec = [r["cold_engine_internal_ms"] for r in successful_results]
    warm_engine_internal_vec = [r["warm_engine_internal_ms"] for r in successful_results]
    wall_clock_vec = [r["wall_clock_ms"] for r in successful_results]
    cold_wall_clock_vec = [r["cold_wall_clock_ms"] for r in successful_results]
    warm_wall_clock_vec = [r["warm_wall_clock_ms"] for r in successful_results]
    host_model_vec = [r["host_model_ms"] for r in successful_results]
    cold_host_model_vec = [r["cold_host_model_ms"] for r in successful_results]
    warm_host_model_vec = [r["warm_host_model_ms"] for r in successful_results]
    binding_overhead_vec = [r["binding_overhead_ms"] for r in successful_results]

    corpus_fingerprint, corpus_file_count = _compute_corpus_fingerprint(template_dir, templates)
    run_fp = _run_fingerprint(corpus_fingerprint, engine_name, "DETAILED", iterations)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    aggregate = {
        "timestamp": timestamp,
        "engine": engine_name,
        "binding": "python",
        "detail_level": "DETAILED",
        "template_dir": str(template_dir),
        "templates_total": len(results),
        "templates_ok": len(successful_results),
        "templates_failed": len(failed_results),
        "iterations_per_template": iterations,
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_file_count": corpus_file_count,
        "run_fingerprint": run_fp,
        "performance": {
            "module_load_ms": _round4(import_elapsed_ms),
            "init_ms": _stats_json(init_samples_ms),
            "cold_init_ms": _round4(cold_init_ms),
            "warm_init_ms": _stats_json(warm_init_samples_ms),
            "schema_init_ms": _stats_json(schema_init_samples_ms),
            "engine_init_ms": _stats_json(engine_init_samples_ms),
            "total_wall_ms": _round4(total_wall_ms),
            "measured_validation_wall_ms": _round4(total_measured_validation_ms),
            "throughput_per_sec": _round4(throughput_per_sec),
            "model_build_ms": _stats_json(model_build_vec),
            "schema_validate_ms": _stats_json(schema_validate_vec),
            "rule_evaluation_ms": _stats_json(rule_eval_vec),
            "diagnostic_finalize_ms": _stats_json(finalize_vec),
            "engine_internal_ms": _stats_json(engine_internal_vec),
            "cold_engine_internal_ms": _stats_json(cold_engine_internal_vec),
            "warm_engine_internal_ms": _stats_json(warm_engine_internal_vec),
            "wall_clock_ms": _stats_json(wall_clock_vec),
            "cold_wall_clock_ms": _stats_json(cold_wall_clock_vec),
            "warm_wall_clock_ms": _stats_json(warm_wall_clock_vec),
            "host_model_ms": _stats_json(host_model_vec),
            "cold_host_model_ms": _stats_json(cold_host_model_vec),
            "warm_host_model_ms": _stats_json(warm_host_model_vec),
            "binding_overhead_ms": _stats_json(binding_overhead_vec),
        },
        "diagnostics": {
            "total_fatal": sum(r["fatal"] for r in successful_results),
            "total_errors": sum(r["errors"] for r in successful_results),
            "total_warnings": sum(r["warnings"] for r in successful_results),
            "total_informational": sum(r["informational"] for r in successful_results),
        },
        "failures": [
            {"file": r["file"], "status": r["status"], "error": r["error_msg"]}
            for r in failed_results
        ],
    }

    aggregate_path = output_dir / "aggregate_detailed.json"
    try:
        with open(aggregate_path, "w", encoding="utf-8") as f:
            json.dump(aggregate, f, indent=2)
    except OSError as exc:
        print(f"ERROR: failed to write aggregate report {aggregate_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Fingerprint file for cache invalidation.
    # -----------------------------------------------------------------------
    fingerprint_path = output_dir / "run_fingerprint.txt"
    try:
        fingerprint_path.write_text(run_fp, encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: failed to write fingerprint {fingerprint_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Summary to stderr.
    # -----------------------------------------------------------------------
    print(file=sys.stderr)
    print(
        f"Benchmark complete: {len(successful_results)} ok, "
        f"{len(failed_results)} failed ({iterations} iterations/template)",
        file=sys.stderr,
    )
    print(
        f"engine_internal (median): median={_median(engine_internal_vec):.4f}ms "
        f"p99={_percentile(engine_internal_vec, 99):.4f}ms "
        f"max={_max(engine_internal_vec):.4f}ms",
        file=sys.stderr,
    )
    print(
        f"wall_clock     (median): median={_median(wall_clock_vec):.4f}ms "
        f"p99={_percentile(wall_clock_vec, 99):.4f}ms "
        f"max={_max(wall_clock_vec):.4f}ms",
        file=sys.stderr,
    )
    print(f"Throughput: {throughput_per_sec:.2f} validations/sec", file=sys.stderr)
    print(
        f"Corpus fingerprint: {corpus_fingerprint} ({corpus_file_count} files)",
        file=sys.stderr,
    )
    print(f"Module load: {import_elapsed_ms:.4f}ms", file=sys.stderr)
    print(f"Reports written to {output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()

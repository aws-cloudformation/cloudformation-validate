"""Python benchmark harness for cloudformation-validate.

Mirrors the aggregate/per-template JSON contract of the native
cfn-validate benchmark (src/cfn-validate/src/benchmark.rs) with
binding='python'. Exercises the wheel-installed package through both
Rego and CEL engines at DETAILED/DEBUG level.

Usage:
    python -m bench.benchmark [TEMPLATE|DIR] --engine rego|cel --iterations N
    python -m bench.benchmark --engine rego|cel --startup-probe
"""

from __future__ import annotations

import argparse
import datetime
import enum
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_BENCH_DIR = Path(__file__).resolve().parent
_BINDINGS_DIR = _BENCH_DIR.parent
_WORKSPACE = _BINDINGS_DIR.parent
_DEFAULT_TEMPLATE_DIR = _WORKSPACE / "resources" / "templates"

_DEFAULT_STARTUP_TEMPLATE = "good/minimal.yaml"

_CONSUMER_INIT_SCOPE = "engine_includes_schema_validator"

_CARGO_VERSION_ENV = "BENCHMARK_CARGO_VERSION"
_RUSTC_VERSION_ENV = "BENCHMARK_RUSTC_VERSION"

_DISTRIBUTION_NAME = "cloudformation-validate"

_TEMPLATE_EXTENSIONS = frozenset((".yaml", ".yml", ".json"))

_CAMEL_RE = re.compile(r"_([a-z0-9])")


@dataclass
class FirstValidation:
    host_ms: float
    internal_ms: float
    model_build_ms: float
    schema_validate_ms: float
    rule_evaluation_ms: float
    diagnostic_finalize_ms: float


@dataclass
class StartupMeasurement:
    startup_template: str
    module_load_ms: float
    consumer_init_scope: str
    consumer_init_ms: float
    schema_init_ms: Optional[float]
    engine_init_ms: float
    first: FirstValidation
    internal_time_to_first_result_ms: float


@dataclass
class SampleSummary:
    first_host_model_ms: float
    subsequent_host_model_ms: Optional[float]
    first_engine_internal_ms: float
    subsequent_engine_internal_ms: Optional[float]
    first_wall_clock_ms: float
    subsequent_wall_clock_ms: Optional[float]


def _camel_case(name: str) -> str:
    return _CAMEL_RE.sub(lambda m: m.group(1).upper(), name)


# The cloudformation_validate types (JsonValue, EntityType) are imported lazily
# inside main(). These functions reference them via module globals that are set
# after import, so they remain usable without a top-level import.
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


def _stats_json(vals: List[float]) -> Dict[str, Any]:
    return {
        "count": len(vals),
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


def _iteration_metrics(
    host_model: float,
    model_build: float,
    schema_validate: float,
    rule_eval: float,
    finalize: float,
    engine_internal: float,
    wall_clock: float,
) -> Dict[str, float]:
    return {
        "hostModelMs": _round4(host_model),
        "modelBuildMs": _round4(model_build),
        "schemaValidateMs": _round4(schema_validate),
        "ruleEvaluationMs": _round4(rule_eval),
        "diagnosticFinalizeMs": _round4(finalize),
        "engineInternalMs": _round4(engine_internal),
        "wallClockMs": _round4(wall_clock),
    }


def _subsequent_metric(vals: List[float]) -> Optional[float]:
    if len(vals) > 1:
        return _round4(_median(vals[1:]))
    return None


def _per_template_metrics(
    iterations: int,
    host_model: List[float],
    model_build: List[float],
    schema_validate: List[float],
    rule_eval: List[float],
    finalize: List[float],
    engine_internal: List[float],
    wall_clock: List[float],
    binding_overhead_ms: float,
) -> Dict[str, Any]:
    first_measured = _iteration_metrics(
        host_model[0],
        model_build[0],
        schema_validate[0],
        rule_eval[0],
        finalize[0],
        engine_internal[0],
        wall_clock[0],
    )
    subsequent = {
        "sampleCount": max(len(wall_clock) - 1, 0),
        "hostModelMs": _subsequent_metric(host_model),
        "modelBuildMs": _subsequent_metric(model_build),
        "schemaValidateMs": _subsequent_metric(schema_validate),
        "ruleEvaluationMs": _subsequent_metric(rule_eval),
        "diagnosticFinalizeMs": _subsequent_metric(finalize),
        "engineInternalMs": _subsequent_metric(engine_internal),
        "wallClockMs": _subsequent_metric(wall_clock),
    }

    def steady_or_first(vals: List[float]) -> float:
        return _median(vals[1:]) if len(vals) > 1 else vals[0]

    # Legacy steadyState mirrors the subsequent window but falls back to the first
    # sample when there are no subsequent samples so older consumers keep a value.
    steady_state = _iteration_metrics(
        steady_or_first(host_model),
        steady_or_first(model_build),
        steady_or_first(schema_validate),
        steady_or_first(rule_eval),
        steady_or_first(finalize),
        steady_or_first(engine_internal),
        steady_or_first(wall_clock),
    )
    return {
        "iterations": iterations,
        "firstMeasured": dict(first_measured),
        "subsequent": subsequent,
        "firstIteration": dict(first_measured),
        "steadyState": steady_state,
        "bindingOverheadMs": binding_overhead_ms,
    }


def _sample_summary(
    host_model: List[float],
    engine_internal: List[float],
    wall_clock: List[float],
) -> SampleSummary:
    def subsequent(vals: List[float]) -> Optional[float]:
        return _median(vals[1:]) if len(vals) > 1 else None

    return SampleSummary(
        first_host_model_ms=host_model[0],
        subsequent_host_model_ms=subsequent(host_model),
        first_engine_internal_ms=engine_internal[0],
        subsequent_engine_internal_ms=subsequent(engine_internal),
        first_wall_clock_ms=wall_clock[0],
        subsequent_wall_clock_ms=subsequent(wall_clock),
    )


def _first_validation_json(first: FirstValidation) -> Dict[str, float]:
    return {
        "host_ms": _round4(first.host_ms),
        "internal_ms": _round4(first.internal_ms),
        "model_build_ms": _round4(first.model_build_ms),
        "schema_validate_ms": _round4(first.schema_validate_ms),
        "rule_evaluation_ms": _round4(first.rule_evaluation_ms),
        "diagnostic_finalize_ms": _round4(first.diagnostic_finalize_ms),
    }


def _startup_section(startup: StartupMeasurement) -> Dict[str, Any]:
    return {
        "startup_template": startup.startup_template,
        "module_load_ms": _round4(startup.module_load_ms),
        "consumer_init": {
            "scope": startup.consumer_init_scope,
            "duration_ms": _round4(startup.consumer_init_ms),
        },
        "schema_init_ms": (
            _round4(startup.schema_init_ms) if startup.schema_init_ms is not None else None
        ),
        "engine_init_ms": _round4(startup.engine_init_ms),
        "first_validation": _first_validation_json(startup.first),
        "internal_time_to_first_result_ms": _round4(startup.internal_time_to_first_result_ms),
    }


def _measure_startup(
    engine_class: Any,
    startup_bytes: bytes,
    startup_label: str,
    benchmark_config: Any,
    module_load_ms: float,
) -> Tuple[Any, StartupMeasurement]:
    engine_start = time.perf_counter()
    engine = engine_class()
    engine_init_ms = (time.perf_counter() - engine_start) * 1000.0

    consumer_init_ms = engine_init_ms

    validate_start = time.perf_counter()
    report = engine._inner.validate_detailed(startup_bytes, benchmark_config, startup_label)
    host_ms = (time.perf_counter() - validate_start) * 1000.0

    perf = report.performance
    first = FirstValidation(
        host_ms=host_ms,
        internal_ms=perf.validate_total.duration_ms,
        model_build_ms=perf.model_build.duration_ms,
        schema_validate_ms=perf.schema_validate.duration_ms,
        rule_evaluation_ms=perf.rule_evaluation.duration_ms,
        diagnostic_finalize_ms=perf.diagnostic_finalize.duration_ms,
    )
    startup = StartupMeasurement(
        startup_template=startup_label,
        module_load_ms=module_load_ms,
        consumer_init_scope=_CONSUMER_INIT_SCOPE,
        consumer_init_ms=consumer_init_ms,
        schema_init_ms=None,
        engine_init_ms=engine_init_ms,
        first=first,
        internal_time_to_first_result_ms=module_load_ms + consumer_init_ms + host_ms,
    )
    return engine, startup


def _core_version(version_fn: Any) -> str:
    try:
        value = version_fn()
    except Exception:
        return "unknown"
    return str(value) if value is not None else "unknown"


def _installed_wheel_version() -> str:
    try:
        return importlib.metadata.version(_DISTRIBUTION_NAME)
    except Exception:
        return "unknown"


def _query_tool_version(tool: str) -> str:
    try:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    lines = result.stdout.splitlines()
    return lines[0].strip() if lines and lines[0].strip() else "unknown"


def _env_or_query(var: str, tool: str) -> str:
    value = os.environ.get(var, "")
    if value.strip():
        return value.strip()
    return _query_tool_version(tool)


def _python_runtime() -> str:
    return f"python {platform.python_version()} {platform.system().lower()}-{platform.machine()}"


def _provenance(version_fn: Any) -> Dict[str, Any]:
    return {
        "cloudformation_validate": _core_version(version_fn),
        "binding_artifact": {
            "kind": "wheel",
            "version": _installed_wheel_version(),
            "source": "cloudformation-validate (Python wheel)",
        },
        "cargo": _env_or_query(_CARGO_VERSION_ENV, "cargo"),
        "rustc": _env_or_query(_RUSTC_VERSION_ENV, "rustc"),
        "runtime": _python_runtime(),
    }


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


def _error_result(rel_path: str, size_bytes: int, status: str, error_msg: str) -> Dict[str, Any]:
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
        "first_measured_host_model_ms": 0.0,
        "subsequent_host_model_ms": None,
        "engine_internal_ms": 0.0,
        "cold_engine_internal_ms": 0.0,
        "warm_engine_internal_ms": 0.0,
        "first_measured_engine_internal_ms": 0.0,
        "subsequent_engine_internal_ms": None,
        "wall_clock_ms": 0.0,
        "cold_wall_clock_ms": 0.0,
        "warm_wall_clock_ms": 0.0,
        "first_measured_wall_clock_ms": 0.0,
        "subsequent_wall_clock_ms": None,
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
        "firstMeasured": zero_iteration(),
        "subsequent": {
            "sampleCount": 0,
            "hostModelMs": None,
            "modelBuildMs": None,
            "schemaValidateMs": None,
            "ruleEvaluationMs": None,
            "diagnosticFinalizeMs": None,
            "engineInternalMs": None,
            "wallClockMs": None,
        },
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


def _write_template_report(
    json_path: Path,
    rel_path: str,
    report: Any,
    benchmark_metrics: Dict[str, Any],
    engine_name: str,
) -> None:
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


def _collect_files(root: Path) -> List[Path]:
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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="Python benchmark harness for cloudformation-validate",
    )
    parser.add_argument(
        "template_dir",
        nargs="?",
        default=None,
        metavar="TEMPLATE|DIR",
        help="Template file or directory to benchmark (default: src/resources/templates).",
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
        default=None,
        help=(
            "Number of iterations per template (must be positive). "
            "Required unless --startup-probe is set, which ignores it."
        ),
    )
    parser.add_argument(
        "--startup-probe",
        action="store_true",
        dest="startup_probe",
        help=(
            "Measure a single uncontaminated cold-start sequence (engine "
            "construction that embeds the schema validator, then the first "
            "raw-byte validation), print one JSON object, and exit."
        ),
    )
    args = parser.parse_args()
    if args.iterations is not None and args.iterations < 1:
        parser.error("--iterations must be a positive integer")
    if not args.startup_probe and args.iterations is None:
        parser.error("--iterations is required")
    return args


def _run_startup_probe(
    engine_name: str,
    engine_class: Any,
    version_fn: Any,
    benchmark_config: Any,
    module_load_ms: float,
) -> None:
    startup_path = _DEFAULT_TEMPLATE_DIR / _DEFAULT_STARTUP_TEMPLATE
    try:
        startup_bytes = startup_path.read_bytes()
    except OSError as exc:
        print(f"failed to read startup template '{startup_path}': {exc}", file=sys.stderr)
        sys.exit(1)
    startup_label = startup_path.name

    _engine, startup = _measure_startup(
        engine_class, startup_bytes, startup_label, benchmark_config, module_load_ms
    )

    probe = _startup_section(startup)
    probe["binding"] = "python"
    probe["engine"] = engine_name
    probe["versions"] = _provenance(version_fn)
    print(json.dumps(probe))


def main() -> None:
    args = _parse_args()

    engine_name: str = args.engine
    startup_probe: bool = args.startup_probe

    # Module load timing - measure import + native library load.
    import_start = time.perf_counter()

    from cloudformation_validate import (  # noqa: E402
        CelEngine,
        EntityType,
        JsonValue,
        RegoEngine,
        Severity,
        TemplateModel,
        ValidateConfig,
        version,
    )

    import_elapsed_ms = (time.perf_counter() - import_start) * 1000.0

    global _JsonValue, _EntityType
    _JsonValue = JsonValue
    _EntityType = EntityType

    engine_class = RegoEngine if engine_name == "rego" else CelEngine

    benchmark_config = ValidateConfig(severity_level=Severity.DEBUG)

    if startup_probe:
        _run_startup_probe(
            engine_name,
            engine_class,
            version,
            benchmark_config,
            import_elapsed_ms,
        )
        return

    iterations: int = args.iterations
    template_dir = (
        Path(args.template_dir).resolve() if args.template_dir is not None else _DEFAULT_TEMPLATE_DIR.resolve()
    )

    output_dir = _BINDINGS_DIR / "reports" / engine_name
    output_dir.mkdir(parents=True, exist_ok=True)

    json_dir = output_dir / "json_detailed"
    if json_dir.exists():
        shutil.rmtree(json_dir)
    json_dir.mkdir(parents=True, exist_ok=True)

    templates = _collect_files(template_dir)
    if not templates:
        print(f"No templates found in {template_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(templates)} templates in {template_dir}", file=sys.stderr)

    # Pre-read all template bytes (excluded from timing).
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

    if template_data:
        startup_label, startup_bytes = template_data[0]
        engine, startup = _measure_startup(
            engine_class, startup_bytes, startup_label, benchmark_config, import_elapsed_ms
        )
    else:
        engine_start = time.perf_counter()
        engine = engine_class()
        engine_init_ms = (time.perf_counter() - engine_start) * 1000.0
        startup = StartupMeasurement(
            startup_template="",
            module_load_ms=import_elapsed_ms,
            consumer_init_scope=_CONSUMER_INIT_SCOPE,
            consumer_init_ms=engine_init_ms,
            schema_init_ms=None,
            engine_init_ms=engine_init_ms,
            first=FirstValidation(0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            internal_time_to_first_result_ms=import_elapsed_ms + engine_init_ms,
        )

    schema_init_samples_ms: List[float] = []
    engine_init_samples_ms: List[float] = [startup.engine_init_ms]

    init_samples_ms = list(engine_init_samples_ms)
    cold_init_ms = import_elapsed_ms + init_samples_ms[0]
    subsequent_init_samples_ms: List[float] = []
    warm_init_samples_ms: List[float] = []

    results: List[Dict[str, Any]] = list(read_errors)

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
            tm0 = time.perf_counter()
            try:
                model = TemplateModel(template_bytes)
            except Exception as exc:
                parse_failure_report = engine._inner.validate_detailed(
                    template_bytes, benchmark_config, rel_path
                )
                _write_template_report(
                    json_path,
                    rel_path,
                    _normalize_parse_failure_report(parse_failure_report),
                    _zero_benchmark_metrics(),
                    engine_name,
                )
                del parse_failure_report
                results.append(_error_result(rel_path, 0, "parse_error", str(exc)))
                print(f" PARSE_ERROR: {exc}", file=sys.stderr)
                failed = True
                break
            host_model_ms = (time.perf_counter() - tm0) * 1000.0
            del model
            iter_host_model_ms.append(host_model_ms)

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

            perf = report.performance
            iter_model_build_ms.append(perf.model_build.duration_ms)
            iter_schema_validate_ms.append(perf.schema_validate.duration_ms)
            iter_rule_eval_ms.append(perf.rule_evaluation.duration_ms)
            iter_finalize_ms.append(perf.diagnostic_finalize.duration_ms)
            iter_engine_internal_ms.append(perf.validate_total.duration_ms)

            if i < iterations - 1:
                del report
            else:
                last_report = report

        if failed:
            continue

        report = last_report

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

        summary = _sample_summary(iter_host_model_ms, iter_engine_internal_ms, iter_host_validate_ms)

        metadata = report.metadata
        report_resources = metadata.resources_scanned
        counts = metadata.counts
        report_fatal = counts.fatal
        report_errors = counts.errors
        report_warnings = counts.warnings
        report_informational = counts.informational
        report_diag_count = len(report.diagnostics)

        benchmark_metrics = _per_template_metrics(
            iterations,
            iter_host_model_ms,
            iter_model_build_ms,
            iter_schema_validate_ms,
            iter_rule_eval_ms,
            iter_finalize_ms,
            iter_engine_internal_ms,
            iter_host_validate_ms,
            binding_overhead_ms,
        )

        _write_template_report(json_path, rel_path, report, benchmark_metrics, engine_name)

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
            "first_measured_host_model_ms": _round4(summary.first_host_model_ms),
            "subsequent_host_model_ms": (
                _round4(summary.subsequent_host_model_ms)
                if summary.subsequent_host_model_ms is not None
                else None
            ),
            "model_build_ms": _round4(_median(iter_model_build_ms)),
            "schema_validate_ms": _round4(_median(iter_schema_validate_ms)),
            "rule_eval_ms": _round4(_median(iter_rule_eval_ms)),
            "diagnostic_finalize_ms": _round4(_median(iter_finalize_ms)),
            "engine_internal_ms": _round4(median_engine_internal_ms),
            "cold_engine_internal_ms": _round4(cold_engine_internal_ms),
            "warm_engine_internal_ms": _round4(warm_engine_internal_ms),
            "first_measured_engine_internal_ms": _round4(summary.first_engine_internal_ms),
            "subsequent_engine_internal_ms": (
                _round4(summary.subsequent_engine_internal_ms)
                if summary.subsequent_engine_internal_ms is not None
                else None
            ),
            "wall_clock_ms": _round4(median_wall_clock_ms),
            "cold_wall_clock_ms": _round4(cold_wall_clock_ms),
            "warm_wall_clock_ms": _round4(warm_wall_clock_ms),
            "first_measured_wall_clock_ms": _round4(summary.first_wall_clock_ms),
            "subsequent_wall_clock_ms": (
                _round4(summary.subsequent_wall_clock_ms)
                if summary.subsequent_wall_clock_ms is not None
                else None
            ),
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

    model_build_vec = [r["model_build_ms"] for r in successful_results]
    schema_validate_vec = [r["schema_validate_ms"] for r in successful_results]
    rule_eval_vec = [r["rule_eval_ms"] for r in successful_results]
    finalize_vec = [r["diagnostic_finalize_ms"] for r in successful_results]
    engine_internal_vec = [r["engine_internal_ms"] for r in successful_results]
    cold_engine_internal_vec = [r["cold_engine_internal_ms"] for r in successful_results]
    warm_engine_internal_vec = [r["warm_engine_internal_ms"] for r in successful_results]
    first_measured_engine_internal_vec = [
        r["first_measured_engine_internal_ms"] for r in successful_results
    ]
    subsequent_engine_internal_vec = [
        r["subsequent_engine_internal_ms"]
        for r in successful_results
        if r["subsequent_engine_internal_ms"] is not None
    ]
    wall_clock_vec = [r["wall_clock_ms"] for r in successful_results]
    cold_wall_clock_vec = [r["cold_wall_clock_ms"] for r in successful_results]
    warm_wall_clock_vec = [r["warm_wall_clock_ms"] for r in successful_results]
    first_measured_wall_clock_vec = [r["first_measured_wall_clock_ms"] for r in successful_results]
    subsequent_wall_clock_vec = [
        r["subsequent_wall_clock_ms"]
        for r in successful_results
        if r["subsequent_wall_clock_ms"] is not None
    ]
    host_model_vec = [r["host_model_ms"] for r in successful_results]
    cold_host_model_vec = [r["cold_host_model_ms"] for r in successful_results]
    warm_host_model_vec = [r["warm_host_model_ms"] for r in successful_results]
    first_measured_host_model_vec = [r["first_measured_host_model_ms"] for r in successful_results]
    subsequent_host_model_vec = [
        r["subsequent_host_model_ms"]
        for r in successful_results
        if r["subsequent_host_model_ms"] is not None
    ]
    binding_overhead_vec = [r["binding_overhead_ms"] for r in successful_results]

    corpus_fingerprint, corpus_file_count = _compute_corpus_fingerprint(template_dir, templates)
    run_fp = _run_fingerprint(corpus_fingerprint, engine_name, "DETAILED", iterations)

    # Provenance is built after all timed work so the cargo/rustc spawns never
    # contaminate a measurement.
    provenance = _provenance(version)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    aggregate = {
        "timestamp": timestamp,
        "engine": engine_name,
        "binding": "python",
        "detail_level": "DETAILED",
        "template_dir": str(template_dir),
        "provenance": provenance,
        "templates_total": len(results),
        "templates_ok": len(successful_results),
        "templates_failed": len(failed_results),
        "iterations_per_template": iterations,
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_file_count": corpus_file_count,
        "run_fingerprint": run_fp,
        "performance": {
            "module_load_ms": _round4(import_elapsed_ms),
            "startup": _startup_section(startup),
            "init_ms": _stats_json(init_samples_ms),
            "cold_init_ms": _round4(cold_init_ms),
            "warm_init_ms": _stats_json(warm_init_samples_ms),
            "subsequent_init_ms": _stats_json(subsequent_init_samples_ms),
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
            "first_measured_engine_internal_ms": _stats_json(first_measured_engine_internal_vec),
            "subsequent_engine_internal_ms": _stats_json(subsequent_engine_internal_vec),
            "cold_engine_internal_ms": _stats_json(cold_engine_internal_vec),
            "warm_engine_internal_ms": _stats_json(warm_engine_internal_vec),
            "wall_clock_ms": _stats_json(wall_clock_vec),
            "first_measured_wall_clock_ms": _stats_json(first_measured_wall_clock_vec),
            "subsequent_wall_clock_ms": _stats_json(subsequent_wall_clock_vec),
            "cold_wall_clock_ms": _stats_json(cold_wall_clock_vec),
            "warm_wall_clock_ms": _stats_json(warm_wall_clock_vec),
            "host_model_ms": _stats_json(host_model_vec),
            "first_measured_host_model_ms": _stats_json(first_measured_host_model_vec),
            "subsequent_host_model_ms": _stats_json(subsequent_host_model_vec),
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

    # Fingerprint file for cache invalidation.
    fingerprint_path = output_dir / "run_fingerprint.txt"
    try:
        fingerprint_path.write_text(run_fp, encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: failed to write fingerprint {fingerprint_path}: {exc}", file=sys.stderr)
        sys.exit(1)

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

#!/usr/bin/env python3
"""Runs benchmarks for every engine × binding and writes a comparison report.

Subsequent distributions are per-template medians of iterations 2..N; throughput
divides all timed ``validate()`` calls by the measured wall time.
"""

import argparse
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
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
DEFAULT_STARTUP_SAMPLES = 5
MIN_STARTUP_SAMPLES = 2

# median/p99/max: median is the typical cost, p99 the tail, max the worst case.
STATS = ["median", "p99", "max"]

# Rust-internal phase timers surfaced in every binding (apples-to-apples).
PHASE_ROWS = [
    ("model build",         "model_build_ms"),
    ("schema validate",     "schema_validate_ms"),
    ("rule evaluation",     "rule_evaluation_ms"),
    ("diagnostic finalize", "diagnostic_finalize_ms"),
]

REQUIRED_SUBSEQUENT_METRICS = [
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

# External process timer used to measure startup and full-corpus memory. The
# GNU coreutils build ("-v") and the macOS build ("-l") report different
# formats and different RSS units, handled by the two parsers below.
TIME_BIN = "/usr/bin/time"

NATIVE_BENCH_BIN = SRC_DIR / "target" / "release" / "cfn-benchmark"
WASM_BENCH_DIR = SRC_DIR / "bindings-wasm" / "bench"
WASM_BENCH_JS = WASM_BENCH_DIR / "build" / "benchmark.js"
JVM_BENCH_DIR = SRC_DIR / "bindings-jvm" / "bench"
JVM_BENCH_BIN = (
    JVM_BENCH_DIR / "build" / "install" / "cloudformation-validate-bench" / "bin"
    / "cloudformation-validate-bench"
)
PYTHON_BENCH_DIR = SRC_DIR / "bindings-python" / "bench"
PYTHON_VENV_PYTHON = PYTHON_BENCH_DIR / ".venv" / "bin" / "python"
PYTHON_BENCH_SCRIPT = PYTHON_BENCH_DIR / "benchmark.py"
GO_BENCH_DIR = SRC_DIR / "bindings-go" / "bench"
GO_BENCH_BIN = GO_BENCH_DIR / "build" / "cfn-benchmark-go"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run benchmarks for every engine × binding and write a comparison report.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building artifacts; validate that the prebuilt executables already exist.",
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
        "--startup-samples",
        type=int,
        default=DEFAULT_STARTUP_SAMPLES,
        help=(
            f"Independent startup-probe processes per engine×binding "
            f"(>= {MIN_STARTUP_SAMPLES}, default {DEFAULT_STARTUP_SAMPLES}). The first is the "
            f"cold sample; the rest form the warm distribution."
        ),
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
    if args.startup_samples < MIN_STARTUP_SAMPLES:
        parser.error(f"--startup-samples must be >= {MIN_STARTUP_SAMPLES}")
    if not args.template_dir.is_dir():
        parser.error(f"--template-dir is not a directory: {args.template_dir}")
    args.template_dir = args.template_dir.resolve()
    return args


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


def corpus_command(binding, engine, iterations, template_dir):
    """The native binary keeps ``--format detailed`` so its invocation stays identical
    to the one ``compare_cfnlint.py`` relies on. The FFI harnesses hardcode DETAILED
    and reject ``--format``, so it is passed to native only.
    """
    template = str(template_dir)
    if binding == "native":
        return (
            [str(NATIVE_BENCH_BIN), template, "--engine", engine,
             "--format", "detailed", "--iterations", str(iterations)],
            SRC_DIR,
        )
    if binding == "wasm":
        return (
            ["node", str(WASM_BENCH_JS), template, "--engine", engine,
             "--iterations", str(iterations)],
            WASM_BENCH_DIR,
        )
    if binding == "jvm":
        return (
            [str(JVM_BENCH_BIN), template, "--engine", engine,
             "--iterations", str(iterations)],
            JVM_BENCH_DIR,
        )
    if binding == "python":
        return (
            [str(PYTHON_VENV_PYTHON), str(PYTHON_BENCH_SCRIPT), template, "--engine", engine,
             "--iterations", str(iterations)],
            PYTHON_BENCH_DIR,
        )
    if binding == "go":
        return (
            [str(GO_BENCH_BIN), template, "--engine", engine,
             "--iterations", str(iterations)],
            GO_BENCH_DIR,
        )
    raise ValueError(f"unknown binding: {binding}")


def probe_command(binding, engine):
    if binding == "native":
        return ([str(NATIVE_BENCH_BIN), "--engine", engine, "--startup-probe"], SRC_DIR)
    if binding == "wasm":
        return (["node", str(WASM_BENCH_JS), "--engine", engine, "--startup-probe"], WASM_BENCH_DIR)
    if binding == "jvm":
        return ([str(JVM_BENCH_BIN), "--engine", engine, "--startup-probe"], JVM_BENCH_DIR)
    if binding == "python":
        return (
            [str(PYTHON_VENV_PYTHON), str(PYTHON_BENCH_SCRIPT), "--engine", engine, "--startup-probe"],
            PYTHON_BENCH_DIR,
        )
    if binding == "go":
        return ([str(GO_BENCH_BIN), "--engine", engine, "--startup-probe"], GO_BENCH_DIR)
    raise ValueError(f"unknown binding: {binding}")


def executable_path(binding):
    return {
        "native": NATIVE_BENCH_BIN,
        "wasm": WASM_BENCH_JS,
        "jvm": JVM_BENCH_BIN,
        "python": PYTHON_VENV_PYTHON,
        "go": GO_BENCH_BIN,
    }.get(binding)


def run_cmd(cmd, cwd, label):
    print(f"  $ {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    result = subprocess.run([str(c) for c in cmd], cwd=str(cwd))
    if result.returncode != 0:
        sys.exit(f"{label} failed (exit {result.returncode})")


def build_all(bindings):
    binding_ids = {b for b, _ in bindings}

    if "native" in binding_ids:
        print("=== Building native Rust (release) ===", file=sys.stderr)
        run_cmd(["cargo", "build", "--locked", "--release", "--workspace"], SRC_DIR, "cargo build")

    if "wasm" in binding_ids:
        print("=== Building WASM package + bench ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-wasm" / "build.sh")],
                SRC_DIR / "bindings-wasm", "WASM build")
        if (WASM_BENCH_DIR / "package-lock.json").exists():
            run_cmd(["npm", "ci", "--silent"], WASM_BENCH_DIR, "npm ci (wasm bench)")
        else:
            run_cmd(["npm", "install", "--silent"], WASM_BENCH_DIR, "npm install (wasm bench)")
        # Compile benchmark.ts -> build/benchmark.js so the corpus/probe commands run
        # plain `node build/benchmark.js` instead of ts-node.
        run_cmd(["npx", "tsc", "-p", "tsconfig.json"], WASM_BENCH_DIR, "compile wasm bench (tsc)")

    if "jvm" in binding_ids:
        print("=== Building JVM native library + bindings + bench ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-jvm" / "build.sh")],
                SRC_DIR / "bindings-jvm", "JVM build")
        gradle = str(JVM_BENCH_DIR / "gradlew") if (JVM_BENCH_DIR / "gradlew").exists() else "gradle"
        run_cmd([gradle, "installDist", "--no-daemon"], JVM_BENCH_DIR, "jvm bench installDist")

    if "python" in binding_ids:
        print("=== Building Python wheel + bench venv ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-python" / "build.sh")],
                SRC_DIR / "bindings-python", "Python build")
        PYTHON_BENCH_DIR.mkdir(parents=True, exist_ok=True)
        venv_dir = PYTHON_BENCH_DIR / ".venv"
        if not venv_dir.exists():
            run_cmd(["python3", "-m", "venv", str(venv_dir)], PYTHON_BENCH_DIR, "create bench venv")
        venv_pip = str(venv_dir / "bin" / "pip")
        wheel_dir = SRC_DIR / "bindings-python" / "generated" / "dist"
        wheels = sorted(wheel_dir.glob("*.whl"))
        if not wheels:
            sys.exit(f"No wheel found in {wheel_dir}")
        run_cmd([venv_pip, "install", "--force-reinstall", "--quiet", str(wheels[-1])],
                PYTHON_BENCH_DIR, "install wheel into bench venv")

    if "go" in binding_ids:
        print("=== Building Go native library + bindings + bench binary ===", file=sys.stderr)
        run_cmd(["bash", str(SRC_DIR / "bindings-go" / "build.sh")],
                SRC_DIR / "bindings-go", "Go build")
        GO_BENCH_BIN.parent.mkdir(parents=True, exist_ok=True)
        run_cmd(["go", "build", "-o", str(GO_BENCH_BIN), "."], GO_BENCH_DIR, "go bench build")


def validate_executables(bindings):
    missing = []
    for binding, label in bindings:
        path = executable_path(binding)
        if path is None or not path.exists():
            missing.append(f"{label} ({binding}): {path}")
    if missing:
        sys.exit(
            "--skip-build set but prebuilt executables are missing:\n"
            + "\n".join(f"  • {m}" for m in missing)
            + "\nDrop --skip-build to build them."
        )


def _tool_version(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True)
    except Exception:
        return ""
    out = (result.stdout or result.stderr or "").strip().splitlines()
    return out[0].strip() if out else ""


def benchmark_env():
    env = os.environ.copy()
    cargo = _tool_version(["cargo", "--version"])
    rustc = _tool_version(["rustc", "--version"])
    if cargo:
        env["BENCHMARK_CARGO_VERSION"] = cargo
    if rustc:
        env["BENCHMARK_RUSTC_VERSION"] = rustc
    return env


def detect_time_flavor():
    if not Path(TIME_BIN).exists():
        return None
    try:
        gnu = subprocess.run([TIME_BIN, "-v", "true"], capture_output=True, text=True)
        if "Maximum resident set size" in (gnu.stderr or ""):
            return "gnu"
    except OSError:
        return None
    if platform.system() != "Darwin":
        return None
    try:
        macos = subprocess.run([TIME_BIN, "-l", "true"], capture_output=True, text=True)
        if "maximum resident set size" in (macos.stderr or ""):
            return "macos"
    except OSError:
        return None
    return None


def _parse_gnu_elapsed(value):
    parts = value.split(":")
    try:
        nums = [float(p) for p in parts]
    except ValueError:
        return None
    if len(nums) == 3:
        hours, minutes, seconds = nums
    elif len(nums) == 2:
        hours, minutes, seconds = 0.0, nums[0], nums[1]
    elif len(nums) == 1:
        hours, minutes, seconds = 0.0, 0.0, nums[0]
    else:
        return None
    return (hours * 3600.0 + minutes * 60.0 + seconds) * 1000.0


def parse_gnu_time(report):
    wall_ms = None
    rss_bytes = None
    for raw in report.splitlines():
        line = raw.strip()
        if line.startswith("Elapsed (wall clock) time"):
            _, sep, value = line.partition("): ")
            if sep:
                wall_ms = _parse_gnu_elapsed(value.strip())
        elif line.startswith("Maximum resident set size"):
            _, sep, value = line.rpartition(":")
            if sep:
                try:
                    rss_bytes = int(float(value.strip())) * 1024
                except ValueError:
                    rss_bytes = None
    return wall_ms, rss_bytes


def parse_macos_time(report):
    wall_ms = None
    rss_bytes = None
    for raw in report.splitlines():
        line = raw.strip()
        if not line:
            continue
        tokens = line.split()
        if wall_ms is None and "real" in tokens:
            idx = tokens.index("real")
            if idx > 0:
                try:
                    wall_ms = float(tokens[idx - 1]) * 1000.0
                except ValueError:
                    wall_ms = None
        if line.endswith("maximum resident set size") and tokens:
            try:
                rss_bytes = int(tokens[0])
            except ValueError:
                rss_bytes = None
    return wall_ms, rss_bytes


def run_with_time(cmd, cwd, env, flavor):
    flag = "-v" if flavor == "gnu" else "-l"
    fd, time_path = tempfile.mkstemp(prefix="cfnbench-time-", suffix=".txt")
    os.close(fd)
    try:
        wrapped = [TIME_BIN, flag, "-o", time_path, *[str(c) for c in cmd]]
        proc = subprocess.run(wrapped, cwd=str(cwd), env=env, capture_output=True, text=True)
        report = Path(time_path).read_text()
    finally:
        try:
            os.unlink(time_path)
        except OSError:
            pass
    parser = parse_gnu_time if flavor == "gnu" else parse_macos_time
    wall_ms, rss_bytes = parser(report)
    return proc, wall_ms, rss_bytes


def _parse_probe_json(stdout, binding, engine):
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        sys.exit(f"startup probe for {binding}/{engine} produced no JSON on stdout")
    try:
        data = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        sys.exit(f"startup probe for {binding}/{engine} emitted invalid JSON: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"startup probe for {binding}/{engine} JSON is not an object")
    probe_binding = data.get("binding")
    if probe_binding is not None and probe_binding != binding:
        sys.exit(f"startup probe binding mismatch: expected '{binding}', got {probe_binding!r}")
    probe_engine = data.get("engine")
    if probe_engine is not None and probe_engine != engine:
        sys.exit(f"startup probe engine mismatch: expected '{engine}', got {probe_engine!r}")
    return data


def run_startup_probes(binding, engine, samples, env, flavor):
    cmd, cwd = probe_command(binding, engine)
    print(f"=== {binding} startup probe (engine={engine}, samples={samples}) ===", file=sys.stderr)
    collected = []
    for index in range(samples):
        proc, wall_ms, rss_bytes = run_with_time(cmd, cwd, env, flavor)
        if proc.returncode != 0:
            sys.exit(
                f"startup probe failed for {binding}/{engine} "
                f"(sample {index + 1}/{samples}, exit {proc.returncode}):\n{proc.stderr.strip()}"
            )
        if wall_ms is None or rss_bytes is None:
            sys.exit(f"could not parse /usr/bin/time output for {binding}/{engine} startup probe")
        data = _parse_probe_json(proc.stdout, binding, engine)
        collected.append({"json": data, "wall_ms": wall_ms, "rss_bytes": rss_bytes})
    return collected


def run_corpus(binding, engine, iterations, template_dir, env, flavor):
    cmd, cwd = corpus_command(binding, engine, iterations, template_dir)
    print(f"=== {binding} corpus benchmark (engine={engine}) ===", file=sys.stderr)
    print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    proc, wall_ms, rss_bytes = run_with_time(cmd, cwd, env, flavor)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        sys.exit(f"{binding} corpus benchmark failed (engine={engine}, exit {proc.returncode})")
    if rss_bytes is None:
        sys.exit(f"could not parse /usr/bin/time RSS for {binding}/{engine} corpus run")
    return wall_ms, rss_bytes


def _median(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    if n % 2 == 0:
        return (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0
    return ordered[n // 2]


def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (pct / 100.0) * (len(ordered) - 1)
    lo = math.floor(rank)
    hi = min(math.ceil(rank), len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + frac * (ordered[hi] - ordered[lo])


def compute_stats(values):
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return {"count": 0, "min": 0.0, "avg": 0.0, "median": 0.0,
                "p90": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    return {
        "count": len(nums),
        "min": round(min(nums), 4),
        "avg": round(sum(nums) / len(nums), 4),
        "median": round(_median(nums), 4),
        "p90": round(_percentile(nums, 90), 4),
        "p95": round(_percentile(nums, 95), 4),
        "p99": round(_percentile(nums, 99), 4),
        "max": round(max(nums), 4),
    }


def aggregate_process_startup(samples):
    if len(samples) < MIN_STARTUP_SAMPLES:
        sys.exit(f"startup aggregation requires >= {MIN_STARTUP_SAMPLES} samples")
    cold = samples[0]
    warm = samples[1:]
    cold_json = cold["json"]
    startup_name = cold_json.get("startup_template")
    if not isinstance(startup_name, str) or not startup_name:
        sys.exit("cold startup probe JSON missing string 'startup_template'")

    cold_section = {
        "consumer_init_ms": get(cold_json, "consumer_init", "duration_ms"),
        "first_validation_host_ms": get(cold_json, "first_validation", "host_ms"),
        "module_load_ms": cold_json.get("module_load_ms"),
        "schema_init_ms": cold_json.get("schema_init_ms"),
        "engine_init_ms": cold_json.get("engine_init_ms"),
        "internal_time_to_first_result_ms": cold_json.get("internal_time_to_first_result_ms"),
        "process_wall_ms": round(float(cold["wall_ms"]), 4),
        "process_peak_rss_bytes": int(cold["rss_bytes"]),
    }
    warm_section = {
        "count": len(warm),
        "process_wall_ms": compute_stats([s["wall_ms"] for s in warm]),
        "process_peak_rss_bytes": compute_stats([s["rss_bytes"] for s in warm]),
        "consumer_init_ms": compute_stats([get(s["json"], "consumer_init", "duration_ms") for s in warm]),
        "first_validation_host_ms": compute_stats([get(s["json"], "first_validation", "host_ms") for s in warm]),
    }
    return {
        "startup_template": startup_name,
        "samples": len(samples),
        "cold": cold_section,
        "warm": warm_section,
    }


def enrich_aggregate(path, process_startup, corpus_rss_bytes):
    with open(path) as f:
        data = json.load(f)
    data["process_startup"] = process_startup
    memory = data.get("memory")
    if not isinstance(memory, dict):
        memory = {}
    memory["full_corpus_peak_rss_bytes"] = int(corpus_rss_bytes)
    data["memory"] = memory
    tmp_path = path.with_name(path.name + ".tmp")
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(str(tmp_path), str(path))


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

    provenance = data.get("provenance")
    if not isinstance(provenance, dict):
        sys.exit(f"aggregate {path}: missing 'provenance' object")
    for field in ("cloudformation_validate", "cargo", "rustc", "runtime"):
        pv = provenance.get(field)
        if not isinstance(pv, str) or not pv:
            sys.exit(f"aggregate {path}: provenance.{field} must be a nonempty string")

    startup = get(data, "performance", "startup")
    if not isinstance(startup, dict):
        sys.exit(f"aggregate {path}: missing 'performance.startup' object")
    if not _is_finite_number(get(startup, "consumer_init", "duration_ms")):
        sys.exit(f"aggregate {path}: performance.startup.consumer_init.duration_ms is not a finite number")
    if not _is_finite_number(get(startup, "first_validation", "host_ms")):
        sys.exit(f"aggregate {path}: performance.startup.first_validation.host_ms is not a finite number")

    process_startup = data.get("process_startup")
    if not isinstance(process_startup, dict):
        sys.exit(f"aggregate {path}: missing 'process_startup' object (run benchmarks to enrich it)")
    cold = process_startup.get("cold")
    if not isinstance(cold, dict):
        sys.exit(f"aggregate {path}: missing 'process_startup.cold' object")
    for field in ("consumer_init_ms", "first_validation_host_ms", "process_wall_ms", "process_peak_rss_bytes"):
        if not _is_finite_number(cold.get(field)):
            sys.exit(f"aggregate {path}: process_startup.cold.{field} is not a finite number (got {cold.get(field)!r})")
    warm = process_startup.get("warm")
    if not isinstance(warm, dict):
        sys.exit(f"aggregate {path}: missing 'process_startup.warm' object")
    for field in ("process_wall_ms", "process_peak_rss_bytes"):
        if not isinstance(warm.get(field), dict):
            sys.exit(f"aggregate {path}: process_startup.warm.{field} must be a stats object")

    if not _is_finite_number(get(data, "memory", "full_corpus_peak_rss_bytes")):
        sys.exit(f"aggregate {path}: memory.full_corpus_peak_rss_bytes is not a finite number")


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
    4. benchmarkMetrics.subsequent is canonical: sampleCount is a non-negative integer;
       zero requires all REQUIRED_SUBSEQUENT_METRICS null, positive requires them finite.
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

                metrics = data.get("benchmarkMetrics", {})
                subsequent = metrics.get("subsequent", {}) if isinstance(metrics, dict) else {}
                if not isinstance(subsequent, dict):
                    errors.append(
                        f"{key}: {json_file.name} benchmarkMetrics.subsequent must be an object"
                    )
                else:
                    sample_count = subsequent.get("sampleCount")
                    if isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < 0:
                        errors.append(
                            f"{key}: {json_file.name} benchmarkMetrics.subsequent.sampleCount "
                            f"must be a non-negative integer (got {sample_count!r})"
                        )
                    else:
                        for metric_name in REQUIRED_SUBSEQUENT_METRICS:
                            val = subsequent.get(metric_name)
                            if sample_count == 0:
                                if val is not None:
                                    errors.append(
                                        f"{key}: {json_file.name} benchmarkMetrics.subsequent."
                                        f"{metric_name} must be null when sampleCount is 0 (got {val!r})"
                                    )
                            elif not _is_finite_number(val):
                                errors.append(
                                    f"{key}: {json_file.name} benchmarkMetrics.subsequent."
                                    f"{metric_name} is not a finite number (got {val!r})"
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


PCT_FLOOR_MS = 0.01


def stat(stats_dict, key):
    """Return (value, present). Present=False means the key was absent."""
    if isinstance(stats_dict, dict) and key in stats_dict:
        return float(stats_dict[key]), True
    return 0.0, False


def _present(value):
    if not _is_finite_number(value):
        return 0.0, False
    return float(value), True


def _stat_present(stats_dict, key):
    if not isinstance(stats_dict, dict) or stats_dict.get("count", 0) == 0:
        return 0.0, False
    return _present(stats_dict.get(key))


def _stat_value(stats_dict, key):
    value, present = _stat_present(stats_dict, key)
    return value if present else None


def ms(val, present=True, digits=4):
    return f"{val:.{digits}f}" if present else "-"


def fmt_bytes(n):
    if not _is_finite_number(n):
        return "-"
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024.0 or unit == "GiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GiB"


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


def top_slowest_section(all_detailed, engines, bindings, top_n):
    """Generate top-N slowest template tables for each engine × binding.

    Each table shows wall, rule, schema, and model subsequent metrics,
    sorted descending by subsequent wallClockMs.

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
        f"## Top-{top_n} Slowest Templates (subsequent wall clock)", "",
        "Per engine × binding: templates with the highest subsequent "
        "`wallClockMs` (median of iterations 2..N). Templates with no subsequent "
        "samples (single-iteration runs) are omitted. Columns: wall (total validate), "
        "rule (rule evaluation), schema (schema validation), model (model build) — all "
        "in milliseconds.", "",
    ]

    for engine in engines:
        lines.append(f"### {engine.upper()}")
        lines.append("")
        for binding, label in bindings:
            reports = all_detailed[engine][binding]

            template_metrics = []
            for file_path, data in reports.items():
                subsequent = get(data, "benchmarkMetrics", "subsequent", default={})
                if not isinstance(subsequent, dict) or subsequent.get("sampleCount", 0) == 0:
                    continue
                wall = subsequent.get("wallClockMs")
                rule = subsequent.get("ruleEvaluationMs")
                schema = subsequent.get("schemaValidateMs")
                model = subsequent.get("modelBuildMs")
                if not all(_is_finite_number(v) for v in (wall, rule, schema, model)):
                    continue
                template_metrics.append((file_path, wall, rule, schema, model))

            lines.append(f"**{label}**")
            lines.append("")
            if not template_metrics:
                lines.append("_No subsequent samples (single-iteration run)._")
                lines.append("")
                continue

            template_metrics.sort(key=lambda x: x[1], reverse=True)
            top = template_metrics[:top_n]

            header = ["#", "Template", "Wall (ms)", "Rule (ms)", "Schema (ms)", "Model (ms)"]
            rows = []
            for i, (fp, wall, rule, schema, model) in enumerate(top, 1):
                display_path = fp if len(fp) <= 60 else "…" + fp[-57:]
                rows.append([
                    str(i), display_path,
                    f"{wall:.4f}", f"{rule:.4f}", f"{schema:.4f}", f"{model:.4f}",
                ])

            lines += table(header, rows)
            lines.append("")

    return lines


def paired_engine_comparison(all_detailed, bindings):
    """Paired Rego-vs-CEL analysis per binding.

    For each binding, computes:
    - Representative corpus-pass sums (sum of per-template subsequent wallClockMs
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
        "Per-binding paired analysis using subsequent per-template metrics. "
        "Each template is compared across engines using the same binding, so "
        "differences reflect engine behavior rather than binding overhead.", "",
        "**Metric definitions:**", "",
        "- **Corpus-pass sum**: representative sum of per-template subsequent "
        "`wallClockMs` medians across templates with subsequent samples — the total "
        "typical validation work for one full corpus pass. This is a sum of medians, "
        "not a measured elapsed time or throughput. Tail outliers (high p99/max) can "
        "make throughput figures close even when typical (median) per-template costs "
        "differ noticeably between engines.",
        "- **Direction ratio**: `sum(Rego subsequent wall) / sum(CEL subsequent wall)` — "
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
        compared = 0
        deltas = []

        for fp in sorted(common_paths):
            rego_sub = get(rego_reports[fp], "benchmarkMetrics", "subsequent", default={})
            cel_sub = get(cel_reports[fp], "benchmarkMetrics", "subsequent", default={})
            if (not isinstance(rego_sub, dict) or rego_sub.get("sampleCount", 0) == 0
                    or not isinstance(cel_sub, dict) or cel_sub.get("sampleCount", 0) == 0):
                continue

            rw = rego_sub.get("wallClockMs")
            cw = cel_sub.get("wallClockMs")
            rr = rego_sub.get("ruleEvaluationMs")
            cr = cel_sub.get("ruleEvaluationMs")
            if not all(_is_finite_number(v) for v in (rw, cw, rr, cr)):
                continue

            compared += 1
            rego_wall_sum += rw
            cel_wall_sum += cw
            rego_rule_sum += rr
            cel_rule_sum += cr

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

        lines.append(f"### {label}")
        lines.append("")
        if compared == 0:
            lines.append("_No subsequent samples to compare (single-iteration run)._")
            lines.append("")
            continue

        deltas.sort(key=lambda x: x[3], reverse=True)

        direction_ratio = (rego_wall_sum / cel_wall_sum) if cel_wall_sum > 0 else float("inf")
        rule_ratio = (rego_rule_sum / cel_rule_sum) if cel_rule_sum > 0 else float("inf")

        lines.append(f"**Templates compared:** {compared}")
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


def _first_steady_tables(all_loaded, engine, key_prefix, bindings):
    def build(mode_key):
        header = ["Binding"] + [s for s in STATS]
        rows = []
        for b, lbl in bindings:
            d = get(all_loaded[engine][b], "performance", f"{mode_key}_{key_prefix}_ms", default={})
            rows.append([lbl] + [ms(*_stat_present(d, stat_name)) for stat_name in STATS])
        return table(header, rows)

    lines = [
        "**First corpus measurement** - first per-template sample (ms)", "",
    ]
    lines += build("first_measured")
    lines += [
        "",
        "**Subsequent corpus measurements** - subsequent iterations per template (ms)", "",
    ]
    lines += build("subsequent")
    lines += [""]
    return lines


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


def provenance_section(all_loaded, engines, bindings):
    first_agg = all_loaded[engines[0]][bindings[0][0]]
    core = get(first_agg, "provenance", "cloudformation_validate", default="unknown")
    cargo = get(first_agg, "provenance", "cargo", default="unknown")
    rustc = get(first_agg, "provenance", "rustc", default="unknown")

    lines = ["## Provenance", "",
             "Recorded from each binding's aggregate. The core `cloudformation-validate` "
             "version, Cargo, and rustc are the exact tool versions used to build the native "
             "core (injected into the harness environment so measurement is not contaminated "
             "by version queries). Each binding additionally reports the artifact it ships as "
             "and its runtime.", "",
             f"- **cloudformation-validate**: {core}",
             f"- **cargo**: {cargo}",
             f"- **rustc**: {rustc}", ""]

    header = ["Binding", "Artifact", "Artifact version", "Runtime"]
    rows = []
    for b, lbl in bindings:
        agg = all_loaded[engines[0]][b]
        kind = get(agg, "provenance", "binding_artifact", "kind", default="unknown")
        version = get(agg, "provenance", "binding_artifact", "version", default="unknown")
        runtime = get(agg, "provenance", "runtime", default="unknown")
        rows.append([lbl, str(kind), str(version), str(runtime)])
    lines += table(header, rows) + [""]
    return lines


def latency_memory_summary(all_loaded, engines, bindings):
    lines = ["## Latency & Memory Summary", "",
             "One row per binding. Latency columns are milliseconds; memory columns are "
             "peak resident set size (RSS).", "",
             "- **Module load**: module/binding initialization from the cold startup-probe "
             "process, measured before consumer init (`process_startup.cold.module_load_ms`).",
             "- **First init** / **First validation**: the cold startup-probe process — its "
             "in-process consumer setup and first `validate()` call (`process_startup.cold`).",
             "- **Subseq median/p99**: subsequent per-template validation latency from the "
             "corpus run (iterations 2..N; `-` when a single iteration leaves no subsequent "
             "window).",
             "- **Cold wall/RSS**: the first (cold) startup-probe process, measured externally "
             "by `/usr/bin/time`.",
             "- **Warm wall median/p99 + RSS**: the remaining startup-probe processes.",
             "- **Corpus RSS**: peak RSS of the full corpus benchmark process.",
             "- **Throughput**: ok × iterations / measured validation wall time.", ""]

    header = ["Binding", "Module load (ms)", "First init (ms)", "First val (ms)", "Subseq median (ms)",
              "Subseq p99 (ms)", "Cold wall (ms)", "Cold RSS", "Warm wall median (ms)",
              "Warm wall p99 (ms)", "Warm RSS", "Corpus RSS", "Throughput (val/s)"]

    for engine in engines:
        rows = []
        for b, lbl in bindings:
            agg = all_loaded[engine][b]
            cold = get(agg, "process_startup", "cold", default={})
            warm = get(agg, "process_startup", "warm", default={})
            subseq = get(agg, "performance", "subsequent_wall_clock_ms", default={})
            warm_wall = warm.get("process_wall_ms", {}) if isinstance(warm, dict) else {}
            warm_rss = warm.get("process_peak_rss_bytes", {}) if isinstance(warm, dict) else {}
            rows.append([
                lbl,
                ms(*_present(cold.get("module_load_ms"))),
                ms(*_present(cold.get("consumer_init_ms"))),
                ms(*_present(cold.get("first_validation_host_ms"))),
                ms(*_stat_present(subseq, "median")),
                ms(*_stat_present(subseq, "p99")),
                ms(*_present(cold.get("process_wall_ms"))),
                fmt_bytes(cold.get("process_peak_rss_bytes")),
                ms(*_stat_present(warm_wall, "median")),
                ms(*_stat_present(warm_wall, "p99")),
                fmt_bytes(_stat_value(warm_rss, "median")),
                fmt_bytes(get(agg, "memory", "full_corpus_peak_rss_bytes")),
                ms(recomputed_throughput(agg), True, 2),
            ])
        lines += [f"### {engine.upper()}", ""] + table(header, rows) + [""]
    return lines


def model_section(all_loaded, engine, bindings):
    lines = ["### Template Modeling - host-timed `SemanticModel::parse` (ms)", "",
             "Host timer around `SemanticModel::parse` (bytes → resolved model). "
             "Standalone measurement; does not include the re-parse inside `validate()`.", ""]
    lines += _first_steady_tables(all_loaded, engine, "host_model", bindings)
    return lines


def phase_table(all_loaded, engine, bindings):
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
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
    }


def run_all_benchmarks(engines, bindings, args, flavor):
    env = benchmark_env()
    plan = build_run_plan(engines, bindings)
    for binding, engine in plan:
        probes = run_startup_probes(
            binding, engine, args.startup_samples, env, flavor
        )
        _corpus_wall_ms, corpus_rss_bytes = run_corpus(
            binding, engine, args.iterations, args.template_dir, env, flavor
        )
        process_startup = aggregate_process_startup(probes)
        enrich_aggregate(aggregate_path(engine, FORMATS[0], binding), process_startup, corpus_rss_bytes)


def build_report(all_loaded, all_detailed, engines, bindings, args, corpus_fp, corpus_file_count):
    host = host_metadata()
    lines = [
        "# Benchmark Comparison",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Host", "",
        *[f"- **{k}**: {v}" for k, v in host.items()],
        f"- **iterations/template**: {args.iterations}",
        f"- **startup samples/binding**: {args.startup_samples} (1 cold + "
        f"{args.startup_samples - 1} warm)",
        f"- **corpus fingerprint**: `{corpus_fp}` ({corpus_file_count} files)",
        f"- **bindings**: {', '.join(lbl for _, lbl in bindings)} ({len(bindings)} total)",
        f"- **engines**: {', '.join(e.upper() for e in engines)}",
        "",
    ]

    lines += provenance_section(all_loaded, engines, bindings)

    lines += [
        "## Methodology Notes", "",
        "### Process startup (cold vs warm) - externally measured", "",
        "Startup is measured by launching independent OS processes of each binding's "
        "benchmark harness in `--startup-probe` mode, each wrapped with `/usr/bin/time`. "
        "A probe constructs the real consumer validation setup (schema validator + engine) "
        "and performs the first `validate()` call on a single small template, printing a "
        "JSON object with the in-process init and first-validation timings. `/usr/bin/time` "
        "reports that process's external wall time and peak RSS (GNU `-v` reports RSS in "
        "kbytes and is scaled to bytes; macOS `-l` reports bytes directly).", "",
        "The **first** probe process is the **cold** sample: the first fresh benchmark "
        "process observed for that engine × binding after the build. Its process-local "
        "state (loaded modules, allocator arenas, and the freshly constructed schema "
        "validator and engine) is new, but the OS page cache and filesystem caches are "
        "not dropped and may already be warm from the build and preceding probes, so this "
        "is not a genuine machine-cold start. The **remaining** probe processes form the "
        "**warm** distribution: later independent fresh processes — each a new process "
        "rather than reuse of one already-initialized process — so their spread reflects "
        "typical process-launch cost rather than first-ever construction.", "",
        "### Consumer-init boundaries differ by binding", "",
        "Consumer-init boundaries differ by binding. The WASM binding prewarms embedded "
        "data during module initialization, so some setup appears in module load rather "
        "than First init. Because that split is not directly comparable across bindings, "
        "the cold process wall is the comparable end-to-end startup metric.", "",
        "### Aggregate cold_*/warm_* fields are corpus aliases", "",
        "The raw per-binding aggregate `cold_*` and `warm_*` fields are compatibility "
        "aliases for the `first_measured_*` and `subsequent_*` corpus metrics and are not "
        "process cold/warm startup measurements. This report's canonical cold/warm startup "
        "figures come from `process_startup`.", "",
        "### Subsequent validation latency vs throughput", "",
        "Normal mode performs one process-first startup validation, then times the corpus "
        "`validate()` calls on that same already-initialized process. **Subsequent "
        "distributions** are per-template medians of iterations 2..N from the corpus run; "
        "the first timed corpus call is reported separately as the \"first corpus "
        "measurement\". When N=1 there is no subsequent window and the subsequent columns "
        "render `-`.", "",
        "**Throughput** uses all timed `validate()` calls (iterations 1..N × templates_ok) "
        "divided by the aggregate `measured_validation_wall_ms` - a sustained processing "
        "rate, not a per-template latency percentile.", "",
        "**Corpus-pass sums** (in the Paired Engine Comparison) are representative sums of "
        "per-template subsequent medians - not a measured elapsed time or throughput.", "",
        "### Memory", "",
        "**Cold/warm RSS** are the peak RSS of the startup-probe processes. **Corpus RSS** "
        "(`memory.full_corpus_peak_rss_bytes`) is the peak RSS of the full corpus benchmark "
        "process. Each harness writes one template's detailed report before processing the "
        "next, outside the per-call validation timers, so the peak includes the runtime, "
        "engine, corpus bookkeeping, and at most one detailed report serialization rather "
        "than a corpus-sized report queue.", "",
        "### Shared-runner temporal noise", "",
        "CI benchmarks run on shared GitHub Actions runners (`ubuntu-latest`) where "
        "neighboring workloads, CPU frequency scaling, and memory pressure introduce "
        "temporal noise. Intra-run relative comparisons (engine-vs-engine, binding-vs-binding) "
        "are more useful than cross-run absolute numbers. The corpus run pairs engines per "
        "binding and alternates run order (AB/BA) across bindings to distribute warm-up and "
        "load drift; results should be read as directional indicators, not precise "
        "measurements.", "",
    ]

    # Table of contents
    engine_anchors = [f"- [{e.upper()} Engine](#{e}-engine)" for e in engines]
    toc_items = [
        "- [Provenance](#provenance)",
        "- [Methodology Notes](#methodology-notes)",
        "- [Latency & Memory Summary](#latency--memory-summary)",
        *engine_anchors,
    ]
    toc_items.append(
        f"- [Top-{args.top_slowest} Slowest Templates](#top-{args.top_slowest}-slowest-templates-subsequent-wall-clock)"
    )
    if len(engines) == 2 and "rego" in engines and "cel" in engines:
        toc_items.append(
            "- [Paired Engine Comparison](#paired-engine-comparison-rego-vs-cel)"
        )
    toc_items.append("- [Data Sources](#data-sources)")

    lines += ["## Table of Contents", "", *toc_items, ""]
    lines += latency_memory_summary(all_loaded, engines, bindings)

    # Track parity results
    parity_all_passed = True

    for engine in engines:
        lines += [f"## {engine.upper()} Engine", ""]
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

    lines += top_slowest_section(all_detailed, engines, bindings, args.top_slowest)
    if len(engines) == 2 and "rego" in engines and "cel" in engines:
        lines += paired_engine_comparison(all_detailed, bindings)

    lines += data_sources_section(all_loaded, engines, bindings)
    return lines, parity_all_passed


def main(argv=None):
    args = parse_args(argv)

    engines = args.engines if args.engines else ENGINES
    bindings = (
        [(b, lbl) for b, lbl in ALL_BINDINGS if b in args.bindings]
        if args.bindings
        else ALL_BINDINGS
    )

    if args.report_only:
        print("Report-only mode - using existing aggregate files", file=sys.stderr)
        run_start_epoch = 0
    else:
        if not args.skip_build:
            build_all(bindings)
        else:
            print("Skipping builds (--skip-build); validating prebuilt executables", file=sys.stderr)
            validate_executables(bindings)

        flavor = detect_time_flavor()
        if flavor is None:
            sys.exit(
                f"{TIME_BIN} (GNU '-v' or macOS '-l') is required to measure process startup and "
                f"memory but is unavailable. Install it (Linux: 'time' package) or use "
                f"--report-only against existing aggregates."
            )

        run_start_epoch = time.time()
        run_all_benchmarks(engines, bindings, args, flavor)

    all_loaded = {
        e: {b: load_aggregate(aggregate_path(e, FORMATS[0], b), run_start_epoch)
            for b, _ in bindings}
        for e in engines
    }

    enforce_corpus_parity(all_loaded, bindings)
    enforce_run_metadata_parity(all_loaded, bindings)
    corpus_fp = all_loaded[engines[0]][bindings[0][0]].get("corpus_fingerprint")
    corpus_file_count = all_loaded[engines[0]][bindings[0][0]].get("corpus_file_count")

    all_detailed = load_and_validate_detailed_reports(engines, bindings)
    validate_detailed_counts(all_detailed, all_loaded, engines, bindings)

    lines, parity_all_passed = build_report(
        all_loaded, all_detailed, engines, bindings, args, corpus_fp, corpus_file_count
    )

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

#!/usr/bin/env python3
"""Runs benchmarks for every scenario × engine × binding and writes comparison reports.

A *scenario* fixes the rules the engine evaluates: ``builtin`` measures the
built-in rules alone, ``custom`` layers every custom Rego rule file of
``src/resources/rules`` on top, and ``guard`` layers every Guard rule file of
that directory. The single report (``scripts/snapshots/benchmark_comparison.md``)
opens with a cross-scenario summary of what each rule pack costs per engine and
binding, then holds the full engine × binding comparison for every scenario.

The native benchmark builds ``cfn-benchmark`` from the workspace. The WASM, JVM,
Python, and Go benchmarks consume the committed distribution artifacts that the
``build-artifacts`` workflow publishes (``bindings-wasm/dist``, the JVM jar, the
Python wheels, and the Go module's static libraries), so they measure exactly
what consumers install; only each binding's benchmark harness is built here.

Every harness accepts the same command line: ``[TEMPLATE|DIR] --engine E
--iterations N`` for a corpus run, ``--engine E --startup-probe`` for a startup
probe, and for a non-default scenario ``--scenario NAME`` plus
``--guard-rules DIR`` and/or ``--rego-rules DIR`` naming the rules directory
(a harness loads every ``.guard`` / ``.rego`` file below a directory argument).
Its aggregate and per-template reports carry ``scenario``, ``custom_rules``, and
``rules_fingerprint`` so this script can prove every binding measured the same
rules.

Subsequent distributions are per-template medians of iterations 2..N; throughput
divides all timed ``validate()`` calls by the measured wall time.
"""

import argparse
import itertools
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

# Composite uses the CEL built-in implementation and also exercises custom Rego
# composition, so a separate CEL benchmark would measure no additional path.
ENGINES = ["rego", "composite"]
FORMATS = ["detailed"]

# Every .guard file here is the Guard rule pack and every .rego file the custom Rego
# rule pack; harnesses receive the directory rather than a file list.
RULES_DIR = SRC_DIR / "resources" / "rules"

# Recorded by a harness when no --scenario is given; its reports keep the historical
# reports/<engine>/ layout that other tooling reads.
DEFAULT_SCENARIO = "builtin"

SCENARIOS = [
    {
        "id": DEFAULT_SCENARIO,
        "label": "Built-in rules only",
        "engines": ENGINES,
        "guard": False,
        "rego": False,
    },
    {
        "id": "custom",
        "label": "Built-in rules + custom Rego rule pack",
        "engines": ENGINES,
        "guard": False,
        "rego": True,
    },
    {
        "id": "guard",
        "label": "Built-in rules + Guard rule pack",
        "engines": ENGINES,
        "guard": True,
        "rego": False,
    },
]
SCENARIO_IDS = [scenario["id"] for scenario in SCENARIOS]
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
VALID_ENGINES = set(ENGINES)

# External process timer used to measure startup and full-corpus memory. The
# GNU coreutils build ("-v") and the macOS build ("-l") report different
# formats and different RSS units, handled by the two parsers below. The
# environment variable points at a GNU time built elsewhere on hosts without it.
TIME_BIN = os.environ.get("CFN_BENCHMARK_TIME_BIN", "/usr/bin/time")

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
PYTHON_DISTRIBUTION_NAME = "cloudformation-validate"
GO_BENCH_DIR = SRC_DIR / "bindings-go" / "bench"
GO_BENCH_BIN = GO_BENCH_DIR / "build" / "cfn-benchmark-go"

# Committed distribution artifacts consumed by the binding harnesses. The
# `build-artifacts` workflow owns and commits them; the harness build below never
# regenerates them, so the benchmark measures the artifact consumers install.
WASM_DIST_DIR = SRC_DIR / "bindings-wasm" / "dist"
WASM_DIST_FILES = [
    WASM_DIST_DIR / "package.json",
    WASM_DIST_DIR / "index.js",
    WASM_DIST_DIR / "bindings_wasm.js",
    WASM_DIST_DIR / "bindings_wasm_bg.wasm",
]
JVM_BINDINGS_JAR = SRC_DIR / "bindings-jvm" / "generated" / "cloudformation-validate.jar"
PYTHON_WHEEL_DIR = SRC_DIR / "bindings-python" / "generated" / "dist"
PYTHON_WHEEL_GLOB = "cloudformation_validate-*.whl"
GO_MODULE_DIR = SRC_DIR / "bindings-go" / "go"
GO_GENERATED_BINDINGS_DIR = GO_MODULE_DIR / "internal" / "bindings_go"
GO_STATIC_LIBS_DIR = GO_MODULE_DIR / "libs"
GO_STATIC_LIB_GLOB = "*/libbindings_go.a"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run benchmarks for every scenario × engine × binding and write comparison reports.",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building the native binary and binding harnesses; validate that the "
             "prebuilt executables already exist.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing aggregate files without running benchmarks.",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=SCENARIO_IDS,
        default=None,
        help="Subset of scenarios to benchmark, in canonical order (default: all).",
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


def scenario_by_id(scenario_id):
    for scenario in SCENARIOS:
        if scenario["id"] == scenario_id:
            return scenario
    raise ValueError(f"unknown scenario: {scenario_id}")


def select_scenarios(scenario_ids):
    if not scenario_ids:
        return list(SCENARIOS)
    selected = set(scenario_ids)
    return [scenario for scenario in SCENARIOS if scenario["id"] in selected]


def scenario_engines(scenario, engines):
    return [engine for engine in engines if engine in scenario["engines"]]


def guard_pack_files():
    return sorted(RULES_DIR.glob("*.guard"))


def rego_pack_files():
    return sorted(RULES_DIR.glob("*.rego"))


def scenario_rule_files(scenario):
    return (
        guard_pack_files() if scenario["guard"] else [],
        rego_pack_files() if scenario["rego"] else [],
    )


def scenario_harness_args(scenario):
    """The default scenario adds nothing so its invocation stays byte-for-byte the
    historical one."""
    if scenario["id"] == DEFAULT_SCENARIO:
        return []
    guard_files, rego_files = scenario_rule_files(scenario)
    if scenario["guard"] and not guard_files:
        sys.exit(f"scenario {scenario['id']}: no .guard files found in {RULES_DIR}")
    if scenario["rego"] and not rego_files:
        sys.exit(f"scenario {scenario['id']}: no .rego files found in {RULES_DIR}")
    extra = ["--scenario", scenario["id"]]
    if scenario["guard"]:
        extra += ["--guard-rules", str(RULES_DIR)]
    if scenario["rego"]:
        extra += ["--rego-rules", str(RULES_DIR)]
    return extra


def build_run_plan(scenarios, engines, bindings):
    """Order runs scenario by scenario; within a scenario pair the engines it can
    run per binding and alternate canonical AB/BA order.

    Alternation is based on each binding's position in ``ALL_BINDINGS``, not its
    position in a filtered subset. Thus WASM remains BA even when it is the only
    selected binding, and repeated subset runs retain the same positional bias
    mitigation as the full run.
    """
    if not scenarios or not engines or not bindings:
        return []

    canonical_positions = {binding: index for index, (binding, _) in enumerate(ALL_BINDINGS)}
    plan = []
    for scenario in scenarios:
        runnable = scenario_engines(scenario, engines)
        for selected_index, (binding, _label) in enumerate(bindings):
            position = canonical_positions.get(binding, selected_index)
            ordered_engines = runnable if position % 2 == 0 else list(reversed(runnable))
            plan.extend((scenario["id"], binding, engine) for engine in ordered_engines)
    return plan


def corpus_command(binding, engine, iterations, template_dir, scenario=None):
    """The native binary keeps ``--format detailed`` so its invocation stays identical
    to the one ``compare_cfnlint.py`` relies on. The FFI harnesses hardcode DETAILED
    and reject ``--format``, so it is passed to native only. A non-default scenario
    appends the same ``--scenario``/rule-file flags to every harness.
    """
    template = str(template_dir)
    scenario_args = scenario_harness_args(scenario) if scenario else []
    if binding == "native":
        return (
            [str(NATIVE_BENCH_BIN), template, "--engine", engine,
             "--format", "detailed", "--iterations", str(iterations)] + scenario_args,
            SRC_DIR,
        )
    if binding == "wasm":
        return (
            ["node", str(WASM_BENCH_JS), template, "--engine", engine,
             "--iterations", str(iterations)] + scenario_args,
            WASM_BENCH_DIR,
        )
    if binding == "jvm":
        return (
            [str(JVM_BENCH_BIN), template, "--engine", engine,
             "--iterations", str(iterations)] + scenario_args,
            JVM_BENCH_DIR,
        )
    if binding == "python":
        return (
            [str(PYTHON_VENV_PYTHON), str(PYTHON_BENCH_SCRIPT), template, "--engine", engine,
             "--iterations", str(iterations)] + scenario_args,
            PYTHON_BENCH_DIR,
        )
    if binding == "go":
        return (
            [str(GO_BENCH_BIN), template, "--engine", engine,
             "--iterations", str(iterations)] + scenario_args,
            GO_BENCH_DIR,
        )
    raise ValueError(f"unknown binding: {binding}")


def probe_command(binding, engine, scenario=None):
    scenario_args = scenario_harness_args(scenario) if scenario else []
    if binding == "native":
        return ([str(NATIVE_BENCH_BIN), "--engine", engine, "--startup-probe"] + scenario_args, SRC_DIR)
    if binding == "wasm":
        return (["node", str(WASM_BENCH_JS), "--engine", engine, "--startup-probe"] + scenario_args, WASM_BENCH_DIR)
    if binding == "jvm":
        return ([str(JVM_BENCH_BIN), "--engine", engine, "--startup-probe"] + scenario_args, JVM_BENCH_DIR)
    if binding == "python":
        return (
            [str(PYTHON_VENV_PYTHON), str(PYTHON_BENCH_SCRIPT), "--engine", engine, "--startup-probe"]
            + scenario_args,
            PYTHON_BENCH_DIR,
        )
    if binding == "go":
        return ([str(GO_BENCH_BIN), "--engine", engine, "--startup-probe"] + scenario_args, GO_BENCH_DIR)
    raise ValueError(f"unknown binding: {binding}")


def display_command(cmd):
    return " ".join(str(c) for c in cmd)


def executable_path(binding):
    return {
        "native": NATIVE_BENCH_BIN,
        "wasm": WASM_BENCH_JS,
        "jvm": JVM_BENCH_BIN,
        "python": PYTHON_VENV_PYTHON,
        "go": GO_BENCH_BIN,
    }.get(binding)


def run_cmd(cmd, cwd, label):
    print(f"  $ {display_command(cmd)}", file=sys.stderr)
    result = subprocess.run([str(c) for c in cmd], cwd=str(cwd))
    if result.returncode != 0:
        sys.exit(f"{label} failed (exit {result.returncode})")


def missing_committed_artifacts(binding):
    """Committed distribution artifacts the binding's harness needs but which are absent."""
    if binding == "wasm":
        return [str(p) for p in WASM_DIST_FILES if not p.is_file()]
    if binding == "jvm":
        return [] if JVM_BINDINGS_JAR.is_file() else [str(JVM_BINDINGS_JAR)]
    if binding == "python":
        if any(PYTHON_WHEEL_DIR.glob(PYTHON_WHEEL_GLOB)):
            return []
        return [str(PYTHON_WHEEL_DIR / PYTHON_WHEEL_GLOB)]
    if binding == "go":
        missing = []
        if not GO_GENERATED_BINDINGS_DIR.is_dir():
            missing.append(str(GO_GENERATED_BINDINGS_DIR))
        if not any(GO_STATIC_LIBS_DIR.glob(GO_STATIC_LIB_GLOB)):
            missing.append(str(GO_STATIC_LIBS_DIR / GO_STATIC_LIB_GLOB))
        return missing
    return []


def require_committed_artifacts(bindings):
    """Fail before any build when a selected binding's committed artifact is absent."""
    missing = []
    for binding, label in bindings:
        for path in missing_committed_artifacts(binding):
            missing.append(f"{label} ({binding}): {path}")
    if missing:
        sys.exit(
            "committed distribution artifacts are missing:\n"
            + "\n".join(f"  • {m}" for m in missing)
            + "\nThe build-artifacts workflow commits them; for a local checkout run the "
            "binding's build.sh to regenerate them."
        )


def build_harnesses(bindings):
    """Build the native benchmark binary and each selected binding's benchmark harness.

    The binding harnesses link against the committed distribution artifacts
    (WASM dist, JVM jar, Python wheel, Go module with static libraries) rather than
    rebuilding the bindings, so the measured code is the published artifact.
    """
    binding_ids = {b for b, _ in bindings}
    require_committed_artifacts(bindings)

    if "native" in binding_ids:
        print("=== Building native Rust benchmark binary (release) ===", file=sys.stderr)
        run_cmd(["cargo", "build", "--locked", "--release", "-p", "cfn-validate"], SRC_DIR, "cargo build")

    if "wasm" in binding_ids:
        print(f"=== Building WASM bench against committed {WASM_DIST_DIR} ===", file=sys.stderr)
        if (WASM_BENCH_DIR / "package-lock.json").exists():
            run_cmd(["npm", "ci", "--silent"], WASM_BENCH_DIR, "npm ci (wasm bench)")
        else:
            run_cmd(["npm", "install", "--silent"], WASM_BENCH_DIR, "npm install (wasm bench)")
        # Compile benchmark.ts -> build/benchmark.js so the corpus/probe commands run
        # plain `node build/benchmark.js` instead of ts-node.
        run_cmd(["npx", "tsc", "-p", "tsconfig.json"], WASM_BENCH_DIR, "compile wasm bench (tsc)")

    if "jvm" in binding_ids:
        print(f"=== Building JVM bench against committed {JVM_BINDINGS_JAR} ===", file=sys.stderr)
        gradle = str(JVM_BENCH_DIR / "gradlew") if (JVM_BENCH_DIR / "gradlew").exists() else "gradle"
        run_cmd([gradle, "installDist", "--no-daemon"], JVM_BENCH_DIR, "jvm bench installDist")

    if "python" in binding_ids:
        print(f"=== Installing committed wheel from {PYTHON_WHEEL_DIR} into bench venv ===",
              file=sys.stderr)
        PYTHON_BENCH_DIR.mkdir(parents=True, exist_ok=True)
        venv_dir = PYTHON_BENCH_DIR / ".venv"
        if not venv_dir.exists():
            run_cmd(["python3", "-m", "venv", str(venv_dir)], PYTHON_BENCH_DIR, "create bench venv")
        # The wheel directory holds one wheel per supported platform; let pip select the
        # one whose tags match the host instead of guessing from file names.
        run_cmd(
            [str(PYTHON_VENV_PYTHON), "-m", "pip", "install", "--force-reinstall", "--quiet",
             "--no-index", "--find-links", str(PYTHON_WHEEL_DIR), "--only-binary=:all:",
             PYTHON_DISTRIBUTION_NAME],
            PYTHON_BENCH_DIR, "install wheel into bench venv",
        )

    if "go" in binding_ids:
        print(f"=== Building Go bench against committed module {GO_MODULE_DIR} ===", file=sys.stderr)
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


def _parse_probe_json(stdout, binding, engine, scenario_id=DEFAULT_SCENARIO):
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        sys.exit(f"startup probe for {scenario_id}/{binding}/{engine} produced no JSON on stdout")
    try:
        data = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        sys.exit(f"startup probe for {scenario_id}/{binding}/{engine} emitted invalid JSON: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"startup probe for {scenario_id}/{binding}/{engine} JSON is not an object")
    probe_binding = data.get("binding")
    if probe_binding is not None and probe_binding != binding:
        sys.exit(f"startup probe binding mismatch: expected '{binding}', got {probe_binding!r}")
    probe_engine = data.get("engine")
    if probe_engine is not None and probe_engine != engine:
        sys.exit(f"startup probe engine mismatch: expected '{engine}', got {probe_engine!r}")
    # A rule-pack scenario must prove the harness understood the flags; only the
    # default scenario tolerates a probe without the label.
    probe_scenario = data.get("scenario")
    if probe_scenario != scenario_id and not (probe_scenario is None and scenario_id == DEFAULT_SCENARIO):
        sys.exit(f"startup probe scenario mismatch: expected '{scenario_id}', got {probe_scenario!r}")
    return data


def run_startup_probes(binding, engine, samples, env, flavor, scenario):
    cmd, cwd = probe_command(binding, engine, scenario)
    print(
        f"=== {scenario['id']}/{binding} startup probe (engine={engine}, samples={samples}) ===",
        file=sys.stderr,
    )
    collected = []
    for index in range(samples):
        proc, wall_ms, rss_bytes = run_with_time(cmd, cwd, env, flavor)
        if proc.returncode != 0:
            sys.exit(
                f"startup probe failed for {scenario['id']}/{binding}/{engine} "
                f"(sample {index + 1}/{samples}, exit {proc.returncode}):\n{proc.stderr.strip()}"
            )
        if wall_ms is None or rss_bytes is None:
            sys.exit(f"could not parse {TIME_BIN} output for {scenario['id']}/{binding}/{engine} startup probe")
        data = _parse_probe_json(proc.stdout, binding, engine, scenario["id"])
        collected.append({"json": data, "wall_ms": wall_ms, "rss_bytes": rss_bytes})
    return collected


def run_corpus(binding, engine, iterations, template_dir, env, flavor, scenario):
    cmd, cwd = corpus_command(binding, engine, iterations, template_dir, scenario)
    print(f"=== {scenario['id']}/{binding} corpus benchmark (engine={engine}) ===", file=sys.stderr)
    print(f"  $ {display_command(cmd)}", file=sys.stderr)
    proc, wall_ms, rss_bytes = run_with_time(cmd, cwd, env, flavor)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        sys.exit(
            f"{binding} corpus benchmark failed (scenario={scenario['id']}, engine={engine}, "
            f"exit {proc.returncode})"
        )
    if rss_bytes is None:
        sys.exit(f"could not parse {TIME_BIN} RSS for {scenario['id']}/{binding}/{engine} corpus run")
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


def reports_dir(engine, binding, scenario_id=DEFAULT_SCENARIO):
    crate_dir = SRC_DIR / ("cfn-validate" if binding == "native" else f"bindings-{binding}")
    if scenario_id == DEFAULT_SCENARIO:
        return crate_dir / "reports" / engine
    return crate_dir / "reports" / "scenarios" / scenario_id / engine


def aggregate_path(engine, fmt, binding, scenario_id=DEFAULT_SCENARIO):
    return reports_dir(engine, binding, scenario_id) / f"aggregate_{fmt}.json"


def expected_aggregate_files(scenarios, engines, bindings):
    """``(scenario_id, binding, engine, path)`` per run; the workflow validates exactly this list."""
    expected = []
    for scenario in scenarios:
        for binding, _label in bindings:
            for engine in scenario_engines(scenario, engines):
                expected.append(
                    (scenario["id"], binding, engine, aggregate_path(engine, FORMATS[0], binding, scenario["id"]))
                )
    return expected


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

    scenario = data.get("scenario")
    if not isinstance(scenario, str) or scenario not in SCENARIO_IDS:
        sys.exit(f"aggregate {path}: 'scenario' must be one of {SCENARIO_IDS} (got {scenario!r})")
    rules_fp = data.get("rules_fingerprint")
    if not isinstance(rules_fp, str) or not rules_fp:
        sys.exit(f"aggregate {path}: missing or empty 'rules_fingerprint'")
    custom_rules = data.get("custom_rules")
    if not isinstance(custom_rules, dict):
        sys.exit(f"aggregate {path}: missing 'custom_rules' object")
    for kind, fields in (("guard", ("files", "rules", "bytes")), ("rego", ("files", "bytes"))):
        section = custom_rules.get(kind)
        if not isinstance(section, dict):
            sys.exit(f"aggregate {path}: missing 'custom_rules.{kind}' object")
        for field in fields:
            val = section.get(field)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                sys.exit(f"aggregate {path}: custom_rules.{kind}.{field} must be a non-negative integer (got {val!r})")

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


def load_aggregate(path, run_start_epoch, scenario_id=DEFAULT_SCENARIO):
    if not path.exists():
        sys.exit(f"expected aggregate not found: {path}")
    if run_start_epoch > 0:
        mtime = path.stat().st_mtime
        if mtime < run_start_epoch - 1:
            sys.exit(f"stale aggregate {path} (mtime={mtime} < run_start={run_start_epoch})")
    with open(path) as f:
        data = json.load(f)
    _validate_aggregate_structure(data, path)
    if data.get("scenario") != scenario_id:
        sys.exit(f"aggregate {path}: scenario={data.get('scenario')!r} but it was loaded for scenario {scenario_id!r}")
    return data


def enforce_corpus_parity(all_loaded, bindings, scenario_id=DEFAULT_SCENARIO):
    """Every binding of every engine must have scanned the same template bytes and
    loaded the same rule files."""
    for field, what in (("corpus_fingerprint", "corpus"), ("rules_fingerprint", "rules")):
        fps = {}
        for engine, by_binding in all_loaded.items():
            for binding, agg in by_binding.items():
                fp = agg.get(field)
                if not fp:
                    sys.exit(f"{scenario_id}/{engine}/{binding}: aggregate missing {field}. "
                             f"Rebuild + rerun benchmarks against current harness.")
                fps.setdefault(fp, []).append(f"{engine}/{binding}")
        if len(fps) > 1:
            lines = [f"  {fp}: {', '.join(who)}" for fp, who in fps.items()]
            sys.exit(f"{what} fingerprint mismatch across bindings in scenario {scenario_id} - cannot compare:\n"
                     + "\n".join(lines))


def failure_set(agg):
    return sorted((f.get("file"), f.get("status")) for f in (agg.get("failures") or []))


def enforce_run_metadata_parity(all_loaded, bindings, scenario_id=DEFAULT_SCENARIO):
    """Every selected run of a scenario must agree on iteration count, detail level,
    corpus totals, the rule pack it loaded, and failure lists."""
    reference_key = None
    reference_meta = None
    for engine, by_binding in all_loaded.items():
        for binding, agg in by_binding.items():
            meta = {
                "iterations_per_template": agg.get("iterations_per_template"),
                "detail_level": agg.get("detail_level"),
                "corpus_fingerprint": agg.get("corpus_fingerprint"),
                "scenario": agg.get("scenario"),
                "rules_fingerprint": agg.get("rules_fingerprint"),
                "custom_rules": agg.get("custom_rules"),
                "templates_total": agg.get("templates_total"),
                "templates_ok": agg.get("templates_ok"),
                "templates_failed": agg.get("templates_failed"),
                "failures": failure_set(agg),
            }
            key = f"{scenario_id}/{engine}/{binding}"
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


def scenario_failure_differences(loaded_by_scenario):
    """Run-metadata parity already guarantees every binding of a scenario agrees, so
    one binding's aggregate per engine is representative. Templates a rule pack
    cannot evaluate (a Guard type block against an empty ``Resources`` section)
    drop out of that scenario's timings, so the report lists them."""
    baseline = loaded_by_scenario.get(DEFAULT_SCENARIO)
    if not baseline:
        return {}
    reference = set(failure_set(next(iter(next(iter(baseline.values())).values()))))
    differences = {}
    for scenario_id, by_engine in loaded_by_scenario.items():
        if scenario_id == DEFAULT_SCENARIO:
            continue
        for engine, by_binding in by_engine.items():
            failures = set(failure_set(next(iter(by_binding.values()))))
            introduced = sorted(failures - reference)
            removed = sorted(reference - failures)
            if introduced or removed:
                differences.setdefault(scenario_id, {})[engine] = {"introduced": introduced, "removed": removed}
    return differences


def _per_template_dir(engine, binding, scenario_id=DEFAULT_SCENARIO):
    return reports_dir(engine, binding, scenario_id) / "json_detailed"


def load_and_validate_detailed_reports(engines, bindings, scenario_id=DEFAULT_SCENARIO):
    """Load per-template detailed-level JSON reports for all engine×binding pairs of
    one scenario.

    Each report is loaded exactly once and indexed by filePath.  Validation rules:
    1. Directory must exist and be nonempty.
    2. Root must be a JSON object with engine/binding labels matching the expected pair
       and, for a rule-pack scenario, the scenario label.
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
            d = _per_template_dir(engine, binding, scenario_id)
            key = f"{scenario_id}/{engine}/{label}"

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
                file_scenario = data.get("scenario")
                if file_scenario != scenario_id and not (file_scenario is None and scenario_id == DEFAULT_SCENARIO):
                    errors.append(
                        f"{key}: {json_file.name} scenario={file_scenario!r} expected '{scenario_id}'"
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
            "Detailed-level report validation failed:\n" +
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
    """Detailed-level file count must equal aggregate templates_total.

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
                    f"{engine}/{label}: detailed-level dir has {actual_count} reports, "
                    f"aggregate says templates_total={expected_count}"
                )
    if errors:
        sys.exit(
            "Detailed-level count vs aggregate templates_total mismatch:\n" +
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


def classify_paired(first_wall, second_wall):
    """Classify a paired comparison of two engines for one template.

    Uses a ratio-based threshold: slower / faster >= PAIRED_RATIO_THRESHOLD means
    the difference is practically significant.  Below PAIRED_FLOOR_MS both values
    are trivially fast and classified as noise regardless of ratio.

    Returns one of: "first_faster", "second_faster", "within_noise".
    """
    faster = min(first_wall, second_wall)
    slower = max(first_wall, second_wall)

    # Both below floor: timer granularity dominates
    if slower < PAIRED_FLOOR_MS:
        return "within_noise"

    # Avoid division by zero when faster == 0 but slower > floor
    if faster <= 0:
        # One is zero, the other is above floor → the nonzero one is slower
        if first_wall < second_wall:
            return "first_faster"
        elif second_wall < first_wall:
            return "second_faster"
        return "within_noise"

    ratio = slower / faster
    if ratio >= PAIRED_RATIO_THRESHOLD:
        if first_wall < second_wall:
            return "first_faster"
        else:
            return "second_faster"

    return "within_noise"


def top_slowest_section(all_detailed, engines, bindings, top_n):
    """Generate top-N slowest template tables for each engine × binding.

    Each table shows wall, rule, schema, and model subsequent metrics,
    sorted descending by subsequent wallClockMs.

    This section is mandatory when detailed-level reports are available.  Missing or
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
            f"top-slowest section requires valid detailed-level reports for all selected "
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


def engine_display_name(engine):
    """Human-readable engine label for report headings and table cells."""
    return {"rego": "Rego", "composite": "Composite"}.get(engine, engine)


def paired_engine_pairs(all_detailed):
    """Every unordered pair of engines present in the loaded reports, in canonical
    ENGINES order."""
    present = [engine for engine in ENGINES if engine in all_detailed]
    return list(itertools.combinations(present, 2))


def paired_engine_comparison(all_detailed, bindings):
    """Paired engine-vs-engine analysis per binding for Rego vs Composite.

    For each engine pair and binding, computes:
    - Representative corpus-pass sums (sum of per-template subsequent wallClockMs
      medians — a representative total, not a measured elapsed time or throughput).
    - Clear direction ratios (first/second)
    - Ratio-based 5% practical threshold counts (templates where slower/faster ≥ 1.05)
    - Rule evaluation comparison
    - Largest paired deltas (templates with biggest absolute difference)

    Note on corpus-pass sums vs throughput: the corpus-pass sum is the sum of
    per-template medians.  It represents typical per-template cost aggregated
    across the corpus but is NOT the same as measured elapsed time or throughput.
    Tail outliers (high p99/max) can make throughput figures close even when
    typical (median) costs differ noticeably between engines.
    """
    pairs = paired_engine_pairs(all_detailed)
    if not pairs:
        return ["## Paired Engine Comparison", "",
                "_Requires at least two engines to be present._", ""]

    lines = [
        "## Paired Engine Comparison", "",
        "Per-binding paired analysis using subsequent per-template metrics, for every "
        "pair of engines that ran. Each template is compared across engines using the "
        "same binding, so differences reflect engine behavior rather than binding "
        "overhead.", "",
        "**Metric definitions:**", "",
        "- **Corpus-pass sum**: representative sum of per-template subsequent "
        "`wallClockMs` medians across templates with subsequent samples — the total "
        "typical validation work for one full corpus pass. This is a sum of medians, "
        "not a measured elapsed time or throughput. Tail outliers (high p99/max) can "
        "make throughput figures close even when typical (median) per-template costs "
        "differ noticeably between engines.",
        "- **Direction ratio**: `sum(first engine subsequent wall) / sum(second engine "
        "subsequent wall)` — values >1.0 mean the first engine is slower overall.",
        f"- **{int((PAIRED_RATIO_THRESHOLD - 1) * 100)}% threshold**: count of templates where "
        f"`slower / faster ≥ {PAIRED_RATIO_THRESHOLD}` (ratio-based practical significance "
        f"threshold). Templates where both engines are below {PAIRED_FLOOR_MS} ms "
        "are always classified as noise regardless of ratio (timer granularity "
        "dominates at trivially-fast latencies).",
        "- **Rule comparison**: ratio of `ruleEvaluationMs` sums — isolates the "
        "pure rule-engine cost from shared model/schema work.", "",
    ]

    for first, second in pairs:
        lines += paired_engine_pair_section(all_detailed, bindings, first, second)

    return lines


def paired_engine_pair_section(all_detailed, bindings, first, second):
    """The report section comparing one engine pair across every binding."""
    first_name = engine_display_name(first)
    second_name = engine_display_name(second)
    lines = [f"### {first_name} vs {second_name}", ""]

    for binding, label in bindings:
        first_reports = all_detailed.get(first, {}).get(binding, {})
        second_reports = all_detailed.get(second, {}).get(binding, {})
        if not first_reports or not second_reports:
            continue

        common_paths = set(first_reports.keys()) & set(second_reports.keys())
        if not common_paths:
            continue

        first_wall_sum = 0.0
        second_wall_sum = 0.0
        first_rule_sum = 0.0
        second_rule_sum = 0.0
        first_faster_5pct = 0
        second_faster_5pct = 0
        within_noise = 0
        compared = 0
        deltas = []

        for fp in sorted(common_paths):
            first_sub = get(first_reports[fp], "benchmarkMetrics", "subsequent", default={})
            second_sub = get(second_reports[fp], "benchmarkMetrics", "subsequent", default={})
            if (not isinstance(first_sub, dict) or first_sub.get("sampleCount", 0) == 0
                    or not isinstance(second_sub, dict) or second_sub.get("sampleCount", 0) == 0):
                continue

            fw = first_sub.get("wallClockMs")
            sw = second_sub.get("wallClockMs")
            fr = first_sub.get("ruleEvaluationMs")
            sr = second_sub.get("ruleEvaluationMs")
            if not all(_is_finite_number(v) for v in (fw, sw, fr, sr)):
                continue

            compared += 1
            first_wall_sum += fw
            second_wall_sum += sw
            first_rule_sum += fr
            second_rule_sum += sr

            classification = classify_paired(fw, sw)
            if classification == "first_faster":
                first_faster_5pct += 1
            elif classification == "second_faster":
                second_faster_5pct += 1
            else:
                within_noise += 1

            abs_diff = abs(fw - sw)
            if fw < sw:
                direction = f"{first_name} faster"
            elif sw < fw:
                direction = f"{second_name} faster"
            else:
                direction = "equal"
            deltas.append((fp, fw, sw, abs_diff, direction))

        lines.append(f"#### {label}")
        lines.append("")
        if compared == 0:
            lines.append("_No subsequent samples to compare (single-iteration run)._")
            lines.append("")
            continue

        deltas.sort(key=lambda x: x[3], reverse=True)

        direction_ratio = (first_wall_sum / second_wall_sum) if second_wall_sum > 0 else float("inf")
        rule_ratio = (first_rule_sum / second_rule_sum) if second_rule_sum > 0 else float("inf")

        lines.append(f"**Templates compared:** {compared}")
        lines.append("")

        summary_header = ["Metric", "Value"]
        summary_rows = [
            [f"{first_name} corpus-pass sum (ms)", f"{first_wall_sum:.2f}"],
            [f"{second_name} corpus-pass sum (ms)", f"{second_wall_sum:.2f}"],
            [f"Direction ratio ({first_name}/{second_name})", f"{direction_ratio:.4f}"],
            [f"{first_name} rule sum (ms)", f"{first_rule_sum:.2f}"],
            [f"{second_name} rule sum (ms)", f"{second_rule_sum:.2f}"],
            [f"Rule ratio ({first_name}/{second_name})", f"{rule_ratio:.4f}"],
            [f"{first_name} faster by ≥5%", str(first_faster_5pct)],
            [f"{second_name} faster by ≥5%", str(second_faster_5pct)],
            ["Within 5% (practical parity)", str(within_noise)],
        ]
        lines += table(summary_header, summary_rows)
        lines.append("")

        # Top-5 largest paired deltas
        top_deltas = deltas[:5]
        if top_deltas:
            lines.append("**Largest paired deltas (top 5):**")
            lines.append("")
            delta_header = ["Template", f"{first_name} (ms)", f"{second_name} (ms)", "Δ (ms)", "Direction"]
            delta_rows = []
            for fp, fw, sw, diff, direction in top_deltas:
                display_path = fp if len(fp) <= 50 else "…" + fp[-47:]
                delta_rows.append([
                    display_path,
                    f"{fw:.4f}", f"{sw:.4f}", f"{diff:.4f}", direction,
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
             "and its runtime. The WASM, JVM, Python, and Go harnesses run against the committed "
             "distribution artifacts published by the build-artifacts workflow, not a local "
             "rebuild of the bindings.", "",
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


def diagnostics_parity(all_loaded, engine, bindings, all_detailed=None, scenario_id=DEFAULT_SCENARIO):
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

    # Use pre-loaded detailed-level reports if available
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
        dirs = {b: _per_template_dir(engine, b, scenario_id) for b, _ in bindings}

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


def data_sources_section(all_loaded, engines, bindings, scenario_id=DEFAULT_SCENARIO):
    lines = ["## Data Sources", ""]
    for engine in engines:
        for b, lbl in bindings:
            p = aggregate_path(engine, FORMATS[0], b, scenario_id)
            lines.append(f"- {engine}/{lbl}: `{p.relative_to(PROJECT_ROOT)}`")
    lines.append("")
    return lines


def rule_pack_section(scenario, agg):
    """Counts come from the aggregate so they describe what was measured, not what
    this checkout would load."""
    rules = agg.get("custom_rules") or {}
    guard = rules.get("guard") or {}
    rego = rules.get("rego") or {}
    lines = [
        "## Rule Pack", "",
        f"Scenario `{scenario['id']}` - {scenario['label']}.", "",
        f"- **Guard rules**: {guard.get('files', 0)} file(s), {guard.get('rules', 0)} distinct rule name(s), "
        f"{fmt_bytes(guard.get('bytes', 0))}",
        f"- **Custom Rego rules**: {rego.get('files', 0)} file(s), {fmt_bytes(rego.get('bytes', 0))}",
        f"- **rules fingerprint**: `{agg.get('rules_fingerprint', 'unknown')}` (identical across every binding "
        "of this scenario, checked before comparing)",
        "",
    ]
    guard_files, rego_files = scenario_rule_files(scenario)
    if guard_files or rego_files:
        lines += ["Pack files (from `src/resources/rules/`):", ""]
        lines += [f"- `{path.name}`" for path in guard_files + rego_files]
        lines.append("")
    return lines


def host_metadata():
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "python": platform.python_version(),
    }


def run_all_benchmarks(scenarios, engines, bindings, args, flavor):
    env = benchmark_env()
    plan = build_run_plan(scenarios, engines, bindings)
    for scenario_id, binding, engine in plan:
        scenario = scenario_by_id(scenario_id)
        probes = run_startup_probes(
            binding, engine, args.startup_samples, env, flavor, scenario
        )
        _corpus_wall_ms, corpus_rss_bytes = run_corpus(
            binding, engine, args.iterations, args.template_dir, env, flavor, scenario
        )
        process_startup = aggregate_process_startup(probes)
        enrich_aggregate(
            aggregate_path(engine, FORMATS[0], binding, scenario_id), process_startup, corpus_rss_bytes
        )


def methodology_section():
    return [
        "## Methodology Notes", "",
        "### Scenarios - rule packs loaded into the engine", "",
        "Every scenario is a complete engine × binding run over the same corpus with a different rule "
        f"set loaded into the engine. `{DEFAULT_SCENARIO}` evaluates the built-in rules alone; `custom` "
        "loads the custom Rego rule pack and `guard` loads the Guard rule pack of `src/resources/rules`. "
        "Each harness records the scenario label, the rule pack it loaded, and a fingerprint of "
        "the rule files; every binding of a scenario must report the same fingerprint before it is "
        "compared. The cross-scenario table reads the rule-evaluation medians as the most robust "
        "measure of a pack's cost because they exclude process startup and host I/O.", "",
        "### Process startup (cold vs warm) - externally measured", "",
        "Startup is measured by launching independent OS processes of each binding's "
        "benchmark harness in `--startup-probe` mode, each wrapped with `/usr/bin/time`. "
        "A probe constructs the real consumer validation setup (schema validator + engine, "
        "including the scenario's rule pack) "
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
        "process. Each harness writes one template's detailed-level report before processing the "
        "next, outside the per-call validation timers, so the peak includes the runtime, "
        "engine, corpus bookkeeping, and at most one detailed-level report serialization rather "
        "than a corpus-sized report queue.", "",
        "### Shared-runner temporal noise", "",
        "CI benchmarks run on shared GitHub Actions runners (`ubuntu-latest`) where "
        "neighboring workloads, CPU frequency scaling, and memory pressure introduce "
        "temporal noise. Intra-run relative comparisons (engine-vs-engine, binding-vs-binding) "
        "are more useful than cross-run absolute numbers. The corpus run pairs engines per "
        "binding and alternates run order (AB/BA) across bindings to distribute warm-up and "
        "load drift; results should be read as directional indicators, not precise "
        "measurements. Scenario runs may execute as separate CI jobs on different runners, so "
        "cross-scenario ratios are directional as well.", "",
    ]


def _ratio(value, base):
    if not _is_finite_number(value) or not _is_finite_number(base) or base <= 0:
        return "-"
    return f"{float(value) / float(base):.2f}×"


def scenario_overview_section(loaded_by_scenario, scenarios, engines):
    lines = ["## Scenarios", ""]
    header = ["Scenario", "Description", "Engines", "Guard files", "Guard rules", "Rego files", "Rules fingerprint"]
    rows = []
    for scenario in scenarios:
        by_engine = loaded_by_scenario.get(scenario["id"], {})
        sample = next((agg for by_binding in by_engine.values() for agg in by_binding.values()), None)
        rules = (sample or {}).get("custom_rules") or {}
        rows.append([
            f"[`{scenario['id']}`](#{scenario_anchor(scenario)})", scenario["label"],
            ", ".join(e.upper() for e in scenario_engines(scenario, engines)),
            str(get(rules, "guard", "files", default="-")), str(get(rules, "guard", "rules", default="-")),
            str(get(rules, "rego", "files", default="-")),
            f"`{(sample or {}).get('rules_fingerprint', '-')[:16]}…`" if sample else "-",
        ])
    return lines + table(header, rows) + [""]


def rule_pack_cost_section(loaded_by_scenario, scenarios, engines, bindings):
    lines = [
        "## Rule Pack Cost per Engine × Binding", "",
        "Columns: engine init and first validation from the cold startup probe; rule evaluation and "
        "wall clock are the subsequent per-template medians (iterations 2..N) with p99 in parentheses; "
        "throughput is ok × iterations / measured validation wall time; RSS is the corpus process peak. "
        f"Ratios (×) are relative to the `{DEFAULT_SCENARIO}` scenario of the same engine and binding. "
        "Templates that fail to evaluate under a rule pack are excluded from its timings (see the "
        "failure list below the table when there are any).", "",
    ]
    header = ["Scenario", "Templates ok", "Engine init (ms)", "First validation (ms)",
              "Rule eval median (p99) ms", "Rule eval ×", "Wall median (p99) ms", "Wall ×",
              "Throughput (val/s)", "Corpus RSS", "Diagnostics (F/E/W/I)"]
    baseline = loaded_by_scenario.get(DEFAULT_SCENARIO, {})
    for engine in engines:
        for binding, label in bindings:
            rows = []
            base = get(baseline, engine, binding)
            for scenario in scenarios:
                agg = get(loaded_by_scenario, scenario["id"], engine, binding)
                if agg is None:
                    continue
                rule_eval = get(agg, "performance", "rule_evaluation_ms", default={})
                wall = get(agg, "performance", "subsequent_wall_clock_ms", default={})
                base_rule = get(base, "performance", "rule_evaluation_ms", "median") if base else None
                base_wall = get(base, "performance", "subsequent_wall_clock_ms", "median") if base else None
                diags = agg.get("diagnostics") or {}
                rows.append([
                    f"`{scenario['id']}`",
                    str(agg.get("templates_ok", "-")),
                    ms(*_present(get(agg, "process_startup", "cold", "engine_init_ms"))),
                    ms(*_present(get(agg, "process_startup", "cold", "first_validation_host_ms"))),
                    f"{ms(*_stat_present(rule_eval, 'median'))} ({ms(*_stat_present(rule_eval, 'p99'))})",
                    _ratio(_stat_value(rule_eval, "median"), base_rule),
                    f"{ms(*_stat_present(wall, 'median'))} ({ms(*_stat_present(wall, 'p99'))})",
                    _ratio(_stat_value(wall, "median"), base_wall),
                    ms(recomputed_throughput(agg), True, 2),
                    fmt_bytes(get(agg, "memory", "full_corpus_peak_rss_bytes")),
                    "/".join(str(diags.get(k, "-")) for k in
                             ("total_fatal", "total_errors", "total_warnings", "total_informational")),
                ])
            if rows:
                lines += [f"### {engine.upper()} - {label}", ""] + table(header, rows) + [""]
    return lines


def failure_difference_section(differences):
    if not differences:
        return []
    lines = [
        "## Templates Failing Under a Rule Pack", "",
        f"Templates whose validation fails in a scenario but not in `{DEFAULT_SCENARIO}` (or the reverse). "
        "Every binding of the scenario agrees on this list. A failing template gets a report with no "
        "diagnostics and zero timings, so it is excluded from that scenario's latency and throughput "
        "figures. The usual cause is a Guard type block, which the Guard evaluator cannot apply to a "
        "template whose `Resources` section is empty.", "",
    ]
    grouped = {}
    for scenario_id, by_engine in differences.items():
        for engine, diff in by_engine.items():
            key = (tuple(diff["introduced"]), tuple(diff["removed"]))
            grouped.setdefault(key, []).append(f"`{scenario_id}` / {engine.upper()}")
    for (introduced, removed), labels in grouped.items():
        where = ", ".join(labels)
        if introduced:
            lines.append(f"- {where}: {len(introduced)} template(s) fail only here")
            lines += [f"  - `{file}` ({status})" for file, status in introduced]
        if removed:
            lines.append(f"- {where}: {len(removed)} template(s) fail only in `{DEFAULT_SCENARIO}`")
            lines += [f"  - `{file}` ({status})" for file, status in removed]
    lines.append("")
    return lines


def scenario_anchor(scenario):
    return f"scenario-{scenario['id']}"


def demote_headings(lines):
    return [f"#{line}" if line.startswith("#") else line for line in lines]


def scenario_section(all_loaded, all_detailed, engines, bindings, args, scenario):
    scenario_id = scenario["id"]
    corpus_fp = all_loaded[engines[0]][bindings[0][0]].get("corpus_fingerprint")
    corpus_file_count = all_loaded[engines[0]][bindings[0][0]].get("corpus_file_count")
    body = [
        f"- **corpus fingerprint**: `{corpus_fp}` ({corpus_file_count} files)",
        f"- **engines**: {', '.join(e.upper() for e in engines)}",
        "",
    ]
    body += rule_pack_section(scenario, all_loaded[engines[0]][bindings[0][0]])
    body += provenance_section(all_loaded, engines, bindings)
    body += latency_memory_summary(all_loaded, engines, bindings)

    parity_all_passed = True
    for engine in engines:
        body += [f"## {engine.upper()} Engine", ""]
        body += model_section(all_loaded, engine, bindings)
        body += headline_section(all_loaded, engine, bindings)
        body += phase_table(all_loaded, engine, bindings)
        body += overhead_table(all_loaded, engine, bindings)
        parity_lines, parity_passed = diagnostics_parity(
            all_loaded, engine, bindings, all_detailed=all_detailed, scenario_id=scenario_id
        )
        body += parity_lines
        if not parity_passed:
            parity_all_passed = False

    body += top_slowest_section(all_detailed, engines, bindings, args.top_slowest)
    if len(engines) >= 2:
        body += paired_engine_comparison(all_detailed, bindings)
    body += data_sources_section(all_loaded, engines, bindings, scenario_id)

    heading = [f"## Scenario: `{scenario_id}` - {scenario['label']} <a id=\"{scenario_anchor(scenario)}\"></a>", ""]
    return heading + demote_headings(body), parity_all_passed


def build_report(loaded_by_scenario, detailed_by_scenario, scenarios, engines, bindings, args):
    host = host_metadata()
    first = scenarios[0]
    first_loaded = loaded_by_scenario[first["id"]]
    first_engines = scenario_engines(first, engines)
    sample = first_loaded[first_engines[0]][bindings[0][0]]
    startup_samples = int(get(sample, "process_startup", "samples", default=args.startup_samples))
    lines = [
        "# Benchmark Comparison",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Host", "",
        *[f"- **{k}**: {v}" for k, v in host.items()],
        f"- **iterations/template**: {sample.get('iterations_per_template')}",
        f"- **startup samples/binding**: {startup_samples} (1 cold + {startup_samples - 1} warm)",
        f"- **corpus fingerprint**: `{sample.get('corpus_fingerprint')}` ({sample.get('corpus_file_count')} files)",
        f"- **bindings**: {', '.join(lbl for _, lbl in bindings)} ({len(bindings)} total)",
        f"- **engines**: {', '.join(e.upper() for e in engines)}",
        f"- **scenarios**: {', '.join(s['id'] for s in scenarios)} ({len(scenarios)} total)",
        "",
        "## Table of Contents", "",
        "- [Scenarios](#scenarios)",
        "- [Rule Pack Cost per Engine × Binding](#rule-pack-cost-per-engine--binding)",
        "- [Methodology Notes](#methodology-notes)",
        *[f"- [Scenario: {s['id']} - {s['label']}](#{scenario_anchor(s)})" for s in scenarios],
        "",
    ]
    lines += scenario_overview_section(loaded_by_scenario, scenarios, engines)
    lines += rule_pack_cost_section(loaded_by_scenario, scenarios, engines, bindings)
    lines += failure_difference_section(scenario_failure_differences(loaded_by_scenario))
    lines += methodology_section()

    parity_all_passed = True
    for scenario in scenarios:
        section, parity_passed = scenario_section(
            loaded_by_scenario[scenario["id"]],
            detailed_by_scenario[scenario["id"]],
            scenario_engines(scenario, engines),
            bindings,
            args,
            scenario,
        )
        lines += section
        if not parity_passed:
            parity_all_passed = False
    return lines, parity_all_passed


REPORT_PATH = SCRIPT_DIR / "snapshots" / "benchmark_comparison.md"


def main(argv=None):
    args = parse_args(argv)

    engines = args.engines if args.engines else ENGINES
    bindings = (
        [(b, lbl) for b, lbl in ALL_BINDINGS if b in args.bindings]
        if args.bindings
        else ALL_BINDINGS
    )
    scenarios = [s for s in select_scenarios(args.scenarios) if scenario_engines(s, engines)]
    if not scenarios:
        sys.exit(f"no selected scenario can run with engines {engines}")

    if args.report_only:
        print("Report-only mode - using existing aggregate files", file=sys.stderr)
        run_start_epoch = 0
    else:
        if not args.skip_build:
            build_harnesses(bindings)
        else:
            print("Skipping builds (--skip-build); validating prebuilt executables", file=sys.stderr)
            validate_executables(bindings)

        flavor = detect_time_flavor()
        if flavor is None:
            sys.exit(
                f"{TIME_BIN} (GNU '-v' or macOS '-l') is required to measure process startup and "
                f"memory but is unavailable. Install it (Linux: 'time' package), point "
                f"CFN_BENCHMARK_TIME_BIN at a GNU time binary, or use --report-only against "
                f"existing aggregates."
            )

        run_start_epoch = time.time()
        run_all_benchmarks(scenarios, engines, bindings, args, flavor)

    loaded_by_scenario = {}
    detailed_by_scenario = {}
    for scenario in scenarios:
        runnable = scenario_engines(scenario, engines)
        all_loaded = {
            e: {b: load_aggregate(aggregate_path(e, FORMATS[0], b, scenario["id"]), run_start_epoch, scenario["id"])
                for b, _ in bindings}
            for e in runnable
        }
        enforce_corpus_parity(all_loaded, bindings, scenario["id"])
        enforce_run_metadata_parity(all_loaded, bindings, scenario["id"])
        all_detailed = load_and_validate_detailed_reports(runnable, bindings, scenario["id"])
        validate_detailed_counts(all_detailed, all_loaded, runnable, bindings)
        loaded_by_scenario[scenario["id"]] = all_loaded
        detailed_by_scenario[scenario["id"]] = all_detailed

    lines, parity_all_passed = build_report(
        loaded_by_scenario, detailed_by_scenario, scenarios, engines, bindings, args
    )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines) + "\n")
    print(f"\nComparison written to {REPORT_PATH}", file=sys.stderr)

    if not parity_all_passed:
        print(
            "\n❌ Diagnostics parity check FAILED - see report for details.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Detect meaningful PR performance regressions with paired base/head runs.

The gate builds one identical Rust harness against each revision, alternates run
order on one runner, and confirms apparent regressions before failing. Absolute
milliseconds are never compared across machines.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
HARNESS_SOURCE = PROJECT_ROOT / "src" / "performance-harness"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "tmp" / "performance-regression"


@dataclass(frozen=True)
class Workload:
    name: str
    templates: tuple[Path, ...]
    iterations: int
    gate_process_lifecycle: bool = True


@dataclass(frozen=True)
class MetricGate:
    name: str
    accessor: Callable[[dict[str, Any]], float]
    threshold: float
    floor: float
    minimum_delta: float


@dataclass(frozen=True)
class MetricEvaluation:
    metric: str
    ratio: float
    median_delta: float
    slower_pairs: int
    pair_count: int
    regression: bool
    enforced: bool = True


METRIC_GATES = (
    MetricGate("initialization", lambda sample: sample["initTotalMs"], math.inf, 1.0, math.inf),
    MetricGate(
        "init + first",
        lambda sample: sample["initTotalMs"] + sample["firstValidation"]["wallMs"],
        1.10,
        1.0,
        5.0,
    ),
    MetricGate("first validation", lambda sample: sample["firstValidation"]["wallMs"], 1.12, 0.5, 5.0),
    MetricGate("warm total", lambda sample: sample["warm"]["perCallTotalMs"], 1.10, 0.2, 1.0),
    MetricGate("warm model", lambda sample: sample["warm"]["modelMedianMs"], 1.15, 0.2, 1.0),
    MetricGate("warm schema", lambda sample: sample["warm"]["schemaMedianMs"], 1.15, 0.2, 1.0),
    MetricGate("warm rules", lambda sample: sample["warm"]["ruleMedianMs"], 1.15, 0.2, 1.0),
    MetricGate("peak RSS", lambda sample: sample["peakRssBytes"], 1.15, 1024.0, 16 * 1024 * 1024),
)
AGGREGATE_WARM_THRESHOLD = 1.07
CONSISTENT_SLOWER_FRACTION = 2 / 3


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="origin/main", help="Git ref for the comparison baseline")
    parser.add_argument("--head-ref", default="HEAD", help="Git ref for the candidate revision")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--initial-pairs", type=int, default=3)
    parser.add_argument("--confirmation-pairs", type=int, default=3)
    parser.add_argument("--quick", action="store_true", help="Use one pair and reduced iterations for local smoke tests")
    parser.add_argument("--keep-worktrees", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="Test comparison logic without building Rust")
    arguments = parser.parse_args()
    if arguments.initial_pairs < 1 or arguments.confirmation_pairs < 1:
        parser.error("pair counts must be positive")
    return arguments


def run_command(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print(f"  $ {' '.join(command)}", file=sys.stderr)
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if completed.returncode != 0:
        if capture:
            print(completed.stdout, file=sys.stderr)
            print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"command failed with exit {completed.returncode}: {' '.join(command)}")
    return completed


def resolve_ref(reference: str) -> str:
    completed = run_command(["git", "rev-parse", reference], cwd=PROJECT_ROOT, capture=True)
    return completed.stdout.strip()


def remove_worktree(path: Path) -> None:
    if not path.exists():
        return
    subprocess.run(
        ["git", "worktree", "remove", "--force", str(path)],
        cwd=PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if path.exists():
        shutil.rmtree(path)


def configure_harness_dependencies(workspace_dir: Path) -> None:
    harness_manifest_path = workspace_dir / "performance-harness" / "Cargo.toml"
    harness_manifest = harness_manifest_path.read_text()
    dependency_directories = {
        "cel-engine": "cel-engine",
        "diagnostics": "diagnostics",
        "rego-engine": "rego-engine",
        "rules": "rules",
        "schema-validator": "schema-validator",
        "validation-engine": "validation-engine",
    }
    for dependency_alias, directory_name in dependency_directories.items():
        crate_manifest_path = workspace_dir / directory_name / "Cargo.toml"
        with crate_manifest_path.open("rb") as crate_manifest_file:
            package_name = tomllib.load(crate_manifest_file)["package"]["name"]
        original = f'{dependency_alias} = {{ path = "../{directory_name}" }}'
        replacement = (
            f'{dependency_alias} = {{ package = "{package_name}", path = "../{directory_name}" }}'
        )
        if original not in harness_manifest:
            raise RuntimeError(f"harness dependency marker not found: {original}")
        harness_manifest = harness_manifest.replace(original, replacement, 1)
    harness_manifest_path.write_text(harness_manifest)


def prepare_worktree(reference: str, destination: Path, target_dir: Path) -> Path:
    remove_worktree(destination)
    run_command(["git", "worktree", "add", "--detach", str(destination), reference], cwd=PROJECT_ROOT)

    workspace_dir = destination / "src"
    run_command(["cargo", "fetch", "--locked"], cwd=workspace_dir)
    harness_destination = workspace_dir / "performance-harness"
    if harness_destination.exists():
        shutil.rmtree(harness_destination)
    shutil.copytree(HARNESS_SOURCE, harness_destination)
    configure_harness_dependencies(workspace_dir)

    manifest_path = workspace_dir / "Cargo.toml"
    manifest = manifest_path.read_text()
    if '"performance-harness"' not in manifest:
        marker = '    "validation-engine",\n]'
        if marker not in manifest:
            raise RuntimeError(f"workspace member marker not found in {manifest_path}")
        manifest = manifest.replace(marker, '    "validation-engine",\n    "performance-harness",\n]', 1)
        manifest_path.write_text(manifest)

    build_environment = os.environ.copy()
    build_environment["CARGO_TARGET_DIR"] = str(target_dir)
    run_command(
        ["cargo", "build", "--release", "--offline", "-p", "performance-harness"],
        cwd=workspace_dir,
        environment=build_environment,
    )
    binary_name = "performance-harness.exe" if platform.system() == "Windows" else "performance-harness"
    binary = target_dir / "release" / binary_name
    if not binary.is_file():
        raise RuntimeError(f"benchmark binary was not produced: {binary}")
    return binary


def generate_fixtures(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    tiny = directory / "tiny.yaml"
    tiny.write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: performance-regression-bucket\n"
    )

    def write_buckets(path: Path, count: int, duplicate: bool) -> None:
        lines = ["AWSTemplateFormatVersion: '2010-09-09'", "Resources:"]
        for index in range(count):
            bucket_name = "shared-performance-id" if duplicate else f"unique-performance-id-{index}"
            lines.extend(
                [
                    f"  Bucket{index}:",
                    "    Type: AWS::S3::Bucket",
                    "    Properties:",
                    f"      BucketName: {bucket_name}",
                ]
            )
        path.write_text("\n".join(lines) + "\n")

    unique = directory / "unique-500.yaml"
    duplicate = directory / "duplicate-500.yaml"
    write_buckets(unique, 500, False)
    write_buckets(duplicate, 500, True)

    conditional = directory / "conditional-100.yaml"
    conditional_lines = [
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Parameters:",
        "  Environment:",
        "    Type: String",
        "    AllowedValues: [a, b]",
        "Conditions:",
        "  IsA: !Equals [!Ref Environment, a]",
        "  IsB: !Equals [!Ref Environment, b]",
        "Resources:",
    ]
    for index in range(100):
        condition = "IsA" if index % 2 == 0 else "IsB"
        conditional_lines.extend(
            [
                f"  Bucket{index}:",
                "    Type: AWS::S3::Bucket",
                f"    Condition: {condition}",
                "    Properties:",
                "      BucketName: shared-conditional-id",
            ]
        )
    conditional.write_text("\n".join(conditional_lines) + "\n")
    return {"tiny": tiny, "unique": unique, "duplicate": duplicate, "conditional": conditional}


def security_workloads(directory: Path, iteration_divisor: int) -> tuple[Workload, ...]:
    iteration_counts = {
        "condition_fusion.yaml": 2,
        "cross_reference_fanout.yaml": 1,
        "cross_resource_scale.yaml": 3,
        "deep_intrinsic_resolution.yaml": 2,
        "deep_nesting.json": 1,
        "deep_yaml_nesting.yaml": 1,
        "many_resources.yaml": 5,
        "pathological_conditions.yaml": 3,
        "scenario_assignment_budget.yaml": 2,
    }
    templates = sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".yaml", ".yml"}
    )
    workloads = []
    for template in templates:
        relative = template.relative_to(directory).with_suffix("")
        label = "-".join(relative.parts).replace("_", "-")
        normal_iterations = iteration_counts.get(template.name, 2)
        workloads.append(
            Workload(
                f"security-{label}",
                (template,),
                max(1, normal_iterations // iteration_divisor),
                gate_process_lifecycle=template.name not in {"deep_nesting.json", "deep_yaml_nesting.yaml"},
            )
        )
    return tuple(workloads)


def workload_matrix(fixtures: dict[str, Path], quick: bool) -> tuple[Workload, ...]:
    divisor = 5 if quick else 1

    def iterations(normal: int) -> int:
        return max(1, normal // divisor)

    templates = PROJECT_ROOT / "src" / "resources" / "templates"
    security = PROJECT_ROOT / "src" / "resources" / "security"
    return (
        Workload("tiny", (fixtures["tiny"],), iterations(151)),
        Workload("unique-500", (fixtures["unique"],), iterations(9)),
        Workload("duplicate-500", (fixtures["duplicate"],), iterations(7)),
        Workload("conditional-100", (fixtures["conditional"],), iterations(15)),
        Workload(
            "mixed-real",
            (
                templates / "cdk" / "codepipeline-build-deploy--CodepipelineBuildDeployStack.template.json",
                templates / "quickstart" / "vpc.json",
            ),
            iterations(7),
        ),
        *security_workloads(security, divisor),
    )


def time_prefix() -> list[str]:
    time_binary = Path("/usr/bin/time")
    if not time_binary.exists():
        raise RuntimeError("/usr/bin/time is required for peak RSS measurement")
    return [str(time_binary), "-v"] if platform.system() == "Linux" else [str(time_binary), "-l"]


def cpu_pin_prefix() -> list[str]:
    taskset = shutil.which("taskset")
    if taskset is None or not hasattr(os, "sched_getaffinity"):
        return []
    allowed_cpus = os.sched_getaffinity(0)
    return [taskset, "-c", str(min(allowed_cpus))] if allowed_cpus else []


def parse_peak_rss(stderr: str) -> int:
    linux_match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
    if linux_match:
        return int(linux_match.group(1)) * 1024
    darwin_match = re.search(r"(\d+)\s+maximum resident set size", stderr)
    if darwin_match:
        return int(darwin_match.group(1))
    raise RuntimeError("maximum resident set size was not present in /usr/bin/time output")


def run_measurement(
    binary: Path,
    engine: str,
    workload: Workload,
    variant: str,
    pair_index: int,
) -> dict[str, Any]:
    command = [
        *time_prefix(),
        *cpu_pin_prefix(),
        str(binary),
        engine,
        str(workload.iterations),
        "2",
        workload.name,
        *(str(path) for path in workload.templates),
    ]
    completed = run_command(command, cwd=PROJECT_ROOT, capture=True)
    output_lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError(f"benchmark emitted no JSON for {engine}/{workload.name}/{variant}")
    measurement = json.loads(output_lines[-1])
    measurement["peakRssBytes"] = parse_peak_rss(completed.stderr)
    measurement["variant"] = variant
    measurement["pair"] = pair_index
    measurement["gateProcessLifecycle"] = workload.gate_process_lifecycle
    return measurement


def diagnostic_signature(measurement: dict[str, Any]) -> tuple[Any, ...]:
    fingerprints = tuple(
        (Path(item["path"]).name, item["fingerprint"], item["diagnostics"], item["status"])
        for item in measurement["fingerprints"]
    )
    return (measurement["firstValidation"]["fingerprint"], fingerprints)


def metric_evaluation(
    pairs: list[dict[str, dict[str, Any]]],
    gate: MetricGate,
) -> MetricEvaluation:
    ratios = []
    deltas = []
    for pair in pairs:
        baseline = gate.accessor(pair["base"])
        candidate = gate.accessor(pair["head"])
        if baseline >= gate.floor:
            ratios.append(candidate / baseline)
            deltas.append(candidate - baseline)
    if not ratios:
        return MetricEvaluation(gate.name, 1.0, 0.0, 0, 0, False)
    ratio = math.exp(sum(math.log(value) for value in ratios) / len(ratios))
    median_delta = median(deltas)
    slower_pairs = sum(value > 1.0 for value in ratios)
    required_slower = math.ceil(len(ratios) * CONSISTENT_SLOWER_FRACTION)
    regression = (
        ratio > gate.threshold
        and median_delta > gate.minimum_delta
        and slower_pairs >= required_slower
    )
    return MetricEvaluation(gate.name, ratio, median_delta, slower_pairs, len(ratios), regression)


def evaluate_cases(
    measurements: dict[tuple[str, str], list[dict[str, dict[str, Any]]]],
) -> tuple[dict[tuple[str, str], list[MetricEvaluation]], list[str], bool]:
    evaluations: dict[tuple[str, str], list[MetricEvaluation]] = {}
    failures: list[str] = []
    diagnostic_mismatch = False
    for case, pairs in sorted(measurements.items()):
        engine, workload = case
        for pair in pairs:
            if diagnostic_signature(pair["base"]) != diagnostic_signature(pair["head"]):
                diagnostic_mismatch = True
                failures.append(f"{engine}/{workload}: diagnostics differ between base and head")
                break
        gate_process_lifecycle = all(
            pair["base"].get("gateProcessLifecycle", True)
            and pair["head"].get("gateProcessLifecycle", True)
            for pair in pairs
        )
        case_evaluations = []
        for gate in METRIC_GATES:
            evaluation = metric_evaluation(pairs, gate)
            if not gate_process_lifecycle and gate.name in {"init + first", "peak RSS"}:
                evaluation = MetricEvaluation(
                    evaluation.metric,
                    evaluation.ratio,
                    evaluation.median_delta,
                    evaluation.slower_pairs,
                    evaluation.pair_count,
                    False,
                    False,
                )
            case_evaluations.append(evaluation)
        evaluations[case] = case_evaluations
        for evaluation in case_evaluations:
            if evaluation.regression:
                failures.append(
                    f"{engine}/{workload}: {evaluation.metric} regressed by "
                    f"{(evaluation.ratio - 1) * 100:.1f}% "
                    f"(median delta {evaluation.median_delta:.3f}; "
                    f"{evaluation.slower_pairs}/{evaluation.pair_count} paired runs slower)"
                )

    warm_ratios = []
    for pairs in measurements.values():
        for pair in pairs:
            baseline = pair["base"]["warm"]["perCallTotalMs"]
            candidate = pair["head"]["warm"]["perCallTotalMs"]
            if baseline >= 0.2:
                warm_ratios.append(candidate / baseline)
    aggregate_regression = False
    if warm_ratios:
        aggregate_ratio = math.exp(sum(math.log(value) for value in warm_ratios) / len(warm_ratios))
        slower_pairs = sum(value > 1 for value in warm_ratios)
        required_slower = math.ceil(len(warm_ratios) * CONSISTENT_SLOWER_FRACTION)
        aggregate_regression = aggregate_ratio > AGGREGATE_WARM_THRESHOLD and slower_pairs >= required_slower
        if aggregate_regression:
            failures.append(
                f"aggregate warm validation regressed by {(aggregate_ratio - 1) * 100:.1f}% "
                f"({slower_pairs}/{len(warm_ratios)} paired runs slower)"
            )
    return evaluations, failures, diagnostic_mismatch


def collect_pairs(
    base_binary: Path,
    head_binary: Path,
    workloads: tuple[Workload, ...],
    engines: tuple[str, ...],
    pair_start: int,
    pair_count: int,
    selected_cases: set[tuple[str, str]] | None,
    measurements: dict[tuple[str, str], list[dict[str, dict[str, Any]]]],
) -> None:
    for engine in engines:
        for workload_index, workload in enumerate(workloads):
            case = (engine, workload.name)
            if selected_cases is not None and case not in selected_cases:
                continue
            case_pairs = measurements.setdefault(case, [])
            for pair_index in range(pair_start, pair_start + pair_count):
                base_first = (pair_index + workload_index + (0 if engine == "rego" else 1)) % 2 == 0
                order = (("base", base_binary), ("head", head_binary))
                if not base_first:
                    order = tuple(reversed(order))
                paired_measurement: dict[str, dict[str, Any]] = {}
                for variant, binary in order:
                    paired_measurement[variant] = run_measurement(binary, engine, workload, variant, pair_index)
                case_pairs.append(paired_measurement)


def render_markdown(
    evaluations: dict[tuple[str, str], list[MetricEvaluation]],
    failures: list[str],
    base_sha: str,
    head_sha: str,
) -> str:
    lines = [
        "# PR performance regression check",
        "",
        f"Base: `{base_sha[:12]}`  ",
        f"Head: `{head_sha[:12]}`",
        "",
        "Ratios are paired head/base geometric means. Values below 1.0 are faster/smaller.",
        "Ratios marked `(info)` are reported but not gated for parser-only robustness fixtures.",
        "",
        "| Engine | Workload | Init | Init + first | First validate | Warm total | Model | Schema | Rules | Peak RSS | Status |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    metric_order = [
        "initialization",
        "init + first",
        "first validation",
        "warm total",
        "warm model",
        "warm schema",
        "warm rules",
        "peak RSS",
    ]
    for (engine, workload), case_evaluations in sorted(evaluations.items()):
        by_name = {evaluation.metric: evaluation for evaluation in case_evaluations}
        values = [by_name[name] for name in metric_order]
        status = "FAIL" if any(value.regression for value in values) else "pass"
        ratios = [f"{value.ratio:.3f}×" + (" (info)" if not value.enforced else "") for value in values]
        lines.append(f"| {engine} | {workload} | {' | '.join(ratios)} | {status} |")
    lines.extend(["", "## Result", ""])
    if failures:
        lines.extend([f"* ❌ {failure}" for failure in failures])
    else:
        lines.append("✅ No meaningful performance or diagnostic regression detected.")
    return "\n".join(lines) + "\n"


def run_self_test() -> None:
    gate = MetricGate("test", lambda sample: sample["value"], 1.10, 0.1, 1.0)

    def pairs(ratios: list[float]) -> list[dict[str, dict[str, float]]]:
        return [{"base": {"value": 10.0}, "head": {"value": 10.0 * ratio}} for ratio in ratios]

    assert not metric_evaluation(pairs([1.01, 0.99, 1.02]), gate).regression
    assert not metric_evaluation(pairs([1.0, 1.0, 1.30]), gate).regression
    assert metric_evaluation(pairs([1.15, 1.14, 1.16]), gate).regression
    tiny_delta_pairs = [{"base": {"value": 1.0}, "head": {"value": 1.2}} for _ in range(3)]
    assert not metric_evaluation(tiny_delta_pairs, gate).regression
    assert not metric_evaluation([{"base": {"value": 0.01}, "head": {"value": 1.0}}], gate).regression

    memory_gate = MetricGate("memory", lambda sample: sample["value"], 1.15, 1.0, 1.0)
    assert metric_evaluation(pairs([1.20, 1.19, 1.21]), memory_gate).regression

    def synthetic_sample(multiplier: float, fingerprint_value: str = "same") -> dict[str, Any]:
        return {
            "initTotalMs": 10.0 * multiplier,
            "firstValidation": {"wallMs": 10.0 * multiplier, "fingerprint": fingerprint_value},
            "warm": {
                "perCallTotalMs": 10.0 * multiplier,
                "modelMedianMs": 2.0 * multiplier,
                "schemaMedianMs": 2.0 * multiplier,
                "ruleMedianMs": 5.0 * multiplier,
            },
            "peakRssBytes": 100_000_000 * multiplier,
            "fingerprints": [
                {"path": "fixture.yaml", "fingerprint": fingerprint_value, "diagnostics": 1, "status": "OK"}
            ],
        }

    stable_measurements = {
        ("rego", "fixture"): [
            {"base": synthetic_sample(1.0), "head": synthetic_sample(1.02)} for _ in range(3)
        ]
    }
    _, stable_failures, stable_diagnostic_mismatch = evaluate_cases(stable_measurements)
    assert not stable_failures and not stable_diagnostic_mismatch

    tradeoff_base = synthetic_sample(1.0)
    tradeoff_head = synthetic_sample(1.0)
    tradeoff_head["initTotalMs"] = 15.0
    tradeoff_head["firstValidation"]["wallMs"] = 5.0
    tradeoff_measurements = {
        ("rego", "tradeoff"): [{"base": tradeoff_base, "head": tradeoff_head} for _ in range(3)]
    }
    _, tradeoff_failures, _ = evaluate_cases(tradeoff_measurements)
    assert not tradeoff_failures

    aggregate_measurements = {
        (engine, workload): [
            {"base": synthetic_sample(1.0), "head": synthetic_sample(1.08)} for _ in range(3)
        ]
        for engine, workload in [("rego", "one"), ("cel", "two")]
    }
    _, aggregate_failures, aggregate_diagnostic_mismatch = evaluate_cases(aggregate_measurements)
    assert any(failure.startswith("aggregate warm") for failure in aggregate_failures)
    assert not aggregate_diagnostic_mismatch

    model_only_head = synthetic_sample(1.0)
    model_only_head["warm"]["modelMedianMs"] = 4.0
    model_only_measurements = {
        ("rego", "model-only"): [
            {"base": synthetic_sample(1.0), "head": model_only_head} for _ in range(3)
        ]
    }
    model_only_evaluations, model_only_failures, _ = evaluate_cases(model_only_measurements)
    model_only_markdown = render_markdown(model_only_evaluations, model_only_failures, "base", "head")
    assert "| Model |" in model_only_markdown
    assert "| rego | model-only |" in model_only_markdown and "| FAIL |" in model_only_markdown

    parser_only_base = synthetic_sample(1.0)
    parser_only_head = synthetic_sample(1.0)
    parser_only_head["initTotalMs"] = 25.0
    parser_only_head["peakRssBytes"] = 200_000_000
    parser_only_measurements = {
        ("rego", "parser-only"): [
            {
                "base": {**parser_only_base, "gateProcessLifecycle": False},
                "head": {**parser_only_head, "gateProcessLifecycle": False},
            }
            for _ in range(3)
        ]
    }
    parser_evaluations, parser_failures, _ = evaluate_cases(parser_only_measurements)
    assert not parser_failures
    parser_by_name = {evaluation.metric: evaluation for evaluation in parser_evaluations[("rego", "parser-only")]}
    assert not parser_by_name["init + first"].enforced
    assert not parser_by_name["peak RSS"].enforced
    assert parser_by_name["first validation"].enforced
    assert parser_by_name["warm total"].enforced

    mismatch_measurements = {
        ("rego", "fixture"): [
            {"base": synthetic_sample(1.0, "base"), "head": synthetic_sample(1.0, "head")}
        ]
    }
    _, mismatch_failures, mismatch_detected = evaluate_cases(mismatch_measurements)
    assert mismatch_detected and any("diagnostics differ" in failure for failure in mismatch_failures)
    security_directory = PROJECT_ROOT / "src" / "resources" / "security"
    expected_security_templates = {
        path.resolve()
        for path in security_directory.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".yaml", ".yml"}
    }
    discovered_security_workloads = security_workloads(security_directory, 5)
    discovered_security_templates = {
        workload.templates[0].resolve() for workload in discovered_security_workloads
    }
    assert expected_security_templates
    assert discovered_security_templates == expected_security_templates
    assert len({workload.name for workload in discovered_security_workloads}) == len(discovered_security_workloads)

    print("performance comparison self-tests passed")


def main() -> int:
    arguments = parse_args()
    if arguments.self_test:
        run_self_test()
        return 0

    time_prefix()
    base_sha = resolve_ref(arguments.base_ref)
    head_sha = resolve_ref(arguments.head_ref)
    if base_sha == head_sha:
        raise RuntimeError("base and head resolve to the same commit")

    output_dir = arguments.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    worktree_root = output_dir / "worktrees"
    target_root = output_dir / "targets"
    fixtures = generate_fixtures(output_dir / "fixtures")
    workloads = workload_matrix(fixtures, arguments.quick)
    engines = ("rego", "cel")
    initial_pairs = 1 if arguments.quick else arguments.initial_pairs
    confirmation_pairs = 1 if arguments.quick else arguments.confirmation_pairs

    base_tree = worktree_root / "base"
    head_tree = worktree_root / "head"
    measurements: dict[tuple[str, str], list[dict[str, dict[str, Any]]]] = {}
    try:
        print(f"Building base {base_sha}", file=sys.stderr)
        base_binary = prepare_worktree(base_sha, base_tree, target_root / "base")
        print(f"Building head {head_sha}", file=sys.stderr)
        head_binary = prepare_worktree(head_sha, head_tree, target_root / "head")

        collect_pairs(base_binary, head_binary, workloads, engines, 0, initial_pairs, None, measurements)
        evaluations, failures, diagnostic_mismatch = evaluate_cases(measurements)
        if failures and not diagnostic_mismatch:
            failing_cases = {
                case
                for case, case_evaluations in evaluations.items()
                if any(evaluation.regression for evaluation in case_evaluations)
            }
            if any(failure.startswith("aggregate ") for failure in failures):
                failing_cases = set(evaluations)
            print(f"Confirming {len(failing_cases)} apparent regression(s)", file=sys.stderr)
            collect_pairs(
                base_binary,
                head_binary,
                workloads,
                engines,
                initial_pairs,
                confirmation_pairs,
                failing_cases,
                measurements,
            )
            evaluations, failures, diagnostic_mismatch = evaluate_cases(measurements)

        serialized_measurements = {
            f"{engine}/{workload}": pairs for (engine, workload), pairs in sorted(measurements.items())
        }
        json_path = output_dir / "performance-comparison.json"
        json_path.write_text(
            json.dumps(
                {
                    "base": base_sha,
                    "head": head_sha,
                    "measurements": serialized_measurements,
                    "failures": failures,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        markdown = render_markdown(evaluations, failures, base_sha, head_sha)
        markdown_path = output_dir / "performance-comparison.md"
        markdown_path.write_text(markdown)
        print(markdown)
        if failures:
            for failure in failures:
                print(f"::error::{failure}")
            return 1
        return 0
    finally:
        if not arguments.keep_worktrees:
            remove_worktree(base_tree)
            remove_worktree(head_tree)
            subprocess.run(["git", "worktree", "prune"], cwd=PROJECT_ROOT, check=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"performance regression check failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error

#!/usr/bin/env python3
"""Compare cloudformation-validate diagnostics against cfn-lint expected results.

Builds the native Rust engine (cargo release), runs cfn-benchmark to generate
fresh per-template JSON reports, then compares against cfn-lint baselines and
writes a comprehensive markdown report.

Only runs native Rust benchmarks - WASM and Java bindings produce identical
diagnostics so they are not needed for cfn-lint parity comparison.
Use compare_benchmarks.py for cross-binding performance comparison.

Usage:
    python3 scripts/compare_cfnlint.py --cfn-lint-root /path/to/cfn-lint [--engine rego|cel] [--skip-build]
    CFN_LINT_ROOT=/path/to/cfn-lint python3 scripts/compare_cfnlint.py [--engine rego|cel] [--skip-build]

When no flags are provided, runs all engines × all formats (standard, full).
Reports are written to scripts/<engine>/report_<engine>_<format>.md.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
SRC_DIR = PROJECT_ROOT / "src"
REPORTS_ROOT = SRC_DIR / "cfn-validate" / "reports"
ENGINE_NAME = "rego"
ENGINE_REPORTS = SRC_DIR / "cfn-validate" / "reports" / "rego" / "json_detailed"
CFN_LINT_ROOT = Path(os.environ["CFN_LINT_ROOT"]) if "CFN_LINT_ROOT" in os.environ else None
CFN_LINT_RESULTS = None
CFN_LINT_TEMPLATES = None
OUTPUT_PATH = None
SKIP_BUILD = False
ALL_ENGINES = ["rego", "cel"]
OUTPUT_FORMAT = "detailed"
ITERATIONS = 1
# Rules that are correct engine-only findings - cfn-lint does not implement them.
# These are NOT false positives; they are intentional engine-extra coverage.
# Computed from audit_rule_categorization.compute_rule_origins() at init time.
ENGINE_EXTRA_RULES = set()  # populated by init_rule_origins()

# Populated by init_rule_origins() from audit_rule_categorization
_CFNLINT_TO_ENGINE = {}
_ENGINE_TO_CFNLINT = {}
_RULE_ALIASES = {}
_IS_ENGINE_EXTRA_DIAGNOSTIC = None  # callable from audit_rule_categorization

_STATEFUL_SAM_RESOURCE_TYPES = frozenset({
    "AWS::Serverless::Application",
    "AWS::Serverless::SimpleTable",
})
_IDENTITY_POLICY_RESOURCE_TYPES = frozenset({
    "AWS::IAM::Group",
    "AWS::IAM::GroupPolicy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Policy",
    "AWS::IAM::Role",
    "AWS::IAM::RolePolicy",
    "AWS::IAM::User",
    "AWS::IAM::UserPolicy",
    "AWS::SSO::PermissionSet",
})
_FORBIDDEN_IDENTITY_POLICY_ID_MESSAGE = (
    "Additional properties are not allowed ('Id' was unexpected)"
)

_REFERENCE_SCOPE_EXCLUSIONS = {
    "E0002": "cfn-lint rule-execution failure rather than a template contract",
    "E3043": "requires loading a referenced nested template from the local filesystem",
    "W4001": "CloudFormation console-interface metadata is outside the validator scope",
    "W4005": "cfn-lint-specific metadata configuration",
    "W6001": "cross-stack import advisory is outside offline template correctness",
}

# Known Reference Incorrect (RI) cases: cfn-lint reports a finding that is
# demonstrably wrong based on CloudFormation's actual behavior. These are
# excluded from FN and recall because reporting them would be incorrect.
_REFERENCE_INCORRECT_CASES = frozenset({
    # E3047: ECS Fargate task definition memory/cpu validations on valid templates
    ("good/ecs_fargate_units_and_sizes.yaml", "E3047"),
    # E3048: ECS Fargate task definition container memory validations on valid templates
    ("good/ecs_fargate_units_and_sizes.yaml", "E3048"),
    # E3048: Fargate task sizes in bad template - incorrect for specific resources
    ("bad/resources/ecs/fargate_task_sizes_e3047.yaml", "E3048"),
})
_REFERENCE_INCORRECT_RESOURCES = {
    # (canonical_path, rule_id) -> frozenset of resource logical IDs that are RI
    ("good/ecs_fargate_units_and_sizes.yaml", "E3047"): frozenset({
        "ThirtyTwoVcpuSixtyGb", "ThirtyTwoVcpuOneTwentyGb", "ThirtyTwoVcpuTwoFortyFourGb",
    }),
    ("good/ecs_fargate_units_and_sizes.yaml", "E3048"): frozenset({
        "ThirtyTwoVcpuSixtyGb", "ThirtyTwoVcpuOneTwentyGb", "ThirtyTwoVcpuTwoFortyFourGb",
    }),
    ("bad/resources/ecs/fargate_task_sizes_e3047.yaml", "E3048"): frozenset({
        "ThirtyTwoVcpuUnsupportedSixtyFourGb",
        "ThirtyTwoVcpuUnsupportedTwoFortyGb",
    }),
}


@dataclass(frozen=True)
class QualityClassification:
    kind: str
    reason: str


@dataclass(frozen=True)
class ReferenceSuppressions:
    global_rule_prefixes: frozenset[str]
    resource_rule_ids: dict[str, frozenset[str]]

    def suppresses(self, reference_rule_ids, resource_id):
        if any(
            rule_id.startswith(prefix)
            for rule_id in reference_rule_ids
            for prefix in self.global_rule_prefixes
        ):
            return True
        ignored_for_resource = self.resource_rule_ids.get(resource_id, frozenset())
        return any(rule_id in ignored_for_resource for rule_id in reference_rule_ids)


NO_REFERENCE_SUPPRESSIONS = ReferenceSuppressions(frozenset(), {})


def init_rule_origins():
    """Initialize rule classification from audit_rule_categorization (single source of truth)."""
    global ENGINE_EXTRA_RULES, _CFNLINT_TO_ENGINE, _ENGINE_TO_CFNLINT, _RULE_ALIASES
    global _IS_ENGINE_EXTRA_DIAGNOSTIC
    from audit_rule_categorization import compute_rule_origins
    origins = compute_rule_origins(CFN_LINT_ROOT)
    ENGINE_EXTRA_RULES = origins.engine_extra
    _CFNLINT_TO_ENGINE = origins.cfnlint_to_engine
    _ENGINE_TO_CFNLINT = origins.engine_to_cfnlint
    _RULE_ALIASES = origins.rule_aliases
    _IS_ENGINE_EXTRA_DIAGNOSTIC = origins.is_engine_extra_diagnostic


def parse_args():
    global CFN_LINT_ROOT, CFN_LINT_RESULTS, CFN_LINT_TEMPLATES, SKIP_BUILD, ENGINE_NAME
    engine_set = False
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] in ("-h", "--help"):
            print(__doc__.strip())
            raise SystemExit(0)
        if sys.argv[i] == "--cfn-lint-root" and i + 1 < len(sys.argv):
            CFN_LINT_ROOT = Path(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--engine" and i + 1 < len(sys.argv):
            ENGINE_NAME = sys.argv[i + 1]
            if ENGINE_NAME not in ALL_ENGINES:
                print(f"Unknown engine '{ENGINE_NAME}', must be one of {ALL_ENGINES}", file=sys.stderr)
                sys.exit(1)
            engine_set = True
            i += 2
        elif sys.argv[i] == "--skip-build":
            SKIP_BUILD = True
            i += 1
        else:
            i += 1

    configure_run(ENGINE_NAME, OUTPUT_FORMAT)

    if CFN_LINT_ROOT is None:
        print("error: --cfn-lint-root or CFN_LINT_ROOT env var is required", file=sys.stderr)
        sys.exit(2)
    if not CFN_LINT_ROOT.exists():
        print(f"error: cfn-lint root does not exist: {CFN_LINT_ROOT}", file=sys.stderr)
        sys.exit(2)
    CFN_LINT_RESULTS = CFN_LINT_ROOT / "test" / "fixtures" / "results"
    CFN_LINT_TEMPLATES = CFN_LINT_ROOT / "test" / "fixtures" / "templates"

    return engine_set


def configure_run(engine, fmt):
    """Set globals for a specific engine/format combination."""
    global ENGINE_NAME, ENGINE_REPORTS, OUTPUT_PATH, OUTPUT_FORMAT
    ENGINE_NAME = engine
    OUTPUT_FORMAT = fmt
    ENGINE_REPORTS = SRC_DIR / "cfn-validate" / "reports" / engine / f"json_{fmt}"
    OUTPUT_PATH = SCRIPT_DIR / "snapshots" / f"report_{engine}_{fmt}.md"


# ── Build & Run ──────────────────────────────────────────────────────────────

def clean_reports():
    """Remove the entire reports/ tree before a run.

    Report filenames are derived from template stems and format/engine names, so
    anything left from a prior run - orphaned per-template reports for renamed or
    removed fixtures, aggregate JSON for a format not regenerated this run, or a
    stale report_*.md - is silently compared against the reference's live results
    and corrupts the FP/FN/location tallies (and inflates the cel↔rego diff with
    ghost disagreements). Wiping the whole tree up front guarantees every artifact
    read downstream was produced by this run.
    """
    if REPORTS_ROOT.exists():
        shutil.rmtree(REPORTS_ROOT)
    print(f"Cleaned reports directory: {REPORTS_ROOT}")


def build():
    if SKIP_BUILD:
        print("Skipping build (--skip-build)", file=sys.stderr)
        return
    print("=== Building release binary ===")
    result = subprocess.run(
        ["cargo", "build", "--profile", "release"],
        cwd=str(SRC_DIR), capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Build succeeded.")


def _warn_if_benchmark_stale(bench_bin):
    """Warn when the cfn-benchmark binary predates the newest Rust source.

    With --skip-build the script reuses whatever cfn-benchmark exists. A common
    trap is rebuilding only `cfn-validate` (`cargo build -p cfn-validate --bin
    cfn-validate`), which leaves cfn-benchmark stale - the comparison then runs on
    old behavior while a freshly-built golden passes, producing phantom results.
    """
    bench_mtime = bench_bin.stat().st_mtime
    newest_src = 0.0
    newest_path = None
    for rs in SRC_DIR.rglob("*.rs"):
        if "target" in rs.parts:
            continue
        m = rs.stat().st_mtime
        if m > newest_src:
            newest_src, newest_path = m, rs
    for rego in SRC_DIR.rglob("*.rego"):
        if "target" in rego.parts:
            continue
        m = rego.stat().st_mtime
        if m > newest_src:
            newest_src, newest_path = m, rego
    if newest_src > bench_mtime:
        print(
            f"WARNING: cfn-benchmark is older than {newest_path} - it may be stale. "
            f"Run `cargo build --release` (whole workspace) or drop --skip-build.",
            file=sys.stderr,
        )


def run_bench():
    bench_bin = SRC_DIR / "target" / "release" / "cfn-benchmark"
    if not bench_bin.exists():
        print(f"cfn-benchmark binary not found at {bench_bin}", file=sys.stderr)
        sys.exit(1)
    if SKIP_BUILD:
        _warn_if_benchmark_stale(bench_bin)

    cmd = [str(bench_bin), str(SRC_DIR / "resources" / "templates"), "--engine", ENGINE_NAME, "--format", OUTPUT_FORMAT, "--iterations", str(ITERATIONS)]
    print(f"=== Running cfn-benchmark (engine={ENGINE_NAME}, format={OUTPUT_FORMAT}) ===")
    result = subprocess.run(cmd, cwd=str(SRC_DIR), capture_output=True, text=True)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print(f"cfn-benchmark failed (exit {result.returncode}):\n{result.stderr}", file=sys.stderr)
        sys.exit(1)


# ── Load cfn-lint expected results ───────────────────────────────────────────

def _canonical_reference_rule_id(cfnlint_id, message):
    """Return the engine identity for one concrete reference occurrence."""
    if (
        cfnlint_id == "E1001"
        and message == "'Resources' is a required property"
    ):
        return "F0001"
    return cfnlint_rule_to_engine(cfnlint_id)


def normalize_cfnlint_diags(diags):
    out = []
    for d in diags:
        rule = d.get("Rule", {})
        loc = d.get("Location", {})
        path_parts = loc.get("Path") or []
        start = loc.get("Start", {})
        end = loc.get("End", {})
        resource_id = ""
        prop_path = ""
        if len(path_parts) >= 2 and path_parts[0] == "Resources":
            resource_id = str(path_parts[1])
            if len(path_parts) >= 3 and path_parts[2] == "Properties":
                prop_parts = [str(part) for part in path_parts[3:]]
                prop_path = "Properties." + ".".join(prop_parts) if prop_parts else "Properties"
            elif len(path_parts) >= 3:
                prop_path = ".".join(str(part) for part in path_parts[2:])
        cfnlint_id = rule.get("Id", "")
        cfnlint_sev = d.get("Level", "")
        message = d.get("Message", "")
        engine_id = _canonical_reference_rule_id(cfnlint_id, message)
        engine_sev = cfnlint_severity_to_engine(
            cfnlint_sev, cfnlint_id, engine_id
        )
        out.append({
            "rule_id": engine_id,
            "cfnlint_rule_id": cfnlint_id,
            "rule_description": rule.get("ShortDescription", ""),
            "rule_source": rule.get("Source", ""),
            "severity": engine_sev,
            "cfnlint_severity": cfnlint_sev,
            "message": message,
            "resource_id": resource_id,
            "resource_path": prop_path,
            "json_path": ".".join(str(p) for p in path_parts) if path_parts else "",
            "line": start.get("LineNumber", 0),
            "column": start.get("ColumnNumber", 0),
            "end_line": end.get("LineNumber", 0),
            "end_column": end.get("ColumnNumber", 0),
            "comparison_excluded_reason": _REFERENCE_SCOPE_EXCLUSIONS.get(
                cfnlint_id, ""
            ),
        })
    return out


def _canonical_template_path_from_filename(filename):
    """Extract canonical POSIX template path from a cfn-lint Filename field.

    cfn-lint stores the path as 'test/fixtures/templates/<corpus_path>'.
    Returns the corpus-relative POSIX path (e.g. 'bad/resources/foo.yaml').
    """
    prefix = "test/fixtures/templates/"
    if filename.startswith(prefix):
        return filename[len(prefix):]
    return filename


def _canonical_key_from_path(canonical_path):
    """Derive the flattened engine-report key from a canonical POSIX path.

    Mirrors the engine's report filename convention:
    'bad/resources/foo.yaml' -> 'bad_resources_foo_yaml'
    """
    return (canonical_path
            .replace("/", "_")
            .replace(".yaml", "_yaml")
            .replace(".yml", "_yml")
            .replace(".json", "_json"))


def _resolve_cfnlint_collision(canonical_key, existing_entry, new_entry):
    """Resolve a duplicate canonical cfn-lint baseline.

    Returns the entry to keep. Raises if ambiguity remains.
    """
    existing_path, existing_diags, existing_file = existing_entry
    new_path, new_diags, new_file = new_entry

    # If normalized diagnostics are identical, deduplicate silently
    if existing_diags == new_diags:
        return existing_entry

    # The engine comparison is non-strict. For QuickStart collisions, an
    # explicit non_strict result wins over either the root/default result or an
    # explicit strict result, independent of traversal order.
    is_quickstart = (
        canonical_key.startswith("quickstart_")
        or existing_path.startswith("quickstart/")
        or new_path.startswith("quickstart/")
    )
    existing_in_non_strict = "non_strict" in existing_file.parts
    new_in_non_strict = "non_strict" in new_file.parts

    if is_quickstart and existing_in_non_strict != new_in_non_strict:
        return existing_entry if existing_in_non_strict else new_entry

    # For other collisions, prefer the result tree matching the template's
    # top-level corpus directory (bad for bad/, good for good/, etc.)
    if existing_path:
        top_dir = existing_path.split("/")[0] if "/" in existing_path else ""
        existing_rel = str(existing_file.relative_to(CFN_LINT_RESULTS)) if CFN_LINT_RESULTS else ""
        new_rel = str(new_file.relative_to(CFN_LINT_RESULTS)) if CFN_LINT_RESULTS else ""
        if top_dir and existing_rel.startswith(top_dir + "/") and not new_rel.startswith(top_dir + "/"):
            return existing_entry
        if top_dir and new_rel.startswith(top_dir + "/") and not existing_rel.startswith(top_dir + "/"):
            return new_entry

    raise ValueError(
        f"Ambiguous cfn-lint baseline collision for key '{canonical_key}': "
        f"files '{existing_file}' and '{new_file}' produce different diagnostics "
        f"and no resolution heuristic applies"
    )


def _load_cfnlint_result_file(f, prefix, results):
    """Load a single cfn-lint result JSON file into results dict."""
    if f.name.startswith("__"):
        return
    try:
        data = json.loads(f.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Malformed JSON in cfn-lint result file '{f}': {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Encoding error in cfn-lint result file '{f}': {exc}"
        ) from exc
    if not isinstance(data, list):
        raise ValueError(
            f"cfn-lint result file '{f}' does not contain a JSON list "
            f"(got {type(data).__name__})"
        )

    # Derive canonical template path from the Filename field
    canonical_path = ""
    if data and isinstance(data[0], dict) and data[0].get("Filename"):
        canonical_path = _canonical_template_path_from_filename(data[0]["Filename"])
        key = _canonical_key_from_path(canonical_path)
    else:
        # Empty result list (cfn-lint found nothing) carries no Filename; derive
        # from the mirror template under the templates tree.
        derived = _derive_key_from_template_path(f)
        if derived:
            key = derived
        else:
            key = f"{prefix}_{f.stem}"

    normalized = normalize_cfnlint_diags(data)

    if key in results:
        existing_entry = results[key]
        new_entry = (canonical_path, normalized, f)
        winner = _resolve_cfnlint_collision(key, existing_entry, new_entry)
        results[key] = winner
    else:
        results[key] = (canonical_path, normalized, f)


def _derive_key_from_template_path(result_file):
    """Recover the extension-suffixed key for an empty-result file by locating the
    mirror template under CFN_LINT_TEMPLATES. The result stem now embeds the source
    extension as a suffix (e.g. "foo_yaml.json"), so split that suffix back off, find
    the matching template, and rebuild the key from its real extension. Returns None
    if no matching template exists (leaving the caller's default key in place)."""
    relative = result_file.relative_to(CFN_LINT_RESULTS)
    stem = relative.stem  # drops ".json"; still carries the "_yaml"/"_yml"/"_json" suffix
    for ext in ("yaml", "yml", "json"):
        base = stem[: -(len(ext) + 1)] if stem.endswith(f"_{ext}") else stem
        template = relative.with_name(f"{base}.{ext}")
        if (CFN_LINT_TEMPLATES / template).exists():
            key_path = str(template.with_suffix("")).replace(os.sep, "_")
            return f"{key_path}_{ext}"
    return None


def load_cfnlint_results_from_files():
    results = {}
    for subdir in ["bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart"]:
        d = CFN_LINT_RESULTS / subdir
        if not d.exists():
            continue
        # Recurse to every depth. The per-file key is derived from the result's
        # internal `Filename` field, so arbitrarily nested fixtures (e.g.
        # good/resources/properties/*.json) still key correctly; the path-derived
        # prefix is only a fallback for files lacking a Filename. A shallow scan
        # would silently drop deeply-nested fixtures, hiding any engine finding on
        # those templates from the false-positive tally.
        for f in sorted(d.rglob("*.json")):
            if any(part.startswith("__") for part in f.relative_to(d).parts):
                continue
            rel_parents = "_".join(f.relative_to(d).parent.parts)
            prefix = f"{subdir}_{rel_parents}" if rel_parents else subdir
            _load_cfnlint_result_file(f, prefix, results)
    # Strip collision-resolution metadata; callers need only key -> diagnostics
    return {key: entry[1] if isinstance(entry, tuple) else entry
            for key, entry in results.items()}


def load_cfnlint_inline_results():
    results = {}
    py_file = CFN_LINT_ROOT / "test" / "integration" / "test_good_templates.py"
    if not py_file.exists():
        return results
    text = py_file.read_text()
    match = re.search(r'scenarios\s*=\s*\[', text)
    if not match:
        return results
    bracket_count = 0
    end = None
    for i in range(match.end() - 1, len(text)):
        if text[i] == '[':
            bracket_count += 1
        elif text[i] == ']':
            bracket_count -= 1
            if bracket_count == 0:
                end = i + 1
                break
    if end is None:
        raise ValueError(
            f"Unterminated inline cfn-lint scenarios list in '{py_file}'"
        )
    scenarios_text = re.sub(r'str\(\s*Path\(\s*("[^"]+")\s*\)\s*\)', r'\1',
                            text[match.start():end])
    try:
        local_ns = {"Path": str}
        exec(scenarios_text, {"Path": str, "__builtins__": {"str": str, "Path": str}}, local_ns)
    except Exception as exc:
        raise ValueError(
            f"Failed to parse inline cfn-lint scenarios from "
            f"'{py_file}': {exc}"
        ) from exc
    scenarios = local_ns.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError(
            f"Inline cfn-lint scenarios in '{py_file}' are not a list"
        )
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ValueError(
                f"Inline cfn-lint scenario {index} in '{py_file}' is not an object"
            )
        scenario_results = scenario.get("results", [])
        if not isinstance(scenario_results, list):
            raise ValueError(
                f"Inline cfn-lint scenario {index} results in '{py_file}' are not a list"
            )
        filename = scenario.get("filename", "")
        rel = filename.replace("test/fixtures/templates/", "")
        key = _canonical_key_from_path(rel)
        results[key] = normalize_cfnlint_diags(scenario_results)
    return results


# ── Severity / rule-ID translation ───────────────────────────────────────────
# _CFNLINT_TO_ENGINE, _ENGINE_TO_CFNLINT, and _RULE_ALIASES are populated
# by init_rule_origins() from audit_rule_categorization.py (single source of truth).

_CFNLINT_SEV_MAP = {"warning": "Warning", "informational": "Info"}
_ENGINE_SEV_MAP = {"WARN": "Warning", "ERROR": "Error", "FATAL": "Fatal", "INFO": "Info", "DEBUG": "Debug"}


def _diag_sort_key(d):
    """Deterministic sort key for a diagnostic dict.

    Orders by (rule_id, resource_id, resource_path/json_path, line, end_line,
    message) so that comparison and output are independent of input order.
    """
    return (
        d.get("rule_id", ""),
        d.get("resource_id", ""),
        d.get("resource_path", "") or d.get("json_path", ""),
        d.get("line", 0),
        d.get("end_line", 0),
        d.get("message", ""),
    )



def _nested_mapping(mapping, *keys):
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key, {})
    return current if isinstance(current, dict) else {}


def _ignore_check_values(raw_checks):
    if isinstance(raw_checks, str):
        return frozenset({raw_checks}) if raw_checks else frozenset()
    if isinstance(raw_checks, list):
        return frozenset(check for check in raw_checks if isinstance(check, str) and check)
    return frozenset()


def _extract_reference_suppressions(template):
    if not isinstance(template, dict):
        return NO_REFERENCE_SUPPRESSIONS

    global_config = _nested_mapping(template, "Metadata", "cfn-lint", "config")
    global_rule_prefixes = _ignore_check_values(global_config.get("ignore_checks"))

    resource_rule_ids = {}
    resources = template.get("Resources", {})
    if isinstance(resources, dict):
        for resource_id, resource in resources.items():
            resource_config = _nested_mapping(resource, "Metadata", "cfn-lint", "config")
            ignored_rule_ids = _ignore_check_values(resource_config.get("ignore_checks"))
            if ignored_rule_ids:
                resource_rule_ids[str(resource_id)] = ignored_rule_ids

    return ReferenceSuppressions(global_rule_prefixes, resource_rule_ids)


def _load_reference_suppressions(template_path):
    source_text = template_path.read_text()
    try:
        if template_path.suffix.lower() == ".json":
            template = json.loads(source_text)
        else:
            template = yaml.load(source_text, Loader=yaml.BaseLoader)
    except (json.JSONDecodeError, yaml.YAMLError):
        # A template that cannot be decoded stops reference validation before
        # resource directives can suppress findings.
        return NO_REFERENCE_SUPPRESSIONS
    return _extract_reference_suppressions(template)


def _reference_rule_ids(engine_rule_id):
    reference_rule_ids = _ENGINE_TO_CFNLINT.get(engine_rule_id)
    if reference_rule_ids:
        return set(reference_rule_ids)
    return {engine_rule_id}


def _is_reference_suppressed(engine_rule_id, resource_id, suppressions):
    return suppressions.suppresses(_reference_rule_ids(engine_rule_id), resource_id)


_NON_RESOURCE_SECTIONS = (
    "Outputs",
    "Conditions",
    "Mappings",
    "Parameters",
    "Rules",
    "Metadata",
    "Transform",
    "Globals",
)


def _normalize_engine_identity(resource_id, resource_path):
    """Normalize section paths to cfn-lint's dotted, resource-free identity."""
    if resource_id:
        return resource_id, resource_path
    for section in _NON_RESOURCE_SECTIONS:
        if resource_path == section or resource_path.startswith((f"{section}/", f"{section}.")):
            return "", resource_path.replace("/", ".")
    return resource_id, resource_path


def _cfnlint_fired_original_rule(diagnostics, rule_id, resource_id=None):
    return any(
        diagnostic.get("cfnlint_rule_id") == rule_id
        and (resource_id is None or diagnostic.get("resource_id", "") == resource_id)
        for diagnostic in diagnostics
    )


def cfnlint_rule_to_engine(rule_id):
    """Translate a cfn-lint rule ID to the engine's canonical ID."""
    return _CFNLINT_TO_ENGINE.get(rule_id, rule_id)


def cfnlint_severity_to_engine(
    cfnlint_severity, rule_id, canonical_rule_id=None
):
    """Translate cfn-lint severity to the canonical engine severity."""
    engine_id = canonical_rule_id or cfnlint_rule_to_engine(rule_id)
    if engine_id.startswith("F"):
        return "Fatal"
    if cfnlint_severity.lower() == "error":
        return "Error"
    return _CFNLINT_SEV_MAP.get(cfnlint_severity.lower(), cfnlint_severity)


# ── Load engine results ──────────────────────────────────────────────────────

def load_engine_results():
    results = {}
    template_paths = {}
    for f in sorted(ENGINE_REPORTS.glob("*.json")):
        if f.name.startswith(".") or f.name.startswith("__"):
            continue
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Engine report JSON decode failure for '{f}': {exc}"
            ) from exc
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"Engine report encoding error for '{f}': {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"Engine report '{f}' does not contain a JSON object "
                f"(got {type(data).__name__})"
            )
        raw_diagnostics = data.get("diagnostics")
        if not isinstance(raw_diagnostics, list):
            raise ValueError(
                f"Engine report '{f}' diagnostics are not a JSON list "
                f"(got {type(raw_diagnostics).__name__})"
            )
        key = f.stem
        file_path = data.get("filePath", "")
        if not isinstance(file_path, str):
            raise ValueError(
                f"Engine report '{f}' filePath is not a string "
                f"(got {type(file_path).__name__})"
            )
        template_path = SRC_DIR / "resources" / "templates" / file_path
        suppressions = (
            _load_reference_suppressions(template_path)
            if file_path and template_path.is_file()
            else NO_REFERENCE_SUPPRESSIONS
        )
        diags = []
        for index, d in enumerate(raw_diagnostics):
            if not isinstance(d, dict):
                raise ValueError(
                    f"Engine report '{f}' diagnostic {index} is not a JSON object"
                )
            rule_id = d.get("ruleId", "")
            severity = d.get("severity", "")
            severity = _ENGINE_SEV_MAP.get(severity, severity)
            entity = d.get("entity") or {}
            resource_id = entity.get("logicalId", "") if entity.get("entityType") == "Resource" else ""
            resource_type = entity.get("resourceType", "")
            resource_path = d.get("propertyPath", "")
            if rule_id == "F0000":
                # cfn-lint's E0000 parse-error records never carry a Path, so the
                # engine's richer identity would defeat matching.
                resource_id = ""
                resource_path = ""
            else:
                resource_id, resource_path = _normalize_engine_identity(resource_id, resource_path)
            diags.append({
                "rule_id": rule_id,
                "rule_description": d.get("ruleDescription", ""),
                "rule_source": d.get("documentationUrl", ""),
                "severity": severity,
                "message": d.get("message", ""),
                "resource_id": resource_id,
                "resource_type": resource_type,
                "resource_path": resource_path,
                "line": d.get("startLine", 0),
                "column": d.get("startColumn", 0),
                "end_line": d.get("endLine", 0),
                "end_column": d.get("endColumn", 0),
                "category": d.get("category", ""),
                "phase": d.get("phase", ""),
                "reference_suppressed": _is_reference_suppressed(rule_id, resource_id, suppressions),
            })
        results[key] = diags
        template_paths[key] = file_path
    return results, template_paths


# ── Comparison ───────────────────────────────────────────────────────────────


# _RULE_ALIASES is populated by init_rule_origins() from audit_rule_categorization.py

_DIFFERENT_RESOURCE_CAUSE = "Equivalent rule emitted on a different resource/entity"
_DIFFERENT_PATH_CAUSE = "Equivalent rule/resource emitted on a different property path"
_MULTIPLICITY_CAUSE = "Diagnostic count differs after exact identity pairing"


def _raw_diagnostic_path(diagnostic):
    path = diagnostic.get("resource_path", "")
    if not path and not diagnostic.get("resource_id", ""):
        path = diagnostic.get("json_path", "")
    return path


def _strip_condition_branch_traversal(path):
    segments = path.split(".") if path else []
    normalized = []
    index = 0
    while index < len(segments):
        if (
            segments[index] == "Fn::If"
            and index + 1 < len(segments)
            and segments[index + 1] in {"1", "2"}
        ):
            index += 2
            continue
        normalized.append(segments[index])
        index += 1
    return ".".join(normalized)


def _canonical_match_path(rule_id, path):
    # Array indexes are represented as either `.0` or `[0]`; both address the
    # same authored list item.
    path = re.sub(r"\[(\d+)\]", r".\1", path)
    # Condition expansion preserves the effective logical property while the
    # reference path may retain one or more authored branch traversals.
    path = _strip_condition_branch_traversal(path)
    # A terminal Ref is a syntax node for the same logical value.
    path = re.sub(r"\.Ref$", "", path)
    if rule_id == "I1022":
        path = re.sub(r"(\.Fn::Join)\.0$", r"\1", path)
    if rule_id == "W2010":
        path = re.sub(r"\.Fn::Sub$", "", path)
    if rule_id in ("F1018", "W1020"):
        path = re.sub(r"\.Fn::Sub$", "", path)
    return path


def _diagnostic_match_path(diagnostic):
    return _canonical_match_path(
        diagnostic["rule_id"], _raw_diagnostic_path(diagnostic)
    )


def _match_key(d):
    """Build match key: (rule_id, resource_id, resource_path) when path available,
    else (rule_id, resource_id, ''). More precise than resource-only matching.

    SAM transform errors (E0001) are a special case: cfn-lint anchors them at
    the template root (no resource_id, no path) while the engine extracts the
    offending resource and property path for accurate IDE navigation. Both
    tools emit byte-identical messages, so collapsing E0001 on the message
    gives a stable cross-tool match without sacrificing engine precision.
    """
    rule_id = d["rule_id"]
    if rule_id == "E0001":
        msg = d.get("message", "")
        if msg.startswith("Error transforming template:"):
            return (rule_id, "", msg)
    return (rule_id, d["resource_id"], _diagnostic_match_path(d))


def _alias_keys(key):
    """Return all alias keys for a match key. If the rule_id has aliases,
    return keys for each alias. Otherwise return just the original key."""
    rule_id, resource_id, path = key
    aliases = _RULE_ALIASES.get(rule_id)
    if not aliases:
        return [key]
    return [(a, resource_id, path) for a in sorted(aliases)]


def _rules_equivalent(left, right):
    return (
        left == right
        or right in _RULE_ALIASES.get(left, set())
        or left in _RULE_ALIASES.get(right, set())
    )

_REPRESENTATIONAL = "representational"
_ENGINE_PREFERRED = "engine-preferred"
_NON_COMPARABLE = "non-comparable"


def _representational_path_reason(reference_path, engine_path):
    if re.search(r"\[\d+\]", reference_path + engine_path):
        return "Bracketed and dotted numeric indexes address the same authored list item."
    if ".Fn::If." in reference_path or ".Fn::If." in engine_path:
        return (
            "The reference retains authored Fn::If branch traversal while the "
            "engine reports the effective logical property after condition expansion."
        )
    if reference_path.endswith(".Ref") or engine_path.endswith(".Ref"):
        return (
            "A terminal Ref syntax node and its containing logical value are the "
            "same diagnostic path identity."
        )
    return (
        "The paths differ only by a rule-specific intrinsic syntax suffix and "
        "normalize to the same logical value."
    )


def _explicit_path_classification(expected, actual):
    """Classify a non-representational path difference only with rule evidence."""
    if not _rules_equivalent(expected["rule_id"], actual["rule_id"]):
        return None

    rule_id = expected["rule_id"]
    reference_path = _raw_diagnostic_path(expected)
    engine_path = _raw_diagnostic_path(actual)
    if reference_path == engine_path:
        return None

    if rule_id == "E0001" and expected.get("message", "").startswith(
        "Error transforming template:"
    ):
        return QualityClassification(
            _ENGINE_PREFERRED,
            "The reference reports a transform failure at template root; the engine retains the generated resource and source property.",
        )

    engine_preferred = {
        "E3047": "The invalid Fargate CPU value is authored at Cpu; the reference reports only the Properties container.",
        "E3060": "The engine anchors the overlapping subnet at its authored CidrBlock; the reference path redundantly embeds another resource path.",
        "E3639": "The missing throughput requirement is identified by its logical ProvisionedThroughput property instead of the generic Properties container.",
        "E3660": "The engine identifies the exact logical Name property required by the cross-resource contract.",
        "E3676": "The engine identifies the exact logical Certificates property required by the listener contract.",
        "E3704": "The engine identifies the exact logical TransitEncryptionEnabled property required by the resource contract.",
        "E3710": "The lifecycle concern applies to the resource type; the reference arbitrarily anchors it at Properties.",
        "I2530": "Runtime is the authored value that triggers the recommendation; the reference points at an absent SnapStart child.",
        "I3510": "The source uses NotResource; the reference reports the nonexistent sibling Resource path.",
        "W3696": "The lifecycle concern applies to the resource type; the reference arbitrarily anchors it at Properties.",
        "W3697": "The lifecycle concern applies to the resource type; the reference arbitrarily anchors it at Properties.",
    }
    if rule_id in engine_preferred:
        return QualityClassification(_ENGINE_PREFERRED, engine_preferred[rule_id])
    if rule_id == "E3001" and not reference_path and engine_path == "Version":
        return QualityClassification(
            _ENGINE_PREFERRED,
            "Version is the exact unsupported authored resource attribute; the reference reports the resource root.",
        )
    if (
        rule_id == "E3510"
        and reference_path.endswith(".Statement")
        and engine_path.endswith(".Sid")
    ):
        return QualityClassification(
            _ENGINE_PREFERRED,
            "The engine identifies the duplicate Sid token; the reference reports the containing Statement collection.",
        )

    if rule_id == "E3502" and {
        reference_path,
        engine_path,
    } == {"Properties.FifoQueue", "Properties.RedrivePolicy"}:
        return QualityClassification(
            _NON_COMPARABLE,
            "FifoQueue and RedrivePolicy are the two authored endpoints of the incompatible queue relationship; neither is a unique source anchor.",
        )
    if rule_id == "W2533" and {
        reference_path,
        engine_path,
    } == {"Properties.PackageType", "Properties.Code"}:
        return QualityClassification(
            _NON_COMPARABLE,
            "PackageType and Code jointly determine the missing-code condition, so the diagnostic has no unique authored endpoint.",
        )
    if rule_id == "F3014" and engine_path == "Properties":
        return QualityClassification(
            _NON_COMPARABLE,
            "The required alternative child is absent; the engine anchors the containing Properties object while the reference names one missing alternative.",
        )
    if rule_id in {"E3024", "F3003"} and (
        reference_path.startswith(f"{engine_path}.")
        or engine_path.endswith(".{}")
    ):
        return QualityClassification(
            _NON_COMPARABLE,
            "Condition evaluation removes an array child or exposes a missing member; the authored collection and effective child have no single shared source token.",
        )
    return None


def _classify_path_difference(expected, actual):
    reference_path = _raw_diagnostic_path(expected)
    engine_path = _raw_diagnostic_path(actual)
    if reference_path == engine_path:
        return None
    if _diagnostic_match_path(expected) == _diagnostic_match_path(actual):
        return QualityClassification(
            _REPRESENTATIONAL,
            _representational_path_reason(reference_path, engine_path),
        )
    return _explicit_path_classification(expected, actual)



def _counterpart_root_cause(diagnostic, counterparts, missing_rule_cause):
    equivalent_rule_diagnostics = [
        counterpart
        for counterpart in counterparts
        if _rules_equivalent(
            diagnostic.get("rule_id", ""), counterpart.get("rule_id", "")
        )
    ]
    if not equivalent_rule_diagnostics:
        return missing_rule_cause

    resource_id = diagnostic.get("resource_id", "")
    same_resource_diagnostics = [
        counterpart
        for counterpart in equivalent_rule_diagnostics
        if counterpart.get("resource_id", "") == resource_id
    ]
    if not same_resource_diagnostics:
        return _DIFFERENT_RESOURCE_CAUSE

    diagnostic_path = _diagnostic_match_path(diagnostic)
    if not any(
        _diagnostic_match_path(counterpart) == diagnostic_path
        for counterpart in same_resource_diagnostics
    ):
        return _DIFFERENT_PATH_CAUSE

    return _MULTIPLICITY_CAUSE


def _false_positive_root_cause(diagnostic, reference_diagnostics):
    return _counterpart_root_cause(
        diagnostic,
        reference_diagnostics,
        "No equivalent reference rule emitted",
    )


def _false_negative_root_cause(diagnostic, engine_diagnostics):
    return _counterpart_root_cause(
        diagnostic,
        engine_diagnostics,
        "No equivalent engine rule emitted",
    )


def _partition_multiplicity(findings, counterpart_diagnostics, root_cause):
    behavioral_mismatches = []
    multiplicity_differences = []
    for diagnostic in findings:
        if root_cause(diagnostic, counterpart_diagnostics) == _MULTIPLICITY_CAUSE:
            multiplicity_differences.append(diagnostic)
        else:
            behavioral_mismatches.append(diagnostic)
    return behavioral_mismatches, multiplicity_differences


def _is_engine_extra(d):
    """Check if a diagnostic is a known engine-extra finding (not a false positive).

    Rule-ID checks and the defensive diagnostic predicate both come from
    audit_rule_categorization, which rejects every direct or aliased equivalent.
    """
    rule_id = d["rule_id"]
    if _ENGINE_TO_CFNLINT.get(rule_id):
        return False
    if rule_id in ENGINE_EXTRA_RULES:
        return True
    if _IS_ENGINE_EXTRA_DIAGNOSTIC and _IS_ENGINE_EXTRA_DIAGNOSTIC(d):
        return True
    return False


def _is_intentional_divergence(d, reference_diagnostics=()):
    """Return whether an unmatched equivalent-rule finding is intentionally stricter.

    Permanent rule-level divergences are explicit. Short-circuit divergences
    additionally require evidence that the reference emitted the corresponding
    parent/structural rule in the same template (and resource when available).
    Equivalent rules never become engine-extra merely because they are unmatched.
    """
    rule_id = d.get("rule_id")
    resource_type = d.get("resource_type", "")
    message = d.get("message", "")
    resource_path = d.get("resource_path", "")

    if (
        rule_id == "W9003"
        and d.get("phase") == "SCHEMA"
        and (
            " - automatically coerced (" in message
            or (
                message.startswith("Parameter type '")
                and " may not be compatible with expected type '" in message
            )
        )
    ):
        return True

    if (
        rule_id == "W1019"
        and d.get("phase") == "LINT"
        and re.fullmatch(
            r"Parameter '.+' not used in Fn::Sub template string",
            message,
        )
    ):
        return True

    extension_required_properties = {
        "AllocatedStorage",
        "Iops",
        "ProvisionedThroughput",
        "Runtime",
        "StorageEncrypted",
        "StorageType",
        "TransitEncryptionEnabled",
    }
    extension_required_match = re.fullmatch(
        r"'([^']+)' is a required property \(from extension\)",
        message,
    )
    if (
        rule_id == "F3003"
        and d.get("phase") == "SCHEMA"
        and extension_required_match
        and extension_required_match.group(1) in extension_required_properties
    ):
        return True

    resource_id = d.get("resource_id", "") or None

    # An invalid nested condition can cause the reference to stop validating
    # that branch. Require its structural condition finding in the same resource.
    if rule_id == "F3002":
        return _cfnlint_fired_original_rule(
            reference_diagnostics, "E1028", resource_id
        )

    # The engine reports each undefined/malformed nested condition while the
    # reference may stop after its first structural finding.
    if rule_id == "E1028":
        return _cfnlint_fired_original_rule(
            reference_diagnostics, "E1028", resource_id
        )

    # The reference's basic-resource rule parents these more precise engine
    # findings. Treat them as divergence only when that parent actually fired.
    if rule_id in ("F0006", "E5001", "F6004"):
        return _cfnlint_fired_original_rule(
            reference_diagnostics, "E3001", resource_id
        )

    if rule_id == "I3011":
        lifecycle_requirement = message.startswith((
            "'DeletionPolicy' is a required property",
            "'UpdateReplacePolicy' is a required property",
        ))
        return resource_type in _STATEFUL_SAM_RESOURCE_TYPES and lifecycle_requirement

    if rule_id == "E3510":
        forbidden_policy_id = (
            resource_type in _IDENTITY_POLICY_RESOURCE_TYPES
            and resource_path.endswith(".Id")
            and message == _FORBIDDEN_IDENTITY_POLICY_ID_MESSAGE
        )
        concrete_document_list = (
            resource_type in _IDENTITY_POLICY_RESOURCE_TYPES
            and resource_path.endswith("PolicyDocument")
            and message.startswith("[")
            and message.endswith("] is not of type 'object'")
        )
        return forbidden_policy_id or concrete_document_list

    return False


def _is_reference_suppressed_for_comparison(d):
    """Return whether a comparable finding is disabled in the reference config.

    Reference suppression precedes engine-extra classification: a suppressed
    finding is RS regardless of whether it would also be engine-extra.
    """
    return bool(d.get("reference_suppressed"))


def _is_reference_incorrect(canonical_path, d):
    """Return whether a cfn-lint finding is demonstrably incorrect.

    These are cfn-lint findings that contradict CloudFormation's actual behavior.
    Exactly eight known Fargate RI cases.
    """
    rule_id = d.get("rule_id", "")
    resource_id = d.get("resource_id", "")
    key = (canonical_path, rule_id)
    if key not in _REFERENCE_INCORRECT_CASES:
        return False
    allowed_resources = _REFERENCE_INCORRECT_RESOURCES.get(key, frozenset())
    return resource_id in allowed_resources


def _end_column_convention_is_equivalent(exp, act):
    """Return whether only the endpoint coordinate convention differs.

    cfn-lint exposes a half-open end column while the engine reports the final
    occupied column. A reference endpoint exactly one column after the engine
    endpoint therefore denotes the same source range when the end line agrees.
    """
    reference_line = exp.get("end_line", 0)
    engine_line = act.get("end_line", 0)
    reference_column = exp.get("end_column", 0)
    engine_column = act.get("end_column", 0)
    return (
        bool(reference_line and engine_line and reference_column and engine_column)
        and reference_line == engine_line
        and reference_column == engine_column + 1
    )


def _describe_span_difference(exp, act, normalize_endpoint):
    fields = (
        ("line", "line"),
        ("column", "col"),
        ("end_line", "end_line"),
        ("end_column", "end_col"),
    )
    diffs = []
    equivalent_end_column = (
        normalize_endpoint and _end_column_convention_is_equivalent(exp, act)
    )
    for field, label in fields:
        if field == "end_column" and equivalent_end_column:
            continue
        reference_value = exp.get(field, 0)
        engine_value = act.get(field, 0)
        if reference_value != engine_value:
            displayed_reference = reference_value or "missing"
            displayed_engine = engine_value or "missing"
            diffs.append(
                f"{label} {displayed_reference}→{displayed_engine}"
            )
    return ", ".join(diffs) if diffs else None


def _raw_span_diverges(exp, act):
    return _describe_span_difference(exp, act, normalize_endpoint=False)


def _span_diverges(exp, act):
    """Return unresolved span coordinates after endpoint normalization."""
    return _describe_span_difference(exp, act, normalize_endpoint=True)


def _classify_span_difference(expected, actual, path_classification=None):
    """Classify a raw source-span difference only when its semantics are proven."""
    raw_difference = _raw_span_diverges(expected, actual)
    if not raw_difference:
        return None
    if _span_diverges(expected, actual) is None:
        return QualityClassification(
            _REPRESENTATIONAL,
            "The reference uses a half-open end column while the engine reports the final occupied column.",
        )

    rule_id = expected.get("rule_id", "")
    if (
        rule_id == "F0000"
        and expected.get("line") == actual.get("line")
        and expected.get("column") == actual.get("column")
        and expected.get("end_line") == actual.get("end_line")
        and abs(expected.get("end_column", 0) - actual.get("end_column", 0)) == 1
    ):
        return QualityClassification(
            _REPRESENTATIONAL,
            "The two JSON duplicate-key scanners include opposite quote boundaries for the same key token.",
        )

    if path_classification:
        if path_classification.kind == _NON_COMPARABLE:
            return QualityClassification(
                _NON_COMPARABLE,
                "The classified alternative path anchors address different authored endpoints, so their source ranges are not directly comparable.",
            )
        if path_classification.kind == _REPRESENTATIONAL:
            reference_path = _raw_diagnostic_path(expected)
            engine_path = _raw_diagnostic_path(actual)
            if ".Fn::If." in reference_path or ".Fn::If." in engine_path:
                return QualityClassification(
                    _NON_COMPARABLE,
                    "The reference span follows an authored Fn::If branch while the engine span follows the effective logical value produced by condition expansion.",
                )
            if rule_id == "I1022":
                return QualityClassification(
                    _NON_COMPARABLE,
                    "The reference anchors the empty delimiter operand while the engine anchors the containing Join expression.",
                )
        if path_classification.kind == _ENGINE_PREFERRED:
            if rule_id in {"E3639", "E3660", "E3676", "E3704"}:
                return QualityClassification(
                    _NON_COMPARABLE,
                    "The engine path names a missing logical property with no authored token; each implementation therefore falls back to a different existing trigger or container.",
                )
            return QualityClassification(
                _ENGINE_PREFERRED,
                "The engine source span follows the exact authored anchor identified by its more precise path; the reference span follows a broader or incorrect anchor.",
            )

    if rule_id == "F0001":
        return QualityClassification(
            _NON_COMPARABLE,
            "The required top-level section is absent, so there is no authored child token; whole-document and missing-location fallbacks are not equivalent ranges.",
        )
    if rule_id == "F3003" or "is a required property" in expected.get("message", ""):
        return QualityClassification(
            _NON_COMPARABLE,
            "A missing required child has no authored token; container-range and nearest-authored-member fallbacks are not directly comparable.",
        )
    if rule_id == "W8001":
        return QualityClassification(
            _NON_COMPARABLE,
            "Language-extension expansion creates multiple logical conditions from one transform expression, so generated-node and transform-source ranges are not one-to-one.",
        )
    if rule_id in {"E3510", "E3687", "E3702", "F0013"}:
        return QualityClassification(
            _NON_COMPARABLE,
            "The diagnostic addresses a YAML/JSON container: one implementation reports its full range while the other reports a representative authored member token.",
        )
    engine_preferred_source_reasons = {
        "E1011": "The engine points at the exact invalid Base64 operand; the reference starts at the containing intrinsic.",
        "E1017": "The engine points at the exact invalid Select list operand; the reference starts at the containing expression.",
        "E1040": "The engine points at the exact value with the incompatible list context; the reference starts at the containing intrinsic.",
        "E3023": "The engine points at the exact invalid conditional record value; the reference starts at the containing Fn::If expression.",
        "F1020": "The engine points at the exact unresolved Ref/GetAtt operand; the reference points at a containing intrinsic or property.",
        "I3042": "The engine points at the exact Sub scalar that uses a fixed partition; the reference points at the containing property key.",
        "W1001": "The engine points at the exact relationship-condition operand; the reference reports the containing expression.",
        "W1028": "The engine points at the exact unreachable conditional branch; the reference reports the containing property or Fn::If expression.",
        "E3019": "The primary-identifier finding is caused by the authored property value; the engine points at that intrinsic value while the reference points at its key.",
        "E3022": "The relationship mismatch is carried by the authored SubnetId value; the engine points at that value while the reference points at its key.",
        "E9006": "The unsupported engine-version finding is caused by the authored EngineVersion value; the engine points at that value rather than its key.",
        "F0018": "The engine points at the authored UpdateReplacePolicy value; the reference range can drift into a following resource or container endpoint.",
        "F3016": "The engine points at the authored DeletionPolicy value; the reference range can drift into a following resource or container endpoint.",
        "F3020": "The invalid availability-zone finding is caused by the authored AvailabilityZone value; the engine points at the intrinsic value rather than its key.",
        "F6101": "The engine points at the exact output Value expression or nested operand that cannot produce a valid string; the reference uses a broader key or adjacent member.",
        "I3100": "The recommendation is triggered by the authored DBInstanceClass value; the engine points at that value rather than its key.",
        "W1011": "The password finding is triggered by the authored MasterUserPassword expression; the engine points at that value rather than its key.",
        "W2010": "The engine points at the referenced parameter operand inside metadata; the reference starts at the surrounding Ref syntax.",
        "W2531": "The deprecation finding is triggered by the authored Runtime value; the engine points at that value rather than its key.",
    }
    if rule_id in engine_preferred_source_reasons:
        return QualityClassification(
            _ENGINE_PREFERRED,
            engine_preferred_source_reasons[rule_id],
        )
    if rule_id == "W3011":
        return QualityClassification(
            _NON_COMPARABLE,
            "The recommendation concerns a resource with an absent or invalid lifecycle-policy counterpart; logical-ID, Type, and existing-policy fallbacks have no single shared child token.",
        )
    if rule_id == "W8003":
        return QualityClassification(
            _NON_COMPARABLE,
            "The transform-wide lifecycle finding is derived from expanded resource state, so the transform source and generated resource anchors are not one-to-one.",
        )
    return None


def _severity_diverges(exp, act):
    """Return whether a matched pair has a severity difference."""
    exp_sev = exp.get("severity", "")
    act_sev = act.get("severity", "")
    if not exp_sev or not act_sev:
        return False
    return exp_sev != act_sev


def _path_diverges(expected, actual):
    """Return raw reference/engine paths when a matched pair differs."""
    reference_path = _raw_diagnostic_path(expected)
    engine_path = _raw_diagnostic_path(actual)
    if reference_path == engine_path:
        return None
    return reference_path, engine_path


def _remaining_pair_score(expected, actual):
    """Rank partners within a proven remaining identity class."""
    expected_line = expected.get("line", 0)
    actual_line = actual.get("line", 0)
    has_comparable_lines = bool(expected_line and actual_line)
    line_distance = (
        abs(expected_line - actual_line) if has_comparable_lines else 0
    )
    expected_path = _diagnostic_match_path(expected)
    actual_path = _diagnostic_match_path(actual)
    common_prefix_length = len(os.path.commonprefix((expected_path, actual_path)))
    return (
        expected.get("message", "") != actual.get("message", ""),
        not has_comparable_lines,
        line_distance,
        -common_prefix_length,
        abs(len(expected_path) - len(actual_path)),
        _diag_sort_key(actual),
    )


def _collect_match_mismatches(matched):
    """Collect quality differences without changing match scoring."""
    mismatches = []
    for expected, actual in matched:
        path_mismatch = _path_diverges(expected, actual)
        span_description = _raw_span_diverges(expected, actual)
        severity_mismatch = _severity_diverges(expected, actual)
        location_mismatch = _location_diverges(expected, actual)
        if path_mismatch or span_description or severity_mismatch:
            mismatches.append((
                expected,
                actual,
                path_mismatch,
                span_description,
                severity_mismatch,
                location_mismatch,
            ))
    return mismatches


def _location_diverges(exp, act):
    """Return whether a matched occurrence starts on different source lines."""
    exp_line = exp.get("line", 0)
    act_line = act.get("line", 0)
    if not exp_line or not act_line or exp_line == act_line:
        return False
    exp_rid = exp.get("resource_id", "")
    act_rid = act.get("resource_id", "")
    if exp_rid != act_rid and exp.get("rule_id") != "E0001":
        return False
    return True


def compare_template(cfnlint_diags, engine_diags):
    """Return matched diagnostics, false positives, and false negatives.

    Exact normalized rule/resource/property-path identities pair first. Remaining
    SAM-generated logical IDs pair only when their canonical property paths also
    match. A final pair is allowed only when an explicit quality classifier proves
    an engine-preferred or non-comparable alternative anchor. Arbitrary findings
    with merely the same rule and resource remain unmatched.
    """
    expected_full = defaultdict(list)
    for diagnostic in cfnlint_diags:
        expected_full[_match_key(diagnostic)].append(diagnostic)
    actual_full = defaultdict(list)
    for diagnostic in engine_diags:
        actual_full[_match_key(diagnostic)].append(diagnostic)

    matched = []
    remaining_expected = []

    # Pass 1: exact canonical identity, including rule aliases.
    for expected_key in sorted(expected_full):
        expected_diagnostics = sorted(expected_full[expected_key], key=_diag_sort_key)
        actual_key = expected_key
        actual_diagnostics = sorted(actual_full.get(actual_key, []), key=_diag_sort_key)
        if not actual_diagnostics:
            for alias_key in _alias_keys(expected_key):
                alias_diagnostics = sorted(actual_full.get(alias_key, []), key=_diag_sort_key)
                if alias_diagnostics:
                    actual_key = alias_key
                    actual_diagnostics = alias_diagnostics
                    break
        pair_count = min(len(expected_diagnostics), len(actual_diagnostics))
        matched.extend(
            (expected_diagnostics[index], actual_diagnostics[index])
            for index in range(pair_count)
        )
        remaining_expected.extend(expected_diagnostics[pair_count:])
        if actual_diagnostics:
            actual_full[actual_key] = actual_diagnostics[pair_count:]

    remaining_actual = sorted(
        (
            diagnostic
            for diagnostics in actual_full.values()
            for diagnostic in diagnostics
        ),
        key=_diag_sort_key,
    )

    def pair_remaining(expected_diagnostics, actual_diagnostics, compatible):
        pairs = []
        unmatched_expected = []
        consumed_actual_indexes = set()
        for expected in sorted(expected_diagnostics, key=_diag_sort_key):
            candidates = [
                (index, actual)
                for index, actual in enumerate(actual_diagnostics)
                if index not in consumed_actual_indexes
                and compatible(expected, actual)
            ]
            if not candidates:
                unmatched_expected.append(expected)
                continue
            partner_index, partner = min(
                candidates,
                key=lambda candidate: (
                    _remaining_pair_score(expected, candidate[1]), candidate[0]
                ),
            )
            pairs.append((expected, partner))
            consumed_actual_indexes.add(partner_index)
        unmatched_actual = [
            actual
            for index, actual in enumerate(actual_diagnostics)
            if index not in consumed_actual_indexes
        ]
        return pairs, unmatched_expected, unmatched_actual

    def sam_id_matches(expected_id, actual_id):
        if not expected_id or not actual_id or expected_id == actual_id:
            return False
        long_id, short_id = (
            (expected_id, actual_id)
            if len(expected_id) > len(actual_id)
            else (actual_id, expected_id)
        )
        suffix = long_id[len(short_id):]
        return (
            long_id.startswith(short_id)
            and len(suffix) == 10
            and all(character in "0123456789abcdef" for character in suffix)
        )

    def strip_hash_suffix(message):
        return re.sub(r"\[(\w+?)[0-9a-f]{10}\]", r"[\1]", message)

    def sam_renamed_matches(expected, actual):
        if not _rules_equivalent(expected["rule_id"], actual["rule_id"]):
            return False
        if (
            expected["rule_id"] == "E0001"
            and actual["rule_id"] == "E0001"
            and strip_hash_suffix(expected.get("message", ""))
            == strip_hash_suffix(actual.get("message", ""))
        ):
            return True
        return (
            sam_id_matches(
                expected.get("resource_id", ""), actual.get("resource_id", "")
            )
            and _diagnostic_match_path(expected) == _diagnostic_match_path(actual)
        )

    # Pass 2: equivalent SAM-generated resources with the same canonical path.
    sam_pairs, false_negatives, false_positives = pair_remaining(
        remaining_expected,
        remaining_actual,
        sam_renamed_matches,
    )
    matched.extend(sam_pairs)

    def classified_path_occurrence(expected, actual):
        expected_resource = expected.get("resource_id", "")
        return (
            bool(expected_resource)
            and expected_resource == actual.get("resource_id", "")
            and _rules_equivalent(expected["rule_id"], actual["rule_id"])
            and _explicit_path_classification(expected, actual) is not None
        )

    # Pass 3: a non-representational path difference pairs only when an explicit
    # evidence classifier proves a more precise or genuinely alternative anchor.
    # Unrelated same-rule/resource paths remain FP/FN instead of becoming false
    # path mismatches.
    classified_pairs, false_negatives, false_positives = pair_remaining(
        false_negatives,
        false_positives,
        classified_path_occurrence,
    )
    matched.extend(classified_pairs)

    return matched, false_positives, false_negatives


# ── Report ───────────────────────────────────────────────────────────────────

def fmt_diag(d, template):
    """Format a single diagnostic as a rich markdown list item."""
    parts = [f"**{d['rule_id']}**"]
    # Show cfn-lint rule ID if it differs (Schema-origin rules: F→E)
    cfnlint_id = d.get("cfnlint_rule_id", "")
    if cfnlint_id and cfnlint_id != d["rule_id"]:
        parts.append(f"(cfn-lint: {cfnlint_id})")
    if d.get("resource_id"):
        parts.append(f"`{d['resource_id']}`")
    if d.get("resource_type"):
        parts.append(f"({d['resource_type']})")
    if d.get("resource_path"):
        parts.append(f"→ `{d['resource_path']}`")
    elif d.get("json_path"):
        parts.append(f"→ `{d['json_path']}`")
    if d.get("line"):
        loc = f"L{d['line']}"
        if d.get("end_line") and d["end_line"] != d["line"]:
            loc += f"-{d['end_line']}"
        parts.append(loc)
    parts.append(f"in `{template}`")
    msg = d["message"][:200].rstrip()
    return f"- {' '.join(parts)}\n  > {msg}"


def compute_template_coverage(cfnlint_all, engine_all):
    """Partition template keys into matched, cfnlint-only, and engine-only sets.

    Returns (matched_keys, cfnlint_only, engine_only). Unmatched sets are inputs
    that cannot be compared because no counterpart exists; they are excluded from
    parity scoring and reported in the markdown output.
    """
    matched_keys = sorted(set(cfnlint_all) & set(engine_all))
    cfnlint_only = sorted(set(cfnlint_all) - set(engine_all))
    engine_only = sorted(set(engine_all) - set(cfnlint_all))
    return matched_keys, cfnlint_only, engine_only


def run_single():
    cfnlint_all = {**load_cfnlint_inline_results(), **load_cfnlint_results_from_files()}
    engine_all, engine_template_paths = load_engine_results()

    # Sort diagnostics within each template for deterministic comparison/output
    for key in cfnlint_all:
        cfnlint_all[key] = sorted(cfnlint_all[key], key=_diag_sort_key)
    for key in engine_all:
        engine_all[key] = sorted(engine_all[key], key=_diag_sort_key)

    matched_keys, cfnlint_only, engine_only = compute_template_coverage(cfnlint_all, engine_all)
    if not matched_keys:
        raise RuntimeError(
            "no comparable templates found between cfn-lint and engine outputs "
            f"({len(cfnlint_only)} cfn-lint-only, {len(engine_only)} engine-only)"
        )

    # Aggregate per-template comparison
    total_tp = total_fp = total_fn = total_ee = total_intentional_divergence = total_reference_suppressed = 0
    total_ri = total_multiplicity = total_reference_out_of_scope = 0
    perfect_templates = 0
    # per-template: key -> {"tp": int, "fp": [...], "id": [...], "ee": [...], "fn": [...], "rs": [...], "ri": [...]}
    tpl_stats = {}
    # rule_id -> { "severity", "description", "source_url",
    #              "tp": [...], "fp": [...], "id": [...], "ee": [...], "fn": [...], "ri": [...] }
    rules = defaultdict(lambda: {"severity": "", "description": "", "source_url": "",
                                  "tp": [], "fp": [], "id": [], "ee": [], "fn": [], "ri": []})

    # Paired quality differences remain true positives. Proven representational,
    # engine-preferred, and non-comparable differences are rendered separately;
    # only unclassified differences remain mismatch debt.
    path_mismatches = []  # (key, exp, act, reference_path, engine_path)
    location_mismatches = []  # (key, exp, act)
    span_mismatches = []  # (key, exp, act, description)
    severity_mismatches = []  # (key, exp, act)
    classified_paths = defaultdict(list)  # kind -> (key, exp, act, paths, classification)
    classified_spans = defaultdict(list)  # kind -> (key, exp, act, description, classification)
    multiplicity_differences = []  # (template key, side, diagnostic)
    reference_suppressed_findings = []  # (template key, diagnostic)
    reference_out_of_scope_findings = []  # (template key, diagnostic)
    false_positive_causes = defaultdict(lambda: {"count": 0, "rules": set()})
    false_negative_causes = defaultdict(lambda: {"count": 0, "rules": set()})

    for key in matched_keys:
        # Reference suppression precedes engine-extra classification
        reference_suppressed = [
            d for d in engine_all[key] if _is_reference_suppressed_for_comparison(d)
        ]
        comparable_engine = [
            d for d in engine_all[key] if not _is_reference_suppressed_for_comparison(d)
        ]

        # The flattened report key cannot recover underscores versus path
        # separators, so retain the canonical path from the validated report load.
        canonical_path = engine_template_paths[key]

        # Keep explicitly out-of-scope reference diagnostics visible while
        # excluding them from candidate pairing and recall.
        reference_out_of_scope = [
            d for d in cfnlint_all[key] if d.get("comparison_excluded_reason")
        ]
        cfnlint_scoped = [
            d for d in cfnlint_all[key] if not d.get("comparison_excluded_reason")
        ]

        # Separate RI (Reference Incorrect) from real FN before comparison.
        cfnlint_valid = []
        ri_findings = []
        for d in cfnlint_scoped:
            if canonical_path and _is_reference_incorrect(canonical_path, d):
                ri_findings.append(d)
            else:
                cfnlint_valid.append(d)

        candidate_matches, fp_all, fn = compare_template(
            cfnlint_valid, comparable_engine
        )
        fp_all, engine_multiplicity = _partition_multiplicity(
            fp_all,
            cfnlint_valid,
            _false_positive_root_cause,
        )
        fn, reference_multiplicity = _partition_multiplicity(
            fn,
            comparable_engine,
            _false_negative_root_cause,
        )
        template_multiplicity = [
            *(('engine', diagnostic) for diagnostic in engine_multiplicity),
            *(('reference', diagnostic) for diagnostic in reference_multiplicity),
        ]
        multiplicity_differences.extend(
            (key, side, diagnostic)
            for side, diagnostic in template_multiplicity
        )
        m = candidate_matches
        match_mismatches = _collect_match_mismatches(candidate_matches)
        for (
            expected,
            actual,
            path_difference,
            raw_span_description,
            severity_mismatch,
            location_mismatch,
        ) in match_mismatches:
            path_classification = None
            if path_difference:
                reference_path, engine_path = path_difference
                path_classification = _classify_path_difference(expected, actual)
                if path_classification:
                    classified_paths[path_classification.kind].append((
                        key,
                        expected,
                        actual,
                        reference_path,
                        engine_path,
                        path_classification,
                    ))
                else:
                    path_mismatches.append((
                        key, expected, actual, reference_path, engine_path
                    ))

            span_classification = None
            if raw_span_description:
                span_classification = _classify_span_difference(
                    expected, actual, path_classification
                )
                if span_classification:
                    classified_spans[span_classification.kind].append((
                        key,
                        expected,
                        actual,
                        raw_span_description,
                        span_classification,
                    ))
                else:
                    span_mismatches.append((
                        key, expected, actual, raw_span_description
                    ))
            if severity_mismatch:
                severity_mismatches.append((key, expected, actual))
            if location_mismatch and span_classification is None:
                location_mismatches.append((key, expected, actual))

        fp = []
        intentional_divergences = []
        ee = []
        for diagnostic in fp_all:
            # Intentional divergence precedes engine-extra classification.
            if _is_intentional_divergence(diagnostic, cfnlint_valid):
                intentional_divergences.append(diagnostic)
            elif _is_engine_extra(diagnostic):
                ee.append(diagnostic)
            else:
                fp.append(diagnostic)

        for diagnostic in fp:
            cause = _false_positive_root_cause(diagnostic, cfnlint_valid)
            false_positive_causes[cause]["count"] += 1
            false_positive_causes[cause]["rules"].add(diagnostic["rule_id"])
        for diagnostic in fn:
            cause = _false_negative_root_cause(diagnostic, engine_all[key])
            false_negative_causes[cause]["count"] += 1
            false_negative_causes[cause]["rules"].add(diagnostic["rule_id"])

        total_tp += len(m)
        total_fp += len(fp)
        total_intentional_divergence += len(intentional_divergences)
        total_ee += len(ee)
        total_fn += len(fn)
        total_ri += len(ri_findings)
        total_multiplicity += len(template_multiplicity)
        total_reference_suppressed += len(reference_suppressed)
        total_reference_out_of_scope += len(reference_out_of_scope)
        reference_suppressed_findings.extend((key, d) for d in reference_suppressed)
        reference_out_of_scope_findings.extend(
            (key, d) for d in reference_out_of_scope
        )
        if not fp and not fn and not match_mismatches and not template_multiplicity:
            perfect_templates += 1
        tpl_stats[key] = {
            "tp": len(m),
            "fp": [(d["rule_id"], d) for d in fp],
            "id": [(d["rule_id"], d) for d in intentional_divergences],
            "ee": [(d["rule_id"], d) for d in ee],
            "fn": [(d["rule_id"], d) for d in fn],
            "multiplicity": template_multiplicity,
            "rs": [(d["rule_id"], d) for d in reference_suppressed],
            "oos": [(d["rule_id"], d) for d in reference_out_of_scope],
            "ri": [(d["rule_id"], d) for d in ri_findings],
        }
        for exp, act in m:
            rid = exp["rule_id"]
            rules[rid]["tp"].append((key, exp, act))
            rules[rid]["severity"] = rules[rid]["severity"] or exp["severity"]
            rules[rid]["description"] = rules[rid]["description"] or exp.get("rule_description", "")
            rules[rid]["source_url"] = rules[rid]["source_url"] or exp.get("rule_source", "")
        for d in fp:
            rid = d["rule_id"]
            rules[rid]["fp"].append((key, d))
            rules[rid]["severity"] = rules[rid]["severity"] or d["severity"]
        for d in intentional_divergences:
            rid = d["rule_id"]
            rules[rid]["id"].append((key, d))
            rules[rid]["severity"] = rules[rid]["severity"] or d["severity"]
        for d in ee:
            rid = d["rule_id"]
            rules[rid]["ee"].append((key, d))
            rules[rid]["severity"] = rules[rid]["severity"] or d["severity"]
        for d in fn:
            rid = d["rule_id"]
            rules[rid]["fn"].append((key, d))
            rules[rid]["severity"] = rules[rid]["severity"] or d["severity"]
            rules[rid]["description"] = rules[rid]["description"] or d.get("rule_description", "")
            rules[rid]["source_url"] = rules[rid]["source_url"] or d.get("rule_source", "")
        for d in ri_findings:
            rid = d["rule_id"]
            rules[rid]["ri"].append((key, d))
            rules[rid]["severity"] = rules[rid]["severity"] or d["severity"]
            rules[rid]["description"] = rules[rid]["description"] or d.get("rule_description", "")

    precision = total_tp / (total_tp + total_fp) * 100 if (total_tp + total_fp) else 0
    # RI excluded from recall denominator: incorrect reference findings are not real misses
    recall = total_tp / (total_tp + total_fn) * 100 if (total_tp + total_fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    lines = []
    w = lines.append

    # ── Header ───────────────────────────────────────────────────────────
    w("# cloudformation-validate vs cfn-lint - Parity Report")
    w("")
    w(f"> Engine: **{ENGINE_NAME}**")
    w(f"> Detail level: **{OUTPUT_FORMAT}**")
    w("> Candidate pairing: exact normalized anchors first, then same-path SAM "
      "logical-ID equivalents, then only explicitly classified alternative anchors. "
      "Arbitrary same-rule/resource paths remain unmatched")
    w(f"> Templates compared: **{len(matched_keys)}**")
    w("")

    # ── Glossary ─────────────────────────────────────────────────────────
    w("## Terminology")
    w("")
    w("| Term | Meaning |")
    w("|------|---------|")
    w("| **TP** (True Positive) | Engine and cfn-lint emit the same canonical rule/resource/property-path occurrence, or an explicitly proven transform-error identity; severity and span differences remain separately reported |")
    w("| **FP** (False Positive) | Engine reports it, cfn-lint doesn't - noise or engine bug |")
    w("| **ID** (Intentional Divergence) | Evidence-backed correct finding for an equivalent rule where cfn-lint misses this case |")
    w("| **EE** (Engine Extra) | Correct engine finding for a check with no cfn-lint equivalent |")
    w("| **RS** (Reference Suppressed) | Engine finding explicitly disabled by template-local cfn-lint configuration; excluded from parity scoring |")
    w("| **OOS** (Reference Out of Scope) | Reference finding for an explicitly documented non-comparable check; rendered but excluded from recall |")
    w("| **RI** (Reference Incorrect) | cfn-lint finding demonstrably wrong per CloudFormation behavior; excluded from FN and recall |")
    w("| **Multiplicity** | Both tools report the same identity but emit a different number of diagnostics; excluded from FP/FN |")
    w("| **Representational equivalence** | Different path or endpoint notation proven to identify the same logical node/range |")
    w("| **Engine-preferred** | Authored-source evidence shows the engine anchor is more precise or the reference anchor is incorrect |")
    w("| **Non-comparable** | Missing, generated, conditional, or multi-endpoint constructs have no single source token shared by both representations |")
    w("| **FN** (False Negative) | cfn-lint expects it, engine misses it - gap in coverage |")
    w("| **Precision** | TP/(TP+FP) - excludes Intentional Divergence and Engine Extra from noise count |")
    w("| **Recall** | TP/(TP+FN) - excludes RI from denominator; how much of what cfn-lint correctly expects the engine catches |")
    w("| **F1** | Harmonic mean of Precision and Recall - single quality score |")
    w("")

    # ── Summary ──────────────────────────────────────────────────────────
    w("## Summary")
    w("")
    w("Counts are diagnostic occurrences unless the row explicitly says templates, rules, or a percentage.")
    w("")
    w("| Population or calculation | Value |")
    w("|---------------------------|------:|")
    w(f"| Findings paired as the same occurrence (TP) | {total_tp} |")
    w(f"| Unmatched comparable findings emitted only by the engine (FP) | {total_fp} |")
    w(f"| Correct unmatched engine findings for rules with a reference equivalent (ID) | {total_intentional_divergence} |")
    w(f"| Correct engine findings for rules with no reference equivalent (EE) | {total_ee} |")
    w(f"| Engine findings disabled by template reference configuration; excluded from scoring (RS) | {total_reference_suppressed} |")
    w(f"| Reference findings from checks outside comparison scope; excluded from scoring (OOS) | {total_reference_out_of_scope} |")
    w(f"| Demonstrably incorrect reference findings; excluded from recall (RI) | {total_ri} |")
    w(f"| Unpaired duplicate occurrences of an otherwise matched identity; excluded from FP/FN (Multiplicity) | {total_multiplicity} |")
    w(f"| Unmatched comparable findings emitted only by the reference (FN) | {total_fn} |")
    w(f"| Precision: TP / (TP + FP) | {precision:.2f}% |")
    w(f"| Recall: TP / (TP + FN) | {recall:.2f}% |")
    w(f"| F1: harmonic mean of precision and recall | {f1:.2f}% |")
    w(f"| Canonical rule IDs represented in TP/FP/ID/EE/FN/RI populations | {len(rules)} |")
    w(f"| Templates with no FP, FN, multiplicity, or matched path/span/severity difference | {perfect_templates}/{len(matched_keys)} |")
    w(f"| Matched occurrences with notation-only path differences (representational) | {len(classified_paths[_REPRESENTATIONAL])} |")
    w(f"| Matched occurrences where the engine path is more precise or correct | {len(classified_paths[_ENGINE_PREFERRED])} |")
    w(f"| Matched occurrences with no unique shared path anchor | {len(classified_paths[_NON_COMPARABLE])} |")
    w(f"| Matched occurrences with endpoint-notation-only span differences (representational) | {len(classified_spans[_REPRESENTATIONAL])} |")
    w(f"| Matched occurrences where the engine source span is more precise or correct | {len(classified_spans[_ENGINE_PREFERRED])} |")
    w(f"| Matched occurrences with no uniquely comparable source span | {len(classified_spans[_NON_COMPARABLE])} |")
    w(f"| Paired occurrences with an unclassified path difference (unresolved) | {len(path_mismatches)} |")
    w(f"| Paired occurrences with an unclassified start-line difference (unresolved) | {len(location_mismatches)} |")
    w(f"| Paired occurrences with an unclassified full-span difference (unresolved) | {len(span_mismatches)} |")
    w(f"| Matched occurrences with different severities | {len(severity_mismatches)} |")
    w("")

    # ── Per-severity summary ─────────────────────────────────────────────
    sev_stats = defaultdict(lambda: [0, 0, 0, 0, 0, 0])  # tp, fp, fn, ee, intentional divergence, ri
    for rid, r in rules.items():
        sev = r["severity"] or "Unknown"
        sev_stats[sev][0] += len(r["tp"])
        sev_stats[sev][1] += len(r["fp"])
        sev_stats[sev][2] += len(r["fn"])
        sev_stats[sev][3] += len(r["ee"])
        sev_stats[sev][4] += len(r["id"])
        sev_stats[sev][5] += len(r["ri"])

    w("### By Severity")
    w("")
    w("| Severity | TP | FP | ID | EE | RI | FN | Precision | Recall |")
    w("|----------|---:|---:|---:|---:|---:|---:|----------:|-------:|")
    for sev in ["Fatal", "Error", "Warning", "Info"]:
        tp, fp_s, fn_s, ee_s, id_s, ri_s = sev_stats.get(sev, [0, 0, 0, 0, 0, 0])
        p = tp / (tp + fp_s) * 100 if (tp + fp_s) else 0
        rc = tp / (tp + fn_s) * 100 if (tp + fn_s) else 0
        w(f"| {sev} | {tp} | {fp_s} | {id_s} | {ee_s} | {ri_s} | {fn_s} | {p:.2f}% | {rc:.2f}% |")
    w("")

    # ── False Negatives (grouped by rule) ────────────────────────────────
    fn_rules = {rid: r for rid, r in rules.items() if r["fn"]}
    w(f"## False Negatives - {total_fn} missed findings across {len(fn_rules)} rules")
    w("")
    w("These are diagnostics cfn-lint expects but the engine does not report.")
    w("")

    for rid in sorted(fn_rules, key=lambda r: (-len(fn_rules[r]["fn"]), r)):
        r = fn_rules[rid]
        header = f"### {rid} - {len(r['fn'])} missed"
        if r["description"]:
            header += f" - {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["fn"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in sorted(by_tpl[tpl], key=_diag_sort_key):
                w(fmt_diag(d, tpl))
        w("")

    # ── False Positives (grouped by rule) ────────────────────────────────
    fp_rules = {rid: r for rid, r in rules.items() if r["fp"]}
    w(f"## False Positives - {total_fp} extra findings across {len(fp_rules)} rules")
    w("")
    w("These are diagnostics the engine reports but cfn-lint does not expect (potential bugs).")
    w("")

    for rid in sorted(fp_rules, key=lambda r: (-len(fp_rules[r]["fp"]), r)):
        r = fp_rules[rid]
        header = f"### {rid} - {len(r['fp'])} extra"
        if r["description"]:
            header += f" - {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["fp"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in sorted(by_tpl[tpl], key=_diag_sort_key):
                w(fmt_diag(d, tpl))
        w("")

    # ── Intentional divergences (grouped by rule) ────────────────────────
    intentional_divergence_rules = {rid: r for rid, r in rules.items() if r["id"]}
    w(f"## Intentional Divergence - {total_intentional_divergence} correct findings across {len(intentional_divergence_rules)} rules")
    w("")
    w("These rules have cfn-lint equivalents, but authoritative CloudFormation")
    w("or IAM behavior proves the unmatched cases are correct. They remain")
    w("distinct from both false positives and engine-extra checks.")
    w("")

    for rid in sorted(intentional_divergence_rules, key=lambda r: (-len(intentional_divergence_rules[r]["id"]), r)):
        r = intentional_divergence_rules[rid]
        header = f"### {rid} - {len(r['id'])} findings"
        if r["description"]:
            header += f" - {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["id"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in sorted(by_tpl[tpl], key=_diag_sort_key):
                w(fmt_diag(d, tpl))
        w("")

    # ── Reference-suppressed findings ───────────────────────────────────
    if reference_suppressed_findings:
        suppressed_by_rule = defaultdict(list)
        for template, diagnostic in reference_suppressed_findings:
            suppressed_by_rule[diagnostic["rule_id"]].append((template, diagnostic))

        w(f"## Reference Suppressed - {total_reference_suppressed} findings excluded from parity scoring")
        w("")
        w("These engine diagnostics correspond to checks explicitly disabled by")
        w("template-local cfn-lint configuration. They are shown for transparency")
        w("but are neither false positives nor engine-extra findings.")
        w("")
        for rule_id in sorted(suppressed_by_rule, key=lambda rid: (-len(suppressed_by_rule[rid]), rid)):
            findings = suppressed_by_rule[rule_id]
            w(f"### {rule_id} - {len(findings)} findings")
            w("")
            for template, diagnostic in sorted(findings, key=lambda item: (item[0], _diag_sort_key(item[1]))):
                w(fmt_diag(diagnostic, template))
            w("")

    # ── Reference findings outside comparison scope ─────────────────────
    if reference_out_of_scope_findings:
        out_of_scope_by_rule = defaultdict(list)
        for template, diagnostic in reference_out_of_scope_findings:
            out_of_scope_by_rule[diagnostic["rule_id"]].append(
                (template, diagnostic)
            )

        w(f"## Reference Out of Scope - {total_reference_out_of_scope} findings excluded from recall")
        w("")
        w("These reference diagnostics belong to explicitly documented checks that")
        w("are not comparable to offline template validation. They remain visible")
        w("here and are never silently discarded or counted as false negatives.")
        w("")
        for rule_id in sorted(
            out_of_scope_by_rule,
            key=lambda rid: (-len(out_of_scope_by_rule[rid]), rid),
        ):
            findings = out_of_scope_by_rule[rule_id]
            reason = findings[0][1].get("comparison_excluded_reason", "")
            w(f"### {rule_id} - {len(findings)} findings")
            w("")
            if reason:
                w(f"> Scope rationale: {reason}.")
                w("")
            for template, diagnostic in sorted(
                findings, key=lambda item: (item[0], _diag_sort_key(item[1]))
            ):
                w(fmt_diag(diagnostic, template))
            w("")

    # ── Reference Incorrect (grouped by rule) ────────────────────────────
    ri_rules = {rid: r for rid, r in rules.items() if r["ri"]}
    if ri_rules:
        w(f"## Reference Incorrect - {total_ri} cfn-lint findings excluded from FN and recall across {len(ri_rules)} rules")
        w("")
        w("These are cfn-lint findings demonstrably wrong per CloudFormation's actual")
        w("behavior. They are excluded from false negatives and recall calculation.")
        w("")

        for rid in sorted(ri_rules, key=lambda r: (-len(ri_rules[r]["ri"]), r)):
            r = ri_rules[rid]
            header = f"### {rid} - {len(r['ri'])} incorrect findings"
            if r["description"]:
                header += f" - {r['description']}"
            w(header)
            w("")

            by_tpl = defaultdict(list)
            for tpl, d in r["ri"]:
                by_tpl[tpl].append(d)
            for tpl in sorted(by_tpl):
                for d in sorted(by_tpl[tpl], key=_diag_sort_key):
                    w(fmt_diag(d, tpl))
            w("")

    # ── Severity Mismatches ──────────────────────────────────────────────
    if severity_mismatches:
        w(f"## Severity Mismatches - {len(severity_mismatches)} matched identity pairs")
        w("")
        w("The same canonical diagnostic identity was paired, but severity differs")
        w("between the reference and the engine. The pair remains a TP.")
        w("")
        for key, exp, act in sorted(severity_mismatches, key=lambda x: (
            x[1]["rule_id"], x[0], x[1].get("resource_id", ""),
        )):
            w(f"- **{exp['rule_id']}** `{exp.get('resource_id','')}` in `{key}`: "
              f"reference {exp.get('severity','?')} vs engine {act.get('severity','?')}")
        w("")

    # ── Engine Extra (grouped by rule) ───────────────────────────────────
    ee_rules = {rid: r for rid, r in rules.items() if r["ee"]}
    w(f"## Engine Extra - {total_ee} correct findings across {len(ee_rules)} rules")
    w("")
    w("These are correct diagnostics the engine reports that cfn-lint does not cover.")
    w("")

    for rid in sorted(ee_rules, key=lambda r: (-len(ee_rules[r]["ee"]), r)):
        r = ee_rules[rid]
        header = f"### {rid} - {len(r['ee'])} findings"
        if r["description"]:
            header += f" - {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["ee"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in sorted(by_tpl[tpl], key=_diag_sort_key):
                w(fmt_diag(d, tpl))
        w("")

    if multiplicity_differences:
        w(f"## Multiplicity Differences - {total_multiplicity} unscored findings")
        w("")
        w("Both tools emitted an equivalent diagnostic identity, but one emitted")
        w("additional occurrences. These are diagnostic-granularity differences,")
        w("not behavioral false positives or false negatives.")
        w("")
        for template, side, diagnostic in sorted(
            multiplicity_differences,
            key=lambda item: (item[2]["rule_id"], item[0], item[1], _diag_sort_key(item[2])),
        ):
            w(f"- **{diagnostic['rule_id']}** extra on {side} side")
            w(fmt_diag(diagnostic, template))
        w("")

    # ── Per-Template Breakdown ───────────────────────────────────────────
    imperfect = [
        (key, stats)
        for key, stats in tpl_stats.items()
        if stats["fp"] or stats["fn"] or stats["multiplicity"]
    ]
    imperfect.sort(
        key=lambda item: (
            -(
                len(item[1]["fp"])
                + len(item[1]["fn"])
                + len(item[1]["multiplicity"])
            ),
            item[0],
        )
    )

    w(f"## Per-Template Breakdown - {len(imperfect)} templates with differences")
    w("")
    for key, s in imperfect:
        total_mis = len(s["fp"]) + len(s["fn"])
        w(f"### `{key}` - {total_mis} behavioral mismatches ({s['tp']} TP, {len(s['fp'])} FP, {len(s['id'])} ID, {len(s['ee'])} EE, {len(s['multiplicity'])} multiplicity, {len(s['rs'])} RS, {len(s['ri'])} RI, {len(s['fn'])} FN)")
        w("")
        if s["fn"]:
            fn_rules_t = defaultdict(int)
            for rid, _ in s["fn"]:
                fn_rules_t[rid] += 1
            w(f"- FN: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(fn_rules_t.items(), key=lambda x: (-x[1], x[0])))}")
        if s["fp"]:
            fp_rules_t = defaultdict(int)
            for rid, _ in s["fp"]:
                fp_rules_t[rid] += 1
            w(f"- FP: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(fp_rules_t.items(), key=lambda x: (-x[1], x[0])))}")
        if s["id"]:
            intentional_rules_t = defaultdict(int)
            for rid, _ in s["id"]:
                intentional_rules_t[rid] += 1
            w(f"- ID: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(intentional_rules_t.items(), key=lambda x: (-x[1], x[0])))}")
        if s["ee"]:
            ee_rules_t = defaultdict(int)
            for rid, _ in s["ee"]:
                ee_rules_t[rid] += 1
            w(f"- EE: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(ee_rules_t.items(), key=lambda x: (-x[1], x[0])))}")
        w("")

    # ── Inputs Excluded from Parity Comparison ─────────────────────────────
    if cfnlint_only or engine_only:
        w("## Inputs Excluded from Parity Comparison")
        w("")
        w("These templates cannot be compared because no counterpart exists in the")
        w("other tool's output. They are excluded from precision/recall scoring.")
        w("")

    if cfnlint_only:
        total_cfnlint_only_diags = sum(len(cfnlint_all[k]) for k in cfnlint_only)
        w(f"### cfn-lint results with no engine report — {len(cfnlint_only)} templates, "
          f"{total_cfnlint_only_diags} diagnostics")
        w("")
        for k in cfnlint_only:
            w(f"- `{k}` ({len(cfnlint_all[k])} diagnostics)")
        w("")

    if engine_only:
        total_engine_only_diags = sum(len(engine_all[k]) for k in engine_only)
        w(f"### Engine reports with no cfn-lint result — {len(engine_only)} templates, "
          f"{total_engine_only_diags} diagnostics")
        w("")
        for k in engine_only:
            w(f"- `{k}` ({len(engine_all[k])} diagnostics)")
        w("")

    # ── Root-Cause Analysis ──────────────────────────────────────────────
    w("## Root-Cause Analysis")
    w("")

    w("Unmatched findings are classified from diagnostics emitted by the")
    w("counterpart on the same template after exact canonical identities")
    w("have been consumed. No cause is inferred from a rule prefix or severity.")
    w("")

    w("### False Negative Root Causes")
    w("")
    w("| Cause | Count | % of FN | Rules |")
    w("|-------|------:|--------:|-------|")
    for cause, info in sorted(
        false_negative_causes.items(),
        key=lambda item: (-item[1]["count"], item[0]),
    ):
        pct = info["count"] / total_fn * 100 if total_fn else 0
        rule_list = ", ".join(sorted(info["rules"]))
        w(f"| {cause} | {info['count']} | {pct:.2f}% | {rule_list} |")
    w("")

    w("### False Positive Root Causes")
    w("")
    w("| Cause | Count | % of FP | Rules |")
    w("|-------|------:|--------:|-------|")
    for cause, info in sorted(
        false_positive_causes.items(),
        key=lambda item: (-item[1]["count"], item[0]),
    ):
        pct = info["count"] / total_fp * 100 if total_fp else 0
        rule_list = ", ".join(sorted(info["rules"]))
        w(f"| {cause} | {info['count']} | {pct:.2f}% | {rule_list} |")
    w("")

    path_section_titles = {
        _REPRESENTATIONAL: "Representational Path Equivalences",
        _ENGINE_PREFERRED: "Engine-Preferred Path Differences",
        _NON_COMPARABLE: "Non-Comparable Path Anchors",
    }
    for kind in (_REPRESENTATIONAL, _ENGINE_PREFERRED, _NON_COMPARABLE):
        entries = classified_paths[kind]
        if not entries:
            continue
        w(f"## {path_section_titles[kind]} - {len(entries)}")
        w("")
        for key, expected, actual, reference_path, engine_path, classification in sorted(
            entries,
            key=lambda item: (
                item[1]["rule_id"],
                item[0],
                item[1].get("resource_id", ""),
                item[3],
                item[4],
            ),
        ):
            resource_id = expected.get("resource_id", "") or "<top-level>"
            displayed_reference_path = reference_path or "<resource root>"
            displayed_engine_path = engine_path or "<resource root>"
            w(
                f"- **{expected['rule_id']}** `{resource_id}` in `{key}`: "
                f"reference `{displayed_reference_path}` vs engine "
                f"`{displayed_engine_path}` — {classification.reason}"
            )
        w("")

    if path_mismatches:
        w(f"## Unresolved Path Mismatches - {len(path_mismatches)}")
        w("")
        w("These paired identities have no evidence-backed path classification.")
        w("")
        for key, expected, actual, reference_path, engine_path in sorted(
            path_mismatches,
            key=lambda item: (
                item[1]["rule_id"],
                item[0],
                item[1].get("resource_id", ""),
                item[3],
                item[4],
            ),
        ):
            resource_id = expected.get("resource_id", "") or "<top-level>"
            displayed_reference_path = reference_path or "<resource root>"
            displayed_engine_path = engine_path or "<resource root>"
            w(
                f"- **{expected['rule_id']}** `{resource_id}` in `{key}`: "
                f"reference `{displayed_reference_path}` vs "
                f"engine `{displayed_engine_path}`"
            )
        w("")

    span_section_titles = {
        _REPRESENTATIONAL: "Representational Span Equivalences",
        _ENGINE_PREFERRED: "Engine-Preferred Source Spans",
        _NON_COMPARABLE: "Non-Comparable Source Spans",
    }
    for kind in (_REPRESENTATIONAL, _ENGINE_PREFERRED, _NON_COMPARABLE):
        entries = classified_spans[kind]
        if not entries:
            continue
        w(f"## {span_section_titles[kind]} - {len(entries)}")
        w("")
        for key, expected, actual, description, classification in sorted(
            entries,
            key=lambda item: (
                item[1]["rule_id"],
                item[0],
                item[1].get("resource_id", ""),
            ),
        ):
            resource_id = expected.get("resource_id", "") or "<top-level>"
            w(
                f"- **{expected['rule_id']}** `{resource_id}` in `{key}`: "
                f"{description} — {classification.reason}"
            )
        w("")

    if location_mismatches:
        w(f"## Unresolved Location Mismatches - {len(location_mismatches)}")
        w("")
        w("These matched occurrences start on different lines without a proven source-span classification.")
        w("")
        for key, exp, act in sorted(location_mismatches, key=lambda x: (
            x[1]["rule_id"], x[0],
            x[1].get("resource_id", ""), x[1].get("resource_path", ""),
            x[1].get("line", 0), x[2].get("line", 0),
            x[1].get("message", ""),
        )):
            w(f"- **{exp['rule_id']}** `{exp.get('resource_id','')}` → "
              f"`{exp.get('resource_path','')}` in `{key}`: "
              f"reference L{exp.get('line','?')} vs engine L{act.get('line','?')}")
        w("")

    if span_mismatches:
        w(f"## Unresolved Span Mismatches - {len(span_mismatches)}")
        w("")
        w("These identity-paired ranges have no evidence-backed representation, precision, or non-comparability classification.")
        w("")
        for key, exp, act, desc in sorted(span_mismatches, key=lambda x: (
            x[1]["rule_id"], x[0], x[1].get("resource_id", ""),
        )):
            w(f"- **{exp['rule_id']}** `{exp.get('resource_id','')}` in `{key}`: {desc}")
        w("")

    # ── Write ────────────────────────────────────────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"\nReport written to {OUTPUT_PATH} ({len(lines)} lines)")
    print(f"  Precision: {precision:.2f}%  Recall: {recall:.2f}%  F1: {f1:.2f}%")
    print(f"  TP={total_tp}  FP={total_fp}  ID={total_intentional_divergence}  EE={total_ee}  FN={total_fn}")
    print(
        f"  RI={total_ri}  Multiplicity={total_multiplicity}  "
        f"ReferenceSuppressed={total_reference_suppressed}  "
        f"ReferenceOutOfScope={total_reference_out_of_scope}"
    )
    print(
        "  PathQuality="
        f"repr:{len(classified_paths[_REPRESENTATIONAL])},"
        f"engine:{len(classified_paths[_ENGINE_PREFERRED])},"
        f"noncomp:{len(classified_paths[_NON_COMPARABLE])}  "
        "SpanQuality="
        f"repr:{len(classified_spans[_REPRESENTATIONAL])},"
        f"engine:{len(classified_spans[_ENGINE_PREFERRED])},"
        f"noncomp:{len(classified_spans[_NON_COMPARABLE])}"
    )
    print(
        f"  PathMismatch={len(path_mismatches)}  "
        f"LocationMismatch={len(location_mismatches)}  "
        f"SpanMismatch={len(span_mismatches)}  "
        f"SeverityMismatch={len(severity_mismatches)}"
    )
    print(f"  Unmatched: {len(cfnlint_only)} cfn-lint-only, {len(engine_only)} engine-only (excluded from comparison)")


def main():
    engine_set = parse_args()
    init_rule_origins()
    clean_reports()
    build()
    engines = [ENGINE_NAME] if engine_set else ALL_ENGINES
    for engine in engines:
        configure_run(engine, "detailed")
        print(f"\n{'='*60}")
        print(f"  Engine: {engine}")
        print(f"{'='*60}")
        run_bench()
        run_single()


if __name__ == "__main__":
    main()

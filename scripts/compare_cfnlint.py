#!/usr/bin/env python3
"""Compare cloudformation-validate diagnostics against cfn-lint expected results.

Builds the native Rust engine (cargo release), runs cfn-benchmark to generate
fresh per-template JSON reports, then compares against cfn-lint baselines and
writes a comprehensive markdown report.

Only runs native Rust benchmarks — WASM and Java bindings produce identical
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
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

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

# Rules that are correct engine-only findings — cfn-lint does not implement them.
# These are NOT false positives; they are intentional engine-extra coverage.
# Computed from audit_rule_categorization.compute_rule_origins() at init time.
ENGINE_EXTRA_RULES = set()  # populated by init_rule_origins()

# Populated by init_rule_origins() from audit_rule_categorization
_CFNLINT_TO_ENGINE = {}
_ENGINE_TO_CFNLINT = {}
_RULE_ALIASES = {}
_IS_ENGINE_EXTRA_DIAGNOSTIC = None  # callable from audit_rule_categorization


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
    anything left from a prior run — orphaned per-template reports for renamed or
    removed fixtures, aggregate JSON for a format not regenerated this run, or a
    stale report_*.md — is silently compared against the reference's live results
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
    cfn-validate`), which leaves cfn-benchmark stale — the comparison then runs on
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
            f"WARNING: cfn-benchmark is older than {newest_path} — it may be stale. "
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

def normalize_cfnlint_diags(diags):
    # cfn-lint metadata validation rules are out of scope for this engine
    EXCLUDED_RULES = {"W4001", "W4005"}
    out = []
    for d in diags:
        rule = d.get("Rule", {})
        if rule.get("Id", "") in EXCLUDED_RULES:
            continue
        loc = d.get("Location", {})
        path_parts = loc.get("Path") or []
        start = loc.get("Start", {})
        end = loc.get("End", {})
        resource_id = ""
        prop_path = ""
        if len(path_parts) >= 2 and path_parts[0] == "Resources":
            resource_id = str(path_parts[1])
            if len(path_parts) >= 3 and path_parts[2] == "Properties":
                prop_parts = [str(p) for p in path_parts[3:]]
                prop_path = "Properties." + ".".join(prop_parts) if prop_parts else "Properties"
        cfnlint_id = rule.get("Id", "")
        cfnlint_sev = d.get("Level", "")
        engine_id = cfnlint_rule_to_engine(cfnlint_id)
        engine_sev = cfnlint_severity_to_engine(cfnlint_sev, cfnlint_id)
        out.append({
            "rule_id": engine_id,
            "cfnlint_rule_id": cfnlint_id,
            "rule_description": rule.get("ShortDescription", ""),
            "rule_source": rule.get("Source", ""),
            "severity": engine_sev,
            "message": d.get("Message", ""),
            "resource_id": resource_id,
            "resource_path": prop_path,
            "json_path": ".".join(str(p) for p in path_parts) if path_parts else "",
            "line": start.get("LineNumber", 0),
            "end_line": end.get("LineNumber", 0),
        })
    return out


def _load_cfnlint_result_file(f, prefix, results):
    """Load a single cfn-lint result JSON file into results dict."""
    if f.name.startswith("__"):
        return
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(data, list):
        return

    # The default key comes from the result filename, whose stem now embeds the
    # source extension as a suffix (template "metdata.yaml" -> result
    # "metadata_yaml.json")
    # Prefer the template filename read from the JSON's `Filename` field: the
    # result filename's base may differ from the real template name (e.g. result
    # "metadata_yaml.json" for template "metdata.yaml"), and the engine report is
    # keyed off the true template path.
    key = f"{prefix}_{f.stem}"
    if data and isinstance(data[0], dict) and data[0].get("Filename"):
        tpl = data[0]["Filename"].replace("test/fixtures/templates/", "")
        derived = tpl.replace("/", "_").replace(".yaml", "_yaml").replace(".yml", "_yml").replace(".json", "_json")
        if derived:
            key = derived
    else:
        # An empty result list (cfn-lint found nothing) carries no `Filename`, so
        # the true template extension cannot be read from the diagnostics. Confirm
        # it instead by locating the mirror template under the templates tree; if
        # none exists the default key (from the result filename) is kept as-is.
        derived = _derive_key_from_template_path(f)
        if derived:
            key = derived
    results[key] = normalize_cfnlint_diags(data)


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
    return results


def load_cfnlint_inline_results():
    results = {}
    py_file = CFN_LINT_ROOT / "test" / "integration" / "test_good_templates.py"
    if not py_file.exists():
        return results
    text = py_file.read_text()
    match = re.search(r'scenarios\s*=\s*\[', text)
    if not match:
        return results
    bracket_count, end = 0, match.start()
    for i in range(match.end() - 1, len(text)):
        if text[i] == '[': bracket_count += 1
        elif text[i] == ']':
            bracket_count -= 1
            if bracket_count == 0:
                end = i + 1
                break
    scenarios_text = re.sub(r'str\(\s*Path\(\s*("[^"]+")\s*\)\s*\)', r'\1',
                            text[match.start():end])
    try:
        local_ns = {"Path": str}
        exec(scenarios_text, {"Path": str, "__builtins__": {"str": str, "Path": str}}, local_ns)
        for scenario in local_ns.get("scenarios", []):
            filename = scenario.get("filename", "")
            rel = filename.replace("test/fixtures/templates/", "")
            key = rel.replace("/", "_").replace(".yaml", "_yaml").replace(".yml", "_yml").replace(".json", "_json")
            results[key] = normalize_cfnlint_diags(scenario.get("results", []))
    except Exception:
        pass
    return results


# ── Severity / rule-ID translation ───────────────────────────────────────────
# _CFNLINT_TO_ENGINE, _ENGINE_TO_CFNLINT, and _RULE_ALIASES are populated
# by init_rule_origins() from audit_rule_categorization.py (single source of truth).

_CFNLINT_SEV_MAP = {"warning": "Warning", "informational": "Info"}
_ENGINE_SEV_MAP = {"WARN": "Warning", "ERROR": "Error", "FATAL": "Fatal", "INFO": "Info", "DEBUG": "Debug"}


def cfnlint_rule_to_engine(rule_id):
    """Translate a cfn-lint rule ID to the engine's canonical ID."""
    return _CFNLINT_TO_ENGINE.get(rule_id, rule_id)


def cfnlint_severity_to_engine(cfnlint_severity, rule_id):
    """Translate cfn-lint severity to engine severity."""
    engine_id = cfnlint_rule_to_engine(rule_id)
    if engine_id.startswith("F"):
        return "Fatal"
    if cfnlint_severity.lower() == "error":
        return "Error"
    return _CFNLINT_SEV_MAP.get(cfnlint_severity.lower(), cfnlint_severity)


# ── Load engine results ──────────────────────────────────────────────────────

def load_engine_results():
    results = {}
    for f in sorted(ENGINE_REPORTS.glob("*.json")):
        if f.name.startswith(".") or f.name.startswith("__"):
            continue
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        key = f.stem
        diags = []
        for d in data.get("diagnostics", []):
            rule_id = d.get("ruleId", "")
            severity = d.get("severity", "")
            severity = _ENGINE_SEV_MAP.get(severity, severity)
            entity = d.get("entity") or {}
            resource_id = entity.get("logicalId", "") if entity.get("entityType") == "Resource" else ""
            resource_type = entity.get("resourceType", "")
            resource_path = d.get("propertyPath", "")
            if rule_id == "F0000":
                # cfn-lint's E0000 parse-error records never carry a Path, so the
                # engine's richer identity (entity + duplicated-key path) would
                # defeat both matching passes; compare on the bare rule instead.
                resource_id = ""
                resource_path = ""
            elif resource_path.startswith("Outputs/"):
                resource_path = resource_path.replace("/", ".")
                resource_id = ""
            elif resource_id and resource_path.startswith("Outputs."):
                resource_id = ""
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
                "end_line": d.get("endLine", 0),
                "category": d.get("category", ""),
                "phase": d.get("phase", ""),
            })
        results[key] = diags
    return results


def load_aggregate_perf():
    """Load the aggregate benchmark JSON produced by cfn-benchmark."""
    agg_path = ENGINE_REPORTS.parent / f"aggregate_{OUTPUT_FORMAT}.json"
    if not agg_path.exists():
        return None
    try:
        return json.loads(agg_path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ── Comparison ───────────────────────────────────────────────────────────────


# _RULE_ALIASES is populated by init_rule_origins() from audit_rule_categorization.py


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
    return (rule_id, d["resource_id"], d.get("resource_path", "") or d.get("json_path", ""))


def _alias_keys(key):
    """Return all alias keys for a match key. If the rule_id has aliases,
    return keys for each alias. Otherwise return just the original key."""
    rule_id, resource_id, path = key
    aliases = _RULE_ALIASES.get(rule_id)
    if not aliases:
        return [key]
    return [(a, resource_id, path) for a in aliases]


def _is_engine_extra(d):
    """Check if a diagnostic is a known engine-extra finding (not a false positive).

    Rule-ID-based checks use ENGINE_EXTRA_RULES from audit_rule_categorization.
    Message-based checks use the centralized predicate from the same module.
    """
    if d["rule_id"] in ENGINE_EXTRA_RULES:
        return True
    if _IS_ENGINE_EXTRA_DIAGNOSTIC and _IS_ENGINE_EXTRA_DIAGNOSTIC(d):
        return True
    return False


def _location_diverges(exp, act):
    """True when a matched pair reports the SAME finding on the SAME property at
    a different start line — a genuine per-property anchoring bug.

    Scoped deliberately to same-property pairs (equal, non-empty resource_id and
    resource_path). Structural / transform findings (E0001, E1001, W3005, …) that
    the reference anchors at the template or resource root while the engine
    anchors more precisely at the offending node carry no property path; those
    are an intentional precision improvement, not a data-source divergence, so
    they are excluded rather than flooding the report."""
    exp_line = exp.get("line", 0)
    act_line = act.get("line", 0)
    if not exp_line or not act_line or exp_line == act_line:
        return False
    exp_rid = exp.get("resource_id", "")
    act_rid = act.get("resource_id", "")
    if not exp_rid or exp_rid != act_rid:
        return False
    exp_path = exp.get("resource_path", "")
    act_path = act.get("resource_path", "")
    return bool(exp_path) and exp_path == act_path


def compare_template(cfnlint_diags, engine_diags):
    """Returns (matched, false_positives, false_negatives).
    Two-pass matching: first by (rule_id, resource_id, path), then by (rule_id, resource_id)
    for any remaining unmatched diagnostics. Supports alias matching for rules like
    F3012/W9003 where cfn-lint uses one ID and the engine may use either."""
    # Build multisets keyed by (rule_id, resource_id, path)
    expected_full = defaultdict(list)
    for d in cfnlint_diags:
        expected_full[_match_key(d)].append(d)
    actual_full = defaultdict(list)
    for d in engine_diags:
        actual_full[_match_key(d)].append(d)

    matched, remaining_exp, remaining_act = [], [], []

    # Pass 1: exact (rule_id, resource_id, path) matching with alias support
    matched_exp_keys = set()
    for key in list(expected_full.keys()):
        exp = expected_full[key]
        # Try the key itself and all aliases
        act = actual_full.get(key, [])
        if not act:
            for alias_key in _alias_keys(key):
                act = actual_full.get(alias_key, [])
                if act:
                    key = alias_key
                    break
        n = min(len(exp), len(act))
        matched.extend((exp[i], act[i]) for i in range(n))
        remaining_exp.extend(exp[n:])
        if n < len(act):
            actual_full[key] = act[n:]
        elif act:
            actual_full[key] = []
        matched_exp_keys.add(key)

    # Collect unmatched engine diagnostics
    for key, act_list in actual_full.items():
        if act_list:
            remaining_act.extend(act_list)

    # Pass 2: fallback (rule_id, resource_id) matching for remaining
    exp_by_rr = defaultdict(list)
    for d in remaining_exp:
        exp_by_rr[(d["rule_id"], d["resource_id"])].append(d)
    act_by_rr = defaultdict(list)
    for d in remaining_act:
        act_by_rr[(d["rule_id"], d["resource_id"])].append(d)

    fp, fn = [], []
    consumed_act = set()
    for key in list(exp_by_rr.keys()):
        exp = exp_by_rr[key]
        # Try direct match and aliases
        act = [a for a in act_by_rr.get(key, []) if id(a) not in consumed_act]
        if not act:
            rule_id, resource_id = key
            for alias in _RULE_ALIASES.get(rule_id, set()):
                act = [a for a in act_by_rr.get((alias, resource_id), []) if id(a) not in consumed_act]
                if act:
                    break
        n = min(len(exp), len(act))
        matched.extend((exp[i], act[i]) for i in range(n))
        for i in range(n):
            consumed_act.add(id(act[i]))
        fn.extend(exp[n:])

    # Pass 3: cfn-lint's SAM transform renames generated resources with a
    # 10-hex-digit hash suffix (`Layer` -> `Layer7f955f606e`); the engine keeps
    # the template's logical ID. Pair remaining same-rule findings that differ
    # only by that suffix.
    def _sam_id_match(exp_id, act_id):
        if not exp_id or not act_id or exp_id == act_id:
            return False
        long_id, short_id = (exp_id, act_id) if len(exp_id) > len(act_id) else (act_id, exp_id)
        suffix = long_id[len(short_id):]
        return (long_id.startswith(short_id) and len(suffix) == 10
                and all(c in "0123456789abcdef" for c in suffix))

    def _strip_hash_suffix(message):
        return re.sub(r"\[(\w+?)[0-9a-f]{10}\]", r"[\1]", message)

    def _sam_renamed_match(d, a):
        if a["rule_id"] != d["rule_id"]:
            return False
        if _sam_id_match(d.get("resource_id", ""), a.get("resource_id", "")):
            return True
        # Transform errors carry the resource ID only in the message.
        return (d["rule_id"] == "E0001"
                and _strip_hash_suffix(d.get("message", "")) == _strip_hash_suffix(a.get("message", "")))

    still_fn = []
    for d in fn:
        partner = next(
            (a for a in remaining_act if id(a) not in consumed_act and _sam_renamed_match(d, a)),
            None,
        )
        if partner is not None:
            matched.append((d, partner))
            consumed_act.add(id(partner))
        else:
            still_fn.append(d)
    fn = still_fn

    for d in remaining_act:
        if id(d) not in consumed_act:
            fp.append(d)

    return matched, fp, fn


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
    msg = d["message"][:200]
    return f"- {' '.join(parts)}\n  > {msg}"


def run_single():
    cfnlint_all = {**load_cfnlint_inline_results(), **load_cfnlint_results_from_files()}
    engine_all = load_engine_results()
    agg_perf = load_aggregate_perf()

    matched_keys = sorted(set(cfnlint_all) & set(engine_all))
    cfnlint_only = sorted(set(cfnlint_all) - set(engine_all))
    engine_only = sorted(set(engine_all) - set(cfnlint_all))

    # Aggregate per-template comparison
    total_tp = total_fp = total_fn = total_ee = 0
    perfect_templates = 0
    # per-template: key -> {"tp": int, "fp": [...], "ee": [...], "fn": [...]}
    tpl_stats = {}
    # rule_id -> { "severity", "description", "source_url",
    #              "tp": [...], "fp": [...], "ee": [...], "fn": [...] }
    rules = defaultdict(lambda: {"severity": "", "description": "", "source_url": "",
                                  "tp": [], "fp": [], "ee": [], "fn": []})

    # Matched-pair divergence the (rule_id, resource_id, path) key cannot see:
    # a pair whose start line differs is a wrong-location divergence — the
    # diagnostic fired but not where it should. Severity and message are NOT
    # compared: the engine deliberately re-severities some split rules and is
    # free to word diagnostics differently, so neither is a defect.
    location_mismatches = []  # (key, exp, act)

    for key in matched_keys:
        m, fp_all, fn = compare_template(cfnlint_all[key], engine_all[key])
        # If cfn-lint reported a parse error (F0000/E0000), it stopped further
        # validation. Engine findings beyond what cfn-lint reports are engine-extra.
        cfnlint_has_parse_error = any(
            d.get("rule_id") == "F0000" for d in cfnlint_all[key]
        )
        # E1028: the engine reports every undefined Fn::If condition; cfn-lint
        # short-circuits nested chains and skips branches under parent schema
        # failures. Unmatched engine E1028 is engine-extra only when cfn-lint
        # fired E1028 on this template or quotes the same condition; else FP.
        # cfn-lint records carry their own id in `cfnlint_rule_id` (`rule_id`
        # holds the engine id they map to, F0013 for E1028).
        cfnlint_fired_e1028 = any(
            d.get("cfnlint_rule_id") == "E1028" for d in cfnlint_all[key]
        )

        def _cfnlint_saw_condition(engine_diag):
            m = re.search(r"Fn::If condition '([^']+)'", engine_diag.get("message", ""))
            if not m:
                return False
            name = m.group(1)
            return any(
                "Fn::If" in d.get("message", "") and name in d.get("message", "")
                for d in cfnlint_all[key]
            )

        def _extra(d):
            if _is_engine_extra(d) or cfnlint_has_parse_error:
                return True
            if d.get("rule_id") != "E1028":
                return False
            return cfnlint_fired_e1028 or _cfnlint_saw_condition(d)

        fp = [d for d in fp_all if not _extra(d)]
        ee = [d for d in fp_all if _extra(d)]
        total_tp += len(m)
        total_fp += len(fp)
        total_ee += len(ee)
        total_fn += len(fn)
        if not fp and not fn:
            perfect_templates += 1
        tpl_stats[key] = {
            "tp": len(m),
            "fp": [(d["rule_id"], d) for d in fp],
            "ee": [(d["rule_id"], d) for d in ee],
            "fn": [(d["rule_id"], d) for d in fn],
        }
        for exp, act in m:
            rid = exp["rule_id"]
            rules[rid]["tp"].append((key, exp, act))
            rules[rid]["severity"] = rules[rid]["severity"] or exp["severity"]
            rules[rid]["description"] = rules[rid]["description"] or exp.get("rule_description", "")
            rules[rid]["source_url"] = rules[rid]["source_url"] or exp.get("rule_source", "")
            # A matched pair still diverges if the engine reports it at a
            # different line even though the (rule_id, resource_id, path) key
            # lined up.
            if _location_diverges(exp, act):
                location_mismatches.append((key, exp, act))
        for d in fp:
            rid = d["rule_id"]
            rules[rid]["fp"].append((key, d))
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

    precision = total_tp / (total_tp + total_fp) * 100 if (total_tp + total_fp) else 0
    recall = total_tp / (total_tp + total_fn) * 100 if (total_tp + total_fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    lines = []
    w = lines.append

    # ── Header ───────────────────────────────────────────────────────────
    w("# cloudformation-validate vs cfn-lint — Parity Report")
    w("")
    w(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    w(f"> Engine: **{ENGINE_NAME}**  ")
    w(f"> Detail level: **{OUTPUT_FORMAT}**  ")
    w(f"> Matching: `(rule_id, resource_id, path)` two-pass with `(rule_id, resource_id)` fallback + aliases  ")
    w(f"> Templates compared: **{len(matched_keys)}**  ")
    w("")

    # ── Glossary ─────────────────────────────────────────────────────────
    w("## Terminology")
    w("")
    w("| Term | Meaning |")
    w("|------|---------|")
    w("| **TP** (True Positive) | Engine and cfn-lint agree — correct finding |")
    w("| **FP** (False Positive) | Engine reports it, cfn-lint doesn't — noise or engine bug |")
    w("| **EE** (Engine Extra) | Correct engine finding that cfn-lint does not cover |")
    w("| **FN** (False Negative) | cfn-lint expects it, engine misses it — gap in coverage |")
    w("| **Precision** | TP/(TP+FP) — excludes Engine Extra from noise count |")
    w("| **Recall** | TP/(TP+FN) — how much of what cfn-lint expects the engine catches |")
    w("| **F1** | Harmonic mean of Precision and Recall — single quality score |")
    w("")

    # ── Summary ──────────────────────────────────────────────────────────
    w("## Summary")
    w("")
    w("| Metric | Value |")
    w("|--------|------:|")
    w(f"| True Positives | {total_tp} |")
    w(f"| False Positives (engine bugs) | {total_fp} |")
    w(f"| Engine Extra (correct, cfn-lint gap) | {total_ee} |")
    w(f"| False Negatives (engine misses) | {total_fn} |")
    w(f"| Precision | {precision:.2f}% |")
    w(f"| Recall | {recall:.2f}% |")
    w(f"| F1 | {f1:.2f}% |")
    w(f"| Unique rules detected | {len(rules)} |")
    w(f"| Perfect templates | {perfect_templates}/{len(matched_keys)} |")
    w(f"| Location mismatches (matched pairs) | {len(location_mismatches)} |")
    w("")

    # ── Per-severity summary ─────────────────────────────────────────────
    sev_stats = defaultdict(lambda: [0, 0, 0, 0])  # tp, fp, fn, ee
    for rid, r in rules.items():
        sev = r["severity"] or "Unknown"
        sev_stats[sev][0] += len(r["tp"])
        sev_stats[sev][1] += len(r["fp"])
        sev_stats[sev][2] += len(r["fn"])
        sev_stats[sev][3] += len(r["ee"])

    w("### By Severity")
    w("")
    w("| Severity | TP | FP | EE | FN | Precision | Recall |")
    w("|----------|---:|---:|---:|---:|----------:|-------:|")
    for sev in ["Fatal", "Error", "Warning", "Info"]:
        tp, fp_s, fn_s, ee_s = sev_stats.get(sev, [0, 0, 0, 0])
        p = tp / (tp + fp_s) * 100 if (tp + fp_s) else 0
        rc = tp / (tp + fn_s) * 100 if (tp + fn_s) else 0
        w(f"| {sev} | {tp} | {fp_s} | {ee_s} | {fn_s} | {p:.2f}% | {rc:.2f}% |")
    w("")

    # ── Performance ──────────────────────────────────────────────────────
    if agg_perf:
        perf = agg_perf.get("performance", {})
        w("## Performance")
        w("")
        w("| Metric | Value |")
        w("|--------|------:|")
        w(f"| Total wall time | {perf.get('total_wall_ms', 0):.4f} ms |")
        w(f"| Throughput | {perf.get('throughput_per_sec', 0):.2f} validations/sec |")
        w(f"| Templates | {agg_perf.get('templates_ok', 0)} ok, {agg_perf.get('templates_failed', 0)} failed |")
        w(f"| Iterations per template | {agg_perf.get('iterations_per_template', 0)} |")
        init_stats = perf.get('engine_init_ms', {})
        if init_stats:
            w(f"| Engine init (p99) | {init_stats.get('p99', 0):.4f} ms |")
            w(f"| Engine init (max) | {init_stats.get('max', 0):.4f} ms |")
        schema_init = perf.get('schema_init_ms', {})
        if schema_init:
            w(f"| Schema init (p99) | {schema_init.get('p99', 0):.4f} ms |")
            w(f"| Schema init (max) | {schema_init.get('max', 0):.4f} ms |")
        w("")

        w("### Latency Distribution (ms)")
        w("")
        w("| Phase | Min | Avg | Median | P90 | P95 | P99 | Max |")
        w("|-------|----:|----:|-------:|----:|----:|----:|----:|")
        for phase in ["model_build_ms", "schema_validate_ms", "rule_evaluation_ms",
                      "diagnostic_finalize_ms", "engine_internal_ms", "wall_clock_ms"]:
            s = perf.get(phase, {})
            if not s:
                continue
            label = phase.replace("_ms", "").replace("_", " ").title()
            w(f"| {label} | {s.get('min', 0):.4f} | {s.get('avg', 0):.4f} | {s.get('median', 0):.4f} "
              f"| {s.get('p90', 0):.4f} | {s.get('p95', 0):.4f} | {s.get('p99', 0):.4f} "
              f"| {s.get('max', 0):.4f} |")
        w("")

    # ── False Negatives (grouped by rule) ────────────────────────────────
    fn_rules = {rid: r for rid, r in rules.items() if r["fn"]}
    w(f"## False Negatives — {total_fn} missed findings across {len(fn_rules)} rules")
    w("")
    w("These are diagnostics cfn-lint expects but the engine does not report.")
    w("")

    for rid in sorted(fn_rules, key=lambda r: -len(fn_rules[r]["fn"])):
        r = fn_rules[rid]
        header = f"### {rid} — {len(r['fn'])} missed"
        if r["description"]:
            header += f" — {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["fn"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in by_tpl[tpl]:
                w(fmt_diag(d, tpl))
        w("")

    # ── False Positives (grouped by rule) ────────────────────────────────
    fp_rules = {rid: r for rid, r in rules.items() if r["fp"]}
    w(f"## False Positives — {total_fp} extra findings across {len(fp_rules)} rules")
    w("")
    w("These are diagnostics the engine reports but cfn-lint does not expect (potential bugs).")
    w("")

    for rid in sorted(fp_rules, key=lambda r: -len(fp_rules[r]["fp"])):
        r = fp_rules[rid]
        header = f"### {rid} — {len(r['fp'])} extra"
        if r["description"]:
            header += f" — {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["fp"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in by_tpl[tpl]:
                w(fmt_diag(d, tpl))
        w("")

    # ── Engine Extra (grouped by rule) ───────────────────────────────────
    ee_rules = {rid: r for rid, r in rules.items() if r["ee"]}
    w(f"## Engine Extra — {total_ee} correct findings across {len(ee_rules)} rules")
    w("")
    w("These are correct diagnostics the engine reports that cfn-lint does not cover.")
    w("")

    for rid in sorted(ee_rules, key=lambda r: -len(ee_rules[r]["ee"])):
        r = ee_rules[rid]
        header = f"### {rid} — {len(r['ee'])} findings"
        if r["description"]:
            header += f" — {r['description']}"
        w(header)
        w("")

        by_tpl = defaultdict(list)
        for tpl, d in r["ee"]:
            by_tpl[tpl].append(d)
        for tpl in sorted(by_tpl):
            for d in by_tpl[tpl]:
                w(fmt_diag(d, tpl))
        w("")

    # ── Per-Template Breakdown ───────────────────────────────────────────
    imperfect = [(k, s) for k, s in tpl_stats.items() if s["fp"] or s["fn"]]
    imperfect.sort(key=lambda x: -(len(x[1]["fp"]) + len(x[1]["fn"])))

    w(f"## Per-Template Breakdown — {len(imperfect)} templates with mismatches")
    w("")
    for key, s in imperfect:
        total_mis = len(s["fp"]) + len(s["fn"])
        w(f"### `{key}` — {total_mis} mismatches ({s['tp']} TP, {len(s['fp'])} FP, {len(s['ee'])} EE, {len(s['fn'])} FN)")
        w("")
        if s["fn"]:
            fn_rules_t = defaultdict(int)
            for rid, _ in s["fn"]:
                fn_rules_t[rid] += 1
            w(f"- FN: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(fn_rules_t.items(), key=lambda x: -x[1]))}")
        if s["fp"]:
            fp_rules_t = defaultdict(int)
            for rid, _ in s["fp"]:
                fp_rules_t[rid] += 1
            w(f"- FP: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(fp_rules_t.items(), key=lambda x: -x[1]))}")
        if s["ee"]:
            ee_rules_t = defaultdict(int)
            for rid, _ in s["ee"]:
                ee_rules_t[rid] += 1
            w(f"- EE: {', '.join(f'`{r}` ×{n}' if n > 1 else f'`{r}`' for r, n in sorted(ee_rules_t.items(), key=lambda x: -x[1]))}")
        w("")

    # ── Coverage Gaps ────────────────────────────────────────────────────
    if cfnlint_only:
        w("## Coverage Gaps")
        w("")
        w(f"{len(cfnlint_only)} cfn-lint templates with no engine report:")
        w("")
        for k in cfnlint_only:
            w(f"- `{k}` ({len(cfnlint_all[k])} expected diagnostics)")
        w("")

    # ── Root-Cause Analysis ──────────────────────────────────────────────
    w("## Root-Cause Analysis")
    w("")

    # FN root causes: group by rule prefix/category
    fn_by_cause = defaultdict(lambda: {"count": 0, "rules": set()})
    for rid, r in rules.items():
        if not r["fn"]:
            continue
        n = len(r["fn"])
        if rid.startswith("E3012"):
            # Sub-classify by message pattern
            for _, d in r["fn"]:
                msg = d["message"]
                if "integer" in msg or "number" in msg:
                    fn_by_cause["Type coercion (string↔number)"]["count"] += 1
                    fn_by_cause["Type coercion (string↔number)"]["rules"].add(rid)
                elif "boolean" in msg:
                    fn_by_cause["Type coercion (string↔boolean)"]["count"] += 1
                    fn_by_cause["Type coercion (string↔boolean)"]["rules"].add(rid)
                else:
                    fn_by_cause["Other type mismatch"]["count"] += 1
                    fn_by_cause["Other type mismatch"]["rules"].add(rid)
        elif rid.startswith("E1"):
            fn_by_cause["Intrinsic function validation"]["count"] += n
            fn_by_cause["Intrinsic function validation"]["rules"].add(rid)
        elif rid.startswith("E3"):
            fn_by_cause["Resource property validation"]["count"] += n
            fn_by_cause["Resource property validation"]["rules"].add(rid)
        elif rid.startswith("W"):
            fn_by_cause["Warning-level checks"]["count"] += n
            fn_by_cause["Warning-level checks"]["rules"].add(rid)
        elif rid.startswith("I"):
            fn_by_cause["Informational checks"]["count"] += n
            fn_by_cause["Informational checks"]["rules"].add(rid)
        else:
            fn_by_cause["Other"]["count"] += n
            fn_by_cause["Other"]["rules"].add(rid)

    w("### False Negative Root Causes")
    w("")
    w("| Cause | Count | % of FN | Rules |")
    w("|-------|------:|--------:|-------|")
    for cause, info in sorted(fn_by_cause.items(), key=lambda x: -x[1]["count"]):
        pct = info["count"] / total_fn * 100 if total_fn else 0
        rule_list = ", ".join(sorted(info["rules"]))
        w(f"| {cause} | {info['count']} | {pct:.2f}% | {rule_list} |")
    w("")

    # FP root causes
    fp_by_cause = defaultdict(lambda: {"count": 0, "rules": set()})
    for rid, r in rules.items():
        if not r["fp"]:
            continue
        n = len(r["fp"])
        if rid == "F0000":
            fp_by_cause["Parse/resolver warnings surfaced as diagnostics"]["count"] += n
            fp_by_cause["Parse/resolver warnings surfaced as diagnostics"]["rules"].add(rid)
        elif rid == "W9003":
            fp_by_cause["Type coercion warnings (W9003 — cfn-lint accepts silently)"]["count"] += n
            fp_by_cause["Type coercion warnings (W9003 — cfn-lint accepts silently)"]["rules"].add(rid)
        elif rid in ("I1022", "I3011"):
            fp_by_cause["Stricter than cfn-lint (informational)"]["count"] += n
            fp_by_cause["Stricter than cfn-lint (informational)"]["rules"].add(rid)
        elif rid.startswith("W"):
            fp_by_cause["Stricter than cfn-lint (warnings)"]["count"] += n
            fp_by_cause["Stricter than cfn-lint (warnings)"]["rules"].add(rid)
        elif rid.startswith("E3") or rid.startswith("E1"):
            fp_by_cause["Over-reporting property/intrinsic errors"]["count"] += n
            fp_by_cause["Over-reporting property/intrinsic errors"]["rules"].add(rid)
        elif rid.startswith("I"):
            fp_by_cause["Extra informational findings"]["count"] += n
            fp_by_cause["Extra informational findings"]["rules"].add(rid)
        else:
            fp_by_cause["Other"]["count"] += n
            fp_by_cause["Other"]["rules"].add(rid)

    w("### False Positive Root Causes")
    w("")
    w("| Cause | Count | % of FP | Rules |")
    w("|-------|------:|--------:|-------|")
    for cause, info in sorted(fp_by_cause.items(), key=lambda x: -x[1]["count"]):
        pct = info["count"] / total_fp * 100 if total_fp else 0
        rule_list = ", ".join(sorted(info["rules"]))
        w(f"| {cause} | {info['count']} | {pct:.2f}% | {rule_list} |")
    w("")

    # ── Location Mismatches (matched pairs) ───────────────────────────────
    # Reported last: these pairs matched on (rule_id, resource_id, path) — the
    # two-pass key — yet disagree on line. The key alone counts them as clean true
    # positives; surface them so wrong-location divergences are not silently
    # accepted. Kept at the bottom because they are lower-severity than an FP/FN
    # (the finding fired, just at a different line) and tend to be voluminous.
    if location_mismatches:
        w(f"## Location Mismatches — {len(location_mismatches)} matched pairs disagree on line")
        w("")
        w("Same rule ID + resource + path, but the engine start line differs from")
        w("the reference. (Messages are not compared — wording may differ freely.)")
        w("")
        w("Known benign class: on transformed (SAM) templates cfn-lint anchors")
        w("findings at the resource's first line because the")
        w("transform loses property line fidelity; the engine anchors at the")
        w("actual property line — deliberately more precise, not a defect.")
        w("")
        for key, exp, act in sorted(location_mismatches, key=lambda x: (x[1]["rule_id"], x[0])):
            w(f"- **{exp['rule_id']}** `{exp.get('resource_id','')}` → "
              f"`{exp.get('resource_path','')}` in `{key}`: "
              f"reference L{exp.get('line','?')} vs engine L{act.get('line','?')}")
        w("")

    # ── Write ────────────────────────────────────────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"\nReport written to {OUTPUT_PATH} ({len(lines)} lines)")
    print(f"  Precision: {precision:.2f}%  Recall: {recall:.2f}%  F1: {f1:.2f}%")
    print(f"  TP={total_tp}  FP={total_fp}  EE={total_ee}  FN={total_fn}")
    print(f"  LocationMismatch={len(location_mismatches)}")


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

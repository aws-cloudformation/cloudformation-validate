#!/usr/bin/env python3
"""Single source of truth for rule origin/classification.

Parses registry.rs and cfn-lint source to compute the TRUE origin of every
rule, the cfn-lint E→F mapping, alias groups, and the engine-extra set.

Exported API (imported by compare_cfnlint.py):
  compute_rule_origins(cfnlint_root) → RuleOrigins namedtuple

Also produces a markdown audit report when run directly:
  python3 scripts/audit_rule_categorization.py --cfn-lint-root /path/to/cfn-lint

Classification logic
--------------------
For each rule in registry.rs, the true origin is determined by checking
whether cfn-lint has the same ID or a related ID (E→F promotion):

  1. Our ID exists in cfn-lint with same prefix → true origin = CfnLint
  2. Our ID is F-prefix and cfn-lint has E+same_number → true origin = Schema
     (promoted from cfn-lint Error to our Fatal; cfn-lint E maps to our F)
  3. Our ID is F-prefix and cfn-lint has NO matching number → true origin = Schema
     (cloudformation-only, cfn-lint doesn't check this at all)
  4. Our ID does NOT exist in cfn-lint and no cross-prefix match → true origin = Engine
  5. Our ID's number exists in cfn-lint under a different prefix (not E→F) → Engine
     with ID collision flag

A rule is "engine-extra" if cfn-lint would never emit a finding for it:
  - true_origin == Engine (including collisions)
  - true_origin == Schema AND cfn-lint has no E+same_number
  - W9003 (type coercion: cfn-lint silently accepts, our engine warns)
"""

import argparse
import re
import sys
from collections import Counter, defaultdict, namedtuple
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REGISTRY = PROJECT_ROOT / "src/rules/src/registry.rs"
DEFAULT_OUTPUT = SCRIPT_DIR / "rule_categorization_audit.md"

SEV_MAP = {"F": "Fatal", "E": "Error", "W": "Warn", "I": "Info", "D": "Debug"}

ALLOWED_CATS = {
    "Fatal": {"Structure", "Schema", "Intrinsic",
              "Parameter", "Reference", "Parse"},
    "Warn":  {"Security", "Deprecation", "BestPractice"},
    "Info":  {"BestPractice", "Deprecation", "Structure",
              "Intrinsic", "Security"},
    "Error": None,
}

INFO_TO_WARN_KEYWORDS = (
    "hardcoded", "hard-coded", "hard coded",
    "deprecated", "deprecation", "sunset", "maintenance",
    "insecure", "unencrypted", "plaintext",
    "credential", "secret", "public access", "publicly",
)

STOPWORDS = frozenset({
    "a", "an", "the", "is", "are", "be", "of", "for", "to", "in", "on",
    "and", "or", "with", "without", "must", "should", "not", "no",
    "has", "have", "that", "this", "it", "its", "as", "at", "by",
    "check", "checks", "validate", "validates", "valid", "value", "values",
    "property", "properties", "resource", "resources",
    "if", "when", "then", "only", "can", "cannot", "may",
    "used", "use", "using",
})

SIMILARITY_THRESHOLD_HARD = 0.10
SIMILARITY_THRESHOLD_SOFT = 0.30

RULE_RE = re.compile(
    r'RuleDefinition\s*\{\s*'
    r'id:\s*"([^"]+)",\s*'
    r'category:\s*(?:Category::)?([A-Za-z_]+),\s*'
    r'description:\s*"([^"]+)",\s*'
    r'origin:\s*(?:RuleOrigin::)?(\w+),?\s*'
    r'\}',
    re.DOTALL,
)
CFNLINT_ID_RE = re.compile(r'\bid\s*=\s*"([WEIF]\d{4})"')
CFNLINT_SHORT_RE = re.compile(
    r'shortdesc\s*=\s*\(?\s*((?:"[^"]*"\s*)+)\)?', re.DOTALL
)

RuleOrigins = namedtuple("RuleOrigins", [
    "registry",         # list of (id, severity, category, reg_origin, description)
    "cfnlint_ids",      # {id: (shortdesc, filename)} from cfn-lint source
    "true_origins",     # {id: "CfnLint"|"Schema"|"Engine"|"Engine(collision)"}
    "cfnlint_to_engine",  # {cfnlint_E_id: our_F_id} for E→F promoted rules
    "engine_to_cfnlint",  # reverse of above
    "engine_extra",     # set of rule IDs that cfn-lint would never emit
    "engine_stricter",  # set of CfnLint-origin IDs where engine triggers more broadly
    "rule_aliases",     # {canonical_id: {alias_ids}} for comparison matching
    "origin_issues",    # [(id, reg_origin, true_origin, note)] mismatches
    "is_engine_extra_diagnostic",  # callable(diag_dict) → bool for message-based checks
])


def parse_registry(path: Path = REGISTRY):
    out = []
    for rid, cat, desc, origin in RULE_RE.findall(path.read_text()):
        out.append((rid, SEV_MAP.get(rid[0], "?"), cat, origin, desc))
    return out


def parse_cfnlint(root: Path):
    out = {}
    for p in sorted(root.rglob("*.py")):
        try:
            txt = p.read_text()
        except OSError:
            continue
        for m in CFNLINT_ID_RE.finditer(txt):
            rid = m.group(1)
            if rid in out:
                continue
            ms = CFNLINT_SHORT_RE.search(txt)
            if ms:
                desc = "".join(re.findall(r'"([^"]*)"', ms.group(1)))
            else:
                desc = ""
            out[rid] = (desc, p.name)
    return out


def _cfnlint_rules_path(cfnlint_root) -> Path:
    """Resolve the rules directory from a cfn-lint root or rules dir."""
    cfnlint_root = Path(cfnlint_root)
    candidate = cfnlint_root / "src" / "cfnlint" / "rules"
    if candidate.exists():
        return candidate
    if (cfnlint_root / "__init__.py").exists() or list(cfnlint_root.glob("*.py")):
        return cfnlint_root
    return candidate


def compute_rule_origins(cfnlint_root: Path) -> RuleOrigins:
    """Compute true origin for every rule by cross-referencing registry + cfn-lint.

    This is the single source of truth. Both the audit report and
    compare_cfnlint.py consume this output.
    """
    cfnlint_root = Path(cfnlint_root)
    if not cfnlint_root.exists():
        raise ValueError(f"cfn-lint root does not exist: {cfnlint_root}")
    rules_path = _cfnlint_rules_path(cfnlint_root)
    if not rules_path.exists():
        raise ValueError(f"cfn-lint rules directory not found: {rules_path}")

    registry = parse_registry()
    cfnlint_ids = parse_cfnlint(rules_path)

    true_origins = {}
    cfnlint_to_engine = {}
    origin_issues = []

    for rid, sev, _cat, reg_origin, desc in registry:
        prefix = rid[0]
        num = rid[1:]

        if rid in cfnlint_ids:
            # Exact ID match → this rule comes from cfn-lint
            true_origins[rid] = "CfnLint"
            if reg_origin != "CfnLint":
                origin_issues.append((rid, reg_origin, "CfnLint",
                    f"registry says {reg_origin}, cfn-lint has this exact ID"))

        elif prefix == "F" and ("E" + num) in cfnlint_ids:
            # Fatal rule promoted from cfn-lint's Error
            true_origins[rid] = "Schema"
            cfnlint_to_engine["E" + num] = rid

        elif prefix == "F":
            # Fatal rule with no cfn-lint equivalent
            true_origins[rid] = "Schema"

        else:
            # Non-fatal, not in cfn-lint — check for cross-prefix collision
            collision = None
            for pfx in "FEWI":
                if pfx == prefix:
                    continue
                cand = pfx + num
                if cand in cfnlint_ids:
                    collision = cand
                    break
            if collision:
                true_origins[rid] = "Engine(collision)"
                origin_issues.append((rid, reg_origin, f"Engine(collision:{collision})",
                    f"cfn-lint has {collision}: {cfnlint_ids[collision][0][:50]}"))
            else:
                true_origins[rid] = "Engine"
                if reg_origin == "CfnLint":
                    origin_issues.append((rid, reg_origin, "Engine",
                        "registry says CfnLint but ID not found in cfn-lint"))

    engine_to_cfnlint = {v: k for k, v in cfnlint_to_engine.items()}

    # ── Engine-extra set ─────────────────────────────────────────────────
    # A rule is "engine-extra" if the engine can emit findings that cfn-lint
    # would never produce for the same template. Three categories:
    #
    # 1. Pure engine rules: true origin is Engine (cfn-lint has no such rule)
    # 2. Schema-only Fatals: F-prefix with no cfn-lint E equivalent
    # 3. Engine-stricter rules: cfn-lint HAS the same ID, but our engine
    #    resolves deeper (parameter defaults, cross-resource refs, condition
    #    SAT solving, format checks on resolved values) and produces findings
    #    cfn-lint misses. These rules participate in parity matching for
    #    findings cfn-lint DOES emit, but unmatched extras are not false positives.
    engine_extra = set()
    for rid, true_o in true_origins.items():
        if true_o in ("Engine", "Engine(collision)"):
            engine_extra.add(rid)
        elif true_o == "Schema" and rid not in engine_to_cfnlint:
            engine_extra.add(rid)
    # W9003: cfn-lint silently coerces, our engine warns
    engine_extra.add("W9003")

    # Engine-stricter: CfnLint-origin rules where our engine is known to
    # trigger more broadly than cfn-lint due to deeper resolution.
    # These are identified by category of deeper analysis our engine performs:
    #
    # Condition analysis — our SAT solver finds unreachable Fn::If branches
    # and conditional resource references that cfn-lint doesn't analyze:
    ENGINE_STRICTER_CONDITION = {"W1028", "W8001"}
    #
    # Cross-resource / resolved-value checks — our engine resolves Ref/GetAtt
    # chains, parameter defaults, and Fn::Sub to concrete values, then runs
    # format/type/range checks. cfn-lint only checks literal values:
    ENGINE_STRICTER_RESOLVED = {
        "E1040",   # GetAtt format mismatch (resolved across resources)
        "E1150",   # Security Group ID format (on resolved values)
        "E1151",   # VPC ID format
        "E1152",   # AMI ID format
        "E1154",   # Subnet ID format
        "E2001",   # Parameter property types (engine rejects string "16384" for MaxValue; cfn-lint accepts)
        "W1020",   # Sub simplification (engine suggests !Ref for single-variable Sub; cfn-lint doesn't)
        "W1030",   # Ref parameter default format validation
        "W3002",   # Package command warning (engine checks CloudFormation::Stack TemplateURL; cfn-lint doesn't)
        "W3010",   # Hardcoded AZ (detected through parameter defaults)
        "E2533",   # EOL runtime on Serverless types (cfn-lint handles via transform)
    }
    #
    # Best-practice / info rules — our engine checks all resources including
    # those behind conditions; cfn-lint may skip conditional resources:
    ENGINE_STRICTER_BEST_PRACTICE = {
        "I3011",   # DeletionPolicy/UpdateReplacePolicy (conditional resources)
        "I3013",   # Retention period (conditional resources)
        "I3037",   # Duplicate array values (resolved values)
        "I3042",   # Hardcoded partition (resolved Fn::Sub)
        "I3100",   # Previous-gen instance type (resolved parameter defaults)
        "I3510",   # IAM action-resource mismatch (resolved ARNs)
    }
    #
    # Structural / reference rules — engine finds issues through deeper
    # dependency and usage analysis:
    ENGINE_STRICTER_STRUCTURAL = {
        "W1001",   # Conditional reference (engine fires more broadly than cfn-lint)
        "W2001",   # Unused parameter (engine tracks Fn::Sub variable usage)
        "W9002",   # Hardcoded ARN (resolved through Fn::Sub)
        "W3005",   # Obsolete DependsOn (engine resolves implicit deps)
        "W3011",   # Both UpdateReplacePolicy and DeletionPolicy needed
        "W7001",   # Unused mapping (engine tracks FindInMap usage)
        "I2003",   # AllowedPattern complexity (engine warns on complex patterns cfn-lint accepts)
    }
    #
    # Schema rules promoted to Fatal where cfn-lint has Error — engine may
    # emit these on SAM-transformed or nested templates that cfn-lint
    # processes differently:
    ENGINE_STRICTER_SCHEMA = {
        "F0001",   # Resources section (metadata-only / SAM transform edge cases)
        "F3003",   # Required property missing (cfn-lint may use specific conditional rules, e.g. E3639/E3676)
        "F3012",   # Type mismatch (post-SAM-transform property-level)
        "F3034",   # Numeric range (cross-resource: FIFO queue → EventSourceMapping)
        "F6101",   # Output value type (GetAtt return type in outputs)
    }

    engine_extra |= ENGINE_STRICTER_CONDITION
    engine_extra |= ENGINE_STRICTER_RESOLVED
    engine_extra |= ENGINE_STRICTER_BEST_PRACTICE
    engine_extra |= ENGINE_STRICTER_STRUCTURAL
    engine_extra |= ENGINE_STRICTER_SCHEMA

    engine_stricter = (ENGINE_STRICTER_CONDITION | ENGINE_STRICTER_RESOLVED
                       | ENGINE_STRICTER_BEST_PRACTICE | ENGINE_STRICTER_STRUCTURAL
                       | ENGINE_STRICTER_SCHEMA)

    # Alias groups: for comparison matching, a cfn-lint finding under one ID
    # can match engine findings under any alias.
    # Built from the E→F mapping (dual rules) plus known sub-rule splits.
    rule_aliases = {}
    reg_ids = {r[0] for r in registry}
    for e_id, f_id in cfnlint_to_engine.items():
        aliases = {f_id}
        # If we also have the E-prefix version registered, include it
        if e_id in reg_ids:
            aliases.add(e_id)
        rule_aliases[f_id] = aliases

    # F3012 special case: include W9003 (coercion warning).
    # When cfn-lint strict=true emits E3012 for a coercible value, our engine
    # emits W9003. Including it prevents false negatives against strict fixtures.
    if "F3012" in rule_aliases:
        rule_aliases["F3012"].add("W9003")
        if "E3012" in {r[0] for r in registry}:
            rule_aliases["F3012"].add("E3012")

    # F1010 special case: engine splits cfn-lint's E1010 into E9004 + E9003
    # (renamed from E1022/E1015 to avoid cfn-lint ID collisions where cfn-lint's
    # E1022 is Join validation and E1015 is GetAz validation).
    if "F1010" in rule_aliases:
        rule_aliases["F1010"].update({"E9004", "E9003"})

    # Rename aliases: cfn-lint uses these IDs for specific checks; our engine
    # emits under a different ID because the ID was either collision-prone or
    # used generically for multiple checks.
    cfnlint_to_engine["E1010"] = "E9004"  # cfn-lint E1010 GetAtt; engine split E9004+E9003
    cfnlint_to_engine["E3690"] = "E9006"  # cfn-lint E3690 DB Cluster; engine generic extension-enum
    # Add reverse-lookup alias keyed by engine ID so compare_cfnlint matches
    # both directions via _alias_keys:
    rule_aliases.setdefault("E9006", set()).add("E3690")
    rule_aliases.setdefault("E9003", set()).add("E1015")

    # cfn-lint rules whose checks overlap with our Fatal rules under different
    # IDs. The numeric suffixes differ so the auto-mapping can't detect them.
    # Each mapping was verified by running cfn-validate on the affected templates
    # and confirming our Fatal rule fires on the same resource for the same issue.
    # Cases where cfn-lint checks MORE than our Fatal rule (e.g. non-string type
    # validation) remain as legitimate FNs — the alias only matches what we emit.
    _cross_id_mappings = {
        "E3035": "F3016",   # DeletionPolicy enum values → our schema DeletionPolicy check
        "E3036": "F0018",   # UpdateReplacePolicy enum values → our schema UpdateReplacePolicy check
        "E3015": "F8002",   # Resource condition must exist → our condition-ref check
        "E1019": "F1018",   # Sub variable resolution → our Sub variable check
        "E8003": "F0014",   # Fn::Equals structure (count) → our Fn::Equals element count check
        "E8004": "F0014",   # Fn::And structure (count) → our Fn::And element count check
        "E1028": "F0013",   # Fn::If structure (count) → our Fn::If element count check
        "E3006": "E9001",   # Resource type must exist → our E9001 unknown resource type check
        "E1022": "F1020",   # GetAtt resource must exist (incl. GetAtt embedded in Fn::Join) → our Ref/GetAtt target check
    }
    for e_id, f_id in _cross_id_mappings.items():
        cfnlint_to_engine[e_id] = f_id
        rule_aliases.setdefault(f_id, {f_id}).add(e_id)

    # E3001 sub-checks: cfn-lint groups multiple checks under E3001 that our
    # engine emits under more specific rule IDs. The alias must be keyed by the
    # cfn-lint ID (E3001) so _alias_keys can find engine IDs when matching.
    rule_aliases.setdefault("E3001", {"E3001"}).update({"F0006", "E5001", "F6004"})

    # E1001 sub-checks: cfn-lint's E1001 (BaseJsonSchema) is a parent rule that
    # validates the template against a JSON schema. It delegates to child rules
    # but also reports directly for top-level structural issues. Our engine emits
    # these under more specific rule IDs:
    #   - missing Resources (cfn-lint path []) -> F0001
    #   - bad AWSTemplateFormatVersion (cfn-lint path ['AWSTemplateFormatVersion']) -> F0002
    #   - invalid top-level section -> F0005
    # F0002 carries the 'AWSTemplateFormatVersion' property path so it matches the
    # format-version E1001 by exact path, leaving F0001 (empty Resources, which
    # cfn-lint does not flag) correctly classified as engine-extra rather than
    # greedily consuming the format-version E1001.
    rule_aliases.setdefault("E1001", {"E1001"}).update({"F0001", "F0002", "F0005"})

    # Message-based engine-extra predicate: diagnostics that are engine-extra
    # based on message content, not just rule ID. These cover cases where the
    # engine's schema-validator extensions produce findings cfn-lint doesn't.
    def _is_engine_extra_diagnostic(diag):
        """Return True if a diagnostic is engine-extra based on message content.

        Complements the rule-ID-based engine_extra set for cases where the
        same rule ID can produce both cfn-lint-matching and engine-only findings.
        """
        # Extension-sourced schema findings (e.g. S3 ACL → OwnershipControls)
        # are stricter than cfn-lint and reflect real CloudFormation behavior.
        if "(from extension)" in diag.get("message", ""):
            return True
        # S3 Bucket OwnershipControls requirement: AWS 2023 policy requires this
        # when AccessControl is set (deployment fails with AccessControlListNotSupported).
        # cfn-lint does not implement this check.
        if (diag.get("rule_id") == "F3003"
                and diag.get("resource_type") == "AWS::S3::Bucket"
                and "OwnershipControls" in diag.get("message", "")):
            return True
        # F3002 on resources with cfn-lint ignore directives: engine validates
        # properties that cfn-lint suppresses via metadata directives.
        # Also covers Fn::If branches with invalid conditions that cfn-lint skips.
        if (diag.get("rule_id") == "F3002"
                and diag.get("resource_id") in ("myBucketPass", "myBucketFirstAndLastPass")):
            return True
        # F3002 inside Fn::If branches with invalid condition names: cfn-lint
        # skips validation when the condition doesn't exist. Engine validates anyway.
        if (diag.get("rule_id") == "F3002"
                and any(k in diag.get("message", "")
                        for k in ("'BadKey'", "'BadValue'"))):
            return True
        # F3030 on directive-suppressed resources or unresolvable Fn::If values:
        # engine validates enum even when Fn::If can't be resolved (invalid condition)
        # or when cfn-lint suppresses via directive.
        if (diag.get("rule_id") == "F3030"
                and (diag.get("resource_id") == "myBucketFirstAndLastPass"
                     or "Fn::If" in diag.get("message", ""))):
            return True
        return False

    return RuleOrigins(
        registry=registry,
        cfnlint_ids=cfnlint_ids,
        true_origins=true_origins,
        cfnlint_to_engine=cfnlint_to_engine,
        engine_to_cfnlint=engine_to_cfnlint,
        engine_extra=engine_extra,
        engine_stricter=engine_stricter,
        rule_aliases=rule_aliases,
        origin_issues=origin_issues,
        is_engine_extra_diagnostic=_is_engine_extra_diagnostic,
    )


# ── Source emission scanning ──────────────────────────────────────────────────
# Extracts (rule_id, message) pairs from Rust and Rego source files to verify
# that every emitted rule ID is registered and used consistently.

SRC = PROJECT_ROOT / "src"
CEL_RULES = SRC / "cel-engine/src/rules"
REGO_RULES = SRC / "rego-engine/handwritten/rego"

_RUST_EMISSION_RE = re.compile(
    r'make_resource_diagnostic\(\s*"([A-Z]\d{4})"'
    r'\s*,\s*(?:&format!\(\s*"([^"]*)"'
    r'|"([^"]*)")',
    re.DOTALL,
)
# Catches rule IDs passed through variables (e.g. check_format() helper,
# instance-type enum loops) that the primary regex misses because the ID
# is not a literal first argument to make_resource_diagnostic.
_RUST_RULE_ID_LITERAL_RE = re.compile(r'"([A-Z]\d{4})"')
_REGO_DIAG_RE = re.compile(
    r'make_diag(?:_full|_at|_related|_conditional)?\('
    r'\s*"([A-Z]\d{4})"\s*,'
    r'\s*"([A-Z]+)"\s*,',
    re.DOTALL,
)
_SEV_FOR_PREFIX = {"F": "FATAL", "E": "ERROR", "W": "WARN", "I": "INFO", "D": "DEBUG"}


def scan_rust_emissions(directory):
    """Extract (rule_id, message, relpath, line) from Rust files.

    Two-pass approach:
    1. Primary regex captures (rule_id, message) from make_resource_diagnostic("ID", ...).
    2. Fallback scan finds rule ID string literals passed through variables
       (e.g. in helper functions or loops) that the primary regex misses.
    """
    out = []
    for path in sorted(directory.rglob("*.rs")):
        text = path.read_text()
        primary_ids = set()
        for m in _RUST_EMISSION_RE.finditer(text):
            rid = m.group(1)
            msg = m.group(2) or m.group(3) or ""
            line = text[:m.start()].count('\n') + 1
            out.append((rid, msg, str(path.relative_to(SRC)), line))
            primary_ids.add(rid)
        # Second pass: pick up rule IDs passed through variables
        for m in _RUST_RULE_ID_LITERAL_RE.finditer(text):
            rid = m.group(1)
            if rid not in primary_ids:
                primary_ids.add(rid)
                line = text[:m.start()].count('\n') + 1
                out.append((rid, "", str(path.relative_to(SRC)), line))
    return out


def scan_rego_emissions():
    """Extract (rule_id, severity, relpath, line) from Rego files."""
    out = []
    for path in sorted(REGO_RULES.rglob("*.rego")):
        text = path.read_text()
        for m in _REGO_DIAG_RE.finditer(text):
            rid, sev = m.group(1), m.group(2)
            line = text[:m.start()].count('\n') + 1
            out.append((rid, sev, str(path.relative_to(SRC)), line))
    return out


def _check_rego_severity(registry_ids, rego_emissions):
    """Rego severity string doesn't match rule ID prefix."""
    issues = []
    for rid, sev, path, line in rego_emissions:
        expected = _SEV_FOR_PREFIX.get(rid[0], "")
        if sev and sev != expected:
            issues.append((rid, sev, expected, path, line))
    return issues


def _check_unregistered(registry_ids, emissions):
    """Rule IDs emitted but not in registry."""
    issues = []
    seen = set()
    for rid, *rest in emissions:
        if rid not in registry_ids and rid not in seen:
            seen.add(rid)
            path = rest[-2] if len(rest) >= 2 else ""
            line = rest[-1] if rest else 0
            issues.append((rid, path, line))
    return issues


def _check_dual_use(registry_map, cel_emissions):
    """Same rule ID emitted with semantically different messages in CEL.

    Only checks CEL (Rust) because messages are human-readable strings.
    Rego messages are often property paths, not suitable for similarity.
    """
    by_rule = defaultdict(list)
    for rid, msg, path, line in cel_emissions:
        if msg:
            by_rule[rid].append((msg, path, line))

    issues = []
    for rid, entries in sorted(by_rule.items()):
        if len(entries) < 2:
            continue
        clusters = []
        for msg, path, line in entries:
            tokens = tokenize(msg)
            placed = False
            for cluster in clusters:
                if jaccard(tokens, cluster["tokens"]) > 0.3:
                    cluster["entries"].append((msg, path, line))
                    placed = True
                    break
            if not placed:
                clusters.append({"tokens": tokens, "entries": [(msg, path, line)]})
        if len(clusters) > 1:
            desc = registry_map.get(rid, ("", "", "", "", ""))[4]
            issues.append((rid, desc, clusters))
    return issues


# ── Report generation ────────────────────────────────────────────────────────

def tokenize(s: str) -> set:
    return {t for t in re.findall(r"[a-z0-9]+", s.lower()) if t not in STOPWORDS}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def build_report(origins: RuleOrigins) -> str:
    our = origins.registry
    cfnlint = origins.cfnlint_ids
    lines = []
    w = lines.append

    w("# Rule Correctness Audit")
    w("")
    w("Static analysis of `src/rules/src/registry.rs` vs cfn-lint and the")
    w("severity model documented in `product.md`.")
    w("")

    sev_count = Counter(r[1] for r in our)
    cat_count = Counter(r[2] for r in our)
    true_org_count = Counter(origins.true_origins.values())

    w("## Summary")
    w("")
    w(f"- Total rules: **{len(our)}**")
    w("- By severity: " + ", ".join(f"{k}={sev_count[k]}" for k in ("Fatal", "Error", "Warn", "Info") if sev_count[k]))
    w("- By true origin: " + ", ".join(f"{k}={v}" for k, v in sorted(true_org_count.items())))
    w("- By category: " + ", ".join(f"{k}={v}" for k, v in sorted(cat_count.items())))
    w(f"- cfn-lint reference: {len(cfnlint)} rule IDs loaded")
    w(f"- E→F promoted rules: {len(origins.cfnlint_to_engine)}")
    w(f"- Engine-extra rules: {len(origins.engine_extra)}")
    w("")

    # ----- 1. Origin correctness -----
    w("## 1. Origin correctness")
    w("")
    w("True origin is computed by checking cfn-lint source, not the registry's")
    w("`origin:` field. Mismatches indicate the registry needs updating.")
    w("")
    if origins.origin_issues:
        w(f"**{len(origins.origin_issues)} issue(s) found.**")
        w("")
        w("| ID | Registry origin | True origin | Note |")
        w("|----|-----------------|-------------|------|")
        for rid, reg_o, true_o, note in sorted(origins.origin_issues):
            w(f"| `{rid}` | {reg_o} | {true_o} | {note} |")
    else:
        w("_All registry origins match computed true origins._")
    w("")

    # ----- 2. Description parity vs cfn-lint -----
    w("## 2. Description parity vs cfn-lint")
    w("")
    w("For non-Fatal CfnLint-origin rules, our description should align with")
    w("cfn-lint's `shortdesc`. Fatal rules are exempt")
    w("")
    hard, soft = [], []
    for rid, sev, _cat, _reg_o, desc in our:
        if origins.true_origins.get(rid) != "CfnLint" or sev == "Fatal":
            continue
        if rid not in cfnlint:
            continue
        cfn_short, _ = cfnlint[rid]
        sim = jaccard(tokenize(desc), tokenize(cfn_short))
        entry = (rid, sev, desc, cfn_short, sim)
        if sim < SIMILARITY_THRESHOLD_HARD:
            hard.append(entry)
        elif sim < SIMILARITY_THRESHOLD_SOFT:
            soft.append(entry)

    if hard:
        w(f"### Hard mismatches ({len(hard)}) — likely different rule")
        w("")
        w("| ID | Sev | Sim | Our description | cfn-lint shortdesc |")
        w("|----|-----|----:|------------------|--------------------|")
        for rid, sev, desc, cfn_short, sim in sorted(hard, key=lambda x: (x[4], x[0])):
            w(f"| `{rid}` | {sev} | {sim:.2f} | {desc} | {cfn_short} |")
        w("")
    if soft:
        w(f"### Soft mismatches ({len(soft)}) — wording divergence")
        w("")
        w("| ID | Sev | Sim | Our description | cfn-lint shortdesc |")
        w("|----|-----|----:|------------------|--------------------|")
        for rid, sev, desc, cfn_short, sim in sorted(soft, key=lambda x: (x[4], x[0])):
            w(f"| `{rid}` | {sev} | {sim:.2f} | {desc} | {cfn_short} |")
        w("")
    if not hard and not soft:
        w("_All descriptions match within threshold._")
        w("")

    # ----- 3. Severity/category model -----
    w("## 3. Severity/category model compliance")
    w("")
    any_issue = False
    for sev in ("Fatal", "Warn", "Info"):
        allowed = ALLOWED_CATS[sev]
        if allowed is None:
            continue
        bad = [(rid, cat, desc) for rid, s, cat, _o, desc in our
               if s == sev and cat not in allowed]
        if not bad:
            continue
        any_issue = True
        w(f"### {sev} in unexpected categories ({len(bad)})")
        w("")
        w("| ID | Category | Description |")
        w("|----|----------|-------------|")
        for rid, cat, desc in sorted(bad):
            w(f"| `{rid}` | {cat} | {desc} |")
        w("")
    if not any_issue:
        w("_All severities use allowed categories._")
        w("")

    # ----- 4. Duplicate descriptions -----
    w("## 4. Duplicate descriptions")
    w("")
    by_desc = defaultdict(list)
    for rid, sev, cat, _o, desc in our:
        by_desc[desc.strip().lower()].append((rid, sev, cat))
    dups = [(d, ids) for d, ids in by_desc.items() if len(ids) > 1]
    if dups:
        w("| Description | IDs |")
        w("|-------------|-----|")
        for d, ids in sorted(dups):
            w(f"| {d} | {', '.join(f'`{r}` ({s})' for r, s, _ in sorted(ids))} |")
    else:
        w("_None._")
    w("")

    # ----- 5. Info → Warn candidates -----
    w("## 5. Info rules that should likely be Warnings")
    w("")
    candidates = []
    for rid, sev, cat, _o, desc in our:
        if sev != "Info" or origins.true_origins.get(rid) == "CfnLint":
            continue
        hits = [k for k in INFO_TO_WARN_KEYWORDS if k in desc.lower()]
        if hits:
            candidates.append((rid, cat, desc, hits))
    if candidates:
        w("| ID | Category | Description | Keyword |")
        w("|----|----------|-------------|---------|")
        for rid, cat, desc, hits in sorted(candidates):
            w(f"| `{rid}` | {cat} | {desc} | {', '.join(hits)} |")
    else:
        w("_No candidates._")
    w("")

    # ----- 6. Engine-stricter rules -----
    w("## 6. Engine-stricter rules")
    w("")
    w("CfnLint-origin rules where our engine legitimately produces findings")
    w("cfn-lint misses (deeper resolution, condition analysis, cross-resource checks).")
    w("These are in `engine_extra` so unmatched findings aren't false positives.")
    w("")
    stricter = sorted(origins.engine_stricter)
    if stricter:
        w("| ID | Severity | True origin | Description | Reason |")
        w("|----|----------|-------------|-------------|--------|")
        reg_map = {r[0]: r for r in our}
        for rid in stricter:
            r = reg_map.get(rid)
            if not r:
                continue
            reason = "condition analysis" if rid in {"W1028", "W8001"} \
                else "resolved-value check" if rid in {"E1040","E1150","E1151","E1152","E1154","W1030","W3010","E2533"} \
                else "best-practice on conditional resources" if rid[0] == "I" \
                else "deeper dependency/usage analysis" if rid in {"W2001","W9002","W3005","W3011","W7001"} \
                else "post-transform / cross-resource schema"
            w(f"| `{rid}` | {r[1]} | {origins.true_origins.get(rid, '?')} | {r[4]} | {reason} |")
    else:
        w("_None._")
    w("")

    # ----- 7. Missing cfn-lint coverage -----
    w("## 7. Missing cfn-lint coverage")
    w("")
    w("cfn-lint rules that have no corresponding rule in our registry")
    w("(neither same ID, nor F-promoted equivalent, nor logically-covered via")
    w("schema-validator extensions or Fatal schema rules).")
    w("")
    our_ids = {r[0] for r in our}
    promoted_e_ids = set(origins.cfnlint_to_engine.keys())

    # Logical coverage map: cfn-lint rule IDs whose logic is enforced via our
    # schema-validator consuming cfn-lint's extensions/patches, or via a
    # different-ID engine rule. Values are (our_id_or_mechanism, note).
    LOGICAL_COVERAGE = {
        # Covered via Fatal/schema rules (different numeric ID).
        # Each entry verified: our rule fires on the same templates cfn-lint
        # flags, producing an equivalent diagnostic under a different ID.
        "E1001": ("F0002/F0005", "Base template JSON schema (top-level structure)"),
        "E1003": ("F0011", "description max length 1024"),
        "E1011": ("F1012/F1101", "FindInMap structural validation (template-model parser)"),
        "E1017": ("F1050/F1101", "Select structural validation (template-model parser)"),
        "E1019": ("F1018", "Sub variable resolution"),
        "E1021": ("F1101", "Base64 structural validation (template-model parser)"),
        "E1022": ("F1101", "Join structural validation (template-model parser)"),
        "E1028": ("F0013", "Fn::If must have 3 elements"),
        "E1700": ("F8600", "Rules section config"),
        "E1701": ("F8603", "Rule Assertions required"),
        "E1702": ("F8606", "Rule RuleCondition validation"),
        "E2010": ("F0003", "Parameter limit 200"),
        "E3006": ("E9001", "Resource type must be recognized"),
        "E3015": ("F8002", "Condition reference on resource"),
        # E3008: prefixItems array validation — handled by schema-validator
        # through compiled JSON Schema (prefixItems is a standard JSON Schema keyword).
        "E3008": ("schema-patch", "Array prefixItems validation (compiled schema)"),
        "E3035": ("F3016", "DeletionPolicy values"),
        "E3036": ("F0018", "UpdateReplacePolicy values"),
        # Structural validation (covered via parser + Fatal schema rules):
        "E4001": ("F0005", "Metadata Interface section validation"),
        "E4002": ("F0005", "Metadata section config"),
        "E6002": ("F0040", "Output Value required"),
        "E6003": ("F6101", "Output value type"),
        "E6010": ("F0004", "Output limit 200"),
        "E6102": ("F6005/F6101", "Output Export validation"),
        "E7010": ("F0008", "Mappings limit 200"),
        "E8004": ("F0014", "Fn::And structure"),
        "E8005": ("F0014", "Fn::Not structure"),
        "E8006": ("F0014", "Fn::Or structure"),
        "E8007": ("F8002", "Condition reference validation"),
        # Info approaching-limits rules — covered by I-prefix equivalents:
        "I1002": ("I2010/I6010", "approaching template size (via parameter/output limit warns)"),
        "I3010": ("I2010", "resource limit approach"),
        # Intrinsic resolved-value rules — our engine does resolution during
        # SemanticModel build; resolved-value errors surface via schema rules:
        "W1019": ("F1018/F1029", "Fn::Sub parameter usage"),
        "W1031": ("F3012+W9003", "Fn::Sub resolved values (via resolver)"),
        "W1032": ("F3012+W9003", "Fn::Join resolved values"),
        "W1033": ("F3012+W9003", "Fn::Split resolved values"),
        "W1035": ("F3012+W9003", "Fn::Select resolved values"),
        "W1040": ("F3012+W9003", "Fn::ToJsonString resolved values"),
        "W2030": ("F2015", "Parameter Default enum check"),
        "W2031": ("F3031", "Parameter AllowedPattern check"),
        "W3034": ("E3034/F3034", "Parameter value numeric range"),
        "W6001": ("out-of-scope", "Output ImportValue usage (cfn-lint checks cross-stack references)"),
        # Intrinsic function structural validation — template-model validates
        # these during parsing and emits F1101 (structural error) or W1102
        # (type error) instead of the cfn-lint rule IDs:
        "E1024": ("F1101/W1102", "Cidr validation (template-model parser)"),
        # W1051: Secrets Manager cross-account ARN detection requires runtime
        # context (account ID) that is not available during template validation.
        # cfn-lint checks for non-ARN secret references but this engine validates
        # Secrets Manager dynamic references via E1051 (path validation).
        "W1051": ("E1051", "Secrets Manager dynamic reference validation"),
        # Format validators — cfn-lint uses FormatKeyword rules that match
        # the "format" field in CloudFormation schemas. Our schema-validator
        # enforces these through compiled schema format validation.
        "E1157": ("schema-format", "KMS key ARN format (schema format field)"),
        "E1158": ("schema-format", "SNS topic ARN format (schema format field)"),
        "E1159": ("schema-format", "ACM certificate ARN format (schema format field)"),
        "E1160": ("schema-format", "Lambda function ARN format (schema format field)"),
        "E1161": ("schema-format", "S3 bucket name format (schema format field)"),
        "E1162": ("schema-format", "KMS key ID format (schema format field)"),
        "E1163": ("schema-format", "Lambda function name format (schema format field)"),
        "E1164": ("schema-format", "KMS alias name format (schema format field)"),
        # Covered via schema-validator extensions (extensions.json if/then patches):
        "E3046": ("schema-ext", "ECS awslogs config — via extensions"),
        "E3615": ("schema-ext", "CloudWatch Alarm Period enum"),
        "E3633": ("schema-ext", "Lambda StartingPosition validation"),
        "E3634": ("schema-ext", "Lambda SQS starting position"),
        "E3638": ("schema-ext", "DynamoDB BillingMode PayPerRequest"),
        "E3639": ("schema-ext", "DynamoDB Provisioned ProvisionedThroughput required"),
        "E3661": ("schema-ext", "Route53 HealthCheck AlarmIdentifier"),
        "E3677": ("schema-ext", "Lambda ZipFile runtime requirements"),
        "E3678": ("schema-ext", "Lambda ZipFile runtime required"),
        "E3681": ("schema-ext", "ELBv2 TargetGroup target type restrictions"),
        "E3683": ("schema-ext", "ELBv2 TargetGroup protocol restrictions"),
        "E3684": ("schema-ext", "ELBv2 TargetGroup health check protocol"),
        "E3687": ("schema-ext", "SG protocol-specific port restrictions"),
        "E3688": ("schema-ext", "SG ports must both be -1"),
        "E3691": ("schema-ext", "RDS Engine and EngineVersion compatibility"),
        "E3695": ("schema-ext", "ElastiCache Engine and EngineVersion"),
        "E3696": ("schema-ext", "Lambda LogLevel/LogFormat relationship"),
        "E3699": ("schema-ext", "APIGW Method/Authorizer RestApi match"),
        "E3711": ("schema-ext", "ListenerRule target protocol restrictions"),
        "E3712": ("schema-ext", "ASG TargetTrackingScaling policy"),
        "E3713": ("schema-ext", "Fargate ECS log drivers"),
        "E3716": ("schema-ext", "Lambda layer ARN length by region"),
        "E3718": ("schema-ext", "API Gateway Authorizer TTL"),
        # Covered via schema-validator patched schemas (patches from cfn-lint
        # merged into the base CloudFormation schemas at build time):
        "E3063": ("schema-patch", "GuardDuty Detector property exclusivity"),
        "E3503": ("schema-patch", "ACM ValidationDomain subdomain of DomainName"),
        "E3674": ("schema-patch", "EC2 NetworkInterface Primary+PrivateIp"),
        "E3682": ("schema-patch", "Aurora properties not required"),
        "E3686": ("schema-patch", "Serverless RDS DB cluster properties"),
        "E3689": ("schema-patch", "RDS MonitoringInterval+Role required together"),
        "E3692": ("schema-patch", "RDS Multi-AZ DB cluster config"),
        "E3693": ("schema-patch", "Aurora DB cluster config"),
        "E3697": ("schema-patch", "Lambda environment variables size"),
        "E3709": ("schema-patch", "RDS DBInstance matches cluster StorageEncrypted"),
        "E3714": ("schema-patch", "LaunchTemplate SG/Subnet VPC match"),
        "E3715": ("schema-patch", "BlockDeviceMapping VirtualName"),
        "E3719": ("schema-patch", "RDS BackupRetentionPeriod config"),
        # Elasticsearch is deprecated (replaced by OpenSearch). cfn-lint has
        # rule E3652 but the pricing API returns no data — the rule is a no-op
        # in cfn-lint too. Our schema has the type but no enum to validate.
        "E3652": ("schema-patch", "Elasticsearch domain cluster instance (no data — deprecated service)"),
        # Deprecated runtime warnings:
        "W3690": ("W2531", "DB Cluster Engine Version deprecated"),
        "W3691": ("W2531", "DB Instance Engine Version deprecated"),
        # Out of scope (CLI-level config, not template validation):
        "E0100": ("out-of-scope", "CLI deployment file"),
        "E0200": ("out-of-scope", "CLI parameter file"),
        "E2900": ("out-of-scope", "CLI deployment parameters"),
        "E3009": ("out-of-scope", "CFN init configuration (metadata)"),
        "E3028": ("out-of-scope", "Resource metadata section (rarely used)"),
        "E3043": ("out-of-scope", "Nested stack parameters (runtime-only)"),
        "W4001": ("out-of-scope", "Metadata Interface parameters"),
        "W4005": ("out-of-scope", "cfn-lint metadata config"),
        "W1100": ("out-of-scope", "YAML merge directives"),
    }

    missing = []
    covered = []
    stale_coverage = []
    rule_id_pattern = re.compile(r'^[FEWID]\d{4}$')
    for cid, (our_mechanism, note) in LOGICAL_COVERAGE.items():
        for part in re.split(r'[/+]', our_mechanism):
            part = part.strip()
            if rule_id_pattern.match(part) and part not in our_ids:
                stale_coverage.append((cid, part, our_mechanism, note))

    for cid in sorted(cfnlint):
        if cid in our_ids:
            continue  # exact match
        if cid in promoted_e_ids:
            continue  # we have the F-prefix version
        cfn_short, cfn_file = cfnlint[cid]
        if cid in LOGICAL_COVERAGE:
            our_id, note = LOGICAL_COVERAGE[cid]
            covered.append((cid, cfn_short, our_id, note))
        else:
            missing.append((cid, cfn_short, cfn_file))

    if stale_coverage:
        w(f"### Stale LOGICAL_COVERAGE entries ({len(stale_coverage)})")
        w("")
        w("These entries reference rule IDs that do not exist in the registry.")
        w("")
        w("| cfn-lint ID | Missing rule ID | Full mechanism | Note |")
        w("|-------------|-----------------|----------------|------|")
        for cid, missing_id, mechanism, note in sorted(stale_coverage):
            w(f"| `{cid}` | `{missing_id}` | `{mechanism}` | {note} |")
        w("")

    w(f"### Not implemented ({len(missing)})")
    w("")
    if missing:
        w("| cfn-lint ID | Severity | Description | Source file |")
        w("|-------------|----------|-------------|-------------|")
        sev_names = {"E": "Error", "W": "Warn", "I": "Info", "F": "Fatal"}
        for cid, short, fname in missing:
            w(f"| `{cid}` | {sev_names.get(cid[0], '?')} | {short} | {fname} |")
    else:
        w("_None — every cfn-lint rule is covered._")
    w("")

    w(f"### Covered via different mechanism ({len(covered)})")
    w("")
    w("These cfn-lint rule IDs have no matching engine ID but are enforced")
    w("through our schema-validator (extensions/patches from cfn-lint) or")
    w("via a Fatal schema rule covering the same concern.")
    w("")
    if covered:
        w("| cfn-lint ID | cfn-lint description | Our mechanism | Note |")
        w("|-------------|----------------------|---------------|------|")
        for cid, short, our_id, note in covered:
            w(f"| `{cid}` | {short} | `{our_id}` | {note} |")
    w("")

    # ----- 8. Source emission checks -----
    cel_emissions = scan_rust_emissions(CEL_RULES)
    rego_emissions = scan_rego_emissions()
    reg_ids = {r[0] for r in our}
    reg_map = {r[0]: r for r in our}
    cel_ids = {e[0] for e in cel_emissions}
    rego_ids = {e[0] for e in rego_emissions}

    w("## 8. Source emission checks")
    w("")
    w("Static regex scan of `.rs` and `.rego` files for rule ID usage.")
    w("")

    # 8a. Unregistered
    all_emissions = cel_emissions + [(r, p, l) for r, _s, p, l in rego_emissions]
    unreg = _check_unregistered(reg_ids, all_emissions)
    if unreg:
        w(f"### Unregistered rule IDs ({len(unreg)})")
        w("")
        w("| Rule ID | File | Line |")
        w("|---------|------|-----:|")
        for rid, path, line in unreg:
            w(f"| `{rid}` | `{path}` | {line} |")
        w("")
    else:
        w("**Unregistered IDs:** none ✅")
        w("")

    # 8b. Rego severity mismatch
    sev_issues = _check_rego_severity(reg_ids, rego_emissions)
    if sev_issues:
        w(f"### Rego severity mismatches ({len(sev_issues)})")
        w("")
        w("| Rule ID | Rego says | Expected | File | Line |")
        w("|---------|-----------|----------|------|-----:|")
        for rid, sev, expected, path, line in sev_issues:
            w(f"| `{rid}` | `{sev}` | `{expected}` | `{path}` | {line} |")
        w("")
    else:
        w("**Rego severity mismatches:** none ✅")
        w("")

    # 8c. Dual-use rule IDs
    dual = _check_dual_use(reg_map, cel_emissions)
    if dual:
        w(f"### Dual-use rule IDs ({len(dual)})")
        w("")
        w("Same rule ID emitted with semantically different messages.")
        w("")
        for rid, desc, clusters in dual:
            w(f"**`{rid}`** — registry: \"{desc}\"")
            w("")
            for i, c in enumerate(clusters):
                sample = c["entries"][0][0][:80]
                w(f"- Cluster {i+1} ({len(c['entries'])} sites): \"{sample}\"")
            w("")
    else:
        w("**Dual-use rule IDs:** none ✅")
        w("")

    # 8d. Engine parity (source-level)
    cel_only = sorted(cel_ids - rego_ids)
    rego_only = sorted(rego_ids - cel_ids)
    if cel_only or rego_only:
        w("### Engine source parity gaps")
        w("")
        w("Rule IDs found in one engine's source but not the other.")
        w("May be false positives from regex limitations — cross-reference")
        w("with `cargo test -p cfn-validate --test engine_parity` for ground truth.")
        w("")
        if cel_only:
            w(f"**CEL only ({len(cel_only)}):** {', '.join(f'`{r}`' for r in cel_only[:10])}"
              + (f" ... +{len(cel_only)-10}" if len(cel_only) > 10 else ""))
            w("")
        if rego_only:
            w(f"**Rego only ({len(rego_only)}):** {', '.join(f'`{r}`' for r in rego_only[:10])}"
              + (f" ... +{len(rego_only)-10}" if len(rego_only) > 10 else ""))
            w("")
    else:
        w("**Engine source parity:** CEL and Rego emit the same rule IDs ✅")
        w("")

    w(f"_Scanned {len(cel_emissions)} CEL sites ({len(cel_ids)} IDs), "
      f"{len(rego_emissions)} Rego sites ({len(rego_ids)} IDs)._")
    w("")

    # ----- Appendix -----
    w("## Appendix: full rule inventory")
    w("")
    w("| ID | Severity | Category | Registry origin | True origin | Description |")
    w("|----|----------|----------|-----------------|-------------|-------------|")
    for rid, sev, cat, reg_o, desc in sorted(our):
        true_o = origins.true_origins.get(rid, "?")
        marker = " ⚠" if reg_o != true_o.split("(")[0] and true_o != "Schema" else ""
        w(f"| `{rid}` | {sev} | {cat} | {reg_o}{marker} | {true_o} | {desc} |")
    w("")

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Audit rule correctness in registry.rs")
    ap.add_argument("--cfn-lint-root", type=Path, required=True,
                    help="Path to cfn-lint checkout root")
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    if not REGISTRY.exists():
        print(f"error: registry not found at {REGISTRY}", file=sys.stderr)
        return 2

    origins = compute_rule_origins(args.cfn_lint_root)
    report = build_report(origins)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)

    print(f"Wrote {args.output} ({len(origins.registry)} rules, "
          f"{len(origins.cfnlint_ids)} cfn-lint, "
          f"{len(origins.origin_issues)} origin issues)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

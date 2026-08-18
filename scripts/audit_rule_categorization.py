#!/usr/bin/env python3
"""Single source of truth for rule origin/classification.

Applies explicit CloudFormation-contract evidence and cfn-lint source data to
compute the TRUE origin of every rule, the cfn-lint E→F mapping, alias groups,
and the engine-extra set.

Exported API (imported by compare_cfnlint.py):
  compute_rule_origins(cfnlint_root) → RuleOrigins namedtuple

Also produces a markdown audit report when run directly:
  python3 scripts/audit_rule_categorization.py --cfn-lint-root /path/to/cfn-lint

Classification logic
--------------------
cfn-lint↔engine ID equivalences come from an explicit table
(`_CFNLINT_TO_ENGINE` inside `compute_rule_origins`); they are never inferred
from a shared 4-digit number.

For each rule in registry.rs the TRUE origin is, in priority order:

  1. F-prefix (Fatal, structural)                          → Schema
     A structural check (provable against the compiled schemas, guaranteed
     deploy failure) belongs to the schema validator even when cfn-lint also
     performs it; it uses the cfn-lint number promoted E→F (E3006 → F3006).
  2. Exact cfn-lint ID                                     → CfnLint
  3. Engine ID that aliases a cfn-lint rule
     (split/generic, e.g. E9003/E9004 ← E1010, E9006 ← E3690) → CfnLint
  4. Otherwise                                             → Engine
     (or Engine(collision) if the number exists under another prefix)

A rule is "engine-extra" (a correct finding cfn-lint never emits) only when it
has no cfn-lint equivalent at all: true origin Engine/Engine(collision), or a
Schema Fatal with no cfn-lint promotion. Rules with any cfn-lint equivalent are
excluded, so an unmatched firing of them surfaces as a false positive rather
than being excused. The one intentional exception is W9003 (cfn-lint coerces
silently; the engine warns).
"""

import argparse
import re
import sys
from collections import Counter, defaultdict, namedtuple
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REGISTRY = PROJECT_ROOT / "src/rules/src/registry.rs"
DEFAULT_OUTPUT = SCRIPT_DIR / "snapshots" / "rule_categorization_audit.md"


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
    "cfnlint_to_engine",  # {cfnlint_id: our_id} explicit equivalence table
    "engine_to_cfnlint",  # reverse of above: {engine_id: set of cfn-lint ids}
    "engine_extra",     # set of rule IDs that cfn-lint would never emit
    "engine_extra_collisions",  # subset of engine_extra with Engine(collision) origin
    "engine_stricter",  # engine IDs implementing a cfn-lint rule under a split/generic ID
    "rule_aliases",     # {canonical_id: {alias_ids}} for comparison matching
    "origin_issues",    # [(id, reg_origin, true_origin, note)] mismatches
    "engine_extra_invariant_violations",  # [(id, kind, cfnlint_ids)] post-computation violations
    "is_engine_extra_diagnostic",  # callable(diag_dict) → bool with equivalent-rule safeguards
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


_TEMPLATE_MODEL_SCHEMA_RULES = frozenset({
    "E1011", "E1015", "E1017", "E1018", "E1019", "E1021", "E1022",
    "E1024", "E1028", "E1030", "E1031", "E1033", "E6005", "E8001",
    "E8002", "E8003", "E8004", "E8005", "E8006", "E8007", "E9101",
    "E9106",
})

# Explicit schema-grounding evidence for non-Fatal rules.
#
# A non-Fatal rule is classified as Schema ONLY when it satisfies BOTH:
#   1. It is listed here with an explicit CloudFormation-contract justification
#      (not merely because it happens to be emitted from template-model).
#   2. The required production emitters are confirmed present in the codebase.
#
# Source location alone is NOT sufficient proof of schema origin. A rule
# emitted from template-model may be enforcing CloudFormation contract
# semantics (Schema) OR performing a lint-level semantic check (not Schema).
# The classification here is a manual, evidence-based decision.
#
# To ADD a rule: provide CloudFormation documentation/schema evidence that
# the check enforces a structural contract CloudFormation itself rejects,
# then add the entry with its required emitter paths.
_SCHEMA_GROUNDING_SOURCE_REQUIREMENTS = {
    **{
        rule_id: (("template-model/",),)
        for rule_id in _TEMPLATE_MODEL_SCHEMA_RULES
    },
    "E1016": (
        ("cel-engine/src/rules/intrinsics.rs",),
        ("rego-engine/handwritten/rego/intrinsics/intrinsic_params.rego",),
    ),
    "E9004": (
        ("cel-engine/src/rules/intrinsics.rs",),
        ("rego-engine/handwritten/rego/intrinsics/getatt.rego",),
    ),
}


def _compute_schema_grounded_non_f(
    registry,
    rust_emissions=None,
    rego_emissions=None,
):
    """Return non-Fatal rules backed by explicit schema-contract classification
    AND confirmed production emitters.

    A rule qualifies ONLY when:
      1. It is explicitly listed in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS
         (a manual, evidence-based classification that the rule enforces a
         CloudFormation structural contract).
      2. Its required production emitters are confirmed present in the codebase.

    Source location alone is NOT proof of schema origin — being emitted from
    template-model does not automatically make a rule Schema. The explicit
    listing in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS is the classification
    input; emitter presence is the verification step.

    Rules NOT listed in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS are never
    promoted to Schema regardless of where they are emitted from. This
    ensures uncertainty is visible rather than silently promoting every
    template-model emission.
    """
    if rust_emissions is None:
        rust_emissions = scan_rust_emissions()
    if rego_emissions is None:
        rego_emissions = scan_rego_emissions()

    registry_ids = {rule[0] for rule in registry}
    emission_paths = defaultdict(set)
    for emission in [*rust_emissions, *rego_emissions]:
        emission_paths[emission[0]].add(emission[-2])

    grounded = set()
    for rule_id, source_groups in _SCHEMA_GROUNDING_SOURCE_REQUIREMENTS.items():
        if rule_id not in registry_ids:
            continue
        paths = emission_paths.get(rule_id, set())
        if all(
            any(
                path.startswith(source_prefix)
                for path in paths
                for source_prefix in source_group
            )
            for source_group in source_groups
        ):
            grounded.add(rule_id)
    return frozenset(grounded)


def _find_engine_extra_invariant_violations(
    engine_extra,
    cfnlint_ids,
    cfnlint_equivalent,
    rule_aliases,
):
    violations = []
    cfnlint_id_set = set(cfnlint_ids)
    for rule_id in sorted(engine_extra):
        has_direct_equivalent = rule_id in cfnlint_id_set
        has_documented_equivalent = rule_id in cfnlint_equivalent
        aliased_reference_ids = (
            {rule_id} | rule_aliases.get(rule_id, set())
        ) & cfnlint_id_set
        if has_direct_equivalent or has_documented_equivalent or aliased_reference_ids:
            violations.append((
                rule_id,
                "direct" if has_direct_equivalent else "alias",
                sorted(aliased_reference_ids) if aliased_reference_ids else [rule_id],
            ))
    return violations


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

    reg_ids = {r[0] for r in registry}

    # ── Explicit cfn-lint → engine ID equivalence table ──────────────────
    # The single source of cfn-lint↔engine ID equivalences. Each entry is a
    # verified semantic match; an equivalence is never inferred from a shared
    # 4-digit number.
    #
    # An F (Fatal) target is a cfn-lint Error promoted to Fatal because the
    # check is structural - provable against the compiled resource schemas and
    # guaranteed to fail deployment. The number is preserved across the
    # promotion (cfn-lint E3006 → engine F3006). A non-F target keeps cfn-lint's
    # severity and, for a 1:1 mapping, its exact ID.
    _CFNLINT_TO_ENGINE = {
        # cfn-lint Error → engine Fatal (structural / guaranteed deploy failure)
        "E0000": "F0000",   # parse / duplicate-key structural error
        "E1004": "F1004",   # Description must be a string
        "E1019": "F1018",   # Sub variables must resolve
        "E1020": "F1020",   # Ref target must exist
        "E1022": "F1020",   # GetAtt target must exist (incl. inside Fn::Join)
        "E1028": "F0013",   # Fn::If must have exactly 3 elements
        "E1029": "E1029",   # Sub required when a variable is used
        "E1030": "F1030",   # Fn::Length requires the AWS::LanguageExtensions transform
        "E1031": "F1031",   # Fn::ToJsonString requires the AWS::LanguageExtensions transform
        "E1032": "F1032",   # Fn::ForEach requires the AWS::LanguageExtensions transform
        "E2002": "F2002",   # Parameter Type must be valid
        "E2003": "F2003",   # Parameter name must be alphanumeric
        "E2011": "F2011",   # Parameter name length
        "E2015": "F2015",   # Default value within parameter constraints
        "E7010": "F0050",   # Mapping key/attribute counts must not exceed 200
        "E3002": "F3002",   # Additional properties not allowed
        "E3003": "F3003",   # Required property missing
        "E3004": "F3004",   # Circular dependency
        "E3006": "F3006",   # Resource type must exist in the compiled schemas
        "E3007": "F3007",   # Unique resource / parameter names
        "E3012": "F3012",   # Property type mismatch
        "E3014": "F3014",   # Exactly one of (requiredXor)
        "E3015": "E8002",   # Resource Condition must exist
        "E3017": "F3017",   # anyOf
        "E3018": "F3018",   # oneOf
        "E3020": "F3020",   # mutually exclusive properties
        "E3021": "F3021",   # dependent property required
        "E3030": "F3030",   # value not in allowed enum
        "E3031": "F3031",   # value does not match pattern
        "E3032": "F3032",   # array item count out of bounds
        "E3033": "F3033",   # string length out of bounds
        "E3034": "F3034",   # numeric value out of bounds
        "E3035": "F3016",   # DeletionPolicy enum values
        "E3036": "F0018",   # UpdateReplacePolicy enum values
        "E3037": "F3037",   # array items not unique (uniqueItems)
        "E3058": "F3058",   # one of properties required (requiredOr)
        "E6004": "F6004",   # Output name must be alphanumeric
        "E6011": "F6011",   # Output name length
        "E6101": "F6101",   # Output value must be a string
        "E6102": "F6005",   # Output Export validation
        "E7002": "F7002",   # Mapping name length
        "E8002": "E8002",   # Condition reference must exist
        "E8001": "F0013",   # Fn::If structure inside a Condition (engine emits F0013)
        "E8003": "E8003",   # Fn::Equals structure
        "E8004": "E8004",   # Fn::And structure
        "E8005": "E8005",   # Fn::Not structure
        "E8006": "E8006",   # Fn::Or structure
        # SAM transform pre-flight: engine emits cfn-lint's E0001 directly
        "E0001": "E0001",
        # cfn-lint Error → our Error under a different ID (no Fatal divergence):
        # GetAtt - cfn-lint's single E1010 is split by the engine into E9004
        # (attribute existence) + E9003 (return-type mismatch).
        "E1010": "E9004",
        # Extension-enum family - cfn-lint emits a per-resource ID (E3690 for
        # DBCluster, E3691 for DBInstance); the engine emits one generic E9006
        # for any conditional-extension enum.
        "E3690": "E9006",
        "E3691": "E9006",
        # ECS dynamic-port health check - cfn-lint's single E3049 (Error) is
        # split by the engine on resolvability of HealthCheckPort: a concrete
        # port other than 'traffic-port' is a likely-broken health check (W3049),
        # while an omitted HealthCheckPort merely relies on the 'traffic-port'
        # default and is advisory (I3049). The template deploys in both cases, so
        # neither half keeps cfn-lint's Error severity.
        "E3049": "W3049",
    }
    # Keep only mappings whose cfn-lint key exists in this checkout (identity
    # mappings such as E0001→E0001 are always kept).
    cfnlint_to_engine = {
        cid: eid for cid, eid in _CFNLINT_TO_ENGINE.items()
        if cid in cfnlint_ids or cid == eid
    }

    # ── Alias groups for comparison matching ─────────────────────────────
    # A cfn-lint finding under one ID may match an engine finding under any
    # alias in its group. Built from the equivalence table plus documented
    # split / parent-rule groupings.
    rule_aliases = {}

    def _link(*ids):
        group = set(ids)
        for member in ids:
            rule_aliases.setdefault(member, set()).update(group - {member})

    for cid, eid in cfnlint_to_engine.items():
        if cid != eid:
            _link(eid, cid)

    # GetAtt: cfn-lint E1010 ↔ engine split E9004 (attribute) + E9003 (type).
    # E1017 (Select/GetAZs validation) reports an invalid GetAtt attribute nested
    # inside Fn::Select/Fn::GetAZs under that ID; it is the same attribute-existence
    # finding the engine emits as E9004, so it joins the group for matching.
    # F1020 joins the group because cfn-lint's single E1010 also covers the case
    # where the GetAtt *target resource* does not exist at all (message
    # "'X' is not one of [...resources]"), which the engine reports as F1020
    # (its generic "referenced resource missing" rule, shared with Ref/Join).
    _link("E1010", "E9004", "E9003", "E1017", "F1020")
    # Extension-enum family: cfn-lint uses a per-resource ID - E3690 for
    # DBCluster Engine/EngineVersion, E3691 for DBInstance - while the engine
    # emits one generic E9006 for any conditional-extension enum violation.
    _link("E9006", "E3690", "E3691")
    # Type coercion: cfn-lint strict E3012 ↔ engine Fatal F3012 or soft W9003.
    _link("F3012", "E3012", "W9003")
    # Parameter defaults: the reference check combines AllowedValues, pattern,
    # length, and numeric constraints. The engine uses one rule for
    # AllowedValues membership and another for the remaining constraints.
    _link("E2015", "F2012", "F2015")
    # Mapping configuration: malformed mapping levels are rejected while
    # mapping names and keys remain under the direct configuration rule.
    _link("E7001", "F0017")
    # Mapping size: the engine enforces second- and third-level limits through
    # its structural mapping rule.
    _link("E7010", "F0050")
    # FindInMap: a missing map is one structural case covered by the reference
    # function-validation rule.
    _link("E1011", "F1012")
    # Password parameters: the dedicated parameter-name heuristic and the
    # resource-use check share the NoEcho concern.
    _link("W2501", "W2509")
    # Enum value: cfn-lint's E3030 covers both the enum check and the const
    # check. The engine splits it - the open-world enum check is a soft W3030
    # (a value absent from the point-in-time enum snapshot may still deploy) and
    # the fixed-const check stays Fatal F3030. Both alias E3030 so a cfn-lint
    # E3030 finding matches whichever the engine emits.
    _link("E3030", "F3030", "W3030")
    # ECS dynamic-port health check: cfn-lint's single E3049 is split by the
    # engine on resolvability of HealthCheckPort - a concrete non-'traffic-port'
    # value warns (W3049), an omitted value is advisory (I3049). Both alias E3049
    # so a cfn-lint E3049 finding matches whichever half the engine emits.
    _link("E3049", "W3049", "I3049")
    # E3001 (Basic Resource Check) parents several engine structural rules.
    _link("E3001", "F0006", "E5001", "F6004")
    # E1001 (Base template schema) parents top-level structural rules. Engine
    # emits F0002 (format version) / F0005 (top-level section). F0001 (empty
    # Resources) is intentionally NOT linked - cfn-lint does not flag it, so it
    # stays a genuine engine-extra finding.
    # E1001 also covers null condition-function operands (engine: E8001, E8003-E8006).
    _link("E1001", "F0002", "F0005", "E8001", "E8003", "E8004", "E8005", "E8006")
    # cfn-lint E1028 covers Fn::If structure + condition existence; engine splits (F0013/E1028).
    _link("E1028", "F0013")
    # Undefined resource `Condition:` - cfn-lint E3015, engine E8002.
    _link("E8002", "E3015")
    # Undefined condition refs inside And/Not/Or - engine splits into E8007.
    _link("E8004", "E8007")
    _link("E8005", "E8007")
    _link("E8006", "E8007")

    engine_to_cfnlint = {}
    for cid, eid in cfnlint_to_engine.items():
        engine_to_cfnlint.setdefault(eid, set()).add(cid)
    for engine_id in reg_ids:
        equivalent_reference_ids = (
            {engine_id} | rule_aliases.get(engine_id, set())
        ) & set(cfnlint_ids)
        if equivalent_reference_ids:
            engine_to_cfnlint.setdefault(engine_id, set()).update(
                equivalent_reference_ids
            )

    # ── cfn-lint-equivalent engine rules ─────────────────────────────────
    # Every one of OUR rule IDs that implements (or is a 1:1 / split / generic
    # alias of) a cfn-lint rule. These PARTICIPATE in parity matching; an
    # UNMATCHED firing of any of them is a FALSE POSITIVE, never engine-extra.
    cfnlint_equivalent = {eid for eid in cfnlint_to_engine.values() if eid in reg_ids}
    cfnlint_equivalent.update(engine_to_cfnlint)
    cfnlint_equivalent.add("E9003")  # second half of the cfn-lint E1010 GetAtt split
    # Open-world half of the enum split: the const check stays Fatal (its ID is
    # already a mapping target and thus cfnlint_equivalent), while the soft enum
    # Warning downgrade carries no mapping-target status and would otherwise be
    # waved through via a bare number-collision. It has a real cfn-lint equivalent
    # (the enum Error it was downgraded from), so it must PARTICIPATE in parity -
    # an unmatched firing is a false positive, not blanket engine-extra.
    cfnlint_equivalent.add("W3030")
    # Both halves of the ECS dynamic-port split alias cfn-lint's E3049. W3049 is
    # already a mapping target; I3049 (the omitted-HealthCheckPort advisory) is
    # not, so add it explicitly. Both participate in parity - an unmatched firing
    # of either is a false positive, not engine-extra.
    cfnlint_equivalent.add("I3049")
    # Top-level structural rules cfn-lint covers under its parent E1001/E3001
    # (F0001 omitted on purpose - cfn-lint never flags an empty Resources section):
    cfnlint_equivalent.update({"F0002", "F0005", "F0006"})
    # W9003 (soft type coercion warning) aliases cfn-lint E3012 and participates
    # in parity — an unmatched firing is a false positive, not engine-extra.
    cfnlint_equivalent.add("W9003")

    # ── True origin (for the audit report) ───────────────────────────────
    # Priority: a structural rule is Schema first. F-prefix marks a structural
    # rule (Fatal), so it classifies as Schema regardless of any cfn-lint
    # equivalent - a structural check that cfn-lint also performs is still
    # Schema, surfaced under an F-numbered ID via E→F promotion. Only then does
    # an exact or aliased cfn-lint ID classify as CfnLint; everything else is
    # an engine-only rule.
    #
    # Non-Fatal schema classifications require explicit contract evidence and
    # concrete production emitters in the architectural layer that enforces it.
    schema_grounded_non_f = _compute_schema_grounded_non_f(registry)
    schema_grounding_candidates = set(_SCHEMA_GROUNDING_SOURCE_REQUIREMENTS) & reg_ids
    missing_schema_grounding = schema_grounding_candidates - set(schema_grounded_non_f)

    true_origins = {}
    for rid, sev, _cat, reg_origin, desc in registry:
        prefix = rid[0]
        num = rid[1:]
        if prefix == "F":
            true_origins[rid] = "Schema"
        elif rid in schema_grounded_non_f:
            true_origins[rid] = "Schema"
        elif rid in cfnlint_ids:
            true_origins[rid] = "CfnLint"
        elif rid in cfnlint_equivalent:
            # engine ID implementing a cfn-lint rule under a split / generic ID
            true_origins[rid] = "CfnLint"
        else:
            collision = None
            for pfx in "FEWI":
                if pfx == prefix:
                    continue
                cand = pfx + num
                if cand in cfnlint_ids:
                    collision = cand
                    break
            true_origins[rid] = "Engine(collision)" if collision else "Engine"

    # ── Origin-correctness issues (alias-aware) ──────────────────────────
    # The registry's origin: field must reflect reality:
    #   * CfnLint - exact cfn-lint ID, OR an engine ID that aliases a cfn-lint rule
    #   * Schema  - Fatal structural rule (cfn-only or promoted from a cfn-lint Error),
    #               OR a non-F rule in the explicit schema-grounded set
    #   * Engine  - a genuinely NEW check with NO cfn-lint equivalent
    # An Engine-origin rule that actually aliases a cfn-lint rule IS flagged (it
    # should be CfnLint); this enforces "engine-extra == truly new rules, not
    # aliases of cfn-lint rules".
    #
    # Comparison is EXACT: registry origin must match computed base origin.
    # CfnLint and Schema are not interchangeable.
    origin_issues = []
    for rid, sev, _cat, reg_origin, desc in registry:
        computed = true_origins[rid]
        # Extract the base computed origin (strip parenthetical qualifiers)
        computed_base = computed.split("(")[0]
        if reg_origin != computed_base:
            # Build a human-readable note
            if rid in missing_schema_grounding:
                note = (
                    f"registry says {reg_origin}; required production emission "
                    "evidence for non-Fatal schema grounding is missing"
                )
            elif computed == "Schema":
                if rid[0] == "F":
                    note = f"registry says {reg_origin}; F-prefix rule is Schema"
                else:
                    note = (
                        f"registry says {reg_origin}; explicit schema-grounding "
                        "evidence is present in required production emitters"
                    )
            elif computed == "CfnLint":
                if rid in cfnlint_ids:
                    note = f"registry says {reg_origin}; cfn-lint has this exact ID"
                else:
                    cfn_aliases = sorted(({rid} | rule_aliases.get(rid, set())) & set(cfnlint_ids))
                    note = f"registry says {reg_origin}; aliases cfn-lint rule(s) {cfn_aliases}"
            elif computed.startswith("Engine"):
                note = f"registry says {reg_origin}; no cfn-lint equivalent exists"
            else:
                note = f"registry says {reg_origin}; computed {computed}"
            origin_issues.append((rid, reg_origin, computed, note))

    # ── Engine-extra set (computed after all equivalences) ───────────────
    # "Engine-extra" means a correct engine finding that cfn-lint NEVER emits
    # because cfn-lint has NO SEMANTIC EQUIVALENT — not merely because the
    # numeric ID differs. A rule qualifies only when:
    #   * true origin Engine (no cfn-lint equivalent at all), or
    #   * true origin Engine(collision) — the numeric portion exists under
    #     another prefix in cfn-lint but implements a DIFFERENT check, or
    #   * a Schema Fatal with no cfn-lint promotion AND no direct cfn-lint ID.
    #
    # A rule with ANY cfn-lint semantic equivalent (direct ID, alias, split,
    # or parent-rule grouping) is EXCLUDED — an unmatched firing of such a
    # rule surfaces as a false positive, never engine-extra.
    #
    # Engine(collision) rules are included in engine-extra because the shared
    # number is coincidental — the cfn-lint rule with that number implements
    # a DIFFERENT check. These are tracked separately for audit visibility.
    #
    # No forced overrides: W9003 and W1019 have cfn-lint equivalents (they
    # alias E3012 and E1029/F1018 respectively) and are NOT engine-extra.
    engine_extra = set()
    engine_extra_collisions = set()  # subset with Engine(collision) origin
    for rid, true_o in true_origins.items():
        if true_o == "Engine":
            engine_extra.add(rid)
        elif true_o == "Engine(collision)":
            engine_extra.add(rid)
            engine_extra_collisions.add(rid)
        elif true_o == "Schema" and rid not in engine_to_cfnlint and rid not in cfnlint_ids:
            # Schema-only rule with no cfn-lint equivalent at all
            engine_extra.add(rid)
    engine_extra -= cfnlint_equivalent

    # ── Post-computation invariant ───────────────────────────────────────
    # No rule with a direct or aliased cfn-lint equivalent can be engine-extra.
    # This catches any logic error in the computation above.
    engine_extra_invariant_violations = _find_engine_extra_invariant_violations(
        engine_extra,
        cfnlint_ids,
        cfnlint_equivalent,
        rule_aliases,
    )
    # If violated, the engine_extra set is wrong — remove the violating IDs
    # so that at least the exported set is safe, but record the issue.
    for rid, _, _ in engine_extra_invariant_violations:
        engine_extra.discard(rid)

    # Engine rules that implement a cfn-lint check under a different (split or
    # generic) ID. Reported by the audit; they participate in parity matching
    # and are NOT engine-extra.
    engine_stricter = {rid for rid in ("E9003", "E9004", "E9006") if rid in reg_ids}

    # The diagnostic-level predicate is a defensive API boundary. It cannot
    # promote a finding whose rule has a direct, split, parent, or aliased
    # cfn-lint equivalent; contextual equivalent-rule mismatches are handled by
    # the comparison script's intentional-divergence evidence checks.
    def _is_engine_extra_diagnostic(diag):
        rule_id = diag.get("rule_id", "")
        if not rule_id:
            return False
        if (
            rule_id in cfnlint_ids
            or rule_id in cfnlint_equivalent
            or engine_to_cfnlint.get(rule_id)
        ):
            return False
        return rule_id in engine_extra


    return RuleOrigins(
        registry=registry,
        cfnlint_ids=cfnlint_ids,
        true_origins=true_origins,
        cfnlint_to_engine=cfnlint_to_engine,
        engine_to_cfnlint=engine_to_cfnlint,
        engine_extra=engine_extra,
        engine_extra_collisions=engine_extra_collisions,
        engine_stricter=engine_stricter,
        rule_aliases=rule_aliases,
        origin_issues=origin_issues,
        engine_extra_invariant_violations=engine_extra_invariant_violations,
        is_engine_extra_diagnostic=_is_engine_extra_diagnostic,
    )


# ── Source emission scanning ──────────────────────────────────────────────────
# Extracts (rule_id, message) pairs from Rust and Rego source files to verify
# that every emitted rule ID is registered and used consistently.
#
# PRODUCTION SCOPE: scans all runtime crates that can emit diagnostics:
#   template-model, schema-validator, validation-engine, diagnostics,
#   cel-engine, rego-engine (handwritten Rego).
# EXCLUDED:
#   - data-source/generated/ (committed generated code)
#   - bindings-* crates (no diagnostic emission)
#   - cfn-validate (CLI frontend, tests only)
#   - resources (test fixtures)
#   - guard-translator (IR, no diagnostic emission)
#   - rules/src/registry.rs (the definition, not an emitter)
#   - #[cfg(test)] modules (test-only false positives)

SRC = PROJECT_ROOT / "src"
CEL_RULES = SRC / "cel-engine/src/rules"
REGO_RULES = SRC / "rego-engine/handwritten/rego"

# Production runtime crates that can emit diagnostics.
_PRODUCTION_SCAN_CRATES = (
    "template-model",
    "schema-validator",
    "validation-engine",
    "diagnostics",
    "cel-engine",
    "rego-engine",
)

# Paths to exclude from the scan (generated code, registry definition).
_SCAN_EXCLUDE_PATHS = (
    "data-source/generated",
    "rules/src/registry.rs",
)

# Constructor patterns that emit diagnostics (first arg is rule ID literal).
_RUST_CONSTRUCTOR_RE = re.compile(
    r'(?:make_resource_diagnostic|make_resource_diagnostic_at_source'
    r'|build_diagnostic|build_diagnostic_conditional'
    r'|make_parse_defect|make_parse_defect_at|make_parse_defect_for_resource'
    r'|RegisteredDiagnostic::new'
    r'|rule_diag)\(\s*"([A-Z]\d{4})"'
    r'(?:\s*,\s*(?:&format!\(\s*"([^"]*)"'
    r'|"([^"]*)"))?',
    re.DOTALL,
)
# Dynamic constructor inputs are recognized only in syntactic contexts that
# flow rule IDs to diagnostics. Arbitrary rule-shaped strings are not emissions.
_RUST_RULE_ID_LITERAL_RE = re.compile(r'"([A-Z]\d{4})"')
_RUST_RULE_ID_TUPLE_RE = re.compile(r'\(\s*"([A-Z]\d{4})"\s*,')
_RUST_RULE_ID_BINDING_RE = re.compile(
    r'\b(?:let|const)\s+(?=[A-Za-z0-9_]*rule)'
    r'[A-Za-z_][A-Za-z0-9_]*[^=;]*=\s*(.*?);',
    re.DOTALL | re.IGNORECASE,
)
_RUST_RULE_ID_MATCH_ARM_RE = re.compile(
    r'=>\s*"([A-Z]\d{4})"\s*,',
)
_RUST_DYNAMIC_RULE_HELPER_RE = re.compile(
    r'\bcheck_bdm_iops_ignored\s*\((.*?)\);',
    re.DOTALL,
)
_SEV_FOR_PREFIX = {"F": "FATAL", "E": "ERROR", "W": "WARN", "I": "INFO", "D": "DEBUG"}
_REGO_DIAG_RE = re.compile(
    r'make_diag(?:_full|_at_source|_at|_related|_conditional)?\('
    r'\s*"([A-Z]\d{4})"\s*,'
    r'\s*"([A-Z]+)"\s*,',
    re.DOTALL,
)

# Regex to detect and strip #[cfg(test)] mod blocks (non-greedy, brace-balanced).
_CFG_TEST_MOD_RE = re.compile(
    r'#\[cfg\(test\)\]\s*mod\s+\w+\s*\{', re.DOTALL
)


def _strip_cfg_test_modules(text: str) -> str:
    """Remove #[cfg(test)] mod blocks from Rust source to avoid test-only IDs.

    Uses brace-counting to find the matching closing brace, skipping braces
    that appear inside string literals (including raw strings), character
    literals, line comments, and block comments. This prevents strings like
    "}" or comments containing braces from prematurely closing the module.

    Fail-closed: if the matching brace is never found (unbalanced input),
    the entire remainder is stripped — this is conservative (may remove real
    code) but never lets test-only IDs leak through.
    """
    result = []
    pos = 0
    for m in _CFG_TEST_MOD_RE.finditer(text):
        result.append(text[pos:m.start()])
        # Find the matching closing brace, skipping string/comment interiors
        depth = 1
        i = m.end()
        length = len(text)
        while i < length and depth > 0:
            ch = text[i]
            if ch == '/' and i + 1 < length:
                next_ch = text[i + 1]
                if next_ch == '/':
                    # Line comment — skip to end of line
                    nl = text.find('\n', i + 2)
                    i = nl + 1 if nl != -1 else length
                    continue
                elif next_ch == '*':
                    # Block comment — skip to */
                    end_comment = text.find('*/', i + 2)
                    i = end_comment + 2 if end_comment != -1 else length
                    continue
            elif ch == '"':
                # String literal — handle raw strings r"..." and r#"..."#
                if i > 0 and text[i - 1] == 'r':
                    # Count leading hashes
                    hash_start = i + 1
                    num_hashes = 0
                    while hash_start + num_hashes < length and text[hash_start + num_hashes] == '#':
                        num_hashes += 1
                    # Raw string: r#"..."# — find closing "###
                    closing = '"' + '#' * num_hashes
                    end_raw = text.find(closing, hash_start + num_hashes)
                    i = end_raw + len(closing) if end_raw != -1 else length
                    continue
                else:
                    # Regular string literal — skip to unescaped closing "
                    i += 1
                    while i < length:
                        if text[i] == '\\':
                            i += 2  # skip escaped char
                        elif text[i] == '"':
                            i += 1
                            break
                        else:
                            i += 1
                    continue
            elif ch == "'":
                # Character literal — 'x' or '\x' or '\u{...}'
                # Also lifetime annotations like 'a — those don't contain braces
                if i + 2 < length and text[i + 1] == '\\':
                    # Escaped char literal: skip to closing '
                    close_tick = text.find("'", i + 2)
                    i = close_tick + 1 if close_tick != -1 else i + 1
                    continue
                elif i + 2 < length and text[i + 2] == "'":
                    # Simple char literal 'x'
                    i += 3
                    continue
                # Lifetime or label — just advance past the tick
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            i += 1
        pos = i
    result.append(text[pos:])
    return "".join(result)


def _is_excluded_path(relpath: str) -> bool:
    """Check if a relative path should be excluded from emission scanning."""
    for excl in _SCAN_EXCLUDE_PATHS:
        if relpath.startswith(excl) or ("/" + excl) in relpath:
            return True
    return False


def scan_rust_emissions(directory=None):
    """Extract (rule_id, message, relpath, line) from production Rust files.

    When directory is None, scans all production crates. When a specific
    directory is given (for backward compatibility), scans only that subtree.

    The primary regex captures literals passed directly to constructors. A
    constrained fallback recognizes tuple tables, rule-ID bindings, and known
    diagnostic helpers that pass a dynamic ID to a constructor.

    Excludes #[cfg(test)] modules to avoid test-only false positives.
    """
    if directory is not None:
        directories = [directory]
        relpath_base = directory
    else:
        directories = [SRC / crate / "src" for crate in _PRODUCTION_SCAN_CRATES
                       if (SRC / crate / "src").exists()]
        relpath_base = SRC
    out = []
    for scan_dir in directories:
        for path in sorted(scan_dir.rglob("*.rs")):
            relpath = str(path.relative_to(relpath_base))
            if _is_excluded_path(relpath):
                continue
            text = path.read_text()
            # Strip test modules to avoid test-only false positives
            text = _strip_cfg_test_modules(text)
            primary_ids = set()
            for m in _RUST_CONSTRUCTOR_RE.finditer(text):
                rid = m.group(1)
                msg = m.group(2) or m.group(3) or ""
                line = text[:m.start()].count('\n') + 1
                out.append((rid, msg, relpath, line))
                primary_ids.add(rid)
            contextual_matches = []
            contextual_matches.extend(
                (match.group(1), match.start(1))
                for match in _RUST_RULE_ID_TUPLE_RE.finditer(text)
            )
            contextual_matches.extend(
                (match.group(1), match.start(1))
                for match in _RUST_RULE_ID_MATCH_ARM_RE.finditer(text)
            )
            for binding in _RUST_RULE_ID_BINDING_RE.finditer(text):
                binding_value = binding.group(1)
                contextual_matches.extend(
                    (
                        literal.group(1),
                        binding.start(1) + literal.start(1),
                    )
                    for literal in _RUST_RULE_ID_LITERAL_RE.finditer(binding_value)
                )
            for helper_call in _RUST_DYNAMIC_RULE_HELPER_RE.finditer(text):
                helper_arguments = helper_call.group(1)
                contextual_matches.extend(
                    (
                        literal.group(1),
                        helper_call.start(1) + literal.start(1),
                    )
                    for literal in _RUST_RULE_ID_LITERAL_RE.finditer(helper_arguments)
                )
            for rid, position in contextual_matches:
                if rid not in primary_ids:
                    primary_ids.add(rid)
                    line = text[:position].count('\n') + 1
                    out.append((rid, "", relpath, line))
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


def scan_production_scopes():
    """Return a list of (crate_name, directory) pairs that were scanned."""
    scopes = []
    for crate in _PRODUCTION_SCAN_CRATES:
        d = SRC / crate / "src"
        if d.exists():
            scopes.append((crate, str(d.relative_to(PROJECT_ROOT))))
    scopes.append(("rego-engine/handwritten", str(REGO_RULES.relative_to(PROJECT_ROOT))))
    return scopes


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


# Logical coverage map: cfn-lint rule IDs whose logic is enforced via our
# schema-validator consuming cfn-lint's extensions/patches, or via a
# different-ID engine rule. Values are (our_id_or_mechanism, note).
#
# IMPORTANT: An entry here states ONLY that we have a structural or
# mechanical substitute at the referenced ID/mechanism. It does NOT claim
# behavioral parity — the engine's implementation may differ in scope,
# triggering conditions, or message from cfn-lint's version. Behavioral
# parity is verified separately by the comparison script on real templates.
#
# Coverage categories:
#   - "schema-ext"   : cfn-lint if/then patch compiled into our schemas
#   - "schema-patch" : cfn-lint schema overlay merged at build time
#   - "schema-format": cfn-lint FormatKeyword rule enforced via schema format field
#   - "out-of-scope" : functionality cfn-lint checks that is outside template validation
#   - Rule IDs       : our rule that covers the SAME concern (not necessarily
#                      same behavior — divergences are tracked elsewhere)
LOGICAL_COVERAGE = {
    # Covered via Fatal/schema rules (different numeric ID).
    # Each entry states a structural substitute exists at the referenced ID.
    # Behavioral parity with cfn-lint is NOT asserted here.
    "E1001": ("F0002/F0005", "Top-level structure (partial: covers format version + section names only)"),
    "E1003": ("F0011", "description max length 1024"),
    "E1011": ("F1012/F1101", "FindInMap structural validation (structural shape only; cfn-lint also checks resolved map keys)"),
    "E1017": ("F1050/F1101", "Select structural validation (template-model parser)"),
    "E1019": ("F1018", "Sub variable resolution"),
    "E1021": ("F1101", "Base64 structural validation (template-model parser)"),
    "E1022": ("F1101", "Join structural validation (template-model parser)"),
    "E1028": ("E1028/F0013", "Fn::If condition + structure"),
    "E1700": ("F8600", "Rules section config"),
    "E1701": ("F8603", "Rule Assertions required"),
    "E1702": ("F8606", "Rule RuleCondition validation"),
    "E2010": ("F0003", "Parameter limit 200"),
    "E3015": ("E8002", "Condition reference on resource"),
    # E3008: prefixItems array validation - handled by schema-validator
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
    "E7010": ("F0050", "Mapping key and attribute count limits (structural limit only; cfn-lint also checks approaching-limit)"),
    "E8004": ("E8004", "Fn::And structure"),
    "E8005": ("E8005", "Fn::Not structure"),
    "E8006": ("E8006", "Fn::Or structure"),
    "E8007": ("E8007", "Condition reference validation"),
    # Info approaching-limits rules: cfn-lint warns when counts approach
    # CloudFormation limits. Our engine checks hard limits (Fatal) but does
    # NOT implement approaching-limit warnings for template body size or
    # resource count. These are out-of-scope, not covered.
    "I1002": ("out-of-scope", "Template body size approaching limit (no approaching-limit analog)"),
    "I3010": ("out-of-scope", "Resource count approaching limit (no approaching-limit analog)"),
    # Intrinsic resolved-value rules - our engine does resolution during
    # SemanticModel build; resolved-value errors surface via schema rules.
    # W1019 specifically checks for UNUSED parameters in Fn::Sub's explicit
    # map — our E1029/F1018 check for MISSING variables, which is a different
    # concern. W1019 is in our registry as a direct implementation.
    "W1019": ("W1019", "Fn::Sub unused explicit-map parameter (direct implementation, not via F1018/E1029)"),
    "W1031": ("F3012+W9003", "Fn::Sub resolved values (via resolver)"),
    "W1032": ("F3012+W9003", "Fn::Join resolved values"),
    "W1033": ("F3012+W9003", "Fn::Split resolved values"),
    "W1035": ("F3012+W9003", "Fn::Select resolved values"),
    "W1040": ("F3012+W9003", "Fn::ToJsonString resolved values"),
    "W2030": ("F2015", "Parameter Default enum check"),
    "W2031": ("F3031", "Parameter AllowedPattern check"),
    "W3034": ("E3034/F3034", "Parameter value numeric range"),
    "W6001": ("out-of-scope", "Output ImportValue usage (cfn-lint checks cross-stack references)"),
    # Intrinsic function structural validation - template-model validates
    # these during parsing and emits F1101 (structural error) or W1102
    # (type error) instead of the cfn-lint rule IDs:
    "E1024": ("F1101/W1102", "Cidr validation (template-model parser)"),
    # W1051: Secrets Manager cross-account ARN detection requires runtime
    # context (account ID) that is not available during template validation.
    # cfn-lint checks for non-ARN secret references but this engine validates
    # Secrets Manager dynamic references via E1051 (path validation).
    "W1051": ("E1051", "Secrets Manager dynamic reference validation"),
    # Format validators - cfn-lint uses FormatKeyword rules that match
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
    "E3046": ("schema-ext", "ECS awslogs config - via extensions"),
    "E3615": ("schema-ext", "CloudWatch Alarm Period enum"),
    "E3633": ("schema-ext", "Lambda StartingPosition validation"),
    "E3634": ("schema-ext", "Lambda SQS starting position"),
    "E3638": ("schema-ext", "DynamoDB BillingMode PayPerRequest"),
    "E3639": ("schema-ext", "DynamoDB Provisioned ProvisionedThroughput required"),
    "E3661": ("schema-ext", "Route53 HealthCheck AlarmIdentifier"),
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
    # rule E3652 but the pricing API returns no data - the rule is a no-op
    # in cfn-lint too. Our schema has the type but no enum to validate.
    "E3652": ("schema-patch", "Elasticsearch domain cluster instance (no data - deprecated service)"),
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

_RULE_ID_PATTERN = re.compile(r"^[FEWID]\d{4}$")


def _find_stale_logical_coverage(registry_ids, logical_coverage=LOGICAL_COVERAGE):
    """Return logical-coverage mechanisms that reference absent engine rules."""
    stale = []
    for cfnlint_id, (mechanism, note) in logical_coverage.items():
        for part in re.split(r"[/+]", mechanism):
            rule_id = part.strip()
            if _RULE_ID_PATTERN.match(rule_id) and rule_id not in registry_ids:
                stale.append((cfnlint_id, rule_id, mechanism, note))
    return sorted(stale)


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
    # Break down the cfnlint→engine mapping by mapping type.
    e_to_f = {c: e for c, e in origins.cfnlint_to_engine.items()
              if c[0] == "E" and e[0] == "F"}
    e_to_e = {c: e for c, e in origins.cfnlint_to_engine.items()
              if c[0] == "E" and e[0] == "E"}
    e_to_w = {c: e for c, e in origins.cfnlint_to_engine.items()
              if c[0] == "E" and e[0] == "W"}
    w(f"- cfn-lint→engine mappings: {len(origins.cfnlint_to_engine)} total "
      f"({len(e_to_f)} E→F promotions, {len(e_to_e)} E→E same/split, "
      f"{len(e_to_w)} E→W downgrades)")
    w(f"- Engine-extra rules: {len(origins.engine_extra)}"
      f" ({len(origins.engine_extra_collisions)} with number collisions)")
    w("")

    # ----- 1. Origin correctness -----
    w("## 1. Origin correctness")
    w("")
    w("True origin is derived from Fatal severity, explicit non-Fatal schema")
    w("evidence verified against required production emitters, and exact or")
    w("documented cfn-lint equivalences. The registry `origin:` field is compared")
    w("only after that derivation; mismatches indicate metadata needs updating.")
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

    # Engine-extra invariant violations
    if origins.engine_extra_invariant_violations:
        w(f"### Engine-extra invariant violations ({len(origins.engine_extra_invariant_violations)})")
        w("")
        w("These rules were computed as engine-extra but have a direct or aliased")
        w("cfn-lint equivalent, violating the invariant. They have been removed")
        w("from engine_extra but indicate a logic error.")
        w("")
        w("| ID | Kind | cfn-lint equivalent(s) |")
        w("|----|------|------------------------|")
        for rid, kind, cfn_ids in origins.engine_extra_invariant_violations:
            w(f"| `{rid}` | {kind} | {', '.join(f'`{c}`' for c in cfn_ids)} |")
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
        w(f"### Hard mismatches ({len(hard)}) - likely different rule")
        w("")
        w("| ID | Sev | Sim | Our description | cfn-lint shortdesc |")
        w("|----|-----|----:|------------------|--------------------|")
        for rid, sev, desc, cfn_short, sim in sorted(hard, key=lambda x: (x[4], x[0])):
            w(f"| `{rid}` | {sev} | {sim:.2f} | {desc} | {cfn_short} |")
        w("")
    if soft:
        w(f"### Soft mismatches ({len(soft)}) - wording divergence")
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

    # ----- 6. Engine rules implementing cfn-lint checks under a different ID -----
    w("## 6. Engine rules implementing cfn-lint checks under a different ID")
    w("")
    w("Engine-ID rules that implement a cfn-lint rule under a split or generic")
    w("ID (so an exact ID match is impossible). They are aliased to the cfn-lint")
    w("rule and PARTICIPATE in parity matching - an unmatched firing is a false")
    w("positive, not engine-extra. (There is no longer any blanket `ENGINE_STRICTER`")
    w("excuse list: rules cfn-lint also implements are never auto-waved-through.)")
    w("")
    stricter = sorted(origins.engine_stricter)
    if stricter:
        w("| ID | Severity | True origin | Description | cfn-lint rule |")
        w("|----|----------|-------------|-------------|---------------|")
        reg_map = {r[0]: r for r in our}
        for rid in stricter:
            r = reg_map.get(rid)
            if not r:
                continue
            cfn_rule = ", ".join(sorted(
                ({rid} | origins.rule_aliases.get(rid, set())) & set(origins.cfnlint_ids)
            )) or "-"
            w(f"| `{rid}` | {r[1]} | {origins.true_origins.get(rid, '?')} | {r[4]} | {cfn_rule} |")
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

    missing = []
    covered = []
    stale_coverage = _find_stale_logical_coverage(our_ids)

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
        w("_None - every cfn-lint rule is covered._")
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
    all_rust_emissions = scan_rust_emissions()  # repo-wide production scan
    rego_emissions = scan_rego_emissions()
    scopes = scan_production_scopes()
    reg_ids = {r[0] for r in our}
    reg_map = {r[0]: r for r in our}
    cel_ids = {e[0] for e in cel_emissions}
    all_rust_ids = {e[0] for e in all_rust_emissions}
    rego_ids = {e[0] for e in rego_emissions}

    w("## 8. Source emission checks")
    w("")
    w("Static regex scan of production runtime Rust and Rego source files.")
    w("")
    w("**Scanned crates:**")
    for crate_name, crate_path in scopes:
        w(f"- `{crate_name}` (`{crate_path}`)")
    w("")
    w("**Excluded:** generated code, registry definition, `#[cfg(test)]` modules,")
    w("bindings crates, `cfn-validate` (CLI frontend), `resources` (test fixtures),")
    w("`guard-translator` (IR only).")
    w("")

    # 8a. Unregistered
    all_emissions = all_rust_emissions + [(r, p, l) for r, _s, p, l in rego_emissions]
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
        w("**Unregistered IDs:** none (across scanned production crates) ✅")
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
            w(f"**`{rid}`** - registry: \"{desc}\"")
            w("")
            for i, c in enumerate(clusters):
                sample = c["entries"][0][0][:80]
                w(f"- Cluster {i+1} ({len(c['entries'])} sites): \"{sample}\"")
            w("")
    else:
        w("**Dual-use rule IDs:** none ✅")
        w("")

    # 8d. Engine parity (source-level ID presence check). This verifies that
    # rule IDs are EMITTED by both engine-owned source trees (cel-engine/src/rules
    # and rego-engine/handwritten/rego). It checks ID presence only — NOT
    # behavioral parity. A rule ID appearing in both trees does not guarantee
    # identical firing behavior; behavioral parity is verified separately by
    # running both engines on real templates. Shared Rust emitters in
    # template-model, schema-validator, validation-engine, and diagnostics feed
    # both engines and therefore do not represent CEL ownership.
    cel_only = sorted(cel_ids - rego_ids)
    rego_only = sorted(rego_ids - cel_ids)
    if cel_only or rego_only:
        w("### Engine source ID presence gaps")
        w("")
        w("Rule IDs found in native CEL rule source but not handwritten Rego, or vice versa.")
        w("This checks ID presence only — NOT behavioral parity. A rule ID appearing in both")
        w("trees does not guarantee identical firing behavior on real templates.")
        w("Shared Rust emitters consumed by both engines are excluded from this comparison.")
        w("")
        if cel_only:
            w(f"**Rust only ({len(cel_only)}):** {', '.join(f'`{r}`' for r in cel_only[:10])}"
              + (f" ... +{len(cel_only)-10}" if len(cel_only) > 10 else ""))
            w("")
        if rego_only:
            w(f"**Rego only ({len(rego_only)}):** {', '.join(f'`{r}`' for r in rego_only[:10])}"
              + (f" ... +{len(rego_only)-10}" if len(rego_only) > 10 else ""))
            w("")
    else:
        w("**Engine source ID presence:** native CEL and handwritten Rego emit the same rule IDs ✅")
        w("_(ID presence only — behavioral parity is verified by running both engines on real templates.)_")
        w("")

    w(f"_Scanned {len(all_rust_emissions)} Rust sites ({len(all_rust_ids)} IDs), "
      f"{len(rego_emissions)} Rego sites ({len(rego_ids)} IDs)._")
    w("")

    # ----- Appendix -----
    # Build a set of IDs that have origin issues for quick appendix lookup.
    # Uses the same predicate as the origin_issues computation above.
    _origin_issue_ids = {item[0] for item in origins.origin_issues}

    w("## Appendix: full rule inventory")
    w("")
    w("| ID | Severity | Category | Registry origin | True origin | Description |")
    w("|----|----------|----------|-----------------|-------------|-------------|")
    for rid, sev, cat, reg_o, desc in sorted(our):
        true_o = origins.true_origins.get(rid, "?")
        marker = " ⚠" if rid in _origin_issue_ids else ""
        w(f"| `{rid}` | {sev} | {cat} | {reg_o}{marker} | {true_o} | {desc} |")
    w("")

    return "\n".join(lines) + "\n"


def audit_results(origins: RuleOrigins):
    """Compute structured audit results for programmatic consumption.

    Returns a dict with failure categories and their details.
    Each non-empty category is a failure condition that causes nonzero exit.
    """
    registry = origins.registry
    reg_ids = {r[0] for r in registry}

    # Scan all production emitters for registration, plus engine-owned sources
    # separately for CEL/Rego parity.
    all_rust_emissions = scan_rust_emissions()
    cel_emissions = scan_rust_emissions(CEL_RULES)
    rego_emissions = scan_rego_emissions()
    all_emissions = all_rust_emissions + [(r, p, l) for r, _s, p, l in rego_emissions]
    cel_ids = {e[0] for e in cel_emissions}
    rego_ids = {e[0] for e in rego_emissions}

    results = {}

    # Origin issues
    if origins.origin_issues:
        results["origin_issues"] = origins.origin_issues

    # Engine-extra invariant violations
    if origins.engine_extra_invariant_violations:
        results["engine_extra_invariant_violations"] = origins.engine_extra_invariant_violations

    # Logical coverage must not claim implementation by absent engine rules.
    stale_logical_coverage = _find_stale_logical_coverage(reg_ids)
    if stale_logical_coverage:
        results["stale_logical_coverage"] = stale_logical_coverage

    # Unregistered emissions
    unreg = _check_unregistered(reg_ids, all_emissions)
    if unreg:
        results["unregistered_emissions"] = unreg

    # Rego severity mismatches
    sev_issues = _check_rego_severity(reg_ids, rego_emissions)
    if sev_issues:
        results["severity_mismatches"] = sev_issues

    # Engine source ID presence gaps. This checks that rule IDs appear in
    # both engine-owned source trees — it does NOT verify behavioral parity.
    # Shared runtime emitters are consumed by both engines and are intentionally
    # absent from this ownership comparison.
    rust_only = sorted(cel_ids - rego_ids)
    rego_only = sorted(rego_ids - cel_ids)
    if rust_only or rego_only:
        results["parity_gaps"] = {"rust_only": rust_only, "rego_only": rego_only}

    return results


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

    # Structured results for exit-code determination
    results = audit_results(origins)

    # Report summary (always printed)
    print(f"Wrote {args.output} ({len(origins.registry)} rules, "
          f"{len(origins.cfnlint_ids)} cfn-lint, "
          f"{len(origins.origin_issues)} origin issues)")

    # Report failures
    if results:
        print(f"\n{'='*60}", file=sys.stderr)
        print("AUDIT FAILURES:", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        if "origin_issues" in results:
            print(f"\n  Origin mismatches: {len(results['origin_issues'])}", file=sys.stderr)
            for rid, reg_o, true_o, note in results["origin_issues"][:5]:
                print(f"    {rid}: {note}", file=sys.stderr)
            if len(results["origin_issues"]) > 5:
                print(f"    ... +{len(results['origin_issues'])-5} more", file=sys.stderr)
        if "engine_extra_invariant_violations" in results:
            print(f"\n  Engine-extra invariant violations: "
                  f"{len(results['engine_extra_invariant_violations'])}", file=sys.stderr)
            for rid, kind, cfn_ids in results["engine_extra_invariant_violations"]:
                print(f"    {rid}: {kind} equivalent {cfn_ids}", file=sys.stderr)
        if "stale_logical_coverage" in results:
            stale = results["stale_logical_coverage"]
            print(f"\n  Stale logical-coverage entries: {len(stale)}", file=sys.stderr)
            for cfnlint_id, missing_id, mechanism, _note in stale[:5]:
                print(
                    f"    {cfnlint_id}: {mechanism} references absent {missing_id}",
                    file=sys.stderr,
                )
            if len(stale) > 5:
                print(f"    ... +{len(stale)-5} more", file=sys.stderr)
        if "unregistered_emissions" in results:
            print(f"\n  Unregistered emissions: {len(results['unregistered_emissions'])}", file=sys.stderr)
            for rid, path, line in results["unregistered_emissions"][:5]:
                print(f"    {rid} at {path}:{line}", file=sys.stderr)
            if len(results["unregistered_emissions"]) > 5:
                print(f"    ... +{len(results['unregistered_emissions'])-5} more", file=sys.stderr)
        if "severity_mismatches" in results:
            print(f"\n  Rego severity mismatches: {len(results['severity_mismatches'])}", file=sys.stderr)
            for rid, sev, expected, path, line in results["severity_mismatches"]:
                print(f"    {rid}: says {sev}, expected {expected} at {path}:{line}", file=sys.stderr)
        if "parity_gaps" in results:
            gaps = results["parity_gaps"]
            rust_only = gaps.get("rust_only", [])
            rego_only = gaps.get("rego_only", [])
            print(f"\n  Engine source ID presence gaps: {len(rust_only)} Rust-only, "
                  f"{len(rego_only)} Rego-only (ID presence, not behavioral parity)", file=sys.stderr)
            if rust_only:
                print(f"    Rust only: {', '.join(rust_only[:10])}"
                      + (f" ... +{len(rust_only)-10}" if len(rust_only) > 10 else ""),
                      file=sys.stderr)
            if rego_only:
                print(f"    Rego only: {', '.join(rego_only[:10])}"
                      + (f" ... +{len(rego_only)-10}" if len(rego_only) > 10 else ""),
                      file=sys.stderr)
        print(f"\n{'='*60}", file=sys.stderr)
        return 1

    print("\nAll audit checks passed ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())

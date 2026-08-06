#!/usr/bin/env python3
"""Generate large and pathological CloudFormation fixtures for robustness testing.

These templates are intentionally oversized or deeply structured so that parsing,
condition resolution, and rule evaluation can be exercised against their worst-case
shapes. They are used to confirm the validator stays bounded (no stack overflow,
no runaway evaluation) on adversarial input.

Fixtures produced:

    deep_nesting.json          one resource with a very deeply nested property value
    many_conditions.yaml       many interdependent conditions over shared inputs
    many_resources.yaml        a large number of independent resources
    cross_resource_scale.yaml  many resources sharing one primary identifier value
                               (worst case for pair-comparison rules)
    pathological_conditions.yaml  conditions with large dependency closures over
                               many shared parameters (worst case for the
                               satisfiability consistency check) — uses helper
                               group conditions so no Fn::And/Fn::Or exceeds the
                               CloudFormation arity limit of 10
    condition_fusion.yaml      many conditions layered over a few shared
                               pseudo-parameters, so the whole condition set is
                               connected through them (worst case for pairwise
                               condition-compatibility analysis)
    condition_chain_boundary.yaml  20 parameters, 40 acyclic chained conditions,
                               10 gated SNS resources, and nested Fn::If depth 2
                               in properties — the public CDK repro shape
    condition_chain_wide.yaml  73 parameters with the same 40-condition/10-resource
                               shape — the reported 73-parameter declaration
    combined_conditions.yaml   200 valid conditions combining recursive chains,
                               shared-input fusion, wide parameter closures,
                               opaque values, De Morgan nesting, Rules constraints,
                               and nested Fn::If resources

All content is synthetic and generic: no account IDs, ARNs, secrets, or any
sensitive or private data. Names are sequential placeholders.

The script is dependency-free and deterministic, so the committed fixtures are
fully reproducible. Run it from the workspace root:

    python3 resources/security/generate.py
"""

import itertools
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent

# Depth of the nested property value. Deep enough that a naive recursive-descent
# parser would exhaust the thread stack (a few thousand frames), proving the
# parser walks iteratively, while the produced file stays far under the 10 MiB
# template size limit.
NESTING_DEPTH = 50000
# Independent base inputs the derived conditions are built from. Each derived
# condition is an And/Or over a distinct subset of these base conditions, so the
# conditions are genuinely varied and interdependent (through the base
# conditions they share) while every condition's satisfiability closure stays
# tiny. That keeps the validator's pairwise condition-compatibility analysis
# (quadratic in the number of conditions) fast even at CONDITION_TOTAL
# conditions. The solver's per-query iteration budget — the mitigation under
# test — is exercised directly by a focused unit test in the template-model
# crate, not by this end-to-end fixture.
CONDITION_BASE_VARS = 4
# Total number of conditions (independent bases + derived).
CONDITION_TOTAL = 200
# Number of resources in the scale fixtures.
RESOURCE_COUNT = 500

# Pathological-conditions fixture. Unlike many_conditions.yaml (tiny closures),
# every derived condition here is an And/Or over the SAME large set of base
# conditions, so each condition's dependency closure references many distinct
# parameters. The pairwise condition-compatibility analysis on the validate hot
# path issues a satisfiability query per condition pair, and each such query
# would otherwise enumerate the full cartesian product of those parameters'
# values (exponential in the parameter count) at every search leaf. This is the
# denial-of-service shape the satisfiability budget and parameter cap defend
# against: with the mitigation the validator returns the conservative
# "satisfiable" answer and stays bounded; without it the analysis runs for
# minutes. PATHOLOGICAL_BASE_VARS exceeds the per-query parameter cap so the cap
# engages, and the totals stay under the 200-condition / 10 MiB limits so the
# template is otherwise accepted.
#
# Helper/group conditions are used to split the 24 base conditions into groups
# of at most 10, preserving the full dependency closure while keeping every
# Fn::And/Fn::Or within CloudFormation's 2..10 arity limit.
PATHOLOGICAL_BASE_VARS = 24
PATHOLOGICAL_DERIVED = 80

# Condition-fusion fixture. Every condition here reaches one of only three shared
# inputs — partition, region, stage — so the whole condition set is connected
# through them. Deciding a condition pair by searching truth assignments over the
# connected set is exponential in the number of conditions, which is what made a
# real deployment template take over a minute per template and, repeated across
# an application's stacks, turned a build into a multi-hour stall. Searching the
# shared inputs instead costs a few dozen assignments regardless of how many
# conditions are layered on top, so the fixture must validate with its analysis
# fully completed rather than curtailed. Totals stay at the 200-condition
# CloudFormation maximum.
FUSION_PARTITIONS = ("aws", "aws-us-gov", "aws-cn", "aws-iso", "aws-iso-b")
FUSION_REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "us-gov-west-1", "cn-north-1")
FUSION_STAGES = ("prod", "gamma", "beta", "dev")
FUSION_LAYERED = 186
FUSION_GATED_RESOURCES = 20

# Condition-chain boundary fixture. Matches the public CDK repro shape: acyclic
# chained conditions where each references prior conditions and a parameter.
CHAIN_BOUNDARY_PARAMS = 20
CHAIN_BOUNDARY_CONDITIONS = 40
CHAIN_BOUNDARY_RESOURCES = 10

# Condition-chain wide fixture. Same shape but with 73 parameters to cover the
# reported 73-parameter case and >2^20 parameter-space path.
CHAIN_WIDE_PARAMS = 73
CHAIN_WIDE_CONDITIONS = 40
CHAIN_WIDE_RESOURCES = 10

COMBINED_PARAMETER_COUNT = 73
COMBINED_CHAIN_CONDITIONS = 40
COMBINED_FUSION_CONDITIONS = 75
COMBINED_WIDE_PARAMETERS = 24
COMBINED_WIDE_CONDITIONS = 20
COMBINED_DEMORGAN_CONDITIONS = 20
COMBINED_RESOURCES = 20

HEADER = "# Generated by resources/security/generate.py — do not edit by hand.\n"


def write(name: str, content: str) -> None:
    path = OUTPUT_DIR / name
    path.write_text(content)
    print(f"wrote {path} ({len(content)} bytes)")


def gen_deep_nesting() -> None:
    """One resource whose freeform-JSON property is nested NESTING_DEPTH deep.

    Built as a raw string (not via json.dumps) so the generator itself does not
    hit Python's recursion limit. AWS::SNS::Topic.DeliveryPolicy accepts an
    arbitrary JSON object, so the deep value is schema-legal and the fixture
    isolates parser/resolver stack behavior.
    """
    opening = '{"level":' * NESTING_DEPTH
    closing = "}" * NESTING_DEPTH
    deep_value = opening + '"leaf"' + closing
    template = (
        "{\n"
        '  "AWSTemplateFormatVersion": "2010-09-09",\n'
        '  "Description": "Fixture: a deeply nested property value. Generated; no sensitive data.",\n'
        '  "Resources": {\n'
        '    "DeeplyNested": {\n'
        '      "Type": "AWS::SNS::Topic",\n'
        '      "Properties": {\n'
        f'        "DeliveryPolicy": {deep_value}\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    write("deep_nesting.json", template)


def gen_many_conditions() -> None:
    """CONDITION_TOTAL interdependent conditions with tiny dependency closures.

    Base conditions test independent parameters. Each derived condition is an
    And/Or over a distinct subset of the base conditions, so the conditions are
    genuinely varied (many distinct expressions, not a couple repeated) and
    interdependent through the base conditions they share, yet every condition's
    satisfiability closure is just the handful of base conditions it references.
    This is a real many-condition workload that the validator resolves quickly.
    The solver's iteration budget is exercised directly by a unit test in the
    template-model crate.
    """
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: many interdependent conditions. Generated; no sensitive data.'",
        "Parameters:",
    ]
    for i in range(CONDITION_BASE_VARS):
        lines.append(f"  Param{i:02d}:")
        lines.append("    Type: String")
        lines.append("    AllowedValues: ['yes', 'no']")
        lines.append("    Default: 'no'")

    lines.append("Conditions:")
    base_conditions = [f"Base{i:02d}" for i in range(CONDITION_BASE_VARS)]
    for i, name in enumerate(base_conditions):
        lines.append(f"  {name}: !Equals [!Ref Param{i:02d}, 'yes']")
    # Distinct And/Or expressions over every 2- and 3-element subset of the base
    # conditions. Cycling through these gives a varied, interdependent condition
    # set while keeping each closure to at most three base conditions.
    subsets = [
        subset
        for size in (2, 3)
        for subset in itertools.combinations(base_conditions, size)
    ]
    shapes = [(op, subset) for op in ("!And", "!Or") for subset in subsets]
    for offset in range(CONDITION_TOTAL - CONDITION_BASE_VARS):
        op, subset = shapes[offset % len(shapes)]
        operands = ", ".join(f"!Condition {c}" for c in subset)
        lines.append(f"  Derived{CONDITION_BASE_VARS + offset:03d}: {op} [{operands}]")

    # Gate a resource and an Fn::If on the last derived condition so the
    # validator runs satisfiability queries over an interdependent condition
    # during validation.
    gated_condition = f"Derived{CONDITION_TOTAL - 1:03d}"
    lines.append("Resources:")
    lines.append("  GatedTopic:")
    lines.append("    Type: AWS::SNS::Topic")
    lines.append(f"    Condition: {gated_condition}")
    lines.append("    Properties:")
    lines.append(f"      DisplayName: !If [{gated_condition}, 'enabled', 'disabled']")
    write("many_conditions.yaml", "\n".join(lines) + "\n")


def gen_many_resources() -> None:
    """RESOURCE_COUNT independent resources."""
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: many independent resources. Generated; no sensitive data.'",
        "Resources:",
    ]
    for i in range(RESOURCE_COUNT):
        lines.append(f"  Topic{i:04d}:")
        lines.append("    Type: AWS::SNS::Topic")
    write("many_resources.yaml", "\n".join(lines) + "\n")


def gen_cross_resource_scale() -> None:
    """RESOURCE_COUNT resources of one type that all share the same primary
    identifier value.

    The primary-identifier uniqueness rule groups resources of a type by their
    resolved identifier value and compares the members of each group. Giving every
    resource the same ``AWS::ApiGateway::DomainName`` ``DomainName`` places all of
    them in a single group — the worst case (every pair compared) for that
    cross-resource rule — and exercises the bound the 500-resource template limit
    places on pairwise comparison.
    """
    shared_domain_name = "duplicate.example.com"
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: many resources sharing one primary identifier. Generated; no sensitive data.'",
        "Resources:",
    ]
    for i in range(RESOURCE_COUNT):
        lines.append(f"  Domain{i:04d}:")
        lines.append("    Type: AWS::ApiGateway::DomainName")
        lines.append("    Properties:")
        lines.append(f"      DomainName: '{shared_domain_name}'")
    write("cross_resource_scale.yaml", "\n".join(lines) + "\n")


def gen_pathological_conditions() -> None:
    """Conditions with large dependency closures over many shared parameters.

    PATHOLOGICAL_BASE_VARS base conditions each test a distinct parameter, and
    every one of the PATHOLOGICAL_DERIVED derived conditions references ALL of
    those base conditions through helper/group conditions. A satisfiability query
    over any derived condition therefore has a dependency closure spanning every
    base parameter, which is the worst case for the consistency check's parameter
    enumeration.

    To keep every Fn::And/Fn::Or within CloudFormation's 2..10 arity limit, the
    24 base conditions are split into groups of at most 10 via helper conditions.
    The derived conditions then combine these helper groups (2-3 operands each),
    preserving the full dependency closure.

    A resource is gated on the last derived condition so the validate path also
    runs satisfiability during scenario resolution. Totals stay under the
    200-condition and 10 MiB limits.
    """
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: conditions with large dependency closures. Generated; no sensitive data.'",
        "Parameters:",
    ]
    for i in range(PATHOLOGICAL_BASE_VARS):
        lines.append(f"  Param{i:02d}:")
        lines.append("    Type: String")
        lines.append("    AllowedValues: ['yes', 'no']")
        lines.append("    Default: 'no'")

    lines.append("Conditions:")
    base_conditions = [f"Base{i:02d}" for i in range(PATHOLOGICAL_BASE_VARS)]
    for i, name in enumerate(base_conditions):
        lines.append(f"  {name}: !Equals [!Ref Param{i:02d}, 'yes']")

    # Build helper/group conditions that split the 24 base conditions into chunks
    # of at most 10 (CloudFormation's arity limit for Fn::And/Fn::Or). Each
    # helper is an Fn::And over a chunk, then derived conditions combine helpers.
    # This preserves the dependency closure spanning all 24 parameters while
    # keeping every operator invocation within the arity limit.
    group_size = 8  # Use groups of 8 for comfortable margin under the 10 limit
    groups_and = []  # Helper condition names for Fn::And groups
    groups_or = []   # Helper condition names for Fn::Or groups

    for chunk_idx in range(0, PATHOLOGICAL_BASE_VARS, group_size):
        chunk = base_conditions[chunk_idx:chunk_idx + group_size]
        operands = ", ".join(f"!Condition {c}" for c in chunk)
        and_name = f"GroupAnd{chunk_idx:02d}"
        or_name = f"GroupOr{chunk_idx:02d}"
        lines.append(f"  {and_name}: !And [{operands}]")
        lines.append(f"  {or_name}: !Or [{operands}]")
        groups_and.append(and_name)
        groups_or.append(or_name)

    # Count helper conditions used so far
    helper_count = len(groups_and) + len(groups_or)  # 6 helpers (3 And + 3 Or)

    # Derived conditions combine the helper groups. Each derived condition
    # references ALL helper groups (3 groups, within 2..10 limit), so its full
    # dependency closure still spans all 24 base parameters.
    and_operands = ", ".join(f"!Condition {g}" for g in groups_and)
    or_operands = ", ".join(f"!Condition {g}" for g in groups_or)

    # Ensure we stay under 200 total conditions
    # Total = 24 base + helper_count + PATHOLOGICAL_DERIVED
    max_derived = 200 - PATHOLOGICAL_BASE_VARS - helper_count
    derived_count = min(PATHOLOGICAL_DERIVED, max_derived)

    for offset in range(derived_count):
        if offset % 2 == 0:
            lines.append(f"  Derived{offset:03d}: !And [{and_operands}]")
        else:
            lines.append(f"  Derived{offset:03d}: !Or [{or_operands}]")

    gated_condition = f"Derived{derived_count - 1:03d}"
    lines.append("Resources:")
    lines.append("  GatedTopic:")
    lines.append("    Type: AWS::SNS::Topic")
    lines.append(f"    Condition: {gated_condition}")
    lines.append("    Properties:")
    lines.append(f"      DisplayName: !If [{gated_condition}, 'enabled', 'disabled']")
    write("pathological_conditions.yaml", "\n".join(lines) + "\n")


def gen_condition_fusion() -> None:
    """Conditions layered over a few shared pseudo-parameters.

    This is the shape of real deployment templates that made CDK's default
    template validation stall for hours: FUSION_LAYERED derived conditions, each
    an And/Or over conditions that all compare the same three inputs (partition,
    region, stage), so every condition is reachable from every other through the
    inputs they share. Deciding compatibility by searching condition truth
    assignments is exponential in the number of conditions, whereas the inputs
    themselves have only a few values each. Resources gated on the layered
    conditions make the validate path run satisfiability during scenario
    resolution as well. Totals stay under the 200-condition and 10 MiB limits.
    """
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: conditions layered over shared inputs. Generated; no sensitive data.'",
        "Parameters:",
        "  Stage:",
        "    Type: String",
        "    AllowedValues: ['prod', 'gamma', 'beta', 'dev']",
        "    Default: 'dev'",
        "Conditions:",
    ]
    base_conditions = []
    for i, partition in enumerate(FUSION_PARTITIONS):
        lines.append(f"  IsPartition{i:02d}: !Equals [!Ref 'AWS::Partition', '{partition}']")
        base_conditions.append(f"IsPartition{i:02d}")
    for i, region in enumerate(FUSION_REGIONS):
        lines.append(f"  IsRegion{i:02d}: !Equals [!Ref 'AWS::Region', '{region}']")
        base_conditions.append(f"IsRegion{i:02d}")
    for i, stage in enumerate(FUSION_STAGES):
        lines.append(f"  IsStage{i:02d}: !Equals [!Ref Stage, '{stage}']")
        base_conditions.append(f"IsStage{i:02d}")

    names = list(base_conditions)
    for offset in range(FUSION_LAYERED):
        op = "!And" if offset % 2 == 0 else "!Or"
        operands = [names[(offset * 7 + step * 3) % len(names)] for step in range(3)]
        lines.append(f"  Layered{offset:03d}: {op} [{', '.join('!Condition ' + o for o in operands)}]")
        names.append(f"Layered{offset:03d}")

    lines.append("Resources:")
    for offset in range(FUSION_GATED_RESOURCES):
        gated_condition = names[len(names) - 1 - offset]
        lines.append(f"  GatedTopic{offset:02d}:")
        lines.append("    Type: AWS::SNS::Topic")
        lines.append(f"    Condition: {gated_condition}")
        lines.append("    Properties:")
        lines.append(f"      DisplayName: !If [{gated_condition}, 'enabled', 'disabled']")
    write("condition_fusion.yaml", "\n".join(lines) + "\n")


def gen_condition_chain(
    filename: str,
    parameter_count: int,
    condition_count: int,
    resource_count: int,
    description: str,
) -> None:
    """The recursive parameter-and-condition shape published in the CDK repro."""
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        f"Description: '{description}'",
        "Parameters:",
    ]
    for index in range(parameter_count):
        lines.append(f"  Param{index:02d}:")
        lines.append("    Type: String")
        lines.append("    AllowedValues: ['yes', 'no']")
        lines.append("    Default: 'no'")

    lines.extend(
        [
            "Conditions:",
            "  Cond00: !Equals [!Ref Param00, 'yes']",
        ]
    )
    for index in range(1, condition_count):
        previous = index - 1
        previous_alternative = max(0, index - 2)
        parameter = index % parameter_count
        lines.append(f"  Cond{index:02d}:")
        lines.append("    Fn::And:")
        lines.append(f"      - Condition: Cond{previous:02d}")
        lines.append("      - Fn::Or:")
        lines.append(f"          - Fn::Equals: [!Ref Param{parameter:02d}, 'yes']")
        lines.append("          - Fn::Not:")
        lines.append(f"              - Condition: Cond{previous_alternative:02d}")

    def nested_if(depth: int, index: int) -> str:
        if depth == 0:
            return f"!Ref Param{index % parameter_count:02d}"
        condition = (index + depth) % condition_count
        when_true = nested_if(depth - 1, index + 1)
        when_false = nested_if(depth - 1, index + 2)
        return f"!If [Cond{condition:02d}, {when_true}, {when_false}]"

    lines.append("Resources:")
    for index in range(resource_count):
        gated_condition = (condition_count - 1 - index) % condition_count
        lines.append(f"  GatedTopic{index:02d}:")
        lines.append("    Type: AWS::SNS::Topic")
        lines.append(f"    Condition: Cond{gated_condition:02d}")
        lines.append("    Properties:")
        lines.append(f"      TopicName: !Join ['-', [{nested_if(2, index)}, 'x']]")
        lines.append(f"      DisplayName: {nested_if(2, index + 1)}")
    write(filename, "\n".join(lines) + "\n")


def gen_condition_chain_boundary() -> None:
    """The expensive 20-parameter boundary from the public reproduction."""
    gen_condition_chain(
        "condition_chain_boundary.yaml",
        CHAIN_BOUNDARY_PARAMS,
        CHAIN_BOUNDARY_CONDITIONS,
        CHAIN_BOUNDARY_RESOURCES,
        "Fixture: recursive condition chain at the parameter-space boundary. Generated; no sensitive data.",
    )


def gen_condition_chain_wide() -> None:
    """The reported 73-parameter declaration with the same condition graph."""
    gen_condition_chain(
        "condition_chain_wide.yaml",
        CHAIN_WIDE_PARAMS,
        CHAIN_WIDE_CONDITIONS,
        CHAIN_WIDE_RESOURCES,
        "Fixture: recursive condition chain with 73 parameters. Generated; no sensitive data.",
    )


def gen_combined_conditions() -> None:
    """A valid maximum-size condition set combining every expensive shape."""
    lines = [
        HEADER,
        "AWSTemplateFormatVersion: '2010-09-09'",
        "Description: 'Fixture: combined worst-case condition analysis. Generated; no sensitive data.'",
        "Parameters:",
    ]
    for index in range(COMBINED_PARAMETER_COUNT):
        lines.append(f"  Param{index:02d}:")
        if index == 70:
            lines.append("    Type: CommaDelimitedList")
        else:
            lines.append("    Type: String")
            lines.append("    AllowedValues: ['yes', 'no']")
            lines.append("    Default: 'no'")
    lines.extend(
        [
            "  Stage:",
            "    Type: String",
            "    AllowedValues: ['prod', 'gamma', 'beta', 'dev']",
            "    Default: 'dev'",
            "Conditions:",
            "  Chain00: !Equals [!Ref Param00, 'yes']",
        ]
    )

    chain_names = ["Chain00"]
    for index in range(1, COMBINED_CHAIN_CONDITIONS):
        previous = index - 1
        previous_alternative = max(0, index - 2)
        lines.append(f"  Chain{index:02d}:")
        lines.append("    Fn::And:")
        lines.append(f"      - Condition: Chain{previous:02d}")
        lines.append("      - Fn::Or:")
        lines.append(f"          - Fn::Equals: [!Ref Param{index % 20:02d}, 'yes']")
        lines.append("          - Fn::Not:")
        lines.append(f"              - Condition: Chain{previous_alternative:02d}")
        chain_names.append(f"Chain{index:02d}")

    shared_names = []
    for index, partition in enumerate(FUSION_PARTITIONS):
        name = f"SharedPartition{index:02d}"
        lines.append(f"  {name}: !Equals [!Ref 'AWS::Partition', '{partition}']")
        shared_names.append(name)
    for index, region in enumerate(FUSION_REGIONS):
        name = f"SharedRegion{index:02d}"
        lines.append(f"  {name}: !Equals [!Ref 'AWS::Region', '{region}']")
        shared_names.append(name)
    for index, stage in enumerate(FUSION_STAGES):
        name = f"SharedStage{index:02d}"
        lines.append(f"  {name}: !Equals [!Ref Stage, '{stage}']")
        shared_names.append(name)

    fusion_inputs = shared_names + chain_names
    fusion_names = []
    for index in range(COMBINED_FUSION_CONDITIONS):
        operator = "!And" if index % 2 == 0 else "!Or"
        operands = [fusion_inputs[(index * 7 + step * 11) % len(fusion_inputs)] for step in range(3)]
        name = f"Fusion{index:03d}"
        lines.append(f"  {name}: {operator} [{', '.join('!Condition ' + operand for operand in operands)}]")
        fusion_inputs.append(name)
        fusion_names.append(name)

    wide_base_names = []
    for index in range(COMBINED_WIDE_PARAMETERS):
        name = f"WideBase{index:02d}"
        lines.append(f"  {name}: !Equals [!Ref Param{40 + index:02d}, 'yes']")
        wide_base_names.append(name)

    wide_and_groups = []
    wide_or_groups = []
    for start in range(0, COMBINED_WIDE_PARAMETERS, 8):
        chunk = wide_base_names[start:start + 8]
        operands = ", ".join(f"!Condition {name}" for name in chunk)
        and_name = f"WideGroupAnd{start:02d}"
        or_name = f"WideGroupOr{start:02d}"
        lines.append(f"  {and_name}: !And [{operands}]")
        lines.append(f"  {or_name}: !Or [{operands}]")
        wide_and_groups.append(and_name)
        wide_or_groups.append(or_name)

    wide_names = []
    for index in range(COMBINED_WIDE_CONDITIONS):
        groups = wide_and_groups if index % 2 == 0 else wide_or_groups
        operator = "!And" if index % 2 == 0 else "!Or"
        operands = groups + [fusion_names[(index * 3) % len(fusion_names)]]
        name = f"Wide{index:02d}"
        lines.append(f"  {name}: {operator} [{', '.join('!Condition ' + operand for operand in operands)}]")
        wide_names.append(name)

    lines.extend(
        [
            "  OpaqueValue:",
            "    Fn::Equals:",
            "      - Fn::Select: [0, !Ref Param70]",
            "      - reserved",
        ]
    )

    demorgan_names = []
    previous = "OpaqueValue"
    demorgan_sources = wide_names + fusion_names[-10:] + chain_names[-10:]
    for index in range(COMBINED_DEMORGAN_CONDITIONS):
        source = demorgan_sources[(index * 5) % len(demorgan_sources)]
        inner_operator = "Fn::Or" if index % 2 == 0 else "Fn::And"
        name = f"DeMorgan{index:02d}"
        lines.append(f"  {name}:")
        lines.append("    Fn::Not:")
        lines.append(f"      - {inner_operator}:")
        lines.append("          - Fn::Not:")
        lines.append(f"              - Condition: {previous}")
        lines.append("          - Fn::Not:")
        lines.append(f"              - Condition: {source}")
        demorgan_names.append(name)
        previous = name

    condition_count = (
        COMBINED_CHAIN_CONDITIONS
        + len(shared_names)
        + COMBINED_FUSION_CONDITIONS
        + len(wide_base_names)
        + len(wide_and_groups)
        + len(wide_or_groups)
        + len(wide_names)
        + 1
        + len(demorgan_names)
    )
    if condition_count != 200:
        raise RuntimeError(f"combined fixture must contain exactly 200 conditions, found {condition_count}")

    lines.extend(
        [
            "Rules:",
            "  CombinedConstraint:",
            "    RuleCondition: !Equals [!Ref Param64, 'yes']",
            "    Assertions:",
            "      - Assert: !Or [!Equals [!Ref Param65, 'yes'], !Equals [!Ref Param66, 'no']]",
            "Resources:",
        ]
    )
    for index in range(COMBINED_RESOURCES):
        gated_condition = demorgan_names[len(demorgan_names) - 1 - index]
        inner_condition = fusion_names[(index * 7) % len(fusion_names)]
        lines.append(f"  CombinedTopic{index:02d}:")
        lines.append("    Type: AWS::SNS::Topic")
        lines.append(f"    Condition: {gated_condition}")
        lines.append("    Properties:")
        lines.append(
            f"      DisplayName: !If [{gated_condition}, !If [{inner_condition}, 'enabled', 'degraded'], 'disabled']"
        )
        lines.append(f"      TopicName: !Join ['-', [!Ref Param{index % 20:02d}, '{index:02d}']]")
    write("combined_conditions.yaml", "\n".join(lines) + "\n")


def main() -> None:
    gen_deep_nesting()
    gen_many_conditions()
    gen_many_resources()
    gen_cross_resource_scale()
    gen_pathological_conditions()
    gen_condition_fusion()
    gen_condition_chain_boundary()
    gen_condition_chain_wide()
    gen_combined_conditions()


if __name__ == "__main__":
    main()

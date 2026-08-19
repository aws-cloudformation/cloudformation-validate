#!/usr/bin/env python3
"""Extract data tables that originate inside cfn-lint's Python rule code.

Some validation data lives in cfn-lint not as JSON files but as Python dicts
embedded in rule classes and the schema layer. This script imports cfn-lint and
emits that data as JSON so the sync pipeline can consume it directly instead of
keeping a hand-copied (and drift-prone) duplicate in data-source/handwritten/.

It produces four files in the data-source generated data directory:

  getatt_additions.json
      Per-resource-type GetAtt attribute names beyond the schema's
      readOnlyProperties, mirroring cfn-lint's own GetAtt expansion
      (cfnlint.schema._getatts: _all_property_types + _exceptions). Only the
      delta over readOnlyProperties is written, since the schema already
      contributes those - keeping the file free of duplicated data.

  retention_period_requirements.json
      Resource type -> retention-period property names whose absence risks
      silent data expiry (cfn-lint rule RetentionPeriodOnResourceTypes...).

  codepipeline_action_artifact_counts.json
      Owner/Category/Provider -> input/output artifact count bounds for
      AWS::CodePipeline::Pipeline actions (cfn-lint rule PipelineArtifactCounts).
      Keyed on the full Owner/Category/Provider tuple, exactly as cfn-lint keys
      it - a category-only key is ambiguous (e.g. AWS/Deploy/CloudFormation
      allows 0 input artifacts while AWS/Deploy/CodeDeploy requires 1).

  cfnlint_rule_tables.json
      Finite validation catalogs and resource/property routes exposed by
      cfn-lint helpers and rules. Values are read from live rule attributes or
      fail-fast AST extraction when a rule keeps a literal local to a method.

Usage:
    python3 scripts/sync_cfnlint_data.py --cfn-lint-root /path/to/cfn-lint --out /path/to/generated/data
"""

import argparse
import ast
import inspect
import json
import sys
import textwrap
from pathlib import Path


def pointer_to_attr(pointer: str) -> str:
    """Convert a `/properties/Foo/Bar` JSON pointer to `Foo.Bar` attribute form."""
    return ".".join(pointer.split("/")[2:])


def extract_getatt_additions(region: str = "us-east-1") -> dict:
    """Compute, per resource type, the GetAtt attribute names cfn-lint exposes
    beyond the schema's readOnlyProperties.

    cfn-lint's GetAtts class returns the full attribute set for a type. The
    schema validator already derives readOnly attributes from the schema, so we
    subtract those and keep only the additional names - the same delta the
    hand-maintained file used to hold, but recomputed from cfn-lint directly.
    """
    from cfnlint.schema import PROVIDER_SCHEMA_MANAGER
    from cfnlint.schema._getatts import _all_property_types, _exceptions

    additions: dict[str, list[str]] = {}
    for type_name in sorted(set(_all_property_types) | set(_exceptions)):
        try:
            getatts = PROVIDER_SCHEMA_MANAGER.get_type_getatts(type_name, region)
        except Exception as e:  # noqa: BLE001 - a missing type should not abort the whole sync
            print(f"  warning: skipping {type_name}: {e}", file=sys.stderr)
            continue
        full_attrs = set(getatts.keys())

        try:
            schema = PROVIDER_SCHEMA_MANAGER.get_resource_schema(region, type_name)
            read_only = {pointer_to_attr(p) for p in schema.schema.get("readOnlyProperties", [])}
        except Exception:  # noqa: BLE001
            read_only = set()

        delta = sorted(full_attrs - read_only)
        if delta:
            additions[type_name] = delta
    return additions


def extract_retention_requirements() -> dict:
    """Resource type -> list of retention-period property names (cfn-lint I-rule)."""
    from cfnlint.rules.resources.RetentionPeriodOnResourceTypesWithAutoExpiringContent import (
        RetentionPeriodOnResourceTypesWithAutoExpiringContent,
    )

    rule = RetentionPeriodOnResourceTypesWithAutoExpiringContent()
    requirements: dict[str, list[str]] = {}
    for type_name, properties in rule._properties.items():
        attrs = [p["Attribute"] for p in properties if p.get("Attribute")]
        if attrs:
            requirements[type_name] = attrs
    return requirements


def extract_codepipeline_artifact_counts() -> dict:
    """Owner/Category/Provider -> artifact count bounds (cfn-lint E-rule).

    The key is the full `Owner/Category/Provider` tuple joined by '/', matching
    how cfn-lint resolves an action's constraints. All bounds in cfn-lint are
    explicit; a missing minItems means 0 and every entry has a maxItems.
    """
    from cfnlint.rules.resources.codepipeline.PipelineArtifactCounts import (
        PipelineArtifactCounts,
    )

    counts = PipelineArtifactCounts()._artifact_counts
    flat: dict[str, dict] = {}
    for owner, categories in counts.items():
        for category, providers in categories.items():
            for provider, spec in providers.items():
                inputs = spec.get("InputArtifacts", {})
                outputs = spec.get("OutputArtifacts", {})
                flat[f"{owner}/{category}/{provider}"] = {
                    "min_input": inputs.get("minItems", 0),
                    "max_input": inputs["maxItems"],
                    "min_output": outputs.get("minItems", 0),
                    "max_output": outputs["maxItems"],
                }
    return flat


def extract_local_list(function, variable_name: str) -> list[str]:
    """Extract one literal string list assigned inside a cfn-lint function."""
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    matches: list[list[str]] = []
    for node in ast.walk(syntax_tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == variable_name for target in targets):
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{variable_name} must be a literal string list")
        matches.append(value)
    if len(matches) != 1:
        raise ValueError(f"expected one {variable_name} assignment, found {len(matches)}")
    return matches[0]


def extract_enum_list(function) -> list[str]:
    """Extract the single literal `enum` list embedded in a rule validator."""
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    matches: list[list[str]] = []
    for node in ast.walk(syntax_tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if not isinstance(key, ast.Constant) or key.value != "enum":
                continue
            enum_values = ast.literal_eval(value)
            if not isinstance(enum_values, list) or not all(isinstance(item, str) for item in enum_values):
                raise ValueError("enum must be a literal string list")
            matches.append(enum_values)
    if len(matches) != 1:
        raise ValueError(f"expected one enum list, found {len(matches)}")
    return matches[0]


def extract_membership_string_list(function) -> list[str]:
    """Extract the single literal string list used by a membership comparison."""
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    matches: list[list[str]] = []
    for node in ast.walk(syntax_tree):
        if not isinstance(node, ast.Compare) or not any(isinstance(operator, (ast.In, ast.NotIn)) for operator in node.ops):
            continue
        for comparator in node.comparators:
            if not isinstance(comparator, (ast.List, ast.Tuple, ast.Set)):
                continue
            values = ast.literal_eval(comparator)
            if not isinstance(values, (list, tuple, set)) or not all(isinstance(item, str) for item in values):
                raise ValueError("membership values must be literal strings")
            matches.append(list(values))
    if len(matches) != 1:
        raise ValueError(f"expected one membership string list, found {len(matches)}")
    return matches[0]


def extract_startswith_predicates(function) -> tuple[list[str], list[str]]:
    """Extract list-driven and direct string prefixes passed to `startswith`."""
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    list_prefixes: list[list[str]] = []
    direct_prefixes: list[str] = []
    for node in ast.walk(syntax_tree):
        if isinstance(node, ast.GeneratorExp):
            for generator in node.generators:
                if not isinstance(generator.iter, (ast.List, ast.Tuple, ast.Set)):
                    continue
                values = ast.literal_eval(generator.iter)
                if isinstance(values, (list, tuple, set)) and all(isinstance(item, str) for item in values):
                    list_prefixes.append(list(values))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "startswith"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            direct_prefixes.append(node.args[0].value)
    if len(list_prefixes) > 1:
        raise ValueError(f"expected at most one startswith prefix list, found {len(list_prefixes)}")
    return (list_prefixes[0] if list_prefixes else []), direct_prefixes


def extract_previous_generation_routes(rule_class) -> list[str]:
    """Extract both flat and nested resource/property paths checked by the rule."""
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(rule_class.match)))
    routes: list[str] = []
    for node in ast.walk(syntax_tree):
        if not isinstance(node, ast.For) or not isinstance(node.iter, (ast.List, ast.Tuple)):
            continue
        try:
            route_tuples = ast.literal_eval(node.iter)
        except (ValueError, TypeError):
            continue
        if not isinstance(route_tuples, list) or not route_tuples:
            continue
        if all(isinstance(route, tuple) and len(route) == 2 for route in route_tuples):
            routes.extend(f"Resources/{resource_type}/Properties/{property}" for resource_type, property in route_tuples)
        elif all(isinstance(route, tuple) and len(route) == 3 for route in route_tuples):
            routes.extend(
                f"Resources/{resource_type}/Properties/{parent}/{property}"
                for resource_type, parent, property in route_tuples
            )
    if not routes:
        raise ValueError("previous-generation instance rule has no literal routes")
    return routes


def extract_previous_generation_pattern(rule_class) -> str:
    """Extract the regular expression passed to the previous-generation check."""
    check = rule_class._PreviousGenerationInstanceType__is_previous_generation_instance_type
    syntax_tree = ast.parse(textwrap.dedent(inspect.getsource(check)))
    matches: list[str] = []
    for node in ast.walk(syntax_tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or node.func.attr != "search":
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            matches.append(node.args[0].value)
    if len(matches) != 1:
        raise ValueError(f"expected one previous-generation regex, found {len(matches)}")
    return matches[0]


def extract_update_policy_resource_types(cfn_lint_root: Path) -> list[str]:
    """Extract the resource-type enum from cfn-lint's UpdatePolicy schema."""
    schema_path = cfn_lint_root / "src/cfnlint/data/schemas/other/resources/update_policy.json"
    schema = json.loads(schema_path.read_text())
    matches: list[list[str]] = []
    for clause in schema.get("allOf", []):
        candidate = clause.get("if", {}).get("properties", {}).get("Type", {}).get("enum")
        if isinstance(candidate, list) and all(isinstance(item, str) for item in candidate):
            matches.append(candidate)
    if not matches:
        raise ValueError("UpdatePolicy schema has no resource-type enum")
    largest_size = max(len(candidate) for candidate in matches)
    largest_matches = [candidate for candidate in matches if len(candidate) == largest_size]
    if len(largest_matches) != 1:
        raise ValueError(f"expected one complete UpdatePolicy resource-type enum, found {len(largest_matches)}")
    return largest_matches[0]


def extract_rule_tables(cfn_lint_root: Path) -> dict:
    """Extract finite validation tables owned by cfn-lint rules and helpers."""
    from cfnlint import helpers
    from cfnlint.rules.parameters.DynamicReferenceSecret import DynamicReferenceSecret
    from cfnlint.rules.resources.PreviousGenerationInstanceType import PreviousGenerationInstanceType
    from cfnlint.rules.resources.apigateway.RestApiMixingDefinitions import RestApiMixingDefinitions
    from cfnlint.rules.resources.ectwo.EbsIopsIgnored import EbsIopsIgnored, _no_iops_volume_types
    from cfnlint.rules.resources.iam.ResourcePolicy import ResourcePolicy
    from cfnlint.rules.resources.iam.RoleArnPattern import RoleArnPattern
    from cfnlint.rules.resources.lmbd.SnapStartEnabled import SnapStartEnabled
    from cfnlint.rules.resources.lmbd.SnapStartSupported import SnapStartSupported
    from cfnlint.rules.resources.lmbd.ZipPackageRequiredProperties import ZipPackageRequiredProperties
    from cfnlint.rules.resources.properties.ImageId import ImageId
    from cfnlint.rules.resources.properties.Password import Password

    image_id_rule = ImageId()
    snapstart_rule = SnapStartSupported()
    api_gateway_rule = RestApiMixingDefinitions()
    snapstart_runtime_prefixes, snapstart_unsupported_runtime_prefixes = extract_startswith_predicates(
        snapstart_rule._is_runtime_valid
    )
    snapstart_recommendation_list_prefixes, snapstart_recommendation_runtime_prefixes = extract_startswith_predicates(
        SnapStartEnabled.validate
    )
    if snapstart_recommendation_list_prefixes:
        raise ValueError("SnapStart recommendation predicate unexpectedly uses a prefix list")

    return {
        "api_gateway_mixing_resource_types": api_gateway_rule._mix_types,
        "ebs_iops_ignored_volume_types": sorted(_no_iops_volume_types),
        "ebs_iops_property_paths": EbsIopsIgnored().keywords,
        "iam_role_arn_property_paths": RoleArnPattern().keywords,
        "image_id_parameter_types": extract_enum_list(image_id_rule.validate),
        "image_id_property_paths": image_id_rule.keywords,
        "lambda_zip_required_properties": extract_local_list(
            ZipPackageRequiredProperties.match, "required_properties"
        ),
        "package_property_paths": sorted(helpers.TEMPLATED_PROPERTY_CFN_PATHS),
        "password_property_names": extract_local_list(Password.match, "password_properties"),
        "previous_generation_instance_pattern": extract_previous_generation_pattern(PreviousGenerationInstanceType),
        "previous_generation_instance_property_paths": extract_previous_generation_routes(
            PreviousGenerationInstanceType
        ),
        "resource_policy_paths": ResourcePolicy().keywords,
        "secret_dynamic_reference_property_paths": DynamicReferenceSecret().keywords,
        "snapstart_recommendation_excluded_runtimes": extract_membership_string_list(SnapStartEnabled.validate),
        "snapstart_recommendation_runtime_prefixes": snapstart_recommendation_runtime_prefixes,
        "snapstart_runtime_prefixes": snapstart_runtime_prefixes,
        "snapstart_supported_regions": snapstart_rule.regions,
        "snapstart_unsupported_runtime_prefixes": snapstart_unsupported_runtime_prefixes,
        "snapstart_unsupported_runtimes": extract_membership_string_list(snapstart_rule._is_runtime_valid),
        "snapshot_capable_resource_types": sorted(helpers.valid_snapshot_types),
        "update_policy_resource_types": extract_update_policy_resource_types(cfn_lint_root),
        "valid_parameter_types": sorted(helpers.VALID_PARAMETER_TYPES),
    }


def write_json(path: Path, key: str, value) -> None:
    path.write_text(json.dumps({key: value}, indent=2, sort_keys=True) + "\n")
    print(f"  wrote {path.name} ({len(value)} entries)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract data tables from cfn-lint Python rule code")
    parser.add_argument("--cfn-lint-root", required=True, type=Path, help="Path to the cfn-lint repo root")
    parser.add_argument("--out", required=True, type=Path, help="Output directory (generated data dir)")
    args = parser.parse_args()

    src = args.cfn_lint_root / "src"
    if not src.exists():
        print(f"error: cfn-lint src not found at {src}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(src))

    args.out.mkdir(parents=True, exist_ok=True)

    print(f"Extracting cfn-lint data tables from {args.cfn_lint_root}")
    write_json(args.out / "getatt_additions.json", "getatt_additions", extract_getatt_additions())
    write_json(
        args.out / "retention_period_requirements.json",
        "retention_period_requirements",
        extract_retention_requirements(),
    )
    write_json(
        args.out / "codepipeline_action_artifact_counts.json",
        "codepipeline_action_artifact_counts",
        extract_codepipeline_artifact_counts(),
    )
    write_json(
        args.out / "cfnlint_rule_tables.json",
        "cfnlint_rule_tables",
        extract_rule_tables(args.cfn_lint_root),
    )
    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

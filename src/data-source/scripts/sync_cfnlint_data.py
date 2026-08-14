#!/usr/bin/env python3
"""Extract data tables that originate inside cfn-lint's Python rule code.

Some validation data lives in cfn-lint not as JSON files but as Python dicts
embedded in rule classes and the schema layer. This script imports cfn-lint and
emits that data as JSON so the sync pipeline can consume it directly instead of
keeping a hand-copied (and drift-prone) duplicate in data-source/handwritten/.

It produces three files in the data-source generated data directory:

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

Usage:
    python3 scripts/sync_cfnlint_data.py --cfn-lint-root /path/to/cfn-lint --out /path/to/generated/data
"""

import argparse
import json
import sys
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
    print("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

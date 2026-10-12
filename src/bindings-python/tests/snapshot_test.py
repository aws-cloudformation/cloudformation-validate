"""Snapshot validation, mirroring the wasm and JVM suites.

Every template in the corpus is validated through all three engines at both
detail levels, and the result must match resources/expected/validation_reports*.json
chunks exactly (up to the fields the snapshot file intentionally excludes). The
typed uniffi records are serialized back into serde's JSON shape (camelCase
names, enum names, unwrapped JsonValue variants, Nones omitted), so this also
proves the Python type surface is faithful to the serialized report shape.
"""

import copy
import enum
import json
import os
import re
import unittest

from cloudformation_validate import (
    CelEngine,
    CompositeEngine,
    DetailLevel,
    EntityType,
    JsonValue,
    RegoEngine,
    Severity,
    ValidateConfig,
)

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(TESTS_DIR))
TEMPLATES_ROOT = os.path.join(WORKSPACE, "resources", "templates")
EXPECTED_DIR = os.path.join(WORKSPACE, "resources", "expected")

CHUNK_PREFIX = "validation_reports"
CHUNK_EXTENSION = ".json"
SNAPSHOT_EXCLUDED_RULE_IDS_PATH = os.path.join(EXPECTED_DIR, "snapshot_excluded_rule_ids.txt")


def _load_snapshot_excluded_rule_ids():
    with open(SNAPSHOT_EXCLUDED_RULE_IDS_PATH, encoding="utf-8") as excluded_rules_file:
        rule_ids = frozenset(line.strip() for line in excluded_rules_file if line.strip())
    if not rule_ids:
        raise RuntimeError(f"snapshot exclusion manifest is empty: {SNAPSHOT_EXCLUDED_RULE_IDS_PATH}")
    return rule_ids


SNAPSHOT_EXCLUDED_RULE_IDS = _load_snapshot_excluded_rule_ids()
SEVERITY_COUNT_FIELDS = {
    "FATAL": "fatal",
    "ERROR": "errors",
    "WARN": "warnings",
    "INFO": "informational",
    "DEBUG": "debug",
}

# Enrichment fields present only at the DETAILED detail level; stripped from the
# snapshot entry when comparing at STANDARD.
ENRICHMENT_DIAGNOSTIC_FIELDS = ["documentationUrl", "context", "ruleDescription", "phase", "section"]

_CAMEL = re.compile(r"_([a-z0-9])")


def _camel_case(name):
    return _CAMEL.sub(lambda m: m.group(1).upper(), name)


def _unwrap_json_value(value):
    if isinstance(value, JsonValue.NULL):
        return None
    if isinstance(value, (JsonValue.BOOL, JsonValue.INT, JsonValue.FLOAT, JsonValue.STRING)):
        return value.value
    if isinstance(value, JsonValue.ARRAY):
        return [_unwrap_json_value(item) for item in value.items]
    if isinstance(value, JsonValue.OBJECT):
        return {key: _unwrap_json_value(entry) for key, entry in value.entries.items()}
    raise AssertionError(f"unhandled JsonValue variant: {value!r}")


def to_jsonable(obj):
    """Converts a uniffi record tree into serde's serialized JSON shape."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, EntityType):
        # Serde serializes EntityType variants verbatim (PascalCase), unlike
        # the SCREAMING_SNAKE forms of the other report enums.
        return "".join(word.capitalize() for word in obj.name.split("_"))
    if isinstance(obj, enum.Enum):
        return obj.name
    if isinstance(obj, JsonValue):
        return _unwrap_json_value(obj)
    if isinstance(obj, list):
        return [to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_jsonable(value) for key, value in obj.items()}
    return {
        _camel_case(field): to_jsonable(value) for field, value in vars(obj).items() if value is not None
    }


def discover_snapshot_templates():
    """Recursively scan the entire templates directory for .yaml/.yml/.json files."""
    templates = []
    if not os.path.isdir(TEMPLATES_ROOT):
        return templates
    for dirpath, _, filenames in os.walk(TEMPLATES_ROOT):
        for filename in filenames:
            if filename.endswith((".yaml", ".yml", ".json")):
                full = os.path.join(dirpath, filename)
                templates.append(os.path.relpath(full, TEMPLATES_ROOT).replace(os.sep, "/"))
    return sorted(templates)


def _exclude_snapshot_rules(report):
    diagnostics = report.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise AssertionError("report has no diagnostics list")
    removed = [
        diagnostic
        for diagnostic in diagnostics
        if diagnostic.get("ruleId") in SNAPSHOT_EXCLUDED_RULE_IDS
    ]
    report["diagnostics"] = [
        diagnostic
        for diagnostic in diagnostics
        if diagnostic.get("ruleId") not in SNAPSHOT_EXCLUDED_RULE_IDS
    ]
    if not removed:
        return

    counts = report.get("metadata", {}).get("counts")
    if not isinstance(counts, dict):
        raise AssertionError("report has no metadata.counts object")
    for diagnostic in removed:
        severity = diagnostic.get("severity")
        count_field = SEVERITY_COUNT_FIELDS.get(severity)
        if count_field is None:
            raise AssertionError(f"excluded diagnostic has unsupported severity: {severity!r}")
        current_count = counts.get(count_field)
        if not isinstance(current_count, int) or current_count < 1:
            raise AssertionError(
                f"metadata.counts does not account for excluded {severity} diagnostic"
            )
        counts[count_field] = current_count - 1


def strip_snapshot_excluded_fields(report, file_path=None):
    _exclude_snapshot_rules(report)
    if file_path is not None:
        report["filePath"] = file_path
    report.pop("version", None)
    report.pop("performance", None)
    if isinstance(report.get("metadata"), dict):
        report["metadata"].pop("rulesEvaluated", None)
        report["metadata"].pop("cfnLintVersion", None)
        report["metadata"].pop("resourceSchemaVersion", None)
        report["metadata"].pop("suppressed", None)
    return report


def strip_enrichment_fields(report):
    for diagnostic in report.get("diagnostics", []):
        for field in ENRICHMENT_DIAGNOSTIC_FIELDS:
            diagnostic.pop(field, None)
    return report


def _load_combined_snapshots():
    """Discover all numbered snapshot chunks in numeric order and merge them strictly."""
    pattern = re.compile(rf"^{re.escape(CHUNK_PREFIX)}([1-9][0-9]*){re.escape(CHUNK_EXTENSION)}$")
    chunks = []
    for entry in os.listdir(EXPECTED_DIR):
        match = pattern.match(entry)
        if match:
            index = int(match.group(1))
            chunks.append((index, os.path.join(EXPECTED_DIR, entry)))
    if not chunks:
        raise RuntimeError(
            f"no snapshot chunk files ({CHUNK_PREFIX}N{CHUNK_EXTENSION}) found in {EXPECTED_DIR}"
        )
    chunks.sort(key=lambda pair: pair[0])

    for i, (idx, filepath) in enumerate(chunks):
        if idx != i + 1:
            raise RuntimeError(
                f"non-contiguous snapshot chunk sequence: expected index {i + 1} but found {idx}"
            )

    merged = {}
    for index, filepath in chunks:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise RuntimeError(f"snapshot chunk {os.path.basename(filepath)} is not a JSON object")
        for key, value in data.items():
            if key in merged:
                raise RuntimeError(
                    f"duplicate template key {key!r} in chunk {os.path.basename(filepath)}"
                )
            merged[key] = value
    return merged


SNAPSHOTS = _load_combined_snapshots()

EXPECTED_TEMPLATES = discover_snapshot_templates()

DETAILED_DEBUG = ValidateConfig(severity_level=Severity.DEBUG, detail_level=DetailLevel.DETAILED)
STANDARD_DEBUG = ValidateConfig(severity_level=Severity.DEBUG, detail_level=DetailLevel.STANDARD)

REGO = RegoEngine()
CEL = CelEngine()
COMPOSITE = CompositeEngine()


class SnapshotNormalizationTest(unittest.TestCase):
    def test_context_rules_and_counts_are_excluded(self):
        report = {
            "diagnostics": [
                {"ruleId": "I4010", "severity": "INFO"},
                {"ruleId": "E3012", "severity": "ERROR"},
            ],
            "metadata": {
                "counts": {
                    "fatal": 0,
                    "errors": 1,
                    "warnings": 0,
                    "informational": 1,
                    "debug": 0,
                }
            },
        }

        normalized = strip_snapshot_excluded_fields(report)

        self.assertEqual([{"ruleId": "E3012", "severity": "ERROR"}], normalized["diagnostics"])
        self.assertEqual(0, normalized["metadata"]["counts"]["informational"])
        self.assertEqual(1, normalized["metadata"]["counts"]["errors"])


class SnapshotValidationTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.assertTrue(EXPECTED_TEMPLATES, "no templates discovered")

    def assert_matches_snapshot(self, engine, detailed):
        config = DETAILED_DEBUG if detailed else STANDARD_DEBUG
        for rel in EXPECTED_TEMPLATES:
            with self.subTest(template=rel):
                self.assertIn(rel, SNAPSHOTS, f"{rel}: missing snapshot entry")
                path = os.path.join(TEMPLATES_ROOT, rel)
                report = engine.validate_template(path, config)
                expected = strip_snapshot_excluded_fields(copy.deepcopy(SNAPSHOTS[rel]))
                actual = strip_snapshot_excluded_fields(to_jsonable(report), rel)
                if not detailed:
                    # validate_template always yields a ValidationReport shape; at STANDARD
                    # the shared projection leaves the enrichment fields unset on every
                    # diagnostic, so they are absent from the actual report. The snapshot
                    # stores the `DETAILED` projection, so drop those fields from both sides
                    # before comparing.
                    expected = strip_enrichment_fields(expected)
                    actual = strip_enrichment_fields(actual)
                self.assertEqual(expected, actual, f"{rel}: report does not match snapshot")

    def test_rego_detailed_matches_snapshot(self):
        self.assert_matches_snapshot(REGO, detailed=True)

    def test_rego_standard_matches_snapshot(self):
        self.assert_matches_snapshot(REGO, detailed=False)

    def test_cel_detailed_matches_snapshot(self):
        self.assert_matches_snapshot(CEL, detailed=True)

    def test_cel_standard_matches_snapshot(self):
        self.assert_matches_snapshot(CEL, detailed=False)

    def test_composite_detailed_matches_snapshot(self):
        self.assert_matches_snapshot(COMPOSITE, detailed=True)

    def test_composite_standard_matches_snapshot(self):
        self.assert_matches_snapshot(COMPOSITE, detailed=False)


class PerformanceMetricsTest(unittest.TestCase):
    def test_performance_present_with_timing_per_phase(self):
        report = REGO.validate_template(os.path.join(TEMPLATES_ROOT, "good", "generic.yaml"), DETAILED_DEBUG)
        performance = report.performance
        for phase in (
            "schema_init",
            "engine_init",
            "model_build",
            "schema_validate",
            "rule_evaluation",
            "diagnostic_finalize",
            "validate_total",
        ):
            metric = getattr(performance, phase)
            self.assertIsInstance(metric.duration_ms, float, f"performance.{phase}.duration_ms")
            self.assertGreaterEqual(metric.duration_ms, 0.0)


class DefaultDetailLevelTest(unittest.TestCase):
    maxDiff = None

    def test_default_config_matches_detailed_snapshot(self):
        # Omitting detail_level must default to DETAILED: the report matches the
        # detailed snapshot for every template.
        default_config = ValidateConfig(severity_level=Severity.DEBUG)
        for rel in EXPECTED_TEMPLATES:
            with self.subTest(template=rel):
                self.assertIn(rel, SNAPSHOTS, f"{rel}: missing snapshot entry")
                path = os.path.join(TEMPLATES_ROOT, rel)
                report = REGO.validate_template(path, default_config)
                expected = strip_snapshot_excluded_fields(copy.deepcopy(SNAPSHOTS[rel]))
                actual = strip_snapshot_excluded_fields(to_jsonable(report), rel)
                self.assertEqual(expected, actual, f"{rel}: default detail level must match the DETAILED snapshot")


if __name__ == "__main__":
    unittest.main(verbosity=2)

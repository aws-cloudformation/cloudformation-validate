"""Snapshot validation, mirroring the wasm and JVM suites.

Every template in the corpus is validated through both engines at both detail
levels, and the result must match resources/expected/validation_reports*.json
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

# Fields present only in detailed reports; stripped from the snapshot entry when
# comparing standard reports.
DETAILED_ONLY_DIAGNOSTIC_FIELDS = ["documentationUrl", "context", "ruleDescription", "phase", "section"]

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


def strip_snapshot_excluded_fields(report, file_path=None):
    if file_path is not None:
        report["filePath"] = file_path
    report.pop("version", None)
    report.pop("performance", None)
    if isinstance(report.get("metadata"), dict):
        report["metadata"].pop("rulesEvaluated", None)
        report["metadata"].pop("cfnLintVersion", None)
        report["metadata"].pop("resourceSchemaVersion", None)
    return report


def strip_detailed_only_fields(report):
    for diagnostic in report.get("diagnostics", []):
        for field in DETAILED_ONLY_DIAGNOSTIC_FIELDS:
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

DEBUG_LEVEL = ValidateConfig(severity_level=Severity.DEBUG)

REGO = RegoEngine()
CEL = CelEngine()


class SnapshotValidationTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.assertTrue(EXPECTED_TEMPLATES, "no templates discovered")

    def assert_matches_snapshot(self, engine, detailed):
        for rel in EXPECTED_TEMPLATES:
            with self.subTest(template=rel):
                self.assertIn(rel, SNAPSHOTS, f"{rel}: missing snapshot entry")
                path = os.path.join(TEMPLATES_ROOT, rel)
                if detailed:
                    report = engine.validate_detailed(path, DEBUG_LEVEL)
                    expected = strip_snapshot_excluded_fields(copy.deepcopy(SNAPSHOTS[rel]))
                else:
                    report = engine.validate_standard(path, DEBUG_LEVEL)
                    expected = strip_detailed_only_fields(strip_snapshot_excluded_fields(copy.deepcopy(SNAPSHOTS[rel])))
                actual = strip_snapshot_excluded_fields(to_jsonable(report), rel)
                self.assertEqual(expected, actual, f"{rel}: report does not match snapshot")

    def test_rego_detailed_matches_snapshot(self):
        self.assert_matches_snapshot(REGO, detailed=True)

    def test_rego_standard_matches_snapshot(self):
        self.assert_matches_snapshot(REGO, detailed=False)

    def test_cel_detailed_matches_snapshot(self):
        self.assert_matches_snapshot(CEL, detailed=True)

    def test_cel_standard_matches_snapshot(self):
        self.assert_matches_snapshot(CEL, detailed=False)


class PerformanceMetricsTest(unittest.TestCase):
    def test_performance_present_with_timing_per_phase(self):
        report = REGO.validate_detailed(os.path.join(TEMPLATES_ROOT, "good", "generic.yaml"), DEBUG_LEVEL)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

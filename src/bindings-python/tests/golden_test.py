"""Golden-file validation, mirroring the wasm and JVM suites.

Every template in the corpus is validated through both engines at both detail
levels, and the result must match resources/expected/validation_reports.json exactly
(up to the fields the golden file intentionally excludes). The typed uniffi
records are serialized back into serde's JSON shape (camelCase names, enum
names, unwrapped JsonValue variants, Nones omitted), so this also proves the
Python type surface is faithful to the serialized report shape.
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
GOLDEN_FILE = os.path.join(WORKSPACE, "resources", "expected", "validation_reports.json")

GOLDEN_DIRS = ["bad", "cdk", "good", "gh-issues", "integration", "issues", "lsp", "public", "quickstart"]

# Fields present only in detailed reports; stripped from the golden entry when
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


def discover_golden_templates():
    templates = []
    for sub in GOLDEN_DIRS:
        root = os.path.join(TEMPLATES_ROOT, sub)
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if filename.endswith((".yaml", ".yml", ".json")):
                    full = os.path.join(dirpath, filename)
                    templates.append(os.path.relpath(full, TEMPLATES_ROOT).replace(os.sep, "/"))
    return sorted(templates)


def strip_golden_excluded_fields(report, file_path=None):
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


with open(GOLDEN_FILE, encoding="utf-8") as f:
    GOLDEN = json.load(f)

EXPECTED_TEMPLATES = discover_golden_templates()

DEBUG_LEVEL = ValidateConfig(severity_level=Severity.DEBUG)

REGO = RegoEngine()
CEL = CelEngine()


class GoldenFileValidationTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.assertTrue(EXPECTED_TEMPLATES, "no templates discovered")

    def assert_matches_golden(self, engine, detailed):
        for rel in EXPECTED_TEMPLATES:
            with self.subTest(template=rel):
                self.assertIn(rel, GOLDEN, f"{rel}: missing golden entry")
                path = os.path.join(TEMPLATES_ROOT, rel)
                if detailed:
                    report = engine.validate_detailed(path, DEBUG_LEVEL)
                    expected = strip_golden_excluded_fields(copy.deepcopy(GOLDEN[rel]))
                else:
                    report = engine.validate_standard(path, DEBUG_LEVEL)
                    expected = strip_detailed_only_fields(strip_golden_excluded_fields(copy.deepcopy(GOLDEN[rel])))
                actual = strip_golden_excluded_fields(to_jsonable(report), rel)
                self.assertEqual(expected, actual, f"{rel}: report does not match golden")

    def test_rego_detailed_matches_golden(self):
        self.assert_matches_golden(REGO, detailed=True)

    def test_rego_standard_matches_golden(self):
        self.assert_matches_golden(REGO, detailed=False)

    def test_cel_detailed_matches_golden(self):
        self.assert_matches_golden(CEL, detailed=True)

    def test_cel_standard_matches_golden(self):
        self.assert_matches_golden(CEL, detailed=False)


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

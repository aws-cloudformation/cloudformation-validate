"""Smoke tests for the Python bindings.

Runs against the assembled package in ../generated (see run.sh), exercising the
public API end to end: engine construction, validation reports, engine parity,
the semantic model, the schema validator, custom rules, and error handling.
Standard library only - no test dependencies.
"""

import os
import re
import tempfile
import unittest
from unittest import mock

import cloudformation_validate._native as native_loader
from cloudformation_validate import (
    AdditionalSchemaSource,
    AwsApiOperationKind,
    AwsApiRequest,
    AwsApiRequestValidationStatus,
    AwsApiTemplateSource,
    CelEngine,
    EngineConfig,
    EntityType,
    ExternalRuleSource,
    LogicalIdFilter,
    RegoEngine,
    ReportStatus,
    RuleFilterConfig,
    RuleOrigin,
    SchemaValidator,
    Severity,
    TemplateModel,
    ValidateConfig,
    ValidationError,
    file_to_additional_schema_source,
    version,
)

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(TESTS_DIR))
RESOURCES = os.path.join(WORKSPACE, "resources")
TEMPLATES = os.path.join(RESOURCES, "templates")
RULES_DIR = os.path.join(RESOURCES, "rules")

GOOD_TEMPLATE = os.path.join(TEMPLATES, "good", "aurora_dbinstance.yaml")

UNENCRYPTED_BUCKET = b"""
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
"""

TEMPLATE_WITH_OVERLAY_PROPERTY = b"""
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Code:
        ZipFile: "exports.handler = async () => {};"
      Role: arn:aws:iam::123456789012:role/lambda-role
      Runtime: nodejs18.x
      Handler: index.handler
      TestForOverride: enabled
"""

LAMBDA_OVERLAY_SCHEMA = """{
  "typeName": "AWS::Lambda::Function",
  "properties": {"TestForOverride": {"type": "string"}}
}"""


def read_workspace_version():
    cargo_toml = os.path.join(WORKSPACE, "Cargo.toml")
    in_workspace_package = False
    with open(cargo_toml, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped == "[workspace.package]":
                in_workspace_package = True
                continue
            if in_workspace_package and stripped.startswith("["):
                break
            if in_workspace_package and stripped.startswith("version = "):
                match = re.fullmatch(r'version = "([^"]+)"', stripped)
                if not match:
                    raise AssertionError(f"malformed version line in {cargo_toml}: {line}")
                return match.group(1)
    raise AssertionError(f"missing 'version = ' under [workspace.package] in {cargo_toml}")


def load_rule(filename):
    with open(os.path.join(RULES_DIR, filename), encoding="utf-8") as f:
        return f.read()


def diagnostic_keys(report):
    return sorted((d.rule_id, d.severity.name, d.start_line, d.start_column) for d in report.diagnostics)


# Engines compile their rule sets at construction; build each once for the module.
REGO = RegoEngine()
CEL = CelEngine()


class VersionTest(unittest.TestCase):
    def test_version_matches_workspace_cargo_toml(self):
        self.assertEqual(read_workspace_version(), version())


class EngineConstructionTest(unittest.TestCase):
    def test_rego_engine_reports_name_rego(self):
        self.assertEqual("rego", REGO.engine_name())

    def test_cel_engine_reports_name_cel(self):
        self.assertEqual("cel", CEL.engine_name())


class ListRulesTest(unittest.TestCase):
    def test_rules_non_empty_and_sorted_by_id(self):
        for engine in (REGO, CEL):
            ids = [r.id for r in engine.list_rules()]
            self.assertTrue(ids, "rule list must not be empty")
            self.assertEqual(ids, sorted(ids), "rules must be sorted by id")

    def test_cel_and_rego_list_identical_rules(self):
        rego_rules = [(r.id, r.severity.name, r.description) for r in REGO.list_rules()]
        cel_rules = [(r.id, r.severity.name, r.description) for r in CEL.list_rules()]
        self.assertEqual(rego_rules, cel_rules)


class SchemaValidatorTest(unittest.TestCase):
    def test_exposes_schemas_and_rules(self):
        sv = SchemaValidator()
        self.assertGreater(sv.schema_count(), 0)
        rules = sv.list_rules()
        self.assertTrue(rules, "schema validator must have rules")
        self.assertTrue(rules[0].id, "first rule must have an id")

    def test_validate_returns_diagnostics_list(self):
        diagnostics = SchemaValidator().validate(GOOD_TEMPLATE)
        self.assertIsInstance(diagnostics, list)


class ValidateTest(unittest.TestCase):
    def test_good_template_passes_both_engines(self):
        for engine in (REGO, CEL):
            report = engine.validate_standard(GOOD_TEMPLATE)
            self.assertEqual(ReportStatus.OK, report.status)
            errors = [d for d in report.diagnostics if d.severity in (Severity.ERROR, Severity.FATAL)]
            self.assertEqual([], errors, f"good template must have no errors via {engine.engine_name()}")

    def test_template_path_recorded_in_report(self):
        report = REGO.validate_standard(GOOD_TEMPLATE)
        self.assertEqual(GOOD_TEMPLATE, report.file_path)

    def test_bytes_input_fires_diagnostics(self):
        report = REGO.validate_standard(UNENCRYPTED_BUCKET)
        self.assertTrue(report.diagnostics, "unencrypted bucket template must produce diagnostics")

    def test_engines_agree_on_diagnostics(self):
        self.assertEqual(
            diagnostic_keys(REGO.validate_standard(UNENCRYPTED_BUCKET)),
            diagnostic_keys(CEL.validate_standard(UNENCRYPTED_BUCKET)),
            "Rego and CEL must produce identical diagnostics",
        )

    def test_severity_level_filters_below_threshold(self):
        config = ValidateConfig(severity_level=Severity.ERROR)
        report = REGO.validate_standard(UNENCRYPTED_BUCKET, config)
        below = [d for d in report.diagnostics if d.severity in (Severity.WARN, Severity.INFO, Severity.DEBUG)]
        self.assertEqual([], below, "severity_level=ERROR must exclude WARN/INFO/DEBUG")

    def test_validate_detailed_counts_match_diagnostics(self):
        report = REGO.validate_detailed(UNENCRYPTED_BUCKET)
        counts = report.metadata.counts
        total = counts.fatal + counts.errors + counts.warnings + counts.informational + counts.debug
        self.assertEqual(len(report.diagnostics), total)

    def test_unparseable_template_reports_error_status(self):
        report = REGO.validate_standard(b"not: a: valid: yaml: [")
        self.assertEqual(ReportStatus.ERROR, report.status)
        self.assertTrue(report.diagnostics, "parse failure must surface as a diagnostic")


class AwsApiRequestValidationTest(unittest.TestCase):
    def test_synthesized_create_validates_with_both_engines(self):
        parameters = {"Bucket": "synthetic-bucket"}
        request = AwsApiRequest(
            "s3",
            "CreateBucket",
            parameters,
            service_prefix="s3",
            http_method="POST",
        )
        results = [engine.validate_aws_api_request(request) for engine in (REGO, CEL)]

        for result in results:
            self.assertEqual(AwsApiRequestValidationStatus.VALIDATED, result.status)
            self.assertEqual(AwsApiOperationKind.CLOUD_FORMATION_CREATE, result.operation_kind)
            self.assertEqual(AwsApiTemplateSource.SYNTHESIZED_CREATE, result.template_source)
            self.assertEqual(["AWS::S3::Bucket"], result.resource_types)
            self.assertIsNotNone(result.report)
        self.assertEqual(diagnostic_keys(results[0].report), diagnostic_keys(results[1].report))
        self.assertEqual({"Bucket": "synthetic-bucket"}, parameters)

    def test_template_body_bytes_are_validated_exactly(self):
        request = AwsApiRequest(
            "cloudformation",
            "CreateChangeSet",
            {"TemplateBody": b'{"Resources":{}}'},
            service_prefix="cloudformation",
            http_method="POST",
        )

        result = REGO.validate_aws_api_request(request)

        self.assertEqual(AwsApiRequestValidationStatus.VALIDATED, result.status)
        self.assertEqual(AwsApiTemplateSource.TEMPLATE_BODY, result.template_source)
        self.assertEqual(ReportStatus.OK, result.report.status)

    def test_read_only_request_reports_explicit_skip(self):
        request = AwsApiRequest(
            "iam",
            "GetRole",
            {"RoleName": "Synthetic"},
            service_prefix="iam",
            http_method="POST",
        )

        result = REGO.validate_aws_api_request(request)

        self.assertEqual(AwsApiRequestValidationStatus.SKIPPED, result.status)
        self.assertEqual(AwsApiOperationKind.READ_ONLY, result.operation_kind)
        self.assertIsNone(result.report)
        self.assertIn("read-only", result.reason)

    def test_partial_update_diagnostics_are_scoped_and_counts_match(self):
        request = AwsApiRequest(
            "lambda",
            "UpdateFunctionConfiguration",
            {"FunctionName": "Synthetic", "MemorySize": 0},
            service_prefix="lambda",
            http_method="POST",
        )

        result = REGO.validate_aws_api_request(request)
        report = result.report

        self.assertEqual(AwsApiTemplateSource.SYNTHESIZED_UPDATE, result.template_source)
        self.assertTrue(
            all(d.property_path and "MemorySize" in d.property_path for d in report.diagnostics),
            report.diagnostics,
        )
        counts = report.metadata.counts
        self.assertEqual(
            len(report.diagnostics),
            counts.fatal + counts.errors + counts.warnings + counts.informational + counts.debug,
        )

    def test_unregistered_operation_never_maps_to_resource_type(self):
        request = AwsApiRequest(
            "ecs",
            "RunTask",
            {"TaskDefinition": "my-task"},
            service_prefix="ecs",
            http_method="POST",
        )

        result = REGO.validate_aws_api_request(request)

        self.assertEqual(AwsApiRequestValidationStatus.SKIPPED, result.status)
        self.assertEqual([], result.resource_types)
        self.assertIsNone(result.report)

    def test_java_sdk_service_name_casing_resolves_adapter(self):
        request = AwsApiRequest(
            "S3",
            "CreateBucket",
            {"Bucket": "synthetic-bucket"},
            service_prefix="S3",
            http_method="PUT",
        )

        result = REGO.validate_aws_api_request(request)

        self.assertEqual(AwsApiOperationKind.CLOUD_FORMATION_CREATE, result.operation_kind)
        self.assertEqual(["AWS::S3::Bucket"], result.resource_types)


class AdditionalSchemasTest(unittest.TestCase):
    def test_additional_schemas_apply_through_the_public_config_on_both_engines(self):
        from cloudformation_validate import SchemaValidatorConfig

        config = EngineConfig(
            schema_validator_config=SchemaValidatorConfig(
                additional_schemas=[AdditionalSchemaSource(type_name=None, schema=LAMBDA_OVERLAY_SCHEMA)]
            )
        )
        for name, baseline, engine_type in (
            ("rego", REGO, RegoEngine),
            ("cel", CEL, CelEngine),
        ):
            baseline_report = baseline.validate_standard(TEMPLATE_WITH_OVERLAY_PROPERTY)
            self.assertTrue(
                any(d.rule_id == "F3002" for d in baseline_report.diagnostics),
                f"{name} baseline must report the unpublished property",
            )
            report = engine_type(config).validate_standard(TEMPLATE_WITH_OVERLAY_PROPERTY)
            self.assertFalse(
                any(d.rule_id == "F3002" for d in report.diagnostics),
                f"{name} public config must apply the overlay",
            )

    def test_file_helper_loads_the_schema_and_optional_type_name(self):
        with tempfile.TemporaryDirectory() as directory:
            schema_path = os.path.join(directory, "schema.json")
            with open(schema_path, "w", encoding="utf-8") as f:
                f.write(LAMBDA_OVERLAY_SCHEMA)

            source = file_to_additional_schema_source(schema_path, "AWS::Lambda::Function")

        self.assertEqual("AWS::Lambda::Function", source.type_name)
        self.assertEqual(LAMBDA_OVERLAY_SCHEMA, source.schema)


class CustomRulesTest(unittest.TestCase):
    def assert_custom_rule_fires(self, engine):
        report = engine.validate_standard(UNENCRYPTED_BUCKET)
        custom = [d for d in report.diagnostics if d.rule_id == "CUSTOM001"]
        self.assertEqual(1, len(custom), f"custom rule must fire once via {engine.engine_name()}")
        self.assertEqual("S3 bucket must have encryption configured", custom[0].message)

    def test_cel_custom_rule_fires(self):
        config = EngineConfig(
            custom_rules=[ExternalRuleSource(name="cel_custom.json", content=load_rule("cel_custom.json"))]
        )
        self.assert_custom_rule_fires(CelEngine(config))

    def test_rego_custom_rule_fires(self):
        config = EngineConfig(
            custom_rules=[ExternalRuleSource(name="rego_custom.rego", content=load_rule("rego_custom.rego"))]
        )
        self.assert_custom_rule_fires(RegoEngine(config))

    def test_guard_rule_fires_on_both_engines(self):
        config = EngineConfig(
            guard_rules=[
                ExternalRuleSource(name="guard_encryption.guard", content=load_rule("guard_encryption.guard"))
            ]
        )
        for engine in (RegoEngine(config), CelEngine(config)):
            report = engine.validate_standard(UNENCRYPTED_BUCKET)
            guard_hits = [d for d in report.diagnostics if "encryption" in d.message.lower()]
            self.assertTrue(guard_hits, f"guard rule must fire via {engine.engine_name()}")


class TemplateModelTest(unittest.TestCase):
    def test_model_exposes_template_structure(self):
        model = TemplateModel(UNENCRYPTED_BUCKET)
        resources = model.resources()
        self.assertEqual(["MyBucket"], list(resources))
        self.assertEqual("AWS::S3::Bucket", resources["MyBucket"].resource_type)
        self.assertEqual({}, model.parameters())
        self.assertEqual({}, model.outputs())
        self.assertEqual([], model.conditions())
        self.assertEqual([], model.transforms())
        self.assertIsNone(model.format_version())

    def test_source_location_resolves_paths(self):
        model = TemplateModel(UNENCRYPTED_BUCKET)
        span = model.source_location("Resources/MyBucket/Properties/BucketName")
        self.assertIsNotNone(span)
        self.assertGreater(span.start_line, 0)
        self.assertIsNone(model.source_location("Resources/DoesNotExist"))

    def test_diagnostic_model_lists_resources(self):
        diagnostic = TemplateModel(UNENCRYPTED_BUCKET).to_diagnostic_model()
        self.assertEqual(1, len(diagnostic.resources))


class ErrorHandlingTest(unittest.TestCase):
    def test_parse_of_garbage_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            TemplateModel(b"\x00\x01garbage")

    def test_invalid_custom_rule_raises_validation_error(self):
        config = EngineConfig(custom_rules=[ExternalRuleSource(name="broken.rego", content="not valid rego {{{")])
        with self.assertRaises(ValidationError):
            RegoEngine(config)


class LogicalIdFilterTest(unittest.TestCase):
    def test_exclude_filter_scopes_diagnostics_to_matching_entity_type(self):
        config = ValidateConfig(
            exclude=RuleFilterConfig(
                logical_ids=[
                    LogicalIdFilter(
                        rule_id=None,
                        logical_id="MyBucket",
                        entity_type=EntityType.RESOURCE,
                    )
                ]
            )
        )
        report = REGO.validate_standard(UNENCRYPTED_BUCKET, config)
        matching = [
            diagnostic
            for diagnostic in report.diagnostics
            if diagnostic.entity is not None and diagnostic.entity.logical_id == "MyBucket"
        ]
        self.assertEqual([], matching)


class NativeLoaderTest(unittest.TestCase):
    def test_unsupported_operating_system_raises_clear_error(self):
        with mock.patch.object(native_loader.sys, "platform", "freebsd14"):
            with self.assertRaisesRegex(RuntimeError, "no native library for operating system 'freebsd14'"):
                native_loader.native_library_dir()


class InvalidInputTest(unittest.TestCase):
    def test_empty_template_reports_fatal_parse_rule(self):
        for engine in (REGO, CEL):
            report = engine.validate_standard(os.path.join(TEMPLATES, "empty.yaml"))
            self.assertEqual(ReportStatus.ERROR, report.status)
            self.assertEqual("F1101", report.diagnostics[0].rule_id)
            self.assertEqual(Severity.FATAL, report.diagnostics[0].severity)


class TemplateModelFixtureTest(unittest.TestCase):
    def test_minimal_template_sections(self):
        model = TemplateModel(os.path.join(TEMPLATES, "good", "minimal.yaml"))
        self.assertEqual("2010-09-09", model.format_version())
        self.assertIn("IamPipeline", model.resources())
        self.assertEqual([], model.conditions())
        self.assertEqual([], model.transforms())

    def test_generic_template_sections(self):
        model = TemplateModel(os.path.join(TEMPLATES, "good", "generic.yaml"))
        self.assertEqual("A sample template", model.description())
        self.assertIn("ProdVolumeSize", model.conditions())
        self.assertIn("ElasticIP", model.outputs())
        diagnostic = model.to_diagnostic_model()
        self.assertIsNotNone(diagnostic.template)
        self.assertTrue(diagnostic.resources)

    def test_rejects_malformed_yaml(self):
        with self.assertRaises(ValidationError):
            TemplateModel(os.path.join(TEMPLATES, "malformed.yaml"))


class CombinedCustomGuardListingTest(unittest.TestCase):
    def assert_sorted_and_identical(self, cel, rego):
        # Rego discovers custom rule metadata during evaluation.
        rego.validate_standard(os.path.join(TEMPLATES, "bad", "invalid_deletion_policy.yaml"))
        listings = {}
        for name, engine in (("cel", cel), ("rego", rego)):
            rules = engine.list_rules()
            ids = [r.id for r in rules]
            self.assertEqual(ids, sorted(ids), f"{name}: rules must be sorted by id")
            listings[name] = [(r.id, r.severity, r.origin, r.description) for r in rules]
        self.assertEqual(listings["cel"], listings["rego"])
        return {r[0]: r for r in listings["rego"]}

    def test_single_combined_custom_and_guard(self):
        cel = CelEngine(
            EngineConfig(
                custom_rules=[ExternalRuleSource(name="cel_custom.json", content=load_rule("cel_custom.json"))],
                guard_rules=[
                    ExternalRuleSource(name="guard_encryption.guard", content=load_rule("guard_encryption.guard"))
                ],
            )
        )
        rego = RegoEngine(
            EngineConfig(
                custom_rules=[ExternalRuleSource(name="rego_custom.rego", content=load_rule("rego_custom.rego"))],
                guard_rules=[
                    ExternalRuleSource(name="guard_encryption.guard", content=load_rule("guard_encryption.guard"))
                ],
            )
        )
        rules = self.assert_sorted_and_identical(cel, rego)
        self.assertEqual(RuleOrigin.CUSTOM, rules["CUSTOM001"][2])
        self.assertEqual(RuleOrigin.GUARD, rules["check_bucket_encryption"][2])

    def test_multi_combined_custom_and_guard(self):
        guard_rules = [
            ExternalRuleSource(name="guard_encryption.guard", content=load_rule("guard_encryption.guard")),
            ExternalRuleSource(name="guard_multi.guard", content=load_rule("guard_multi.guard")),
        ]
        cel = CelEngine(
            EngineConfig(
                custom_rules=[
                    ExternalRuleSource(name="cel_multi_custom.json", content=load_rule("cel_multi_custom.json"))
                ],
                guard_rules=guard_rules,
            )
        )
        rego = RegoEngine(
            EngineConfig(
                custom_rules=[
                    ExternalRuleSource(name="rego_multi_custom.rego", content=load_rule("rego_multi_custom.rego"))
                ],
                guard_rules=guard_rules,
            )
        )
        rules = self.assert_sorted_and_identical(cel, rego)
        expected = {
            "CUSTOM010": (Severity.ERROR, RuleOrigin.CUSTOM, "S3 bucket must have versioning enabled"),
            "CUSTOM011": (Severity.WARN, RuleOrigin.CUSTOM, "S3 bucket should have lifecycle rules configured"),
            "check_bucket_encryption": (None, RuleOrigin.GUARD, "S3 bucket must have encryption configured"),
            "check_bucket_versioning": (None, RuleOrigin.GUARD, "S3 bucket must have versioning enabled"),
            "check_bucket_lifecycle": (None, RuleOrigin.GUARD, "S3 bucket should have lifecycle rules configured"),
        }
        for rule_id, (severity, origin, description) in expected.items():
            self.assertIn(rule_id, rules, f"{rule_id} must be listed")
            _, actual_severity, actual_origin, actual_description = rules[rule_id]
            if severity is not None:
                self.assertEqual(severity, actual_severity, rule_id)
            self.assertEqual(origin, actual_origin, rule_id)
            self.assertEqual(description, actual_description, rule_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)

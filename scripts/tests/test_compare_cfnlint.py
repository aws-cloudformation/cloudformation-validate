import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS_DIR))

import compare_cfnlint as comparison


class ComparisonIdentityTests(unittest.TestCase):
    def setUp(self):
        self.original_aliases = comparison._RULE_ALIASES
        self.original_engine_to_cfnlint = comparison._ENGINE_TO_CFNLINT
        comparison._RULE_ALIASES = {}
        comparison._ENGINE_TO_CFNLINT = {}

    def tearDown(self):
        comparison._RULE_ALIASES = self.original_aliases
        comparison._ENGINE_TO_CFNLINT = self.original_engine_to_cfnlint

    def test_resource_metadata_keeps_logical_id_and_slash_keys(self):
        identity = comparison._normalize_engine_identity(
            "Instance",
            "Metadata.AWS::CloudFormation::Init.files./etc/cfn/cfn-hup.conf.content.Fn::Join",
        )

        self.assertEqual(
            (
                "Instance",
                "Metadata.AWS::CloudFormation::Init.files./etc/cfn/cfn-hup.conf.content.Fn::Join",
            ),
            identity,
        )

    def test_top_level_output_uses_resource_free_dotted_identity(self):
        identity = comparison._normalize_engine_identity("", "Outputs/WebsiteUrl/Value.Fn::Join")

        self.assertEqual(("", "Outputs.WebsiteUrl.Value.Fn::Join"), identity)

    def test_proven_equivalent_anchors_share_match_keys(self):
        cases = [
            ("I1022", "Metadata.Command.Fn::Join.0", "Metadata.Command.Fn::Join"),
            ("W2010", "Metadata.Secret.Ref", "Metadata.Secret"),
            ("W2010", "Metadata.Secret.Fn::Sub", "Metadata.Secret"),
            ("F1018", "Metadata.Name.Fn::Sub", "Metadata.Name"),
            ("F1020", "Metadata.Target.Ref", "Metadata.Target"),
            ("W1020", "Properties.Command.Fn::Sub", "Properties.Command"),
            (
                "E3053",
                "Properties.ContainerDefinitions.0.PortMappings.0.HostPort",
                "Properties.ContainerDefinitions[0].PortMappings[0].HostPort",
            ),
            (
                "E1152",
                "Properties.Fn::If.2.Fn::If.1.ImageId",
                "Properties.ImageId",
            ),
        ]

        for rule_id, reference_path, engine_path in cases:
            with self.subTest(rule_id=rule_id, reference_path=reference_path):
                reference = self._diagnostic(rule_id, "Resource", reference_path)
                engine = self._diagnostic(rule_id, "Resource", engine_path)
                self.assertEqual(comparison._match_key(reference), comparison._match_key(engine))

    def test_depends_on_indices_remain_distinct(self):
        scalar = self._diagnostic("W3005", "Resource", "DependsOn")
        indexed = self._diagnostic("W3005", "Resource", "DependsOn.1")

        self.assertNotEqual(comparison._match_key(scalar), comparison._match_key(indexed))

    def test_resource_root_json_path_matches_empty_engine_resource_path(self):
        reference = self._diagnostic("I3011", "Table", "")
        reference["json_path"] = "Resources.Table"
        engine = self._diagnostic("I3011", "Table", "")

        self.assertEqual(
            ("I3011", "Table", ""),
            comparison._match_key(reference),
        )
        self.assertEqual(
            comparison._match_key(reference),
            comparison._match_key(engine),
        )

    def test_unrelated_intrinsic_paths_remain_distinct(self):
        reference = self._diagnostic("F1020", "Resource", "Metadata.Target.Fn::GetAtt")
        engine = self._diagnostic("F1020", "Resource", "Metadata.Target")

        self.assertNotEqual(comparison._match_key(reference), comparison._match_key(engine))

    def test_resource_directive_suppresses_only_the_named_rule_and_resource(self):
        template = {
            "Resources": {
                "Suppressed": {
                    "Metadata": {
                        "cfn-lint": {
                            "config": {"ignore_checks": ["E3001", "E3030"]}
                        }
                    }
                },
                "Unsuppressed": {"Type": "AWS::S3::Bucket"},
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)

        self.assertTrue(suppressions.suppresses({"E3001"}, "Suppressed"))
        self.assertFalse(suppressions.suppresses({"E3001"}, "Unsuppressed"))
        self.assertFalse(suppressions.suppresses({"E3019"}, "Suppressed"))

    def test_resource_directive_uses_reference_rule_id_for_promoted_rule(self):
        comparison._ENGINE_TO_CFNLINT = {"F3003": {"E3003"}}
        template = {
            "Resources": {
                "Resource": {
                    "Metadata": {
                        "cfn-lint": {"config": {"ignore_checks": ["E3003"]}}
                    }
                }
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)

        self.assertTrue(
            comparison._is_reference_suppressed("F3003", "Resource", suppressions)
        )

    def test_global_ignore_prefix_applies_without_resource_scope(self):
        template = {
            "Metadata": {
                "cfn-lint": {"config": {"ignore_checks": ["W", "E2530"]}}
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)

        self.assertTrue(suppressions.suppresses({"W2010"}, "AnyResource"))
        self.assertTrue(suppressions.suppresses({"E2530"}, ""))
        self.assertFalse(suppressions.suppresses({"E3001"}, "AnyResource"))

    def test_reference_suppression_precedes_engine_extra_classification(self):
        diagnostic = {
            "rule_id": "F3002",
            "reference_suppressed": True,
        }
        original_engine_extra_rules = comparison.ENGINE_EXTRA_RULES
        comparison.ENGINE_EXTRA_RULES = {"F3002"}
        try:
            # Reference suppression takes precedence: a suppressed finding is RS
            # regardless of whether it would also be engine-extra.
            self.assertTrue(
                comparison._is_reference_suppressed_for_comparison(diagnostic)
            )
        finally:
            comparison.ENGINE_EXTRA_RULES = original_engine_extra_rules

    def test_sam_stateful_effective_types_are_intentional_divergences(self):
        for resource_type in ("AWS::Serverless::Application", "AWS::Serverless::SimpleTable"):
            with self.subTest(resource_type=resource_type):
                diagnostic = self._diagnostic("I3011", "Resource", "")
                diagnostic.update({
                    "resource_type": resource_type,
                    "message": "'DeletionPolicy' is a required property (stateful resource)",
                })
                self.assertTrue(comparison._is_intentional_divergence(diagnostic))

        diagnostic["resource_type"] = "AWS::DynamoDB::Table"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_forbidden_identity_policy_id_is_an_intentional_divergence(self):
        diagnostic = self._diagnostic("E3510", "Policy", "Properties.PolicyDocument.Id")
        diagnostic.update({
            "resource_type": "AWS::IAM::ManagedPolicy",
            "message": "Additional properties are not allowed ('Id' was unexpected)",
        })
        self.assertTrue(comparison._is_intentional_divergence(diagnostic))

        diagnostic["resource_type"] = "AWS::S3::BucketPolicy"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_concrete_identity_policy_document_list_is_an_intentional_divergence(self):
        diagnostic = self._diagnostic("E3510", "Policy", "Properties.PolicyDocument")
        diagnostic.update({
            "resource_type": "AWS::IAM::Policy",
            "message": "[{\"Statement\":{}}] is not of type 'object'",
        })
        self.assertTrue(comparison._is_intentional_divergence(diagnostic))

        diagnostic["resource_path"] = "Properties.PolicyDocument.Statement"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

        diagnostic["resource_path"] = "Properties.PolicyDocument"
        diagnostic["message"] = "{\"Statement\":{}} is not of type 'object'"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

        diagnostic["message"] = "[{\"Statement\":{}}] is not of type 'object'"
        diagnostic["resource_type"] = "AWS::S3::BucketPolicy"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_default_provisioned_billing_is_not_blanket_intentional_divergence(self):
        diagnostic = self._diagnostic("E3639", "Table", "Properties.ProvisionedThroughput")
        diagnostic.update({
            "resource_type": "AWS::DynamoDB::Table",
            "message": "ProvisionedThroughput is required when BillingMode defaults to 'PROVISIONED'",
        })

        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_formatted_diagnostic_strips_trailing_whitespace(self):
        diagnostic = self._diagnostic("E3001", "Resource", "")
        diagnostic.update(
            {
                "resource_type": "AWS::S3::Bucket",
                "line": 1,
                "end_line": 1,
                "message": "message with trailing space ",
            }
        )

        formatted = comparison.fmt_diag(diagnostic, "template_yaml")

        self.assertEqual("  > message with trailing space", formatted.splitlines()[-1])

    def test_yaml_loader_handles_cloudformation_tags_and_directives(self):
        template = """\
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Metadata:
      cfn-lint:
        config:
          ignore_checks:
            - E3001
    Properties:
      BucketName: !Sub '${AWS::StackName}-bucket'
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.yaml"
            path.write_text(template)

            suppressions = comparison._load_reference_suppressions(path)

        self.assertTrue(suppressions.suppresses({"E3001"}, "Bucket"))

    @staticmethod
    def _diagnostic(rule_id, resource_id, resource_path):
        return {
            "rule_id": rule_id,
            "resource_id": resource_id,
            "resource_path": resource_path,
            "json_path": "",
            "message": "message",
        }


class ReferenceNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.original_mapping = comparison._CFNLINT_TO_ENGINE

    def tearDown(self):
        comparison._CFNLINT_TO_ENGINE = self.original_mapping

    @staticmethod
    def _raw(rule_id, message, level="Error"):
        return {
            "Rule": {"Id": rule_id, "ShortDescription": "description"},
            "Level": level,
            "Location": {},
            "Message": message,
        }

    def test_promoted_identity_retains_raw_reference_id_and_severity(self):
        comparison._CFNLINT_TO_ENGINE = {"E3003": "F3003"}

        diagnostic = comparison.normalize_cfnlint_diags([
            self._raw("E3003", "'Name' is a required property")
        ])[0]

        self.assertEqual("F3003", diagnostic["rule_id"])
        self.assertEqual("E3003", diagnostic["cfnlint_rule_id"])
        self.assertEqual("Fatal", diagnostic["severity"])
        self.assertEqual("Error", diagnostic["cfnlint_severity"])

    def test_missing_resources_e1001_maps_to_f0001_only_for_that_occurrence(self):
        comparison._CFNLINT_TO_ENGINE = {}

        missing_resources, invalid_globals = comparison.normalize_cfnlint_diags([
            self._raw("E1001", "'Resources' is a required property"),
            self._raw("E1001", "'notadict' is not of type 'object'"),
        ])

        self.assertEqual("F0001", missing_resources["rule_id"])
        self.assertEqual("E1001", missing_resources["cfnlint_rule_id"])
        self.assertEqual("Fatal", missing_resources["severity"])
        self.assertEqual("E1001", invalid_globals["rule_id"])
        self.assertEqual("Error", invalid_globals["severity"])


class EngineToReferenceAliasTests(unittest.TestCase):
    """Tests for the reverse-alias (engine_to_cfnlint) resolution mechanism.

    Verifies that _reference_rule_ids correctly resolves engine rule IDs to the
    full set of cfn-lint IDs they correspond to, enabling reference suppressions
    to work for all many-to-one mappings.
    """

    def setUp(self):
        self.original_engine_to_cfnlint = comparison._ENGINE_TO_CFNLINT
        self.original_aliases = comparison._RULE_ALIASES
        self.original_engine_extra = comparison.ENGINE_EXTRA_RULES

    def tearDown(self):
        comparison._ENGINE_TO_CFNLINT = self.original_engine_to_cfnlint
        comparison._RULE_ALIASES = self.original_aliases
        comparison.ENGINE_EXTRA_RULES = self.original_engine_extra

    def test_single_alias_resolves_to_singleton_set(self):
        """A 1:1 mapping returns a single-element set."""
        comparison._ENGINE_TO_CFNLINT = {"F3003": {"E3003"}}
        result = comparison._reference_rule_ids("F3003")
        self.assertEqual(result, {"E3003"})

    def test_many_to_one_e3691_e3690_resolve_to_e9006(self):
        """E3691→E9006 and E3690→E9006: both cfn-lint IDs must be in the set."""
        comparison._ENGINE_TO_CFNLINT = {"E9006": {"E3690", "E3691"}}
        result = comparison._reference_rule_ids("E9006")
        self.assertEqual(result, {"E3690", "E3691"})

    def test_many_to_one_e1022_e1020_resolve_to_f1020(self):
        """E1022→F1020 and E1020→F1020: both cfn-lint IDs in the reverse set."""
        comparison._ENGINE_TO_CFNLINT = {"F1020": {"E1020", "E1022"}}
        result = comparison._reference_rule_ids("F1020")
        self.assertEqual(result, {"E1020", "E1022"})

    def test_many_to_one_e8001_e1028_resolve_to_f0013(self):
        """E8001→F0013 and E1028→F0013: both cfn-lint IDs in the reverse set."""
        comparison._ENGINE_TO_CFNLINT = {"F0013": {"E1028", "E8001"}}
        result = comparison._reference_rule_ids("F0013")
        self.assertEqual(result, {"E1028", "E8001"})

    def test_fallback_returns_engine_id_when_no_mapping_exists(self):
        """An unmapped engine ID falls back to itself."""
        comparison._ENGINE_TO_CFNLINT = {}
        result = comparison._reference_rule_ids("E9999")
        self.assertEqual(result, {"E9999"})

    def test_global_suppression_covers_all_reverse_aliases(self):
        """A global ignore_checks prefix like 'E' suppresses engine findings
        whose cfn-lint reverse-aliases start with E."""
        comparison._ENGINE_TO_CFNLINT = {"E9006": {"E3690", "E3691"}}
        comparison.ENGINE_EXTRA_RULES = set()
        template = {
            "Metadata": {
                "cfn-lint": {"config": {"ignore_checks": ["E"]}}
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)
        # The engine finding E9006 reverse-maps to E3690/E3691, both start with E
        self.assertTrue(
            comparison._is_reference_suppressed("E9006", "AnyResource", suppressions),
            "Global 'E' prefix should suppress E9006 via reverse-aliases E3690/E3691"
        )

    def test_resource_suppression_with_many_to_one_alias(self):
        """A per-resource ignore_checks for E3691 suppresses engine E9006 on that resource."""
        comparison._ENGINE_TO_CFNLINT = {"E9006": {"E3690", "E3691"}}
        comparison.ENGINE_EXTRA_RULES = set()
        template = {
            "Resources": {
                "MyDB": {
                    "Metadata": {
                        "cfn-lint": {"config": {"ignore_checks": ["E3691"]}}
                    }
                }
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)
        self.assertTrue(
            comparison._is_reference_suppressed("E9006", "MyDB", suppressions),
            "E3691 suppression on MyDB should suppress engine E9006"
        )
        self.assertFalse(
            comparison._is_reference_suppressed("E9006", "OtherDB", suppressions),
            "Other resources should not be suppressed"
        )

    def test_compute_rule_origins_retains_all_reverse_aliases(self):
        from audit_rule_categorization import compute_rule_origins

        cfnlint_rule_ids = ["E1020", "E1022", "E1028", "E3690", "E3691", "E8001"]
        with tempfile.TemporaryDirectory() as directory:
            rules_dir = Path(directory) / "src" / "cfnlint" / "rules"
            rules_dir.mkdir(parents=True)
            rules_dir.joinpath("fixture_rules.py").write_text(
                "shortdesc = \"fixture\"\n"
                + "\n".join(f'id = "{rule_id}"' for rule_id in cfnlint_rule_ids)
            )

            origins = compute_rule_origins(Path(directory))

        self.assertTrue(origins.engine_to_cfnlint)
        self.assertTrue(all(isinstance(ids, set) for ids in origins.engine_to_cfnlint.values()))
        self.assertEqual(origins.engine_to_cfnlint["F1020"], {"E1020", "E1022"})
        self.assertEqual(origins.engine_to_cfnlint["E9006"], {"E3690", "E3691"})
        self.assertEqual(origins.engine_to_cfnlint["F0013"], {"E1028", "E8001"})


class OccurrenceMatchingTests(unittest.TestCase):
    """Behavioral identity is independent from final diagnostic anchoring."""

    def setUp(self):
        self.original_aliases = comparison._RULE_ALIASES
        comparison._RULE_ALIASES = {}

    def tearDown(self):
        comparison._RULE_ALIASES = self.original_aliases

    def test_unrelated_paths_on_same_resource_remain_unmatched(self):
        reference = [_diag("E3012", "MyBucket", "Properties.BucketName")]
        engine = [_diag("E3012", "MyBucket", "Properties.AccessControl")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual([], comparison._collect_match_mismatches(matched))

    def test_same_path_matches_without_path_mismatch(self):
        reference = [_diag("E3012", "MyBucket", "Properties.BucketName")]
        engine = [_diag("E3012", "MyBucket", "Properties.BucketName")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual([], comparison._collect_match_mismatches(matched))

    def test_top_level_different_paths_remain_unmatched(self):
        reference = [_diag("E3001", "", "Outputs.Foo")]
        engine = [_diag("E3001", "", "Outputs.Bar")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))

    def test_same_rule_on_different_resources_remains_unmatched(self):
        reference = [_diag("E3012", "First", "Properties.Name")]
        engine = [_diag("E3012", "Second", "Properties.Name")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))

    def test_different_rules_on_same_resource_remain_unmatched(self):
        reference = [_diag("E3012", "Resource", "Properties.Name")]
        engine = [_diag("E3001", "Resource", "Properties.Name")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))

    def test_duplicate_exact_identities_pair_deterministically_by_message(self):
        reference = [
            _diag("E3012", "Resource", "Properties.Name", message="first"),
            _diag("E3012", "Resource", "Properties.Name", message="second"),
        ]
        engine = [
            _diag("E3012", "Resource", "Properties.Name", message="second"),
            _diag("E3012", "Resource", "Properties.Name", message="first"),
        ]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((2, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual(
            [("first", "first"), ("second", "second")],
            sorted((expected["message"], actual["message"]) for expected, actual in matched),
        )

    def test_transform_error_message_identity_reports_path_quality_separately(self):
        message = "Error transforming template: invalid generated resource"
        reference = [_diag("E0001", "", "", message=message)]
        engine = [_diag("E0001", "Generated", "Properties.Source", message=message)]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )
        mismatches = comparison._collect_match_mismatches(matched)

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual(("", "Properties.Source"), mismatches[0][2])
        classification = comparison._classify_path_difference(*matched[0])
        self.assertEqual(comparison._ENGINE_PREFERRED, classification.kind)

    def test_condition_branch_path_is_representational(self):
        reference = [_diag(
            "E1152", "Instance", "Properties.Fn::If.2.Fn::If.1.ImageId"
        )]
        engine = [_diag("E1152", "Instance", "Properties.ImageId")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        classification = comparison._classify_path_difference(*matched[0])
        self.assertEqual(comparison._REPRESENTATIONAL, classification.kind)

    def test_engine_preferred_anchor_pairs_only_explicit_rule(self):
        reference = [_diag("E3047", "Task", "Properties")]
        engine = [_diag("E3047", "Task", "Properties.Cpu")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        classification = comparison._classify_path_difference(*matched[0])
        self.assertEqual(comparison._ENGINE_PREFERRED, classification.kind)

    def test_non_comparable_relationship_endpoints_pair(self):
        reference = [_diag("E3502", "Queue", "Properties.FifoQueue")]
        engine = [_diag("E3502", "Queue", "Properties.RedrivePolicy")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        classification = comparison._classify_path_difference(*matched[0])
        self.assertEqual(comparison._NON_COMPARABLE, classification.kind)

    def test_same_rule_resource_pairing_artifact_remains_unmatched(self):
        reference = [_diag("F3012", "Database", "Properties.MultiAZ")]
        engine = [_diag("F3012", "Database", "Properties.AllocatedStorage")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))


class SAMPathMatchingTests(unittest.TestCase):
    """SAM hash-suffix equivalents still require the same canonical path."""

    def setUp(self):
        self.original_aliases = comparison._RULE_ALIASES
        comparison._RULE_ALIASES = {}

    def tearDown(self):
        comparison._RULE_ALIASES = self.original_aliases

    def test_sam_hash_match_with_same_path_has_no_path_mismatch(self):
        reference = [_diag("E3012", "Layer7f955f606e", "Properties.Content")]
        engine = [_diag("E3012", "Layer", "Properties.Content")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((1, 0, 0), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual([], comparison._collect_match_mismatches(matched))

    def test_sam_hash_match_with_different_path_remains_unmatched(self):
        reference = [_diag("E3012", "Layer7f955f606e", "Properties.Content")]
        engine = [_diag("E3012", "Layer", "Properties.Runtime")]

        matched, false_positives, false_negatives = comparison.compare_template(
            reference, engine
        )

        self.assertEqual((0, 1, 1), (
            len(matched), len(false_positives), len(false_negatives)
        ))
        self.assertEqual([], comparison._collect_match_mismatches(matched))


class CollisionResolutionTests(unittest.TestCase):
    """Tests for duplicate cfn-lint baseline collision resolution."""

    def test_identical_diagnostics_deduplicate_silently(self):
        """When normalized diagnostics are identical, keep either without error."""
        existing = ("good/serverless.yaml", [{"rule_id": "E0001"}], Path("/a/b.json"))
        new_entry = ("good/serverless.yaml", [{"rule_id": "E0001"}], Path("/c/d.json"))

        result = comparison._resolve_cfnlint_collision("key", existing, new_entry)

        self.assertEqual(result, existing)

    def test_quickstart_non_strict_preferred_over_strict(self):
        """For QuickStart collisions, non_strict wins."""
        strict_file = Path("/results/quickstart/strict/cis.json")
        non_strict_file = Path("/results/quickstart/non_strict/cis.json")

        existing = ("quickstart/cis.yaml", [{"rule_id": "E3012"}], non_strict_file)
        new_entry = ("quickstart/cis.yaml", [{"rule_id": "F3012"}], strict_file)

        result = comparison._resolve_cfnlint_collision("key", existing, new_entry)

        self.assertEqual(result, existing)

    def test_quickstart_strict_replaced_by_non_strict(self):
        """When strict is existing and non_strict comes second, non_strict wins."""
        strict_file = Path("/results/quickstart/strict/cis.json")
        non_strict_file = Path("/results/quickstart/non_strict/cis.json")

        existing = ("quickstart/cis.yaml", [{"rule_id": "F3012"}], strict_file)
        new_entry = ("quickstart/cis.yaml", [{"rule_id": "E3012"}], non_strict_file)

        result = comparison._resolve_cfnlint_collision("key", existing, new_entry)

        self.assertEqual(result, new_entry)

    def test_quickstart_non_strict_preferred_over_root_in_both_orders(self):
        """An explicit non_strict baseline wins over the root/default result."""
        root_file = Path("/results/quickstart/cis_benchmark_yaml.json")
        non_strict_file = Path("/results/quickstart/non_strict/cis_benchmark_yaml.json")
        root_entry = ("quickstart/cis_benchmark.yaml", [{"rule_id": "F3012"}], root_file)
        non_strict_entry = ("quickstart/cis_benchmark.yaml", [{"rule_id": "E3012"}], non_strict_file)

        for existing, new_entry in ((root_entry, non_strict_entry), (non_strict_entry, root_entry)):
            with self.subTest(existing=existing[2]):
                result = comparison._resolve_cfnlint_collision(
                    "quickstart_cis_benchmark_yaml", existing, new_entry
                )
                self.assertEqual(result, non_strict_entry)

    def test_ambiguous_collision_raises(self):
        """Unresolvable collision raises ValueError."""
        file_a = Path("/results/other/a.json")
        file_b = Path("/results/another/b.json")

        existing = ("", [{"rule_id": "E3012"}], file_a)
        new_entry = ("", [{"rule_id": "F3012"}], file_b)

        with self.assertRaises(ValueError) as ctx:
            comparison._resolve_cfnlint_collision("test_key", existing, new_entry)
        self.assertIn("test_key", str(ctx.exception))


class StrictNonStrictSelectionTests(unittest.TestCase):
    """Test that QuickStart strict/non_strict selection works correctly."""

    def test_corpus_dir_preference_for_non_quickstart(self):
        """For non-QuickStart, prefer result tree matching template top-level dir."""
        global CFN_LINT_RESULTS
        original = comparison.CFN_LINT_RESULTS
        comparison.CFN_LINT_RESULTS = Path("/results")
        try:
            # Template is in bad/, existing result is in bad/ tree, new is in good/
            bad_file = Path("/results/bad/template.json")
            good_file = Path("/results/good/template.json")

            existing = ("bad/template.yaml", [{"rule_id": "E3012"}], bad_file)
            new_entry = ("bad/template.yaml", [{"rule_id": "E3012", "extra": True}], good_file)

            result = comparison._resolve_cfnlint_collision("key", existing, new_entry)
            self.assertEqual(result, existing)
        finally:
            comparison.CFN_LINT_RESULTS = original


class TaxonomyPrecedenceTests(unittest.TestCase):
    """Tests suppression, evidence-backed divergence, and engine-extra precedence."""

    def setUp(self):
        self.original_engine_to_cfnlint = comparison._ENGINE_TO_CFNLINT
        self.original_engine_extra_rules = comparison.ENGINE_EXTRA_RULES
        self.original_engine_extra_predicate = comparison._IS_ENGINE_EXTRA_DIAGNOSTIC

    def tearDown(self):
        comparison._ENGINE_TO_CFNLINT = self.original_engine_to_cfnlint
        comparison.ENGINE_EXTRA_RULES = self.original_engine_extra_rules
        comparison._IS_ENGINE_EXTRA_DIAGNOSTIC = self.original_engine_extra_predicate

    def test_w9003_requires_schema_coercion_evidence(self):
        diagnostic = _diag(
            "W9003",
            "Resource",
            "Properties.Foo",
            phase="SCHEMA",
            message="'5' is not of type 'integer' - automatically coerced (string to integer)",
        )

        self.assertTrue(comparison._is_intentional_divergence(diagnostic))
        diagnostic["message"] = "unrecognized warning"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_w1019_requires_unused_sub_parameter_evidence(self):
        diagnostic = _diag(
            "W1019",
            "Resource",
            "Properties.Foo",
            phase="LINT",
            message="Parameter 'Unused' not used in Fn::Sub template string",
        )

        self.assertTrue(comparison._is_intentional_divergence(diagnostic))
        diagnostic["phase"] = "SCHEMA"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_extension_schema_findings_require_known_property_and_phase(self):
        diagnostic = _diag(
            "F3003",
            "Resource",
            "Properties",
            phase="SCHEMA",
            message="'ProvisionedThroughput' is a required property (from extension)",
        )
        self.assertTrue(comparison._is_intentional_divergence(diagnostic))

        diagnostic["message"] = "'UnreviewedProperty' is a required property (from extension)"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))
        diagnostic["message"] = "'ProvisionedThroughput' is a required property (from extension)"
        diagnostic["phase"] = "LINT"
        self.assertFalse(comparison._is_intentional_divergence(diagnostic))

    def test_f3002_condition_short_circuit_requires_same_resource_e1028(self):
        diagnostic = _diag(
            "F3002",
            "Resource",
            "Properties.Foo",
            message="Additional properties are not allowed ('BadKey' was unexpected)",
        )
        same_resource_evidence = [
            _diag(
                "F0013",
                "Resource",
                "Properties.Foo.Fn::If",
                cfnlint_rule_id="E1028",
            )
        ]
        other_resource_evidence = [
            _diag(
                "F0013",
                "OtherResource",
                "Properties.Foo.Fn::If",
                cfnlint_rule_id="E1028",
            )
        ]

        self.assertFalse(comparison._is_intentional_divergence(diagnostic))
        self.assertFalse(
            comparison._is_intentional_divergence(
                diagnostic, other_resource_evidence
            )
        )
        self.assertTrue(
            comparison._is_intentional_divergence(
                diagnostic, same_resource_evidence
            )
        )

    def test_e1028_short_circuit_requires_same_resource_reference_finding(self):
        diagnostic = _diag("E1028", "Resource", "Properties.Foo")
        same_resource_evidence = [
            _diag(
                "E1028",
                "Resource",
                "Properties.Foo",
                cfnlint_rule_id="E1028",
            )
        ]
        other_resource_evidence = [
            _diag(
                "E1028",
                "OtherResource",
                "Properties.Foo",
                cfnlint_rule_id="E1028",
            )
        ]

        self.assertFalse(comparison._is_intentional_divergence(diagnostic))
        self.assertFalse(
            comparison._is_intentional_divergence(
                diagnostic, other_resource_evidence
            )
        )
        self.assertTrue(
            comparison._is_intentional_divergence(
                diagnostic, same_resource_evidence
            )
        )

    def test_resource_shape_short_circuit_requires_same_resource_e3001(self):
        same_resource_evidence = [
            _diag("E3001", "Resource", "", cfnlint_rule_id="E3001")
        ]
        other_resource_evidence = [
            _diag("E3001", "OtherResource", "", cfnlint_rule_id="E3001")
        ]

        for rule_id in ("F0006", "E5001", "F6004"):
            with self.subTest(rule_id=rule_id):
                diagnostic = _diag(rule_id, "Resource", "")
                self.assertFalse(
                    comparison._is_intentional_divergence(diagnostic)
                )
                self.assertFalse(
                    comparison._is_intentional_divergence(
                        diagnostic, other_resource_evidence
                    )
                )
                self.assertTrue(
                    comparison._is_intentional_divergence(
                        diagnostic, same_resource_evidence
                    )
                )

    def test_w3030_suppression_uses_e3030_reverse_equivalence(self):
        comparison._ENGINE_TO_CFNLINT = {"W3030": {"E3030"}}
        template = {
            "Resources": {
                "SuppressedBucket": {
                    "Metadata": {
                        "cfn-lint": {
                            "config": {"ignore_checks": ["E3030"]}
                        }
                    }
                }
            }
        }
        suppressions = comparison._extract_reference_suppressions(template)

        self.assertTrue(
            comparison._is_reference_suppressed(
                "W3030", "SuppressedBucket", suppressions
            )
        )

    def test_rule_with_reverse_equivalent_can_never_be_engine_extra(self):
        comparison._ENGINE_TO_CFNLINT = {"W3030": {"E3030"}}
        comparison.ENGINE_EXTRA_RULES = {"W3030"}
        comparison._IS_ENGINE_EXTRA_DIAGNOSTIC = lambda diagnostic: True

        self.assertFalse(
            comparison._is_engine_extra(
                _diag("W3030", "Bucket", "Properties.AccessControl")
            )
        )

    def test_parse_error_is_not_blanket_engine_extra(self):
        comparison._ENGINE_TO_CFNLINT = {}
        comparison.ENGINE_EXTRA_RULES = set()
        comparison._IS_ENGINE_EXTRA_DIAGNOSTIC = lambda diagnostic: False

        self.assertFalse(comparison._is_engine_extra(_diag("F0000", "", "")))

    def test_reference_suppression_precedes_engine_extra(self):
        diagnostic = {"rule_id": "F0001", "reference_suppressed": True}
        comparison.ENGINE_EXTRA_RULES = {"F0001"}

        self.assertTrue(
            comparison._is_reference_suppressed_for_comparison(diagnostic)
        )


class ReferenceIncorrectTests(unittest.TestCase):
    """Tests for the RI (Reference Incorrect) category.

    Exactly eight known Fargate RI cases, excluded from FN and recall.
    """

    def test_e3047_fargate_good_template_is_ri(self):
        """E3047 x3 in good/ecs_fargate_units_and_sizes.yaml are RI."""
        for resource_id in ("ThirtyTwoVcpuSixtyGb", "ThirtyTwoVcpuOneTwentyGb", "ThirtyTwoVcpuTwoFortyFourGb"):
            with self.subTest(resource_id=resource_id):
                d = _diag("E3047", resource_id, "Properties.Cpu")
                self.assertTrue(comparison._is_reference_incorrect(
                    "good/ecs_fargate_units_and_sizes.yaml", d
                ))

    def test_e3048_fargate_good_template_is_ri(self):
        """E3048 x3 in good/ecs_fargate_units_and_sizes.yaml are RI."""
        for resource_id in ("ThirtyTwoVcpuSixtyGb", "ThirtyTwoVcpuOneTwentyGb", "ThirtyTwoVcpuTwoFortyFourGb"):
            with self.subTest(resource_id=resource_id):
                d = _diag("E3048", resource_id, "Properties.Memory")
                self.assertTrue(comparison._is_reference_incorrect(
                    "good/ecs_fargate_units_and_sizes.yaml", d
                ))

    def test_e3048_fargate_bad_template_specific_resources_are_ri(self):
        """E3048 x2 in bad/resources/ecs/fargate_task_sizes_e3047.yaml are RI."""
        for resource_id in ("ThirtyTwoVcpuUnsupportedSixtyFourGb", "ThirtyTwoVcpuUnsupportedTwoFortyGb"):
            with self.subTest(resource_id=resource_id):
                d = _diag("E3048", resource_id, "Properties.Memory")
                self.assertTrue(comparison._is_reference_incorrect(
                    "bad/resources/ecs/fargate_task_sizes_e3047.yaml", d
                ))

    def test_total_ri_count_is_exactly_eight(self):
        """Verify exactly 8 known RI cases exist."""
        count = 0
        for (path, rule_id), resources in comparison._REFERENCE_INCORRECT_RESOURCES.items():
            count += len(resources)
        self.assertEqual(count, 8)

    def test_ri_excluded_from_fn(self):
        """RI findings do not appear as FN in comparison results."""
        # An RI finding that is in cfn-lint but not engine should not be FN
        d = _diag("E3047", "ThirtyTwoVcpuSixtyGb", "Properties.Cpu")
        self.assertTrue(comparison._is_reference_incorrect(
            "good/ecs_fargate_units_and_sizes.yaml", d
        ))

    def test_non_ri_resource_for_same_rule_is_not_ri(self):
        """A different resource for the same rule is not RI."""
        d = _diag("E3047", "OtherTask", "Properties.Cpu")
        self.assertFalse(comparison._is_reference_incorrect(
            "good/ecs_fargate_units_and_sizes.yaml", d
        ))

    def test_non_ri_template_for_same_rule_is_not_ri(self):
        """Same rule on a different template is not RI."""
        d = _diag("E3047", "ThirtyTwoVcpuSixtyGb", "Properties.Cpu")
        self.assertFalse(comparison._is_reference_incorrect(
            "bad/other_template.yaml", d
        ))


class SeverityMismatchTests(unittest.TestCase):
    """Tests that severity differences are surfaced explicitly."""

    def test_severity_divergence_detected(self):
        """Matched pair with different severity is detected."""
        exp = _diag("E3012", "Res", "Properties.Foo")
        exp["severity"] = "Error"
        act = _diag("E3012", "Res", "Properties.Foo")
        act["severity"] = "Fatal"

        self.assertTrue(comparison._severity_diverges(exp, act))

    def test_same_severity_not_flagged(self):
        """Matched pair with same severity is not flagged."""
        exp = _diag("E3012", "Res", "Properties.Foo")
        exp["severity"] = "Error"
        act = _diag("E3012", "Res", "Properties.Foo")
        act["severity"] = "Error"

        self.assertFalse(comparison._severity_diverges(exp, act))

    def test_empty_severity_not_flagged(self):
        """Missing severity on either side is not flagged."""
        exp = _diag("E3012", "Res", "Properties.Foo")
        exp["severity"] = ""
        act = _diag("E3012", "Res", "Properties.Foo")
        act["severity"] = "Error"

        self.assertFalse(comparison._severity_diverges(exp, act))


class FullSpanMatchingTests(unittest.TestCase):
    """Tests for full span (line, column, end_line, end_column) comparison."""

    def test_span_divergence_detects_column_difference(self):
        """Column difference is detected in span comparison."""
        exp = {"line": 10, "column": 5, "end_line": 10, "end_column": 20}
        act = {"line": 10, "column": 8, "end_line": 10, "end_column": 20}

        result = comparison._span_diverges(exp, act)

        self.assertIsNotNone(result)
        self.assertIn("col 5→8", result)

    def test_span_divergence_detects_end_column_difference(self):
        """end_column difference is detected."""
        exp = {"line": 10, "column": 5, "end_line": 10, "end_column": 20}
        act = {"line": 10, "column": 5, "end_line": 10, "end_column": 25}

        result = comparison._span_diverges(exp, act)

        self.assertIsNotNone(result)
        self.assertIn("end_col 20→25", result)

    def test_half_open_reference_endpoint_matches_inclusive_engine_endpoint(self):
        exp = {"line": 10, "column": 5, "end_line": 10, "end_column": 20}
        act = {"line": 10, "column": 5, "end_line": 10, "end_column": 19}

        self.assertIsNone(comparison._span_diverges(exp, act))

    def test_endpoint_convention_is_removed_without_hiding_other_differences(self):
        exp = {"line": 10, "column": 5, "end_line": 10, "end_column": 20}
        act = {"line": 10, "column": 8, "end_line": 10, "end_column": 19}

        result = comparison._span_diverges(exp, act)

        self.assertEqual("col 5→8", result)

    def test_span_divergence_detects_line_difference(self):
        """Line difference is detected."""
        exp = {"line": 10, "column": 5, "end_line": 12, "end_column": 20}
        act = {"line": 11, "column": 5, "end_line": 12, "end_column": 20}

        result = comparison._span_diverges(exp, act)

        self.assertIsNotNone(result)
        self.assertIn("line 10→11", result)

    def test_span_divergence_detects_end_line_difference(self):
        """end_line difference is detected."""
        exp = {"line": 10, "column": 5, "end_line": 12, "end_column": 20}
        act = {"line": 10, "column": 5, "end_line": 15, "end_column": 20}

        result = comparison._span_diverges(exp, act)

        self.assertIsNotNone(result)
        self.assertIn("end_line 12→15", result)

    def test_identical_span_returns_none(self):
        """Identical spans return None (no divergence)."""
        exp = {"line": 10, "column": 5, "end_line": 12, "end_column": 20}
        act = {"line": 10, "column": 5, "end_line": 12, "end_column": 20}

        result = comparison._span_diverges(exp, act)

        self.assertIsNone(result)

    def test_missing_coordinates_are_reported(self):
        exp = {"line": 10, "column": 0, "end_line": 10, "end_column": 0}
        act = {"line": 10, "column": 5, "end_line": 10, "end_column": 20}

        span_difference = comparison._span_diverges(exp, act)

        self.assertIn("col missing→5", span_difference)
        self.assertIn("end_col missing→20", span_difference)

    def test_pathless_structural_findings_span_compared(self):
        """Pathless (structural/top-level) findings have spans compared too."""
        exp = {"line": 1, "column": 1, "end_line": 1, "end_column": 10}
        act = {"line": 1, "column": 1, "end_line": 2, "end_column": 5}

        result = comparison._span_diverges(exp, act)

        self.assertIsNotNone(result)
        self.assertIn("end_line 1→2", result)


class SpanQualityClassificationTests(unittest.TestCase):
    def test_endpoint_convention_is_representational(self):
        reference = _diag(
            "E3012", "Resource", "Properties.Foo",
            line=10, column=5, end_line=10, end_column=20,
        )
        engine = _diag(
            "E3012", "Resource", "Properties.Foo",
            line=10, column=5, end_line=10, end_column=19,
        )

        classification = comparison._classify_span_difference(reference, engine)

        self.assertEqual(comparison._REPRESENTATIONAL, classification.kind)

    def test_exact_invalid_operand_is_engine_preferred(self):
        reference = _diag(
            "I3042", "Key", "Properties.Description",
            line=10, column=5, end_line=10, end_column=16,
        )
        engine = _diag(
            "I3042", "Key", "Properties.Description",
            line=11, column=12, end_line=11, end_column=30,
        )

        classification = comparison._classify_span_difference(reference, engine)

        self.assertEqual(comparison._ENGINE_PREFERRED, classification.kind)

    def test_missing_required_child_is_non_comparable(self):
        reference = _diag(
            "F3003", "Resource", "Properties.Items.0",
            message="'Name' is a required property",
            line=10, column=5, end_line=12, end_column=3,
        )
        engine = _diag(
            "F3003", "Resource", "Properties.Items.0",
            message="'Name' is a required property",
            line=10, column=9, end_line=10, end_column=13,
        )

        classification = comparison._classify_span_difference(reference, engine)

        self.assertEqual(comparison._NON_COMPARABLE, classification.kind)

    def test_condition_source_ranges_are_non_comparable(self):
        reference = _diag(
            "E1152", "Resource", "Properties.Fn::If.1.ImageId",
            line=12, column=9, end_line=12, end_column=16,
        )
        engine = _diag(
            "E1152", "Resource", "Properties.ImageId",
            line=8, column=5, end_line=8, end_column=12,
        )
        path_classification = comparison._classify_path_difference(
            reference, engine
        )

        classification = comparison._classify_span_difference(
            reference, engine, path_classification
        )

        self.assertEqual(comparison._NON_COMPARABLE, classification.kind)

    def test_unproven_source_difference_remains_unclassified(self):
        reference = _diag(
            "E3012", "Resource", "Properties.Foo",
            line=10, column=5, end_line=10, end_column=20,
        )
        engine = _diag(
            "E3012", "Resource", "Properties.Foo",
            line=11, column=8, end_line=11, end_column=25,
        )

        self.assertIsNone(
            comparison._classify_span_difference(reference, engine)
        )

    def test_intrinsic_property_value_is_engine_preferred(self):
        reference = _diag(
            "E3022", "Association", "Properties.SubnetId",
            line=10, column=9, end_line=10, end_column=17,
        )
        engine = _diag(
            "E3022", "Association", "Properties.SubnetId",
            line=11, column=11, end_line=11, end_column=14,
        )

        classification = comparison._classify_span_difference(reference, engine)

        self.assertEqual(comparison._ENGINE_PREFERRED, classification.kind)

    def test_missing_lifecycle_counterpart_is_non_comparable(self):
        reference = _diag(
            "W3011", "Database", "",
            line=10, column=3, end_line=10, end_column=11,
        )
        engine = _diag(
            "W3011", "Database", "",
            line=11, column=5, end_line=11, end_column=13,
        )

        classification = comparison._classify_span_difference(reference, engine)

        self.assertEqual(comparison._NON_COMPARABLE, classification.kind)


class MatchQualityReportingTests(unittest.TestCase):
    """Identity pairs remain matched when severity or spans differ."""

    @staticmethod
    def _comparison_counts(reference, engine):
        matched, false_positives, false_negatives = comparison.compare_template(
            [reference], [engine]
        )
        mismatches = comparison._collect_match_mismatches(matched)
        return (
            len(matched),
            len(false_positives),
            len(false_negatives),
            len(mismatches),
        )

    def test_severity_mismatch_remains_matched_and_is_reported(self):
        reference = _diag(
            "E3012", "Resource", "Properties.Foo", severity="Error"
        )
        engine = _diag(
            "E3012", "Resource", "Properties.Foo", severity="Fatal"
        )

        self.assertEqual(
            (1, 0, 0, 1), self._comparison_counts(reference, engine)
        )

    def test_span_mismatch_remains_matched_and_is_reported(self):
        reference = _diag(
            "E3012",
            "Resource",
            "Properties.Foo",
            line=10,
            column=5,
            end_line=10,
            end_column=20,
        )
        engine = _diag(
            "E3012",
            "Resource",
            "Properties.Foo",
            line=10,
            column=8,
            end_line=10,
            end_column=20,
        )

        self.assertEqual(
            (1, 0, 0, 1), self._comparison_counts(reference, engine)
        )

    def test_classified_path_difference_remains_matched_and_is_reported(self):
        reference = _diag("E3047", "Resource", "Properties")
        engine = _diag("E3047", "Resource", "Properties.Cpu")

        self.assertEqual(
            (1, 0, 0, 1), self._comparison_counts(reference, engine)
        )
        classification = comparison._classify_path_difference(reference, engine)
        self.assertEqual(comparison._ENGINE_PREFERRED, classification.kind)

    def test_explicit_transform_identity_path_mismatch_is_reported(self):
        message = "Error transforming template: invalid generated resource"
        reference = _diag("E0001", "", "", message=message)
        engine = _diag(
            "E0001", "Generated", "Properties.Source", message=message
        )

        self.assertEqual(
            (1, 0, 0, 1), self._comparison_counts(reference, engine)
        )

    def test_exact_pair_remains_matched_without_mismatch(self):
        reference = _diag(
            "E3012",
            "Resource",
            "Properties.Foo",
            line=10,
            column=5,
            end_line=10,
            end_column=20,
        )
        engine = dict(reference)

        self.assertEqual(
            (1, 0, 0, 0), self._comparison_counts(reference, engine)
        )


class RootCauseEvidenceTests(unittest.TestCase):
    """Unmatched causes are derived from diagnostics on the counterpart side."""

    def setUp(self):
        self.original_aliases = comparison._RULE_ALIASES
        comparison._RULE_ALIASES = {}

    def tearDown(self):
        comparison._RULE_ALIASES = self.original_aliases

    def test_missing_equivalent_rule_identifies_counterpart_side(self):
        diagnostic = _diag("E3012", "Resource", "Properties.Foo")
        unrelated = [_diag("W3005", "Resource", "DependsOn")]

        self.assertEqual(
            "No equivalent reference rule emitted",
            comparison._false_positive_root_cause(diagnostic, unrelated),
        )
        self.assertEqual(
            "No equivalent engine rule emitted",
            comparison._false_negative_root_cause(diagnostic, unrelated),
        )

    def test_equivalent_rule_on_different_resource_is_identified(self):
        diagnostic = _diag("E3012", "First", "Properties.Foo")
        counterparts = [_diag("E3012", "Second", "Properties.Foo")]

        self.assertEqual(
            "Equivalent rule emitted on a different resource/entity",
            comparison._false_positive_root_cause(diagnostic, counterparts),
        )

    def test_equivalent_rule_and_resource_on_different_path_is_identified(self):
        diagnostic = _diag("E3012", "Resource", "Properties.Foo")
        counterparts = [_diag("E3012", "Resource", "Properties.Bar")]

        self.assertEqual(
            "Equivalent rule/resource emitted on a different property path",
            comparison._false_negative_root_cause(diagnostic, counterparts),
        )

    def test_same_identity_is_identified_as_multiplicity_difference(self):
        diagnostic = _diag("E3012", "Resource", "Properties.Foo")
        counterparts = [_diag("E3012", "Resource", "Properties.Foo")]

        self.assertEqual(
            "Diagnostic count differs after exact identity pairing",
            comparison._false_positive_root_cause(diagnostic, counterparts),
        )

    def test_multiplicity_is_partitioned_from_behavioral_mismatches(self):
        duplicate = _diag("E3012", "Resource", "Properties.Foo")
        behavioral, multiplicity = comparison._partition_multiplicity(
            [duplicate],
            [_diag("E3012", "Resource", "Properties.Foo")],
            comparison._false_positive_root_cause,
        )

        self.assertEqual([], behavioral)
        self.assertEqual([duplicate], multiplicity)

    def test_alias_equivalent_rule_uses_counterpart_identity_evidence(self):
        comparison._RULE_ALIASES = {"F3012": {"E3012"}}
        diagnostic = _diag("E3012", "Resource", "Properties.Foo")
        counterparts = [_diag("F3012", "Resource", "Properties.Foo")]

        self.assertEqual(
            "Diagnostic count differs after exact identity pairing",
            comparison._false_negative_root_cause(diagnostic, counterparts),
        )


class ReferenceScopeTests(unittest.TestCase):
    def test_internal_and_runtime_only_rules_are_renderable_but_unscored(self):
        rule_ids = ("E0002", "E3043", "W4001", "W4005", "W6001")
        diagnostics = [
            {
                "Rule": {"Id": rule_id},
                "Level": "Error",
                "Location": {},
                "Message": "not comparable",
            }
            for rule_id in rule_ids
        ]

        normalized = comparison.normalize_cfnlint_diags(diagnostics)

        self.assertEqual(list(rule_ids), [d["rule_id"] for d in normalized])
        self.assertTrue(all(d["comparison_excluded_reason"] for d in normalized))

    def test_comparable_rule_has_no_scope_exclusion(self):
        normalized = comparison.normalize_cfnlint_diags([{
            "Rule": {"Id": "E3001"},
            "Level": "Error",
            "Location": {},
            "Message": "comparable",
        }])

        self.assertEqual("", normalized[0]["comparison_excluded_reason"])


class LoaderAndParsingFailureTests(unittest.TestCase):
    """Tests that malformed JSON, non-list results, and parse failures raise."""

    def test_malformed_json_in_cfnlint_result_raises(self):
        """Non-parseable JSON in a cfn-lint result file raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bad.json"
            f.write_text("{not valid json")
            results = {}

            with self.assertRaises(ValueError) as ctx:
                comparison._load_cfnlint_result_file(f, "prefix", results)
            self.assertIn("Malformed JSON", str(ctx.exception))

    def test_non_list_cfnlint_result_raises(self):
        """A cfn-lint result that is not a JSON list raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "obj.json"
            f.write_text('{"not": "a list"}')
            results = {}

            with self.assertRaises(ValueError) as ctx:
                comparison._load_cfnlint_result_file(f, "prefix", results)
            self.assertIn("does not contain a JSON list", str(ctx.exception))

    def test_engine_json_decode_failure_raises(self):
        """Engine report with invalid JSON raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            reports_dir = Path(td)
            bad_report = reports_dir / "template_yaml.json"
            bad_report.write_text("{invalid")

            original_reports = comparison.ENGINE_REPORTS
            comparison.ENGINE_REPORTS = reports_dir
            try:
                with self.assertRaises(ValueError) as ctx:
                    comparison.load_engine_results()
                self.assertIn("Engine report JSON decode failure", str(ctx.exception))
            finally:
                comparison.ENGINE_REPORTS = original_reports

    def test_engine_report_top_level_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            reports_dir = Path(directory)
            (reports_dir / "template_yaml.json").write_text("[]")
            original_reports = comparison.ENGINE_REPORTS
            comparison.ENGINE_REPORTS = reports_dir
            try:
                with self.assertRaisesRegex(ValueError, "JSON object"):
                    comparison.load_engine_results()
            finally:
                comparison.ENGINE_REPORTS = original_reports

    def test_engine_report_diagnostics_must_be_present_as_a_list(self):
        for payload in ({}, {"diagnostics": {}}):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                reports_dir = Path(directory)
                (reports_dir / "template_yaml.json").write_text(
                    json.dumps(payload)
                )
                original_reports = comparison.ENGINE_REPORTS
                comparison.ENGINE_REPORTS = reports_dir
                try:
                    with self.assertRaisesRegex(ValueError, "diagnostics.*JSON list"):
                        comparison.load_engine_results()
                finally:
                    comparison.ENGINE_REPORTS = original_reports

    def test_engine_report_each_diagnostic_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            reports_dir = Path(directory)
            (reports_dir / "template_yaml.json").write_text(
                '{"filePath": "good/template.yaml", "diagnostics": ["bad"]}'
            )
            original_reports = comparison.ENGINE_REPORTS
            comparison.ENGINE_REPORTS = reports_dir
            try:
                with self.assertRaisesRegex(ValueError, "diagnostic 0.*JSON object"):
                    comparison.load_engine_results()
            finally:
                comparison.ENGINE_REPORTS = original_reports

    def test_engine_report_load_retains_validated_template_path(self):
        with tempfile.TemporaryDirectory() as directory:
            reports_dir = Path(directory)
            (reports_dir / "template_yaml.json").write_text(
                '{"filePath": "good/template.yaml", "diagnostics": []}'
            )
            original_reports = comparison.ENGINE_REPORTS
            comparison.ENGINE_REPORTS = reports_dir
            try:
                diagnostics, template_paths = comparison.load_engine_results()
            finally:
                comparison.ENGINE_REPORTS = original_reports

        self.assertEqual({"template_yaml": []}, diagnostics)
        self.assertEqual(
            {"template_yaml": "good/template.yaml"}, template_paths
        )

    def test_inline_result_parse_failure_raises(self):
        """Malformed inline scenarios file raises ValueError."""
        with tempfile.TemporaryDirectory() as td:
            test_dir = Path(td) / "test" / "integration"
            test_dir.mkdir(parents=True)
            py_file = test_dir / "test_good_templates.py"
            # Write a file with a scenarios list that contains invalid Python syntax
            py_file.write_text('scenarios = [{"filename": invalid_syntax]')

            original_root = comparison.CFN_LINT_ROOT
            comparison.CFN_LINT_ROOT = Path(td)
            try:
                with self.assertRaises(ValueError) as ctx:
                    comparison.load_cfnlint_inline_results()
                self.assertIn("Failed to parse inline cfn-lint scenarios", str(ctx.exception))
            finally:
                comparison.CFN_LINT_ROOT = original_root

    def test_unterminated_inline_scenarios_raise(self):
        """An opening scenarios list without a closing bracket is an error."""
        with tempfile.TemporaryDirectory() as td:
            test_dir = Path(td) / "test" / "integration"
            test_dir.mkdir(parents=True)
            (test_dir / "test_good_templates.py").write_text(
                'scenarios = [{"filename": "test/fixtures/templates/good/a.yaml"}'
            )

            original_root = comparison.CFN_LINT_ROOT
            comparison.CFN_LINT_ROOT = Path(td)
            try:
                with self.assertRaisesRegex(ValueError, "Unterminated inline"):
                    comparison.load_cfnlint_inline_results()
            finally:
                comparison.CFN_LINT_ROOT = original_root

    def test_inline_scenario_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            test_dir = Path(directory) / "test" / "integration"
            test_dir.mkdir(parents=True)
            (test_dir / "test_good_templates.py").write_text(
                'scenarios = ["not an object"]\n'
            )

            original_root = comparison.CFN_LINT_ROOT
            comparison.CFN_LINT_ROOT = Path(directory)
            try:
                with self.assertRaisesRegex(ValueError, "scenario 0.*not an object"):
                    comparison.load_cfnlint_inline_results()
            finally:
                comparison.CFN_LINT_ROOT = original_root

    def test_inline_scenario_results_must_be_a_list(self):
        """Inline scenario result payloads must be diagnostic lists."""
        with tempfile.TemporaryDirectory() as td:
            test_dir = Path(td) / "test" / "integration"
            test_dir.mkdir(parents=True)
            (test_dir / "test_good_templates.py").write_text(
                'scenarios = [{"filename": "test/fixtures/templates/good/a.yaml", "results": {}}]\n'
            )

            original_root = comparison.CFN_LINT_ROOT
            comparison.CFN_LINT_ROOT = Path(td)
            try:
                with self.assertRaisesRegex(ValueError, "results.*not a list"):
                    comparison.load_cfnlint_inline_results()
            finally:
                comparison.CFN_LINT_ROOT = original_root


class CanonicalPathTests(unittest.TestCase):
    """Tests for canonical POSIX path derivation."""

    def test_canonical_path_from_cfnlint_filename(self):
        """Filename field is stripped to corpus-relative POSIX path."""
        result = comparison._canonical_template_path_from_filename(
            "test/fixtures/templates/bad/resources/foo.yaml"
        )
        self.assertEqual(result, "bad/resources/foo.yaml")

    def test_canonical_key_from_path(self):
        """Canonical path produces correct flattened key."""
        self.assertEqual(
            comparison._canonical_key_from_path("bad/resources/foo.yaml"),
            "bad_resources_foo_yaml",
        )
        self.assertEqual(
            comparison._canonical_key_from_path("good/serverless.yml"),
            "good_serverless_yml",
        )
        self.assertEqual(
            comparison._canonical_key_from_path("quickstart/cis.json"),
            "quickstart_cis_json",
        )

    def test_canonical_path_without_prefix_returns_unchanged(self):
        """Filename without the expected prefix is returned as-is."""
        result = comparison._canonical_template_path_from_filename("some/other/path.yaml")
        self.assertEqual(result, "some/other/path.yaml")


class RunSingleSafetyTests(unittest.TestCase):
    """Comparison runs fail closed and render deterministic tracked reports."""

    def test_zero_comparable_templates_fails(self):
        with (
            patch.object(comparison, "load_cfnlint_inline_results", return_value={}),
            patch.object(
                comparison,
                "load_cfnlint_results_from_files",
                return_value={"reference_only": []},
            ),
            patch.object(
                comparison,
                "load_engine_results",
                return_value=(
                    {"engine_only": []},
                    {"engine_only": "good/engine-only.yaml"},
                ),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "no comparable templates"):
                comparison.run_single()

    def test_out_of_scope_reference_findings_are_rendered_but_not_scored(self):
        reference = comparison.normalize_cfnlint_diags([{
            "Rule": {"Id": "E0002", "ShortDescription": "internal failure"},
            "Level": "Error",
            "Location": {},
            "Message": "reference rule failed",
        }])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            original_output = comparison.OUTPUT_PATH
            comparison.OUTPUT_PATH = output
            try:
                with (
                    patch.object(comparison, "load_cfnlint_inline_results", return_value={}),
                    patch.object(
                        comparison,
                        "load_cfnlint_results_from_files",
                        return_value={"shared": reference},
                    ),
                    patch.object(
                        comparison,
                        "load_engine_results",
                        return_value=(
                            {"shared": []},
                            {"shared": "good/shared.yaml"},
                        ),
                    ),
                ):
                    comparison.run_single()
                    report = output.read_text()
            finally:
                comparison.OUTPUT_PATH = original_output

        self.assertIn(
            "| Reference findings from checks outside comparison scope; excluded from scoring (OOS) | 1 |",
            report,
        )
        self.assertIn("## Reference Out of Scope - 1 findings excluded from recall", report)
        self.assertIn("**E0002**", report)
        self.assertIn("False Negatives - 0 missed findings", report)

    def test_summary_rows_define_their_population_or_calculation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            original_output = comparison.OUTPUT_PATH
            comparison.OUTPUT_PATH = output
            try:
                with (
                    patch.object(comparison, "load_cfnlint_inline_results", return_value={}),
                    patch.object(
                        comparison,
                        "load_cfnlint_results_from_files",
                        return_value={"shared": []},
                    ),
                    patch.object(
                        comparison,
                        "load_engine_results",
                        return_value=(
                            {"shared": []},
                            {"shared": "good/shared.yaml"},
                        ),
                    ),
                ):
                    comparison.run_single()
                    report = output.read_text()
            finally:
                comparison.OUTPUT_PATH = original_output

        self.assertIn(
            "Counts are diagnostic occurrences unless the row explicitly says templates, rules, or a percentage.",
            report,
        )
        self.assertIn("| Population or calculation | Value |", report)
        labels = (
            "Findings paired as the same occurrence (TP)",
            "Unmatched comparable findings emitted only by the engine (FP)",
            "Correct unmatched engine findings for rules with a reference equivalent (ID)",
            "Correct engine findings for rules with no reference equivalent (EE)",
            "Engine findings disabled by template reference configuration; excluded from scoring (RS)",
            "Reference findings from checks outside comparison scope; excluded from scoring (OOS)",
            "Demonstrably incorrect reference findings; excluded from recall (RI)",
            "Unpaired duplicate occurrences of an otherwise matched identity; excluded from FP/FN (Multiplicity)",
            "Unmatched comparable findings emitted only by the reference (FN)",
            "Precision: TP / (TP + FP)",
            "Recall: TP / (TP + FN)",
            "F1: harmonic mean of precision and recall",
            "Canonical rule IDs represented in TP/FP/ID/EE/FN/RI populations",
            "Templates with no FP, FN, multiplicity, or matched path/span/severity difference",
            "Matched occurrences with notation-only path differences (representational)",
            "Matched occurrences where the engine path is more precise or correct",
            "Matched occurrences with no unique shared path anchor",
            "Matched occurrences with endpoint-notation-only span differences (representational)",
            "Matched occurrences where the engine source span is more precise or correct",
            "Matched occurrences with no uniquely comparable source span",
            "Paired occurrences with an unclassified path difference (unresolved)",
            "Paired occurrences with an unclassified start-line difference (unresolved)",
            "Paired occurrences with an unclassified full-span difference (unresolved)",
            "Matched occurrences with different severities",
        )
        for label in labels:
            with self.subTest(label=label):
                self.assertIn(f"| {label} |", report)
        self.assertNotIn("| Metric | Value |", report)
        self.assertNotIn("| Perfect templates |", report)
        self.assertNotIn("| Unique rules detected |", report)

    def test_identical_inputs_produce_byte_identical_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            original_output = comparison.OUTPUT_PATH
            comparison.OUTPUT_PATH = output
            try:
                with (
                    patch.object(comparison, "load_cfnlint_inline_results", return_value={}),
                    patch.object(
                        comparison,
                        "load_cfnlint_results_from_files",
                        return_value={"shared": []},
                    ),
                    patch.object(
                        comparison,
                        "load_engine_results",
                        return_value=(
                            {"shared": []},
                            {"shared": "good/shared.yaml"},
                        ),
                    ),
                ):
                    comparison.run_single()
                    first = output.read_bytes()
                    comparison.run_single()
                    second = output.read_bytes()
            finally:
                comparison.OUTPUT_PATH = original_output

        self.assertEqual(first, second)
        self.assertNotIn(b"Generated:", first)


def _diag(rule_id, resource_id, resource_path, **kwargs):
    """Helper to construct a minimal diagnostic dict for tests."""
    d = {
        "rule_id": rule_id,
        "resource_id": resource_id,
        "resource_path": resource_path,
        "json_path": "",
        "message": kwargs.get("message", "test message"),
        "severity": kwargs.get("severity", "Error"),
        "line": kwargs.get("line", 0),
        "column": kwargs.get("column", 0),
        "end_line": kwargs.get("end_line", 0),
        "end_column": kwargs.get("end_column", 0),
    }
    d.update(kwargs)
    return d


if __name__ == "__main__":
    unittest.main()

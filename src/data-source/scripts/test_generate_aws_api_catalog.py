#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

import generate_aws_api_catalog as catalog


class Shape:
    def __init__(self, type_name, *, member=None, value=None, metadata=None,
                 serialization=None):
        self.type_name = type_name
        self.member = member
        self.value = value
        self.metadata = metadata or {}
        self.serialization = serialization or {}


class CatalogGeneratorTest(unittest.TestCase):
    def test_unreviewed_collision_is_dropped(self):
        adapters = [
            {
                "service": "quicksight",
                "operation": "CreateTopic",
                "cfn_type": "AWS::QuickSight::Topic",
            },
            {
                "service": "quicksight",
                "operation": "CreateTopic",
                "cfn_type": "AWS::QuickSight::TopicV2",
            },
        ]

        kept, dropped = catalog._enforce_global_uniqueness(adapters)

        self.assertEqual([], kept)
        self.assertEqual(2, len(dropped))

    def test_reviewed_collision_keeps_only_preferred_type(self):
        adapters = [
            {
                "service": "dynamodb",
                "operation": "CreateTable",
                "cfn_type": "AWS::DynamoDB::GlobalTable",
            },
            {
                "service": "dynamodb",
                "operation": "CreateTable",
                "cfn_type": "AWS::DynamoDB::Table",
            },
        ]

        kept, dropped = catalog._enforce_global_uniqueness(adapters)

        self.assertEqual(["AWS::DynamoDB::Table"], [entry["cfn_type"] for entry in kept])
        self.assertEqual(["AWS::DynamoDB::GlobalTable"], [entry["cfn_type"] for entry in dropped])

    def test_runtime_safe_mapping_accepts_only_serializable_shapes(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {"Key": {"type": "string"}, "Value": {"type": "string"}},
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}
        strings = {"type": "array", "items": {"type": "string"}}

        self.assertTrue(
            catalog._is_runtime_safe_mapping(Shape("string"), {"type": "string"}, {}, "Name")
        )
        self.assertTrue(
            catalog._is_runtime_safe_mapping(
                Shape("list", member=Shape("string")), strings, {}, "Names"
            )
        )
        self.assertTrue(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )
        self.assertFalse(
            catalog._is_runtime_safe_mapping(Shape("structure"), {"type": "object"}, {}, "Config")
        )
        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("list", member=Shape("structure")),
                {"type": "array", "items": {"type": "object"}},
                {},
                "Configs",
            )
        )

    def test_provider_schema_directory_is_loaded_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.json").write_text(json.dumps({"typeName": "AWS::Test::B"}))
            (root / "a.json").write_text(json.dumps({"typeName": "AWS::Test::A"}))
            (root / "ignored.json").write_text(json.dumps({"notTypeName": "AWS::Test::Ignored"}))

            schemas = catalog._load_provider_schemas(root)
            first_hash = catalog._source_sha256(root)
            second_hash = catalog._source_sha256(root)

        self.assertEqual(["AWS::Test::A", "AWS::Test::B"], sorted(schemas))
        self.assertEqual(first_hash, second_hash)


class IgnoredInputsTest(unittest.TestCase):
    """Tests for _ignored_inputs_for_operation."""

    def test_curated_name_is_ignored(self):
        members = {
            'ClientToken': Shape('string'),
            'BucketName': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 's3', 'CreateBucket')
        self.assertEqual(result, ['ClientToken'])

    def test_dry_run_is_ignored(self):
        members = {
            'DryRun': Shape('boolean'),
            'InstanceId': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 'ec2', 'RunInstances')
        self.assertEqual(result, ['DryRun'])

    def test_idempotency_token_metadata_is_detected(self):
        members = {
            'Token': Shape('string', metadata={'idempotencyToken': True}),
            'Name': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 'test', 'CreateThing')
        self.assertEqual(result, ['Token'])

    def test_idempotency_token_serialization_is_detected(self):
        members = {
            'RequestId': Shape('string', serialization={'idempotencyToken': True}),
            'Data': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 'test', 'CreateThing')
        self.assertEqual(result, ['RequestId'])

    def test_update_phase_does_not_add_curated_identifiers(self):
        """_ignored_inputs_for_operation derives only request-control fields."""
        members = {
            'FunctionName': Shape('string'),
            'MemorySize': Shape('integer'),
        }
        result = catalog._ignored_inputs_for_operation(
            members, 'update', 'lambda', 'UpdateFunctionConfiguration'
        )
        self.assertNotIn('FunctionName', result)

    def test_no_heuristic_detection(self):
        """Members not in the curated set or metadata are never ignored."""
        members = {
            'TokenValue': Shape('string'),
            'RequestId': Shape('string'),
            'Nonce': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 'test', 'CreateThing')
        self.assertEqual(result, [])

    def test_returns_sorted(self):
        members = {
            'DryRun': Shape('boolean'),
            'ClientToken': Shape('string'),
            'BucketName': Shape('string'),
        }
        result = catalog._ignored_inputs_for_operation(members, 'create', 's3', 'CreateBucket')
        self.assertEqual(result, sorted(result))


class CoverageMetricsTest(unittest.TestCase):
    """Tests for _compute_coverage and _render_coverage with synthetic data."""

    def _synthetic_coverage(self, adapters, botocore_operations=100,
                            botocore_services=10, compiled_schemas=None):
        """Build a synthetic coverage computation."""
        if compiled_schemas is None:
            compiled_schemas = {
                'AWS::Test::Type': {
                    'properties': {'Name': {}, 'Arn': {}, 'Id': {}},
                    'read_only_properties': ['Arn'],
                },
            }

        class FakeIndex:
            def __init__(self, services, operations):
                self.service_count = services
                self.operation_count = operations

        index = FakeIndex(botocore_services, botocore_operations)
        return catalog._compute_coverage(adapters, index, compiled_schemas)

    def test_zero_adapters_yields_zero_coverage(self):
        coverage = self._synthetic_coverage([])
        self.assertEqual(coverage['catalog_services']['covered'], 0)
        self.assertEqual(coverage['catalog_resources']['covered'], 0)
        self.assertEqual(coverage['writable_properties']['covered'], 0)
        self.assertEqual(coverage['catalog_commands']['covered'], 0)
        self.assertEqual(coverage['state_commands']['covered'], 0)

    def test_single_create_adapter_coverage(self):
        adapters = [{
            'service': 'test',
            'operation': 'CreateThing',
            'cfn_type': 'AWS::Test::Type',
            'phase': 'create',
            'mappings': [{'source': 'Name', 'target': 'Name'}],
        }]
        coverage = self._synthetic_coverage(adapters)
        self.assertEqual(coverage['catalog_services']['covered'], 1)
        self.assertEqual(coverage['catalog_services']['total'], 10)
        self.assertEqual(coverage['catalog_resources']['covered'], 1)
        self.assertEqual(coverage['catalog_commands']['covered'], 1)
        self.assertEqual(coverage['catalog_commands']['total'], 100)
        self.assertEqual(coverage['state_commands']['covered'], 1)
        self.assertEqual(coverage['state_services']['covered'], 1)
        self.assertEqual(coverage['state_resources']['covered'], 1)
        self.assertEqual(coverage['writable_properties']['covered'], 1)
        # Total writable is 2 (Name + Id; Arn is read-only)
        self.assertEqual(coverage['writable_properties']['total'], 2)

    def test_delete_adapter_does_not_count_as_state_validation(self):
        adapters = [{
            'service': 'test',
            'operation': 'DeleteThing',
            'cfn_type': 'AWS::Test::Type',
            'phase': 'delete',
            'mappings': [],
        }]
        coverage = self._synthetic_coverage(adapters)
        self.assertEqual(coverage['state_commands']['covered'], 0)
        self.assertEqual(coverage['catalog_commands']['covered'], 1)
        self.assertEqual(coverage['lifecycle_adapters'], {'delete': 1})

    def test_writable_properties_are_deduplicated_across_adapters(self):
        """Two adapters mapping to the same (cfn_type, target) count once."""
        adapters = [
            {
                'service': 'test',
                'operation': 'Create',
                'cfn_type': 'AWS::Test::Type',
                'phase': 'create',
                'mappings': [{'source': 'Name', 'target': 'Name'}],
            },
            {
                'service': 'test',
                'operation': 'Update',
                'cfn_type': 'AWS::Test::Type',
                'phase': 'update',
                'mappings': [{'source': 'Name', 'target': 'Name'}],
            },
        ]
        coverage = self._synthetic_coverage(adapters)
        self.assertEqual(coverage['writable_properties']['covered'], 1)

    def test_render_derivation_explains_outcomes_and_subset(self):
        counters = {
            'verified': 1305,
            'rejected': 113,
            'no_candidates': 118,
            'no_handler': 175,
            'tied_rejected': 3,
            'excluded_service': 15,
            'stale_model_rejected': 1,
        }

        lines = catalog._render_derivation('create', counters)

        self.assertEqual([
            'Create API operation matching:',
            '  Resource types evaluated from provider schemas: 1,729',
            '  Resource types with one API operation selected: 1,305',
            '  Resource types without an operation selection: 424',
            '    No create handler declared in the provider schema: 175',
            '    Service excluded from catalog generation: 15',
            (
                '    Handler permissions contained no usable botocore API '
                'operation: 118'
            ),
            (
                '    Best candidate failed resource-name/property matching '
                'safety checks: 113'
            ),
            (
                '      Of those, the exact create operation from handler '
                'permissions was absent from the loaded botocore models: 1'
            ),
            '    Multiple API operations tied for best candidate: 3',
        ], lines)

    def test_render_derivation_rejects_unexplained_outcome(self):
        with self.assertRaisesRegex(
            ValueError, 'no reader-facing description.*new_outcome'
        ):
            catalog._render_derivation(
                'create', {'verified': 1, 'new_outcome': 1}
            )

    def test_render_coverage_formats_percentages(self):
        coverage = {
            'catalog_services': {'covered': 3, 'total': 10},
            'catalog_resources': {'covered': 5, 'total': 20},
            'catalog_commands': {'covered': 7, 'total': 50},
            'state_services': {'covered': 2, 'total': 10},
            'state_resources': {'covered': 4, 'total': 20},
            'state_commands': {'covered': 4, 'total': 50},
            'writable_properties': {'covered': 15, 'total': 100},
            'lifecycle_adapters': {'create': 4, 'delete': 3},
        }

        lines = catalog._render_coverage(coverage)

        self.assertEqual([
            'Catalog coverage (all final create, update, and delete adapters):',
            '  botocore services represented: 3 of 10 (30.0%)',
            (
                '  Compiled CloudFormation resource types represented: '
                '5 of 20 (25.0%)'
            ),
            '  botocore API operations represented: 7 of 50 (14.0%)',
            '',
            (
                'State validation coverage (create/update adapters with at '
                'least one writable-property mapping):'
            ),
            '  botocore services with state validation: 2 of 10 (20.0%)',
            (
                '  Compiled CloudFormation resource types with state '
                'validation: 4 of 20 (20.0%)'
            ),
            (
                '  botocore API operations used for state validation: '
                '4 of 50 (8.0%)'
            ),
            (
                '  Writable CloudFormation properties mapped for state '
                'validation: 15 of 100 (15.0%)'
            ),
            '',
            'Final adapters by lifecycle phase:',
            '  Create adapters: 4',
            '  Update adapters: 0',
            '  Delete adapters: 3',
        ], lines)

    def test_generation_report_explains_uniqueness_and_output(self):
        coverage = {
            'catalog_services': {'covered': 1, 'total': 1},
            'catalog_resources': {'covered': 1, 'total': 1},
            'catalog_commands': {'covered': 2, 'total': 2},
            'state_services': {'covered': 1, 'total': 1},
            'state_resources': {'covered': 1, 'total': 1},
            'state_commands': {'covered': 1, 'total': 2},
            'writable_properties': {'covered': 1, 'total': 2},
            'lifecycle_adapters': {'create': 1, 'delete': 1},
        }

        lines = catalog._render_generation_report(
            {'verified': 1},
            {'verified': 1},
            2,
            coverage,
            2,
            Path('/tmp/catalog.json'),
        )

        self.assertEqual('AWS API catalog generation summary', lines[0])
        self.assertIn(
            'An adapter links one CloudFormation resource type and lifecycle '
            'action to one botocore API operation.',
            lines,
        )
        self.assertIn('API operation uniqueness check:', lines)
        self.assertIn(
            '  Adapters removed so each botocore API operation appears only '
            'once: 2',
            lines,
        )
        self.assertEqual([
            'Catalog output:',
            '  Adapters written: 2',
            '  File: /tmp/catalog.json',
        ], lines[-3:])

    def test_zero_total_does_not_divide_by_zero(self):
        coverage = {
            'catalog_services': {'covered': 0, 'total': 0},
            'catalog_resources': {'covered': 0, 'total': 0},
            'catalog_commands': {'covered': 0, 'total': 0},
            'state_services': {'covered': 0, 'total': 0},
            'state_resources': {'covered': 0, 'total': 0},
            'state_commands': {'covered': 0, 'total': 0},
            'writable_properties': {'covered': 0, 'total': 0},
            'lifecycle_adapters': {},
        }

        lines = catalog._render_coverage(coverage)

        percentage_lines = [line for line in lines if line.endswith('%)')]
        self.assertEqual(7, len(percentage_lines))
        self.assertTrue(all('(0.0%)' in line for line in percentage_lines))

    def test_exact_percentage_calculation(self):
        adapters = [
            {
                'service': 'svc0',
                'operation': 'Create',
                'cfn_type': 'AWS::A::B',
                'phase': 'create',
                'mappings': [{'source': 'X', 'target': 'Y'}],
            },
            {
                'service': 'svc1',
                'operation': 'Update',
                'cfn_type': 'AWS::A::B',
                'phase': 'update',
                'mappings': [{'source': 'Z', 'target': 'W'}],
            },
        ]
        # 2 services out of 4, 2 commands out of 8
        compiled = {'AWS::A::B': {'properties': {'Y': {}, 'W': {}}, 'read_only_properties': []}}
        coverage = self._synthetic_coverage(
            adapters, botocore_operations=8, botocore_services=4,
            compiled_schemas=compiled,
        )
        self.assertEqual(coverage['catalog_services']['covered'], 2)
        self.assertEqual(coverage['catalog_services']['total'], 4)
        self.assertEqual(coverage['catalog_commands']['covered'], 2)
        self.assertEqual(coverage['catalog_commands']['total'], 8)
        self.assertEqual(coverage['state_commands']['covered'], 2)
        self.assertEqual(coverage['writable_properties']['covered'], 2)
        self.assertEqual(coverage['writable_properties']['total'], 2)


if __name__ == "__main__":
    unittest.main()

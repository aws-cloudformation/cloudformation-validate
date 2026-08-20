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


class ExactServiceResolutionTest(unittest.TestCase):
    """Resolution is literal: a case-insensitive identity or a reviewed override.

    Punctuation is significant and substrings never match, so an IAM prefix
    denotes a service only when it equals a service identity exactly (ignoring
    case) or is a reviewed action-prefix override.
    """

    @staticmethod
    def _index(by_identity, operations):
        index = catalog.BotocoreIndex.__new__(catalog.BotocoreIndex)
        index._by_identity = {key: set(services) for key, services in by_identity.items()}
        index._operations = operations
        index._identities = {service: set() for service in operations}
        return index

    def test_identity_key_lowercases_and_preserves_punctuation(self):
        # The identity key folds case only; _normalize is the lossy sibling used
        # for relatedness. Keeping them distinct is what stops punctuation from
        # being erased into a false identity match.
        self.assertEqual('s3-control', catalog._identity_key('S3-Control'))
        self.assertEqual('kafka-cluster', catalog._identity_key('Kafka-Cluster'))
        self.assertEqual('s3control', catalog._normalize('S3-Control'))

    def test_substring_service_identity_no_longer_resolves(self):
        # A prefix that is only a *substring* of a real identity resolves to
        # nothing: 'mq' is contained in 'amazonmq', but 'amazonmq' is neither an
        # identity nor an override.
        index = self._index({'mq': {'mq'}}, {'mq': {'createbroker': 'CreateBroker'}})
        self.assertEqual(set(), index.resolve('amazonmq', 'CreateBroker'))
        # 'es' is contained in many identities; without a substring fallback an
        # unrelated 'es'-containing service is never reached.
        index = self._index(
            {'esoteric': {'esoteric'}}, {'esoteric': {'deleteapplication': 'DeleteApplication'}}
        )
        self.assertEqual(set(), index.resolve('es', 'DeleteApplication'))

    def test_punctuation_variant_does_not_resolve(self):
        # The identity is literally 's3-control'; the hyphen is preserved, so the
        # punctuation-free prefix 's3control' is a different key and reaches no
        # service. Only the exact-punctuation prefix resolves.
        index = self._index(
            {'s3-control': {'s3control'}},
            {'s3control': {'deletebucketpolicy': 'DeleteBucketPolicy'}},
        )
        self.assertEqual(set(), index.resolve('s3control', 'DeleteBucketPolicy'))
        self.assertEqual(
            {('s3control', 'DeleteBucketPolicy')},
            index.resolve('s3-control', 'DeleteBucketPolicy'),
        )

    def test_exact_identity_resolves(self):
        index = self._index({'s3': {'s3'}}, {'s3': {'createbucket': 'CreateBucket'}})
        self.assertEqual({('s3', 'CreateBucket')}, index.resolve('s3', 'CreateBucket'))

    def test_reviewed_action_prefix_overrides_resolve(self):
        index = self._index(
            {
                'kafka': {'kafka'},
                's3control': {'s3control'},
                's3-outposts': {'s3outposts'},
            },
            {
                'kafka': {'createtopic': 'CreateTopic'},
                's3control': {'deletebucket': 'DeleteBucket'},
                's3outposts': {'createendpoint': 'CreateEndpoint'},
            },
        )
        # 'kafka-cluster' is not a botocore identity, so it resolves only through
        # the reviewed override to 'kafka'.
        self.assertEqual({('kafka', 'CreateTopic')}, index.resolve('kafka-cluster', 'CreateTopic'))
        # The literal 's3-outposts' bucket action resolves only to s3control (the
        # review); no 's3'-containing service is reached by containment.
        self.assertEqual({('s3control', 'DeleteBucket')}, index.resolve('s3-outposts', 'DeleteBucket'))
        # Where the s3outposts service itself owns the operation, its exact
        # 's3-outposts' endpoint-prefix identity resolves alongside the review.
        self.assertEqual({('s3outposts', 'CreateEndpoint')}, index.resolve('s3-outposts', 'CreateEndpoint'))

    def test_punctuation_free_override_spelling_does_not_resolve(self):
        # Override keys are literal ('s3-outposts', 'kafka-cluster'), so the
        # punctuation-free spellings that punctuation-folding once produced are
        # not keys and resolve to nothing.
        index = self._index(
            {'s3control': {'s3control'}, 'kafka': {'kafka'}},
            {'s3control': {'deletebucket': 'DeleteBucket'}, 'kafka': {'createtopic': 'CreateTopic'}},
        )
        self.assertEqual(set(), index.resolve('s3outposts', 'DeleteBucket'))
        self.assertEqual(set(), index.resolve('kafkacluster', 'CreateTopic'))

    def test_override_is_silent_when_service_lacks_operation(self):
        index = self._index({'kafka': {'kafka'}}, {'kafka': {'createcluster': 'CreateCluster'}})
        self.assertEqual(set(), index.resolve('kafka-cluster', 'CreateTopic'))


class PropertyRenameAllowlistTest(unittest.TestCase):
    """Renames are accepted only in a fully reviewed context."""

    @staticmethod
    def _mappings(member, target, cfn_type, service, operation, resource_segment='thing'):
        members = {member: Shape('string')}
        property_schemas = {target: {'type': 'string'}}
        writable_by_lower = {target.lower(): target}
        return catalog._property_mappings(
            members, property_schemas, writable_by_lower, resource_segment, {},
            cfn_type, service, operation,
        )

    def test_case_only_same_identifier_mapping_is_always_allowed(self):
        # Member and property are the same identifier differing only in case.
        result = self._mappings('bucketname', 'BucketName', 'AWS::Any::Type', 'any', 'AnyOp')
        self.assertEqual([('bucketname', 'BucketName')], result)

    def test_reviewed_rename_in_exact_context_is_accepted(self):
        result = self._mappings('Bucket', 'BucketName', 'AWS::S3::Bucket', 's3', 'CreateBucket')
        self.assertEqual([('Bucket', 'BucketName')], result)

    def test_reviewed_name_to_segment_rename_is_accepted(self):
        result = self._mappings(
            'Name', 'TopicName', 'AWS::SNS::Topic', 'sns', 'CreateTopic', resource_segment='topic'
        )
        self.assertEqual([('Name', 'TopicName')], result)

    def test_unreviewed_rename_is_rejected(self):
        # Same shape of rename, but this (cfn_type, service, operation) tuple was
        # never reviewed, so the resource-name transform must not be synthesized.
        self.assertEqual([], self._mappings('Bucket', 'BucketName', 'AWS::Other::Thing', 'other', 'CreateThing'))

    def test_reviewed_rename_rejected_when_any_context_field_changes(self):
        # Each field individually differs from the reviewed S3 bucket entry.
        self.assertEqual([], self._mappings('Bucket', 'BucketName', 'AWS::S3::AccessPoint', 's3', 'CreateBucket'))
        self.assertEqual([], self._mappings('Bucket', 'BucketName', 'AWS::S3::Bucket', 's3control', 'CreateBucket'))
        self.assertEqual([], self._mappings('Bucket', 'BucketName', 'AWS::S3::Bucket', 's3', 'PutBucket'))


class SegmentRelatednessTest(unittest.TestCase):
    """Service relatedness is exact: an alias or exact identity, never substring containment."""

    @staticmethod
    def _index(identities):
        index = catalog.BotocoreIndex.__new__(catalog.BotocoreIndex)
        index._identities = {service: set(ids) for service, ids in identities.items()}
        index._by_identity = {}
        index._operations = {}
        return index

    def test_containment_without_alias_is_unrelated(self):
        # 'mq' is a substring of segment 'amazonmq', but without an explicit alias
        # the service is unrelated: the old containment tier no longer applies.
        index = self._index({'mq': {'mq'}})
        self.assertIsNone(index.identity_tier('mq', 'mq', {'amazonmq'}))

    def test_exact_segment_name_is_strongest_tier(self):
        index = self._index({'kafka': {'kafka'}})
        self.assertEqual(0, index.identity_tier('kafka', 'kafka', {'msk', 'kafka'}))

    def test_reviewed_alias_relates_exactly(self):
        # The reviewed 'amazonmq' -> 'mq' alias makes the exact 'mq' identity relate.
        index = self._index({'mq': {'mq'}})
        aliases = {'amazonmq'}
        aliases.update(catalog.SEGMENT_ALIASES.get('amazonmq', ()))
        self.assertEqual(0, index.identity_tier('mq', 'mq', aliases))

    def test_alias_table_values_are_identity_tuples(self):
        # Every entry is a tuple of normalized identities so one segment can relate
        # to more than one service (for example cognito).
        for segment, identities in catalog.SEGMENT_ALIASES.items():
            self.assertIsInstance(identities, tuple, segment)
            self.assertTrue(all(isinstance(identity, str) for identity in identities), segment)
        self.assertIn('cognitoidp', catalog.SEGMENT_ALIASES['cognito'])
        self.assertIn('cognitoidentity', catalog.SEGMENT_ALIASES['cognito'])


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
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("integer")), tags, definitions, "Tags"
            )
        )
        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Labels"
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

    def test_tag_map_rejects_additional_required_target_field(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Value": {"type": "string"},
                    "PropagateAtLaunch": {"type": "boolean"},
                },
                "required": ["Key", "Value", "PropagateAtLaunch"],
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_rejects_additional_required_alternative_field(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {"Key": {"type": "string"}},
                "required": ["Key"],
                "any_of": [
                    {
                        "properties": {
                            "Value": {"type": "string"},
                            "PropagateAtLaunch": {"type": "boolean"},
                        },
                        "required": ["Value", "PropagateAtLaunch"],
                    }
                ],
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_accepts_unambiguous_key_value_alternative(self):
        definitions = {
            "Tag": {
                "one_of": [
                    {
                        "type": "object",
                        "properties": {
                            "Key": {"type": "string"},
                            "Value": {"type": "string"},
                        },
                        "required": ["Key", "Value"],
                        "additional_properties": False,
                    },
                    {
                        "type": "object",
                        "properties": {
                            "TagKey": {"type": "string"},
                            "TagValue": {"type": "string"},
                        },
                        "required": ["TagKey", "TagValue"],
                        "additional_properties": False,
                    },
                ]
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertTrue(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_rejects_ambiguous_key_value_alternatives(self):
        key_value_branch = {
            "type": "object",
            "properties": {
                "Key": {"type": "string"},
                "Value": {"type": "string"},
            },
            "required": ["Key", "Value"],
        }
        definitions = {
            "Tag": {"one_of": [key_value_branch, dict(key_value_branch)]}
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_rejects_permissive_one_of_sibling(self):
        definitions = {
            "Tag": {
                "one_of": [
                    {
                        "type": "object",
                        "properties": {
                            "Key": {"type": "string"},
                            "Value": {"type": "string"},
                        },
                        "required": ["Key", "Value"],
                    },
                    {"type": "object"},
                ]
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_rejects_unmodeled_object_constraint(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Value": {"type": "string"},
                    "Scope": {"type": "string"},
                },
                "required": ["Key", "Value"],
                "dependent_required": {"Key": ["Scope"]},
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_rejects_non_string_value_field(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Value": {"type": "integer"},
                },
                "required": ["Key", "Value"],
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertFalse(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
            )
        )

    def test_tag_map_accepts_optional_additional_target_field(self):
        definitions = {
            "Tag": {
                "type": "object",
                "properties": {
                    "Key": {"type": "string"},
                    "Value": {"type": "string"},
                    "Description": {"type": "string"},
                },
                "required": ["Key", "Value"],
            }
        }
        tags = {"type": "array", "items": {"ref_name": "Tag"}}

        self.assertTrue(
            catalog._is_runtime_safe_mapping(
                Shape("map", value=Shape("string")), tags, definitions, "Tags"
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

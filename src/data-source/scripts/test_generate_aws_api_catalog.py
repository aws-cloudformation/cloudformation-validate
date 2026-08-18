#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

import generate_aws_api_catalog as catalog


class Shape:
    def __init__(self, type_name, *, member=None, value=None):
        self.type_name = type_name
        self.member = member
        self.value = value


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


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import compare_cfnlint


class NormalizeEngineIdentityTests(unittest.TestCase):
    def test_resource_metadata_identity_preserves_logical_id_and_literal_slashes(self):
        resource_path = "Metadata.AWS::CloudFormation::Init.config.files./etc/cfn/cfn-hup.conf.content.Fn::Sub"

        normalized = compare_cfnlint._normalize_engine_identity("Instance", resource_path)

        self.assertEqual(("Instance", resource_path), normalized)

    def test_template_section_identity_normalizes_slash_separators(self):
        normalized = compare_cfnlint._normalize_engine_identity("", "Outputs/Endpoint/Value")

        self.assertEqual(("", "Outputs.Endpoint.Value"), normalized)


if __name__ == "__main__":
    unittest.main()

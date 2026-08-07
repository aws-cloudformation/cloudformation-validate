import unittest

from compare_cfnlint import require_matched_template_coverage


class MatchedTemplateCoverageTest(unittest.TestCase):
    def test_returns_shared_and_reference_only_templates(self):
        matched, reference_only = require_matched_template_coverage(
            {"shared": [], "reference-only": []},
            {"shared": []},
        )

        self.assertEqual(matched, ["shared"])
        self.assertEqual(reference_only, ["reference-only"])

    def test_rejects_engine_template_without_matching_result(self):
        with self.assertRaisesRegex(RuntimeError, "engine-only"):
            require_matched_template_coverage(
                {"shared": []},
                {"shared": [], "engine-only": []},
            )


if __name__ == "__main__":
    unittest.main()

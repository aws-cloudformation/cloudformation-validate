"""Detailed validation smoke tests for every security fixture."""

import multiprocessing
import os
import queue
import unittest

from cloudformation_validate import CelEngine, RegoEngine, Severity, ValidateConfig, ValidationError

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(TESTS_DIR))
SECURITY_ROOT = os.path.join(WORKSPACE, "resources", "security")
SECURITY_TIMEOUT_SECONDS = 120


def discover_security_templates():
    templates = []
    for directory, _, filenames in os.walk(SECURITY_ROOT):
        for filename in filenames:
            if filename.endswith((".json", ".yaml", ".yml")):
                templates.append(os.path.join(directory, filename))
    return sorted(templates)


def validate_security_template(engine_name, template_path, outcome_queue):
    try:
        engine = RegoEngine() if engine_name == "rego" else CelEngine()
        config = ValidateConfig(severity_level=Severity.DEBUG)
        report = engine.validate_detailed(template_path, config)
        if report.status is None or not isinstance(report.diagnostics, list):
            outcome_queue.put(("error", "detailed validation returned an incomplete report"))
            return
        outcome_queue.put(("ok", ""))
    except ValidationError as error:
        outcome_queue.put(("structured_error", str(error)))
    except BaseException as error:  # The child must communicate unexpected binding failures.
        outcome_queue.put(("error", repr(error)))


class SecurityTemplateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.templates = discover_security_templates()
        if not cls.templates:
            raise AssertionError(f"no security templates found under {SECURITY_ROOT}")
        cls.process_context = multiprocessing.get_context("spawn")

    def test_every_security_template_with_both_engines(self):
        for engine_name in ("rego", "cel"):
            for template_path in self.templates:
                relative_path = os.path.relpath(template_path, SECURITY_ROOT).replace(os.sep, "/")
                with self.subTest(engine=engine_name, template=relative_path):
                    outcome_queue = self.process_context.Queue()
                    process = self.process_context.Process(
                        target=validate_security_template,
                        args=(engine_name, template_path, outcome_queue),
                    )
                    process.start()
                    process.join(SECURITY_TIMEOUT_SECONDS)
                    if process.is_alive():
                        process.terminate()
                        process.join(5)
                        if process.is_alive():
                            process.kill()
                            process.join()
                        self.fail(
                            f"{engine_name}/{relative_path} exceeded the hard "
                            f"{SECURITY_TIMEOUT_SECONDS}-second limit"
                        )
                    try:
                        status, message = outcome_queue.get(timeout=5)
                    except queue.Empty:
                        self.fail(
                            f"{engine_name}/{relative_path} exited with status {process.exitcode} "
                            "without returning an outcome"
                        )
                    if relative_path == "deep_nesting.json" and status == "structured_error":
                        self.assertTrue(message, "deep nesting must return a structured error")
                        continue
                    self.assertEqual("ok", status, f"{engine_name}/{relative_path}: {message}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for end-to-end platform validation."""

import re
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

from oad_parser.platform_validation import (
    format_platform_validation_report,
    validate_platform,
)


class PlatformValidationTests(unittest.TestCase):
    def test_validate_platform_with_kept_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = validate_platform(output_dir=tmp, run_tests=False)
            output_dir = Path(tmp)

            self.assertTrue(report.passed)
            self.assertTrue(report.kept_output_dir)
            self.assertFalse(report.run_tests)
            self.assertIsNone(report.tests_passed)
            self.assertTrue(report.raw_golden_match)
            self.assertTrue(report.pcap_golden_match)
            self.assertEqual(report.corpus_files_with_errors, 0)
            self.assertEqual(report.corpus_mismatch_count, 0)
            self.assertTrue((output_dir / "sample.bin").exists())
            self.assertTrue((output_dir / "sample.pcap").exists())

    def test_format_platform_validation_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = validate_platform(output_dir=tmp, run_tests=False)
            text = format_platform_validation_report(report)

        self.assertIn("Parser platform validation", text)
        self.assertIn("Passed: true", text)
        self.assertIn("Raw golden match: true", text)
        self.assertIn("Pcap golden match: true", text)
        self.assertIn("Corpus mismatches: 0", text)

    def test_validate_platform_json_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = validate_platform(output_dir=tmp, run_tests=False).to_dict()

        self.assertTrue(data["passed"])
        self.assertIn("generated_files", data)
        self.assertEqual(data["corpus_mismatch_count"], 0)


class Python39CompatibilityTests(unittest.TestCase):
    def test_runtime_metadata_supports_python_392(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('python = ">=3.9.2,<4.0"', pyproject)
        self.assertIn('target-version = ["py39"]', pyproject)
        self.assertIn('py-version = "3.9"', pyproject)

    def test_no_python310_dataclass_slots(self):
        offenders = []
        for path in sorted((REPO_ROOT / "oad_parser").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if re.search(r"@dataclass\([^\n)]*slots\s*=\s*True", text):
                offenders.append(str(path.relative_to(REPO_ROOT)))

        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

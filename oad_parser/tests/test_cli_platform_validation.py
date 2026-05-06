"""CLI tests for platform validation."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_validate_platform


class PlatformValidationCliTests(unittest.TestCase):
    def test_validate_platform_cli_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(output_dir=tmp, run_tests=False, json=False)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_validate_platform(args)

            output = stdout.getvalue()
            output_dir = Path(tmp)

            self.assertEqual(rc, 0)
            self.assertIn("Parser platform validation", output)
            self.assertIn("Passed: true", output)
            self.assertTrue((output_dir / "sample.bin").exists())

    def test_validate_platform_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(output_dir=tmp, run_tests=False, json=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_validate_platform(args)

            report = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["corpus_mismatch_count"], 0)
        self.assertIn("sample.bin", report["generated_files"])


if __name__ == "__main__":
    unittest.main()

"""CLI tests for golden fixtures."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_check_golden_fixture, run_export_golden_fixture
from oad_parser.tests.test_ecg import build_ecg_payload


class GoldenCliTests(unittest.TestCase):
    def test_export_golden_fixture_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            output = Path(tmp) / "fixture.json"
            sample.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(sample),
                output=str(output),
                raw_payload=True,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_export_golden_fixture(args)

            self.assertEqual(rc, 0)
            self.assertIn("wrote golden fixture", stdout.getvalue())
            fixture = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(fixture["kind"], "raw-payload")
        self.assertEqual(fixture["summary"]["match_count"], 1)

    def test_check_golden_fixture_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            output = Path(tmp) / "fixture.json"
            sample.write_bytes(build_ecg_payload())
            export_args = argparse.Namespace(
                input=str(sample),
                output=str(output),
                raw_payload=True,
            )
            run_export_golden_fixture(export_args)

            check_args = argparse.Namespace(
                fixture=str(output),
                input=None,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_check_golden_fixture(check_args)

        self.assertEqual(rc, 0)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["match"])
        self.assertEqual(result["difference_count"], 0)


if __name__ == "__main__":
    unittest.main()

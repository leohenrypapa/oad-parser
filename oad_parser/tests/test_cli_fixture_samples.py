"""CLI tests for synthetic fixture sample generation."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_generate_fixture_samples


class FixtureSampleCliTests(unittest.TestCase):
    def test_generate_fixture_samples_cli_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(output_dir=tmp, json=False)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_generate_fixture_samples(args)

            output = stdout.getvalue()
            output_dir = Path(tmp)
            self.assertEqual(rc, 0)
            self.assertIn("generated fixture samples", output)
            self.assertTrue((output_dir / "sample.bin").exists())
            self.assertTrue((output_dir / "sample.pcap").exists())
            self.assertTrue((output_dir / "corpus-report.json").exists())

    def test_generate_fixture_samples_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(output_dir=tmp, json=True)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_generate_fixture_samples(args)

            manifest = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertIn("sample.bin", manifest["files"])
        self.assertIn("sample.pcap", manifest["files"])
        self.assertIn("sample.raw-payload.golden.json", manifest["files"])


if __name__ == "__main__":
    unittest.main()

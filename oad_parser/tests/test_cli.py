"""Unit tests for CLI helper functions."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import packet_timestamp_iso


class CliTests(unittest.TestCase):
    def test_packet_timestamp_iso_uses_utc_pcap_timestamp(self):
        self.assertEqual(packet_timestamp_iso(0, 0), "1970-01-01T00:00:00+00:00")
        self.assertEqual(packet_timestamp_iso(1, 500000), "1970-01-01T00:00:01.500000+00:00")

    def test_python_module_entrypoint_propagates_failure_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_jsonl = Path(tmp) / "bad.jsonl"
            bad_jsonl.write_text("not-json\n", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, "-m", "oad_parser", "validate", str(bad_jsonl)],
                cwd=Path(__file__).resolve().parents[2],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("line 1:", result.stdout)

    def test_top_level_help_includes_validate_platform(self):
        result = subprocess.run(
            [sys.executable, "-m", "oad_parser", "--help"],
            cwd=Path(__file__).resolve().parents[2],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("validate-platform", result.stdout)
        self.assertIn("generate-fixture-samples", result.stdout)


if __name__ == "__main__":
    unittest.main()

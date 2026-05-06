"""CLI failure-mode tests for operator-safe errors."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class CliErrorHandlingTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "oad_parser", *args],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def assert_clean_cli_error(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_inspect_empty_pcap_fails_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.pcap"
            empty.write_bytes(b"")
            result = self.run_cli("inspect-pcap", str(empty))

        self.assert_clean_cli_error(result)
        self.assertIn("pcap file is too small", result.stderr)

    def test_parse_non_pcap_fails_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            not_pcap = Path(tmp) / "not-pcap.bin"
            output = Path(tmp) / "out.jsonl"
            not_pcap.write_bytes(b"not a pcap")
            result = self.run_cli("parse-pcap", str(not_pcap), "--output", str(output))

        self.assert_clean_cli_error(result)
        self.assertIn("pcap file is too small", result.stderr)

    def test_missing_output_parent_fails_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "empty.bin"
            raw.write_bytes(b"")
            output = Path(tmp) / "missing-parent" / "out.json"
            result = self.run_cli(
                "extract-ecg-messages",
                str(raw),
                "--raw-payload",
                "--output",
                str(output),
            )

        self.assert_clean_cli_error(result)
        self.assertIn("No such file or directory", result.stderr)


if __name__ == "__main__":
    unittest.main()

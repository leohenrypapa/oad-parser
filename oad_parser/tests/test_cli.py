"""Unit tests for CLI helper functions and compatibility guards."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import packet_timestamp_iso


REPO_ROOT = Path(__file__).resolve().parents[2]


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
                cwd=REPO_ROOT,
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
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("validate-platform", result.stdout)
        self.assertIn("generate-fixture-samples", result.stdout)

    def test_top_level_help_preserves_existing_commands(self):
        result = subprocess.run(
            [sys.executable, "-m", "oad_parser", "--help"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        expected_commands = [
            "inspect-pcap",
            "parse-pcap",
            "capture",
            "live",
            "decode-cd2-words",
            "extract-ecg-messages",
            "compare-legacy-envelope",
            "validate-corpus",
            "summarize-corpus-report",
            "export-golden-fixture",
            "check-golden-fixture",
            "generate-fixture-samples",
            "validate-platform",
            "create-source-pack",
            "validate",
        ]
        for command in expected_commands:
            with self.subTest(command=command):
                self.assertIn(command, result.stdout)

    def test_existing_subcommand_help_preserves_core_commands(self):
        commands = [
            "parse-pcap",
            "capture",
            "live",
            "extract-ecg-messages",
            "validate",
            "validate-platform",
            "create-source-pack",
        ]

        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(
                    [sys.executable, "-m", "oad_parser", command, "--help"],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0)
                self.assertIn("usage:", result.stdout)

    def test_live_help_documents_smoke_max_frames(self):
        result = subprocess.run(
            [sys.executable, "-m", "oad_parser", "live", "--help"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--config", result.stdout)
        self.assertIn("--interface", result.stdout)
        self.assertIn("--max-frames", result.stdout)
        self.assertIn("test/smoke", result.stdout)

    def test_live_max_frames_zero_smoke_run_writes_audit_and_status_without_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "ecg_conf.ini"
            output_path = tmp_path / "ecg-current.json"
            audit_path = tmp_path / "ecg-audit.jsonl"
            status_path = tmp_path / "ecg-status.json"
            config_path.write_text(
                "[Outputs]\n"
                f"output_json_file = {output_path}\n"
                "[Live]\n"
                "interface = eno1\n"
                "[Audit]\n"
                f"audit_file = {audit_path}\n"
                f"status_file = {status_path}\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oad_parser",
                    "live",
                    "--config",
                    str(config_path),
                    "--interface",
                    "eno2",
                    "--max-frames",
                    "0",
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )

            combined_output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, combined_output)
            self.assertIn("reason=max_frames", result.stdout)
            self.assertIn("frames=0", result.stdout)
            self.assertIn("records=0", result.stdout)
            self.assertIn("interface=eno2", result.stdout)
            self.assertTrue(audit_path.exists())
            self.assertTrue(status_path.exists())
            self.assertFalse(output_path.exists())
            self.assertEqual(len(audit_path.read_text(encoding="utf-8").splitlines()), 2)
            self.assertIn('"record_type":"ecg_status"', status_path.read_text(encoding="utf-8"))

    def test_live_invalid_config_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "bad-live.ini"
            config_path.write_text(
                "[Options]\noutput_json = false\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oad_parser",
                    "live",
                    "--config",
                    str(config_path),
                    "--max-frames",
                    "0",
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )

            combined_output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("live JSON output", combined_output)

    def test_capture_without_max_frames_fails_before_unbounded_socket_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "capture.jsonl"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "oad_parser",
                    "capture",
                    "--interface",
                    "lo",
                    "--output",
                    str(output_path),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=10,
            )

            combined_output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("max-frames", combined_output)
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()

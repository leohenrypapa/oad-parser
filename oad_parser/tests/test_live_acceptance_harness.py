"""Tests for the synthetic 6100 PPS live acceptance harness."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "run_live_acceptance_6100pps.py"


def load_harness_module():
    spec = importlib.util.spec_from_file_location("run_live_acceptance_6100pps", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LiveAcceptanceHarnessTests(unittest.TestCase):
    def test_script_exists(self):
        self.assertTrue(SCRIPT.exists(), SCRIPT)

    def test_short_synthetic_run_writes_report_schema(self):
        harness = load_harness_module()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "acceptance.json"
            report = harness.run_acceptance(
                target_pps=100,
                duration_seconds=0.05,
                interface="synthetic0",
                output_path=str(output_path),
            )

            self.assertTrue(output_path.exists())
            from_disk = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "sprint2.synthetic_acceptance.v1")
            self.assertEqual(from_disk["schema_version"], "sprint2.synthetic_acceptance.v1")
            self.assertEqual(report["traffic_source"], "synthetic")
            self.assertEqual(report["contains_real_pcap"], False)
            self.assertEqual(report["contains_operational_payloads"], False)
            self.assertEqual(report["target_pps"], 100)
            self.assertEqual(report["frames_generated"], 5)
            self.assertEqual(report["frames_processed"], 5)
            self.assertEqual(report["records_emitted"], 5)
            self.assertEqual(report["acceptance_counters"]["packets_received"], 5)
            self.assertEqual(report["acceptance_counters"]["packets_parsed"], 5)
            self.assertEqual(report["acceptance_counters"]["output_drops"], 0)
            self.assertIn("One-hour operational acceptance", " ".join(report["limitations"]))

    def test_synthetic_run_can_report_warning_and_malformed_counts(self):
        harness = load_harness_module()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "acceptance.json"
            report = harness.run_acceptance(
                target_pps=100,
                duration_seconds=0.1,
                interface="synthetic0",
                output_path=str(output_path),
                warning_every=2,
                malformed_every=5,
            )

            counters = report["acceptance_counters"]
            self.assertEqual(report["frames_generated"], 10)
            self.assertEqual(counters["packets_received"], 10)
            self.assertEqual(counters["malformed_count"], 2)
            self.assertEqual(counters["parse_warnings_count"], 4)
            self.assertEqual(counters["error_records_emitted"], 2)
            self.assertEqual(counters["ecg_messages_emitted"], 8)

    def test_rejects_invalid_arguments(self):
        harness = load_harness_module()

        with self.assertRaises(ValueError):
            harness.run_acceptance(
                target_pps=0,
                duration_seconds=1,
                interface="synthetic0",
                output_path="/tmp/unused.json",
            )

        with self.assertRaises(ValueError):
            harness.run_acceptance(
                target_pps=100,
                duration_seconds=0,
                interface="synthetic0",
                output_path="/tmp/unused.json",
            )

        with self.assertRaises(ValueError):
            harness.run_acceptance(
                target_pps=100,
                duration_seconds=1,
                interface="synthetic0",
                output_path="/tmp/unused.json",
                malformed_every=-1,
            )

    def test_cli_main_writes_report(self):
        harness = load_harness_module()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "acceptance.json"
            rc = harness.main([
                "--target-pps",
                "100",
                "--duration-seconds",
                "0.01",
                "--output",
                str(output_path),
            ])

            self.assertEqual(rc, 0)
            self.assertTrue(output_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["target_pps"], 100)


if __name__ == "__main__":
    unittest.main()

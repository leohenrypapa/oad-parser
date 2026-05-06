"""CLI tests for legacy-vs-envelope comparison."""

import argparse
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_compare_legacy_envelope
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


def write_one_packet_pcap(path: Path, payload: bytes) -> None:
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    packet_header = struct.pack("<IIII", 1, 2, len(payload), len(payload))
    path.write_bytes(global_header + packet_header + payload)


class CompareCliTests(unittest.TestCase):
    def test_compare_raw_payload_outputs_match_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(path),
                raw_payload=True,
                jsonl=False,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_compare_legacy_envelope(args)

        self.assertEqual(rc, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result[0]["summary"]["comparison_count"], 1)
        self.assertEqual(result[0]["summary"]["match_count"], 1)
        self.assertEqual(result[0]["summary"]["mismatch_count"], 0)
        self.assertTrue(result[0]["comparisons"][0]["match"])

    def test_compare_pcap_includes_packet_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcap"
            write_one_packet_pcap(path, build_ethernet_ipv4_udp_frame(build_ecg_payload()))
            args = argparse.Namespace(
                input=str(path),
                raw_payload=False,
                jsonl=False,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_compare_legacy_envelope(args)

        self.assertEqual(rc, 0)
        result = json.loads(stdout.getvalue())
        comparison = result[0]["comparisons"][0]
        self.assertTrue(comparison["match"])
        self.assertEqual(comparison["packet_timestamp"], "1970-01-01T00:00:01.000002+00:00")

    def test_compare_writes_jsonl_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "payload.bin"
            output_path = Path(tmp) / "compare.jsonl"
            input_path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(input_path),
                raw_payload=True,
                jsonl=True,
                output=str(output_path),
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_compare_legacy_envelope(args)

            self.assertEqual(rc, 0)
            self.assertIn("wrote 1 legacy/envelope comparisons", stdout.getvalue())
            line = output_path.read_text(encoding="utf-8").splitlines()[0]
            result = json.loads(line)

        self.assertEqual(result["summary"]["match_count"], 1)


if __name__ == "__main__":
    unittest.main()

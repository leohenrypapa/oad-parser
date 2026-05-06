"""Tests for golden fixture export and checking."""

import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.golden import check_golden_fixture, export_golden_fixture, write_golden_fixture
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


def write_one_packet_pcap(path: Path, payload: bytes) -> None:
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    packet_header = struct.pack("<IIII", 1, 2, len(payload), len(payload))
    path.write_bytes(global_header + packet_header + payload)


class GoldenFixtureTests(unittest.TestCase):
    def test_export_raw_payload_golden_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(build_ecg_payload())

            fixture = export_golden_fixture(path, raw_payload=True)

        self.assertEqual(fixture["schema_version"], 1)
        self.assertEqual(fixture["kind"], "raw-payload")
        self.assertEqual(fixture["summary"]["comparison_count"], 1)
        self.assertEqual(fixture["summary"]["match_count"], 1)
        self.assertTrue(fixture["comparisons"][0]["match"])

    def test_write_and_check_raw_payload_golden_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            fixture_path = Path(tmp) / "fixture.json"
            sample.write_bytes(build_ecg_payload())

            write_golden_fixture(sample, fixture_path, raw_payload=True)
            result = check_golden_fixture(fixture_path)

        self.assertTrue(result.match)
        self.assertEqual(result.difference_count, 0)
        self.assertEqual(result.actual_summary["match_count"], 1)

    def test_check_golden_fixture_with_input_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original.bin"
            copy = Path(tmp) / "copy.bin"
            fixture_path = Path(tmp) / "fixture.json"
            original.write_bytes(build_ecg_payload())
            copy.write_bytes(build_ecg_payload())

            write_golden_fixture(original, fixture_path, raw_payload=True)
            result = check_golden_fixture(fixture_path, input_override=copy)

        self.assertTrue(result.match)
        self.assertEqual(result.input_path, str(copy))

    def test_export_pcap_golden_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcap"
            write_one_packet_pcap(path, build_ethernet_ipv4_udp_frame(build_ecg_payload()))

            fixture = export_golden_fixture(path, raw_payload=False)

        self.assertEqual(fixture["kind"], "pcap")
        self.assertEqual(fixture["summary"]["comparison_count"], 1)
        self.assertEqual(fixture["summary"]["match_count"], 1)
        self.assertTrue(fixture["comparisons"][0]["match"])
        self.assertEqual(fixture["comparisons"][0]["packet_timestamp_seconds"], 1)


if __name__ == "__main__":
    unittest.main()

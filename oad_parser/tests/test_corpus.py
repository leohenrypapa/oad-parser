"""Tests for corpus validation helpers."""

import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.corpus import validate_corpus_path
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


def write_one_packet_pcap(path: Path, payload: bytes) -> None:
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    packet_header = struct.pack("<IIII", 1, 2, len(payload), len(payload))
    path.write_bytes(global_header + packet_header + payload)


class CorpusValidationTests(unittest.TestCase):
    def test_validate_single_raw_payload_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(build_ecg_payload())

            report = validate_corpus_path(path)

        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.files_with_errors, 0)
        self.assertEqual(report.comparison_count, 1)
        self.assertEqual(report.match_count, 1)
        self.assertEqual(report.mismatch_count, 0)
        self.assertEqual(report.zero_comparison_file_count, 0)
        self.assertEqual(report.files[0].kind, "raw-payload")

    def test_validate_single_pcap_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcap"
            write_one_packet_pcap(path, build_ethernet_ipv4_udp_frame(build_ecg_payload()))

            report = validate_corpus_path(path)

        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.files_with_errors, 0)
        self.assertEqual(report.comparison_count, 1)
        self.assertEqual(report.match_count, 1)
        self.assertEqual(report.mismatch_count, 0)
        self.assertEqual(report.zero_comparison_file_count, 0)
        self.assertEqual(report.files[0].kind, "pcap")

    def test_validate_directory_skips_unsupported_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.bin").write_bytes(build_ecg_payload())
            write_one_packet_pcap(
                root / "sample.pcap",
                build_ethernet_ipv4_udp_frame(build_ecg_payload()),
            )
            (root / "notes.txt").write_text("ignore me", encoding="utf-8")

            report = validate_corpus_path(root)

        self.assertEqual(report.files_scanned, 2)
        self.assertEqual(report.files_with_errors, 0)
        self.assertEqual(report.comparison_count, 2)
        self.assertEqual(report.match_count, 2)
        self.assertEqual(report.mismatch_count, 0)
        self.assertEqual(report.zero_comparison_file_count, 0)

    def test_validate_corpus_reports_zero_comparison_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.bin"
            path.write_bytes(b"")

            report = validate_corpus_path(path)

        self.assertEqual(report.files_scanned, 1)
        self.assertEqual(report.files_with_errors, 0)
        self.assertEqual(report.comparison_count, 0)
        self.assertEqual(report.zero_comparison_file_count, 1)
        self.assertEqual(report.files[0].comparison_count, 0)


if __name__ == "__main__":
    unittest.main()

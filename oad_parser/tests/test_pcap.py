"""Unit tests for the standard-library pcap reader."""

import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import packet_timestamp_iso
from oad_parser.errors import ParseError
from oad_parser.ingest.pcap import iter_pcap_packets


class PcapTests(unittest.TestCase):
    @staticmethod
    def _write_pcap(path: Path, magic: bytes, timestamp_fraction: int, payload: bytes) -> None:
        endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
        global_header = magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, 65535, 1)
        packet_header = struct.pack(f"{endian}IIII", 1, timestamp_fraction, len(payload), len(payload))
        path.write_bytes(global_header + packet_header + payload)

    def test_iter_pcap_packets_reads_one_packet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.pcap"
            payload = b"abc"
            self._write_pcap(path, b"\xd4\xc3\xb2\xa1", 2, payload)

            packets = list(iter_pcap_packets(path))

            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0].timestamp_seconds, 1)
            self.assertEqual(packets[0].timestamp_fraction, 2)
            self.assertEqual(packets[0].data, payload)
            self.assertEqual(packets[0].timestamp_fraction_resolution, 1_000_000)

    def test_iter_pcap_packets_tracks_nanosecond_resolution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample-ns.pcap"
            self._write_pcap(path, b"\x4d\x3c\xb2\xa1", 500_000_000, b"abc")

            packets = list(iter_pcap_packets(path))

            self.assertEqual(packets[0].timestamp_fraction_resolution, 1_000_000_000)
            self.assertEqual(
                packet_timestamp_iso(
                    packets[0].timestamp_seconds,
                    packets[0].timestamp_fraction,
                    packets[0].timestamp_fraction_resolution,
                ),
                "1970-01-01T00:00:01.500000+00:00",
            )

    def test_iter_pcap_packets_rejects_trailing_partial_packet_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "truncated.pcap"
            global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
            path.write_bytes(global_header + b"partial")

            with self.assertRaisesRegex(ParseError, "trailing partial packet header"):
                list(iter_pcap_packets(path))

    def test_iter_pcap_packets_rejects_captured_length_larger_than_original(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad-length.pcap"
            global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
            packet_header = struct.pack("<IIII", 1, 0, 4, 3)
            path.write_bytes(global_header + packet_header + b"abcd")

            with self.assertRaisesRegex(ParseError, "captured packet length exceeds original"):
                list(iter_pcap_packets(path))


if __name__ == "__main__":
    unittest.main()

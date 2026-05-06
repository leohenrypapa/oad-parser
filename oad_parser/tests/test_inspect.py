"""Unit tests for pcap inspection helpers."""

import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.inspect import inspect_pcap
from oad_parser.tests.test_ecg import build_ecg_payload
from oad_parser.tests.test_ethernet import build_ethernet_ipv4_udp_frame


class InspectTests(unittest.TestCase):
    def test_inspect_pcap_counts_candidate_ecg_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.pcap"
            frame = build_ethernet_ipv4_udp_frame(build_ecg_payload())
            global_header = (
                b"\xd4\xc3\xb2\xa1"
                + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
            )
            packet_header = struct.pack("<IIII", 1, 2, len(frame), len(frame))
            path.write_bytes(global_header + packet_header + frame)

            result = inspect_pcap(path)

            self.assertEqual(result.packets, 1)
            self.assertEqual(result.ipv4_udp_packets, 1)
            self.assertEqual(result.candidate_ecg_payloads, 1)
            self.assertEqual(result.parsed_records, 1)
            self.assertEqual(result.first_candidate_offsets, [1])


if __name__ == "__main__":
    unittest.main()

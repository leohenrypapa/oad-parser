"""Unit tests for runtime frame-stream helpers."""

import tempfile
import unittest
from pathlib import Path

from oad_parser.output import validate_jsonl
from oad_parser.runtime import parse_frame_stream, write_frame_stream_jsonl
from oad_parser.tests.test_ecg import build_ethernet_ipv4_udp_frame, build_ecg_payload


class RuntimeTests(unittest.TestCase):
    def test_parse_frame_stream(self):
        frame = build_ethernet_ipv4_udp_frame(build_ecg_payload())

        records = parse_frame_stream([frame], observer_interface="eth0", detect=True)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].observer_interface, "eth0")
        self.assertEqual(records[0].message, "cd-2")

    def test_write_frame_stream_jsonl(self):
        frame = build_ethernet_ipv4_udp_frame(build_ecg_payload())

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "out.jsonl"
            count = write_frame_stream_jsonl([frame], output, observer_interface="eth0", detect=True)

            self.assertEqual(count, 1)

            validated_count, errors = validate_jsonl(output)
            self.assertEqual(validated_count, 1)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

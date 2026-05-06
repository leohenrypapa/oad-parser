"""Unit tests for ECG parser extraction behavior."""

import struct
import unittest

from oad_parser.parsers.ecg import parse_frame


def build_ecg_payload() -> bytes:
    words = bytearray(14)
    words[0] = 0x06
    words[1] = 0x40
    words[2:4] = (160).to_bytes(2, "big")
    words[4:6] = (1024).to_bytes(2, "big")
    words[8:10] = (0o1234).to_bytes(2, "big")
    words[12:14] = (30).to_bytes(2, "big")

    message_data_length = len(words)
    ecg_payload_length = 16 + message_data_length

    ecg_header = bytearray(16)
    ecg_header[0:2] = ecg_payload_length.to_bytes(2, "big")
    ecg_header[4:7] = b"ZAB"
    ecg_header[8] = 1
    ecg_header[12:16] = (123400).to_bytes(4, "big")

    message_header = bytearray(16)
    message_header[0:2] = message_data_length.to_bytes(2, "big")
    message_header[4:8] = b"ST1\x00"
    message_header[8] = 1
    message_header[9] = 7
    message_header[10] = 0x20
    message_header[12:16] = (5678000).to_bytes(4, "big")

    return bytes(ecg_header + message_header + words)


def build_ethernet_ipv4_udp_frame(payload: bytes) -> bytes:
    ethernet = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00"

    total_length = 20 + 8 + len(payload)
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = total_length.to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = 17
    ipv4[12:16] = bytes([10, 1, 2, 3])
    ipv4[16:20] = bytes([10, 4, 5, 6])

    udp = struct.pack("!HHHH", 1000, 2000, 8 + len(payload), 0)

    return ethernet + bytes(ipv4) + udp + payload


class EcgParserTests(unittest.TestCase):
    def test_parse_raw_ecg_payload(self):
        records = parse_frame(build_ecg_payload(), skip_headers=False, timestamp="fixture-time")

        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertEqual(record.timestamp, "fixture-time")
        self.assertEqual(record.artcc, "ZAB")
        self.assertEqual(record.site_id, "ST1")
        self.assertEqual(record.message, "cd-2")
        self.assertEqual(record.message_type, "beacon")
        self.assertEqual(record.sequence, 7)
        self.assertEqual(record.channel, 2)
        self.assertEqual(record.router_timestamp, 12.34)
        self.assertEqual(record.radar_timestamp, 5.678)
        self.assertEqual(record.range_nm, 10.0)
        self.assertEqual(record.acp, 1024)
        self.assertEqual(record.azimuth_degrees, 90.0)
        self.assertEqual(record.mode_3_code, 1234)
        self.assertEqual(record.altitude_feet, 3000)
        self.assertIsNotNone(record.fingerprint)

    def test_parse_ethernet_ipv4_udp_ecg_payload(self):
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)

        records = parse_frame(frame, observer_interface="eth0")

        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertEqual(record.source_ip, "10.1.2.3")
        self.assertEqual(record.destination_ip, "10.4.5.6")
        self.assertEqual(record.source_port, 1000)
        self.assertEqual(record.destination_port, 2000)
        self.assertEqual(record.observer_interface, "eth0")
        self.assertEqual(record.total_bytes, len(frame))

    def test_non_udp_frame_returns_no_records(self):
        self.assertEqual(parse_frame(b"not an ecg frame"), [])


if __name__ == "__main__":
    unittest.main()

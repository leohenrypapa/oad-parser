"""Unit tests for Ethernet, IPv4, and UDP parsing."""

import struct
import unittest
from typing import Optional

from oad_parser.ingest.ethernet import parse_ipv4_udp_frame


BYTE_ORDER = "big"
ETHERNET_DESTINATION_MAC = b"\xaa\xbb\xcc\xdd\xee\xff"
ETHERNET_SOURCE_MAC = b"\x11\x22\x33\x44\x55\x66"
ETHERTYPE_IPV4 = b"\x08\x00"
IPV4_HEADER_BYTES = 20
UDP_HEADER_BYTES = 8
IPV4_VERSION_IHL = 0x45
IPV4_TTL = 64
IPV4_PROTOCOL_UDP = 17
SOURCE_IP = bytes([10, 1, 2, 3])
DESTINATION_IP = bytes([10, 4, 5, 6])
SOURCE_PORT = 1000
DESTINATION_PORT = 2000


def build_ethernet_ipv4_udp_frame(
    payload: bytes,
    *,
    ip_total_length: Optional[int] = None,
    udp_length: Optional[int] = None,
    protocol: int = IPV4_PROTOCOL_UDP,
) -> bytes:
    ethernet = ETHERNET_DESTINATION_MAC + ETHERNET_SOURCE_MAC + ETHERTYPE_IPV4

    resolved_udp_length = udp_length if udp_length is not None else UDP_HEADER_BYTES + len(payload)
    resolved_ip_total_length = (
        ip_total_length
        if ip_total_length is not None
        else IPV4_HEADER_BYTES + resolved_udp_length
    )

    ipv4 = bytearray(IPV4_HEADER_BYTES)
    ipv4[0] = IPV4_VERSION_IHL
    ipv4[2:4] = resolved_ip_total_length.to_bytes(2, BYTE_ORDER)
    ipv4[8] = IPV4_TTL
    ipv4[9] = protocol
    ipv4[12:16] = SOURCE_IP
    ipv4[16:20] = DESTINATION_IP

    udp = struct.pack("!HHHH", SOURCE_PORT, DESTINATION_PORT, resolved_udp_length, 0)

    return ethernet + bytes(ipv4) + udp + payload


class EthernetTests(unittest.TestCase):
    def test_parse_ipv4_udp_frame(self):
        payload = b"payload"
        frame = build_ethernet_ipv4_udp_frame(payload)

        parsed = parse_ipv4_udp_frame(frame)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.source_ip, "10.1.2.3")
        self.assertEqual(parsed.destination_ip, "10.4.5.6")
        self.assertEqual(parsed.source_port, SOURCE_PORT)
        self.assertEqual(parsed.destination_port, DESTINATION_PORT)
        self.assertEqual(parsed.total_length, IPV4_HEADER_BYTES + UDP_HEADER_BYTES + len(payload))

    def test_non_ipv4_udp_returns_none(self):
        self.assertIsNone(parse_ipv4_udp_frame(b"too short"))

    def test_rejects_ip_total_length_shorter_than_header(self):
        frame = build_ethernet_ipv4_udp_frame(b"payload", ip_total_length=IPV4_HEADER_BYTES - 1)

        self.assertIsNone(parse_ipv4_udp_frame(frame))

    def test_rejects_ip_total_length_larger_than_frame(self):
        frame = build_ethernet_ipv4_udp_frame(b"payload", ip_total_length=999)

        self.assertIsNone(parse_ipv4_udp_frame(frame))

    def test_rejects_udp_length_shorter_than_header(self):
        frame = build_ethernet_ipv4_udp_frame(b"payload", udp_length=UDP_HEADER_BYTES - 1)

        self.assertIsNone(parse_ipv4_udp_frame(frame))

    def test_rejects_udp_length_larger_than_ip_packet(self):
        frame = build_ethernet_ipv4_udp_frame(b"payload", udp_length=999)

        self.assertIsNone(parse_ipv4_udp_frame(frame))

    def test_ignores_ethernet_padding_after_ip_packet(self):
        payload = b"payload"
        frame = build_ethernet_ipv4_udp_frame(payload) + b"padding"

        parsed = parse_ipv4_udp_frame(frame)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.payload, payload)


if __name__ == "__main__":
    unittest.main()

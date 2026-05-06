"""Ethernet, IPv4, and UDP frame parsing.

The parser only needs UDP payloads. This module extracts network metadata and
payload bytes without requiring third-party packet libraries.
"""

from __future__ import annotations

from dataclasses import dataclass


# Ethernet, IPv4, and UDP fields are encoded in network byte order.
BYTE_ORDER = "big"

# Ethernet II header layout.
ETHERNET_HEADER_BYTES = 14
ETHERTYPE_OFFSET_START = 12
ETHERTYPE_OFFSET_END = 14
ETHERTYPE_IPV4 = 0x0800

# IPv4 header layout and UDP protocol selection.
IP_VERSION_SHIFT = 4
IP_IHL_MASK = 0x0F
IP_IHL_WORD_BYTES = 4
IPV4_VERSION = 4
MIN_IPV4_HEADER_BYTES = 20
IPV4_TOTAL_LENGTH_OFFSET_START = 2
IPV4_TOTAL_LENGTH_OFFSET_END = 4
IP_PROTOCOL_OFFSET = 9
IP_PROTOCOL_UDP = 17
IP_SOURCE_OFFSET_START = 12
IP_SOURCE_OFFSET_END = 16
IP_DESTINATION_OFFSET_START = 16
IP_DESTINATION_OFFSET_END = 20

# UDP header layout.
UDP_HEADER_BYTES = 8
UDP_SOURCE_PORT_OFFSET_START = 0
UDP_SOURCE_PORT_OFFSET_END = 2
UDP_DESTINATION_PORT_OFFSET_START = 2
UDP_DESTINATION_PORT_OFFSET_END = 4
UDP_LENGTH_OFFSET_START = 4
UDP_LENGTH_OFFSET_END = 6

# Minimum Ethernet + IPv4 + UDP frame size used as a structural guard.
MIN_IPV4_UDP_FRAME_BYTES = (
    ETHERNET_HEADER_BYTES + MIN_IPV4_HEADER_BYTES + UDP_HEADER_BYTES
)


@dataclass
class UdpFrame:
    payload: bytes
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    total_length: int


def parse_ipv4_udp_frame(frame: bytes) -> UdpFrame | None:
    if len(frame) < MIN_IPV4_UDP_FRAME_BYTES:
        return None

    ethertype = int.from_bytes(
        frame[ETHERTYPE_OFFSET_START:ETHERTYPE_OFFSET_END], BYTE_ORDER
    )
    if ethertype != ETHERTYPE_IPV4:
        return None

    ip_start = ETHERNET_HEADER_BYTES
    version = frame[ip_start] >> IP_VERSION_SHIFT
    header_length = (frame[ip_start] & IP_IHL_MASK) * IP_IHL_WORD_BYTES

    if version != IPV4_VERSION or header_length < MIN_IPV4_HEADER_BYTES:
        return None

    if len(frame) < ip_start + header_length:
        return None

    ip_total_length = int.from_bytes(
        frame[
            ip_start + IPV4_TOTAL_LENGTH_OFFSET_START : ip_start + IPV4_TOTAL_LENGTH_OFFSET_END
        ],
        BYTE_ORDER,
    )
    if ip_total_length < header_length:
        return None

    ip_packet_end = ip_start + ip_total_length
    if ip_packet_end > len(frame):
        return None

    protocol = frame[ip_start + IP_PROTOCOL_OFFSET]
    if protocol != IP_PROTOCOL_UDP:
        return None

    udp_start = ip_start + header_length
    if udp_start + UDP_HEADER_BYTES > ip_packet_end:
        return None

    source_ip = format_ipv4(
        frame[ip_start + IP_SOURCE_OFFSET_START : ip_start + IP_SOURCE_OFFSET_END]
    )
    destination_ip = format_ipv4(
        frame[
            ip_start + IP_DESTINATION_OFFSET_START : ip_start + IP_DESTINATION_OFFSET_END
        ]
    )
    source_port = int.from_bytes(
        frame[
            udp_start + UDP_SOURCE_PORT_OFFSET_START : udp_start + UDP_SOURCE_PORT_OFFSET_END
        ],
        BYTE_ORDER,
    )
    destination_port = int.from_bytes(
        frame[
            udp_start
            + UDP_DESTINATION_PORT_OFFSET_START : udp_start
            + UDP_DESTINATION_PORT_OFFSET_END
        ],
        BYTE_ORDER,
    )
    udp_length = int.from_bytes(
        frame[udp_start + UDP_LENGTH_OFFSET_START : udp_start + UDP_LENGTH_OFFSET_END],
        BYTE_ORDER,
    )

    if udp_length < UDP_HEADER_BYTES:
        return None

    udp_end = udp_start + udp_length
    if udp_end > ip_packet_end:
        return None

    payload_start = udp_start + UDP_HEADER_BYTES
    payload = frame[payload_start:udp_end]

    return UdpFrame(
        payload=payload,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        total_length=ip_total_length,
    )


def format_ipv4(value: bytes) -> str:
    return ".".join(str(part) for part in value)

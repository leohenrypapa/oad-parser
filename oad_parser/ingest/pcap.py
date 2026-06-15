"""Minimal standard-library PCAP reader.

This reader supports classic pcap files and avoids adding packet dependencies
to the parser core. It yields raw frame bytes for parser replay.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from oad_parser.errors import ParseError


PCAP_MICROSECOND_RESOLUTION = 1_000_000
PCAP_NANOSECOND_RESOLUTION = 1_000_000_000


@dataclass
class PcapPacket:
    timestamp_seconds: int
    timestamp_fraction: int
    data: bytes
    timestamp_fraction_resolution: int = PCAP_MICROSECOND_RESOLUTION


# Classic PCAP file and packet header layout.
PCAP_GLOBAL_HEADER_BYTES = 24
PCAP_PACKET_HEADER_BYTES = 16
PCAP_MAGIC_BYTES = 4
PCAP_PACKET_HEADER_STRUCT = "IIII"


# Supported PCAP magic values and associated byte order plus timestamp resolution.
PCAP_MAGIC_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", PCAP_MICROSECOND_RESOLUTION),
    b"\xa1\xb2\xc3\xd4": (">", PCAP_MICROSECOND_RESOLUTION),
    b"\x4d\x3c\xb2\xa1": ("<", PCAP_NANOSECOND_RESOLUTION),
    b"\xa1\xb2\x3c\x4d": (">", PCAP_NANOSECOND_RESOLUTION),
}


def iter_pcap_packets(path: str | Path) -> Iterator[PcapPacket]:
    with Path(path).open("rb") as handle:
        global_header = handle.read(PCAP_GLOBAL_HEADER_BYTES)
        if len(global_header) < PCAP_GLOBAL_HEADER_BYTES:
            raise ParseError("pcap file is too small to contain a global header")

        magic = global_header[:PCAP_MAGIC_BYTES]
        pcap_format = PCAP_MAGIC_FORMATS.get(magic)
        if pcap_format is None:
            raise ParseError("unsupported pcap magic header")
        endian, timestamp_fraction_resolution = pcap_format

        while True:
            packet_header = handle.read(PCAP_PACKET_HEADER_BYTES)
            if packet_header == b"":
                break
            if len(packet_header) < PCAP_PACKET_HEADER_BYTES:
                raise ParseError("pcap contains trailing partial packet header")

            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                f"{endian}{PCAP_PACKET_HEADER_STRUCT}",
                packet_header,
            )

            if incl_len > orig_len:
                raise ParseError("pcap captured packet length exceeds original packet length")

            packet_data = handle.read(incl_len)
            if len(packet_data) < incl_len:
                raise ParseError("pcap packet length exceeds file size")

            yield PcapPacket(
                timestamp_seconds=ts_sec,
                timestamp_fraction=ts_frac,
                data=packet_data,
                timestamp_fraction_resolution=timestamp_fraction_resolution,
            )

"""PCAP inspection helpers.

The inspection path is intentionally standard-library only. It helps operators
confirm whether a pcap contains candidate ECG/CD2 traffic before parsing.
"""

from __future__ import annotations

DEFAULT_TOP_COUNT_LIMIT = 20
MIN_HEX_PREVIEW_BYTES = 25

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from oad_parser.ingest.ethernet import parse_ipv4_udp_frame
from oad_parser.ingest.pcap import iter_pcap_packets
from oad_parser.parsers.ecg import looks_like_ecg_payload, parse_frame


@dataclass
class PcapInspection:
    path: str
    packets: int = 0
    ipv4_udp_packets: int = 0
    candidate_ecg_payloads: int = 0
    parsed_records: int = 0
    udp_pairs: Counter[str] = field(default_factory=Counter)
    payload_lengths: Counter[int] = field(default_factory=Counter)
    first_candidate_offsets: list[int] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            f"path: {self.path}",
            f"packets: {self.packets}",
            f"ipv4_udp_packets: {self.ipv4_udp_packets}",
            f"candidate_ecg_payloads: {self.candidate_ecg_payloads}",
            f"parsed_records: {self.parsed_records}",
            "",
            "top_udp_pairs:",
        ]

        for pair, count in self.udp_pairs.most_common(DEFAULT_TOP_COUNT_LIMIT):
            lines.append(f"  {count:>8}  {pair}")

        lines.append("")
        lines.append("top_payload_lengths:")
        for length, count in self.payload_lengths.most_common(DEFAULT_TOP_COUNT_LIMIT):
            lines.append(f"  {count:>8}  {length}")

        lines.append("")
        lines.append("first_candidate_packet_numbers:")
        if self.first_candidate_offsets:
            for packet_number in self.first_candidate_offsets:
                lines.append(f"  {packet_number}")
        else:
            lines.append("  none")

        return "\n".join(lines)


def inspect_pcap(path: str | Path) -> PcapInspection:
    inspection = PcapInspection(path=str(path))

    for packet_number, packet in enumerate(iter_pcap_packets(path), start=1):
        inspection.packets += 1
        udp_frame = parse_ipv4_udp_frame(packet.data)
        if udp_frame is None:
            continue

        inspection.ipv4_udp_packets += 1

        pair = (
            f"{udp_frame.source_ip}:{udp_frame.source_port}"
            f" -> {udp_frame.destination_ip}:{udp_frame.destination_port}"
        )
        inspection.udp_pairs[pair] += 1
        inspection.payload_lengths[len(udp_frame.payload)] += 1

        if looks_like_ecg_payload(udp_frame.payload):
            inspection.candidate_ecg_payloads += 1
            if len(inspection.first_candidate_offsets) < MIN_HEX_PREVIEW_BYTES:
                inspection.first_candidate_offsets.append(packet_number)

        inspection.parsed_records += len(parse_frame(packet.data))

    return inspection

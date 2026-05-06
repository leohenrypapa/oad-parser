"""Synthetic fixture sample generation.

Generated samples are non-sensitive and deterministic. They are intended for
developer onboarding, CI smoke checks, and AI handoff without requiring real or
sanitized operational captures.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

from oad_parser.corpus import validate_corpus_path
from oad_parser.corpus_report import summarize_corpus_report
from oad_parser.golden import write_golden_fixture


BYTE_ORDER = "big"
UINT32_BYTES = 4
IPV4_CHECKSUM_PAD_BYTE = b"\x00"
IPV4_CHECKSUM_FOLD_SHIFT = 16
IPV4_CHECKSUM_WORD_MASK = 0xFFFF
EMPTY_BYTES = b""

SAMPLE_RAW_PAYLOAD_FILENAME = "sample.bin"
SAMPLE_PCAP_FILENAME = "sample.pcap"
SAMPLE_RAW_GOLDEN_FILENAME = "sample.raw-payload.golden.json"
SAMPLE_PCAP_GOLDEN_FILENAME = "sample.pcap.golden.json"
SAMPLE_CORPUS_REPORT_FILENAME = "corpus-report.json"
SAMPLE_CORPUS_SUMMARY_FILENAME = "corpus-summary.txt"
SAMPLE_README_FILENAME = "README.md"

ECG_HEADER_BYTES = 16
ECG_MESSAGE_HEADER_BYTES = 16

ECG_PAYLOAD_LENGTH_SLICE = slice(0, 2)
ECG_SITE_ID_SLICE = slice(4, 7)
ECG_SITE_ID = b"ZAB"
ECG_RECORD_TYPE_OFFSET = 8
ECG_RECORD_TYPE = 1
ECG_TIMESTAMP_SLICE = slice(12, 16)

MESSAGE_PAYLOAD_LENGTH_SLICE = slice(0, 2)
MESSAGE_STATION_ID_SLICE = slice(4, 8)
MESSAGE_STATION_ID = b"ST1\x00"
MESSAGE_SENSOR_TYPE_OFFSET = 8
MESSAGE_SENSOR_TYPE = 1
MESSAGE_MESSAGE_TYPE_OFFSET = 9
MESSAGE_MESSAGE_TYPE = 7
MESSAGE_FLAGS_OFFSET = 10
MESSAGE_FLAGS = 0x20
MESSAGE_TIMESTAMP_SLICE = slice(12, 16)

SYNTHETIC_MESSAGE_TIMESTAMP_MICROSECONDS = 5_678_000
SYNTHETIC_ECG_TIMESTAMP_100_MICROSECOND_TICKS = 123_400

SYNTHETIC_DATA_WORDS = (
    1600,
    160,
    1024,
    0,
    0o1234,
    0,
    30,
)

ETHERNET_DESTINATION_MAC = b"\xaa\xbb\xcc\xdd\xee\xff"
ETHERNET_SOURCE_MAC = b"\x11\x22\x33\x44\x55\x66"
ETHERNET_TYPE_IPV4 = b"\x08\x00"

IPV4_VERSION_IHL = b"\x45"
IPV4_DSCP_ECN = b"\x00"
IPV4_IDENTIFICATION = b"\x00\x01"
IPV4_FLAGS_FRAGMENT_OFFSET = b"\x00\x00"
IPV4_TTL = b"\x40"
IPV4_PROTOCOL_UDP = b"\x11"
IPV4_EMPTY_CHECKSUM = b"\x00\x00"
IPV4_HEADER_BYTES = 20
IPV4_CHECKSUM_SLICE = slice(10, 12)
IPV4_AFTER_CHECKSUM_OFFSET = 12
IPV4_SOURCE_ADDRESS = bytes([10, 1, 2, 3])
IPV4_DESTINATION_ADDRESS = bytes([10, 4, 5, 6])

UDP_HEADER_BYTES = 8
UDP_SOURCE_PORT = 1000
UDP_DESTINATION_PORT = 2000
UDP_EMPTY_CHECKSUM = b"\x00\x00"

PCAP_MAGIC_LITTLE_ENDIAN_MICROSECOND = b"\xd4\xc3\xb2\xa1"
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS = 0
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1
PCAP_SAMPLE_TIMESTAMP_SECONDS = 1
PCAP_SAMPLE_TIMESTAMP_MICROSECONDS = 2


@dataclass(frozen=True)
class FixtureSampleResult:
    output_dir: str
    files: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "output_dir": self.output_dir,
            "files": list(self.files),
        }


def generate_fixture_samples(output_dir: str | Path) -> FixtureSampleResult:
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    raw_payload_path = output_root / SAMPLE_RAW_PAYLOAD_FILENAME
    pcap_path = output_root / SAMPLE_PCAP_FILENAME
    raw_golden_path = output_root / SAMPLE_RAW_GOLDEN_FILENAME
    pcap_golden_path = output_root / SAMPLE_PCAP_GOLDEN_FILENAME
    corpus_report_path = output_root / SAMPLE_CORPUS_REPORT_FILENAME
    corpus_summary_path = output_root / SAMPLE_CORPUS_SUMMARY_FILENAME
    readme_path = output_root / SAMPLE_README_FILENAME

    raw_payload = build_synthetic_ecg_payload()
    raw_payload_path.write_bytes(raw_payload)

    pcap_frame = build_synthetic_ethernet_ipv4_udp_frame(raw_payload)
    write_single_packet_pcap(pcap_path, pcap_frame)

    write_golden_fixture(raw_payload_path, raw_golden_path, raw_payload=True)
    write_golden_fixture(pcap_path, pcap_golden_path, raw_payload=False)

    report = validate_corpus_path(output_root)
    corpus_report_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    corpus_summary_path.write_text(
        summarize_corpus_report(report.to_dict(), show_matches=True),
        encoding="utf-8",
    )
    readme_path.write_text(sample_readme(), encoding="utf-8")

    files = tuple(
        str(path.relative_to(output_root))
        for path in sorted(output_root.iterdir())
        if path.is_file()
    )
    return FixtureSampleResult(output_dir=str(output_root), files=files)


def uint16(value: int) -> bytes:
    return value.to_bytes(2, BYTE_ORDER)


def uint32(value: int) -> bytes:
    return value.to_bytes(UINT32_BYTES, BYTE_ORDER)


def build_synthetic_ecg_payload() -> bytes:
    message_payload = EMPTY_BYTES.join(uint16(word) for word in SYNTHETIC_DATA_WORDS)

    message_header = bytearray(ECG_MESSAGE_HEADER_BYTES)
    message_header[MESSAGE_PAYLOAD_LENGTH_SLICE] = uint16(len(message_payload))
    message_header[MESSAGE_STATION_ID_SLICE] = MESSAGE_STATION_ID
    message_header[MESSAGE_SENSOR_TYPE_OFFSET] = MESSAGE_SENSOR_TYPE
    message_header[MESSAGE_MESSAGE_TYPE_OFFSET] = MESSAGE_MESSAGE_TYPE
    message_header[MESSAGE_FLAGS_OFFSET] = MESSAGE_FLAGS
    message_header[MESSAGE_TIMESTAMP_SLICE] = uint32(SYNTHETIC_MESSAGE_TIMESTAMP_MICROSECONDS)

    message = bytes(message_header) + message_payload

    ecg_header = bytearray(ECG_HEADER_BYTES)
    ecg_header[ECG_PAYLOAD_LENGTH_SLICE] = uint16(len(message))
    ecg_header[ECG_SITE_ID_SLICE] = ECG_SITE_ID
    ecg_header[ECG_RECORD_TYPE_OFFSET] = ECG_RECORD_TYPE
    ecg_header[ECG_TIMESTAMP_SLICE] = uint32(SYNTHETIC_ECG_TIMESTAMP_100_MICROSECOND_TICKS)

    return bytes(ecg_header) + message


def build_synthetic_ethernet_ipv4_udp_frame(payload: bytes) -> bytes:
    ethernet = ETHERNET_DESTINATION_MAC + ETHERNET_SOURCE_MAC + ETHERNET_TYPE_IPV4

    udp_length = UDP_HEADER_BYTES + len(payload)
    total_length = IPV4_HEADER_BYTES + udp_length

    ipv4_without_checksum = (
        IPV4_VERSION_IHL
        + IPV4_DSCP_ECN
        + uint16(total_length)
        + IPV4_IDENTIFICATION
        + IPV4_FLAGS_FRAGMENT_OFFSET
        + IPV4_TTL
        + IPV4_PROTOCOL_UDP
        + IPV4_EMPTY_CHECKSUM
        + IPV4_SOURCE_ADDRESS
        + IPV4_DESTINATION_ADDRESS
    )
    checksum = ipv4_header_checksum(ipv4_without_checksum)
    ipv4 = (
        ipv4_without_checksum[: IPV4_CHECKSUM_SLICE.start]
        + uint16(checksum)
        + ipv4_without_checksum[IPV4_AFTER_CHECKSUM_OFFSET:]
    )

    udp = (
        uint16(UDP_SOURCE_PORT)
        + uint16(UDP_DESTINATION_PORT)
        + uint16(udp_length)
        + UDP_EMPTY_CHECKSUM
    )

    return ethernet + ipv4 + udp + payload


def ipv4_header_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += IPV4_CHECKSUM_PAD_BYTE

    total = 0
    for index in range(0, len(header), 2):
        total += int.from_bytes(header[index : index + 2], BYTE_ORDER)
        total = (total & IPV4_CHECKSUM_WORD_MASK) + (total >> IPV4_CHECKSUM_FOLD_SHIFT)

    return (~total) & IPV4_CHECKSUM_WORD_MASK


def write_single_packet_pcap(path: Path, frame: bytes) -> None:
    global_header = PCAP_MAGIC_LITTLE_ENDIAN_MICROSECOND + struct.pack(
        "<HHIIII",
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        PCAP_THISZONE,
        PCAP_SIGFIGS,
        PCAP_SNAPLEN,
        PCAP_LINKTYPE_ETHERNET,
    )
    packet_header = struct.pack(
        "<IIII",
        PCAP_SAMPLE_TIMESTAMP_SECONDS,
        PCAP_SAMPLE_TIMESTAMP_MICROSECONDS,
        len(frame),
        len(frame),
    )
    path.write_bytes(global_header + packet_header + frame)


def sample_readme() -> str:
    return """# Synthetic parser fixture samples

These files are generated by:

    python3 -m oad_parser generate-fixture-samples --output-dir samples/fixtures

Files:

- sample.bin - raw synthetic ECG payload
- sample.pcap - synthetic Ethernet/IPv4/UDP/ECG pcap
- sample.raw-payload.golden.json - golden fixture for sample.bin
- sample.pcap.golden.json - golden fixture for sample.pcap
- corpus-report.json - validate-corpus report over the generated samples
- corpus-summary.txt - compact report summary

These samples are deterministic and non-sensitive. They are for parser regression testing and developer handoff only.
"""

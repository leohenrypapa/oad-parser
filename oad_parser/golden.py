"""Golden fixture export and verification.

Golden fixtures capture expected legacy-vs-envelope comparison output so parser
behavior can be checked for drift before adding deeper semantic decoders.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oad_parser.compare import compare_legacy_records_to_envelopes
from oad_parser.ingest.pcap import iter_pcap_packets
from oad_parser.parsers.ecg import extract_ecg_messages, parse_frame

GOLDEN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class GoldenCheckResult:
    match: bool
    fixture_path: str
    input_path: str
    expected_summary: dict[str, int]
    actual_summary: dict[str, int]
    difference_count: int
    differences: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "match": self.match,
            "fixture_path": self.fixture_path,
            "input_path": self.input_path,
            "expected_summary": self.expected_summary,
            "actual_summary": self.actual_summary,
            "difference_count": self.difference_count,
            "differences": list(self.differences),
        }


def export_golden_fixture(
    input_path: str | Path,
    raw_payload: bool = False,
) -> dict[str, object]:
    path = Path(input_path)
    comparisons = _build_comparisons(path, raw_payload=raw_payload)
    summary = _summary(comparisons)

    return {
        "schema_version": GOLDEN_SCHEMA_VERSION,
        "kind": "raw-payload" if raw_payload else "pcap",
        "source": {
            "path": str(path),
            "name": path.name,
        },
        "summary": summary,
        "comparisons": comparisons,
    }


def write_golden_fixture(
    input_path: str | Path,
    output_path: str | Path,
    raw_payload: bool = False,
) -> dict[str, object]:
    fixture = export_golden_fixture(input_path, raw_payload=raw_payload)
    Path(output_path).write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return fixture


def check_golden_fixture(
    fixture_path: str | Path,
    input_override: str | Path | None = None,
) -> GoldenCheckResult:
    fixture_file = Path(fixture_path)
    expected = json.loads(fixture_file.read_text(encoding="utf-8"))

    schema_version = expected.get("schema_version")
    if schema_version != GOLDEN_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported golden fixture schema_version: {schema_version}"
        )

    source = expected.get("source", {})
    input_path = Path(input_override or source.get("path", ""))
    if not str(input_path):
        raise ValueError("golden fixture does not include a source path; pass --input")

    raw_payload = expected.get("kind") == "raw-payload"
    actual = export_golden_fixture(input_path, raw_payload=raw_payload)

    expected_compact = _compact_fixture(expected)
    actual_compact = _compact_fixture(actual)

    differences = _diff_values(expected_compact, actual_compact)
    return GoldenCheckResult(
        match=not differences,
        fixture_path=str(fixture_file),
        input_path=str(input_path),
        expected_summary=dict(expected.get("summary", {})),
        actual_summary=dict(actual.get("summary", {})),
        difference_count=len(differences),
        differences=tuple(differences),
    )


def _build_comparisons(path: Path, raw_payload: bool) -> list[dict[str, object]]:
    if raw_payload:
        data = path.read_bytes()
        return [
            item.to_dict()
            for item in compare_legacy_records_to_envelopes(
                parse_frame(data, skip_headers=False),
                extract_ecg_messages(data, skip_headers=False),
            )
        ]

    records: list[dict[str, object]] = []
    for packet in iter_pcap_packets(path):
        packet_comparisons = compare_legacy_records_to_envelopes(
            parse_frame(packet.data),
            extract_ecg_messages(packet.data),
        )
        for item in packet_comparisons:
            data = item.to_dict()
            data["packet_timestamp_seconds"] = packet.timestamp_seconds
            data["packet_timestamp_fraction"] = packet.timestamp_fraction
            records.append(data)
    return records


def _summary(comparisons: list[dict[str, object]]) -> dict[str, int]:
    return {
        "comparison_count": len(comparisons),
        "match_count": sum(1 for item in comparisons if item.get("match") is True),
        "mismatch_count": sum(1 for item in comparisons if item.get("match") is not True),
    }


def _compact_fixture(fixture: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": fixture.get("schema_version"),
        "kind": fixture.get("kind"),
        "summary": fixture.get("summary"),
        "comparisons": fixture.get("comparisons"),
    }


def _diff_values(expected: object, actual: object, path: str = "$") -> list[str]:
    differences: list[str] = []

    if type(expected) is not type(actual):
        return [f"{path}: type mismatch expected={type(expected).__name__} actual={type(actual).__name__}"]

    if isinstance(expected, dict):
        expected_keys = set(expected)
        actual_keys = set(actual)
        for key in sorted(expected_keys - actual_keys):
            differences.append(f"{path}.{key}: missing from actual")
        for key in sorted(actual_keys - expected_keys):
            differences.append(f"{path}.{key}: unexpected in actual")
        for key in sorted(expected_keys & actual_keys):
            differences.extend(_diff_values(expected[key], actual[key], f"{path}.{key}"))
        return differences

    if isinstance(expected, list):
        if len(expected) != len(actual):
            differences.append(f"{path}: length mismatch expected={len(expected)} actual={len(actual)}")
            return differences
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            differences.extend(_diff_values(expected_item, actual_item, f"{path}[{index}]"))
        return differences

    if expected != actual:
        differences.append(f"{path}: expected={expected!r} actual={actual!r}")

    return differences

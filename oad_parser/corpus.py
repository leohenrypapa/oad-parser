"""Corpus validation for parser regression checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oad_parser.compare import LegacyEnvelopeComparison, compare_legacy_records_to_envelopes
from oad_parser.ingest.pcap import iter_pcap_packets
from oad_parser.parsers.ecg import extract_ecg_messages, parse_frame

PCAP_SUFFIXES = {".pcap", ".cap"}
RAW_PAYLOAD_SUFFIXES = {".bin", ".payload", ".ecg"}


@dataclass(frozen=True)
class CorpusFileResult:
    path: str
    kind: str
    comparison_count: int
    match_count: int
    mismatch_count: int
    error: str | None = None
    comparisons: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "comparison_count": self.comparison_count,
            "match_count": self.match_count,
            "mismatch_count": self.mismatch_count,
            "error": self.error,
            "comparisons": list(self.comparisons),
        }


@dataclass(frozen=True)
class CorpusValidationReport:
    root: str
    files_scanned: int
    files_with_errors: int
    comparison_count: int
    match_count: int
    mismatch_count: int
    zero_comparison_file_count: int
    files: tuple[CorpusFileResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_with_errors": self.files_with_errors,
            "comparison_count": self.comparison_count,
            "match_count": self.match_count,
            "mismatch_count": self.mismatch_count,
            "zero_comparison_file_count": self.zero_comparison_file_count,
            "files": [item.to_dict() for item in self.files],
        }


def validate_corpus_path(path: str | Path, force_raw_payload: bool = False) -> CorpusValidationReport:
    root = Path(path)
    files = list(_iter_supported_files(root, force_raw_payload=force_raw_payload))

    results = tuple(
        _validate_file(file_path, root=root, force_raw_payload=force_raw_payload)
        for file_path in files
    )

    return CorpusValidationReport(
        root=str(root),
        files_scanned=len(results),
        files_with_errors=sum(1 for item in results if item.error is not None),
        comparison_count=sum(item.comparison_count for item in results),
        match_count=sum(item.match_count for item in results),
        mismatch_count=sum(item.mismatch_count for item in results),
        zero_comparison_file_count=sum(
            1 for item in results if item.error is None and item.comparison_count == 0
        ),
        files=results,
    )


def _iter_supported_files(root: Path, force_raw_payload: bool = False) -> list[Path]:
    if root.is_file():
        return [root] if force_raw_payload or _is_supported_file(root) else []

    if not root.exists():
        raise FileNotFoundError(f"corpus path not found: {root}")

    candidates: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        if force_raw_payload or _is_supported_file(path):
            candidates.append(path)
    return candidates


def _is_supported_file(path: Path) -> bool:
    return path.suffix.lower() in PCAP_SUFFIXES | RAW_PAYLOAD_SUFFIXES


def _validate_file(file_path: Path, root: Path, force_raw_payload: bool = False) -> CorpusFileResult:
    relative_path = _relative_path(file_path, root)

    try:
        if force_raw_payload or file_path.suffix.lower() in RAW_PAYLOAD_SUFFIXES:
            comparisons = _compare_raw_payload(file_path)
            return _result_from_comparisons(relative_path, "raw-payload", comparisons)

        if file_path.suffix.lower() in PCAP_SUFFIXES:
            comparisons = _compare_pcap(file_path)
            return _result_from_comparisons(relative_path, "pcap", comparisons)

        return CorpusFileResult(
            path=relative_path,
            kind="unsupported",
            comparison_count=0,
            match_count=0,
            mismatch_count=0,
            error=f"unsupported file type: {file_path.suffix}",
        )
    except Exception as exc:
        return CorpusFileResult(
            path=relative_path,
            kind=_kind_for_path(file_path, force_raw_payload=force_raw_payload),
            comparison_count=0,
            match_count=0,
            mismatch_count=0,
            error=str(exc),
        )


def _compare_raw_payload(file_path: Path) -> list[dict[str, object]]:
    data = file_path.read_bytes()
    return [
        item.to_dict()
        for item in compare_legacy_records_to_envelopes(
            parse_frame(data, skip_headers=False),
            extract_ecg_messages(data, skip_headers=False),
        )
    ]


def _compare_pcap(file_path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for packet in iter_pcap_packets(file_path):
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


def _result_from_comparisons(
    relative_path: str,
    kind: str,
    comparisons: list[dict[str, object]],
) -> CorpusFileResult:
    return CorpusFileResult(
        path=relative_path,
        kind=kind,
        comparison_count=len(comparisons),
        match_count=sum(1 for item in comparisons if item.get("match") is True),
        mismatch_count=sum(1 for item in comparisons if item.get("match") is not True),
        comparisons=tuple(comparisons),
    )


def _relative_path(file_path: Path, root: Path) -> str:
    if root.is_file():
        return file_path.name
    try:
        return str(file_path.relative_to(root))
    except ValueError:
        return str(file_path)


def _kind_for_path(file_path: Path, force_raw_payload: bool = False) -> str:
    if force_raw_payload:
        return "raw-payload"
    suffix = file_path.suffix.lower()
    if suffix in RAW_PAYLOAD_SUFFIXES:
        return "raw-payload"
    if suffix in PCAP_SUFFIXES:
        return "pcap"
    return "unsupported"

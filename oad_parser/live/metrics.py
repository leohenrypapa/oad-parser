"""Runtime counters for the production live ECG parser path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class LiveMetrics:
    """Mutable live parser counters.

    The minimum counters are required by the live parser acceptance criteria.
    Additional counters support audit, storage, and detector visibility.
    """

    packets_received: int = 0
    packets_dropped: int = 0
    packets_parsed: int = 0
    ecg_messages_emitted: int = 0
    malformed_count: int = 0

    non_ipv4_or_non_udp: int = 0
    non_ecg: int = 0
    ecg_candidates: int = 0
    valid_ecg_payloads: int = 0
    error_records_emitted: int = 0
    detector_alerts: int = 0
    bytes_written: int = 0
    files_rotated: int = 0
    files_pruned: int = 0
    writer_block_seconds: float = 0.0
    output_drops: int = 0

    def snapshot(self) -> Dict[str, Any]:
        return {
            "packets_received": self.packets_received,
            "packets_dropped": self.packets_dropped,
            "packets_parsed": self.packets_parsed,
            "ecg_messages_emitted": self.ecg_messages_emitted,
            "malformed_count": self.malformed_count,
            "non_ipv4_or_non_udp": self.non_ipv4_or_non_udp,
            "non_ecg": self.non_ecg,
            "ecg_candidates": self.ecg_candidates,
            "valid_ecg_payloads": self.valid_ecg_payloads,
            "error_records_emitted": self.error_records_emitted,
            "detector_alerts": self.detector_alerts,
            "bytes_written": self.bytes_written,
            "files_rotated": self.files_rotated,
            "files_pruned": self.files_pruned,
            "writer_block_seconds": self.writer_block_seconds,
            "output_drops": self.output_drops,
        }

    def increment(self, name: str, amount: int = 1) -> None:
        if not hasattr(self, name):
            raise AttributeError(f"unknown live metric: {name}")
        current = getattr(self, name)
        setattr(self, name, current + amount)

    def add_writer_block_seconds(self, seconds: float) -> None:
        self.writer_block_seconds += seconds

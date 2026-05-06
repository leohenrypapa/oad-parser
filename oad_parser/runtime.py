"""Runtime stream helpers.

This module connects frame streams to parser and detector logic. It keeps live
capture and pcap replay behavior consistent without putting I/O in parser core.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from oad_parser.detectors import DetectionConfig, DetectionEngine
from oad_parser.models import ParsedPlot
from oad_parser.output import SchemaName, write_jsonl
from oad_parser.parsers.ecg import parse_frame


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def parse_frame_stream(
    frames: Iterable[bytes],
    observer_interface: str | None = None,
    detect: bool = False,
    detection_config: DetectionConfig | None = None,
    use_wall_clock_timestamp: bool = True,
) -> list[ParsedPlot]:
    records: list[ParsedPlot] = []
    detector = DetectionEngine(detection_config or DetectionConfig()) if detect else None

    for frame in frames:
        timestamp = utc_now_iso() if use_wall_clock_timestamp else None
        frame_records = parse_frame(
            frame,
            observer_interface=observer_interface,
            timestamp=timestamp,
        )

        if detector is not None:
            frame_records = detector.process_records(frame_records)

        records.extend(frame_records)

    return records


def write_frame_stream_jsonl(
    frames: Iterable[bytes],
    output_path: str | Path,
    observer_interface: str | None = None,
    schema: SchemaName = "ecs",
    detect: bool = False,
    detection_config: DetectionConfig | None = None,
) -> int:
    records = parse_frame_stream(
        frames,
        observer_interface=observer_interface,
        detect=detect,
        detection_config=detection_config,
        use_wall_clock_timestamp=True,
    )
    return write_jsonl(records, output_path, schema=schema)

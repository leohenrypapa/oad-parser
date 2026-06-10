"""Append-mode JSONL writer for live ECG runtime output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable, Dict, Optional

from oad_parser.config import LiveParserConfig


NowFn = Callable[[], datetime]


@dataclass(frozen=True)
class JsonlWriteResult:
    """Result from one append-mode JSONL write."""

    active_path: str
    bytes_written: int
    rotated_path: Optional[str] = None


class RotatingJsonlWriter:
    """Append JSON objects to an active JSONL file with time/size rotation.

    The active runtime file may keep the legacy .json suffix, but every write is
    JSON Lines behavior: exactly one JSON object plus a newline.
    """

    def __init__(
        self,
        active_path: str,
        *,
        rotate_seconds: int = 900,
        rotate_max_bytes: int = 536870912,
        now_fn: Optional[NowFn] = None,
    ) -> None:
        if rotate_seconds <= 0:
            raise ValueError("rotate_seconds must be > 0")
        if rotate_max_bytes <= 0:
            raise ValueError("rotate_max_bytes must be > 0")

        self.active_path = Path(active_path)
        self.rotate_seconds = int(rotate_seconds)
        self.rotate_max_bytes = int(rotate_max_bytes)
        self._now_fn = now_fn if now_fn is not None else _utc_now
        self._active_started_at_utc = self._initial_active_started_at()

    @classmethod
    def from_config(
        cls,
        config: LiveParserConfig,
        *,
        now_fn: Optional[NowFn] = None,
    ) -> "RotatingJsonlWriter":
        return cls(
            config.output_json_file,
            rotate_seconds=config.rotate_seconds,
            rotate_max_bytes=config.rotate_max_bytes,
            now_fn=now_fn,
        )

    def write_record(self, record: Dict[str, object]) -> JsonlWriteResult:
        payload = _encode_jsonl_record(record)

        if not payload:
            return JsonlWriteResult(
                active_path=str(self.active_path),
                bytes_written=0,
                rotated_path=None,
            )
        rotated_path = self._rotate_if_needed(len(payload))

        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        with self.active_path.open("ab") as handle:
            handle.write(payload)

        return JsonlWriteResult(
            active_path=str(self.active_path),
            bytes_written=len(payload),
            rotated_path=str(rotated_path) if rotated_path is not None else None,
        )

    def rotate_now(self) -> Optional[str]:
        rotated_path = self._rotate_active_file()
        return str(rotated_path) if rotated_path is not None else None

    def _rotate_if_needed(self, next_write_size: int) -> Optional[Path]:
        now = self._now_fn()
        age_seconds = (now - self._active_started_at_utc).total_seconds()

        if self._active_file_has_content() and age_seconds >= self.rotate_seconds:
            return self._rotate_active_file(rotation_time=now)

        current_size = self._active_file_size()
        if current_size > 0 and current_size + next_write_size > self.rotate_max_bytes:
            return self._rotate_active_file(rotation_time=now)

        return None

    def _rotate_active_file(
        self,
        *,
        rotation_time: Optional[datetime] = None,
    ) -> Optional[Path]:
        if not self._active_file_has_content():
            self._active_started_at_utc = self._now_fn()
            return None

        rotation_time = rotation_time if rotation_time is not None else self._now_fn()
        rotated_path = self._next_rotated_path(rotation_time)

        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(str(self.active_path), str(rotated_path))
        self._active_started_at_utc = self._now_fn()
        return rotated_path

    def _next_rotated_path(self, rotation_time: datetime) -> Path:
        timestamp = _format_utc_rotation_timestamp(rotation_time)
        active_name = self.active_path.name
        if active_name.endswith(".json"):
            base_name = active_name[:-5]
        else:
            base_name = self.active_path.stem

        candidate = self.active_path.with_name("%s-%s.jsonl" % (base_name, timestamp))
        if not candidate.exists():
            return candidate

        for index in range(1, 10000):
            candidate = self.active_path.with_name(
                "%s-%s-%04d.jsonl" % (base_name, timestamp, index)
            )
            if not candidate.exists():
                return candidate

        raise RuntimeError("could not allocate rotated JSONL filename")

    def _initial_active_started_at(self) -> datetime:
        if self.active_path.exists():
            return datetime.fromtimestamp(self.active_path.stat().st_mtime, timezone.utc)
        return self._now_fn()

    def _active_file_size(self) -> int:
        try:
            return self.active_path.stat().st_size
        except FileNotFoundError:
            return 0

    def _active_file_has_content(self) -> bool:
        return self._active_file_size() > 0



def _format_utc_rotation_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

COMPACT_EVENT_DROP_FIELDS = {
    "parser_name",
    "parser_version",
    "record_schema_version",
    "package_profile",
    "record_type",
    "interface",
    "ecg_message",
    "message_code",
    "message_data_length",
    "modec_valid",
    "parse_warnings",
    "sha256_ecg_payload",
}

COMPACT_EVENT_RENAME_FIELDS = {
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "source_port": "source.port",
    "destination_port": "destination.port",
    "ip_total_length": "tot.bytes",
    "message_type": "type",
}

COMPACT_PROJECTABLE_MESSAGES = {"cd-2", "cd-asr", "mar"}
COMPACT_PROJECTABLE_TYPES = {"beacon", "search", "rtqc"}
COMPACT_PROJECTED_FIELDS = {
    "range_nm",
    "azimuth_degrees",
    "altitude_feet",
    "mode_3_code",
    "acp",
}


def _encode_jsonl_record(record: Dict[str, object]) -> bytes:
    encoded_record = _compact_live_event_record(record)
    if encoded_record is None:
        return b""

    return (
        json.dumps(encoded_record, sort_keys=True, separators=(",", ":"), default=str)
        + "\n"
    ).encode("utf-8")


def _compact_live_event_record(record: Dict[str, object]) -> Optional[Dict[str, object]]:
    if record.get("record_type") != "ecg_event":
        return dict(record)

    if not _should_emit_live_event(record):
        return None

    compact: Dict[str, object] = {}

    for key, value in record.items():
        if key in COMPACT_EVENT_DROP_FIELDS:
            continue
        if value is None:
            continue
        if value == [] and key != "alerts":
            continue

        output_key = COMPACT_EVENT_RENAME_FIELDS.get(key, key)

        if output_key == "fingerprint" and "fingerprint" in compact:
            continue

        compact[output_key] = value

    event_type = compact.get("type")

    if event_type == "search":
        compact.setdefault("mode_3_code", -1)
        compact.setdefault("altitude_feet", -1)

    if event_type == "rtqc":
        compact.setdefault("alert", "OAD-ECG-001")
        compact.setdefault("alert_details", "RTQC message detected.")
        compact.setdefault("range_nm", -1)
        compact.setdefault("mode_3_code", -1)
        compact.setdefault("acp", -1)
        compact.setdefault("azimuth_degrees", -1)
        compact.setdefault("altitude_feet", -1)
        compact["fingerprint"] = "none"

    return compact


def _should_emit_live_event(record: Dict[str, object]) -> bool:
    message = record.get("message")
    message_type = record.get("message_type")

    if message is None and message_type is None:
        return True

    if message_type == "rtqc":
        return True

    if message not in COMPACT_PROJECTABLE_MESSAGES:
        return False

    if message_type not in COMPACT_PROJECTABLE_TYPES:
        return False

    return any(record.get(field) is not None for field in COMPACT_PROJECTED_FIELDS)

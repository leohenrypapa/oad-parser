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


def _encode_jsonl_record(record: Dict[str, object]) -> bytes:
    return (
        json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        + "\n"
    ).encode("utf-8")


def _format_utc_rotation_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

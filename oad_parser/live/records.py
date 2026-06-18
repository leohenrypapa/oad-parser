"""Record models for the production live ECG parser path."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from oad_parser import __version__ as OAD_PARSER_VERSION
from oad_parser.config import (
    DEFAULT_LIVE_AUDIT_FILE,
    DEFAULT_LIVE_DISK_CRITICAL_PERCENT,
    DEFAULT_LIVE_DISK_HIGH_WATER_PERCENT,
    DEFAULT_LIVE_OUTPUT_DIR,
    DEFAULT_LIVE_OUTPUT_JSON_FILE,
    DEFAULT_LIVE_PRUNE_AFTER_SECONDS,
    DEFAULT_LIVE_ROTATE_MAX_BYTES,
    DEFAULT_LIVE_ROTATE_SECONDS,
    DEFAULT_LIVE_STATUS_FILE,
)


LIVE_PARSER_NAME = "oad-parser"
LIVE_RECORD_SCHEMA_VERSION = "live-legacy-v1"
LIVE_PACKAGE_PROFILE = "customer-runtime-operator"


def live_record_metadata() -> Dict[str, str]:
    """Return common release/schema metadata for live-path records."""

    return {
        "parser_name": LIVE_PARSER_NAME,
        "parser_version": OAD_PARSER_VERSION,
        "record_schema_version": LIVE_RECORD_SCHEMA_VERSION,
        "package_profile": LIVE_PACKAGE_PROFILE,
    }


def format_utc_timestamp(value: Optional[datetime] = None) -> str:
    """Return an RFC 3339 style UTC timestamp with Z suffix."""

    if value is None:
        value = datetime.now(timezone.utc)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest for bytes."""

    return hashlib.sha256(data).hexdigest()


@dataclass
class LiveCaptureFrame:
    """Frame bytes plus capture metadata for the live service path."""

    frame_bytes: bytes
    interface: str
    capture_time_utc: datetime
    frame_length: Optional[int] = None
    sequence_number: Optional[int] = None

    def __post_init__(self) -> None:
        if self.frame_length is None:
            self.frame_length = len(self.frame_bytes)

    def to_dict(self) -> Dict[str, Any]:
        record = {
            "interface": self.interface,
            "capture_time_utc": format_utc_timestamp(self.capture_time_utc),
            "frame_length": self.frame_length,
        }
        if self.sequence_number is not None:
            record["sequence_number"] = self.sequence_number
        return record


@dataclass
class EcgOutputRecord:
    """Normal ECG event record for JSONL output."""

    timestamp_utc: datetime
    interface: str
    fields: Dict[str, Any] = field(default_factory=dict)
    record_type: str = "ecg_event"

    def to_dict(self) -> Dict[str, Any]:
        record = dict(self.fields)
        record.update(live_record_metadata())
        record["@timestamp"] = format_utc_timestamp(self.timestamp_utc)
        record["record_type"] = self.record_type
        record["interface"] = self.interface
        return record


@dataclass
class EcgParseErrorRecord:
    """Malformed ECG-looking payload record for JSONL output."""

    timestamp_utc: datetime
    interface: str
    sha256_ecg_payload: str
    error_code: str
    error_message: str
    parser_stage: str
    packet_metadata: Dict[str, Any] = field(default_factory=dict)
    record_type: str = "ecg_parse_error"

    def to_dict(self) -> Dict[str, Any]:
        record = dict(self.packet_metadata)
        record.update(live_record_metadata())
        record.update(
            {
                "@timestamp": format_utc_timestamp(self.timestamp_utc),
                "record_type": self.record_type,
                "interface": self.interface,
                "sha256_ecg_payload": self.sha256_ecg_payload,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "parser_stage": self.parser_stage,
            }
        )
        return record


@dataclass
class EcgAuditRecord:
    """Audit/status event emitted by the live service."""

    timestamp_utc: datetime
    event_type: str
    interface: str
    fields: Dict[str, Any] = field(default_factory=dict)
    record_type: str = "ecg_audit"

    def to_dict(self) -> Dict[str, Any]:
        record = dict(self.fields)
        record.update(live_record_metadata())
        record.update(
            {
                "@timestamp": format_utc_timestamp(self.timestamp_utc),
                "record_type": self.record_type,
                "event_type": self.event_type,
                "interface": self.interface,
            }
        )
        return record


@dataclass
class EcgStatusSnapshot:
    """Latest status snapshot intended for ecg-status.json."""

    timestamp_utc: datetime
    interface: str
    counters: Dict[str, Any]
    active_file: Optional[str] = None
    disk_percent: Optional[float] = None
    last_rotation: Optional[str] = None
    last_prune: Optional[str] = None
    last_error: Optional[str] = None
    last_packet_time_utc: Optional[datetime] = None
    last_status_time_utc: Optional[datetime] = None
    idle_age_seconds: Optional[float] = None
    frames_processed: Optional[int] = None
    storage_state: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        record = live_record_metadata()
        last_packet_time = (
            format_utc_timestamp(self.last_packet_time_utc)
            if self.last_packet_time_utc is not None
            else None
        )
        last_status_time = (
            format_utc_timestamp(self.last_status_time_utc)
            if self.last_status_time_utc is not None
            else None
        )
        record.update(
            {
                "@timestamp": format_utc_timestamp(self.timestamp_utc),
                "record_type": "ecg_status",
                "interface": self.interface,
                "counters": dict(self.counters),
                "active_file": self.active_file,
                "disk_percent": self.disk_percent,
                "last_rotation": self.last_rotation,
                "last_prune": self.last_prune,
                "last_error": self.last_error,
                "last_packet_time_utc": last_packet_time,
                "last_status_time_utc": last_status_time,
                "idle_age_seconds": self.idle_age_seconds,
                "frames_processed": self.frames_processed,
                "storage_state": self.storage_state,
            }
        )
        return record


@dataclass
class StoragePolicy:
    """Storage defaults for live JSONL rotation and pruning."""

    output_dir: str = DEFAULT_LIVE_OUTPUT_DIR
    active_output_file: str = DEFAULT_LIVE_OUTPUT_JSON_FILE
    audit_file: str = DEFAULT_LIVE_AUDIT_FILE
    status_file: str = DEFAULT_LIVE_STATUS_FILE
    rotate_seconds: int = DEFAULT_LIVE_ROTATE_SECONDS
    rotate_max_bytes: int = DEFAULT_LIVE_ROTATE_MAX_BYTES
    prune_after_seconds: int = DEFAULT_LIVE_PRUNE_AFTER_SECONDS
    high_water_percent: int = DEFAULT_LIVE_DISK_HIGH_WATER_PERCENT
    critical_percent: int = DEFAULT_LIVE_DISK_CRITICAL_PERCENT
    block_when_full: bool = True
    compress_archives: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "output_dir": self.output_dir,
            "active_output_file": self.active_output_file,
            "audit_file": self.audit_file,
            "status_file": self.status_file,
            "rotate_seconds": self.rotate_seconds,
            "rotate_max_bytes": self.rotate_max_bytes,
            "prune_after_seconds": self.prune_after_seconds,
            "high_water_percent": self.high_water_percent,
            "critical_percent": self.critical_percent,
            "block_when_full": self.block_when_full,
            "compress_archives": self.compress_archives,
        }

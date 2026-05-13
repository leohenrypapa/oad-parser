"""Audit JSONL and local status JSON writers for the live ECG parser."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Dict, Optional

from oad_parser.config import LiveParserConfig
from oad_parser.live.records import EcgAuditRecord, EcgStatusSnapshot


@dataclass(frozen=True)
class AuditWriteResult:
    """Result from one audit JSONL append."""

    path: str
    bytes_written: int


@dataclass(frozen=True)
class StatusWriteResult:
    """Result from one local status JSON replacement."""

    path: str
    bytes_written: int


class AuditJsonlWriter:
    """Append audit events as JSON Lines."""

    def __init__(self, audit_path: str) -> None:
        if not audit_path:
            raise ValueError("audit_path must not be empty")
        self.audit_path = Path(audit_path)

    @classmethod
    def from_config(cls, config: LiveParserConfig) -> "AuditJsonlWriter":
        return cls(config.audit_file)

    def write(self, record: EcgAuditRecord) -> AuditWriteResult:
        payload = _encode_json(record.to_dict()) + b"\n"
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("ab") as handle:
            handle.write(payload)

        return AuditWriteResult(
            path=str(self.audit_path),
            bytes_written=len(payload),
        )

    def __call__(self, record: EcgAuditRecord) -> AuditWriteResult:
        return self.write(record)


class StatusSnapshotWriter:
    """Write the latest status snapshot as a local JSON object."""

    def __init__(self, status_path: str) -> None:
        if not status_path:
            raise ValueError("status_path must not be empty")
        self.status_path = Path(status_path)

    @classmethod
    def from_config(cls, config: LiveParserConfig) -> "StatusSnapshotWriter":
        return cls(config.status_file)

    def write(self, snapshot: EcgStatusSnapshot) -> StatusWriteResult:
        payload = _encode_json(snapshot.to_dict()) + b"\n"
        self.status_path.parent.mkdir(parents=True, exist_ok=True)

        tmp_path = self._temporary_path()
        with tmp_path.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(str(tmp_path), str(self.status_path))

        return StatusWriteResult(
            path=str(self.status_path),
            bytes_written=len(payload),
        )

    def __call__(self, snapshot: EcgStatusSnapshot) -> StatusWriteResult:
        return self.write(snapshot)

    def _temporary_path(self) -> Path:
        return self.status_path.with_name(
            ".%s.%d.tmp" % (self.status_path.name, os.getpid())
        )


@dataclass
class LiveObservabilityWriters:
    """Container for audit and status writers used as service callbacks."""

    audit_writer: AuditJsonlWriter
    status_writer: StatusSnapshotWriter

    @classmethod
    def from_config(cls, config: LiveParserConfig) -> "LiveObservabilityWriters":
        return cls(
            audit_writer=AuditJsonlWriter.from_config(config),
            status_writer=StatusSnapshotWriter.from_config(config),
        )

    def audit_sink(self, record: EcgAuditRecord) -> AuditWriteResult:
        return self.audit_writer.write(record)

    def status_sink(self, snapshot: EcgStatusSnapshot) -> StatusWriteResult:
        return self.status_writer.write(snapshot)


def audit_record_from_storage_result(
    *,
    timestamp_utc,
    interface: str,
    event_type: str,
    storage_result,
) -> EcgAuditRecord:
    """Build an aggregate audit record from storage policy output."""

    fields: Dict[str, object] = {
        "disk_usage_percent": storage_result.disk_usage_percent,
        "files_pruned": storage_result.files_pruned,
        "bytes_pruned": storage_result.bytes_pruned,
        "writer_blocked": storage_result.writer_blocked,
        "critical": storage_result.critical,
        "pruned_paths": list(storage_result.pruned_paths),
    }
    return EcgAuditRecord(
        timestamp_utc=timestamp_utc,
        event_type=event_type,
        interface=interface,
        fields=fields,
    )


def status_snapshot_from_metrics(
    *,
    timestamp_utc,
    interface: str,
    metrics,
    active_file: Optional[str] = None,
    disk_percent: Optional[float] = None,
    last_rotation: Optional[str] = None,
    last_prune: Optional[str] = None,
    last_error: Optional[str] = None,
) -> EcgStatusSnapshot:
    """Build a status snapshot from current live metrics."""

    return EcgStatusSnapshot(
        timestamp_utc=timestamp_utc,
        interface=interface,
        counters=metrics.snapshot(),
        active_file=active_file,
        disk_percent=disk_percent,
        last_rotation=last_rotation,
        last_prune=last_prune,
        last_error=last_error,
    )


def _encode_json(value: Dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

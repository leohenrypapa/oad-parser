"""Append-mode JSONL writer for live ECG SIEM handoff output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Callable, Dict, Mapping, Optional, Sequence

from oad_parser.config import (
    DEFAULT_LIVE_DATA_STREAM_DATASET,
    DEFAULT_LIVE_DATA_STREAM_TYPE,
    DEFAULT_LIVE_EVENT_DATASET,
    DEFAULT_LIVE_SERVICE_NAME,
    LiveParserConfig,
)


NowFn = Callable[[], datetime]
FIELD_POLICY_V2_SCHEMA_VERSION = "2026-06-17.field-policy-v2"
FIELD_POLICY_V1_SCHEMA_VERSIONS = frozenset({"2026-06-15.phase5a", "2026-06-15.phase5b"})
FIELD_POLICY_SUPPORTED_SCHEMA_VERSIONS = FIELD_POLICY_V1_SCHEMA_VERSIONS | frozenset({FIELD_POLICY_V2_SCHEMA_VERSION})


@dataclass(frozen=True)
class JsonlWriteResult:
    """Result from one append-mode JSONL write."""

    active_path: str
    bytes_written: int
    rotated_path: Optional[str] = None


@dataclass(frozen=True)
class FieldPolicy:
    """Runtime-supported field policy.

    V1 policies support suppression of fields already cataloged as optional.
    V2 additionally supports controlled ordering, aliases for non-protected
    fields, and validated SIEM mapping metadata. Compact cyber/evidence fields
    remain protected.
    """

    schema_version: str = "2026-06-15.phase5b"
    policy_name: str = "default"
    disabled_fields: frozenset[str] = frozenset()
    desired_order: tuple[str, ...] = ()
    display_labels: Mapping[str, str] = None
    siem_mapping_notes: Mapping[str, str] = None


def load_field_policy(path: str | Path | None) -> Optional[FieldPolicy]:
    if path is None or str(path).strip() == "":
        return None
    policy_path = Path(path)
    if not policy_path.exists():
        return None
    with policy_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return field_policy_from_dict(data)


def field_policy_from_dict(data: Mapping[str, object]) -> FieldPolicy:
    if not isinstance(data, Mapping):
        raise ValueError("field policy must be a JSON object")
    allowed_keys = {
        "schema_version",
        "policy_name",
        "enabled_fields",
        "required_fields",
        "optional_fields",
        "disabled_fields",
        "display_labels",
        "grouping",
        "desired_order",
        "siem_mapping_notes",
        "compatibility_mode",
        "operator_notes",
    }
    unknown = sorted(set(data) - allowed_keys)
    if unknown:
        raise ValueError("field policy has unknown keys: %s" % ", ".join(unknown))
    schema_version = str(data.get("schema_version") or "2026-06-15.phase5b")
    if schema_version not in FIELD_POLICY_SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("field policy schema_version is not supported")

    disabled = _string_sequence(data.get("disabled_fields", []), "disabled_fields")
    known_fields = set(SIEM_KNOWN_POLICY_FIELDS) | set(SIEM_OPTIONAL_EVENT_FIELDS)
    unknown_fields = sorted(set(disabled) - known_fields)
    if unknown_fields:
        raise ValueError("field policy references unknown field(s): %s" % ", ".join(unknown_fields))

    unsupported_disabled = sorted(set(disabled) - set(SIEM_OPTIONAL_EVENT_FIELDS))
    if unsupported_disabled:
        raise ValueError("field policy may only disable optional field(s): %s" % ", ".join(unsupported_disabled))

    desired_order = _string_sequence(data.get("desired_order", []), "desired_order")
    display_labels = _string_map(data.get("display_labels", {}), "display_labels")
    siem_mapping_notes = _string_map(data.get("siem_mapping_notes", {}), "siem_mapping_notes")
    if schema_version in FIELD_POLICY_V1_SCHEMA_VERSIONS:
        for unsupported_key, value in (
            ("display_labels", display_labels),
            ("desired_order", desired_order),
            ("siem_mapping_notes", siem_mapping_notes),
        ):
            if value:
                raise ValueError("%s is not runtime-supported by field policy v1" % unsupported_key)
    else:
        _validate_field_policy_v2_controls(
            known_fields=known_fields,
            disabled=disabled,
            desired_order=desired_order,
            display_labels=display_labels,
            siem_mapping_notes=siem_mapping_notes,
        )

    return FieldPolicy(
        schema_version=schema_version,
        policy_name=str(data.get("policy_name") or "unnamed field policy")[:120],
        disabled_fields=frozenset(disabled),
        desired_order=desired_order,
        display_labels=dict(display_labels),
        siem_mapping_notes=dict(siem_mapping_notes),
    )


class _DuplicateKeyAccounting:
    """Exact duplicate-key counts with bounded Python memory.

    The SQLite table holds per-key counts on disk. The live writer keeps only
    scalar totals in memory, so event emission is immediate and does not buffer
    already-emitted records while still supporting exact duplicate suppression.
    """

    def __init__(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory(prefix="oad-duplicate-keys-")
        self._db_path = Path(self._tempdir.name) / "keys.sqlite"
        self._connection = sqlite3.connect(str(self._db_path), isolation_level=None)
        self._connection.execute("pragma synchronous=off")
        self._connection.execute("pragma journal_mode=memory")
        self._connection.execute(
            "create table duplicate_key_counts (key text primary key, count integer not null)"
        )
        self.unique_keys_seen = 0
        self.keys_with_duplicates = 0
        self.max_key_count = 0
        self.observations = 0
        self.last_key: Optional[str] = None
        self.last_key_count = 0

    def register(self, duplicate_key: str) -> int:
        row = self._connection.execute(
            "select count from duplicate_key_counts where key = ?",
            (duplicate_key,),
        ).fetchone()
        if row is None:
            next_count = 1
            self._connection.execute(
                "insert into duplicate_key_counts(key, count) values (?, ?)",
                (duplicate_key, next_count),
            )
            self.unique_keys_seen += 1
        else:
            next_count = int(row[0]) + 1
            self._connection.execute(
                "update duplicate_key_counts set count = ? where key = ?",
                (next_count, duplicate_key),
            )
            if next_count == 2:
                self.keys_with_duplicates += 1

        self.observations += 1
        if next_count > self.max_key_count:
            self.max_key_count = next_count
        self.last_key = duplicate_key
        self.last_key_count = next_count
        return next_count

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
            self._connection = None
        tempdir = getattr(self, "_tempdir", None)
        if tempdir is not None:
            tempdir.cleanup()
            self._tempdir = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


SIEM_EVENT_FIELDS = (
    "@timestamp",
    "event.created",
    "record_type",
    "event.dataset",
    "data_stream.type",
    "data_stream.dataset",
    "service.name",
    "observer.ingress.interface",
    "source.ip",
    "destination.ip",
    "source.port",
    "destination.port",
    "udp.payload.length",
    "udp.checksum.valid",
    "udp.checksum.value_hex",
    "ecg.frame.length_valid",
    "ecg.artcc",
    "ecg.outer_message.code",
    "ecg.outer_message.name",
    "cd2.site.id",
    "cd2.message.code",
    "cd2.message.name",
    "cd2.message.description",
    "cd2.sequence",
    "cd2.channel",
    "cd2.channel_raw_byte",
    "ecg.router.timestamp_sec",
    "cd2.radar.timestamp_sec",
    "radar.subtypes",
    "radar.range_nm",
    "radar.acp",
    "radar.azimuth_degrees",
    "radar.mode_3_code",
    "radar.altitude_feet",
    "hash.payload.sha256",
    "hash.message.sha256",
    "ecg.fingerprint",
    "parser.validation.accepted",
    "parser.validation.drop_reason",
    "parser.validation.warnings",
    "security.sequence.delta",
    "parser.analysis.mode",
    "parser.duplicate.key",
    "parser.duplicate.count",
    "parser.duplicate.suppressed",
    "alerts",
)

SIEM_DEBUG_ONLY_EVENT_FIELDS = (
    "network.bytes",
    "udp.length",
    "ecg.frame.length.claimed",
    "ecg.frame.length.expected",
)

SIEM_ACCOUNTING_EVENT_FIELDS = (
    "parser.accounting.output.records_seen",
    "parser.accounting.output.records_emitted",
    "parser.accounting.suppressed.duplicates",
    "parser.accounting.suppressed.sampled_normals",
    "parser.accounting.suppressed.parse_warnings",
    "parser.accounting.suppressed.modec_altitude_missing",
    "parser.accounting.duplicate.unique_keys_seen",
    "parser.accounting.duplicate.keys_with_duplicates",
    "parser.accounting.duplicate.max_key_count",
)

SIEM_ACCOUNTING_SNAPSHOT_ONLY_FIELDS = (
    "parser.accounting.snapshot.reason",
    "parser.accounting.duplicate.observations",
    "parser.accounting.duplicate.last_key",
    "parser.accounting.duplicate.last_key.count",
)

SIEM_RECORD_CONTRACT_FIELDS = (
    "record_type",
    "event.kind",
    "event.category",
    "event.action",
) + SIEM_ACCOUNTING_SNAPSHOT_ONLY_FIELDS

SIEM_FULL_EVENT_FIELDS = (
    SIEM_EVENT_FIELDS[:-1]
    + SIEM_DEBUG_ONLY_EVENT_FIELDS
    + SIEM_ACCOUNTING_EVENT_FIELDS
    + ("alerts",)
)

SIEM_OPTIONAL_EVENT_FIELDS = (
    "event.sample.rate",
)

SIEM_KNOWN_POLICY_FIELDS = frozenset(SIEM_FULL_EVENT_FIELDS) | frozenset(SIEM_RECORD_CONTRACT_FIELDS)


SIEM_FIELD_RENAMES = {
    "interface": "observer.ingress.interface",
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "source_port": "source.port",
    "destination_port": "destination.port",
    "network_bytes": "network.bytes",
    "ip_total_length": "network.bytes",
    "udp_length": "udp.length",
    "udp_payload_length": "udp.payload.length",
    "udp_checksum_valid": "udp.checksum.valid",
    "udp_checksum_hex": "udp.checksum.value_hex",
    "ecg_frame_length_claimed": "ecg.frame.length.claimed",
    "ecg_frame_length_expected": "ecg.frame.length.expected",
    "ecg_frame_length_valid": "ecg.frame.length_valid",
    "artcc": "ecg.artcc",
    "ecg_message": "ecg.outer_message.code",
    "outer_message_name": "ecg.outer_message.name",
    "site_id": "cd2.site.id",
    "message_code": "cd2.message.code",
    "message": "cd2.message.name",
    "sequence": "cd2.sequence",
    "channel": "cd2.channel",
    "channel_raw_byte": "cd2.channel_raw_byte",
    "router_timestamp": "ecg.router.timestamp_sec",
    "radar_timestamp": "cd2.radar.timestamp_sec",
    "radar_subtypes": "radar.subtypes",
    "range_nm": "radar.range_nm",
    "acp": "radar.acp",
    "azimuth_degrees": "radar.azimuth_degrees",
    "mode_3_code": "radar.mode_3_code",
    "altitude_feet": "radar.altitude_feet",
    "sha256_ecg_payload": "hash.payload.sha256",
    "hash_payload_sha256": "hash.payload.sha256",
    "hash_message_sha256": "hash.message.sha256",
    "fingerprint": "ecg.fingerprint",
    "parser_validation_accepted": "parser.validation.accepted",
    "parser_validation_drop_reason": "parser.validation.drop_reason",
    "parser_validation_warnings": "parser.validation.warnings",
    "parse_warnings": "parser.validation.warnings",
    "sequence_delta": "security.sequence.delta",
}

COMPACT_ALERT_FIELDS = ("id", "name", "severity", "category", "details", "message", "event.kind", "event.category", "event.action", "event.severity", "rule.id", "rule.name", "rule.category", "operator.category", "operator.alert", "operator.subtype")
SEVERITY_RANK = {"low": 10, "medium": 20, "high": 30, "critical": 40}


class RotatingJsonlWriter:
    """Append JSON objects to the active JSONL handoff file.

    Rotation is opt-in. The default operator/customer path writes only the
    active /nsm/ecg/ecg-current.json file. The file keeps the legacy .json
    suffix but is newline-delimited JSON.
    """

    def __init__(
        self,
        active_path: str,
        *,
        rotate_seconds: int = 900,
        rotate_max_bytes: int = 536870912,
        rotation_enabled: bool = False,
        include_debug_evidence: bool = False,
        normal_record_sample_rate: int = 1,
        emit_parse_warning_alerts: bool = True,
        emit_modec_altitude_missing_alerts: bool = True,
        data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
        data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
        event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
        service_name: str = DEFAULT_LIVE_SERVICE_NAME,
        field_policy: Optional[FieldPolicy] = None,
        now_fn: Optional[NowFn] = None,
    ) -> None:
        if rotate_seconds <= 0:
            raise ValueError("rotate_seconds must be > 0")
        if rotate_max_bytes <= 0:
            raise ValueError("rotate_max_bytes must be > 0")
        if normal_record_sample_rate <= 0:
            raise ValueError("normal_record_sample_rate must be > 0")

        self.active_path = Path(active_path)
        self.rotate_seconds = int(rotate_seconds)
        self.rotate_max_bytes = int(rotate_max_bytes)
        self.rotation_enabled = bool(rotation_enabled)
        self.include_debug_evidence = bool(include_debug_evidence)
        self.normal_record_sample_rate = int(normal_record_sample_rate)
        self.emit_parse_warning_alerts = bool(emit_parse_warning_alerts)
        self.emit_modec_altitude_missing_alerts = bool(emit_modec_altitude_missing_alerts)
        self.data_stream_type = data_stream_type
        self.data_stream_dataset = data_stream_dataset
        self.event_dataset = event_dataset
        self.service_name = service_name
        self.field_policy = field_policy
        self._normal_event_counter = 0
        self._records_seen = 0
        self._records_emitted = 0
        self._duplicate_suppressed = 0
        self._sampled_normal_suppressed = 0
        self._duplicate_accounting = _DuplicateKeyAccounting()
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
            rotation_enabled=config.rotation_enabled,
            include_debug_evidence=config.siem_debug_evidence,
            normal_record_sample_rate=config.normal_record_sample_rate,
            emit_parse_warning_alerts=config.emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=config.emit_modec_altitude_missing_alerts,
            data_stream_type=config.data_stream_type,
            data_stream_dataset=config.data_stream_dataset,
            event_dataset=config.event_dataset,
            service_name=config.service_name,
            field_policy=load_field_policy(config.field_policy_path),
            now_fn=now_fn,
        )

    def write_record(self, record: Dict[str, object]) -> JsonlWriteResult:
        encoded_record = _compact_live_record(
            record,
            include_debug_evidence=self.include_debug_evidence,
            emit_parse_warning_alerts=self.emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=self.emit_modec_altitude_missing_alerts,
            data_stream_type=self.data_stream_type,
            data_stream_dataset=self.data_stream_dataset,
            event_dataset=self.event_dataset,
            service_name=self.service_name,
        )
        if encoded_record is None:
            return JsonlWriteResult(
                active_path=str(self.active_path),
                bytes_written=0,
                rotated_path=None,
            )

        self._records_seen += 1
        duplicate_key = _analysis_duplicate_key(encoded_record)
        duplicate_count = self._register_duplicate_observation(duplicate_key)
        if duplicate_key is not None and duplicate_count > 1:
            if not _should_emit_duplicate_observation(encoded_record, duplicate_count):
                self._duplicate_suppressed += 1
                return JsonlWriteResult(
                    active_path=str(self.active_path),
                    bytes_written=0,
                    rotated_path=None,
                )

        if not self._should_emit_record(record, encoded_record):
            self._sampled_normal_suppressed += 1
            return JsonlWriteResult(
                active_path=str(self.active_path),
                bytes_written=0,
                rotated_path=None,
            )

        self._records_emitted += 1
        _apply_analysis_mode_accounting(
            encoded_record,
            duplicate_key=duplicate_key,
            duplicate_count=duplicate_count,
            records_seen=self._records_seen,
            records_emitted=self._records_emitted,
            duplicates_suppressed=self._duplicate_suppressed,
            sampled_normals_suppressed=self._sampled_normal_suppressed,
            duplicate_unique_keys_seen=self._duplicate_accounting.unique_keys_seen,
            duplicate_keys_with_duplicates=self._duplicate_keys_with_duplicates(),
            duplicate_max_key_count=self._duplicate_max_key_count(),
        )
        _apply_field_policy(encoded_record, self.field_policy)

        return self._write_encoded_record(encoded_record)

    def write_accounting_snapshot(self, *, reason: str = "snapshot") -> JsonlWriteResult:
        """Append a final/heartbeat accounting snapshot without changing ECG counts."""

        if self._records_seen == 0:
            return JsonlWriteResult(
                active_path=str(self.active_path),
                bytes_written=0,
                rotated_path=None,
            )

        now = self._now_fn()
        snapshot = {
            "@timestamp": _format_iso_utc(now),
            "event.created": _format_iso_utc(now),
            "event.kind": "metric",
            "event.category": "parser_accounting",
            "event.action": "parser-accounting-snapshot",
            "event.dataset": self.event_dataset,
            "data_stream.type": self.data_stream_type,
            "data_stream.dataset": self.data_stream_dataset,
            "service.name": self.service_name,
            "record_type": "parser_accounting",
            "parser.analysis.mode": "mode1_analysis_duplicate_only",
            "parser.accounting.snapshot.reason": reason,
            "parser.accounting.output.records_seen": self._records_seen,
            "parser.accounting.output.records_emitted": self._records_emitted,
            "parser.accounting.suppressed.duplicates": self._duplicate_suppressed,
            "parser.accounting.suppressed.sampled_normals": self._sampled_normal_suppressed,
            "parser.accounting.suppressed.parse_warnings": 0,
            "parser.accounting.suppressed.modec_altitude_missing": 0,
            "parser.accounting.duplicate.unique_keys_seen": self._duplicate_accounting.unique_keys_seen,
            "parser.accounting.duplicate.keys_with_duplicates": self._duplicate_keys_with_duplicates(),
            "parser.accounting.duplicate.max_key_count": self._duplicate_max_key_count(),
            "parser.accounting.duplicate.observations": self._duplicate_accounting.observations,
            "parser.accounting.duplicate.last_key": self._duplicate_accounting.last_key,
            "parser.accounting.duplicate.last_key.count": self._duplicate_accounting.last_key_count,
        }
        _apply_field_policy(snapshot, self.field_policy)
        return self._write_encoded_record(snapshot)

    def _write_encoded_record(self, encoded_record: Mapping[str, object]) -> JsonlWriteResult:
        payload = (
            json.dumps(
                encoded_record,
                sort_keys=not _field_policy_controls_order(self.field_policy),
                separators=(",", ":"),
                default=str,
            )
            + "\n"
        ).encode("utf-8")

        rotated_path = self._rotate_if_needed(len(payload))

        self.active_path.parent.mkdir(parents=True, exist_ok=True)
        with self.active_path.open("ab") as handle:
            handle.write(payload)

        return JsonlWriteResult(
            active_path=str(self.active_path),
            bytes_written=len(payload),
            rotated_path=str(rotated_path) if rotated_path is not None else None,
        )

    def _register_duplicate_observation(self, duplicate_key: Optional[str]) -> int:
        if duplicate_key is None:
            return 0
        return self._duplicate_accounting.register(duplicate_key)

    def _duplicate_keys_with_duplicates(self) -> int:
        return self._duplicate_accounting.keys_with_duplicates

    def _duplicate_max_key_count(self) -> int:
        return self._duplicate_accounting.max_key_count

    def _should_emit_record(
        self,
        source_record: Mapping[str, object],
        encoded_record: Mapping[str, object],
    ) -> bool:
        if source_record.get("record_type") != "ecg_event":
            return True
        if _has_actionable_alerts(encoded_record):
            return True
        if self.normal_record_sample_rate <= 1:
            if isinstance(encoded_record, dict):
                encoded_record["event.sample.rate"] = 1
            return True

        self._normal_event_counter += 1
        if (self._normal_event_counter - 1) % self.normal_record_sample_rate == 0:
            if isinstance(encoded_record, dict):
                encoded_record["event.sample.rate"] = self.normal_record_sample_rate
            return True
        return False

    def rotate_now(self) -> Optional[str]:
        rotated_path = self._rotate_active_file()
        return str(rotated_path) if rotated_path is not None else None

    def _rotate_if_needed(self, next_write_size: int) -> Optional[Path]:
        if not self.rotation_enabled:
            return None

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


def _format_iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _encode_jsonl_record(
    record: Dict[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
    service_name: str = DEFAULT_LIVE_SERVICE_NAME,
) -> bytes:
    encoded_record = _compact_live_record(
        record,
        include_debug_evidence=include_debug_evidence,
        emit_parse_warning_alerts=emit_parse_warning_alerts,
        emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        data_stream_type=data_stream_type,
        data_stream_dataset=data_stream_dataset,
        event_dataset=event_dataset,
        service_name=service_name,
    )
    if encoded_record is None:
        return b""

    return (
        json.dumps(encoded_record, sort_keys=True, separators=(",", ":"), default=str)
        + "\n"
    ).encode("utf-8")


def _compact_live_record(
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
    service_name: str = DEFAULT_LIVE_SERVICE_NAME,
) -> Optional[Dict[str, object]]:
    record_type = record.get("record_type")
    if record_type == "ecg_event":
        return _compact_live_event_record(
            record,
            include_debug_evidence=include_debug_evidence,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
            data_stream_type=data_stream_type,
            data_stream_dataset=data_stream_dataset,
            event_dataset=event_dataset,
            service_name=service_name,
        )
    if record_type == "ecg_parse_error":
        return _compact_parse_error_record(
            record,
            include_debug_evidence=include_debug_evidence,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
            data_stream_type=data_stream_type,
            data_stream_dataset=data_stream_dataset,
            event_dataset=event_dataset,
            service_name=service_name,
        )
    return dict(record)


def _compact_live_event_record(
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
    service_name: str = DEFAULT_LIVE_SERVICE_NAME,
) -> Optional[Dict[str, object]]:
    if not _should_emit_live_event(record):
        return None

    normalized = _renamed_record(record)
    _apply_common_defaults(normalized, record)
    return _project_normalized_siem_record(
        normalized,
        record,
        include_debug_evidence=include_debug_evidence,
        emit_parse_warning_alerts=emit_parse_warning_alerts,
        emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        data_stream_type=data_stream_type,
        data_stream_dataset=data_stream_dataset,
        event_dataset=event_dataset,
        service_name=service_name,
    )


def _compact_parse_error_record(
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
    service_name: str = DEFAULT_LIVE_SERVICE_NAME,
) -> Dict[str, object]:
    normalized = _renamed_record(record)
    normalized["parser.validation.accepted"] = False
    if normalized.get("parser.validation.drop_reason") is None:
        normalized["parser.validation.drop_reason"] = record.get("error_code")
    _apply_common_defaults(normalized, record)
    return _project_normalized_siem_record(
        normalized,
        record,
        include_debug_evidence=include_debug_evidence,
        emit_parse_warning_alerts=emit_parse_warning_alerts,
        emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        data_stream_type=data_stream_type,
        data_stream_dataset=data_stream_dataset,
        event_dataset=event_dataset,
        service_name=service_name,
    )


def _project_normalized_siem_record(
    normalized: Mapping[str, object],
    source_record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE,
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET,
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET,
    service_name: str = DEFAULT_LIVE_SERVICE_NAME,
) -> Dict[str, object]:
    normalized_with_defaults = dict(normalized)
    _scope_parser_validation_warnings_for_siem(normalized_with_defaults, source_record)
    normalized_with_defaults.setdefault("data_stream.type", data_stream_type)
    normalized_with_defaults.setdefault("data_stream.dataset", data_stream_dataset)
    normalized_with_defaults.setdefault("event.dataset", event_dataset)
    normalized_with_defaults.setdefault("service.name", service_name)

    projected_fields = SIEM_FULL_EVENT_FIELDS if include_debug_evidence else SIEM_EVENT_FIELDS
    compact: Dict[str, object] = {}
    for key in projected_fields:
        if key == "alerts":
            continue
        compact[key] = _clean_unavailable_value(normalized_with_defaults.get(key))

    compact["alerts"] = _compact_alerts(
        source_record,
        emit_parse_warning_alerts=emit_parse_warning_alerts,
        emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
    )
    if include_debug_evidence:
        compact["alerts_debug"] = _normal_alerts(source_record)
    return compact


def _apply_common_defaults(normalized: Dict[str, object], record: Mapping[str, object]) -> None:
    if normalized.get("event.created") is None:
        normalized["event.created"] = normalized.get("@timestamp")
    if normalized.get("parser.validation.warnings") is None:
        normalized["parser.validation.warnings"] = []
    if normalized.get("radar.subtypes") is None:
        normalized["radar.subtypes"] = []
    if normalized.get("cd2.message.description") is None:
        message_code = normalized.get("cd2.message.code")
        message_name = normalized.get("cd2.message.name")
        if message_code is not None and message_name in (None, "unknown", ""):
            normalized["cd2.message.description"] = f"unknown_message_code:{message_code}"
    # metadata-only unknown message-code warnings are regular traffic;
    # preserve the searchable description but do not emit a SIEM warning.
    warnings = normalized.get("parser.validation.warnings")
    if isinstance(warnings, list):
        normalized["parser.validation.warnings"] = [
            warning
            for warning in warnings
            if not (
                isinstance(warning, dict)
                and _clean_str(warning.get("code")) == "unknown_message_code"
                and normalized.get("cd2.message.description") is not None
            )
        ]
    if normalized.get("hash.payload.sha256") is None and record.get("sha256_ecg_payload") is not None:
        normalized["hash.payload.sha256"] = record.get("sha256_ecg_payload")


def _renamed_record(record: Mapping[str, object]) -> Dict[str, object]:
    normalized: Dict[str, object] = {}
    for key, value in record.items():
        output_key = SIEM_FIELD_RENAMES.get(key, key)
        if output_key in normalized and normalized[output_key] is not None:
            continue
        normalized[output_key] = value
    return normalized


def _should_emit_live_event(record: Mapping[str, object]) -> bool:
    return record.get("record_type") == "ecg_event"


def _compact_alerts(
    record: Mapping[str, object],
    *,
    emit_parse_warning_alerts: bool = True,
    emit_modec_altitude_missing_alerts: bool = True,
) -> list[dict[str, object]]:
    alerts = []
    for alert in _normal_alerts(record):
        scoped_alert = _scope_parse_warning_alert_for_siem(record, alert)
        if scoped_alert is None:
            continue
        if _is_operator_metadata_only_alert(record, scoped_alert):
            continue
        if _is_suppressed_parse_warning_alert(
            record,
            scoped_alert,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
        ):
            continue
        if _is_suppressed_modec_altitude_missing_alert(
            record,
            scoped_alert,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        ):
            continue
        alerts.append(_compact_alert(scoped_alert))
    return alerts


def _has_actionable_alerts(record: Mapping[str, object]) -> bool:
    for alert in _normal_alerts(record):
        if not _is_operator_metadata_only_alert(record, alert):
            return True
    return False


def _should_emit_duplicate_observation(
    record: Mapping[str, object],
    duplicate_count: int,
) -> bool:
    return False


def _is_operator_metadata_only_alert(
    record: Mapping[str, object],
    alert: Mapping[str, object],
) -> bool:
    alert_id = _clean_str(alert.get("id"))
    if alert_id in {"OAD-ECG-003", "OAD-ECG-005", "OAD-ECG-008"}:
        return True
    return False


def _is_suppressed_parse_warning_alert(
    record: Mapping[str, object],
    alert: Mapping[str, object],
    *,
    emit_parse_warning_alerts: bool = True,
) -> bool:
    if emit_parse_warning_alerts:
        return False
    if _clean_str(alert.get("id")) != "OAD-ECG-003":
        return False
    accepted = record.get("parser_validation_accepted")
    if accepted is None:
        accepted = record.get("parser.validation.accepted")
    return accepted is not False


def _is_suppressed_modec_altitude_missing_alert(
    record: Mapping[str, object],
    alert: Mapping[str, object],
    *,
    emit_modec_altitude_missing_alerts: bool = True,
) -> bool:
    if emit_modec_altitude_missing_alerts:
        return False
    if _clean_str(alert.get("id")) != "OAD-ECG-008":
        return False
    accepted = record.get("parser_validation_accepted")
    if accepted is None:
        accepted = record.get("parser.validation.accepted")
    return accepted is not False



def _scope_parser_validation_warnings_for_siem(
    normalized: Dict[str, object],
    source_record: Mapping[str, object],
) -> None:
    warnings = _warning_dicts(normalized.get("parser.validation.warnings"))
    if not warnings:
        normalized["parser.validation.warnings"] = []
        return
    normalized["parser.validation.warnings"] = _scope_warning_dicts_for_record(source_record, warnings)


def _scope_parse_warning_alert_for_siem(
    record: Mapping[str, object],
    alert: Mapping[str, object],
) -> Optional[dict[str, object]]:
    if _clean_str(alert.get("id")) != "OAD-ECG-003":
        return dict(alert)

    scoped = dict(alert)
    evidence = scoped.get("evidence")
    if not isinstance(evidence, Mapping):
        return scoped

    if "parse_warnings" not in evidence:
        return scoped

    warnings = _warning_dicts(evidence.get("parse_warnings"))
    scoped_warnings = _scope_warning_dicts_for_record(record, warnings)
    if not scoped_warnings:
        return None

    scoped_evidence = dict(evidence)
    scoped_evidence["parse_warnings"] = scoped_warnings
    scoped["evidence"] = scoped_evidence
    return scoped


def _scope_warning_dicts_for_record(
    record: Mapping[str, object],
    warnings: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    scoped: list[dict[str, object]] = []
    seen: set[tuple[object, object, object]] = set()
    for warning in warnings:
        if not _parse_warning_applies_to_record(record, warning):
            continue
        key = (warning.get("code"), warning.get("message"), warning.get("parser_stage"))
        if key in seen:
            continue
        seen.add(key)
        scoped.append(dict(warning))
    return scoped


def _warning_dicts(value: object) -> list[dict[str, object]]:
    warnings: list[dict[str, object]] = []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return warnings
    for item in value:
        if isinstance(item, Mapping):
            warnings.append(dict(item))
    return warnings


def _parse_warning_applies_to_record(
    record: Mapping[str, object],
    warning: Mapping[str, object],
) -> bool:
    warning_code = _clean_str(warning.get("code"))
    if warning_code != "unknown_message_code":
        return True

    record_message = _clean_str(record.get("message"))
    if record_message is None:
        record_message = _clean_str(record.get("cd2.message.name"))
    if record_message not in {"unknown", "none"}:
        return False

    record_message_code = _clean_str(record.get("message_code"))
    if record_message_code is None:
        record_message_code = _clean_str(record.get("cd2.message.code"))
    warning_message_code = _unknown_message_code_from_warning(warning)
    if warning_message_code is None or record_message_code is None:
        return True
    return warning_message_code == record_message_code


def _unknown_message_code_from_warning(warning: Mapping[str, object]) -> Optional[str]:
    message = _clean_str(warning.get("message"))
    if message is None or ":" not in message:
        return None
    candidate = message.rsplit(":", 1)[-1].strip()
    return candidate or None



def _analysis_duplicate_key(record: Mapping[str, object]) -> Optional[str]:
    """Return a bounded exact-duplicate key for Mode 1 analysis output.

    The key intentionally excludes capture timestamp and parser accounting fields.
    It requires at least one parser hash so low-confidence/incomplete records are
    emitted instead of suppressed.
    """

    message_hash = record.get("hash.message.sha256")
    payload_hash = record.get("hash.payload.sha256")
    fingerprint = record.get("ecg.fingerprint")
    if not message_hash and not payload_hash and not fingerprint:
        return None

    key_fields = (
        "source.ip",
        "destination.ip",
        "source.port",
        "destination.port",
        "udp.length",
        "udp.payload.length",
        "udp.checksum.value_hex",
        "ecg.frame.length.claimed",
        "ecg.frame.length.expected",
        "ecg.artcc",
        "cd2.site.id",
        "cd2.message.code",
        "cd2.message.name",
        "cd2.sequence",
        "cd2.channel",
        "cd2.channel_raw_byte",
        "ecg.router.timestamp_sec",
        "cd2.radar.timestamp_sec",
        "radar.range_nm",
        "radar.acp",
        "radar.azimuth_degrees",
        "radar.mode_3_code",
        "radar.altitude_feet",
        "hash.payload.sha256",
        "hash.message.sha256",
        "ecg.fingerprint",
    )
    material = [(key, record.get(key)) for key in key_fields]
    raw = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _apply_analysis_mode_accounting(
    record: Dict[str, object],
    *,
    duplicate_key: Optional[str],
    duplicate_count: int,
    records_seen: int,
    records_emitted: int,
    duplicates_suppressed: int,
    sampled_normals_suppressed: int,
    duplicate_unique_keys_seen: int,
    duplicate_keys_with_duplicates: int,
    duplicate_max_key_count: int,
) -> None:
    record.setdefault("event.sample.rate", 1)
    record["parser.analysis.mode"] = "mode1_analysis_duplicate_only"
    record["parser.duplicate.key"] = duplicate_key
    record["parser.duplicate.count"] = duplicate_count if duplicate_key is not None else 0
    record["parser.duplicate.suppressed"] = 0

    accounting_values = {
        "parser.accounting.output.records_seen": records_seen,
        "parser.accounting.output.records_emitted": records_emitted,
        "parser.accounting.suppressed.duplicates": duplicates_suppressed,
        "parser.accounting.suppressed.sampled_normals": sampled_normals_suppressed,
        "parser.accounting.suppressed.parse_warnings": 0,
        "parser.accounting.suppressed.modec_altitude_missing": 0,
        "parser.accounting.duplicate.unique_keys_seen": duplicate_unique_keys_seen,
        "parser.accounting.duplicate.keys_with_duplicates": duplicate_keys_with_duplicates,
        "parser.accounting.duplicate.max_key_count": duplicate_max_key_count,
    }
    for key, value in accounting_values.items():
        if key in record:
            record[key] = value


def _clean_unavailable_value(value: object) -> object:
    if value == -1 or value == "none":
        return None
    if value == "unknown":
        return None
    return value


def _apply_field_policy(record: Dict[str, object], policy: Optional[FieldPolicy]) -> None:
    if policy is None:
        return
    for field_name in policy.disabled_fields:
        if field_name in SIEM_OPTIONAL_EVENT_FIELDS:
            record.pop(field_name, None)
    labels = dict(policy.display_labels or {})
    if not policy.desired_order and not labels:
        return

    ordered: Dict[str, object] = {}
    emitted = set()
    for field_name in policy.desired_order:
        if field_name in record and field_name not in emitted:
            ordered[labels.get(field_name, field_name)] = record[field_name]
            emitted.add(field_name)
    for field_name, value in record.items():
        if field_name in emitted:
            continue
        ordered[labels.get(field_name, field_name)] = value
    record.clear()
    record.update(ordered)


def _field_policy_controls_order(policy: Optional[FieldPolicy]) -> bool:
    return bool(policy and policy.schema_version == FIELD_POLICY_V2_SCHEMA_VERSION and policy.desired_order)


def _string_sequence(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("%s must be an array of strings" % field_name)
    items = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("%s must be an array of strings" % field_name)
        items.append(item)
    return tuple(items)


def _string_map(value: object, field_name: str) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("%s must be an object of strings" % field_name)
    items: Dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("%s must be an object of strings" % field_name)
        items[key] = item
    return items


def _validate_field_policy_v2_controls(
    *,
    known_fields: set[str],
    disabled: Sequence[str],
    desired_order: Sequence[str],
    display_labels: Mapping[str, str],
    siem_mapping_notes: Mapping[str, str],
) -> None:
    protected_fields = set(SIEM_EVENT_FIELDS) | set(SIEM_ACCOUNTING_EVENT_FIELDS) | set(SIEM_RECORD_CONTRACT_FIELDS)
    disabled_set = set(disabled)
    unknown_order = sorted(set(desired_order) - known_fields)
    unknown_labels = sorted(set(display_labels) - known_fields)
    unknown_mapping = sorted(set(siem_mapping_notes) - known_fields)
    unknown = sorted(set(unknown_order) | set(unknown_labels) | set(unknown_mapping))
    if unknown:
        raise ValueError("field policy references unknown field(s): %s" % ", ".join(unknown))
    duplicates = _duplicates(desired_order)
    if duplicates:
        raise ValueError("desired_order contains duplicate field(s): %s" % ", ".join(duplicates))
    disabled_order = sorted(set(desired_order) & disabled_set)
    if disabled_order:
        raise ValueError("desired_order references disabled field(s): %s" % ", ".join(disabled_order))
    protected_aliases = sorted(set(display_labels) & protected_fields)
    if protected_aliases:
        raise ValueError("protected compact field(s) cannot be renamed: %s" % ", ".join(protected_aliases))

    output_names = set(known_fields)
    for source, alias in display_labels.items():
        _validate_siem_field_name(alias, "display_labels.%s" % source)
        if source in disabled_set:
            raise ValueError("display_labels references disabled field: %s" % source)
        if alias in known_fields and alias != source:
            raise ValueError("display_labels alias collides with existing field: %s" % alias)
        if alias in output_names and alias != source:
            raise ValueError("display_labels creates duplicate output field: %s" % alias)
        output_names.add(alias)
    duplicate_aliases = sorted({alias for alias in display_labels.values() if list(display_labels.values()).count(alias) > 1})
    if duplicate_aliases:
        raise ValueError("display_labels contains duplicate alias output(s): %s" % ", ".join(duplicate_aliases))

    for source, target in siem_mapping_notes.items():
        if source in disabled_set:
            raise ValueError("siem_mapping_notes references disabled field: %s" % source)
        _validate_siem_field_name(target, "siem_mapping_notes.%s" % source)


def _validate_siem_field_name(name: str, label: str) -> None:
    if not name or len(name) > 128:
        raise ValueError("%s must be 1-128 characters" % label)
    first = name[0]
    if not (first.isalpha() or first in {"_", "@"}):
        raise ValueError("%s must start with a letter, underscore, or @" % label)
    blocked = set(" \t\r\n/\\;&|`$<>'\"(){}[]*?!")
    if any(ord(ch) < 32 or ch in blocked for ch in name):
        raise ValueError("%s contains unsupported characters" % label)
    if any(not (ch.isalnum() or ch in {"_", ".", "-", "@"}) for ch in name):
        raise ValueError("%s contains unsupported characters" % label)


def _duplicates(values: Sequence[str]) -> list[str]:
    seen = set()
    duplicates = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _apply_alert_projection(
    compact: Dict[str, object],
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
) -> None:
    alerts = _normal_alerts(record)
    if not alerts:
        return

    selected = _select_alert(alerts, record.get("alert"))
    alert_id = _clean_str(selected.get("id")) or _clean_str(record.get("alert"))
    if alert_id is not None:
        compact["alert"] = alert_id

    for source_key, output_key in (
        ("name", "alert_name"),
        ("severity", "alert_severity"),
        ("category", "alert_category"),
        ("details", "alert_details"),
    ):
        value = _clean_str(selected.get(source_key))
        if value is not None:
            compact[output_key] = value

    scalar_details = _clean_str(record.get("alert_details"))
    if scalar_details is not None:
        compact["alert_details"] = scalar_details

    compact["alert_count"] = len(alerts)
    compact_alerts = [_compact_alert(alert) for alert in alerts]
    if len(compact_alerts) > 1:
        compact["alerts"] = compact_alerts

    if include_debug_evidence:
        compact["alerts_debug"] = [dict(alert) for alert in alerts]


def _apply_parse_warning_summary(
    compact: Dict[str, object],
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
) -> None:
    warnings = _parse_warnings_from_record(record)
    if not warnings:
        return

    compact["parse_warning_count"] = len(warnings)
    codes = _unique_clean_values(warning.get("code") for warning in warnings)
    messages = _unique_clean_values(warning.get("message") for warning in warnings)
    stages = _unique_clean_values(warning.get("parser_stage") for warning in warnings)

    if codes:
        compact["parse_warning_codes"] = codes
    if messages:
        compact["parse_warning_messages"] = messages
    if stages:
        compact["parse_warning_parser_stages"] = stages
    if include_debug_evidence:
        compact["parse_warnings"] = warnings


def _normal_alerts(record: Mapping[str, object]) -> list[dict[str, object]]:
    raw_alerts = record.get("alerts")
    alerts: list[dict[str, object]] = []
    if isinstance(raw_alerts, Sequence) and not isinstance(raw_alerts, (str, bytes, bytearray)):
        for item in raw_alerts:
            if isinstance(item, Mapping):
                alerts.append(dict(item))

    if alerts:
        return alerts

    alert_id = _clean_str(record.get("alert"))
    if alert_id is None:
        return []

    alert: dict[str, object] = {"id": alert_id}
    details = _clean_str(record.get("alert_details"))
    if details is not None:
        alert["details"] = details
    return [alert]


def _select_alert(alerts: Sequence[Mapping[str, object]], selected_id: object) -> Mapping[str, object]:
    selected_id_text = _clean_str(selected_id)
    if selected_id_text is not None:
        for alert in alerts:
            if _clean_str(alert.get("id")) == selected_id_text:
                return alert

    return max(
        alerts,
        key=lambda item: SEVERITY_RANK.get(str(item.get("severity")), 0),
    )


def _compact_alert(alert: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in COMPACT_ALERT_FIELDS:
        value = _clean_str(alert.get(key))
        if value is not None:
            result[key] = value
    evidence = alert.get("evidence")
    if isinstance(evidence, Mapping):
        compact_evidence = {
            key: value
            for key, value in evidence.items()
            if _safe_evidence_item(str(key), value)
        }
        if compact_evidence:
            result["evidence"] = compact_evidence
    return result


def _safe_evidence_item(key: str, value: object) -> bool:
    if value is None:
        return False
    lowered = key.lower()
    if lowered in {"raw", "raw_payload", "payload", "packet_bytes", "frame_bytes"}:
        return False
    if isinstance(value, (bytes, bytearray)):
        return False
    return True


def _parse_warnings_from_record(record: Mapping[str, object]) -> list[dict[str, object]]:
    warnings: list[dict[str, object]] = []
    raw_warnings = record.get("parse_warnings")
    if isinstance(raw_warnings, Sequence) and not isinstance(raw_warnings, (str, bytes, bytearray)):
        for item in raw_warnings:
            if isinstance(item, Mapping):
                warnings.append(dict(item))

    if warnings:
        return warnings

    for alert in _normal_alerts(record):
        evidence = alert.get("evidence")
        if not isinstance(evidence, Mapping):
            continue
        alert_warnings = evidence.get("parse_warnings")
        if not isinstance(alert_warnings, Sequence) or isinstance(alert_warnings, (str, bytes, bytearray)):
            continue
        for item in alert_warnings:
            if isinstance(item, Mapping):
                warnings.append(dict(item))
    return warnings


def _unique_clean_values(values: object) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = _clean_str(value)
        if text is None or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _clean_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

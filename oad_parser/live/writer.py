"""Append-mode JSONL writer for live ECG SIEM handoff output."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence

from oad_parser.config import LiveParserConfig


NowFn = Callable[[], datetime]


@dataclass(frozen=True)
class JsonlWriteResult:
    """Result from one append-mode JSONL write."""

    active_path: str
    bytes_written: int
    rotated_path: Optional[str] = None


SIEM_EVENT_FIELDS = (
    "@timestamp",
    "event.created",
    "observer.ingress.interface",
    "source.ip",
    "destination.ip",
    "source.port",
    "destination.port",
    "network.bytes",
    "udp.length",
    "udp.payload.length",
    "udp.checksum.valid",
    "udp.checksum.value_hex",
    "ecg.frame.length.claimed",
    "ecg.frame.length.expected",
    "ecg.frame.length_valid",
    "ecg.artcc",
    "ecg.outer_message.code",
    "ecg.outer_message.name",
    "cd2.site.id",
    "cd2.message.code",
    "cd2.message.name",
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
    "alerts",
)

SIEM_OPTIONAL_EVENT_FIELDS = (
    "event.sample.rate",
)


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

COMPACT_ALERT_FIELDS = ("id", "name", "severity", "category", "details", "message", "event.kind", "event.category", "event.action", "event.severity", "rule.id", "rule.name", "rule.category")
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
        normal_record_sample_rate: int = 100,
        emit_parse_warning_alerts: bool = False,
        emit_modec_altitude_missing_alerts: bool = False,
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
        self._normal_event_counter = 0
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
            now_fn=now_fn,
        )

    def write_record(self, record: Dict[str, object]) -> JsonlWriteResult:
        encoded_record = _compact_live_record(
            record,
            include_debug_evidence=self.include_debug_evidence,
            emit_parse_warning_alerts=self.emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=self.emit_modec_altitude_missing_alerts,
        )
        if encoded_record is None or not self._should_emit_record(record, encoded_record):
            return JsonlWriteResult(
                active_path=str(self.active_path),
                bytes_written=0,
                rotated_path=None,
            )

        payload = (
            json.dumps(encoded_record, sort_keys=True, separators=(",", ":"), default=str)
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


def _encode_jsonl_record(
    record: Dict[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
) -> bytes:
    encoded_record = _compact_live_record(
        record,
        include_debug_evidence=include_debug_evidence,
        emit_parse_warning_alerts=emit_parse_warning_alerts,
        emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
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
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
) -> Optional[Dict[str, object]]:
    record_type = record.get("record_type")
    if record_type == "ecg_event":
        return _compact_live_event_record(
            record,
            include_debug_evidence=include_debug_evidence,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        )
    if record_type == "ecg_parse_error":
        return _compact_parse_error_record(
            record,
            include_debug_evidence=include_debug_evidence,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        )
    return dict(record)


def _compact_live_event_record(
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
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
    )


def _compact_parse_error_record(
    record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
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
    )


def _project_normalized_siem_record(
    normalized: Mapping[str, object],
    source_record: Mapping[str, object],
    *,
    include_debug_evidence: bool = False,
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
) -> Dict[str, object]:
    compact: Dict[str, object] = {}
    for key in SIEM_EVENT_FIELDS:
        if key == "alerts":
            continue
        compact[key] = _clean_unavailable_value(normalized.get(key))

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
    emit_parse_warning_alerts: bool = False,
    emit_modec_altitude_missing_alerts: bool = False,
) -> list[dict[str, object]]:
    alerts = []
    for alert in _normal_alerts(record):
        if _is_suppressed_parse_warning_alert(
            record,
            alert,
            emit_parse_warning_alerts=emit_parse_warning_alerts,
        ):
            continue
        if _is_suppressed_modec_altitude_missing_alert(
            record,
            alert,
            emit_modec_altitude_missing_alerts=emit_modec_altitude_missing_alerts,
        ):
            continue
        alerts.append(_compact_alert(alert))
    return alerts


def _has_actionable_alerts(record: Mapping[str, object]) -> bool:
    alerts = record.get("alerts")
    return bool(alerts)


def _is_suppressed_parse_warning_alert(
    record: Mapping[str, object],
    alert: Mapping[str, object],
    *,
    emit_parse_warning_alerts: bool = False,
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
    emit_modec_altitude_missing_alerts: bool = False,
) -> bool:
    if emit_modec_altitude_missing_alerts:
        return False
    if _clean_str(alert.get("id")) != "OAD-ECG-008":
        return False
    accepted = record.get("parser_validation_accepted")
    if accepted is None:
        accepted = record.get("parser.validation.accepted")
    return accepted is not False


def _clean_unavailable_value(value: object) -> object:
    if value == -1 or value == "none":
        return None
    if value == "unknown":
        return None
    return value


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

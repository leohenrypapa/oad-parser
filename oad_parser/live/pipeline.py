"""Per-frame live ECG processing pipeline.

This module connects the classifier, ECG parser, legacy transformer, and live
metrics for one already-classified capture frame. It intentionally reuses the
classifier result so the live path does not parse Ethernet/IPv4/UDP headers a
second time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from oad_parser.live.alerts import EcgAlertConfig, apply_legacy_alert_fields, make_alert
from oad_parser.live.classifier import (
    OUTCOME_ECG_CANDIDATE,
    LiveFrameClassification,
)
from oad_parser.live.metrics import LiveMetrics
from oad_parser.parsers.ecg import (
    EcgEnvelopeParseResult,
    extract_ecg_messages_with_errors,
)
from oad_parser.transformers.legacy_ecg import transform_parse_result_to_legacy_records


@dataclass
class LiveSequenceState:
    """Per-feed state for duplicate collapse plus sequence/timestamp modeling."""

    last_sequence_by_key: Dict[Tuple[object, ...], int] = None
    last_radar_timestamp_by_key: Dict[Tuple[object, ...], float] = None
    last_router_timestamp_by_key: Dict[Tuple[object, ...], float] = None
    duplicate_window_by_key: Dict[Tuple[object, ...], List[Tuple[datetime, str]]] = None

    def __post_init__(self) -> None:
        if self.last_sequence_by_key is None:
            self.last_sequence_by_key = {}
        if self.last_radar_timestamp_by_key is None:
            self.last_radar_timestamp_by_key = {}
        if self.last_router_timestamp_by_key is None:
            self.last_router_timestamp_by_key = {}
        if self.duplicate_window_by_key is None:
            self.duplicate_window_by_key = {}

    def annotate_records(
        self,
        records: List[Dict[str, Any]],
        *,
        alert_config: EcgAlertConfig | None = None,
    ) -> None:
        for record in records:
            if record.get("record_type") != "ecg_event":
                continue

            existing_alerts = list(record.get("alerts") or [])
            duplicate_collapsed = self._apply_duplicate_alert(record, existing_alerts, alert_config)
            if duplicate_collapsed:
                apply_legacy_alert_fields(record, existing_alerts)
                continue

            self._annotate_sequence(record, existing_alerts, alert_config)
            self._annotate_time(record, existing_alerts, alert_config)
            apply_legacy_alert_fields(record, existing_alerts)

    def _apply_duplicate_alert(
        self,
        record: Dict[str, Any],
        alerts: List[Mapping[str, Any]],
        alert_config: EcgAlertConfig | None,
    ) -> bool:
        if alert_config is None:
            return False

        window_seconds = alert_config.duplicate_payload_window_seconds
        threshold = alert_config.duplicate_payload_threshold
        if window_seconds is None or threshold is None:
            return False

        message_hash = _message_hash(record)
        if message_hash is None:
            return False

        seen_at = _record_datetime(record)
        duplicate_key = _duplicate_key(record) + (message_hash,)
        window = self.duplicate_window_by_key.setdefault(duplicate_key, [])
        cutoff = seen_at.timestamp() - window_seconds
        window[:] = [(stamp, text) for stamp, text in window if stamp.timestamp() >= cutoff]
        window.append((seen_at, str(record.get("@timestamp") or seen_at.isoformat())))

        if len(window) <= 1:
            return False

        if len(window) >= threshold:
            alerts.append(
                make_alert(
                    "ECG-CD2-004",
                    "Duplicate payload/message hash repeated above threshold in the configured window; treat as duplicate/replay or capture-path anomaly until validated.",
                    {
                        "hash": message_hash,
                        "packet_count": len(window),
                        "first_seen": window[0][1],
                        "last_seen": window[-1][1],
                        "window_sec": window_seconds,
                        "source_site_channel_tuple": _feed_evidence(record),
                    },
                    scope="stateful",
                )
            )

        return True

    def _annotate_sequence(
        self,
        record: Dict[str, Any],
        alerts: List[Mapping[str, Any]],
        alert_config: EcgAlertConfig | None,
    ) -> None:
        sequence = record.get("sequence")
        if not isinstance(sequence, int):
            record["sequence_delta"] = None
            return

        key = _sequence_key(record)
        previous = self.last_sequence_by_key.get(key)
        delta = None if previous is None else (sequence - previous) % 256
        record["sequence_delta"] = delta
        self.last_sequence_by_key[key] = sequence

        if previous is None or alert_config is None or alert_config.max_sequence_delta is None:
            return
        if delta is not None and delta > alert_config.max_sequence_delta:
            alerts.append(
                make_alert(
                    "ECG-CD2-005",
                    "Modulo-256 message sequence gap exceeded the configured threshold after duplicate collapse.",
                    {
                        "previous_sequence": previous,
                        "current_sequence": sequence,
                        "sequence_delta": delta,
                        "threshold": alert_config.max_sequence_delta,
                        "source_site_channel_tuple": _feed_evidence(record),
                    },
                    scope="stateful",
                )
            )

    def _annotate_time(
        self,
        record: Dict[str, Any],
        alerts: List[Mapping[str, Any]],
        alert_config: EcgAlertConfig | None,
    ) -> None:
        if alert_config is None:
            self._update_time_state(record)
            return

        key = _sequence_key(record)
        self._check_time_delta(
            record=record,
            alerts=alerts,
            key=key,
            field="radar_timestamp",
            state=self.last_radar_timestamp_by_key,
            threshold=alert_config.max_radar_time_delta_seconds,
            delta_field="radar_time_delta",
        )
        self._check_time_delta(
            record=record,
            alerts=alerts,
            key=key,
            field="router_timestamp",
            state=self.last_router_timestamp_by_key,
            threshold=alert_config.max_router_time_delta_seconds,
            delta_field="router_time_delta",
        )

    def _check_time_delta(
        self,
        *,
        record: Dict[str, Any],
        alerts: List[Mapping[str, Any]],
        key: Tuple[object, ...],
        field: str,
        state: Dict[Tuple[object, ...], float],
        threshold: float | None,
        delta_field: str,
    ) -> None:
        current = _as_float(record.get(field))
        previous = state.get(key)
        if current is not None:
            state[key] = current
        if current is None or previous is None:
            return

        delta = current - previous
        record[delta_field] = delta
        if threshold is None:
            return
        if delta > threshold or delta < 0:
            alerts.append(
                make_alert(
                    "ECG-CD2-006",
                    "Timestamp gap, rollback, or stale replay condition exceeded the configured threshold after duplicate collapse.",
                    {
                        "timestamp_field": field,
                        "previous_timestamp": previous,
                        "current_timestamp": current,
                        "delta_seconds": delta,
                        "threshold_seconds": threshold,
                        "source_site_channel_tuple": _feed_evidence(record),
                    },
                    scope="stateful",
                )
            )

    def _update_time_state(self, record: Dict[str, Any]) -> None:
        key = _sequence_key(record)
        radar_timestamp = _as_float(record.get("radar_timestamp"))
        router_timestamp = _as_float(record.get("router_timestamp"))
        if radar_timestamp is not None:
            self.last_radar_timestamp_by_key[key] = radar_timestamp
        if router_timestamp is not None:
            self.last_router_timestamp_by_key[key] = router_timestamp


@dataclass(frozen=True)
class LivePipelineResult:
    """Result of processing one classified live frame."""

    classification: LiveFrameClassification
    records: List[Dict[str, Any]]
    parse_result: Optional[EcgEnvelopeParseResult] = None


def process_classified_live_frame(
    classification: LiveFrameClassification,
    metrics: Optional[LiveMetrics] = None,
    alert_config: EcgAlertConfig | None = None,
    sequence_state: LiveSequenceState | None = None,
) -> LivePipelineResult:
    """Parse and transform one ECG-candidate classification.

    Non-ECG classifications are returned without parsing or records. ECG
    candidates are parsed from classification.ecg_payload with skip_headers=False
    so packet metadata from the classifier can be reused without re-parsing
    Ethernet/IPv4/UDP headers.
    """

    if classification.outcome != OUTCOME_ECG_CANDIDATE:
        return LivePipelineResult(
            classification=classification,
            records=[],
            parse_result=None,
        )

    payload = classification.ecg_payload or b""
    parse_result = extract_ecg_messages_with_errors(payload, skip_headers=False)
    parse_result = _with_packet_metadata(
        parse_result,
        classification.packet_metadata,
    )

    records = transform_parse_result_to_legacy_records(
        result=parse_result,
        timestamp_utc=classification.capture_frame.capture_time_utc,
        interface=classification.capture_frame.interface,
        alert_config=alert_config,
    )

    if sequence_state is not None:
        sequence_state.annotate_records(records, alert_config=alert_config)

    if metrics is not None:
        _update_metrics(parse_result, records, metrics)

    return LivePipelineResult(
        classification=classification,
        records=records,
        parse_result=parse_result,
    )



def _sequence_key(record: Dict[str, Any]) -> Tuple[object, ...]:
    return (
        record.get("source_ip"),
        record.get("destination_ip"),
        record.get("source_port"),
        record.get("destination_port"),
        record.get("artcc"),
        record.get("site_id"),
        record.get("channel"),
        record.get("message_code"),
    )



def _duplicate_key(record: Dict[str, Any]) -> Tuple[object, ...]:
    return _sequence_key(record)


def _message_hash(record: Mapping[str, Any]) -> str | None:
    value = record.get("hash_message_sha256") or record.get("fingerprint") or record.get("hash_payload_sha256")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _record_datetime(record: Mapping[str, Any]) -> datetime:
    value = record.get("@timestamp")
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.utcnow()


def _feed_evidence(record: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "source_ip": record.get("source_ip"),
        "source_port": record.get("source_port"),
        "destination_ip": record.get("destination_ip"),
        "destination_port": record.get("destination_port"),
        "artcc": record.get("artcc"),
        "site_id": record.get("site_id"),
        "channel": record.get("channel"),
        "message_code": record.get("message_code"),
        "message_name": record.get("message"),
    }


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def _with_packet_metadata(
    result: EcgEnvelopeParseResult,
    packet_metadata: Dict[str, Any],
) -> EcgEnvelopeParseResult:
    return EcgEnvelopeParseResult(
        envelopes=result.envelopes,
        error=result.error,
        warnings=result.warnings,
        payload=result.payload,
        packet_metadata=dict(packet_metadata),
        frame_length_claimed=result.frame_length_claimed,
        frame_length_expected=result.frame_length_expected,
        frame_length_valid=result.frame_length_valid,
    )


def _update_metrics(
    result: EcgEnvelopeParseResult,
    records: List[Dict[str, Any]],
    metrics: LiveMetrics,
) -> None:
    if result.is_error:
        metrics.increment("malformed_count")
        metrics.increment("error_records_emitted", len(records))
        return

    if result.envelopes:
        metrics.increment("valid_ecg_payloads")

    if result.warnings:
        metrics.increment("parse_warnings_count", len(result.warnings))

    if records:
        metrics.increment("ecg_messages_emitted", len(records))

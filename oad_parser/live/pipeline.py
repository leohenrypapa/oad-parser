"""Per-frame live ECG processing pipeline.

This module connects the classifier, ECG parser, legacy transformer, and live
metrics for one already-classified capture frame. It intentionally reuses the
classifier result so the live path does not parse Ethernet/IPv4/UDP headers a
second time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

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


@dataclass(frozen=True)
class LivePipelineResult:
    """Result of processing one classified live frame."""

    classification: LiveFrameClassification
    records: List[Dict[str, Any]]
    parse_result: Optional[EcgEnvelopeParseResult] = None


def process_classified_live_frame(
    classification: LiveFrameClassification,
    metrics: Optional[LiveMetrics] = None,
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
    )

    if metrics is not None:
        _update_metrics(parse_result, records, metrics)

    return LivePipelineResult(
        classification=classification,
        records=records,
        parse_result=parse_result,
    )


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

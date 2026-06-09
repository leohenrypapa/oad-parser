"""Legacy-compatible ECG JSONL transformer for the live parser path."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from oad_parser.decoders.cd2_radar import decode_beacon_candidate_words
from oad_parser.live.records import EcgOutputRecord, EcgParseErrorRecord, sha256_hex
from oad_parser.parsers.ecg import (
    EcgEnvelopeParseIssue,
    EcgEnvelopeParseResult,
    EcgMessageEnvelope,
)


LEGACY_NULL_FIELDS = (
    "range_nm",
    "azimuth_degrees",
    "altitude_feet",
    "mode_3_code",
    "acp",
    "alert",
    "alert_details",
)

LEGACY_PACKET_FIELDS = (
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "ip_total_length",
)

UNKNOWN_CATEGORICAL_FIELDS = {
    "site_id",
    "message_type",
}


def transform_parse_result_to_legacy_records(
    result: EcgEnvelopeParseResult,
    timestamp_utc: datetime,
    interface: str,
) -> List[Dict[str, Any]]:
    """Transform an ECG parse result into JSON-ready legacy-compatible records."""

    if result.is_error:
        return [
            transform_parse_error_to_legacy_record(
                result=result,
                timestamp_utc=timestamp_utc,
                interface=interface,
            ).to_dict()
        ]

    if result.payload is None:
        return []

    return [
        transform_envelope_to_legacy_record(
            envelope=envelope,
            timestamp_utc=timestamp_utc,
            interface=interface,
            ecg_payload=result.payload,
            packet_metadata=result.packet_metadata or {},
            parse_warnings=result.warnings,
        ).to_dict()
        for envelope in result.envelopes
    ]


def transform_envelope_to_legacy_record(
    envelope: EcgMessageEnvelope,
    timestamp_utc: datetime,
    interface: str,
    ecg_payload: bytes,
    packet_metadata: Dict[str, Any] | None = None,
    parse_warnings: tuple[EcgEnvelopeParseIssue, ...] = (),
) -> EcgOutputRecord:
    """Build one legacy-compatible ECG event record from an envelope."""

    fields = legacy_fields_for_envelope(
        envelope,
        ecg_payload,
        parse_warnings=parse_warnings,
    )
    fields.update(_packet_fields(packet_metadata or {}, envelope))
    return EcgOutputRecord(
        timestamp_utc=timestamp_utc,
        interface=interface,
        fields=fields,
    )


def transform_parse_error_to_legacy_record(
    result: EcgEnvelopeParseResult,
    timestamp_utc: datetime,
    interface: str,
) -> EcgParseErrorRecord:
    """Build one legacy-compatible ECG parse-error record."""

    if result.error is None:
        raise ValueError("parse error result is required")

    payload = result.payload or b""
    packet_metadata = legacy_error_fields()
    packet_metadata.update(_packet_fields(result.packet_metadata or {}, None))

    return EcgParseErrorRecord(
        timestamp_utc=timestamp_utc,
        interface=interface,
        sha256_ecg_payload=sha256_hex(payload),
        error_code=result.error.code,
        error_message=result.error.message,
        parser_stage=result.error.parser_stage,
        packet_metadata=packet_metadata,
    )


def legacy_fields_for_envelope(
    envelope: EcgMessageEnvelope,
    ecg_payload: bytes,
    parse_warnings: tuple[EcgEnvelopeParseIssue, ...] = (),
) -> Dict[str, Any]:
    """Return legacy-compatible fields for a valid ECG envelope.

    The transformer projects the same provisional beacon/search fields used by
    the parser and decoder paths so live output does not suppress Sensor5 plot
    fields after the ECG envelope has been parsed.
    """

    fields: Dict[str, Any] = {
        "artcc": envelope.artcc,
        "site_id": _categorical_or_unknown(envelope.site_id),
        "ecg_message": envelope.ecg_message,
        "message_code": envelope.message_code,
        "message": _message_or_unknown(envelope.message_name),
        "message_type": _categorical_or_unknown(envelope.message_type),
        "sequence": envelope.sequence,
        "channel": envelope.channel,
        "router_timestamp": envelope.router_timestamp,
        "radar_timestamp": envelope.radar_timestamp,
        "message_data_length": envelope.message_data_length,
        "modec_valid": envelope.modec_valid,
        "sha256_ecg_payload": sha256_hex(ecg_payload),
    }

    fields.update(_project_plot_fields(envelope))

    if parse_warnings:
        fields["parse_warnings"] = _parse_warning_dicts(parse_warnings)

    return fields



def _project_plot_fields(envelope: EcgMessageEnvelope) -> Dict[str, Any]:
    fields: Dict[str, Any] = {name: None for name in LEGACY_NULL_FIELDS}

    if envelope.message_type in {"beacon", "search"}:
        decoded = decode_beacon_candidate_words(
            envelope.data_words,
            input_basis="ecg_envelope_16bit_words",
        )
        for name in ("range_nm", "azimuth_degrees", "altitude_feet", "mode_3_code", "acp"):
            fields[name] = decoded.get(name)
        return fields

    if envelope.message_type == "rtqc":
        fields["alert"] = "RTQC"
        fields["alert_details"] = "RTQC message detected."

    return fields


def _parse_warning_dicts(
    warnings: tuple[EcgEnvelopeParseIssue, ...],
) -> List[Dict[str, str]]:
    return [
        {
            "code": warning.code,
            "message": warning.message,
            "parser_stage": warning.parser_stage,
        }
        for warning in warnings
    ]


def legacy_error_fields() -> Dict[str, Any]:
    """Return known legacy fields for an ECG parse error record."""

    fields: Dict[str, Any] = {
        "artcc": None,
        "site_id": "unknown",
        "ecg_message": None,
        "message_code": None,
        "message": None,
        "message_type": "unknown",
        "sequence": None,
        "channel": None,
        "router_timestamp": None,
        "radar_timestamp": None,
        "message_data_length": None,
        "modec_valid": None,
    }

    for name in LEGACY_NULL_FIELDS:
        fields[name] = None

    return fields


def _packet_fields(
    packet_metadata: Dict[str, Any],
    envelope: EcgMessageEnvelope | None,
) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}

    for name in LEGACY_PACKET_FIELDS:
        if name in packet_metadata:
            fields[name] = packet_metadata[name]
        elif envelope is not None and hasattr(envelope, name):
            fields[name] = getattr(envelope, name)
        else:
            fields[name] = None

    return fields


def _categorical_or_unknown(value: str | None) -> str:
    if value is None:
        return "unknown"
    stripped = value.strip()
    return stripped if stripped else "unknown"


def _message_or_unknown(value: str | None) -> str:
    if value is None:
        return "unknown"
    stripped = value.strip()
    return stripped if stripped and stripped != "none" else "unknown"

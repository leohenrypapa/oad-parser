"""Legacy-compatible ECG JSONL transformer for the live parser path.

Boundary rule:
    This module preserves the legacy-compatible record contract. Do not place
    SIEM compaction, alert-output shaping, or warning-dedup policy here. Those
    belong in the live pipeline/writer layer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from oad_parser.decoders.provisional_beacon_constants import (
    ACP_DEGREES_PER_COUNT,
    ACP_WORD_INDEX,
    ALTITUDE_FEET_PER_COUNT,
    ALTITUDE_SIGN_MASK,
    LEGACY_ALTITUDE_WORD_MASK,
    LEGACY_RANGE_NM_SCALE,
    LEGACY_RANGE_WORD_MASK,
    LEGACY_RANGE_WORD_SHIFT,
    MODE_3_WORD_INDEX,
    RANGE_WORD_INDEX,
    WORD_DATA_MASK,
)

from oad_parser.decoders.cd2_radar import decode_beacon_candidate_words
from oad_parser.live.alerts import (
    EcgAlertConfig,
    apply_legacy_alert_fields,
    evaluate_ecg_parse_error_alerts,
    evaluate_ecg_record_alerts,
)
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
    "network_bytes",
    "ip_total_length",
    "udp_length",
    "udp_payload_length",
    "udp_checksum",
    "udp_checksum_hex",
    "udp_checksum_valid",
    "ecg_frame_length_claimed",
    "ecg_frame_length_expected",
    "ecg_frame_length_valid",
)

UNKNOWN_CATEGORICAL_FIELDS = {
    "site_id",
    "message_type",
}

PROJECTABLE_RADAR_MESSAGES = {"cd-2", "cd-asr", "mar"}
PROJECTABLE_RADAR_MESSAGE_TYPES = {"beacon", "search"}


def transform_parse_result_to_legacy_records(
    result: EcgEnvelopeParseResult,
    timestamp_utc: datetime,
    interface: str,
    alert_config: EcgAlertConfig | None = None,
) -> List[Dict[str, Any]]:
    """Transform an ECG parse result into JSON-ready legacy-compatible records."""

    if result.is_error:
        return [
            transform_parse_error_to_legacy_record(
                result=result,
                timestamp_utc=timestamp_utc,
                interface=interface,
                alert_config=alert_config,
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
            packet_metadata=_packet_metadata_with_frame_lengths(result),
            parse_warnings=result.warnings,
            alert_config=alert_config,
        ).to_dict()
        for envelope in result.envelopes
        if envelope.ecg_message == 1
    ]


def transform_envelope_to_legacy_record(
    envelope: EcgMessageEnvelope,
    timestamp_utc: datetime,
    interface: str,
    ecg_payload: bytes,
    packet_metadata: Dict[str, Any] | None = None,
    parse_warnings: tuple[EcgEnvelopeParseIssue, ...] = (),
    alert_config: EcgAlertConfig | None = None,
) -> EcgOutputRecord:
    """Build one legacy-compatible ECG event record from an envelope."""

    fields = legacy_fields_for_envelope(
        envelope,
        ecg_payload,
        parse_warnings=parse_warnings,
        packet_metadata=packet_metadata or {},
        alert_config=alert_config,
    )
    return EcgOutputRecord(
        timestamp_utc=timestamp_utc,
        interface=interface,
        fields=fields,
    )


def transform_parse_error_to_legacy_record(
    result: EcgEnvelopeParseResult,
    timestamp_utc: datetime,
    interface: str,
    alert_config: EcgAlertConfig | None = None,
) -> EcgParseErrorRecord:
    """Build one legacy-compatible ECG parse-error record."""

    if result.error is None:
        raise ValueError("parse error result is required")

    payload = result.payload or b""
    packet_metadata = legacy_error_fields()
    result_metadata = _packet_metadata_with_frame_lengths(result)
    packet_metadata.update(_packet_fields(result_metadata, None))
    for name in ("artcc", "ecg_message", "router_timestamp", "outer_message_name"):
        if name in result_metadata:
            packet_metadata[name] = result_metadata[name]
    packet_metadata.update(
        {
            "parser_validation_accepted": False,
            "parser_validation_drop_reason": result.error.code,
            "parser_validation_warnings": [],
        }
    )
    apply_legacy_alert_fields(
        packet_metadata,
        evaluate_ecg_parse_error_alerts(
            packet_metadata,
            error_code=result.error.code,
            error_message=result.error.message,
            parser_stage=result.error.parser_stage,
            config=alert_config,
        ),
    )

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
    packet_metadata: Dict[str, Any] | None = None,
    alert_config: EcgAlertConfig | None = None,
) -> Dict[str, Any]:
    """Return legacy-compatible fields for a valid ECG envelope.

    Live mode receives ECG envelopes, not ParsedPlot objects. Keep the legacy
    JSON schema, but project provisional radar fields directly from envelope
    data words for CD-2/CD-ASR/MAR beacon/search messages.
    """

    message_type = envelope.message_type
    fields: Dict[str, Any] = {
        "artcc": envelope.artcc,
        "site_id": _categorical_or_unknown(envelope.site_id),
        "ecg_message": envelope.ecg_message,
        "message_code": envelope.message_code,
        "message": _message_or_unknown(envelope.message_name),
        "message_type": _categorical_or_unknown(message_type),
        "radar_subtypes": _radar_subtypes(envelope),
        "rtqc_message": envelope.rtqc_message,
        "sequence": envelope.sequence,
        "sequence_delta": None,
        "channel": envelope.channel,
        "channel_raw_byte": envelope.channel_raw_byte,
        "router_timestamp": envelope.router_timestamp,
        "radar_timestamp": envelope.radar_timestamp,
        "message_data_length": envelope.message_data_length,
        "modec_valid": envelope.modec_valid,
        "outer_message_name": None,
        "sha256_ecg_payload": sha256_hex(ecg_payload),
        "hash_payload_sha256": sha256_hex(ecg_payload),
        "hash_message_sha256": _legacy_plot_fingerprint(ecg_payload, envelope),
        "fingerprint": _legacy_plot_fingerprint(ecg_payload, envelope),
    }

    fields.update(_project_legacy_radar_fields(envelope))

    parsed_warnings = _parse_warning_dicts(parse_warnings) if parse_warnings else []
    fields["parser_validation_accepted"] = True
    fields["parser_validation_drop_reason"] = None
    fields["parser_validation_warnings"] = parsed_warnings
    if parsed_warnings:
        fields["parse_warnings"] = parsed_warnings

    if packet_metadata is not None:
        fields.update(_packet_fields(packet_metadata, envelope))

    apply_legacy_alert_fields(
        fields,
        evaluate_ecg_record_alerts(
            fields,
            data_words=envelope.data_words,
            parse_warnings=parsed_warnings,
            config=alert_config,
        ),
    )

    return fields



def _packet_metadata_with_frame_lengths(result: EcgEnvelopeParseResult) -> Dict[str, Any]:
    metadata = dict(result.packet_metadata or {})
    metadata["ecg_frame_length_claimed"] = result.frame_length_claimed
    metadata["ecg_frame_length_expected"] = result.frame_length_expected
    metadata["ecg_frame_length_valid"] = result.frame_length_valid
    return metadata


def _radar_subtypes(envelope: EcgMessageEnvelope) -> List[str]:
    subtypes: List[str] = []
    if envelope.beacon_message:
        subtypes.append("beacon")
    if envelope.search_message:
        subtypes.append("search")
    if envelope.rtqc_message:
        subtypes.append("rtqc")
    return subtypes

def _project_legacy_radar_fields(envelope: EcgMessageEnvelope) -> Dict[str, Any]:
    fields: Dict[str, Any] = {name: None for name in LEGACY_NULL_FIELDS}

    if envelope.message_name not in PROJECTABLE_RADAR_MESSAGES:
        return fields

    if envelope.rtqc_message:
        return fields

    if envelope.message_type not in PROJECTABLE_RADAR_MESSAGE_TYPES:
        return fields

    words = list(envelope.data_words)

    if len(words) > RANGE_WORD_INDEX and not _word_has_legacy_status_bit(words[RANGE_WORD_INDEX]):
        fields["range_nm"] = (
            int((words[RANGE_WORD_INDEX] & LEGACY_RANGE_WORD_MASK) >> LEGACY_RANGE_WORD_SHIFT)
            * LEGACY_RANGE_NM_SCALE
        )

    if len(words) > ACP_WORD_INDEX and not _word_has_legacy_status_bit(words[ACP_WORD_INDEX]):
        acp = int(words[ACP_WORD_INDEX] & WORD_DATA_MASK)
        fields["acp"] = acp
        fields["azimuth_degrees"] = acp * ACP_DEGREES_PER_COUNT

    if (
        len(words) > MODE_3_WORD_INDEX
        and envelope.message_type == "beacon"
        and not _word_has_legacy_status_bit(words[MODE_3_WORD_INDEX])
    ):
        fields["mode_3_code"] = int(oct(int(words[MODE_3_WORD_INDEX] & WORD_DATA_MASK))[2:])

    if (
        envelope.message_type == "beacon"
        and envelope.modec_valid
        and len(words) > 6
        and not _word_has_legacy_status_bit(words[6])
    ):
        altitude_word = int(words[6] & LEGACY_ALTITUDE_WORD_MASK)
        altitude_feet = altitude_word * ALTITUDE_FEET_PER_COUNT
        if words[6] & ALTITUDE_SIGN_MASK:
            altitude_feet *= -1
        fields["altitude_feet"] = altitude_feet

    return fields




def _legacy_plot_fingerprint(ecg_payload: bytes, envelope: EcgMessageEnvelope) -> str:
    return sha256_hex(ecg_payload[:16] + (envelope.message_payload or b""))


def _word_has_legacy_status_bit(word: int) -> bool:
    high_byte = (int(word) >> 8) & 0xFF
    return bool(high_byte & 0b00110000)


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
        "radar_subtypes": [],
        "sequence": None,
        "sequence_delta": None,
        "channel": None,
        "channel_raw_byte": None,
        "router_timestamp": None,
        "radar_timestamp": None,
        "message_data_length": None,
        "modec_valid": None,
        "outer_message_name": None,
        "hash_payload_sha256": None,
        "hash_message_sha256": None,
        "fingerprint": None,
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

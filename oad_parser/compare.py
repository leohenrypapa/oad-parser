"""Comparison helpers for legacy parser output and ECG envelope decoding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from oad_parser.decoders.provisional_beacon_constants import (
    ACP_DEGREES_PER_COUNT,
    ACP_WORD_INDEX,
    ALTITUDE_FEET_PER_COUNT,
    ALTITUDE_SIGN_MASK,
    ALTITUDE_VALUE_MASK,
    ALTITUDE_WORD_INDEX,
    ALTITUDE_WORD_MASK,
    DATA_WORD_HEX_WIDTH,
    LEGACY_RANGE_NM_DIVISOR,
    MODE_3_WORD_INDEX,
    RANGE_WORD_INDEX,
    WORD_DATA_MASK,
)
from oad_parser.models import ParsedPlot
from oad_parser.parsers.ecg import EcgMessageEnvelope


FLOAT_TOLERANCE = 1e-9

LEGACY_PROJECTION_DECODER_NAME = "legacy-projection"
LEGACY_PROJECTION_BASIS = "current parse_frame-compatible ECG field projection"


@dataclass(frozen=True)
class FieldComparison:
    field: str
    legacy: object
    envelope: object
    match: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "field": self.field,
            "legacy": self.legacy,
            "envelope": self.envelope,
            "match": self.match,
        }


@dataclass(frozen=True)
class LegacyEnvelopeComparison:
    index: int
    match: bool
    compared_field_count: int
    mismatches: tuple[FieldComparison, ...]
    legacy: dict[str, object]
    envelope: dict[str, object]
    decoded: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "match": self.match,
            "compared_field_count": self.compared_field_count,
            "mismatches": [item.to_dict() for item in self.mismatches],
            "legacy": self.legacy,
            "envelope": self.envelope,
            "decoded": self.decoded,
        }


def compare_legacy_record_to_envelope(
    legacy: ParsedPlot,
    envelope: EcgMessageEnvelope,
    index: int = 0,
) -> LegacyEnvelopeComparison:
    decoded = project_envelope_with_legacy_fields(envelope)

    comparisons = [
        _compare("artcc", legacy.artcc, envelope.artcc),
        _compare("site_id", legacy.site_id, envelope.site_id),
        _compare("sequence", legacy.sequence, envelope.sequence),
        _compare("channel", legacy.channel, envelope.channel),
        _compare("message", legacy.message, envelope.message_name),
        _compare("message_type", legacy.message_type, envelope.message_type),
        _compare("router_timestamp", legacy.router_timestamp, envelope.router_timestamp),
        _compare("radar_timestamp", legacy.radar_timestamp, envelope.radar_timestamp),
        _compare("range_nm", legacy.range_nm, decoded.get("range_nm")),
        _compare("mode_3_code", legacy.mode_3_code, decoded.get("mode_3_code")),
        _compare("acp", legacy.acp, decoded.get("acp")),
        _compare("azimuth_degrees", legacy.azimuth_degrees, decoded.get("azimuth_degrees")),
        _compare("altitude_feet", legacy.altitude_feet, decoded.get("altitude_feet")),
    ]

    mismatches = tuple(item for item in comparisons if not item.match)

    return LegacyEnvelopeComparison(
        index=index,
        match=not mismatches,
        compared_field_count=len(comparisons),
        mismatches=mismatches,
        legacy=_legacy_summary(legacy),
        envelope=_envelope_summary(envelope),
        decoded=decoded,
    )


def compare_legacy_records_to_envelopes(
    legacy_records: list[ParsedPlot],
    envelopes: list[EcgMessageEnvelope],
) -> list[LegacyEnvelopeComparison]:
    comparisons: list[LegacyEnvelopeComparison] = []

    pair_count = min(len(legacy_records), len(envelopes))
    for index in range(pair_count):
        comparisons.append(
            compare_legacy_record_to_envelope(
                legacy_records[index],
                envelopes[index],
                index=index,
            )
        )

    for index in range(pair_count, len(legacy_records)):
        legacy = legacy_records[index]
        comparisons.append(
            LegacyEnvelopeComparison(
                index=index,
                match=False,
                compared_field_count=0,
                mismatches=(
                    FieldComparison(
                        field="record_count",
                        legacy="legacy-only",
                        envelope=None,
                        match=False,
                    ),
                ),
                legacy=_legacy_summary(legacy),
                envelope={},
                decoded={},
            )
        )

    for index in range(pair_count, len(envelopes)):
        envelope = envelopes[index]
        comparisons.append(
            LegacyEnvelopeComparison(
                index=index,
                match=False,
                compared_field_count=0,
                mismatches=(
                    FieldComparison(
                        field="record_count",
                        legacy=None,
                        envelope="envelope-only",
                        match=False,
                    ),
                ),
                legacy={},
                envelope=_envelope_summary(envelope),
                decoded=project_envelope_with_legacy_fields(envelope),
            )
        )

    return comparisons


def project_envelope_with_legacy_fields(envelope: EcgMessageEnvelope) -> dict[str, object]:
    """Project ECG envelope words using the current legacy parser assumptions.

    This is intentionally separate from beacon-candidate. The comparison command
    is a regression validator for the existing parser path, not an authority for
    final radar semantics.
    """
    words = list(envelope.data_words)
    result: dict[str, object] = {
        "decoder": LEGACY_PROJECTION_DECODER_NAME,
        "basis": LEGACY_PROJECTION_BASIS,
        "word_count": len(words),
        "data_words_hex": [_format_data_word_hex(word) for word in words],
    }

    if len(words) > RANGE_WORD_INDEX:
        result["range_nm"] = (
            words[RANGE_WORD_INDEX] & WORD_DATA_MASK
        ) / LEGACY_RANGE_NM_DIVISOR

    if len(words) > ACP_WORD_INDEX:
        acp = words[ACP_WORD_INDEX] & WORD_DATA_MASK
        result["acp"] = acp
        result["azimuth_degrees"] = acp * ACP_DEGREES_PER_COUNT

    if len(words) > MODE_3_WORD_INDEX:
        result["mode_3_code"] = int(
            oct(words[MODE_3_WORD_INDEX] & WORD_DATA_MASK)[2:]
        )

    if len(words) > ALTITUDE_WORD_INDEX:
        altitude_word = words[ALTITUDE_WORD_INDEX] & ALTITUDE_WORD_MASK
        altitude_feet = (altitude_word & ALTITUDE_VALUE_MASK) * ALTITUDE_FEET_PER_COUNT
        if altitude_word & ALTITUDE_SIGN_MASK:
            altitude_feet *= -1
        result["altitude_feet"] = altitude_feet

    return result


def _format_data_word_hex(word: int) -> str:
    return f"0x{word:0{DATA_WORD_HEX_WIDTH}x}"


def comparison_summary(comparisons: list[LegacyEnvelopeComparison]) -> dict[str, int]:
    return {
        "comparison_count": len(comparisons),
        "match_count": sum(1 for item in comparisons if item.match),
        "mismatch_count": sum(1 for item in comparisons if not item.match),
    }


def _compare(field: str, legacy: object, envelope: object) -> FieldComparison:
    return FieldComparison(
        field=field,
        legacy=legacy,
        envelope=envelope,
        match=_values_match(legacy, envelope),
    )


def _values_match(left: object, right: object) -> bool:
    if isinstance(left, float) or isinstance(right, float):
        try:
            return abs(float(left) - float(right)) <= FLOAT_TOLERANCE
        except (TypeError, ValueError):
            return False
    return left == right


def _legacy_summary(record: ParsedPlot) -> dict[str, Any]:
    return {
        "artcc": record.artcc,
        "site_id": record.site_id,
        "sequence": record.sequence,
        "channel": record.channel,
        "message": record.message,
        "message_type": record.message_type,
        "router_timestamp": record.router_timestamp,
        "radar_timestamp": record.radar_timestamp,
        "range_nm": record.range_nm,
        "mode_3_code": record.mode_3_code,
        "acp": record.acp,
        "azimuth_degrees": record.azimuth_degrees,
        "altitude_feet": record.altitude_feet,
    }


def _envelope_summary(envelope: EcgMessageEnvelope) -> dict[str, Any]:
    return {
        "artcc": envelope.artcc,
        "site_id": envelope.site_id,
        "sequence": envelope.sequence,
        "channel": envelope.channel,
        "message_name": envelope.message_name,
        "message_type": envelope.message_type,
        "router_timestamp": envelope.router_timestamp,
        "radar_timestamp": envelope.radar_timestamp,
        "data_words_hex": [_format_data_word_hex(word) for word in envelope.data_words],
    }

"""CD2 radar-message decoder scaffolds.

These decoders are deliberately conservative. `raw12` exposes framed CD2 words
with no semantic interpretation. `beacon-candidate` applies the same field
positions already used by the legacy parser, but marks the result provisional
until validated with sanitized captures and authoritative message references.
"""

from __future__ import annotations

from oad_parser.decoders.provisional_beacon_constants import (
    ACP_DEGREES_PER_COUNT,
    ACP_WORD_INDEX,
    ALTITUDE_FEET_PER_COUNT,
    ALTITUDE_SIGN_MASK,
    ALTITUDE_VALUE_MASK,
    ALTITUDE_WORD_INDEX,
    ALTITUDE_WORD_MASK,
    CD2_WORD_HEX_WIDTH,
    LEGACY_RANGE_NM_SCALE,
    LEGACY_RANGE_WORD_MASK,
    LEGACY_RANGE_WORD_SHIFT,
    MODE_3_WORD_INDEX,
    RANGE_WORD_INDEX,
    WORD_DATA_MASK,
)
from oad_parser.decoders.registry import DecoderEntry
from oad_parser.parsers.cd2 import Cd2Frame


RAW12_DECODER_NAME = "raw12"
BEACON_CANDIDATE_DECODER_NAME = "beacon-candidate"
BEACON_CANDIDATE_STATUS = "provisional"
BEACON_CANDIDATE_BASIS = (
    "provisional legacy-style field extraction; not authoritative radar semantics"
)
BEACON_CANDIDATE_INPUT_BASIS = "framed_12bit_cd2_words"

RAW12_DECODER_DESCRIPTION = (
    "Expose framed CD2 12-bit data words without semantic radar decoding."
)
BEACON_CANDIDATE_DECODER_DESCRIPTION = (
    "Provisional beacon-style field extraction from framed CD2 12-bit words."
)


def _format_data_word_hex(word: int) -> str:
    return f"0x{word:0{CD2_WORD_HEX_WIDTH}x}"


def decode_raw12_words(
    words: list[int] | tuple[int, ...],
    extended_error_status: int = 0,
    errors: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object]:
    return {
        "decoder": RAW12_DECODER_NAME,
        "word_count": len(words),
        "data_words": list(words),
        "data_words_hex": [_format_data_word_hex(word) for word in words],
        "extended_error_status": extended_error_status,
        "errors": list(errors or []),
    }


def decode_raw12(frame: Cd2Frame) -> dict[str, object]:
    return decode_raw12_words(
        list(frame.data_words),
        extended_error_status=frame.extended_error_status,
        errors=list(frame.errors),
    )


def decode_beacon_candidate_words(
    words: list[int] | tuple[int, ...],
    extended_error_status: int = 0,
    errors: list[str] | tuple[str, ...] | None = None,
    input_basis: str = BEACON_CANDIDATE_INPUT_BASIS,
) -> dict[str, object]:
    words = list(words)
    result: dict[str, object] = {
        "decoder": BEACON_CANDIDATE_DECODER_NAME,
        "status": BEACON_CANDIDATE_STATUS,
        "basis": BEACON_CANDIDATE_BASIS,
        "input_basis": input_basis,
        "word_count": len(words),
        "extended_error_status": extended_error_status,
        "errors": list(errors or []),
        "data_words_hex": [_format_data_word_hex(word) for word in words],
    }

    if len(words) > RANGE_WORD_INDEX:
        range_word = words[RANGE_WORD_INDEX]
        if input_basis == BEACON_CANDIDATE_INPUT_BASIS:
            result["range_nm"] = (range_word & WORD_DATA_MASK) * LEGACY_RANGE_NM_SCALE
        else:
            result["range_nm"] = (
                (range_word & LEGACY_RANGE_WORD_MASK)
                >> LEGACY_RANGE_WORD_SHIFT
            ) * LEGACY_RANGE_NM_SCALE

    if len(words) > ACP_WORD_INDEX:
        acp = words[ACP_WORD_INDEX] & WORD_DATA_MASK
        result["acp"] = acp
        result["azimuth_degrees"] = acp * ACP_DEGREES_PER_COUNT

    if len(words) > MODE_3_WORD_INDEX:
        result["mode_3_code"] = int(oct(words[MODE_3_WORD_INDEX] & WORD_DATA_MASK)[2:])

    if len(words) > ALTITUDE_WORD_INDEX:
        altitude_word = words[ALTITUDE_WORD_INDEX] & ALTITUDE_WORD_MASK
        altitude_feet = (altitude_word & ALTITUDE_VALUE_MASK) * ALTITUDE_FEET_PER_COUNT
        if altitude_word & ALTITUDE_SIGN_MASK:
            altitude_feet *= -1
        result["altitude_feet"] = altitude_feet

    missing_fields = []
    if len(words) <= RANGE_WORD_INDEX:
        missing_fields.append("range_nm")
    if len(words) <= ACP_WORD_INDEX:
        missing_fields.append("azimuth_degrees")
    if len(words) <= MODE_3_WORD_INDEX:
        missing_fields.append("mode_3_code")
    if len(words) <= ALTITUDE_WORD_INDEX:
        missing_fields.append("altitude_feet")

    if missing_fields:
        result["missing_fields"] = missing_fields

    return result


def decode_beacon_candidate(frame: Cd2Frame) -> dict[str, object]:
    return decode_beacon_candidate_words(
        list(frame.data_words),
        extended_error_status=frame.extended_error_status,
        errors=list(frame.errors),
    )


RAW12_DECODER = DecoderEntry(
    name=RAW12_DECODER_NAME,
    description=RAW12_DECODER_DESCRIPTION,
    decode=decode_raw12,
)

BEACON_CANDIDATE_DECODER = DecoderEntry(
    name=BEACON_CANDIDATE_DECODER_NAME,
    description=BEACON_CANDIDATE_DECODER_DESCRIPTION,
    decode=decode_beacon_candidate,
)

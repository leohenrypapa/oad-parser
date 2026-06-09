"""Pure ECG/CD2 parser extraction.

This module contains parser logic extracted from the working legacy field script.
It accepts raw frame bytes or raw ECG payload bytes and returns parsed records.
It does not open sockets, write files, mutate global runtime state, or depend on
systemd/Filebeat/Kibana.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from oad_parser.fingerprints import sha256
from typing import Iterable

from oad_parser.decoders.provisional_beacon_constants import (
    ACP_DEGREES_PER_COUNT as LEGACY_ACP_DEGREES_PER_COUNT,
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
from oad_parser.ingest.ethernet import parse_ipv4_udp_frame
from oad_parser.models import ParsedPlot


# ECG/CD2 foundation parser constants. These document wire layout only.
BYTE_ORDER = "big"
TEXT_ENCODING = "ascii"
FALLBACK_TEXT_ENCODING = "utf-8"
TEXT_DECODE_ERRORS = "replace"


# ECG envelope and message block layout.
ECG_MIN_PAYLOAD_BYTES = 18
ECG_LENGTH_TRAILER_BYTES = 16
ECG_MESSAGE_BLOCK_HEADER_BYTES = 16
BYTES_PER_WORD = 2

ARTCC_START = 4
ARTCC_END = 7
ECG_MESSAGE_OFFSET = 8
ROUTER_TIMESTAMP_START = 12
ROUTER_TIMESTAMP_END = 16
ROUTER_TIMESTAMP_SCALE = 0.0001


# Embedded message header layout.
SITE_ID_OFFSET_START = 4
SITE_ID_OFFSET_END = 8
MESSAGE_CODE_OFFSET = 8
SEQUENCE_OFFSET = 9
CHANNEL_OFFSET = 10
CHANNEL_MASK = 0b11110000
CHANNEL_SHIFT = 4
RADAR_TIMESTAMP_OFFSET_START = 12
RADAR_TIMESTAMP_OFFSET_END = 16
RADAR_TIMESTAMP_SCALE = 0.000001


# Provisional message-classification bits. These are not operational radar truth.
FIRST_WORD_BYTES = 2
BEACON_MESSAGE_MASK = 0b00000110
BEACON_MESSAGE_SHIFT = 1
BEACON_MESSAGE_PATTERN = 3
MODEC_VALID_MASK = 0b01000000
MODEC_VALID_SHIFT = 6
RTQC_MESSAGE_MASK = 0b00001000
RTQC_MESSAGE_SHIFT = 3
SEARCH_MESSAGE_MASK = 0b0000011111111100
SEARCH_MESSAGE_SHIFT = 2
SEARCH_MESSAGE_PATTERN = 108


# Per-word status bits.
WORD_PARITY_ERROR_MASK = 0b00100000
WORD_PARITY_ERROR_SHIFT = 5
WORD_MALFUNCTION_MASK = 0b00010000
WORD_MALFUNCTION_SHIFT = 4


# Provisional beacon-candidate extraction constants used for regression only.
# Canonical values live in decoders.provisional_beacon_constants so the ECG
# legacy projection and decoder scaffolds do not drift apart.
RANGE_WORD_MASK = LEGACY_RANGE_WORD_MASK
RANGE_WORD_SHIFT = LEGACY_RANGE_WORD_SHIFT
RANGE_NM_SCALE = LEGACY_RANGE_NM_SCALE
ACP_WORD_MASK = WORD_DATA_MASK
ACP_DEGREES_PER_COUNT = LEGACY_ACP_DEGREES_PER_COUNT
MODE_3_WORD_MASK = WORD_DATA_MASK
ALTITUDE_WORD_INDEX = 6
ALTITUDE_WORD_MASK = LEGACY_ALTITUDE_WORD_MASK
ALTITUDE_FEET_SCALE = ALTITUDE_FEET_PER_COUNT
ALTITUDE_SIGN_SHIFT = 11


# Display labels for observed message-code categories.
MESSAGE_NAME_BY_CODE = {
    1: "cd-2",
    3: "cd-asr",
    4: "mar",
}

ECG_ERROR_LENGTH_MISMATCH = "ecg_length_mismatch"
ECG_ERROR_SHORT_PAYLOAD = "ecg_short_payload"
ECG_ERROR_MESSAGE_BLOCK_TRUNCATED = "ecg_message_block_truncated"
ECG_WARNING_UNKNOWN_MESSAGE_CODE = "unknown_message_code"

@dataclass(frozen=True)
class EcgMessageEnvelope:
    """One ECG message block extracted from an ECG payload."""

    artcc: str
    site_id: str
    ecg_message: int
    message_code: int
    message_name: str
    sequence: int
    channel: int
    router_timestamp: float
    radar_timestamp: float
    message_data_length: int
    message_payload: bytes
    data_words: tuple[int, ...]
    message_type: str
    modec_valid: bool
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "artcc": self.artcc,
            "site_id": self.site_id,
            "ecg_message": self.ecg_message,
            "message_code": self.message_code,
            "message_name": self.message_name,
            "sequence": self.sequence,
            "channel": self.channel,
            "router_timestamp": self.router_timestamp,
            "radar_timestamp": self.radar_timestamp,
            "message_data_length": self.message_data_length,
            "data_words": list(self.data_words),
            "data_words_hex": [f"0x{word:04x}" for word in self.data_words],
            "message_type": self.message_type,
            "modec_valid": self.modec_valid,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
        }

@dataclass(frozen=True)
class EcgEnvelopeParseIssue:
    """Structured parse issue for the production live ECG path."""

    code: str
    message: str
    parser_stage: str


@dataclass(frozen=True)
class EcgEnvelopeParseResult:
    """ECG envelope parse result that preserves malformed-payload detail."""

    envelopes: list[EcgMessageEnvelope]
    error: EcgEnvelopeParseIssue | None = None
    warnings: tuple[EcgEnvelopeParseIssue, ...] = ()
    payload: bytes | None = None
    packet_metadata: dict[str, object] | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_ecg_candidate(self) -> bool:
        return self.payload is not None and looks_like_ecg_candidate_payload(self.payload)


def extract_ecg_messages(
    frame: bytes,
    skip_headers: bool = True,
) -> list[EcgMessageEnvelope]:
    """Extract ECG message envelopes without applying plot semantics.

    This is a low-risk bridge between ECG wrapper parsing and future decoder
    registry work. It preserves the existing parser path while exposing message
    payloads and data words for additional decoders.
    """
    payload = frame
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    if skip_headers:
        udp_frame = parse_ipv4_udp_frame(frame)
        if udp_frame is not None:
            payload = udp_frame.payload
            source_ip = udp_frame.source_ip
            destination_ip = udp_frame.destination_ip
            source_port = udp_frame.source_port
            destination_port = udp_frame.destination_port
        elif not looks_like_ecg_payload(frame):
            return []

    if len(payload) < ECG_MIN_PAYLOAD_BYTES:
        return []

    ecg_payload_length = int.from_bytes(payload[:2], "big")
    if ecg_payload_length != len(payload) - ECG_LENGTH_TRAILER_BYTES:
        return []

    artcc = _decode_text(payload[ARTCC_START:ARTCC_END])
    ecg_message = payload[ECG_MESSAGE_OFFSET]
    router_timestamp = (
        int.from_bytes(payload[ROUTER_TIMESTAMP_START:ROUTER_TIMESTAMP_END], BYTE_ORDER)
        * ROUTER_TIMESTAMP_SCALE
    )
    offset = ECG_MESSAGE_BLOCK_HEADER_BYTES

    envelopes: list[EcgMessageEnvelope] = []

    while offset < len(payload):
        if offset + ECG_MESSAGE_BLOCK_HEADER_BYTES > len(payload):
            break

        message_data_length = int.from_bytes(
            payload[offset : offset + BYTES_PER_WORD], BYTE_ORDER
        )
        if message_data_length == 0:
            offset += 1
            continue

        message_payload_start = offset + ECG_MESSAGE_BLOCK_HEADER_BYTES
        message_payload_end = message_payload_start + message_data_length
        if message_payload_end > len(payload):
            break

        message_payload = payload[message_payload_start:message_payload_end]
        words = message_data_length // BYTES_PER_WORD
        data_words = tuple(
            int.from_bytes(
                message_payload[
                    index * BYTES_PER_WORD : index * BYTES_PER_WORD + BYTES_PER_WORD
                ],
                BYTE_ORDER,
            )
            for index in range(words)
            if index * BYTES_PER_WORD + BYTES_PER_WORD <= len(message_payload)
        )

        beacon_message, search_message, rtqc_message, modec_valid = _classify_message(
            payload=payload,
            message_payload_start=message_payload_start,
            words=words,
        )

        if beacon_message:
            message_type = "beacon"
        elif search_message:
            message_type = "search"
        elif rtqc_message:
            message_type = "rtqc"
        else:
            message_type = "none"

        message_code = payload[offset + MESSAGE_CODE_OFFSET]
        envelopes.append(
            EcgMessageEnvelope(
                artcc=artcc,
                site_id=_strip_trailing_null(
                    _decode_text(payload[offset + SITE_ID_OFFSET_START : offset + SITE_ID_OFFSET_END])
                ),
                ecg_message=ecg_message,
                message_code=message_code,
                message_name=_message_name(message_code),
                sequence=payload[offset + SEQUENCE_OFFSET],
                channel=(payload[offset + CHANNEL_OFFSET] & CHANNEL_MASK) >> CHANNEL_SHIFT,
                router_timestamp=router_timestamp,
                radar_timestamp=(
                    int.from_bytes(
                        payload[
                            offset + RADAR_TIMESTAMP_OFFSET_START : offset + RADAR_TIMESTAMP_OFFSET_END
                        ],
                        BYTE_ORDER,
                    )
                    * RADAR_TIMESTAMP_SCALE
                ),
                message_data_length=message_data_length,
                message_payload=message_payload,
                data_words=data_words,
                message_type=message_type,
                modec_valid=modec_valid,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
            )
        )

        offset = message_payload_end

    return envelopes

def extract_ecg_messages_with_errors(
    frame: bytes,
    skip_headers: bool = True,
) -> EcgEnvelopeParseResult:
    """Extract ECG envelopes and expose malformed ECG-looking payload errors.

    Existing extract_ecg_messages and parse_frame behavior intentionally remain
    unchanged. This API is for the production live path, where malformed
    ECG-looking UDP payloads must become explicit error records.
    """

    payload, packet_metadata = _resolve_ecg_payload_and_metadata(frame, skip_headers)

    if payload is None:
        return EcgEnvelopeParseResult(
            envelopes=[],
            payload=None,
            packet_metadata=packet_metadata,
        )

    if not looks_like_ecg_candidate_payload(payload):
        return EcgEnvelopeParseResult(
            envelopes=[],
            payload=payload,
            packet_metadata=packet_metadata,
        )

    if len(payload) < ECG_MIN_PAYLOAD_BYTES:
        return EcgEnvelopeParseResult(
            envelopes=[],
            error=EcgEnvelopeParseIssue(
                code=ECG_ERROR_SHORT_PAYLOAD,
                message="ECG-looking payload is shorter than minimum ECG envelope",
                parser_stage="ecg_envelope",
            ),
            payload=payload,
            packet_metadata=packet_metadata,
        )

    ecg_payload_length = int.from_bytes(payload[:BYTES_PER_WORD], BYTE_ORDER)
    expected_payload_length = len(payload) - ECG_LENGTH_TRAILER_BYTES
    if ecg_payload_length != expected_payload_length:
        return EcgEnvelopeParseResult(
            envelopes=[],
            error=EcgEnvelopeParseIssue(
                code=ECG_ERROR_LENGTH_MISMATCH,
                message=(
                    "ECG length field does not match payload length: "
                    f"declared={ecg_payload_length} expected={expected_payload_length}"
                ),
                parser_stage="ecg_envelope",
            ),
            payload=payload,
            packet_metadata=packet_metadata,
        )

    block_issue = _validate_ecg_message_blocks(payload)
    if block_issue is not None:
        return EcgEnvelopeParseResult(
            envelopes=[],
            error=block_issue,
            payload=payload,
            packet_metadata=packet_metadata,
        )

    envelopes = extract_ecg_messages(frame, skip_headers=skip_headers)
    warnings = tuple(_warnings_for_envelope(envelope) for envelope in envelopes if _warnings_for_envelope(envelope) is not None)

    return EcgEnvelopeParseResult(
        envelopes=envelopes,
        warnings=warnings,
        payload=payload,
        packet_metadata=packet_metadata,
    )


def parse_frame(
    frame: bytes,
    observer_interface: str | None = None,
    skip_headers: bool = True,
    timestamp: str | None = None,
) -> list[ParsedPlot]:
    """Parse one Ethernet/IP/UDP frame or one raw ECG payload.

    This is a pure extraction of the field-tested ECG parser path. It does not open
    sockets, write files, launch threads, or run detector state.
    """
    total_bytes = len(frame)
    payload = frame
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    if skip_headers:
        udp_frame = parse_ipv4_udp_frame(frame)
        if udp_frame is not None:
            payload = udp_frame.payload
            source_ip = udp_frame.source_ip
            destination_ip = udp_frame.destination_ip
            source_port = udp_frame.source_port
            destination_port = udp_frame.destination_port
        elif not looks_like_ecg_payload(frame):
            return []

    if len(payload) < ECG_MIN_PAYLOAD_BYTES:
        return []

    ecg_payload_length = _read_uint16(payload, 0)
    if ecg_payload_length != len(payload) - ECG_LENGTH_TRAILER_BYTES:
        return []

    artcc = _decode_text(payload[ARTCC_START:ARTCC_END])
    ecg_message = payload[ECG_MESSAGE_OFFSET]
    router_timestamp = _read_scaled_uint32(
        payload,
        ROUTER_TIMESTAMP_START,
        ROUTER_TIMESTAMP_END,
        ROUTER_TIMESTAMP_SCALE,
    )
    offset = ECG_MESSAGE_BLOCK_HEADER_BYTES

    if ecg_message != 1:
        return []

    records: list[ParsedPlot] = []

    while offset < len(payload):
        if offset + ECG_MESSAGE_BLOCK_HEADER_BYTES > len(payload):
            break

        message_data_length = _message_data_length(payload, offset)
        if message_data_length == 0:
            offset += 1
            continue

        message_payload_start = offset + ECG_MESSAGE_BLOCK_HEADER_BYTES
        message_payload_end = message_payload_start + message_data_length
        if message_payload_end > len(payload):
            break

        words = message_data_length // BYTES_PER_WORD
        record = _create_plot(
            payload=payload,
            offset=offset,
            observer_interface=observer_interface,
            total_bytes=total_bytes,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            artcc=artcc,
            router_timestamp=router_timestamp,
            timestamp=timestamp,
        )

        beacon_message, search_message, rtqc_message, modec_valid = _classify_message(
            payload=payload,
            message_payload_start=message_payload_start,
            words=words,
        )

        if beacon_message:
            record.message_type = "beacon"
        elif search_message:
            record.message_type = "search"
        elif rtqc_message:
            record.message_type = "rtqc"
        else:
            record.message_type = "none"

        if (beacon_message or search_message) and record.message in {"cd-2", "cd-asr", "mar"}:
            _extract_plot_words(
                payload=payload,
                message_payload_start=message_payload_start,
                message_payload_end=message_payload_end,
                words=words,
                beacon_message=beacon_message,
                modec_valid=modec_valid,
                record=record,
            )
            record.fingerprint = sha256(
                payload[:ECG_MESSAGE_BLOCK_HEADER_BYTES]
                + payload[message_payload_start:message_payload_end]
            ).hexdigest()
            if rtqc_message:
                record.extra["classification_flags"] = ["rtqc_bit_set"]
            records.append(record)
        elif rtqc_message:
            record.alert = "RTQC"
            record.alert_details = "RTQC message detected."
            records.append(record)

        offset = message_payload_end

    return records

def parse_frames(
    frames: Iterable[bytes],
    observer_interface: str | None = None,
    skip_headers: bool = True,
    timestamp: str | None = None,
) -> list[ParsedPlot]:
    records: list[ParsedPlot] = []
    for frame in frames:
        records.extend(
            parse_frame(
                frame,
                observer_interface=observer_interface,
                skip_headers=skip_headers,
                timestamp=timestamp,
            )
        )
    return records

def _create_plot(
    payload: bytes,
    offset: int,
    observer_interface: str | None,
    total_bytes: int,
    source_ip: str | None,
    destination_ip: str | None,
    source_port: int | None,
    destination_port: int | None,
    artcc: str,
    router_timestamp: float,
    timestamp: str | None,
) -> ParsedPlot:
    site_id = _site_id_at(payload, offset)
    message_code = _message_code_at(payload, offset)

    return ParsedPlot(
        timestamp=timestamp or datetime.now().isoformat(),
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        observer_interface=observer_interface,
        total_bytes=total_bytes,
        artcc=artcc,
        site_id=site_id,
        sequence=_sequence_at(payload, offset),
        channel=_channel_at(payload, offset),
        message=_message_name(message_code),
        router_timestamp=router_timestamp,
        radar_timestamp=_radar_timestamp_at(payload, offset),
        range_nm=-1,
        mode_3_code=-1,
        acp=-1,
        azimuth_degrees=-1,
        altitude_feet=-1,
    )

def _read_uint16(payload: bytes, offset: int) -> int:
    return int.from_bytes(payload[offset : offset + BYTES_PER_WORD], BYTE_ORDER)


def _read_scaled_uint32(payload: bytes, start: int, end: int, scale: float) -> float:
    return int.from_bytes(payload[start:end], BYTE_ORDER) * scale


def _message_data_length(payload: bytes, offset: int) -> int:
    return _read_uint16(payload, offset)


def _site_id_at(payload: bytes, offset: int) -> str:
    return _strip_trailing_null(
        _decode_text(payload[offset + SITE_ID_OFFSET_START : offset + SITE_ID_OFFSET_END])
    )


def _message_code_at(payload: bytes, offset: int) -> int:
    return payload[offset + MESSAGE_CODE_OFFSET]


def _sequence_at(payload: bytes, offset: int) -> int:
    return payload[offset + SEQUENCE_OFFSET]


def _channel_at(payload: bytes, offset: int) -> int:
    return (payload[offset + CHANNEL_OFFSET] & CHANNEL_MASK) >> CHANNEL_SHIFT


def _radar_timestamp_at(payload: bytes, offset: int) -> float:
    return _read_scaled_uint32(
        payload,
        offset + RADAR_TIMESTAMP_OFFSET_START,
        offset + RADAR_TIMESTAMP_OFFSET_END,
        RADAR_TIMESTAMP_SCALE,
    )


def _classify_message(
    payload: bytes,
    message_payload_start: int,
    words: int,
) -> tuple[bool, bool, bool, bool]:
    if words <= 0 or message_payload_start + FIRST_WORD_BYTES > len(payload):
        return False, False, False, False

    first_word = int.from_bytes(
        payload[message_payload_start : message_payload_start + FIRST_WORD_BYTES],
        BYTE_ORDER,
    )
    first_byte = payload[message_payload_start]
    second_byte = payload[message_payload_start + 1]

    beacon_message = (
        (first_byte & BEACON_MESSAGE_MASK) >> BEACON_MESSAGE_SHIFT
        == BEACON_MESSAGE_PATTERN
    )
    modec_valid = (second_byte & MODEC_VALID_MASK) >> MODEC_VALID_SHIFT == 1
    rtqc_message = (first_byte & RTQC_MESSAGE_MASK) >> RTQC_MESSAGE_SHIFT == 1
    search_message = (
        words > RANGE_WORD_INDEX
        and (first_word & SEARCH_MESSAGE_MASK) >> SEARCH_MESSAGE_SHIFT
        == SEARCH_MESSAGE_PATTERN
    )

    return beacon_message, search_message, rtqc_message, modec_valid

def _extract_plot_words(
    payload: bytes,
    message_payload_start: int,
    message_payload_end: int,
    words: int,
    beacon_message: bool,
    modec_valid: bool,
    record: ParsedPlot,
) -> None:
    for index in range(words):
        word_offset = message_payload_start + index * BYTES_PER_WORD
        if word_offset + BYTES_PER_WORD > message_payload_end:
            break

        word = int.from_bytes(
            payload[word_offset : word_offset + BYTES_PER_WORD], BYTE_ORDER
        )

        if index == RANGE_WORD_INDEX:
            record.range_nm = int((word & RANGE_WORD_MASK) >> RANGE_WORD_SHIFT) * RANGE_NM_SCALE
        elif index == ACP_WORD_INDEX:
            record.acp = word & ACP_WORD_MASK
            record.azimuth_degrees = int(word & ACP_WORD_MASK) * ACP_DEGREES_PER_COUNT
        elif index == MODE_3_WORD_INDEX:
            record.mode_3_code = int(oct(int(word & MODE_3_WORD_MASK))[2:])
        elif index == ALTITUDE_WORD_INDEX and beacon_message and modec_valid:
            altitude = int(word & ALTITUDE_WORD_MASK) * ALTITUDE_FEET_SCALE
            if int((word & ALTITUDE_SIGN_MASK) >> ALTITUDE_SIGN_SHIFT) == 1:
                altitude *= -1
            record.altitude_feet = altitude

def _resolve_ecg_payload_and_metadata(
    frame: bytes,
    skip_headers: bool,
) -> tuple[bytes | None, dict[str, object]]:
    if not skip_headers:
        return frame, {}

    udp_frame = parse_ipv4_udp_frame(frame)
    if udp_frame is not None:
        return udp_frame.payload, {
            "source_ip": udp_frame.source_ip,
            "source_port": udp_frame.source_port,
            "destination_ip": udp_frame.destination_ip,
            "destination_port": udp_frame.destination_port,
            "ip_total_length": udp_frame.total_length,
        }

    if looks_like_ecg_candidate_payload(frame):
        return frame, {}

    return None, {}


def _validate_ecg_message_blocks(payload: bytes) -> EcgEnvelopeParseIssue | None:
    offset = ECG_MESSAGE_BLOCK_HEADER_BYTES

    while offset < len(payload):
        if offset + ECG_MESSAGE_BLOCK_HEADER_BYTES > len(payload):
            return EcgEnvelopeParseIssue(
                code=ECG_ERROR_MESSAGE_BLOCK_TRUNCATED,
                message="ECG message block header overruns payload",
                parser_stage="ecg_message_block",
            )

        message_data_length = int.from_bytes(
            payload[offset : offset + BYTES_PER_WORD],
            BYTE_ORDER,
        )
        if message_data_length == 0:
            offset += 1
            continue

        message_payload_start = offset + ECG_MESSAGE_BLOCK_HEADER_BYTES
        message_payload_end = message_payload_start + message_data_length
        if message_payload_end > len(payload):
            return EcgEnvelopeParseIssue(
                code=ECG_ERROR_MESSAGE_BLOCK_TRUNCATED,
                message="ECG message block payload overruns payload",
                parser_stage="ecg_message_block",
            )

        offset = message_payload_end

    return None


def _warnings_for_envelope(envelope: EcgMessageEnvelope) -> EcgEnvelopeParseIssue | None:
    if envelope.message_name == "none":
        return EcgEnvelopeParseIssue(
            code=ECG_WARNING_UNKNOWN_MESSAGE_CODE,
            message=f"ECG message code is unmapped: {envelope.message_code}",
            parser_stage="ecg_message_block",
        )
    return None


def looks_like_ecg_candidate_payload(data: bytes) -> bool:
    if len(data) < ECG_MESSAGE_OFFSET + 1:
        return False

    declared_length = int.from_bytes(data[:BYTES_PER_WORD], BYTE_ORDER)
    if declared_length < 1:
        return False

    artcc = data[ARTCC_START:ARTCC_END]
    if len(artcc) != ARTCC_END - ARTCC_START:
        return False

    for value in artcc:
        if not (value == 0x20 or 0x30 <= value <= 0x39 or 0x41 <= value <= 0x5A):
            return False

    return data[ECG_MESSAGE_OFFSET] != 0


def looks_like_ecg_payload(data: bytes) -> bool:
    return (
        len(data) >= ECG_MIN_PAYLOAD_BYTES
        and int.from_bytes(data[:BYTES_PER_WORD], BYTE_ORDER)
        == len(data) - ECG_LENGTH_TRAILER_BYTES
    )

def _decode_text(value: bytes) -> str:
    try:
        return value.decode(TEXT_ENCODING)
    except UnicodeDecodeError:
        return value.decode(FALLBACK_TEXT_ENCODING, errors=TEXT_DECODE_ERRORS)

def _strip_trailing_null(value: str) -> str:
    return value.rstrip("\x00")

def _message_name(code: int) -> str:
    return MESSAGE_NAME_BY_CODE.get(code, "none")

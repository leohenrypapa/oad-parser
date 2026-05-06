"""CD2 protocol helpers.

The legacy ECG parser consumes already segmented UDP payloads. This module is the
spec-backed CD2 layer: 13-bit word handling, idle-word synchronization, parity
checking, EOM detection, and lightweight diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

from oad_parser.protocols.cd2_spec import (
    BITS_PER_BYTE,
    CD2_DATA_BITS,
    CD2_DATA_MASK,
    CD2_DEFAULT_RECEIVE_FRAME_SIZE_WORDS,
    CD2_EXTENDED_ERROR_EOM,
    CD2_EXTENDED_ERROR_EOM_SHIFT,
    CD2_EXTENDED_ERROR_PARITY,
    CD2_EXTENDED_ERROR_PARITY_SHIFT,
    CD2_IDLE_WORD,
    CD2_MIN_RECEIVE_FRAME_SIZE_WORDS,
    CD2_WIRE_WORD_LIMIT,
    CD2_WORD_BITS,
    CLIENT_WORD_BITS,
    CLIENT_WORD_MAX,
    LEGACY_CLIENT_DATA_SHIFT_WITHOUT_PARITY,
    LEGACY_CLIENT_DATA_SHIFT_WITH_PARITY,
    PARITY_BIT_MASK,
    SPEC_CLIENT_DATA_SHIFT_WITH_PARITY,
)

# Backward-compatible public names for callers/tests that imported constants
# from oad_parser.parsers.cd2 before the spec module was introduced.
DEFAULT_RECEIVE_FRAME_SIZE_WORDS = CD2_DEFAULT_RECEIVE_FRAME_SIZE_WORDS
MIN_RECEIVE_FRAME_SIZE_WORDS = CD2_MIN_RECEIVE_FRAME_SIZE_WORDS
EXTENDED_ERROR_PARITY_SHIFT = CD2_EXTENDED_ERROR_PARITY_SHIFT
EXTENDED_ERROR_EOM_SHIFT = CD2_EXTENDED_ERROR_EOM_SHIFT
EXTENDED_ERROR_PARITY = CD2_EXTENDED_ERROR_PARITY
EXTENDED_ERROR_EOM = CD2_EXTENDED_ERROR_EOM

ParityMode = Literal["odd", "even"]


@dataclass(frozen=True)
class Cd2LinkConfig:
    """Runtime behavior for one CD2 link.

    Defaults follow DC-900-1607F where practical: add/remove parity disabled,
    receive frame size of 32 words, error screening disabled, and data inversion
    disabled. Parity mode remains configurable because fielded systems should be
    validated against known-good captures.
    """

    add_remove_parity: bool = False
    receive_frame_size_words: int = CD2_DEFAULT_RECEIVE_FRAME_SIZE_WORDS
    error_screening: bool = False
    data_inversion: bool = False
    parity_mode: ParityMode = "odd"

    def __post_init__(self) -> None:
        if self.receive_frame_size_words < CD2_MIN_RECEIVE_FRAME_SIZE_WORDS:
            raise ValueError("receive_frame_size_words must be >= 1")
        if self.parity_mode not in {"odd", "even"}:
            raise ValueError("parity_mode must be 'odd' or 'even'")


@dataclass(frozen=True)
class Cd2Word:
    """Decoded 13-bit CD2 wire word."""

    raw: int
    index: int
    data_bits: int
    parity_bit: int | None
    parity_valid: bool | None
    is_idle: bool
    bit_offset: int | None = None
    byte_offset: int | None = None

    def to_dict(self) -> dict[str, int | bool | None]:
        return {
            "index": self.index,
            "raw": self.raw,
            "data_bits": self.data_bits,
            "parity_bit": self.parity_bit,
            "parity_valid": self.parity_valid,
            "is_idle": self.is_idle,
            "bit_offset": self.bit_offset,
            "byte_offset": self.byte_offset,
        }


@dataclass(frozen=True)
class Cd2Frame:
    """One CD2 message extracted from a synchronized 13-bit word stream."""

    words: tuple[Cd2Word, ...]
    start_word_index: int
    end_word_index: int
    extended_error_status: int = 0
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_errors(self) -> bool:
        return self.extended_error_status != 0 or bool(self.errors)

    @property
    def data_words(self) -> tuple[int, ...]:
        return tuple(word.data_bits for word in self.words)

    def to_dict(self) -> dict[str, object]:
        return {
            "start_word_index": self.start_word_index,
            "end_word_index": self.end_word_index,
            "word_count": len(self.words),
            "extended_error_status": self.extended_error_status,
            "errors": list(self.errors),
            "data_words": list(self.data_words),
        }


def is_idle_word(word: int) -> bool:
    return normalize_13_bit_word(word) == CD2_IDLE_WORD


def normalize_13_bit_word(word: int) -> int:
    if word < 0 or word >= CD2_WIRE_WORD_LIMIT:
        raise ValueError("CD2 wire word must fit in 13 bits")
    return word


def validate_client_word(word: int) -> None:
    if word < 0 or word > CLIENT_WORD_MAX:
        raise ValueError("CD2 client word must fit in 16 bits")


def extract_12_data_bits_from_client_word(word: int, parity_present: bool = True) -> int:
    """Backward-compatible extraction for existing legacy tests.

    This preserves the source-pack baseline behavior. New spec-oriented code
    should prefer decode_wire_word for 13-bit serial words or
    decode_client_data_area_word for 16-bit client/ICP data-area words.
    """
    validate_client_word(word)

    if parity_present:
        return (word >> LEGACY_CLIENT_DATA_SHIFT_WITH_PARITY) & CD2_DATA_MASK

    return (word >> LEGACY_CLIENT_DATA_SHIFT_WITHOUT_PARITY) & CD2_DATA_MASK


def extract_spec_data_bits_from_client_word(word: int, parity_present: bool = True) -> int:
    """Extract 12 data bits from a 16-bit data-area word using the guide layout.

    With parity present: three high padding bits, 12 data bits, one parity bit.
    Without parity present: four high padding bits, 12 data bits.
    """
    validate_client_word(word)
    if parity_present:
        return (word >> SPEC_CLIENT_DATA_SHIFT_WITH_PARITY) & CD2_DATA_MASK
    return word & CD2_DATA_MASK


def extract_spec_parity_bit_from_client_word(word: int) -> int:
    validate_client_word(word)
    return word & PARITY_BIT_MASK


def count_set_bits(value: int) -> int:
    """Return the number of one bits using Python 3.9-compatible logic."""
    if value < 0:
        raise ValueError("value must be non-negative")
    count = 0
    while value:
        value &= value - 1
        count += 1
    return count


def calculate_parity_bit(data_bits: int, mode: ParityMode = "odd") -> int:
    if data_bits < 0 or data_bits > CD2_DATA_MASK:
        raise ValueError("CD2 data bits must fit in 12 bits")
    ones = count_set_bits(data_bits)
    if mode == "odd":
        return 0 if ones % 2 else 1
    if mode == "even":
        return 1 if ones % 2 else 0
    raise ValueError("parity mode must be 'odd' or 'even'")


def parity_is_valid(data_bits: int, parity_bit: int, mode: ParityMode = "odd") -> bool:
    if parity_bit not in {0, 1}:
        raise ValueError("parity bit must be 0 or 1")
    return parity_bit == calculate_parity_bit(data_bits, mode=mode)


def decode_wire_word(word: int, index: int = 0, config: Cd2LinkConfig | None = None) -> Cd2Word:
    """Decode one 13-bit CD2 serial word.

    A non-idle data word is represented as 12 data bits followed by a parity bit.
    When add/remove parity is enabled, callers may treat parity as managed by ICP;
    this function still exposes the 13th bit when present on the wire.
    """
    config = config or Cd2LinkConfig()
    raw = normalize_13_bit_word(word)
    if config.data_inversion:
        raw ^= CD2_WIRE_WORD_LIMIT - 1

    idle = raw == CD2_IDLE_WORD
    data_bits = (raw >> SPEC_CLIENT_DATA_SHIFT_WITH_PARITY) & CD2_DATA_MASK
    parity_bit = raw & PARITY_BIT_MASK
    valid = None if idle else parity_is_valid(data_bits, parity_bit, mode=config.parity_mode)

    return Cd2Word(
        raw=raw,
        index=index,
        data_bits=data_bits,
        parity_bit=parity_bit,
        parity_valid=valid,
        is_idle=idle,
    )


def decode_client_data_area_word(
    word: int,
    index: int = 0,
    config: Cd2LinkConfig | None = None,
) -> Cd2Word:
    """Decode one 16-bit client/ICP data-area word using DC-900-1607F layout."""
    config = config or Cd2LinkConfig()
    validate_client_word(word)
    value = word ^ CLIENT_WORD_MAX if config.data_inversion else word
    parity_present = not config.add_remove_parity
    data_bits = extract_spec_data_bits_from_client_word(value, parity_present=parity_present)
    parity_bit = extract_spec_parity_bit_from_client_word(value) if parity_present else None
    valid = None
    if parity_bit is not None:
        valid = parity_is_valid(data_bits, parity_bit, mode=config.parity_mode)

    raw = ((data_bits & CD2_DATA_MASK) << SPEC_CLIENT_DATA_SHIFT_WITH_PARITY) | (parity_bit or 0)
    return Cd2Word(
        raw=raw,
        index=index,
        data_bits=data_bits,
        parity_bit=parity_bit,
        parity_valid=valid,
        is_idle=is_idle_word(raw),
    )


def iter_msb_bits(data: bytes) -> Iterable[int]:
    for byte in data:
        for shift in range(BITS_PER_BYTE - 1, -1, -1):
            yield (byte >> shift) & 0x1


def iter_13_bit_words_from_bytes(data: bytes, config: Cd2LinkConfig | None = None) -> Iterable[Cd2Word]:
    """Yield full 13-bit words from an MSB-first byte stream.

    Trailing partial bits are ignored because they cannot form a CD2 word.
    """
    config = config or Cd2LinkConfig()
    value = 0
    bits_collected = 0
    word_index = 0
    bit_offset = 0

    for bit in iter_msb_bits(data):
        value = (value << 1) | bit
        bits_collected += 1
        if bits_collected == CD2_WORD_BITS:
            word = decode_wire_word(value, index=word_index, config=config)
            yield Cd2Word(
                raw=word.raw,
                index=word.index,
                data_bits=word.data_bits,
                parity_bit=word.parity_bit,
                parity_valid=word.parity_valid,
                is_idle=word.is_idle,
                bit_offset=bit_offset,
                byte_offset=bit_offset // BITS_PER_BYTE,
            )
            word_index += 1
            bit_offset += CD2_WORD_BITS
            value = 0
            bits_collected = 0


def frame_words(words: Iterable[Cd2Word], config: Cd2LinkConfig | None = None) -> list[Cd2Frame]:
    """Segment decoded CD2 words into messages using idle-word sync."""
    config = config or Cd2LinkConfig()
    frames: list[Cd2Frame] = []
    current: list[Cd2Word] = []
    synced = False
    frame_start = 0
    errors: list[str] = []
    status = 0

    for word in words:
        if word.is_idle:
            synced = True
            if current:
                frames.append(
                    Cd2Frame(
                        words=tuple(current),
                        start_word_index=frame_start,
                        end_word_index=word.index - 1,
                        extended_error_status=status,
                        errors=tuple(errors),
                    )
                )
                current = []
                errors = []
                status = 0
            continue

        if not synced:
            continue

        if not current:
            frame_start = word.index

        if word.parity_valid is False:
            status |= CD2_EXTENDED_ERROR_PARITY
            errors.append(f"parity error at word {word.index}")

        current.append(word)

        if len(current) > config.receive_frame_size_words:
            status |= CD2_EXTENDED_ERROR_EOM
            errors.append(
                f"EOM error: frame exceeded {config.receive_frame_size_words} CD2 data words"
            )
            frames.append(
                Cd2Frame(
                    words=tuple(current),
                    start_word_index=frame_start,
                    end_word_index=word.index,
                    extended_error_status=status,
                    errors=tuple(errors),
                )
            )
            current = []
            errors = []
            status = 0
            synced = False

    return frames


def frame_13_bit_values(values: Iterable[int], config: Cd2LinkConfig | None = None) -> list[Cd2Frame]:
    config = config or Cd2LinkConfig()
    return frame_words(
        (decode_wire_word(value, index=index, config=config) for index, value in enumerate(values)),
        config=config,
    )


def frame_byte_stream(data: bytes, config: Cd2LinkConfig | None = None) -> list[Cd2Frame]:
    config = config or Cd2LinkConfig()
    return frame_words(iter_13_bit_words_from_bytes(data, config=config), config=config)


def pack_13_bit_words_to_bytes(values: Iterable[int]) -> bytes:
    """Pack 13-bit word values into an MSB-first byte stream for tests/tools."""
    bits: list[int] = []
    for value in values:
        raw = normalize_13_bit_word(value)
        for shift in range(CD2_WORD_BITS - 1, -1, -1):
            bits.append((raw >> shift) & 0x1)

    output = bytearray()
    while bits:
        chunk = bits[:BITS_PER_BYTE]
        del bits[:BITS_PER_BYTE]
        while len(chunk) < BITS_PER_BYTE:
            chunk.append(0)
        byte = 0
        for bit in chunk:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)

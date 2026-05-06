"""CD2 protocol constants sourced from DC-900-1607F.

These values describe the CD2 client/ICP protocol layer only. They do not encode
radar-message semantics.
"""

from __future__ import annotations

from dataclasses import dataclass


CD2_MANUAL_ID = "DC-900-1607F"
CD2_MANUAL_TITLE = "CD2 Military/Government Protocol Programmer's Guide"
CD2_MANUAL_VERSION = "F"
CD2_MANUAL_RELEASE = "September 2011"


@dataclass(frozen=True)
class Cd2ManualReference:
    """Source location for a manual-derived CD2 value."""

    manual_id: str
    section: str
    page: int
    note: str


CD2_DATA_FORMATS_REFERENCE = Cd2ManualReference(
    manual_id=CD2_MANUAL_ID,
    section="Chapter 1 / Sections 1.1-1.2",
    page=13,
    note="CD2 data word, idle word, transmission, and reception framing.",
)
CD2_LINK_OPTIONS_REFERENCE = Cd2ManualReference(
    manual_id=CD2_MANUAL_ID,
    section="Chapter 2 / Table 2-1",
    page=20,
    note="CD2 link configuration option numbers, values, and defaults.",
)
CD2_COMMAND_RESPONSE_REFERENCE = Cd2ManualReference(
    manual_id=CD2_MANUAL_ID,
    section="Chapter 3",
    page=27,
    note="CD2 protocol selection code and link statistics report fields.",
)

CD2_SPEC_PROVENANCE = {
    "CD2_WORD_BITS": CD2_DATA_FORMATS_REFERENCE,
    "CD2_DATA_BITS": CD2_DATA_FORMATS_REFERENCE,
    "CD2_IDLE_WORD": Cd2ManualReference(
        manual_id=CD2_MANUAL_ID,
        section="Section 1.1 / Section 1.2",
        page=14,
        note="Idle word is 0001111111111; idle words synchronize reception and delimit messages.",
    ),
    "CD2_EXTENDED_ERROR_PARITY_SHIFT": Cd2ManualReference(
        manual_id=CD2_MANUAL_ID,
        section="Section 1.2",
        page=14,
        note="Extended Error Status bit 0 reports parity errors.",
    ),
    "CD2_EXTENDED_ERROR_EOM_SHIFT": Cd2ManualReference(
        manual_id=CD2_MANUAL_ID,
        section="Section 1.2",
        page=14,
        note="Extended Error Status bit 5 reports EOM errors.",
    ),
    "CD2_PROTOCOL_SELECTION_CODE": CD2_COMMAND_RESPONSE_REFERENCE,
    "CD2_ADD_REMOVE_PARITY_OPTION_NUMBER": Cd2ManualReference(
        manual_id=CD2_MANUAL_ID,
        section="Section 2.12 / Table 2-1",
        page=23,
        note="Add/Remove Parity link option number is 22.",
    ),
    "CD2_RECEIVE_FRAME_SIZE_OPTION_NUMBER": Cd2ManualReference(
        manual_id=CD2_MANUAL_ID,
        section="Section 2.13 / Table 2-1",
        page=24,
        note="Receive Frame Size link option number is 26; default is 32 words.",
    ),
}

CD2_WORD_BITS = 13
CD2_DATA_BITS = 12
CLIENT_WORD_BITS = 16
BITS_PER_BYTE = 8

CD2_DATA_MASK = (1 << CD2_DATA_BITS) - 1
CD2_WIRE_WORD_LIMIT = 1 << CD2_WORD_BITS
CLIENT_WORD_MAX = (1 << CLIENT_WORD_BITS) - 1
PARITY_BIT_MASK = 0x1

CD2_IDLE_WORD = 0b0001111111111

CD2_EXTENDED_ERROR_PARITY_SHIFT = 0
CD2_EXTENDED_ERROR_EOM_SHIFT = 5
CD2_EXTENDED_ERROR_PARITY = 1 << CD2_EXTENDED_ERROR_PARITY_SHIFT
CD2_EXTENDED_ERROR_EOM = 1 << CD2_EXTENDED_ERROR_EOM_SHIFT

CD2_PROTOCOL_OPTION_NUMBER = -1
CD2_PROTOCOL_SELECTION_CODE = 11

CD2_ADD_REMOVE_PARITY_OPTION_NUMBER = 22
CD2_RECEIVE_FRAME_SIZE_OPTION_NUMBER = 26
CD2_DEFAULT_RECEIVE_FRAME_SIZE_WORDS = 32
CD2_MIN_RECEIVE_FRAME_SIZE_WORDS = 1

CD2_DEFAULT_DATA_RATE_BPS = 9600

CD2_LINK_STATISTICS_WORDS = {
    "messages_received": 3,
    "parity_errors": 4,
    "receive_character_overruns": 6,
    "transmit_character_underruns": 7,
    "messages_received_with_no_errors": 8,
    "messages_received_with_errors": 9,
    "eom_errors": 13,
    "messages_transmitted": 17,
    "lost_receive_messages_no_receive_buffer": 18,
}

LEGACY_CLIENT_DATA_SHIFT_WITH_PARITY = 3
LEGACY_CLIENT_DATA_SHIFT_WITHOUT_PARITY = 4
SPEC_CLIENT_DATA_SHIFT_WITH_PARITY = 1

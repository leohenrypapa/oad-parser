"""CD2 link configuration option metadata from DC-900-1607F Table 2-1.

This module is manual-derived protocol metadata. It intentionally contains no
parser behavior and no provisional radar-message assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass

from oad_parser.protocols.cd2_spec import CD2_MANUAL_ID


@dataclass(frozen=True)
class Cd2LinkOption:
    """One CD2 link configuration option from DC-900-1607F Table 2-1."""

    name: str
    number: int
    default: object
    allowed_values: tuple[object, ...] | str
    setting: str
    section: str
    page: int


CD2_LINK_OPTIONS = (
    Cd2LinkOption(
        name="Protocol",
        number=-1,
        default=None,
        allowed_values=(11,),
        setting="11 = CD2",
        section="2.1 / Table 2-1",
        page=19,
    ),
    Cd2LinkOption(
        name="Data Rate",
        number=1,
        default=9600,
        allowed_values=(300, 600, 1200, 2400, 4800, 9600, 19200, 38400),
        setting="Bits per second",
        section="2.2 / Table 2-1",
        page=19,
    ),
    Cd2LinkOption(
        name="Clocking Source",
        number=2,
        default=2,
        allowed_values=(1, 2),
        setting="1 = External; 2 = Internal",
        section="2.3 / Table 2-1",
        page=21,
    ),
    Cd2LinkOption(
        name="Error Screening",
        number=3,
        default=2,
        allowed_values=(1, 2),
        setting="1 = Enable; 2 = Disable",
        section="2.4 / Table 2-1",
        page=21,
    ),
    Cd2LinkOption(
        name="Transmit Clocking",
        number=4,
        default=60,
        allowed_values="n = 1 to 60 seconds",
        setting="Monitor interval in seconds",
        section="2.5 / Table 2-1",
        page=22,
    ),
    Cd2LinkOption(
        name="Receive Clocking",
        number=5,
        default=60,
        allowed_values="n = 1 to 60 seconds",
        setting="Monitor interval in seconds",
        section="2.6 / Table 2-1",
        page=22,
    ),
    Cd2LinkOption(
        name="Data Inversion",
        number=11,
        default=1,
        allowed_values=(1, 2),
        setting="1 = Disable/spacing; 2 = Enable/marking",
        section="2.7 / Table 2-1",
        page=22,
    ),
    Cd2LinkOption(
        name="Electrical Interface",
        number=15,
        default=2,
        allowed_values=(2, 12, 13, 14),
        setting="2 = EIA-232; 12 = EIA-449; 13 = EIA-530; 14 = V.35",
        section="2.8 / Table 2-1",
        page=22,
    ),
    Cd2LinkOption(
        name="Internal Loopback",
        number=16,
        default=2,
        allowed_values=(1, 2),
        setting="1 = Enable; 2 = Disable",
        section="2.9 / Table 2-1",
        page=23,
    ),
    Cd2LinkOption(
        name="Request to Send",
        number=17,
        default=1,
        allowed_values=(1, 2),
        setting="1 = Enable; 2 = Disable",
        section="2.10 / Table 2-1",
        page=23,
    ),
    Cd2LinkOption(
        name="Transmit Acknowledgment Threshold",
        number=19,
        default=0,
        allowed_values="n = any 16-bit value",
        setting="Transmit acknowledgments disabled when zero",
        section="2.11 / Table 2-1",
        page=23,
    ),
    Cd2LinkOption(
        name="Add/Remove Parity",
        number=22,
        default=2,
        allowed_values=(1, 2),
        setting="1 = Enable; 2 = Disable",
        section="2.12 / Table 2-1",
        page=23,
    ),
    Cd2LinkOption(
        name="Receive Frame Size",
        number=26,
        default=32,
        allowed_values="n = 1 to communication buffer size / 2",
        setting="Maximum receive frame size in 16-bit data words",
        section="2.13 / Table 2-1",
        page=24,
    ),
    Cd2LinkOption(
        name="Data Direction",
        number=29,
        default=2,
        allowed_values=(1, 2, 3),
        setting="1 = Receive-only; 2 = Transmit and Receive; 3 = Transmit-only",
        section="2.14 / Table 2-1",
        page=24,
    ),
    Cd2LinkOption(
        name="Blocking Interval",
        number=36,
        default=1000,
        allowed_values="10 to 10000 milliseconds",
        setting="Input data segmentation buffer blocking interval",
        section="2.15 / Table 2-1",
        page=25,
    ),
)

CD2_LINK_OPTIONS_BY_NUMBER = {option.number: option for option in CD2_LINK_OPTIONS}
CD2_LINK_OPTIONS_MANUAL_ID = CD2_MANUAL_ID


def get_cd2_link_option(number: int) -> Cd2LinkOption:
    """Return CD2 link option metadata by option number."""

    try:
        return CD2_LINK_OPTIONS_BY_NUMBER[number]
    except KeyError as exc:
        raise ValueError(f"unknown CD2 link option number: {number}") from exc

"""Stateful detector engine.

Detector rules run after parsing. They annotate parsed records with alert fields
without changing the parser core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from oad_parser.models import ParsedPlot

DEFAULT_DISCOVERY_WINDOW_RECORDS = 100
DEFAULT_MAX_SEQUENCE_DELTA = 10
DEFAULT_MAX_RANGE_NM = 300.0
DEFAULT_MAX_AZIMUTH_JUMP_DEGREES = 45.0
DEFAULT_AZIMUTH_WINDOW_SECONDS = 1.0
SEQUENCE_NUMBER_MODULUS = 256
AZIMUTH_DEGREES_PER_CIRCLE = 360.0
LEGACY_SEQUENCE_DELTA_MIN = 15
LEGACY_SEQUENCE_DELTA_MAX = 240
LEGACY_CHANNEL_SITE_ARTCCS = {"ZHN", "WNN"}


@dataclass
class DetectionConfig:
    discovery_window_records: int = DEFAULT_DISCOVERY_WINDOW_RECORDS
    max_sequence_delta: int | None = DEFAULT_MAX_SEQUENCE_DELTA
    max_router_time_delta_seconds: float | None = None
    max_radar_time_delta_seconds: float | None = None
    min_range_nm: float | None = None
    max_range_nm: float | None = DEFAULT_MAX_RANGE_NM
    max_azimuth_jump_degrees: float | None = DEFAULT_MAX_AZIMUTH_JUMP_DEGREES
    azimuth_window_seconds: float | None = DEFAULT_AZIMUTH_WINDOW_SECONDS
    legacy_sequence_delta: bool = False


@dataclass
class SiteState:
    last_sequence: int | None = None
    last_router_timestamp: float | None = None
    last_radar_timestamp: float | None = None
    last_azimuth_degrees: float | None = None
    window_start_radar_timestamp: float | None = None
    min_azimuth_degrees: float = 360.0
    max_azimuth_degrees: float = 0.0


@dataclass
class DetectionFinding:
    rule: str
    alert: str
    details: str


@dataclass
class DetectionEngine:
    config: DetectionConfig = field(default_factory=DetectionConfig)
    record_count: int = 0
    sites: dict[str, SiteState] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)

    def process_records(self, records: Iterable[ParsedPlot]) -> list[ParsedPlot]:
        return [self.process_record(record) for record in records]

    def process_record(self, record: ParsedPlot) -> ParsedPlot:
        self.record_count += 1

        findings: list[DetectionFinding] = []
        findings.extend(self._detect_rtqc(record))
        findings.extend(self._detect_duplicate_fingerprint(record))
        findings.extend(self._detect_range(record))
        findings.extend(self._detect_site_state(record))

        if findings:
            record.alert = findings[0].alert
            record.alert_details = "; ".join(f"{item.rule}: {item.details}" for item in findings)

        return record

    def _detect_rtqc(self, record: ParsedPlot) -> list[DetectionFinding]:
        if record.message_type == "rtqc" or record.alert == "RTQC":
            return [
                DetectionFinding(
                    rule="rtqc",
                    alert="RTQC",
                    details="RTQC message detected.",
                )
            ]
        return []

    def _detect_duplicate_fingerprint(self, record: ParsedPlot) -> list[DetectionFinding]:
        if not record.fingerprint:
            return []

        current_timestamp = record.timestamp or datetime.now().isoformat()
        first_seen = self.fingerprints.get(record.fingerprint)
        self.fingerprints[record.fingerprint] = current_timestamp
        if first_seen is not None:
            return [
                DetectionFinding(
                    rule="fingerprint",
                    alert="Duplicate plot found.",
                    details=f"Duplicate plot originally transmitted at {first_seen}.",
                )
            ]

        return []

    def _detect_range(self, record: ParsedPlot) -> list[DetectionFinding]:
        if record.range_nm is None or record.range_nm < 0:
            return []

        if self.config.min_range_nm is not None and record.range_nm <= self.config.min_range_nm:
            return [
                DetectionFinding(
                    rule="range",
                    alert="plot detected at an impossible range.",
                    details=f"plot detected with an impossible range of {record.range_nm}.",
                )
            ]

        if self.config.max_range_nm is not None and record.range_nm >= self.config.max_range_nm:
            return [
                DetectionFinding(
                    rule="range",
                    alert="plot detected at an impossible range.",
                    details=f"plot detected with an impossible range of {record.range_nm}.",
                )
            ]

        return []

    def _detect_site_state(self, record: ParsedPlot) -> list[DetectionFinding]:
        site_key = _legacy_site_key(record)
        if not site_key:
            return []

        findings: list[DetectionFinding] = []
        state = self.sites.get(site_key)

        if state is None:
            if self.record_count > self.config.discovery_window_records:
                findings.append(
                    DetectionFinding(
                        rule="site_discovery",
                        alert="New unknown site discovered.",
                        details=f"New site {site_key} discovered after discovery window.",
                    )
                )

            self.sites[site_key] = SiteState(
                last_sequence=record.sequence,
                last_router_timestamp=record.router_timestamp,
                last_radar_timestamp=record.radar_timestamp,
                last_azimuth_degrees=record.azimuth_degrees,
                window_start_radar_timestamp=record.radar_timestamp,
                min_azimuth_degrees=_valid_azimuth_or_default(record.azimuth_degrees, 360.0),
                max_azimuth_degrees=_valid_azimuth_or_default(record.azimuth_degrees, 0.0),
            )
            return findings

        findings.extend(self._detect_sequence(record, state))
        findings.extend(self._detect_legacy_time_delta(record, state))
        findings.extend(self._detect_azimuth(record, state))

        self._update_site_state(record, state)
        return findings

    def _detect_sequence(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        if record.sequence is None or state.last_sequence is None:
            return []

        raw_delta = record.sequence - state.last_sequence
        if self.config.legacy_sequence_delta:
            record.sequence_delta = raw_delta
            if (
                LEGACY_SEQUENCE_DELTA_MIN <= raw_delta <= LEGACY_SEQUENCE_DELTA_MAX
                or -LEGACY_SEQUENCE_DELTA_MAX <= raw_delta <= -LEGACY_SEQUENCE_DELTA_MIN
            ):
                return [
                    DetectionFinding(
                        rule="sequence",
                        alert="Sequence delta between plots is too large.",
                        details=f"Sequence delta is: {raw_delta}",
                    )
                ]
            return []

        if self.config.max_sequence_delta is None:
            return []

        delta = (record.sequence - state.last_sequence) % SEQUENCE_NUMBER_MODULUS
        record.sequence_delta = delta

        if delta > self.config.max_sequence_delta:
            return [
                DetectionFinding(
                    rule="sequence",
                    alert="Sequence Delta",
                    details=f"sequence delta {delta} exceeds {self.config.max_sequence_delta}",
                )
            ]

        return []

    def _detect_legacy_time_delta(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        threshold = self.config.max_radar_time_delta_seconds
        use_router_time = record.artcc == "WNN"
        current = record.router_timestamp if use_router_time else record.radar_timestamp
        previous = state.last_router_timestamp if use_router_time else state.last_radar_timestamp

        if threshold is None or current is None or previous is None:
            return []

        delta = current - previous
        record.radar_time_delta = delta
        if use_router_time:
            record.router_time_delta = delta

        if delta > threshold:
            return [
                DetectionFinding(
                    rule="time_delta",
                    alert="Time delta between plots is too large.",
                    details=f"Time delta is: {round(delta, 2)} seconds.",
                )
            ]

        return []

    def _detect_azimuth(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        if self.config.max_azimuth_jump_degrees is None:
            return []

        if record.azimuth_degrees is None or record.azimuth_degrees < 0:
            return []

        if state.last_azimuth_degrees is None or state.last_azimuth_degrees < 0:
            return []

        if (
            self.config.azimuth_window_seconds is not None
            and record.radar_timestamp is not None
            and state.window_start_radar_timestamp is not None
        ):
            if record.radar_timestamp - state.window_start_radar_timestamp > self.config.azimuth_window_seconds:
                state.window_start_radar_timestamp = record.radar_timestamp
                state.min_azimuth_degrees = record.azimuth_degrees
                state.max_azimuth_degrees = record.azimuth_degrees
                return []

            min_azimuth = min(record.azimuth_degrees, state.min_azimuth_degrees)
            max_azimuth = max(record.azimuth_degrees, state.max_azimuth_degrees)
            azimuth_delta = max_azimuth - min_azimuth
            inverse_azimuth_delta = AZIMUTH_DEGREES_PER_CIRCLE - azimuth_delta
            if (
                azimuth_delta > self.config.max_azimuth_jump_degrees
                and inverse_azimuth_delta > self.config.max_azimuth_jump_degrees
            ):
                state.window_start_radar_timestamp = record.radar_timestamp
                state.min_azimuth_degrees = record.azimuth_degrees
                state.max_azimuth_degrees = record.azimuth_degrees
                return [
                    DetectionFinding(
                        rule="azimuth",
                        alert="plot detected outside the radar detection lobe.",
                        details=(
                            f"Azimuth delta {azimuth_delta} and inverse azimuth delta "
                            f"{inverse_azimuth_delta}."
                        ),
                    )
                ]

            state.min_azimuth_degrees = min_azimuth
            state.max_azimuth_degrees = max_azimuth
            return []

        delta = _circular_degrees_delta(record.azimuth_degrees, state.last_azimuth_degrees)
        if delta > self.config.max_azimuth_jump_degrees:
            return [
                DetectionFinding(
                    rule="azimuth",
                    alert="Azimuth Jump",
                    details=f"azimuth jump {delta} exceeds {self.config.max_azimuth_jump_degrees}",
                )
            ]

        return []

    @staticmethod
    def _update_site_state(record: ParsedPlot, state: SiteState) -> None:
        if record.sequence is not None:
            state.last_sequence = record.sequence
        if record.router_timestamp is not None:
            state.last_router_timestamp = record.router_timestamp
        if record.radar_timestamp is not None:
            state.last_radar_timestamp = record.radar_timestamp
        if record.azimuth_degrees is not None and record.azimuth_degrees >= 0:
            state.last_azimuth_degrees = record.azimuth_degrees


def _legacy_site_key(record: ParsedPlot) -> str:
    artcc = record.artcc or ""
    site_id = record.site_id or ""
    if not site_id:
        return ""
    if artcc in LEGACY_CHANNEL_SITE_ARTCCS:
        return f"{artcc}_{site_id}_{record.channel}"
    if artcc:
        return f"{artcc}_{site_id}"
    return site_id


def _valid_azimuth_or_default(value: float | None, default: float) -> float:
    if value is None or value < 0:
        return default
    return value


def _circular_degrees_delta(first: float, second: float) -> float:
    raw_delta = abs(first - second) % AZIMUTH_DEGREES_PER_CIRCLE
    return min(raw_delta, AZIMUTH_DEGREES_PER_CIRCLE - raw_delta)

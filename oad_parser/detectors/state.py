"""Stateful detector engine.

Detector rules run after parsing. They annotate parsed records with alert fields
without changing the parser core.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_DISCOVERY_WINDOW_RECORDS = 100
DEFAULT_MAX_SEQUENCE_DELTA = 10
DEFAULT_MAX_RANGE_NM = 300.0
DEFAULT_MAX_AZIMUTH_JUMP_DEGREES = 45.0
SEQUENCE_NUMBER_MODULUS = 256
AZIMUTH_DEGREES_PER_CIRCLE = 360.0
from typing import Iterable

from oad_parser.models import ParsedPlot


@dataclass
class DetectionConfig:
    discovery_window_records: int = DEFAULT_DISCOVERY_WINDOW_RECORDS
    max_sequence_delta: int | None = DEFAULT_MAX_SEQUENCE_DELTA
    max_router_time_delta_seconds: float | None = None
    max_radar_time_delta_seconds: float | None = None
    max_range_nm: float | None = DEFAULT_MAX_RANGE_NM
    max_azimuth_jump_degrees: float | None = DEFAULT_MAX_AZIMUTH_JUMP_DEGREES


@dataclass
class SiteState:
    last_sequence: int | None = None
    last_router_timestamp: float | None = None
    last_radar_timestamp: float | None = None
    last_azimuth_degrees: float | None = None


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
    fingerprints: set[str] = field(default_factory=set)

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

        if record.fingerprint in self.fingerprints:
            return [
                DetectionFinding(
                    rule="fingerprint",
                    alert="Duplicate Fingerprint",
                    details=f"duplicate plot fingerprint {record.fingerprint}",
                )
            ]

        self.fingerprints.add(record.fingerprint)
        return []

    def _detect_range(self, record: ParsedPlot) -> list[DetectionFinding]:
        if self.config.max_range_nm is None:
            return []

        if record.range_nm is None or record.range_nm < 0:
            return []

        if record.range_nm > self.config.max_range_nm:
            return [
                DetectionFinding(
                    rule="range",
                    alert="Impossible Range",
                    details=f"range {record.range_nm} NM exceeds {self.config.max_range_nm} NM",
                )
            ]

        return []

    def _detect_site_state(self, record: ParsedPlot) -> list[DetectionFinding]:
        if not record.site_id:
            return []

        findings: list[DetectionFinding] = []
        state = self.sites.get(record.site_id)

        if state is None:
            if self.record_count > self.config.discovery_window_records:
                findings.append(
                    DetectionFinding(
                        rule="site_discovery",
                        alert="Unknown Site",
                        details=f"site {record.site_id} appeared after discovery window",
                    )
                )

            self.sites[record.site_id] = SiteState(
                last_sequence=record.sequence,
                last_router_timestamp=record.router_timestamp,
                last_radar_timestamp=record.radar_timestamp,
                last_azimuth_degrees=record.azimuth_degrees,
            )
            return findings

        findings.extend(self._detect_sequence(record, state))
        findings.extend(self._detect_router_time(record, state))
        findings.extend(self._detect_radar_time(record, state))
        findings.extend(self._detect_azimuth(record, state))

        self._update_site_state(record, state)
        return findings

    def _detect_sequence(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        if self.config.max_sequence_delta is None:
            return []

        if record.sequence is None or state.last_sequence is None:
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

    def _detect_router_time(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        if self.config.max_router_time_delta_seconds is None:
            return []

        if record.router_timestamp is None or state.last_router_timestamp is None:
            return []

        delta = abs(record.router_timestamp - state.last_router_timestamp)
        record.router_time_delta = delta

        if delta > self.config.max_router_time_delta_seconds:
            return [
                DetectionFinding(
                    rule="router_time",
                    alert="Router Time Delta",
                    details=(
                        f"router timestamp delta {delta} exceeds "
                        f"{self.config.max_router_time_delta_seconds}"
                    ),
                )
            ]

        return []

    def _detect_radar_time(self, record: ParsedPlot, state: SiteState) -> list[DetectionFinding]:
        if self.config.max_radar_time_delta_seconds is None:
            return []

        if record.radar_timestamp is None or state.last_radar_timestamp is None:
            return []

        delta = abs(record.radar_timestamp - state.last_radar_timestamp)
        record.radar_time_delta = delta

        if delta > self.config.max_radar_time_delta_seconds:
            return [
                DetectionFinding(
                    rule="radar_time",
                    alert="Radar Time Delta",
                    details=(
                        f"radar timestamp delta {delta} exceeds "
                        f"{self.config.max_radar_time_delta_seconds}"
                    ),
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


def _circular_degrees_delta(first: float, second: float) -> float:
    raw_delta = abs(first - second) % AZIMUTH_DEGREES_PER_CIRCLE
    return min(raw_delta, AZIMUTH_DEGREES_PER_CIRCLE - raw_delta)

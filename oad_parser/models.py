"""Data models for parsed ECG/CD2 records.

Internal Python fields use safe names such as ``source_ip``. Output conversion
can emit ECS-style dotted keys such as ``source.ip`` for Filebeat/Kibana.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedPlot:
    timestamp: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    observer_interface: str | None = None
    total_bytes: int | None = None
    artcc: str | None = None
    site_id: str | None = None
    sequence: int | None = None
    sequence_delta: int | None = None
    channel: int | None = None
    message: str | None = None
    message_type: str | None = None
    router_timestamp: float | None = None
    router_time_delta: float | None = None
    radar_timestamp: float | None = None
    radar_time_delta: float | None = None
    range_nm: float | None = None
    mode_3_code: int | None = None
    acp: int | None = None
    azimuth_degrees: float | None = None
    altitude_feet: int | None = None
    fingerprint: str | None = None
    alert: str | None = None
    alert_details: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_ecs_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {}

        mapping = {
            "@timestamp": self.timestamp,
            "source.ip": self.source_ip,
            "source.port": self.source_port,
            "destination.ip": self.destination_ip,
            "destination.port": self.destination_port,
            "observer.interface": self.observer_interface,
            "tot.bytes": self.total_bytes,
            "artcc": self.artcc,
            "site_id": self.site_id,
            "sequence": self.sequence,
            "sequence_delta": self.sequence_delta,
            "channel": self.channel,
            "message": self.message,
            "type": self.message_type,
            "router_timestamp": self.router_timestamp,
            "router_time_delta": self.router_time_delta,
            "radar_timestamp": self.radar_timestamp,
            "radar_time_delta": self.radar_time_delta,
            "range_nm": self.range_nm,
            "mode_3_code": self.mode_3_code,
            "acp": self.acp,
            "azimuth_degrees": self.azimuth_degrees,
            "altitude_feet": self.altitude_feet,
            "fingerprint": self.fingerprint,
            "alert": self.alert,
            "alert_details": self.alert_details,
        }

        for key, value in mapping.items():
            if value is not None:
                record[key] = value

        record.update(self.extra)
        return record

    def to_legacy_dict(self) -> dict[str, Any]:
        record = self.to_ecs_dict()

        aliases = {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "interface": self.observer_interface,
        }

        for key, value in aliases.items():
            if value is not None:
                record[key] = value

        return record

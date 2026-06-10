"""Stateless ECG/CD2 alert evaluation for live legacy-compatible output."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SEVERITY_RANK = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

ALERT_DEFINITIONS = {
    "OAD-ECG-001": ("RTQC message", "medium", "quality_control"),
    "OAD-ECG-002": ("Parse error", "high", "parser_integrity"),
    "OAD-ECG-003": ("Parse warning", "medium", "parser_integrity"),
    "OAD-ECG-004": ("Unknown site", "high", "site_identity"),
    "OAD-ECG-005": ("Unknown message type", "medium", "message_semantics"),
    "OAD-ECG-006": ("Unexpected message type", "medium", "message_semantics"),
    "OAD-ECG-007": ("Missing required radar words", "medium", "message_semantics"),
    "OAD-ECG-008": ("Mode C valid but altitude missing", "medium", "message_semantics"),
    "OAD-ECG-009": ("Impossible altitude", "high", "radar_value"),
    "OAD-ECG-010": ("Impossible range", "high", "radar_value"),
    "OAD-ECG-011": ("Invalid azimuth", "high", "radar_value"),
    "OAD-ECG-012": ("Unexpected channel", "medium", "site_policy"),
    "OAD-ECG-013": ("Unauthorized source IP", "critical", "authorization"),
    "OAD-ECG-014": ("Unauthorized destination or consumer", "critical", "authorization"),
    "OAD-ECG-015": ("Site/source mismatch", "critical", "site_identity"),
    "OAD-ECG-016": ("Unexpected radar port", "medium", "authorization"),
    "OAD-ECG-017": ("Admin workstation radar traffic", "critical", "authorization"),
}

PROJECTABLE_RADAR_MESSAGES = {"cd-2", "cd-asr", "mar"}
PROJECTABLE_RADAR_MESSAGE_TYPES = {"beacon", "search"}


@dataclass(frozen=True)
class EcgAlertConfig:
    """Explicit opt-in policy for site and authorization dependent alerts."""

    version: int = 1
    known_sites: frozenset[str] = frozenset()
    allowed_message_types: frozenset[str] = frozenset()
    allowed_message_types_by_site: Mapping[str, frozenset[str]] = field(default_factory=dict)
    altitude_min_ft: int | None = None
    altitude_max_ft: int | None = None
    max_range_nm: float | None = None
    expected_channels: frozenset[int] = frozenset()
    expected_channels_by_site: Mapping[str, frozenset[int]] = field(default_factory=dict)
    authorized_source_ips: frozenset[str] = frozenset()
    authorized_destination_ips: frozenset[str] = frozenset()
    site_source_ips: Mapping[str, frozenset[str]] = field(default_factory=dict)
    allowed_radar_ports: frozenset[int] = frozenset()
    admin_workstation_ips: frozenset[str] = frozenset()
    raw_azimuth_max: int | None = None


def load_ecg_alert_config(path: str | Path | None) -> EcgAlertConfig | None:
    """Load explicit JSON alert config or return None when no config is supplied."""

    if path is None or str(path).strip() == "":
        return None

    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError("ECG alert config must be a JSON object")

    allowed_keys = {
        "version",
        "known_sites",
        "allowed_message_types",
        "allowed_message_types_by_site",
        "altitude_min_ft",
        "altitude_max_ft",
        "max_range_nm",
        "expected_channels",
        "expected_channels_by_site",
        "authorized_source_ips",
        "authorized_destination_ips",
        "site_source_ips",
        "allowed_radar_ports",
        "admin_workstation_ips",
        "raw_azimuth_max",
    }
    unknown = sorted(set(data) - allowed_keys)
    if unknown:
        raise ValueError("ECG alert config has unknown keys: %s" % ", ".join(unknown))

    version = _optional_int(data.get("version", 1), "version")
    if version != 1:
        raise ValueError("ECG alert config version must be 1")

    altitude_min = _optional_int(data.get("altitude_min_ft"), "altitude_min_ft")
    altitude_max = _optional_int(data.get("altitude_max_ft"), "altitude_max_ft")
    if altitude_min is not None and altitude_max is not None and altitude_min > altitude_max:
        raise ValueError("altitude_min_ft must be <= altitude_max_ft")

    max_range = _optional_float(data.get("max_range_nm"), "max_range_nm")
    if max_range is not None and max_range < 0:
        raise ValueError("max_range_nm must be >= 0")

    raw_azimuth_max = _optional_int(data.get("raw_azimuth_max"), "raw_azimuth_max")
    if raw_azimuth_max is not None and raw_azimuth_max < 0:
        raise ValueError("raw_azimuth_max must be >= 0")

    return EcgAlertConfig(
        version=version,
        known_sites=_string_set(data.get("known_sites"), "known_sites"),
        allowed_message_types=_string_set(data.get("allowed_message_types"), "allowed_message_types"),
        allowed_message_types_by_site=_string_set_map(data.get("allowed_message_types_by_site"), "allowed_message_types_by_site"),
        altitude_min_ft=altitude_min,
        altitude_max_ft=altitude_max,
        max_range_nm=max_range,
        expected_channels=_int_set(data.get("expected_channels"), "expected_channels"),
        expected_channels_by_site=_int_set_map(data.get("expected_channels_by_site"), "expected_channels_by_site"),
        authorized_source_ips=_string_set(data.get("authorized_source_ips"), "authorized_source_ips"),
        authorized_destination_ips=_string_set(data.get("authorized_destination_ips"), "authorized_destination_ips"),
        site_source_ips=_string_set_map(data.get("site_source_ips"), "site_source_ips"),
        allowed_radar_ports=_int_set(data.get("allowed_radar_ports"), "allowed_radar_ports"),
        admin_workstation_ips=_string_set(data.get("admin_workstation_ips"), "admin_workstation_ips"),
        raw_azimuth_max=raw_azimuth_max,
    )


def evaluate_ecg_record_alerts(
    record: Mapping[str, Any],
    *,
    data_words: Sequence[int] = (),
    parse_warnings: Sequence[Mapping[str, Any]] | Sequence[Any] = (),
    config: EcgAlertConfig | None = None,
) -> list[dict[str, Any]]:
    """Return stateless alerts for one parsed ECG event record."""

    alerts: list[dict[str, Any]] = []
    message_type = _as_str(record.get("message_type"))
    message = _as_str(record.get("message"))
    site_id = _as_str(record.get("site_id"))

    if message_type == "rtqc":
        alerts.append(_alert("OAD-ECG-001", "RTQC message detected.", {"message_type": message_type}))

    warning_dicts = [_warning_to_dict(item) for item in parse_warnings]
    if warning_dicts:
        alerts.append(
            _alert(
                "OAD-ECG-003",
                "ECG parse warnings were emitted.",
                {"parse_warnings": warning_dicts},
            )
        )

    if message_type == "unknown":
        alerts.append(_alert("OAD-ECG-005", "Unknown ECG message type.", {"message_type": message_type}))

    alerts.extend(_missing_required_word_alerts(record, data_words))

    if (
        message_type == "beacon"
        and record.get("modec_valid") is True
        and record.get("altitude_feet") is None
    ):
        alerts.append(
            _alert(
                "OAD-ECG-008",
                "Mode C is valid but altitude could not be projected.",
                {"modec_valid": True, "altitude_feet": None, "data_word_count": len(data_words)},
            )
        )

    if config is not None:
        alerts.extend(_configured_alerts(record, data_words, config, message, message_type, site_id))

    return _deduplicate_alerts(alerts)


def evaluate_ecg_parse_error_alerts(
    record: Mapping[str, Any],
    *,
    error_code: str,
    error_message: str,
    parser_stage: str,
    config: EcgAlertConfig | None = None,
) -> list[dict[str, Any]]:
    alerts = [
        _alert(
            "OAD-ECG-002",
            "ECG payload could not be parsed.",
            {
                "error_code": error_code,
                "error_message": error_message,
                "parser_stage": parser_stage,
            },
        )
    ]
    if config is not None:
        alerts.extend(
            _configured_alerts(
                record,
                (),
                config,
                _as_str(record.get("message")),
                _as_str(record.get("message_type")),
                _as_str(record.get("site_id")),
            )
        )
    return _deduplicate_alerts(alerts)


def apply_legacy_alert_fields(record: dict[str, Any], alerts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Populate additive alert list plus legacy scalar alert fields."""

    alert_list = [dict(alert) for alert in alerts]
    record["alerts"] = alert_list
    if not alert_list:
        record["alert"] = None
        record["alert_details"] = None
        return record

    selected = max(
        alert_list,
        key=lambda item: (SEVERITY_RANK.get(str(item.get("severity")), 0), -alert_list.index(item)),
    )
    record["alert"] = selected["id"]
    record["alert_details"] = selected["details"]
    return record


def _configured_alerts(
    record: Mapping[str, Any],
    data_words: Sequence[int],
    config: EcgAlertConfig,
    message: str,
    message_type: str,
    site_id: str,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    if config.known_sites and (site_id == "unknown" or site_id not in config.known_sites):
        alerts.append(_alert("OAD-ECG-004", "ECG site is not in the configured known-site register.", {"site_id": site_id}))

    allowed_types = config.allowed_message_types_by_site.get(site_id) or config.allowed_message_types
    if allowed_types and message_type not in allowed_types:
        alerts.append(
            _alert(
                "OAD-ECG-006",
                "ECG message type is not allowed by explicit alert config.",
                {"site_id": site_id, "message_type": message_type, "allowed_message_types": sorted(allowed_types)},
            )
        )

    altitude = record.get("altitude_feet")
    if altitude is not None:
        altitude_value = _as_float(altitude)
        if altitude_value is not None:
            if config.altitude_min_ft is not None and altitude_value < config.altitude_min_ft:
                alerts.append(_alert("OAD-ECG-009", "Altitude is below configured minimum.", {"altitude_feet": altitude, "altitude_min_ft": config.altitude_min_ft}))
            if config.altitude_max_ft is not None and altitude_value > config.altitude_max_ft:
                alerts.append(_alert("OAD-ECG-009", "Altitude exceeds configured maximum.", {"altitude_feet": altitude, "altitude_max_ft": config.altitude_max_ft}))

    range_nm = _as_float(record.get("range_nm"))
    if range_nm is not None and config.max_range_nm is not None and range_nm > config.max_range_nm:
        alerts.append(_alert("OAD-ECG-010", "Range exceeds configured radar maximum.", {"range_nm": range_nm, "max_range_nm": config.max_range_nm}))

    if config.raw_azimuth_max is not None and len(data_words) > 2:
        raw_acp = int(data_words[2])
        if raw_acp > config.raw_azimuth_max:
            alerts.append(_alert("OAD-ECG-011", "Raw azimuth word exceeds configured maximum before projection masking.", {"raw_acp_word": raw_acp, "raw_azimuth_max": config.raw_azimuth_max}))

    expected_channels = config.expected_channels_by_site.get(site_id) or config.expected_channels
    channel = _as_int(record.get("channel"))
    if expected_channels and channel is not None and channel not in expected_channels:
        alerts.append(_alert("OAD-ECG-012", "Channel is not expected for this site/radar policy.", {"site_id": site_id, "channel": channel, "expected_channels": sorted(expected_channels)}))

    source_ip = _as_str(record.get("source_ip"))
    if config.authorized_source_ips and source_ip not in config.authorized_source_ips:
        alerts.append(_alert("OAD-ECG-013", "Source IP is not in the authorized extractor register.", {"source_ip": source_ip}))

    destination_ip = _as_str(record.get("destination_ip"))
    if config.authorized_destination_ips and destination_ip not in config.authorized_destination_ips:
        alerts.append(_alert("OAD-ECG-014", "Destination IP is not in the authorized consumer register.", {"destination_ip": destination_ip}))

    allowed_sources_for_site = config.site_source_ips.get(site_id)
    if allowed_sources_for_site and source_ip not in allowed_sources_for_site:
        alerts.append(_alert("OAD-ECG-015", "Site identity was observed from an unexpected source IP.", {"site_id": site_id, "source_ip": source_ip, "allowed_source_ips": sorted(allowed_sources_for_site)}))

    source_port = _as_int(record.get("source_port"))
    destination_port = _as_int(record.get("destination_port"))
    if config.allowed_radar_ports and source_port not in config.allowed_radar_ports and destination_port not in config.allowed_radar_ports:
        alerts.append(
            _alert(
                "OAD-ECG-016",
                "Neither source nor destination port is in the allowed radar port register.",
                {"source_port": source_port, "destination_port": destination_port, "allowed_radar_ports": sorted(config.allowed_radar_ports)},
            )
        )

    if config.admin_workstation_ips and (source_ip in config.admin_workstation_ips or destination_ip in config.admin_workstation_ips):
        alerts.append(_alert("OAD-ECG-017", "Admin workstation IP appeared in radar traffic.", {"source_ip": source_ip, "destination_ip": destination_ip}))

    return alerts


def _missing_required_word_alerts(record: Mapping[str, Any], data_words: Sequence[int]) -> list[dict[str, Any]]:
    message = _as_str(record.get("message"))
    message_type = _as_str(record.get("message_type"))
    if message not in PROJECTABLE_RADAR_MESSAGES or message_type not in PROJECTABLE_RADAR_MESSAGE_TYPES:
        return []

    required = {"range_word": 1, "acp_word": 2}
    if message_type == "beacon":
        required["mode_3_word"] = 4

    missing = [name for name, index in required.items() if len(data_words) <= index]
    if not missing:
        return []

    return [
        _alert(
            "OAD-ECG-007",
            "Required radar words are missing from a projectable ECG message.",
            {"message": message, "message_type": message_type, "missing_words": missing, "data_word_count": len(data_words)},
        )
    ]


def _alert(alert_id: str, details: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    name, severity, category = ALERT_DEFINITIONS[alert_id]
    return {
        "id": alert_id,
        "name": name,
        "severity": severity,
        "category": category,
        "scope": "stateless",
        "details": details,
        "evidence": dict(evidence),
    }


def _deduplicate_alerts(alerts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for alert in alerts:
        key = (str(alert.get("id")), str(alert.get("details")))
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(alert))
    return result


def _warning_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {
        "code": getattr(value, "code", None),
        "message": getattr(value, "message", None),
        "parser_stage": getattr(value, "parser_stage", None),
    }


def _string_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise ValueError("%s must be a list" % name)
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("%s entries must be non-empty strings" % name)
        result.append(item.strip())
    return frozenset(result)


def _int_set(value: Any, name: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise ValueError("%s must be a list" % name)
    return frozenset(_required_int(item, "%s entry" % name) for item in value)


def _string_set_map(value: Any, name: str) -> dict[str, frozenset[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % name)
    return {str(key): _string_set(item, "%s.%s" % (name, key)) for key, item in value.items()}


def _int_set_map(value: Any, name: str) -> dict[str, frozenset[int]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % name)
    return {str(key): _int_set(item, "%s.%s" % (name, key)) for key, item in value.items()}


def _required_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError("%s must be an integer" % name)
    if not isinstance(value, int):
        raise ValueError("%s must be an integer" % name)
    return int(value)


def _optional_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return _required_int(value, name)


def _optional_float(value: Any, name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("%s must be numeric" % name)
    return float(value)


def _as_str(value: Any) -> str:
    if value is None:
        return "unknown"
    stripped = str(value).strip()
    return stripped if stripped else "unknown"


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

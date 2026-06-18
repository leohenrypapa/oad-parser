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

ALERT_POLICY_V2_SCHEMA_VERSION = "2026-06-17.alert-policy-v2"
ALERT_POLICY_LEGACY_SCHEMA_VERSIONS = frozenset(
    {
        "",
        "2026-06-15.phase6a",
        "2026-06-15.phase6b",
    }
)
ALERT_POLICY_SUPPORTED_OVERRIDE_KEYS = frozenset({"enabled", "severity"})
ALERT_POLICY_UNSUPPORTED_OVERRIDE_KEYS = frozenset(
    {
        "cooldown",
        "cooldown_seconds",
        "evidence",
        "evidence_fields",
        "evidence_mutation",
        "suppression_seconds",
        "suppression_window_seconds",
    }
)

ALERT_DEFINITIONS = {
    "ECG-CD2-001": ("unauthorized_source_tuple", "high", "source_integrity"),
    "ECG-CD2-002": ("malformed_ecg_frame_length", "high", "protocol_integrity"),
    "ECG-CD2-003": ("udp_checksum_bad_or_zero_unexpected", "medium", "checksum_integrity"),
    "ECG-CD2-004": ("duplicate_payload_burst_or_replay", "medium", "replay_duplicate"),
    "ECG-CD2-005": ("message_sequence_gap", "medium", "timing_anomaly"),
    "ECG-CD2-006": ("timestamp_gap_or_stale_replay", "medium", "timing_anomaly"),
    "ECG-CD2-007": ("site_artcc_channel_change", "high", "route_site_change"),
    "OAD-ECG-003": ("Parse warning", "medium", "parser_integrity"),
    "OAD-ECG-005": ("Unknown message type", "medium", "message_semantics"),
    "OAD-ECG-006": ("Unexpected message type", "medium", "message_semantics"),
    "OAD-ECG-007": ("Missing required radar words", "medium", "message_semantics"),
    "OAD-ECG-008": ("Mode C valid but altitude missing", "medium", "message_semantics"),
}

ALERT_CATEGORIES = {
    "checksum_integrity": {
        "label": "Checksum integrity",
        "description": "UDP checksum was invalid or unexpectedly zero under the active policy.",
    },
    "message_semantics": {
        "label": "Message semantics",
        "description": "Message content was missing, unknown, or unexpected for the configured ECG/CD2 mode.",
    },
    "parser_integrity": {
        "label": "Parser integrity",
        "description": "Parser validation or warning evidence was elevated to an alert record.",
    },
    "protocol_integrity": {
        "label": "Protocol integrity",
        "description": "Malformed ECG/CD2 frame, length, or message-block evidence was observed.",
    },
    "replay_duplicate": {
        "label": "Replay or duplicate",
        "description": "Duplicate payload or message-hash behavior crossed the configured replay threshold.",
    },
    "route_site_change": {
        "label": "Route or site change",
        "description": "ARTCC, site, channel, message, or source tuple differed from the approved baseline.",
    },
    "source_integrity": {
        "label": "Source integrity",
        "description": "Source, destination, port, feed, or message tuple missed the configured authorization policy.",
    },
    "timing_anomaly": {
        "label": "Timing anomaly",
        "description": "Sequence, radar timestamp, or router timestamp behavior exceeded the configured gap or replay threshold.",
    },
}

LEGACY_OPERATOR_ALERT_TAXONOMY = {
    # Unknown-site category: source/site/channel authorization and parser/frame integrity
    # are grouped here so the operator sees one legacy site/feed-integrity family.
    "ECG-CD2-001": {
        "operator.category": "unknown_site",
        "operator.alert": "New unknown site discovered.",
        "operator.subtype": "unauthorized_source_site_channel_tuple",
    },
    "ECG-CD2-002": {
        "operator.category": "unknown_site",
        "operator.alert": "New unknown site discovered.",
        "operator.subtype": "malformed_ecg_cd2_frame_length",
    },
    "ECG-CD2-003": {
        "operator.category": "unknown_site",
        "operator.alert": "New unknown site discovered.",
        "operator.subtype": "udp_checksum_bad_or_zero_unexpected",
    },
    "ECG-CD2-007": {
        "operator.category": "unknown_site",
        "operator.alert": "New unknown site discovered.",
        "operator.subtype": "site_artcc_channel_change",
    },
    # Legacy duplicate-plot category. Normal duplicate packet/output suppression
    # must remain accounting-only and must not become this alert.
    "ECG-CD2-004": {
        "operator.category": "duplicate_plot",
        "operator.alert": "Duplicate plot found.",
        "operator.subtype": "duplicate_payload_burst_or_replay",
    },
    # Legacy sequence/time categories.
    "ECG-CD2-005": {
        "operator.category": "sequence_delta",
        "operator.alert": "Sequence delta between plots is too large.",
        "operator.subtype": "sequence_gap_after_duplicate_collapse",
    },
    "ECG-CD2-006": {
        "operator.category": "time_delta",
        "operator.alert": "Time delta between plots is too large.",
        "operator.subtype": "timestamp_gap_or_stale_replay",
    },
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
    allowed_source_tuples: frozenset[str] = frozenset()
    allowed_site_artcc_channel_tuples: frozenset[str] = frozenset()
    emit_unknown_site_alerts: bool = True
    udp_zero_checksum_allowed: bool = True
    duplicate_payload_window_seconds: float | None = None
    duplicate_payload_threshold: int | None = None
    max_sequence_delta: int | None = None
    legacy_sequence_delta_min_abs: int | None = None
    legacy_sequence_delta_max_abs: int | None = None
    max_radar_time_delta_seconds: float | None = None
    max_router_time_delta_seconds: float | None = None
    desired_alert_overrides: Mapping[str, "AlertOverride"] = field(default_factory=dict)


@dataclass(frozen=True)
class AlertOverride:
    """Allowlisted v2 per-alert behavior override."""

    enabled: bool | None = None
    severity: str | None = None


DEFAULT_ECG_ALERT_CONFIG = EcgAlertConfig(
    duplicate_payload_window_seconds=1.0,
    duplicate_payload_threshold=6,
    max_sequence_delta=None,
    legacy_sequence_delta_min_abs=15,
    legacy_sequence_delta_max_abs=240,
    max_radar_time_delta_seconds=5.0,
    max_router_time_delta_seconds=5.0,
)


def default_ecg_alert_config() -> EcgAlertConfig:
    """Return the live default legacy-compatible operator alert policy."""

    return DEFAULT_ECG_ALERT_CONFIG


def load_ecg_alert_config(path: str | Path | None) -> EcgAlertConfig | None:
    """Load explicit JSON alert config or return None when no config is supplied."""

    if path is None or str(path).strip() == "":
        return None

    config_path = Path(path)
    if not config_path.exists():
        return None

    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError("ECG alert config must be a JSON object")

    allowed_keys = {
        "schema_version",
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
        "allowed_source_tuples",
        "allowed_site_artcc_channel_tuples",
        "emit_unknown_site_alerts",
        "udp_zero_checksum_allowed",
        "duplicate_payload_window_seconds",
        "duplicate_payload_threshold",
        "max_sequence_delta",
        "legacy_sequence_delta_min_abs",
        "legacy_sequence_delta_max_abs",
        "max_radar_time_delta_seconds",
        "max_router_time_delta_seconds",
        "desired_alert_overrides",
    }
    unknown = sorted(set(data) - allowed_keys)
    if unknown:
        raise ValueError("ECG alert config has unknown keys: %s" % ", ".join(unknown))

    version = _optional_int(data.get("version", 1), "version")
    if version != 1:
        raise ValueError("ECG alert config version must be 1")

    schema_version = str(data.get("schema_version") or "")
    if schema_version not in ALERT_POLICY_LEGACY_SCHEMA_VERSIONS | {ALERT_POLICY_V2_SCHEMA_VERSION}:
        raise ValueError("Unsupported ECG alert config schema_version: %s" % schema_version)

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

    duplicate_payload_window_seconds = _optional_float(
        data.get("duplicate_payload_window_seconds"),
        "duplicate_payload_window_seconds",
    )
    if duplicate_payload_window_seconds is not None and duplicate_payload_window_seconds <= 0:
        raise ValueError("duplicate_payload_window_seconds must be > 0")

    duplicate_payload_threshold = _optional_int(data.get("duplicate_payload_threshold"), "duplicate_payload_threshold")
    if duplicate_payload_threshold is not None and duplicate_payload_threshold < 2:
        raise ValueError("duplicate_payload_threshold must be >= 2")

    max_sequence_delta = _optional_int(data.get("max_sequence_delta"), "max_sequence_delta")
    if max_sequence_delta is not None and not 0 <= max_sequence_delta <= 255:
        raise ValueError("max_sequence_delta must be between 0 and 255")

    legacy_sequence_delta_min_abs = _optional_int(
        data.get("legacy_sequence_delta_min_abs"),
        "legacy_sequence_delta_min_abs",
    )
    if legacy_sequence_delta_min_abs is not None and not 0 <= legacy_sequence_delta_min_abs <= 255:
        raise ValueError("legacy_sequence_delta_min_abs must be between 0 and 255")

    legacy_sequence_delta_max_abs = _optional_int(
        data.get("legacy_sequence_delta_max_abs"),
        "legacy_sequence_delta_max_abs",
    )
    if legacy_sequence_delta_max_abs is not None and not 0 <= legacy_sequence_delta_max_abs <= 255:
        raise ValueError("legacy_sequence_delta_max_abs must be between 0 and 255")
    if (
        legacy_sequence_delta_min_abs is not None
        and legacy_sequence_delta_max_abs is not None
        and legacy_sequence_delta_min_abs > legacy_sequence_delta_max_abs
    ):
        raise ValueError("legacy_sequence_delta_min_abs must be <= legacy_sequence_delta_max_abs")

    max_radar_time_delta_seconds = _optional_float(data.get("max_radar_time_delta_seconds"), "max_radar_time_delta_seconds")
    if max_radar_time_delta_seconds is not None and max_radar_time_delta_seconds < 0:
        raise ValueError("max_radar_time_delta_seconds must be >= 0")

    max_router_time_delta_seconds = _optional_float(data.get("max_router_time_delta_seconds"), "max_router_time_delta_seconds")
    if max_router_time_delta_seconds is not None and max_router_time_delta_seconds < 0:
        raise ValueError("max_router_time_delta_seconds must be >= 0")

    desired_alert_overrides = _alert_override_map(
        data.get("desired_alert_overrides"),
        schema_version,
    )

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
        allowed_source_tuples=_string_set(data.get("allowed_source_tuples"), "allowed_source_tuples"),
        allowed_site_artcc_channel_tuples=_string_set(
            data.get("allowed_site_artcc_channel_tuples"),
            "allowed_site_artcc_channel_tuples",
        ),
        emit_unknown_site_alerts=_optional_bool(
            data.get("emit_unknown_site_alerts", True),
            "emit_unknown_site_alerts",
        ),
        udp_zero_checksum_allowed=_optional_bool(
            data.get("udp_zero_checksum_allowed", True),
            "udp_zero_checksum_allowed",
        ),
        duplicate_payload_window_seconds=duplicate_payload_window_seconds,
        duplicate_payload_threshold=duplicate_payload_threshold,
        max_sequence_delta=max_sequence_delta,
        legacy_sequence_delta_min_abs=legacy_sequence_delta_min_abs,
        legacy_sequence_delta_max_abs=legacy_sequence_delta_max_abs,
        max_radar_time_delta_seconds=max_radar_time_delta_seconds,
        max_router_time_delta_seconds=max_router_time_delta_seconds,
        desired_alert_overrides=desired_alert_overrides,
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

    warning_dicts = [_warning_to_dict(item) for item in parse_warnings]
    if warning_dicts:
        # Parser warnings stay on parser.validation.warnings. Unknown or unmapped
        # message codes are metadata, not operator alerts.
        pass

    # Unknown ECG/CD2 message codes and missing altitude are retained as fields
    # and validation/decoder metadata. They are not operator alerts by themselves.
    alerts.extend(_missing_required_word_alerts(record, data_words))

    alerts.extend(_checksum_alerts(record, config))

    if config is not None:
        alerts.extend(_configured_alerts(record, data_words, config, message, message_type, site_id))

    return _deduplicate_alerts(_apply_alert_overrides(alerts, config))


def evaluate_ecg_parse_error_alerts(
    record: Mapping[str, Any],
    *,
    error_code: str,
    error_message: str,
    parser_stage: str,
    config: EcgAlertConfig | None = None,
) -> list[dict[str, Any]]:
    alerts = []
    if error_code != "ecg_outer_message_not_surveillance":
        alerts.append(
            make_alert(
                "ECG-CD2-002",
                "Malformed ECG/CD2 frame length or message block was observed; parser emitted a rejected-frame record instead of silently dropping it.",
                _malformed_evidence(record, error_code, error_message, parser_stage),
            )
        )
    alerts.extend(_checksum_alerts(record, config))

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
    return _deduplicate_alerts(_apply_alert_overrides(alerts, config))


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

    source_tuple = _source_tuple_key(record)
    if config.allowed_source_tuples and source_tuple not in config.allowed_source_tuples:
        alerts.append(
            make_alert(
                "ECG-CD2-001",
                "Source/destination/feed/message tuple is not in the configured ECG/CD2 allowlist.",
                _source_tuple_evidence(record, "miss"),
            )
        )

    site_tuple = _site_artcc_channel_tuple_key(record)
    if config.allowed_site_artcc_channel_tuples and site_tuple not in config.allowed_site_artcc_channel_tuples:
        alerts.append(
            make_alert(
                "ECG-CD2-007",
                "ARTCC/site/channel/message/source tuple is new or not approved by the configured baseline.",
                _site_tuple_evidence(record, "miss"),
            )
        )

    if config.emit_unknown_site_alerts and config.known_sites and (site_id == "unknown" or site_id not in config.known_sites):
        alerts.append(
            make_alert(
                "ECG-CD2-007",
                "Site identity is not in the configured approved-site baseline.",
                _site_tuple_evidence(record, "known_site_miss"),
            )
        )

    allowed_types = config.allowed_message_types_by_site.get(site_id) or config.allowed_message_types
    if allowed_types and message_type not in allowed_types:
        alerts.append(
            make_alert(
                "ECG-CD2-007",
                "ECG message type is not allowed by explicit site/feed/message baseline.",
                _site_tuple_evidence(record, "message_type_miss")
                | {
                    "message_type": message_type,
                    "allowed_message_types": sorted(allowed_types),
                    "operator.subtype.detail": "unexpected_message_type",
                },
            )
        )

    expected_channels = config.expected_channels_by_site.get(site_id) or config.expected_channels
    channel = _as_int(record.get("channel"))
    if expected_channels and channel is not None and channel not in expected_channels:
        alerts.append(
            make_alert(
                "ECG-CD2-007",
                "Channel is not expected for this site/radar baseline.",
                _site_tuple_evidence(record, "channel_miss") | {"expected_channels": sorted(expected_channels)},
            )
        )

    source_ip = _as_str(record.get("source_ip"))
    destination_ip = _as_str(record.get("destination_ip"))
    source_port = _as_int(record.get("source_port"))
    destination_port = _as_int(record.get("destination_port"))

    if config.authorized_source_ips and source_ip not in config.authorized_source_ips:
        alerts.append(
            make_alert(
                "ECG-CD2-001",
                "Source IP is not in the authorized ECG/CD2 source register.",
                _source_tuple_evidence(record, "source_ip_miss") | {"authorized_source_ips": sorted(config.authorized_source_ips)},
            )
        )

    if config.authorized_destination_ips and destination_ip not in config.authorized_destination_ips:
        alerts.append(
            make_alert(
                "ECG-CD2-001",
                "Destination IP is not in the authorized ECG/CD2 destination register.",
                _source_tuple_evidence(record, "destination_ip_miss") | {"authorized_destination_ips": sorted(config.authorized_destination_ips)},
            )
        )

    allowed_sources_for_site = config.site_source_ips.get(site_id)
    if allowed_sources_for_site and source_ip not in allowed_sources_for_site:
        alerts.append(
            make_alert(
                "ECG-CD2-001",
                "Site identity was observed from an unexpected ECG/CD2 source IP.",
                _source_tuple_evidence(record, "site_source_miss") | {"allowed_source_ips": sorted(allowed_sources_for_site)},
            )
        )

    if config.allowed_radar_ports and source_port not in config.allowed_radar_ports and destination_port not in config.allowed_radar_ports:
        alerts.append(
            make_alert(
                "ECG-CD2-001",
                "Neither source nor destination port is in the allowed ECG/CD2 port register.",
                _source_tuple_evidence(record, "port_miss") | {"allowed_radar_ports": sorted(config.allowed_radar_ports)},
            )
        )

    return alerts


def _checksum_alerts(record: Mapping[str, Any], config: EcgAlertConfig | None) -> list[dict[str, Any]]:
    checksum_value = _as_int(record.get("udp_checksum"))
    checksum_valid = record.get("udp_checksum_valid")
    zero_allowed = True if config is None else config.udp_zero_checksum_allowed

    if checksum_valid is False:
        return [
            make_alert(
                "ECG-CD2-003",
                "UDP checksum is invalid; validate capture/NIC offload path before treating as malicious.",
                _checksum_evidence(record, "invalid"),
            )
        ]

    if checksum_value == 0 and not zero_allowed:
        return [
            make_alert(
                "ECG-CD2-003",
                "UDP checksum is zero while policy expects a nonzero checksum; account for IPv4 zero-checksum and checksum-offload behavior.",
                _checksum_evidence(record, "zero_unexpected"),
            )
        ]

    return []


def _malformed_evidence(
    record: Mapping[str, Any],
    error_code: str,
    error_message: str,
    parser_stage: str,
) -> dict[str, Any]:
    return {
        "network_bytes": record.get("network_bytes"),
        "udp_length": record.get("udp_length"),
        "udp_payload_length": record.get("udp_payload_length"),
        "claimed_ecg_length": record.get("ecg_frame_length_claimed"),
        "expected_ecg_length": record.get("ecg_frame_length_expected"),
        "ecg_frame_length_valid": record.get("ecg_frame_length_valid"),
        "inner_message_offset": None,
        "inner_message_length": record.get("message_data_length"),
        "parser_drop_reason": error_code,
        "error_message": error_message,
        "parser_stage": parser_stage,
    }


def _checksum_evidence(record: Mapping[str, Any], result: str) -> dict[str, Any]:
    return {
        "udp.checksum.valid": record.get("udp_checksum_valid"),
        "udp.checksum.value_hex": record.get("udp_checksum_hex"),
        "source_ip": record.get("source_ip"),
        "source_port": record.get("source_port"),
        "destination_ip": record.get("destination_ip"),
        "destination_port": record.get("destination_port"),
        "udp_payload_length": record.get("udp_payload_length"),
        "checksum_policy_result": result,
    }


def _source_tuple_key(record: Mapping[str, Any]) -> str:
    values = (
        record.get("source_ip"),
        record.get("destination_ip"),
        record.get("source_port"),
        record.get("destination_port"),
        record.get("artcc"),
        record.get("site_id"),
        record.get("channel"),
        record.get("message_code"),
        record.get("message"),
    )
    return "|".join(_tuple_part(value) for value in values)


def _site_artcc_channel_tuple_key(record: Mapping[str, Any]) -> str:
    values = (
        record.get("source_ip"),
        record.get("destination_ip"),
        record.get("artcc"),
        record.get("site_id"),
        record.get("channel"),
        record.get("message_code"),
        record.get("message"),
    )
    return "|".join(_tuple_part(value) for value in values)


def _source_tuple_evidence(record: Mapping[str, Any], allowlist_result: str) -> dict[str, Any]:
    return {
        "source_ip": record.get("source_ip"),
        "source_port": record.get("source_port"),
        "destination_ip": record.get("destination_ip"),
        "destination_port": record.get("destination_port"),
        "artcc": record.get("artcc"),
        "site_id": record.get("site_id"),
        "channel": record.get("channel"),
        "message_code": record.get("message_code"),
        "message_name": record.get("message"),
        "allowlist_result": allowlist_result,
        "observed_tuple": _source_tuple_key(record),
    }


def _site_tuple_evidence(record: Mapping[str, Any], baseline_result: str) -> dict[str, Any]:
    return {
        "source_ip": record.get("source_ip"),
        "destination_ip": record.get("destination_ip"),
        "artcc": record.get("artcc"),
        "site_id": record.get("site_id"),
        "channel": record.get("channel"),
        "message_code": record.get("message_code"),
        "message_name": record.get("message"),
        "baseline_result": baseline_result,
        "observed_tuple": _site_artcc_channel_tuple_key(record),
    }


def _tuple_part(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()

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
        make_alert(
            "OAD-ECG-007",
            "Required radar words are missing from a projectable ECG message.",
            {"message": message, "message_type": message_type, "missing_words": missing, "data_word_count": len(data_words)},
        )
    ]


def make_alert(
    alert_id: str,
    details: str,
    evidence: Mapping[str, Any],
    *,
    scope: str = "stateless",
) -> dict[str, Any]:
    name, severity, category = ALERT_DEFINITIONS[alert_id]
    operator = LEGACY_OPERATOR_ALERT_TAXONOMY.get(alert_id, {})
    alert = {
        "id": alert_id,
        "name": name,
        "severity": severity,
        "category": category,
        "details": details,
        "message": details,
        "event.kind": "alert",
        "event.category": category,
        "event.action": name,
        "event.severity": severity,
        "rule.id": alert_id,
        "rule.name": name,
        "rule.category": category,
        "evidence": dict(evidence),
    }
    alert.update(operator)
    return alert


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


def _apply_alert_overrides(
    alerts: Sequence[Mapping[str, Any]],
    config: EcgAlertConfig | None,
) -> list[dict[str, Any]]:
    if config is None or not config.desired_alert_overrides:
        return [dict(alert) for alert in alerts]

    result: list[dict[str, Any]] = []
    for alert in alerts:
        alert_id = str(alert.get("id") or "")
        override = config.desired_alert_overrides.get(alert_id)
        if override is not None and override.enabled is False:
            continue
        updated = dict(alert)
        if override is not None and override.severity:
            updated["severity"] = override.severity
            updated["event.severity"] = override.severity
        result.append(updated)
    return result


def _alert_override_map(value: Any, schema_version: str) -> dict[str, AlertOverride]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("desired_alert_overrides must be an object keyed by alert ID")
    if value and schema_version != ALERT_POLICY_V2_SCHEMA_VERSION:
        raise ValueError(
            "desired_alert_overrides require schema_version %s" % ALERT_POLICY_V2_SCHEMA_VERSION
        )

    overrides: dict[str, AlertOverride] = {}
    for alert_id, override in sorted(value.items()):
        if alert_id not in ALERT_DEFINITIONS:
            raise ValueError("Unknown alert ID in desired_alert_overrides: %s" % alert_id)
        if not isinstance(override, dict):
            raise ValueError("desired_alert_overrides.%s must be an object" % alert_id)
        unknown = sorted(set(override) - ALERT_POLICY_SUPPORTED_OVERRIDE_KEYS)
        unsupported = [key for key in unknown if key in ALERT_POLICY_UNSUPPORTED_OVERRIDE_KEYS]
        if unsupported:
            raise ValueError(
                "desired_alert_overrides.%s has unsupported override key(s): %s"
                % (alert_id, ", ".join(unsupported))
            )
        if unknown:
            raise ValueError(
                "desired_alert_overrides.%s has unknown override key(s): %s"
                % (alert_id, ", ".join(unknown))
            )

        enabled = override.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("desired_alert_overrides.%s.enabled must be boolean" % alert_id)
        severity = override.get("severity")
        if severity is not None:
            if not isinstance(severity, str) or severity not in SEVERITY_RANK:
                raise ValueError(
                    "desired_alert_overrides.%s.severity must be one of: %s"
                    % (alert_id, ", ".join(sorted(SEVERITY_RANK)))
                )
        overrides[alert_id] = AlertOverride(enabled=enabled, severity=severity)
    return overrides


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


def _optional_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("%s must be boolean" % name)


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

"""INI configuration support for oad-parser.

Operators can run the parser with simple config files instead of long command
lines. CLI flags still override config-file values when both are provided.
"""

from __future__ import annotations

from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DISCOVERY_WINDOW_RECORDS = 100
DEFAULT_MAX_SEQUENCE_DELTA = 10
DEFAULT_MAX_RANGE_NM = 300.0
DEFAULT_MAX_AZIMUTH_JUMP_DEGREES = 45.0
DEFAULT_CD2_RECEIVE_FRAME_SIZE_WORDS = 32

DEFAULT_LIVE_OUTPUT_JSON_FILE = "/nsm/ecg/ecg-current.json"
DEFAULT_LIVE_OUTPUT_CSV_FILE = "/nsm/ecg/ecg.csv"
DEFAULT_LIVE_OUTPUT_DIR = "/nsm/ecg"
DEFAULT_LIVE_AUDIT_FILE = "/var/log/oad-parser/ecg-audit.jsonl"
DEFAULT_LIVE_STATUS_FILE = "/run/oad-parser/ecg-status.json"
DEFAULT_LIVE_INTERFACE = "eno1"
DEFAULT_LIVE_MODE = "legacy_jsonl"
DEFAULT_LIVE_DATA_STREAM_TYPE = "logs"
DEFAULT_LIVE_DATA_STREAM_DATASET = "radar.oad.new"
DEFAULT_LIVE_EVENT_DATASET = "radar.oad.new"
DEFAULT_LIVE_SERVICE_NAME = "oad-ecg-parser"
DEFAULT_LIVE_ROTATE_SECONDS = 900
DEFAULT_LIVE_ROTATE_MAX_BYTES = 536870912
DEFAULT_LIVE_ROTATION_ENABLED = False
DEFAULT_LIVE_OUTPUT_STATUS = False
DEFAULT_LIVE_SIEM_DEBUG_EVIDENCE = False
DEFAULT_LIVE_NORMAL_RECORD_SAMPLE_RATE = 1
DEFAULT_LIVE_EMIT_PARSE_WARNING_ALERTS = True
DEFAULT_LIVE_EMIT_MODEC_ALTITUDE_MISSING_ALERTS = True
DEFAULT_LIVE_RECEIVE_BUFFER_BYTES = 134217728
DEFAULT_LIVE_STATUS_INTERVAL_SECONDS = 60
DEFAULT_LIVE_METRICS_INTERVAL_SECONDS = 60
DEFAULT_LIVE_PRUNE_AFTER_SECONDS = 43200
DEFAULT_LIVE_DISK_HIGH_WATER_PERCENT = 75
DEFAULT_LIVE_DISK_CRITICAL_PERCENT = 95


@dataclass
class ParserConfig:
    output_path: str | None = None
    schema: str = "ecs"
    interface: str | None = None
    max_frames: int | None = None
    detectors_enabled: bool = False
    discovery_window_records: int = DEFAULT_DISCOVERY_WINDOW_RECORDS
    max_sequence_delta: int | None = DEFAULT_MAX_SEQUENCE_DELTA
    max_range_nm: float | None = DEFAULT_MAX_RANGE_NM
    max_azimuth_jump_degrees: float | None = DEFAULT_MAX_AZIMUTH_JUMP_DEGREES
    max_router_time_delta_seconds: float | None = None
    max_radar_time_delta_seconds: float | None = None

    cd2_add_remove_parity: bool = False
    cd2_receive_frame_size_words: int = DEFAULT_CD2_RECEIVE_FRAME_SIZE_WORDS
    cd2_error_screening: bool = False
    cd2_data_inversion: bool = False
    cd2_parity_mode: str = "odd"
    cd2_decoder: str | None = None


@dataclass
class LiveParserConfig:
    output_json_file: str = DEFAULT_LIVE_OUTPUT_JSON_FILE
    output_csv_file: str = DEFAULT_LIVE_OUTPUT_CSV_FILE
    output_json: bool = True
    output_csv: bool = False
    output_csv_requested: bool = False
    skip_headers: bool = True

    check_range: bool = True
    check_altitude: bool = True
    check_azimuth: bool = True
    check_site_discovery: bool = True
    check_time_delta: bool = True
    check_fingerprint: bool = True
    output_status: bool = DEFAULT_LIVE_OUTPUT_STATUS

    interface: str = DEFAULT_LIVE_INTERFACE
    mode: str = DEFAULT_LIVE_MODE
    data_stream_type: str = DEFAULT_LIVE_DATA_STREAM_TYPE
    data_stream_dataset: str = DEFAULT_LIVE_DATA_STREAM_DATASET
    event_dataset: str = DEFAULT_LIVE_EVENT_DATASET
    service_name: str = DEFAULT_LIVE_SERVICE_NAME
    rotation_enabled: bool = DEFAULT_LIVE_ROTATION_ENABLED
    rotate_seconds: int = DEFAULT_LIVE_ROTATE_SECONDS
    rotate_max_bytes: int = DEFAULT_LIVE_ROTATE_MAX_BYTES
    receive_buffer_bytes: int = DEFAULT_LIVE_RECEIVE_BUFFER_BYTES
    status_interval_seconds: int = DEFAULT_LIVE_STATUS_INTERVAL_SECONDS
    metrics_interval_seconds: int = DEFAULT_LIVE_METRICS_INTERVAL_SECONDS

    output_dir: str = DEFAULT_LIVE_OUTPUT_DIR
    prune_after_seconds: int = DEFAULT_LIVE_PRUNE_AFTER_SECONDS
    disk_high_water_percent: int = DEFAULT_LIVE_DISK_HIGH_WATER_PERCENT
    disk_critical_percent: int = DEFAULT_LIVE_DISK_CRITICAL_PERCENT
    block_when_full: bool = True
    compress_archives: bool = False
    compress_archives_requested: bool = False

    audit_file: str = DEFAULT_LIVE_AUDIT_FILE
    status_file: str = DEFAULT_LIVE_STATUS_FILE
    alert_config_path: str | None = None
    siem_debug_evidence: bool = DEFAULT_LIVE_SIEM_DEBUG_EVIDENCE
    normal_record_sample_rate: int = DEFAULT_LIVE_NORMAL_RECORD_SAMPLE_RATE
    emit_parse_warning_alerts: bool = DEFAULT_LIVE_EMIT_PARSE_WARNING_ALERTS
    emit_modec_altitude_missing_alerts: bool = DEFAULT_LIVE_EMIT_MODEC_ALTITUDE_MISSING_ALERTS


def load_parser_config(path: str | Path | None) -> ParserConfig:
    config = ParserConfig()
    if path is None:
        return config

    parser = ConfigParser()
    loaded = parser.read(path)
    if not loaded:
        raise FileNotFoundError(f"config file not found: {path}")

    if parser.has_section("output"):
        config.output_path = _optional_string(parser.get("output", "path", fallback=None))
        config.schema = parser.get("output", "schema", fallback=config.schema).strip() or config.schema

    if parser.has_section("capture"):
        config.interface = _optional_string(parser.get("capture", "interface", fallback=None))
        config.max_frames = _optional_int(parser.get("capture", "max_frames", fallback=None))

    if parser.has_section("detectors"):
        config.detectors_enabled = parser.getboolean(
            "detectors",
            "enabled",
            fallback=config.detectors_enabled,
        )
        config.discovery_window_records = parser.getint(
            "detectors",
            "discovery_window_records",
            fallback=config.discovery_window_records,
        )
        config.max_sequence_delta = _optional_int(
            parser.get("detectors", "max_sequence_delta", fallback=None),
            default=config.max_sequence_delta,
        )
        config.max_range_nm = _optional_float(
            parser.get("detectors", "max_range_nm", fallback=None),
            default=config.max_range_nm,
        )
        config.max_azimuth_jump_degrees = _optional_float(
            parser.get("detectors", "max_azimuth_jump_degrees", fallback=None),
            default=config.max_azimuth_jump_degrees,
        )
        config.max_router_time_delta_seconds = _optional_float(
            parser.get("detectors", "max_router_time_delta_seconds", fallback=None),
        )
        config.max_radar_time_delta_seconds = _optional_float(
            parser.get("detectors", "max_radar_time_delta_seconds", fallback=None),
        )

    if parser.has_section("cd2"):
        config.cd2_add_remove_parity = parser.getboolean(
            "cd2",
            "add_remove_parity",
            fallback=config.cd2_add_remove_parity,
        )
        config.cd2_receive_frame_size_words = parser.getint(
            "cd2",
            "receive_frame_size_words",
            fallback=config.cd2_receive_frame_size_words,
        )
        config.cd2_error_screening = parser.getboolean(
            "cd2",
            "error_screening",
            fallback=config.cd2_error_screening,
        )
        config.cd2_data_inversion = parser.getboolean(
            "cd2",
            "data_inversion",
            fallback=config.cd2_data_inversion,
        )
        config.cd2_parity_mode = parser.get(
            "cd2",
            "parity_mode",
            fallback=config.cd2_parity_mode,
        ).strip().lower()
        config.cd2_decoder = _optional_string(
            parser.get("cd2", "decoder", fallback=None)
        )

    if config.schema not in {"ecs", "legacy"}:
        raise ValueError(f"unsupported schema in config: {config.schema}")

    if config.cd2_receive_frame_size_words < 1:
        raise ValueError("cd2 receive_frame_size_words must be >= 1")

    if config.cd2_parity_mode not in {"odd", "even"}:
        raise ValueError("cd2 parity_mode must be odd or even")

    if config.cd2_decoder is not None and config.cd2_decoder not in {"raw12", "beacon-candidate"}:
        raise ValueError("cd2 decoder must be raw12 or beacon-candidate")

    return config


def load_live_parser_config(path: str | Path | None) -> LiveParserConfig:
    config = LiveParserConfig()
    if path is None:
        return config

    parser = ConfigParser()
    loaded = parser.read(path)
    if not loaded:
        raise FileNotFoundError(f"config file not found: {path}")

    if parser.has_section("Outputs"):
        config.output_json_file = _get_string(
            parser,
            "Outputs",
            "output_json_file",
            config.output_json_file,
        )
        config.output_csv_file = _get_string(
            parser,
            "Outputs",
            "output_csv_file",
            config.output_csv_file,
        )

    if parser.has_section("Options"):
        config.skip_headers = parser.getboolean("Options", "skip_headers", fallback=config.skip_headers)
        config.output_json = parser.getboolean("Options", "output_json", fallback=config.output_json)

        requested_csv = parser.getboolean("Options", "output_csv", fallback=config.output_csv_requested)
        config.output_csv_requested = requested_csv
        config.output_csv = False

        config.check_range = parser.getboolean("Options", "check_range", fallback=config.check_range)
        config.check_altitude = parser.getboolean("Options", "check_altitude", fallback=config.check_altitude)
        config.check_azimuth = parser.getboolean("Options", "check_azimuth", fallback=config.check_azimuth)
        config.check_site_discovery = parser.getboolean(
            "Options",
            "check_site_discovery",
            fallback=config.check_site_discovery,
        )
        config.check_time_delta = parser.getboolean(
            "Options",
            "check_time_delta",
            fallback=config.check_time_delta,
        )
        config.check_fingerprint = parser.getboolean(
            "Options",
            "check_fingerprint",
            fallback=config.check_fingerprint,
        )
        config.output_status = parser.getboolean("Options", "output_status", fallback=config.output_status)
        config.siem_debug_evidence = parser.getboolean("Options", "siem_debug_evidence", fallback=config.siem_debug_evidence)

    if parser.has_section("Live"):
        if parser.has_option("Live", "interface"):
            config.interface = _optional_string(
                parser.get("Live", "interface", fallback=None)
            ) or ""
        config.mode = _get_string(parser, "Live", "mode", config.mode)
        config.rotation_enabled = parser.getboolean("Live", "rotation_enabled", fallback=config.rotation_enabled)
        config.rotate_seconds = parser.getint("Live", "rotate_seconds", fallback=config.rotate_seconds)
        config.rotate_max_bytes = parser.getint("Live", "rotate_max_bytes", fallback=config.rotate_max_bytes)
        config.receive_buffer_bytes = parser.getint(
            "Live",
            "receive_buffer_bytes",
            fallback=config.receive_buffer_bytes,
        )
        config.status_interval_seconds = parser.getint(
            "Live",
            "status_interval_seconds",
            fallback=config.status_interval_seconds,
        )
        config.metrics_interval_seconds = parser.getint(
            "Live",
            "metrics_interval_seconds",
            fallback=config.metrics_interval_seconds,
        )
        config.normal_record_sample_rate = parser.getint(
            "Live",
            "normal_record_sample_rate",
            fallback=config.normal_record_sample_rate,
        )
        config.emit_parse_warning_alerts = parser.getboolean(
            "Live",
            "emit_parse_warning_alerts",
            fallback=config.emit_parse_warning_alerts,
        )
        config.emit_modec_altitude_missing_alerts = parser.getboolean(
            "Live",
            "emit_modec_altitude_missing_alerts",
            fallback=config.emit_modec_altitude_missing_alerts,
        )

    if parser.has_section("Storage"):
        config.output_dir = _get_string(parser, "Storage", "output_dir", config.output_dir)
        config.prune_after_seconds = parser.getint(
            "Storage",
            "prune_after_seconds",
            fallback=config.prune_after_seconds,
        )
        config.disk_high_water_percent = parser.getint(
            "Storage",
            "disk_high_water_percent",
            fallback=config.disk_high_water_percent,
        )
        config.disk_critical_percent = parser.getint(
            "Storage",
            "disk_critical_percent",
            fallback=config.disk_critical_percent,
        )
        config.block_when_full = parser.getboolean(
            "Storage",
            "block_when_full",
            fallback=config.block_when_full,
        )

        requested_compression = parser.getboolean(
            "Storage",
            "compress_archives",
            fallback=config.compress_archives_requested,
        )
        config.compress_archives_requested = requested_compression
        config.compress_archives = False

    if parser.has_section("Audit"):
        config.audit_file = _get_string(parser, "Audit", "audit_file", config.audit_file)
        config.status_file = _get_string(parser, "Audit", "status_file", config.status_file)

    if parser.has_section("SIEM"):
        config.data_stream_type = _get_string(parser, "SIEM", "data_stream_type", config.data_stream_type)
        config.data_stream_dataset = _get_string(parser, "SIEM", "data_stream_dataset", config.data_stream_dataset)
        config.event_dataset = _get_string(parser, "SIEM", "event_dataset", config.event_dataset)
        config.service_name = _get_string(parser, "SIEM", "service_name", config.service_name)

    if parser.has_section("Alerts"):
        config.alert_config_path = _optional_string(
            parser.get("Alerts", "alert_config_path", fallback=None)
        )

    _apply_existing_ini_fallbacks(parser, config)
    _validate_live_parser_config(config)
    return config


def _apply_existing_ini_fallbacks(parser: ConfigParser, config: LiveParserConfig) -> None:
    if parser.has_section("output"):
        output_path = _optional_string(parser.get("output", "path", fallback=None))
        if output_path is not None and not parser.has_section("Outputs"):
            config.output_json_file = output_path

    if parser.has_section("capture"):
        interface = _optional_string(parser.get("capture", "interface", fallback=None))
        if interface is not None and not parser.has_section("Live"):
            config.interface = interface

    if parser.has_section("detectors") and not parser.has_section("Options"):
        detectors_enabled = parser.getboolean("detectors", "enabled", fallback=True)
        if not detectors_enabled:
            config.check_range = False
            config.check_altitude = False
            config.check_azimuth = False
            config.check_site_discovery = False
            config.check_time_delta = False
            config.check_fingerprint = False


def _validate_live_parser_config(config: LiveParserConfig) -> None:
    if not config.output_json:
        raise ValueError("live JSON output must remain enabled for MVP")

    if config.output_csv:
        raise ValueError("live CSV output is disabled for MVP")

    if not config.output_json_file:
        raise ValueError("live output_json_file is required")

    if not config.interface:
        raise ValueError("live interface is required")

    if config.mode != "legacy_jsonl":
        raise ValueError("live mode must be legacy_jsonl for MVP")

    if not config.data_stream_type:
        raise ValueError("live data_stream_type is required")

    if not config.data_stream_dataset:
        raise ValueError("live data_stream_dataset is required")

    if not config.event_dataset:
        raise ValueError("live event_dataset is required")

    if not config.service_name:
        raise ValueError("live service_name is required")

    if config.rotate_seconds < 1:
        raise ValueError("live rotate_seconds must be >= 1")

    if config.rotate_max_bytes < 1:
        raise ValueError("live rotate_max_bytes must be >= 1")

    if config.receive_buffer_bytes < 1:
        raise ValueError("live receive_buffer_bytes must be >= 1")

    if config.normal_record_sample_rate < 1:
        raise ValueError("live normal_record_sample_rate must be >= 1")

    if config.status_interval_seconds < 1:
        raise ValueError("live status_interval_seconds must be >= 1")

    if config.metrics_interval_seconds < 1:
        raise ValueError("live metrics_interval_seconds must be >= 1")

    if config.prune_after_seconds < 0:
        raise ValueError("live prune_after_seconds must be >= 0")

    if not 0 <= config.disk_high_water_percent <= 100:
        raise ValueError("live disk_high_water_percent must be between 0 and 100")

    if not 0 <= config.disk_critical_percent <= 100:
        raise ValueError("live disk_critical_percent must be between 0 and 100")

    if config.disk_critical_percent <= config.disk_high_water_percent:
        raise ValueError("live disk_critical_percent must be greater than disk_high_water_percent")


def _get_string(parser: ConfigParser, section: str, option: str, default: str) -> str:
    return _optional_string(parser.get(section, option, fallback=None)) or default


def _optional_string(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _optional_int(value: str | None, default: int | None = None) -> int | None:
    stripped = _optional_string(value)
    if stripped is None:
        return default
    return int(stripped)


def _optional_float(value: str | None, default: float | None = None) -> float | None:
    stripped = _optional_string(value)
    if stripped is None:
        return default
    return float(stripped)

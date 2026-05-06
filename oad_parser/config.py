"""INI configuration support for oad-parser.

Operators can run the parser with simple config files instead of long command
lines. CLI flags still override config-file values when both are provided.
"""

from __future__ import annotations

from configparser import ConfigParser
from dataclasses import dataclass

DEFAULT_DISCOVERY_WINDOW_RECORDS = 100
DEFAULT_MAX_SEQUENCE_DELTA = 10
DEFAULT_MAX_RANGE_NM = 300.0
DEFAULT_MAX_AZIMUTH_JUMP_DEGREES = 45.0
DEFAULT_CD2_RECEIVE_FRAME_SIZE_WORDS = 32
from pathlib import Path


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

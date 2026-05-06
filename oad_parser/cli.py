"""Command-line interface for oad-parser.

This module keeps operator-facing commands separate from parser logic.
The parser core can be tested with bytes and records; this file only handles
arguments, config resolution, and user-friendly command execution.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from oad_parser import __version__
from oad_parser.compare import compare_legacy_records_to_envelopes, comparison_summary
from oad_parser.corpus import validate_corpus_path
from oad_parser.corpus_report import load_corpus_report, summarize_corpus_report
from oad_parser.config import ParserConfig, load_parser_config
from oad_parser.decoders.cd2_radar import decode_beacon_candidate_words, decode_raw12_words
from oad_parser.decoders.registry import build_default_registry
from oad_parser.fixture_samples import generate_fixture_samples
from oad_parser.golden import check_golden_fixture, write_golden_fixture
from oad_parser.errors import OadParserError
from oad_parser.detectors import DetectionConfig, DetectionEngine
from oad_parser.ingest.live_socket import iter_live_frames
from oad_parser.ingest.pcap import iter_pcap_packets
from oad_parser.inspect import inspect_pcap
from oad_parser.output import validate_jsonl, write_jsonl
from oad_parser.parsers.cd2 import (
    Cd2Frame,
    Cd2LinkConfig,
    frame_13_bit_values,
    frame_byte_stream,
    normalize_13_bit_word,
)
from oad_parser.parsers.ecg import extract_ecg_messages, parse_frame
from oad_parser.platform_validation import format_platform_validation_report, validate_platform
from oad_parser.runtime import write_frame_stream_jsonl
from oad_parser.source_pack import create_source_pack


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oad-parser",
        description="OAD parser platform for ECG/CD2 pcap replay, live capture, and JSONL output.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect-pcap", help="Inspect a pcap with stdlib parsing.")
    inspect.add_argument("input", help="Input pcap path.")

    parse_pcap = subparsers.add_parser("parse-pcap", help="Replay a pcap and emit JSONL.")
    add_output_args(parse_pcap)
    add_detector_args(parse_pcap)
    parse_pcap.add_argument("input", help="Input pcap path.")
    parse_pcap.add_argument("--interface", default=None, help="Observer interface name.")

    capture = subparsers.add_parser("capture", help="Capture from a Linux interface and emit JSONL.")
    add_output_args(capture)
    add_detector_args(capture)
    capture.add_argument("--interface", default=None, help="Linux interface to capture from.")
    capture.add_argument(
        "--max-frames",
        type=int,
        default=None,
        help="Stop after N frames. Required for bounded JSONL output.",
    )

    decode_cd2 = subparsers.add_parser(
        "decode-cd2-words",
        help="Decode and frame CD2 13-bit words for troubleshooting.",
    )
    decode_cd2.add_argument(
        "words",
        nargs="*",
        help="13-bit CD2 words as 0x-prefixed hex, 0b-prefixed binary, decimal, or hex with A-F.",
    )
    decode_cd2.add_argument("--config", default=None, help="Optional INI config path.")
    decode_cd2.add_argument(
        "--input",
        default=None,
        help="Optional file containing word tokens, or raw bytes when --from-bytes is set.",
    )
    decode_cd2.add_argument(
        "--from-bytes",
        action="store_true",
        help="Treat --input as raw MSB-first bytes instead of text word tokens.",
    )
    decode_cd2.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    decode_cd2.add_argument(
        "--decoder",
        choices=["raw12", "beacon-candidate"],
        default=None,
        help="Optionally decode each framed CD2 message with a registered decoder.",
    )
    decode_cd2.add_argument(
        "--list-decoders",
        action="store_true",
        help="List available CD2 frame decoders and exit.",
    )

    extract_ecg = subparsers.add_parser(
        "extract-ecg-messages",
        help="Extract ECG message envelopes from pcap or raw ECG payload bytes.",
    )
    extract_ecg.add_argument("input", help="Input pcap path, or raw ECG payload path with --raw-payload.")
    extract_ecg.add_argument("--config", default=None, help="Optional INI config path.")
    extract_ecg.add_argument(
        "--raw-payload",
        action="store_true",
        help="Treat input as raw ECG payload bytes instead of a pcap.",
    )
    extract_ecg.add_argument("--jsonl", action="store_true", help="Emit one JSON object per line.")
    extract_ecg.add_argument("--output", default=None, help="Optional output path for JSON or JSONL.")
    extract_ecg.add_argument(
        "--decoder",
        choices=["raw12", "beacon-candidate"],
        default=None,
        help="Optionally attach decoder output to each ECG envelope.",
    )

    compare_legacy = subparsers.add_parser(
        "compare-legacy-envelope",
        help="Compare legacy parse_frame output against ECG envelope decoder output.",
    )
    compare_legacy.add_argument("input", help="Input pcap path, or raw ECG payload path with --raw-payload.")
    compare_legacy.add_argument(
        "--raw-payload",
        action="store_true",
        help="Treat input as raw ECG payload bytes instead of a pcap.",
    )
    compare_legacy.add_argument("--jsonl", action="store_true", help="Emit one JSON object per line.")
    compare_legacy.add_argument("--output", default=None, help="Optional output path for JSON or JSONL.")

    validate_corpus = subparsers.add_parser(
        "validate-corpus",
        help="Validate a corpus of pcap and raw ECG payload files against legacy/envelope comparison.",
    )
    validate_corpus.add_argument("path", help="Corpus directory or single file.")
    validate_corpus.add_argument(
        "--raw-payload",
        action="store_true",
        help="Treat input file(s) as raw ECG payload bytes.",
    )
    validate_corpus.add_argument("--output", default=None, help="Optional output path for report JSON.")

    summarize_corpus = subparsers.add_parser(
        "summarize-corpus-report",
        help="Print a compact human-readable summary of a validate-corpus JSON report.",
    )
    summarize_corpus.add_argument("input", help="Input corpus report JSON path.")
    summarize_corpus.add_argument(
        "--show-matches",
        action="store_true",
        help="Include matched files in the summary.",
    )
    summarize_corpus.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of files to show per section.",
    )
    summarize_corpus.add_argument("--output", default=None, help="Optional output path for text summary.")

    export_golden = subparsers.add_parser(
        "export-golden-fixture",
        help="Export a golden fixture from a pcap or raw ECG payload.",
    )
    export_golden.add_argument("input", help="Input pcap path, or raw ECG payload path with --raw-payload.")
    export_golden.add_argument("--output", required=True, help="Golden fixture JSON output path.")
    export_golden.add_argument(
        "--raw-payload",
        action="store_true",
        help="Treat input as raw ECG payload bytes instead of a pcap.",
    )

    check_golden = subparsers.add_parser(
        "check-golden-fixture",
        help="Check current parser output against a golden fixture.",
    )
    check_golden.add_argument("fixture", help="Golden fixture JSON path.")
    check_golden.add_argument(
        "--input",
        default=None,
        help="Optional input sample override. Defaults to the fixture source path.",
    )

    generate_fixtures = subparsers.add_parser(
        "generate-fixture-samples",
        help="Generate deterministic non-sensitive parser fixture samples.",
    )
    generate_fixtures.add_argument(
        "--output-dir",
        required=True,
        help="Directory where synthetic fixture samples will be written.",
    )
    generate_fixtures.add_argument(
        "--json",
        action="store_true",
        help="Emit generated file manifest as JSON.",
    )

    validate_platform_parser = subparsers.add_parser(
        "validate-platform",
        help="Run a local end-to-end parser platform health check.",
    )
    validate_platform_parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional directory to keep generated validation artifacts.",
    )
    validate_platform_parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Run unittest discovery as part of the platform validation.",
    )
    validate_platform_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit validation report as JSON.",
    )

    source_pack = subparsers.add_parser(
        "create-source-pack",
        help="Create a safe source-pack tar.gz for AI/developer handoff.",
    )
    source_pack.add_argument(
        "--output",
        required=True,
        help="Output .tar.gz path.",
    )
    source_pack.add_argument(
        "--tracked-only",
        action="store_true",
        help="Use tracked-only source-pack mode. This is the default for release safety.",
    )
    source_pack.add_argument(
        "--include-untracked",
        action="store_true",
        help="Include untracked files. Internal use only; do not use for customer release packs.",
    )
    source_pack.add_argument(
        "--json",
        action="store_true",
        help="Emit source-pack result as JSON.",
    )

    validate = subparsers.add_parser("validate", help="Validate JSONL output.")
    validate.add_argument("input", help="Input JSONL path.")

    return parser


def add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default=None, help="Optional INI config path.")
    parser.add_argument("--output", default=None, help="Output JSONL path.")
    parser.add_argument("--schema", choices=["ecs", "legacy"], default=None)


def add_detector_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--detect", action="store_true", help="Run detector state.")
    parser.add_argument("--discovery-window-records", type=int, default=None)
    parser.add_argument("--max-sequence-delta", type=int, default=None)
    parser.add_argument("--max-range-nm", type=float, default=None)
    parser.add_argument("--max-azimuth-jump-degrees", type=float, default=None)
    parser.add_argument("--max-router-time-delta-seconds", type=float, default=None)
    parser.add_argument("--max-radar-time-delta-seconds", type=float, default=None)


def packet_timestamp_iso(
    timestamp_seconds: int,
    timestamp_fraction: int,
    timestamp_fraction_resolution: int = 1_000_000,
) -> str:
    if timestamp_fraction_resolution <= 0:
        raise ValueError("timestamp_fraction_resolution must be greater than zero")

    timestamp = timestamp_seconds + (timestamp_fraction / timestamp_fraction_resolution)
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def resolved_config_from_args(args: argparse.Namespace) -> ParserConfig:
    config = load_parser_config(args.config)

    if getattr(args, "output", None) is not None:
        config.output_path = args.output
    if getattr(args, "schema", None) is not None:
        config.schema = args.schema
    if getattr(args, "interface", None) is not None:
        config.interface = args.interface
    if getattr(args, "max_frames", None) is not None:
        config.max_frames = args.max_frames
    if getattr(args, "detect", False):
        config.detectors_enabled = True

    if getattr(args, "discovery_window_records", None) is not None:
        config.discovery_window_records = args.discovery_window_records
    if getattr(args, "max_sequence_delta", None) is not None:
        config.max_sequence_delta = args.max_sequence_delta
    if getattr(args, "max_range_nm", None) is not None:
        config.max_range_nm = args.max_range_nm
    if getattr(args, "max_azimuth_jump_degrees", None) is not None:
        config.max_azimuth_jump_degrees = args.max_azimuth_jump_degrees
    if getattr(args, "max_router_time_delta_seconds", None) is not None:
        config.max_router_time_delta_seconds = args.max_router_time_delta_seconds
    if getattr(args, "max_radar_time_delta_seconds", None) is not None:
        config.max_radar_time_delta_seconds = args.max_radar_time_delta_seconds

    if config.schema not in {"ecs", "legacy"}:
        raise ValueError(f"unsupported schema: {config.schema}")

    return config


def cd2_link_config_from_config(config: ParserConfig) -> Cd2LinkConfig:
    return Cd2LinkConfig(
        add_remove_parity=config.cd2_add_remove_parity,
        receive_frame_size_words=config.cd2_receive_frame_size_words,
        error_screening=config.cd2_error_screening,
        data_inversion=config.cd2_data_inversion,
        parity_mode=config.cd2_parity_mode,
    )


def detection_config_from_config(config: ParserConfig) -> DetectionConfig:
    return DetectionConfig(
        discovery_window_records=config.discovery_window_records,
        max_sequence_delta=config.max_sequence_delta,
        max_router_time_delta_seconds=config.max_router_time_delta_seconds,
        max_radar_time_delta_seconds=config.max_radar_time_delta_seconds,
        max_range_nm=config.max_range_nm,
        max_azimuth_jump_degrees=config.max_azimuth_jump_degrees,
    )


def require_output_path(config: ParserConfig) -> str:
    if not config.output_path:
        raise ValueError("output path is required; pass --output or set [output] path in config")
    return config.output_path


def require_interface(config: ParserConfig) -> str:
    if not config.interface:
        raise ValueError("interface is required; pass --interface or set [capture] interface in config")
    return config.interface


def require_capture_max_frames(config: ParserConfig) -> int:
    if config.max_frames is None or config.max_frames < 1:
        raise ValueError("capture max_frames is required and must be >= 1; pass --max-frames or set [capture] max_frames")
    return config.max_frames


def parse_cd2_word_token(token: str) -> int:
    cleaned = token.strip().strip(",")
    if not cleaned:
        raise ValueError("empty CD2 word token")

    if cleaned.lower().startswith("0b"):
        value = int(cleaned[2:], 2)
    elif cleaned.lower().startswith("0x"):
        value = int(cleaned[2:], 16)
    elif re.search(r"[a-fA-F]", cleaned):
        value = int(cleaned, 16)
    else:
        value = int(cleaned, 10)

    return normalize_13_bit_word(value)


def read_cd2_word_tokens(path: str | None, words: list[str]) -> list[str]:
    tokens: list[str] = []

    if path is not None:
        text = Path(path).read_text(encoding="utf-8")
        tokens.extend(token for token in re.split(r"[\s,]+", text) if token)

    tokens.extend(words)
    return tokens


def format_cd2_frames_text(frames: list[Cd2Frame]) -> str:
    lines = [f"frame_count={len(frames)}"]
    for index, frame in enumerate(frames):
        data_words = " ".join(f"0x{word:03x}" for word in frame.data_words) or "none"
        errors = "; ".join(frame.errors) if frame.errors else "none"
        lines.append(
            "frame "
            f"{index}: words={len(frame.words)} "
            f"start={frame.start_word_index} "
            f"end={frame.end_word_index} "
            f"extended_error_status=0x{frame.extended_error_status:04x} "
            f"errors={errors} "
            f"data_words={data_words}"
        )
    return "\n".join(lines)


def run_inspect_pcap(args: argparse.Namespace) -> int:
    print(inspect_pcap(args.input).to_text())
    return 0


def run_parse_pcap(args: argparse.Namespace) -> int:
    config = resolved_config_from_args(args)
    output_path = require_output_path(config)

    records = []
    for packet in iter_pcap_packets(args.input):
        records.extend(
            parse_frame(
                packet.data,
                observer_interface=config.interface,
                timestamp=packet_timestamp_iso(
                    packet.timestamp_seconds,
                    packet.timestamp_fraction,
                    packet.timestamp_fraction_resolution,
                ),
            )
        )

    if config.detectors_enabled:
        records = DetectionEngine(detection_config_from_config(config)).process_records(records)

    count = write_jsonl(records, Path(output_path), schema=config.schema)
    print(f"wrote {count} records to {output_path}")
    return 0


def run_capture(args: argparse.Namespace) -> int:
    config = resolved_config_from_args(args)
    output_path = require_output_path(config)
    interface = require_interface(config)
    max_frames = require_capture_max_frames(config)

    frames = iter_live_frames(interface=interface, max_frames=max_frames)
    count = write_frame_stream_jsonl(
        frames,
        output_path=Path(output_path),
        observer_interface=interface,
        schema=config.schema,
        detect=config.detectors_enabled,
        detection_config=detection_config_from_config(config),
    )
    print(f"wrote {count} records to {output_path}")
    return 0


def run_decode_cd2_words(args: argparse.Namespace) -> int:
    parser_config = load_parser_config(args.config)
    cd2_config = cd2_link_config_from_config(parser_config)

    if getattr(args, "list_decoders", False):
        registry = build_default_registry()
        for name in registry.names():
            entry = registry.get(name)
            print(f"{entry.name}: {entry.description}")
        return 0

    if args.from_bytes:
        if args.input is None:
            raise ValueError("--from-bytes requires --input")
        frames = frame_byte_stream(Path(args.input).read_bytes(), config=cd2_config)
    else:
        tokens = read_cd2_word_tokens(args.input, list(args.words))
        if not tokens:
            raise ValueError("provide CD2 words as arguments or with --input")
        values = [parse_cd2_word_token(token) for token in tokens]
        frames = frame_13_bit_values(values, config=cd2_config)

    decoder = getattr(args, "decoder", None) or parser_config.cd2_decoder
    if decoder:
        registry = build_default_registry()
        decoded = [registry.decode(decoder, frame) for frame in frames]
        print(json.dumps(decoded, indent=2, sort_keys=True))
    elif args.json:
        print(json.dumps([frame.to_dict() for frame in frames], indent=2, sort_keys=True))
    else:
        print(format_cd2_frames_text(frames))

    return 0


def decode_ecg_envelope_words(decoder: str, words: list[int] | tuple[int, ...]) -> dict[str, object]:
    if decoder == "raw12":
        return decode_raw12_words(words)
    if decoder == "beacon-candidate":
        return decode_beacon_candidate_words(words, input_basis="ecg_envelope_16bit_words")
    raise ValueError(f"unsupported ECG envelope decoder: {decoder}")


def run_extract_ecg_messages(args: argparse.Namespace) -> int:
    parser_config = load_parser_config(getattr(args, "config", None))
    selected_decoder = getattr(args, "decoder", None) or parser_config.cd2_decoder
    records: list[dict[str, object]] = []

    if args.raw_payload:
        for envelope in extract_ecg_messages(Path(args.input).read_bytes(), skip_headers=False):
            data = envelope.to_dict()
            if selected_decoder:
                data["decoded"] = decode_ecg_envelope_words(selected_decoder, envelope.data_words)
            records.append(data)
    else:
        for packet in iter_pcap_packets(args.input):
            for envelope in extract_ecg_messages(packet.data):
                data = envelope.to_dict()
                data["packet_timestamp"] = packet_timestamp_iso(
                    packet.timestamp_seconds,
                    packet.timestamp_fraction,
                    packet.timestamp_fraction_resolution,
                )
                if selected_decoder:
                    data["decoded"] = decode_ecg_envelope_words(selected_decoder, envelope.data_words)
                records.append(data)

    rendered = render_records(records, args.jsonl)

    output_path = getattr(args, "output", None)
    emit_rendered_output(
        rendered,
        output_path,
        f"wrote {len(records)} ECG message envelopes to {output_path}",
    )

    return 0


def render_records(records: list[dict[str, object]], jsonl: bool) -> str:
    if jsonl:
        rendered = "\n".join(json.dumps(record, sort_keys=True) for record in records)
        if rendered:
            rendered += "\n"
        return rendered
    return json.dumps(records, indent=2, sort_keys=True) + "\n"


def emit_rendered_output(rendered: str, output_path: str | None, message: str) -> None:
    if output_path:
        Path(output_path).write_text(rendered, encoding="utf-8")
        print(message)
    else:
        print(rendered, end="")


def run_compare_legacy_envelope(args: argparse.Namespace) -> int:
    comparisons = []

    if args.raw_payload:
        data = Path(args.input).read_bytes()
        comparisons.extend(
            compare_legacy_records_to_envelopes(
                parse_frame(data, skip_headers=False),
                extract_ecg_messages(data, skip_headers=False),
            )
        )
    else:
        for packet in iter_pcap_packets(args.input):
            packet_comparisons = compare_legacy_records_to_envelopes(
                parse_frame(
                    packet.data,
                    timestamp=packet_timestamp_iso(
                        packet.timestamp_seconds,
                        packet.timestamp_fraction,
                        packet.timestamp_fraction_resolution,
                    ),
                ),
                extract_ecg_messages(packet.data),
            )
            for item in packet_comparisons:
                record = item.to_dict()
                record["packet_timestamp"] = packet_timestamp_iso(
                    packet.timestamp_seconds,
                    packet.timestamp_fraction,
                    packet.timestamp_fraction_resolution,
                )
                comparisons.append(record)

    if args.raw_payload:
        records = [item.to_dict() for item in comparisons]
    else:
        records = comparisons

    summary = comparison_summary(
        [
            item
            for item in comparisons
            if hasattr(item, "match")
        ]
    ) if args.raw_payload else {
        "comparison_count": len(records),
        "match_count": sum(1 for item in records if item.get("match") is True),
        "mismatch_count": sum(1 for item in records if item.get("match") is not True),
    }

    output_records = [
        {
            "summary": summary,
            "comparisons": records,
        }
    ]

    rendered = render_records(output_records, args.jsonl)
    output_path = getattr(args, "output", None)
    emit_rendered_output(
        rendered,
        output_path,
        f"wrote {summary['comparison_count']} legacy/envelope comparisons to {output_path}",
    )

    return 0


def run_validate_corpus(args: argparse.Namespace) -> int:
    report = validate_corpus_path(args.path, force_raw_payload=args.raw_payload)
    rendered = json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    output_path = getattr(args, "output", None)
    emit_rendered_output(
        rendered,
        output_path,
        f"wrote corpus validation report to {output_path}",
    )
    if (
        report.files_with_errors
        or report.mismatch_count
        or report.zero_comparison_file_count
    ):
        return 1
    return 0


def run_summarize_corpus_report(args: argparse.Namespace) -> int:
    report = load_corpus_report(args.input)
    rendered = summarize_corpus_report(
        report,
        show_matches=args.show_matches,
        limit=args.limit,
    )
    output_path = getattr(args, "output", None)
    emit_rendered_output(
        rendered,
        output_path,
        f"wrote corpus report summary to {output_path}",
    )
    return 0


def run_export_golden_fixture(args: argparse.Namespace) -> int:
    fixture = write_golden_fixture(
        args.input,
        args.output,
        raw_payload=args.raw_payload,
    )
    print(
        "wrote golden fixture "
        f"kind={fixture['kind']} "
        f"comparisons={fixture['summary']['comparison_count']} "
        f"to {args.output}"
    )
    return 0


def run_check_golden_fixture(args: argparse.Namespace) -> int:
    result = check_golden_fixture(args.fixture, input_override=args.input)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.match else 1


def run_generate_fixture_samples(args: argparse.Namespace) -> int:
    result = generate_fixture_samples(args.output_dir)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"generated fixture samples in {result.output_dir}")
        for file_name in result.files:
            print(f"- {file_name}")
    return 0


def run_validate_platform(args: argparse.Namespace) -> int:
    report = validate_platform(
        output_dir=args.output_dir,
        run_tests=args.run_tests,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_platform_validation_report(report), end="")
    return 0 if report.passed else 1


def run_create_source_pack(args: argparse.Namespace) -> int:
    include_untracked = bool(
        getattr(args, "include_untracked", False)
        and not getattr(args, "tracked_only", False)
    )
    result = create_source_pack(
        Path.cwd(),
        args.output,
        include_untracked=include_untracked,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"created source pack: {result.output_path}")
        print(f"files: {result.file_count}")
        print(f"manifest: {result.manifest_name}")
    return 0


def run_validate(args: argparse.Namespace) -> int:
    count, errors = validate_jsonl(args.input)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"validated {count} JSONL records")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "inspect-pcap":
            return run_inspect_pcap(args)
        if args.command == "parse-pcap":
            return run_parse_pcap(args)
        if args.command == "capture":
            return run_capture(args)
        if args.command == "decode-cd2-words":
            return run_decode_cd2_words(args)
        if args.command == "extract-ecg-messages":
            return run_extract_ecg_messages(args)
        if args.command == "compare-legacy-envelope":
            return run_compare_legacy_envelope(args)
        if args.command == "validate-corpus":
            return run_validate_corpus(args)
        if args.command == "summarize-corpus-report":
            return run_summarize_corpus_report(args)
        if args.command == "export-golden-fixture":
            return run_export_golden_fixture(args)
        if args.command == "check-golden-fixture":
            return run_check_golden_fixture(args)
        if args.command == "generate-fixture-samples":
            return run_generate_fixture_samples(args)
        if args.command == "validate-platform":
            return run_validate_platform(args)
        if args.command == "create-source-pack":
            return run_create_source_pack(args)
        if args.command == "validate":
            return run_validate(args)
    except (OSError, OadParserError, ValueError) as exc:
        parser.exit(status=2, message=f"error: {exc}\n")

    parser.error(f"unsupported command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

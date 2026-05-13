#!/usr/bin/env python3
"""Synthetic 6100 PPS acceptance harness for the live ECG parser.

This harness uses deterministic synthetic frames only. It does not read PCAPs,
capture live traffic, or include operational payloads.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Dict, Iterator, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from oad_parser.config import LiveParserConfig
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.live.service import run_live_service


ETHERTYPE_IPV4 = b"\x08\x00"
IP_PROTO_UDP = 17


def build_synthetic_ecg_payload(message_code: int = 1) -> bytes:
    payload = bytearray(40)
    payload[0:2] = (24).to_bytes(2, "big")
    payload[4:8] = b"ECG\x00"
    payload[8] = 1
    payload[16:18] = (8).to_bytes(2, "big")
    payload[20:24] = b"MSG\x00"
    payload[24] = message_code
    payload[25:32] = b"PAYLOAD"
    return bytes(payload)


def build_synthetic_udp_ipv4_frame(payload: bytes) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + ETHERTYPE_IPV4

    total_length = 20 + 8 + len(payload)
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[1] = 0
    ipv4[2:4] = total_length.to_bytes(2, "big")
    ipv4[4:6] = (1).to_bytes(2, "big")
    ipv4[6:8] = (0).to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = IP_PROTO_UDP
    ipv4[10:12] = (0).to_bytes(2, "big")
    ipv4[12:16] = bytes([10, 1, 2, 3])
    ipv4[16:20] = bytes([10, 4, 5, 6])

    udp_length = 8 + len(payload)
    udp = bytearray(8)
    udp[0:2] = (6100).to_bytes(2, "big")
    udp[2:4] = (6101).to_bytes(2, "big")
    udp[4:6] = udp_length.to_bytes(2, "big")
    udp[6:8] = (0).to_bytes(2, "big")

    return ethernet + bytes(ipv4) + bytes(udp) + payload


def generate_synthetic_frames(
    *,
    frame_count: int,
    interface: str,
    timestamp_utc: datetime,
    malformed_every: int = 0,
    warning_every: int = 0,
) -> Iterator[LiveCaptureFrame]:
    for index in range(1, frame_count + 1):
        if malformed_every and index % malformed_every == 0:
            payload = bytearray(build_synthetic_ecg_payload())
            payload[0:2] = (999).to_bytes(2, "big")
            payload_bytes = bytes(payload)
        elif warning_every and index % warning_every == 0:
            payload_bytes = build_synthetic_ecg_payload(message_code=99)
        else:
            payload_bytes = build_synthetic_ecg_payload()

        frame_bytes = build_synthetic_udp_ipv4_frame(payload_bytes)
        yield LiveCaptureFrame(
            frame_bytes=frame_bytes,
            interface=interface,
            capture_time_utc=timestamp_utc,
            frame_length=len(frame_bytes),
            sequence_number=index,
        )


def run_acceptance(
    *,
    target_pps: int,
    duration_seconds: float,
    interface: str,
    output_path: str,
    malformed_every: int = 0,
    warning_every: int = 0,
) -> Dict[str, object]:
    if target_pps <= 0:
        raise ValueError("target_pps must be > 0")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be > 0")
    if malformed_every < 0:
        raise ValueError("malformed_every must be >= 0")
    if warning_every < 0:
        raise ValueError("warning_every must be >= 0")

    frame_count = int(target_pps * duration_seconds)
    if frame_count < 1:
        frame_count = 1

    started_at = datetime.now(timezone.utc)
    start_perf = time.perf_counter()

    config = LiveParserConfig(
        interface=interface,
        output_json_file="/tmp/oad-live-acceptance-ecg-current.json",
        audit_file="/tmp/oad-live-acceptance-ecg-audit.jsonl",
        status_file="/tmp/oad-live-acceptance-ecg-status.json",
    )

    records: List[dict] = []
    result = run_live_service(
        config,
        generate_synthetic_frames(
            frame_count=frame_count,
            interface=interface,
            timestamp_utc=started_at,
            malformed_every=malformed_every,
            warning_every=warning_every,
        ),
        record_sink=records.append,
        max_frames=frame_count,
        now_fn=lambda: datetime.now(timezone.utc),
    )

    elapsed_seconds = time.perf_counter() - start_perf
    completed_at = datetime.now(timezone.utc)
    observed_pps = float(result.frames_processed) / elapsed_seconds if elapsed_seconds > 0 else 0.0

    report: Dict[str, object] = {
        "schema_version": "sprint2.synthetic_acceptance.v1",
        "harness": "scripts/run_live_acceptance_6100pps.py",
        "traffic_source": "synthetic",
        "contains_real_pcap": False,
        "contains_operational_payloads": False,
        "target_pps": target_pps,
        "duration_seconds": duration_seconds,
        "target_frame_count": frame_count,
        "started_at_utc": _format_utc(started_at),
        "completed_at_utc": _format_utc(completed_at),
        "elapsed_seconds": elapsed_seconds,
        "observed_pps": observed_pps,
        "best_effort_target_met": observed_pps >= float(target_pps),
        "interface": interface,
        "stopped_reason": result.stopped_reason,
        "frames_generated": frame_count,
        "frames_processed": result.frames_processed,
        "records_emitted": result.records_emitted,
        "metrics": result.metrics.snapshot(),
        "acceptance_counters": {
            "packets_received": result.metrics.packets_received,
            "packets_dropped": result.metrics.packets_dropped,
            "packets_parsed": result.metrics.packets_parsed,
            "ecg_candidates": result.metrics.ecg_candidates,
            "valid_ecg_payloads": result.metrics.valid_ecg_payloads,
            "parse_warnings_count": result.metrics.parse_warnings_count,
            "malformed_count": result.metrics.malformed_count,
            "ecg_messages_emitted": result.metrics.ecg_messages_emitted,
            "error_records_emitted": result.metrics.error_records_emitted,
            "output_drops": result.metrics.output_drops,
            "writer_blocked_seconds": 0,
            "files_rotated": result.metrics.files_rotated,
            "files_pruned": result.metrics.files_pruned,
        },
        "limitations": [
            "Synthetic in-memory frames only.",
            "No real PCAP replay.",
            "No live raw socket capture.",
            "No operational payloads.",
            "One-hour operational acceptance must be collected on Oracle Linux Server 9.6 target hardware.",
        ],
    }

    write_report(report, output_path)
    return report


def write_report(report: Dict[str, object], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run sanitized synthetic live parser acceptance harness."
    )
    parser.add_argument(
        "--target-pps",
        type=int,
        default=6100,
        help="Target packets per second for synthetic input generation.",
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=1.0,
        help="Synthetic run duration in seconds.",
    )
    parser.add_argument(
        "--interface",
        default="synthetic0",
        help="Interface label to place on synthetic frames.",
    )
    parser.add_argument(
        "--output",
        default="reports/validation/live-acceptance-6100pps.json",
        help="Report output path.",
    )
    parser.add_argument(
        "--malformed-every",
        type=int,
        default=0,
        help="Emit a malformed synthetic ECG candidate every N frames. Zero disables.",
    )
    parser.add_argument(
        "--warning-every",
        type=int,
        default=0,
        help="Emit a warning synthetic ECG candidate every N frames. Zero disables.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    report = run_acceptance(
        target_pps=args.target_pps,
        duration_seconds=args.duration_seconds,
        interface=args.interface,
        output_path=args.output,
        malformed_every=args.malformed_every,
        warning_every=args.warning_every,
    )
    print("synthetic live acceptance complete")
    print("target_pps=%s" % report["target_pps"])
    print("duration_seconds=%s" % report["duration_seconds"])
    print("frames_processed=%s" % report["frames_processed"])
    print("observed_pps=%.2f" % report["observed_pps"])
    print("best_effort_target_met=%s" % report["best_effort_target_met"])
    print("report=%s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

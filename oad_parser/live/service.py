"""Synthetic-frame service skeleton for the production live ECG parser.

The service consumes already-captured LiveCaptureFrame objects so it can be
tested without root privileges, raw sockets, operational traffic, or runtime
files. Later issues can connect this skeleton to the raw socket adapter,
JSONL writer, audit writer, and status writer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from oad_parser.config import LiveParserConfig
from oad_parser.live.classifier import classify_live_frame
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.pipeline import process_classified_live_frame
from oad_parser.live.records import (
    EcgAuditRecord,
    EcgStatusSnapshot,
    LiveCaptureFrame,
)


RecordSink = Callable[[dict], None]
AuditSink = Callable[[EcgAuditRecord], None]
StatusSink = Callable[[EcgStatusSnapshot], None]
NowFn = Callable[[], datetime]


@dataclass(frozen=True)
class LiveServiceResult:
    """Summary returned after a finite live service run."""

    metrics: LiveMetrics
    frames_processed: int
    records_emitted: int
    stopped_reason: str
    last_error: Optional[str] = None


def run_live_service(
    config: LiveParserConfig,
    capture_frames: Iterable[LiveCaptureFrame],
    *,
    metrics: Optional[LiveMetrics] = None,
    record_sink: Optional[RecordSink] = None,
    audit_sink: Optional[AuditSink] = None,
    status_sink: Optional[StatusSink] = None,
    max_frames: Optional[int] = None,
    now_fn: Optional[NowFn] = None,
) -> LiveServiceResult:
    """Run the live service over a finite iterable of capture frames.

    Args:
        config: Live parser configuration.
        capture_frames: Iterable of synthetic or adapter-produced capture frames.
        metrics: Optional metrics instance to update.
        record_sink: Optional callable that receives JSON-serializable records.
        audit_sink: Optional callable that receives audit records.
        status_sink: Optional callable that receives final status snapshots.
        max_frames: Optional smoke-test frame limit. Not intended for systemd use.
        now_fn: Optional UTC clock function for deterministic tests.
    """

    if max_frames is not None and max_frames < 0:
        raise ValueError("max_frames must be >= 0")

    resolved_metrics = metrics if metrics is not None else LiveMetrics()
    resolved_now_fn = now_fn if now_fn is not None else _utc_now
    frames_processed = 0
    records_emitted = 0
    last_error: Optional[str] = None

    last_error = _emit_audit(
        audit_sink,
        config,
        resolved_now_fn,
        "live_service_start",
        {"max_frames": max_frames},
        last_error,
    )

    frame_iter = iter(capture_frames)
    while True:
        if max_frames is not None and frames_processed >= max_frames:
            stopped_reason = "max_frames"
            break

        try:
            capture_frame = next(frame_iter)
        except StopIteration:
            stopped_reason = "input_exhausted"
            break

        classification = classify_live_frame(capture_frame, metrics=resolved_metrics)
        pipeline_result = process_classified_live_frame(
            classification,
            metrics=resolved_metrics,
        )

        for record in pipeline_result.records:
            try:
                if record_sink is not None:
                    record_sink(record)
                records_emitted += 1
            except Exception as exc:
                resolved_metrics.increment("output_drops")
                last_error = "record sink failed: %s" % exc

        frames_processed += 1

    last_error = _emit_audit(
        audit_sink,
        config,
        resolved_now_fn,
        "live_service_stop",
        {
            "stopped_reason": stopped_reason,
            "frames_processed": frames_processed,
            "records_emitted": records_emitted,
            "output_drops": resolved_metrics.output_drops,
        },
        last_error,
    )

    last_error = _emit_status(
        status_sink,
        config,
        resolved_metrics,
        resolved_now_fn,
        last_error,
    )

    return LiveServiceResult(
        metrics=resolved_metrics,
        frames_processed=frames_processed,
        records_emitted=records_emitted,
        stopped_reason=stopped_reason,
        last_error=last_error,
    )


def _emit_audit(
    audit_sink: Optional[AuditSink],
    config: LiveParserConfig,
    now_fn: NowFn,
    event_type: str,
    fields: dict,
    last_error: Optional[str],
) -> Optional[str]:
    if audit_sink is None:
        return last_error

    try:
        audit_sink(
            EcgAuditRecord(
                timestamp_utc=now_fn(),
                event_type=event_type,
                interface=config.interface,
                fields=dict(fields),
            )
        )
        return last_error
    except Exception as exc:
        return "audit sink failed: %s" % exc


def _emit_status(
    status_sink: Optional[StatusSink],
    config: LiveParserConfig,
    metrics: LiveMetrics,
    now_fn: NowFn,
    last_error: Optional[str],
) -> Optional[str]:
    if status_sink is None:
        return last_error

    try:
        status_sink(
            EcgStatusSnapshot(
                timestamp_utc=now_fn(),
                interface=config.interface,
                counters=metrics.snapshot(),
                active_file=config.output_json_file,
                last_error=last_error,
            )
        )
        return last_error
    except Exception as exc:
        return "status sink failed: %s" % exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

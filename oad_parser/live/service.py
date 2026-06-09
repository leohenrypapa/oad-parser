"""Synthetic-frame service skeleton for the production live ECG parser.

The service consumes already-captured LiveCaptureFrame objects so it can be
tested without root privileges, raw sockets, operational traffic, or runtime
files. Production wiring can inject JSONL writer, audit/status writers, and
storage policy while unit tests use synthetic frames and temporary paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from oad_parser.config import LiveParserConfig
from oad_parser.live.audit import audit_record_from_storage_result
from oad_parser.live.classifier import classify_live_frame
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.pipeline import process_classified_live_frame
from oad_parser.live.records import (
    EcgAuditRecord,
    EcgStatusSnapshot,
    LiveCaptureFrame,
)
from oad_parser.live.storage import LiveStoragePolicy, StorageProtectionResult


RecordSink = Callable[[dict], object]
AuditSink = Callable[[EcgAuditRecord], object]
StatusSink = Callable[[EcgStatusSnapshot], object]
NowFn = Callable[[], datetime]


@dataclass(frozen=True)
class LiveServiceResult:
    """Summary returned after a finite live service run."""

    metrics: LiveMetrics
    frames_processed: int
    records_emitted: int
    stopped_reason: str
    last_error: Optional[str] = None
    storage_critical: bool = False
    writer_blocked: bool = False


@dataclass(frozen=True)
class _StorageState:
    result: Optional[StorageProtectionResult]
    writer_blocked: bool
    critical: bool
    last_error: Optional[str]


def run_live_service(
    config: LiveParserConfig,
    capture_frames: Iterable[LiveCaptureFrame],
    *,
    metrics: Optional[LiveMetrics] = None,
    record_sink: Optional[RecordSink] = None,
    audit_sink: Optional[AuditSink] = None,
    status_sink: Optional[StatusSink] = None,
    storage_policy: Optional[LiveStoragePolicy] = None,
    max_frames: Optional[int] = None,
    now_fn: Optional[NowFn] = None,
) -> LiveServiceResult:
    """Run the live service over a finite iterable of capture frames."""

    if max_frames is not None and max_frames < 0:
        raise ValueError("max_frames must be >= 0")

    resolved_metrics = metrics if metrics is not None else LiveMetrics()
    resolved_now_fn = now_fn if now_fn is not None else _utc_now
    frames_processed = 0
    records_emitted = 0
    last_error: Optional[str] = None
    stopped_reason = "input_exhausted"
    writer_blocked = False
    storage_critical = False
    last_storage_result: Optional[StorageProtectionResult] = None
    writer_block_started_at: Optional[datetime] = None

    last_error = _emit_audit(
        audit_sink,
        config,
        resolved_now_fn,
        "live_service_start",
        {"max_frames": max_frames},
        last_error,
    )
    last_status_emit_at = resolved_now_fn()
    last_metrics_emit_at = resolved_now_fn()

    frame_iter = iter(capture_frames)
    while True:
        if max_frames is not None and frames_processed >= max_frames:
            stopped_reason = "max_frames"
            break

        storage_state = _apply_storage_policy(
            config=config,
            metrics=resolved_metrics,
            storage_policy=storage_policy,
            audit_sink=audit_sink,
            status_sink=status_sink,
            now_fn=resolved_now_fn,
            last_error=last_error,
        )
        last_error = storage_state.last_error
        last_storage_result = storage_state.result
        writer_blocked = storage_state.writer_blocked

        writer_block_started_at = _update_writer_block_timer(
            metrics=resolved_metrics,
            writer_blocked=writer_blocked,
            writer_block_started_at=writer_block_started_at,
            now_fn=resolved_now_fn,
        )

        if storage_state.critical:
            storage_critical = True
            stopped_reason = "critical_storage"
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

        if writer_blocked and config.block_when_full:
            if pipeline_result.records:
                resolved_metrics.increment("output_drops", len(pipeline_result.records))
            frames_processed += 1
            continue

        for record in pipeline_result.records:
            try:
                write_result = None
                if record_sink is not None:
                    write_result = record_sink(record)
                _update_metrics_from_write_result(resolved_metrics, write_result)
                if getattr(write_result, "bytes_written", None) == 0:
                    continue
                records_emitted += 1
            except Exception as exc:
                resolved_metrics.increment("output_drops")
                last_error = "record sink failed: %s" % exc

        frames_processed += 1

        last_status_emit_at, last_error = _emit_periodic_status(
            status_sink=status_sink,
            config=config,
            metrics=resolved_metrics,
            now_fn=resolved_now_fn,
            last_error=last_error,
            last_status_emit_at=last_status_emit_at,
            storage_result=last_storage_result,
        )
        last_metrics_emit_at, last_error = _emit_periodic_metrics(
            audit_sink=audit_sink,
            config=config,
            metrics=resolved_metrics,
            now_fn=resolved_now_fn,
            last_error=last_error,
            last_metrics_emit_at=last_metrics_emit_at,
            frames_processed=frames_processed,
            records_emitted=records_emitted,
            writer_blocked=writer_blocked,
            storage_critical=storage_critical,
        )

    _update_writer_block_timer(
        metrics=resolved_metrics,
        writer_blocked=False,
        writer_block_started_at=writer_block_started_at,
        now_fn=resolved_now_fn,
    )

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
            "writer_blocked": writer_blocked,
            "storage_critical": storage_critical,
        },
        last_error,
    )

    last_error = _emit_status(
        status_sink,
        config,
        resolved_metrics,
        resolved_now_fn,
        last_error,
        storage_result=last_storage_result,
    )

    return LiveServiceResult(
        metrics=resolved_metrics,
        frames_processed=frames_processed,
        records_emitted=records_emitted,
        stopped_reason=stopped_reason,
        last_error=last_error,
        storage_critical=storage_critical,
        writer_blocked=writer_blocked,
    )


def _apply_storage_policy(
    *,
    config: LiveParserConfig,
    metrics: LiveMetrics,
    storage_policy: Optional[LiveStoragePolicy],
    audit_sink: Optional[AuditSink],
    status_sink: Optional[StatusSink],
    now_fn: NowFn,
    last_error: Optional[str],
) -> _StorageState:
    if storage_policy is None:
        return _StorageState(
            result=None,
            writer_blocked=False,
            critical=False,
            last_error=last_error,
        )

    try:
        result = storage_policy.apply()
    except Exception as exc:
        metrics.increment("output_drops")
        return _StorageState(
            result=None,
            writer_blocked=True if config.block_when_full else False,
            critical=False,
            last_error="storage policy failed: %s" % exc,
        )

    if result.files_pruned:
        metrics.increment("files_pruned", result.files_pruned)

    if result.files_pruned or result.writer_blocked or result.critical:
        event_type = "storage_critical" if result.critical else "storage_protection"
        try:
            if audit_sink is not None:
                audit_sink(
                    audit_record_from_storage_result(
                        timestamp_utc=now_fn(),
                        interface=config.interface,
                        event_type=event_type,
                        storage_result=result,
                    )
                )
        except Exception as exc:
            last_error = "audit sink failed: %s" % exc

        if result.writer_blocked or result.critical:
            last_error = _emit_status(
                status_sink,
                config,
                metrics,
                now_fn,
                last_error,
                storage_result=result,
            )

    return _StorageState(
        result=result,
        writer_blocked=result.writer_blocked,
        critical=result.critical,
        last_error=last_error,
    )



def _emit_periodic_status(
    *,
    status_sink: Optional[StatusSink],
    config: LiveParserConfig,
    metrics: LiveMetrics,
    now_fn: NowFn,
    last_error: Optional[str],
    last_status_emit_at: datetime,
    storage_result: Optional[StorageProtectionResult],
) -> tuple[datetime, Optional[str]]:
    now = now_fn()
    elapsed_seconds = (now - last_status_emit_at).total_seconds()
    if elapsed_seconds < config.status_interval_seconds:
        return last_status_emit_at, last_error

    last_error = _emit_status(
        status_sink,
        config,
        metrics,
        lambda: now,
        last_error,
        storage_result=storage_result,
    )
    return now, last_error


def _emit_periodic_metrics(
    *,
    audit_sink: Optional[AuditSink],
    config: LiveParserConfig,
    metrics: LiveMetrics,
    now_fn: NowFn,
    last_error: Optional[str],
    last_metrics_emit_at: datetime,
    frames_processed: int,
    records_emitted: int,
    writer_blocked: bool,
    storage_critical: bool,
) -> tuple[datetime, Optional[str]]:
    now = now_fn()
    elapsed_seconds = (now - last_metrics_emit_at).total_seconds()
    if elapsed_seconds < config.metrics_interval_seconds:
        return last_metrics_emit_at, last_error

    last_error = _emit_audit(
        audit_sink,
        config,
        lambda: now,
        "live_service_metrics",
        {
            "frames_processed": frames_processed,
            "records_emitted": records_emitted,
            "writer_blocked": writer_blocked,
            "storage_critical": storage_critical,
            "counters": metrics.snapshot(),
        },
        last_error,
    )
    return now, last_error

def _update_metrics_from_write_result(metrics: LiveMetrics, write_result: object) -> None:
    if write_result is None:
        return

    bytes_written = getattr(write_result, "bytes_written", None)
    if isinstance(bytes_written, int):
        metrics.increment("bytes_written", bytes_written)

    rotated_path = getattr(write_result, "rotated_path", None)
    if rotated_path:
        metrics.increment("files_rotated")


def _update_writer_block_timer(
    *,
    metrics: LiveMetrics,
    writer_blocked: bool,
    writer_block_started_at: Optional[datetime],
    now_fn: NowFn,
) -> Optional[datetime]:
    now = now_fn()

    if writer_blocked and writer_block_started_at is None:
        return now

    if not writer_blocked and writer_block_started_at is not None:
        seconds = (now - writer_block_started_at).total_seconds()
        if seconds > 0:
            metrics.add_writer_block_seconds(seconds)
        return None

    return writer_block_started_at


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
    *,
    storage_result: Optional[StorageProtectionResult] = None,
) -> Optional[str]:
    if status_sink is None:
        return last_error

    disk_percent = storage_result.disk_usage_percent if storage_result is not None else None
    last_prune = None
    if storage_result is not None and storage_result.files_pruned:
        last_prune = "files_pruned=%d bytes_pruned=%d" % (
            storage_result.files_pruned,
            storage_result.bytes_pruned,
        )

    try:
        status_sink(
            EcgStatusSnapshot(
                timestamp_utc=now_fn(),
                interface=config.interface,
                counters=metrics.snapshot(),
                active_file=config.output_json_file,
                disk_percent=disk_percent,
                last_prune=last_prune,
                last_error=last_error,
            )
        )
        return last_error
    except Exception as exc:
        return "status sink failed: %s" % exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

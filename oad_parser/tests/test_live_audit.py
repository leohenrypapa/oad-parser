"""Unit tests for live audit JSONL and status JSON writers."""

from collections import namedtuple
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from oad_parser.config import LiveParserConfig
from oad_parser.live.audit import (
    AuditJsonlWriter,
    LiveObservabilityWriters,
    StatusSnapshotWriter,
    audit_record_from_storage_result,
    status_snapshot_from_metrics,
)
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.records import EcgAuditRecord, EcgStatusSnapshot
from oad_parser.live.service import run_live_service
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame
from oad_parser.live.records import LiveCaptureFrame


FIXED_TIME = datetime(2026, 5, 12, 18, 0, 0, tzinfo=timezone.utc)
StorageResult = namedtuple(
    "StorageResult",
    "disk_usage_percent files_pruned bytes_pruned writer_blocked critical pruned_paths",
)


class LiveAuditWriterTests(unittest.TestCase):
    def test_audit_writer_appends_one_json_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "ecg-audit.jsonl"
            writer = AuditJsonlWriter(str(audit_path))

            first = writer.write(
                EcgAuditRecord(
                    timestamp_utc=FIXED_TIME,
                    event_type="live_service_start",
                    interface="eno1",
                    fields={"max_frames": 2},
                )
            )
            second = writer.write(
                EcgAuditRecord(
                    timestamp_utc=FIXED_TIME,
                    event_type="live_service_stop",
                    interface="eno1",
                    fields={"frames_processed": 2},
                )
            )

            self.assertEqual(first.path, str(audit_path))
            self.assertGreater(first.bytes_written, 0)
            self.assertGreater(second.bytes_written, 0)

            lines = audit_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["record_type"], "ecg_audit")
            self.assertEqual(json.loads(lines[0])["event_type"], "live_service_start")
            self.assertEqual(json.loads(lines[1])["event_type"], "live_service_stop")

    def test_status_writer_replaces_with_single_json_object(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status_path = Path(tmpdir) / "ecg-status.json"
            writer = StatusSnapshotWriter(str(status_path))

            first = writer.write(
                EcgStatusSnapshot(
                    timestamp_utc=FIXED_TIME,
                    interface="eno1",
                    counters={"packets_received": 1},
                    active_file="/nsm/ecg/ecg-current.json",
                )
            )
            second = writer.write(
                EcgStatusSnapshot(
                    timestamp_utc=FIXED_TIME,
                    interface="eno1",
                    counters={"packets_received": 2},
                    active_file="/nsm/ecg/ecg-current.json",
                    last_error="simulated",
                )
            )

            self.assertEqual(first.path, str(status_path))
            self.assertEqual(second.path, str(status_path))
            payload = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["record_type"], "ecg_status")
            self.assertEqual(payload["counters"]["packets_received"], 2)
            self.assertEqual(payload["last_error"], "simulated")
            self.assertFalse(writer._temporary_path().exists())

    def test_observability_writers_from_config_work_as_service_sinks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            config = LiveParserConfig(
                interface="eno1",
                audit_file=str(output_dir / "ecg-audit.jsonl"),
                status_file=str(output_dir / "ecg-status.json"),
            )
            observability = LiveObservabilityWriters.from_config(config)

            frame = LiveCaptureFrame(
                frame_bytes=build_ethernet_ipv4_udp_frame(build_ecg_payload()),
                interface="eno1",
                capture_time_utc=FIXED_TIME,
            )

            result = run_live_service(
                config,
                [frame],
                audit_sink=observability.audit_sink,
                status_sink=observability.status_sink,
                now_fn=lambda: FIXED_TIME,
            )

            self.assertEqual(result.frames_processed, 1)
            audit_lines = Path(config.audit_file).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(audit_lines), 2)
            self.assertEqual(json.loads(audit_lines[0])["event_type"], "live_service_start")
            self.assertEqual(json.loads(audit_lines[1])["event_type"], "live_service_stop")

            status = json.loads(Path(config.status_file).read_text(encoding="utf-8"))
            self.assertEqual(status["record_type"], "ecg_status")
            self.assertEqual(status["counters"]["packets_received"], 1)
            self.assertEqual(status["active_file"], "/nsm/ecg/ecg-current.json")

    def test_storage_result_audit_record_is_aggregate_not_per_warning(self):
        storage_result = StorageResult(
            disk_usage_percent=80.0,
            files_pruned=2,
            bytes_pruned=1234,
            writer_blocked=True,
            critical=False,
            pruned_paths=["/nsm/ecg/ecg-current-20260512T010000Z.jsonl"],
        )

        record = audit_record_from_storage_result(
            timestamp_utc=FIXED_TIME,
            interface="eno1",
            event_type="storage_prune",
            storage_result=storage_result,
        ).to_dict()

        self.assertEqual(record["record_type"], "ecg_audit")
        self.assertEqual(record["event_type"], "storage_prune")
        self.assertEqual(record["files_pruned"], 2)
        self.assertEqual(record["bytes_pruned"], 1234)
        self.assertEqual(record["writer_blocked"], True)
        self.assertEqual(record["critical"], False)
        self.assertEqual(len(record["pruned_paths"]), 1)

    def test_status_snapshot_from_metrics_includes_warning_counter(self):
        metrics = LiveMetrics(
            packets_received=10,
            parse_warnings_count=3,
            output_drops=1,
        )

        snapshot = status_snapshot_from_metrics(
            timestamp_utc=FIXED_TIME,
            interface="eno1",
            metrics=metrics,
            active_file="/nsm/ecg/ecg-current.json",
            disk_percent=70.5,
            last_rotation="/nsm/ecg/ecg-current-20260512T180000Z.jsonl",
            last_prune="storage_prune",
            last_error="writer blocked",
        ).to_dict()

        self.assertEqual(snapshot["record_type"], "ecg_status")
        self.assertEqual(snapshot["counters"]["packets_received"], 10)
        self.assertEqual(snapshot["counters"]["parse_warnings_count"], 3)
        self.assertEqual(snapshot["counters"]["output_drops"], 1)
        self.assertEqual(snapshot["disk_percent"], 70.5)
        self.assertEqual(snapshot["last_error"], "writer blocked")

    def test_rejects_empty_paths(self):
        with self.assertRaises(ValueError):
            AuditJsonlWriter("")

        with self.assertRaises(ValueError):
            StatusSnapshotWriter("")


if __name__ == "__main__":
    unittest.main()

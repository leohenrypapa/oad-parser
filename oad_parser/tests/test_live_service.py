"""Unit tests for the synthetic-frame live service skeleton."""

from datetime import datetime, timezone
import unittest

from oad_parser.config import LiveParserConfig
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.live.service import run_live_service
from oad_parser.parsers.ecg import ECG_ERROR_LENGTH_MISMATCH
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


FIXED_TIME = datetime(2026, 5, 12, 15, 0, 0, tzinfo=timezone.utc)


class LiveServiceTests(unittest.TestCase):
    def _capture_frame(self, payload, interface="eno1"):
        return LiveCaptureFrame(
            frame_bytes=build_ethernet_ipv4_udp_frame(payload),
            interface=interface,
            capture_time_utc=FIXED_TIME,
        )

    def _valid_payload(self):
        return build_ecg_payload()

    def _warning_payload(self):
        payload = bytearray(build_ecg_payload())
        payload[24] = 99
        return bytes(payload)

    def _malformed_payload(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")
        return bytes(payload)

    def test_service_processes_synthetic_frame_iterable(self):
        config = LiveParserConfig(interface="eno1")
        frames = [
            self._capture_frame(self._valid_payload()),
            self._capture_frame(self._warning_payload()),
            self._capture_frame(self._malformed_payload()),
            self._capture_frame(b"not an ECG payload"),
        ]
        records = []
        audits = []
        statuses = []

        result = run_live_service(
            config,
            frames,
            record_sink=records.append,
            audit_sink=audits.append,
            status_sink=statuses.append,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.frames_processed, 4)
        self.assertEqual(result.records_emitted, 3)
        self.assertEqual(result.stopped_reason, "input_exhausted")
        self.assertIsNone(result.last_error)

        self.assertEqual([record["record_type"] for record in records], [
            "ecg_event",
            "ecg_event",
            "ecg_parse_error",
        ])
        self.assertIn("parse_warnings", records[1])
        self.assertEqual(records[2]["error_code"], ECG_ERROR_LENGTH_MISMATCH)

        metrics = result.metrics
        self.assertEqual(metrics.packets_received, 4)
        self.assertEqual(metrics.packets_parsed, 4)
        self.assertEqual(metrics.ecg_candidates, 3)
        self.assertEqual(metrics.non_ecg, 1)
        self.assertEqual(metrics.valid_ecg_payloads, 2)
        self.assertEqual(metrics.parse_warnings_count, 1)
        self.assertEqual(metrics.malformed_count, 1)
        self.assertEqual(metrics.ecg_messages_emitted, 2)
        self.assertEqual(metrics.error_records_emitted, 1)
        self.assertEqual(metrics.output_drops, 0)

        self.assertEqual([record.event_type for record in audits], [
            "live_service_start",
            "live_service_stop",
        ])
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].active_file, "/nsm/ecg/ecg-current.json")
        self.assertEqual(statuses[0].counters["packets_received"], 4)

    def test_service_honors_max_frames_for_smoke_runs(self):
        config = LiveParserConfig(interface="eno1")
        frames = [
            self._capture_frame(self._valid_payload()),
            self._capture_frame(self._valid_payload()),
            self._capture_frame(self._valid_payload()),
        ]
        records = []

        result = run_live_service(
            config,
            frames,
            record_sink=records.append,
            max_frames=2,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.frames_processed, 2)
        self.assertEqual(result.records_emitted, 2)
        self.assertEqual(result.stopped_reason, "max_frames")
        self.assertEqual(len(records), 2)
        self.assertEqual(result.metrics.packets_received, 2)

    def test_service_allows_zero_max_frames_for_smoke_checks(self):
        config = LiveParserConfig(interface="eno1")
        frames = [self._capture_frame(self._valid_payload())]

        result = run_live_service(
            config,
            frames,
            max_frames=0,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.frames_processed, 0)
        self.assertEqual(result.records_emitted, 0)
        self.assertEqual(result.stopped_reason, "max_frames")
        self.assertEqual(result.metrics.packets_received, 0)

    def test_service_rejects_negative_max_frames(self):
        config = LiveParserConfig(interface="eno1")

        with self.assertRaises(ValueError):
            run_live_service(
                config,
                [],
                max_frames=-1,
                now_fn=lambda: FIXED_TIME,
            )

    def test_service_counts_output_drop_when_record_sink_fails(self):
        config = LiveParserConfig(interface="eno1")
        frames = [self._capture_frame(self._valid_payload())]

        def failing_sink(record):
            raise RuntimeError("simulated writer failure")

        result = run_live_service(
            config,
            frames,
            record_sink=failing_sink,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.frames_processed, 1)
        self.assertEqual(result.records_emitted, 0)
        self.assertEqual(result.metrics.output_drops, 1)
        self.assertIn("record sink failed", result.last_error)
        self.assertIn("simulated writer failure", result.last_error)

    def test_service_works_without_injected_sinks(self):
        config = LiveParserConfig(interface="eno1")
        frames = [self._capture_frame(self._valid_payload())]

        result = run_live_service(
            config,
            frames,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.frames_processed, 1)
        self.assertEqual(result.records_emitted, 1)
        self.assertIsNone(result.last_error)
        self.assertEqual(result.metrics.ecg_messages_emitted, 1)


if __name__ == "__main__":
    unittest.main()

class _FakeWriteResult:
    def __init__(self, bytes_written=42, rotated_path=None):
        self.bytes_written = bytes_written
        self.rotated_path = rotated_path


class _StaticStoragePolicy:
    def __init__(self, results):
        self._results = list(results)
        self.apply_count = 0

    def apply(self):
        if self.apply_count < len(self._results):
            result = self._results[self.apply_count]
        else:
            result = self._results[-1]
        self.apply_count += 1
        return result


class StorageIntegrationLiveServiceTests(unittest.TestCase):
    def _capture_frame(self, payload, interface="eno1"):
        return LiveCaptureFrame(
            frame_bytes=build_ethernet_ipv4_udp_frame(payload),
            interface=interface,
            capture_time_utc=FIXED_TIME,
        )

    def _storage_result(
        self,
        *,
        disk_usage_percent=10.0,
        files_pruned=0,
        bytes_pruned=0,
        writer_blocked=False,
        critical=False,
    ):
        from oad_parser.live.storage import StorageProtectionResult

        return StorageProtectionResult(
            disk_usage_percent=disk_usage_percent,
            files_pruned=files_pruned,
            bytes_pruned=bytes_pruned,
            writer_blocked=writer_blocked,
            critical=critical,
            pruned_paths=[],
            protected_paths=[],
        )

    def test_service_updates_metrics_from_writer_result(self):
        config = LiveParserConfig(interface="eno1")
        frames = [self._capture_frame(build_ecg_payload())]

        result = run_live_service(
            config,
            frames,
            record_sink=lambda record: _FakeWriteResult(bytes_written=77, rotated_path="/tmp/rotated.jsonl"),
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.records_emitted, 1)
        self.assertEqual(result.metrics.bytes_written, 77)
        self.assertEqual(result.metrics.files_rotated, 1)
        self.assertEqual(result.metrics.output_drops, 0)

    def test_service_blocks_output_when_storage_high_water_and_block_when_full(self):
        config = LiveParserConfig(interface="eno1", block_when_full=True)
        frames = [self._capture_frame(build_ecg_payload())]
        storage_policy = _StaticStoragePolicy([
            self._storage_result(
                disk_usage_percent=80.0,
                files_pruned=1,
                bytes_pruned=100,
                writer_blocked=True,
                critical=False,
            )
        ])
        records = []
        audits = []
        statuses = []

        result = run_live_service(
            config,
            frames,
            record_sink=records.append,
            audit_sink=audits.append,
            status_sink=statuses.append,
            storage_policy=storage_policy,
            max_frames=1,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.stopped_reason, "max_frames")
        self.assertFalse(result.storage_critical)
        self.assertTrue(result.writer_blocked)
        self.assertEqual(records, [])
        self.assertEqual(result.records_emitted, 0)
        self.assertEqual(result.metrics.output_drops, 1)
        self.assertEqual(result.metrics.files_pruned, 1)
        self.assertEqual([audit.event_type for audit in audits], [
            "live_service_start",
            "storage_protection",
            "live_service_stop",
        ])
        self.assertEqual(statuses[-1].disk_percent, 80.0)
        self.assertEqual(statuses[-1].counters["output_drops"], 1)

    def test_service_critical_storage_stops_before_processing_frames(self):
        config = LiveParserConfig(interface="eno1", block_when_full=True)
        frames = [self._capture_frame(build_ecg_payload())]
        storage_policy = _StaticStoragePolicy([
            self._storage_result(
                disk_usage_percent=96.0,
                files_pruned=1,
                bytes_pruned=100,
                writer_blocked=True,
                critical=True,
            )
        ])
        records = []
        audits = []
        statuses = []

        result = run_live_service(
            config,
            frames,
            record_sink=records.append,
            audit_sink=audits.append,
            status_sink=statuses.append,
            storage_policy=storage_policy,
            max_frames=1,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(result.stopped_reason, "critical_storage")
        self.assertTrue(result.storage_critical)
        self.assertTrue(result.writer_blocked)
        self.assertEqual(result.frames_processed, 0)
        self.assertEqual(result.records_emitted, 0)
        self.assertEqual(result.metrics.packets_received, 0)
        self.assertEqual(result.metrics.files_pruned, 1)
        self.assertEqual(records, [])
        self.assertIn("storage_critical", [audit.event_type for audit in audits])
        self.assertEqual(statuses[-1].disk_percent, 96.0)

    def test_service_allows_output_when_storage_blocks_but_config_disables_blocking(self):
        config = LiveParserConfig(interface="eno1", block_when_full=False)
        frames = [self._capture_frame(build_ecg_payload())]
        storage_policy = _StaticStoragePolicy([
            self._storage_result(
                disk_usage_percent=80.0,
                writer_blocked=True,
                critical=False,
            )
        ])
        records = []

        result = run_live_service(
            config,
            frames,
            record_sink=records.append,
            storage_policy=storage_policy,
            max_frames=1,
            now_fn=lambda: FIXED_TIME,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(result.records_emitted, 1)
        self.assertEqual(result.metrics.output_drops, 0)
        self.assertTrue(result.writer_blocked)

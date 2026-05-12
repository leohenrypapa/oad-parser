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

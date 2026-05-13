"""Unit tests for per-frame live ECG pipeline processing."""

from datetime import datetime, timezone
import unittest

from oad_parser.live.classifier import (
    OUTCOME_ECG_CANDIDATE,
    OUTCOME_NON_ECG_PAYLOAD,
    LiveFrameClassification,
    classify_live_frame,
)
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.pipeline import process_classified_live_frame
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.parsers.ecg import ECG_ERROR_LENGTH_MISMATCH
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


FIXED_TIME = datetime(2026, 5, 12, 14, 0, 0, tzinfo=timezone.utc)


class LivePipelineTests(unittest.TestCase):
    def _capture_frame(self, frame_bytes, interface="eno1"):
        return LiveCaptureFrame(
            frame_bytes=frame_bytes,
            interface=interface,
            capture_time_utc=FIXED_TIME,
        )

    def test_valid_ecg_candidate_emits_record_and_updates_metrics(self):
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)
        metrics = LiveMetrics()
        classification = classify_live_frame(self._capture_frame(frame), metrics=metrics)

        result = process_classified_live_frame(classification, metrics=metrics)

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record["@timestamp"], "2026-05-12T14:00:00Z")
        self.assertEqual(record["record_type"], "ecg_event")
        self.assertEqual(record["interface"], "eno1")
        self.assertEqual(record["source_ip"], "10.1.2.3")
        self.assertEqual(record["destination_ip"], "10.4.5.6")
        self.assertEqual(metrics.packets_received, 1)
        self.assertEqual(metrics.packets_parsed, 1)
        self.assertEqual(metrics.ecg_candidates, 1)
        self.assertEqual(metrics.valid_ecg_payloads, 1)
        self.assertEqual(metrics.ecg_messages_emitted, 1)
        self.assertEqual(metrics.malformed_count, 0)
        self.assertEqual(metrics.error_records_emitted, 0)

    def test_warning_ecg_candidate_counts_warning_and_emits_valid_event(self):
        payload = bytearray(build_ecg_payload())
        payload[24] = 99
        frame = build_ethernet_ipv4_udp_frame(bytes(payload))
        metrics = LiveMetrics()
        classification = classify_live_frame(self._capture_frame(frame), metrics=metrics)

        result = process_classified_live_frame(classification, metrics=metrics)

        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0]["record_type"], "ecg_event")
        self.assertIn("parse_warnings", result.records[0])
        self.assertEqual(metrics.valid_ecg_payloads, 1)
        self.assertEqual(metrics.parse_warnings_count, 1)
        self.assertEqual(metrics.ecg_messages_emitted, 1)
        self.assertEqual(metrics.malformed_count, 0)

    def test_malformed_ecg_candidate_emits_error_record_and_updates_metrics(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")
        frame = build_ethernet_ipv4_udp_frame(bytes(payload))
        metrics = LiveMetrics()
        classification = classify_live_frame(self._capture_frame(frame), metrics=metrics)

        result = process_classified_live_frame(classification, metrics=metrics)

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record["record_type"], "ecg_parse_error")
        self.assertEqual(record["error_code"], ECG_ERROR_LENGTH_MISMATCH)
        self.assertEqual(record["source_ip"], "10.1.2.3")
        self.assertEqual(metrics.malformed_count, 1)
        self.assertEqual(metrics.error_records_emitted, 1)
        self.assertEqual(metrics.valid_ecg_payloads, 0)
        self.assertEqual(metrics.ecg_messages_emitted, 0)

    def test_non_ecg_classification_does_not_parse_or_emit_records(self):
        frame = build_ethernet_ipv4_udp_frame(b"not an ECG payload")
        metrics = LiveMetrics()
        classification = classify_live_frame(self._capture_frame(frame), metrics=metrics)

        result = process_classified_live_frame(classification, metrics=metrics)

        self.assertEqual(classification.outcome, OUTCOME_NON_ECG_PAYLOAD)
        self.assertEqual(result.records, [])
        self.assertIsNone(result.parse_result)
        self.assertEqual(metrics.non_ecg, 1)
        self.assertEqual(metrics.valid_ecg_payloads, 0)
        self.assertEqual(metrics.ecg_messages_emitted, 0)
        self.assertEqual(metrics.malformed_count, 0)

    def test_pipeline_reuses_classification_payload_and_metadata(self):
        payload = build_ecg_payload()
        classification = LiveFrameClassification(
            outcome=OUTCOME_ECG_CANDIDATE,
            capture_frame=self._capture_frame(b"not an ethernet frame", interface="eno5"),
            ecg_payload=payload,
            packet_metadata={
                "source_ip": "192.0.2.1",
                "source_port": 6100,
                "destination_ip": "192.0.2.2",
                "destination_port": 6101,
                "ip_total_length": 128,
            },
        )
        metrics = LiveMetrics()

        result = process_classified_live_frame(classification, metrics=metrics)

        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0]["interface"], "eno5")
        self.assertEqual(result.records[0]["source_ip"], "192.0.2.1")
        self.assertEqual(result.records[0]["destination_port"], 6101)
        self.assertEqual(result.parse_result.packet_metadata["ip_total_length"], 128)
        self.assertEqual(metrics.valid_ecg_payloads, 1)


if __name__ == "__main__":
    unittest.main()

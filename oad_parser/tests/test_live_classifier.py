"""Unit tests for live frame classification."""

from datetime import datetime, timezone
import unittest

from oad_parser.live.classifier import (
    OUTCOME_ECG_CANDIDATE,
    OUTCOME_NON_ECG_PAYLOAD,
    OUTCOME_NON_IPV4_OR_NON_UDP,
    classify_live_frame,
    packet_metadata_from_udp_frame,
)
from oad_parser.live.metrics import LiveMetrics
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.tests.test_ecg import build_ecg_payload
from oad_parser.tests.test_ethernet import (
    DESTINATION_PORT,
    SOURCE_PORT,
    build_ethernet_ipv4_udp_frame,
)


class LiveClassifierTests(unittest.TestCase):
    def _capture_frame(self, frame_bytes):
        return LiveCaptureFrame(
            frame_bytes=frame_bytes,
            interface="eno1",
            capture_time_utc=datetime(2026, 5, 12, 13, 0, 0, tzinfo=timezone.utc),
        )

    def test_non_ipv4_or_non_udp_frame_updates_metrics(self):
        metrics = LiveMetrics()

        result = classify_live_frame(self._capture_frame(b"too short"), metrics)

        self.assertEqual(result.outcome, OUTCOME_NON_IPV4_OR_NON_UDP)
        self.assertIsNone(result.udp_frame)
        self.assertIsNone(result.ecg_payload)
        self.assertEqual(result.packet_metadata, {})
        self.assertEqual(metrics.packets_received, 1)
        self.assertEqual(metrics.non_ipv4_or_non_udp, 1)
        self.assertEqual(metrics.packets_parsed, 0)
        self.assertEqual(metrics.non_ecg, 0)
        self.assertEqual(metrics.ecg_candidates, 0)

    def test_udp_non_ecg_payload_updates_metrics_without_event_payload(self):
        metrics = LiveMetrics()
        frame = build_ethernet_ipv4_udp_frame(b"not an ecg payload")

        result = classify_live_frame(self._capture_frame(frame), metrics)

        self.assertEqual(result.outcome, OUTCOME_NON_ECG_PAYLOAD)
        self.assertIsNotNone(result.udp_frame)
        self.assertIsNone(result.ecg_payload)
        self.assertEqual(result.packet_metadata["source_ip"], "10.1.2.3")
        self.assertEqual(result.packet_metadata["destination_ip"], "10.4.5.6")
        self.assertEqual(result.packet_metadata["source_port"], SOURCE_PORT)
        self.assertEqual(result.packet_metadata["destination_port"], DESTINATION_PORT)
        self.assertEqual(metrics.packets_received, 1)
        self.assertEqual(metrics.packets_parsed, 1)
        self.assertEqual(metrics.non_ecg, 1)
        self.assertEqual(metrics.non_ipv4_or_non_udp, 0)
        self.assertEqual(metrics.ecg_candidates, 0)

    def test_udp_ecg_candidate_returns_payload_and_metadata(self):
        metrics = LiveMetrics()
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)

        result = classify_live_frame(self._capture_frame(frame), metrics)

        self.assertEqual(result.outcome, OUTCOME_ECG_CANDIDATE)
        self.assertIsNotNone(result.udp_frame)
        self.assertEqual(result.ecg_payload, payload)
        self.assertEqual(result.packet_metadata["source_ip"], "10.1.2.3")
        self.assertEqual(result.packet_metadata["destination_ip"], "10.4.5.6")
        self.assertEqual(result.packet_metadata["source_port"], SOURCE_PORT)
        self.assertEqual(result.packet_metadata["destination_port"], DESTINATION_PORT)
        self.assertEqual(metrics.packets_received, 1)
        self.assertEqual(metrics.packets_parsed, 1)
        self.assertEqual(metrics.ecg_candidates, 1)
        self.assertEqual(metrics.non_ecg, 0)
        self.assertEqual(metrics.non_ipv4_or_non_udp, 0)

    def test_classifier_does_not_require_metrics(self):
        frame = build_ethernet_ipv4_udp_frame(build_ecg_payload())

        result = classify_live_frame(self._capture_frame(frame))

        self.assertEqual(result.outcome, OUTCOME_ECG_CANDIDATE)

    def test_packet_metadata_from_udp_frame(self):
        frame = build_ethernet_ipv4_udp_frame(b"payload")
        result = classify_live_frame(self._capture_frame(frame))

        metadata = packet_metadata_from_udp_frame(result.udp_frame)

        self.assertEqual(
            metadata,
            {
                "source_ip": "10.1.2.3",
                "source_port": SOURCE_PORT,
                "destination_ip": "10.4.5.6",
                "destination_port": DESTINATION_PORT,
                "ip_total_length": 35,
            },
        )


if __name__ == "__main__":
    unittest.main()

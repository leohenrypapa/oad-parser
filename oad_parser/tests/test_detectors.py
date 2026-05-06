"""Unit tests for detector state behavior."""

import unittest

from oad_parser.detectors import DetectionConfig, DetectionEngine
from oad_parser.models import ParsedPlot


class DetectionEngineTests(unittest.TestCase):
    def test_duplicate_fingerprint_alerts_on_second_seen(self):
        engine = DetectionEngine(DetectionConfig(discovery_window_records=10))
        first = ParsedPlot(site_id="A", fingerprint="same")
        second = ParsedPlot(site_id="A", fingerprint="same")

        engine.process_record(first)
        engine.process_record(second)

        self.assertIsNone(first.alert)
        self.assertEqual(second.alert, "Duplicate Fingerprint")
        self.assertIn("duplicate plot fingerprint", second.alert_details)

    def test_unknown_site_after_discovery_window(self):
        engine = DetectionEngine(DetectionConfig(discovery_window_records=1))
        first = ParsedPlot(site_id="A")
        second = ParsedPlot(site_id="B")

        engine.process_record(first)
        engine.process_record(second)

        self.assertIsNone(first.alert)
        self.assertEqual(second.alert, "Unknown Site")

    def test_sequence_delta_alert(self):
        engine = DetectionEngine(
            DetectionConfig(discovery_window_records=10, max_sequence_delta=2)
        )
        first = ParsedPlot(site_id="A", sequence=1)
        second = ParsedPlot(site_id="A", sequence=5)

        engine.process_record(first)
        engine.process_record(second)

        self.assertEqual(second.sequence_delta, 4)
        self.assertEqual(second.alert, "Sequence Delta")

    def test_range_alert(self):
        engine = DetectionEngine(DetectionConfig(max_range_nm=100.0))
        record = ParsedPlot(site_id="A", range_nm=150.0)

        engine.process_record(record)

        self.assertEqual(record.alert, "Impossible Range")

    def test_azimuth_jump_alert(self):
        engine = DetectionEngine(
            DetectionConfig(discovery_window_records=10, max_azimuth_jump_degrees=20.0)
        )
        first = ParsedPlot(site_id="A", azimuth_degrees=10.0)
        second = ParsedPlot(site_id="A", azimuth_degrees=45.0)

        engine.process_record(first)
        engine.process_record(second)

        self.assertEqual(second.alert, "Azimuth Jump")

    def test_rtqc_alert(self):
        engine = DetectionEngine()
        record = ParsedPlot(message_type="rtqc")

        engine.process_record(record)

        self.assertEqual(record.alert, "RTQC")


if __name__ == "__main__":
    unittest.main()

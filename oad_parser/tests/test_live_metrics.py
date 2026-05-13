"""Unit tests for live ECG parser metrics."""

import unittest

from oad_parser.live.metrics import LiveMetrics


class LiveMetricsTests(unittest.TestCase):
    def test_snapshot_includes_required_acceptance_counters(self):
        metrics = LiveMetrics(
            packets_received=1,
            packets_dropped=2,
            packets_parsed=3,
            ecg_messages_emitted=4,
            malformed_count=5,
            parse_warnings_count=6,
        )

        snapshot = metrics.snapshot()

        self.assertEqual(snapshot["packets_received"], 1)
        self.assertEqual(snapshot["packets_dropped"], 2)
        self.assertEqual(snapshot["packets_parsed"], 3)
        self.assertEqual(snapshot["ecg_messages_emitted"], 4)
        self.assertEqual(snapshot["malformed_count"], 5)
        self.assertEqual(snapshot["parse_warnings_count"], 6)

    def test_snapshot_includes_recommended_operational_counters(self):
        snapshot = LiveMetrics().snapshot()

        expected = [
            "non_ipv4_or_non_udp",
            "non_ecg",
            "ecg_candidates",
            "valid_ecg_payloads",
            "error_records_emitted",
            "parse_warnings_count",
            "detector_alerts",
            "bytes_written",
            "files_rotated",
            "files_pruned",
            "writer_block_seconds",
            "output_drops",
        ]
        for name in expected:
            with self.subTest(name=name):
                self.assertIn(name, snapshot)

    def test_increment_updates_named_counter(self):
        metrics = LiveMetrics()

        metrics.increment("packets_received")
        metrics.increment("packets_received", 4)

        self.assertEqual(metrics.packets_received, 5)

    def test_increment_rejects_unknown_counter(self):
        metrics = LiveMetrics()

        with self.assertRaises(AttributeError):
            metrics.increment("missing_counter")

    def test_add_writer_block_seconds_accumulates_float(self):
        metrics = LiveMetrics()

        metrics.add_writer_block_seconds(1.25)
        metrics.add_writer_block_seconds(2.5)

        self.assertEqual(metrics.writer_block_seconds, 3.75)


if __name__ == "__main__":
    unittest.main()

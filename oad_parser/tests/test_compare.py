"""Tests for legacy-vs-envelope comparison helpers."""

import unittest

from oad_parser.compare import compare_legacy_records_to_envelopes, comparison_summary
from oad_parser.parsers.ecg import extract_ecg_messages, parse_frame
from oad_parser.tests.test_ecg import build_ecg_payload


class LegacyEnvelopeCompareTests(unittest.TestCase):
    def test_legacy_and_envelope_match_for_fixture_payload(self):
        payload = build_ecg_payload()
        comparisons = compare_legacy_records_to_envelopes(
            parse_frame(payload, skip_headers=False, timestamp="fixture-time"),
            extract_ecg_messages(payload, skip_headers=False),
        )

        self.assertEqual(len(comparisons), 1)
        comparison = comparisons[0]
        self.assertTrue(comparison.match)
        self.assertEqual(comparison.compared_field_count, 13)
        self.assertEqual(comparison.mismatches, ())
        self.assertEqual(comparison.legacy["range_nm"], 10.0)
        self.assertEqual(comparison.decoded["decoder"], "legacy-projection")
        self.assertEqual(comparison.decoded["range_nm"], 10.0)
        self.assertEqual(comparison.decoded["mode_3_code"], 1234)

    def test_comparison_summary_counts_matches(self):
        payload = build_ecg_payload()
        comparisons = compare_legacy_records_to_envelopes(
            parse_frame(payload, skip_headers=False, timestamp="fixture-time"),
            extract_ecg_messages(payload, skip_headers=False),
        )

        self.assertEqual(
            comparison_summary(comparisons),
            {"comparison_count": 1, "match_count": 1, "mismatch_count": 0},
        )


if __name__ == "__main__":
    unittest.main()

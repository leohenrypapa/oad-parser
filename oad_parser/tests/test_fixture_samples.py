"""Tests for synthetic fixture sample generation."""

import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.fixture_samples import (
    sample_readme,
    build_synthetic_ecg_payload,
    build_synthetic_ethernet_ipv4_udp_frame,
    generate_fixture_samples,
)
from oad_parser.golden import check_golden_fixture
from oad_parser.parsers.ecg import extract_ecg_messages, parse_frame


class FixtureSampleTests(unittest.TestCase):
    def test_synthetic_payload_matches_legacy_and_envelope_paths(self):
        payload = build_synthetic_ecg_payload()

        legacy_records = parse_frame(payload, skip_headers=False)
        envelopes = extract_ecg_messages(payload, skip_headers=False)

        self.assertEqual(len(legacy_records), 1)
        self.assertEqual(len(envelopes), 1)
        self.assertEqual(legacy_records[0].message_type, "beacon")
        self.assertEqual(envelopes[0].message_type, "beacon")
        self.assertEqual(envelopes[0].data_words[1], 160)

    def test_synthetic_pcap_frame_has_ecg_envelope(self):
        payload = build_synthetic_ecg_payload()
        frame = build_synthetic_ethernet_ipv4_udp_frame(payload)

        envelopes = extract_ecg_messages(frame)

        self.assertEqual(len(envelopes), 1)
        self.assertEqual(envelopes[0].source_ip, "10.1.2.3")
        self.assertEqual(envelopes[0].destination_ip, "10.4.5.6")

    def test_generate_fixture_samples_outputs_expected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = generate_fixture_samples(tmp)
            output_dir = Path(tmp)

            expected = {
                "README.md",
                "corpus-report.json",
                "corpus-summary.txt",
                "sample.bin",
                "sample.pcap",
                "sample.pcap.golden.json",
                "sample.raw-payload.golden.json",
            }

            self.assertEqual(set(result.files), expected)
            report = json.loads((output_dir / "corpus-report.json").read_text(encoding="utf-8"))

            raw_check = check_golden_fixture(output_dir / "sample.raw-payload.golden.json")
            pcap_check = check_golden_fixture(output_dir / "sample.pcap.golden.json")

        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["match_count"], 2)
        self.assertTrue(raw_check.match)
        self.assertTrue(pcap_check.match)

    def test_sample_readme_uses_canonical_module_invocation(self):
        readme = sample_readme()
        self.assertIn("python3 -m oad_parser generate-fixture-samples", readme)
        self.assertNotIn("python3 -m oad_parser.cli", readme)


if __name__ == "__main__":
    unittest.main()

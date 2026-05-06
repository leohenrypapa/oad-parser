"""Tests for corpus report summaries."""

import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.corpus_report import load_corpus_report, summarize_corpus_report


class CorpusReportTests(unittest.TestCase):
    def sample_report(self):
        return {
            "root": "samples/sanitized",
            "files_scanned": 4,
            "files_with_errors": 1,
            "comparison_count": 2,
            "match_count": 1,
            "mismatch_count": 1,
            "zero_comparison_file_count": 1,
            "files": [
                {
                    "path": "good.bin",
                    "kind": "raw-payload",
                    "comparison_count": 1,
                    "match_count": 1,
                    "mismatch_count": 0,
                    "error": None,
                    "comparisons": [],
                },
                {
                    "path": "bad.pcap",
                    "kind": "pcap",
                    "comparison_count": 1,
                    "match_count": 0,
                    "mismatch_count": 1,
                    "error": None,
                    "comparisons": [
                        {
                            "index": 0,
                            "mismatches": [
                                {
                                    "field": "range_nm",
                                    "legacy": 10.0,
                                    "envelope": 20.0,
                                }
                            ],
                        }
                    ],
                },
                {
                    "path": "empty.bin",
                    "kind": "raw-payload",
                    "comparison_count": 0,
                    "match_count": 0,
                    "mismatch_count": 0,
                    "error": None,
                    "comparisons": [],
                },
                {
                    "path": "broken.bin",
                    "kind": "raw-payload",
                    "comparison_count": 0,
                    "match_count": 0,
                    "mismatch_count": 0,
                    "error": "failed to parse",
                    "comparisons": [],
                },
            ],
        }

    def test_summarize_corpus_report_default(self):
        text = summarize_corpus_report(self.sample_report())

        self.assertIn("Corpus validation summary", text)
        self.assertIn("Files scanned: 4", text)
        self.assertIn("File errors: 1", text)
        self.assertIn("Mismatched files: 1", text)
        self.assertIn("Zero-comparison files: 1", text)
        self.assertIn("empty.bin", text)
        self.assertIn("field=range_nm", text)
        self.assertNotIn("Matched files:", text)

    def test_summarize_corpus_report_show_matches(self):
        text = summarize_corpus_report(self.sample_report(), show_matches=True)

        self.assertIn("Matched files: 1", text)
        self.assertIn("good.bin", text)

    def test_load_corpus_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(self.sample_report()), encoding="utf-8")

            report = load_corpus_report(path)

        self.assertEqual(report["files_scanned"], 4)

    def test_summarize_rejects_bad_limit(self):
        with self.assertRaises(ValueError):
            summarize_corpus_report(self.sample_report(), limit=0)


if __name__ == "__main__":
    unittest.main()

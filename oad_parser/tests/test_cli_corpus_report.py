"""CLI tests for corpus report summarization."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_summarize_corpus_report


class CorpusReportCliTests(unittest.TestCase):
    def sample_report(self):
        return {
            "root": "samples/sanitized",
            "files_scanned": 1,
            "files_with_errors": 0,
            "comparison_count": 1,
            "match_count": 1,
            "mismatch_count": 0,
            "files": [
                {
                    "path": "sample.bin",
                    "kind": "raw-payload",
                    "comparison_count": 1,
                    "match_count": 1,
                    "mismatch_count": 0,
                    "error": None,
                    "comparisons": [],
                }
            ],
        }

    def test_summarize_corpus_report_prints_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(self.sample_report()), encoding="utf-8")
            args = argparse.Namespace(
                input=str(path),
                show_matches=True,
                limit=20,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_summarize_corpus_report(args)

        self.assertEqual(rc, 0)
        output = stdout.getvalue()
        self.assertIn("Corpus validation summary", output)
        self.assertIn("Matched files: 1", output)

    def test_summarize_corpus_report_writes_text_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "report.json"
            output_path = Path(tmp) / "summary.txt"
            input_path.write_text(json.dumps(self.sample_report()), encoding="utf-8")
            args = argparse.Namespace(
                input=str(input_path),
                show_matches=False,
                limit=20,
                output=str(output_path),
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_summarize_corpus_report(args)

            self.assertEqual(rc, 0)
            self.assertIn("wrote corpus report summary", stdout.getvalue())
            summary = output_path.read_text(encoding="utf-8")

        self.assertIn("Corpus validation summary", summary)
        self.assertIn("Mismatched files: 0", summary)


if __name__ == "__main__":
    unittest.main()

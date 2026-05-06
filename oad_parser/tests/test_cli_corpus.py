"""CLI tests for corpus validation."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_validate_corpus
from oad_parser.tests.test_ecg import build_ecg_payload


class CorpusCliTests(unittest.TestCase):
    def test_validate_corpus_prints_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.bin").write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                path=str(root),
                raw_payload=False,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_validate_corpus(args)

        self.assertEqual(rc, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["match_count"], 1)
        self.assertEqual(report["mismatch_count"], 0)

    def test_validate_corpus_returns_nonzero_for_zero_comparison_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "empty.bin").write_bytes(b"")
            args = argparse.Namespace(
                path=str(root),
                raw_payload=False,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_validate_corpus(args)

        self.assertEqual(rc, 1)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["comparison_count"], 0)
        self.assertEqual(report["zero_comparison_file_count"], 1)

    def test_validate_corpus_writes_report_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_path = root / "report.json"
            (root / "sample.bin").write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                path=str(root),
                raw_payload=False,
                output=str(output_path),
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_validate_corpus(args)

            self.assertEqual(rc, 0)
            self.assertIn("wrote corpus validation report", stdout.getvalue())
            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["comparison_count"], 1)
        self.assertEqual(report["match_count"], 1)


if __name__ == "__main__":
    unittest.main()

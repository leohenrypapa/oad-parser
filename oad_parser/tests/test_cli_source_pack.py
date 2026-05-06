"""CLI tests for source-pack generation."""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_create_source_pack


class SourcePackCliTests(unittest.TestCase):
    def test_create_source_pack_cli_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "source-pack.tar.gz"
            args = argparse.Namespace(
                output=str(output),
                tracked_only=False,
                include_untracked=False,
                json=False,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_create_source_pack(args)

            self.assertEqual(rc, 0)
            self.assertIn("created source pack", stdout.getvalue())
            self.assertTrue(output.exists())

    def test_create_source_pack_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "source-pack.tar.gz"
            args = argparse.Namespace(
                output=str(output),
                tracked_only=False,
                include_untracked=False,
                json=True,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_create_source_pack(args)

            data = json.loads(stdout.getvalue())

        self.assertEqual(rc, 0)
        self.assertTrue(data["output_path"].endswith("source-pack.tar.gz"))
        self.assertGreater(data["file_count"], 0)
        self.assertIn("SOURCE-PACK-MANIFEST.json", data["manifest_name"])


if __name__ == "__main__":
    unittest.main()

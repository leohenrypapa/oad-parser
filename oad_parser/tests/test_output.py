"""Unit tests for JSONL output helpers."""

import json
import tempfile
import unittest
from pathlib import Path

from oad_parser.models import ParsedPlot
from oad_parser.output import validate_jsonl, write_jsonl


class OutputTests(unittest.TestCase):
    def test_write_and_validate_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "out.jsonl"
            count = write_jsonl([ParsedPlot(sequence=1), ParsedPlot(sequence=2)], path)

            self.assertEqual(count, 2)

            validated_count, errors = validate_jsonl(path)
            self.assertEqual(validated_count, 2)
            self.assertEqual(errors, [])

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(json.loads(lines[0])["sequence"], 1)


if __name__ == "__main__":
    unittest.main()

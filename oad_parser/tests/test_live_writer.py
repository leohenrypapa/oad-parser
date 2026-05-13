"""Unit tests for append-mode rotating JSONL writer."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from oad_parser.config import LiveParserConfig
from oad_parser.live.writer import RotatingJsonlWriter


class Clock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value

    def advance(self, **kwargs):
        self.value = self.value + timedelta(**kwargs)


class RotatingJsonlWriterTests(unittest.TestCase):
    def test_appends_one_json_object_per_line_to_active_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            clock = Clock(datetime(2026, 5, 12, 16, 0, 0, tzinfo=timezone.utc))
            writer = RotatingJsonlWriter(str(active_path), now_fn=clock.now)

            first = writer.write_record({"record_type": "ecg_event", "seq": 1})
            second = writer.write_record({"record_type": "ecg_event", "seq": 2})

            self.assertEqual(first.active_path, str(active_path))
            self.assertIsNone(first.rotated_path)
            self.assertIsNone(second.rotated_path)
            lines = active_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["seq"], 1)
            self.assertEqual(json.loads(lines[1])["seq"], 2)
            self.assertGreater(first.bytes_written, 0)

    def test_preserves_existing_active_file_content_by_appending(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            active_path.write_text('{"existing":true}\n', encoding="utf-8")
            writer = RotatingJsonlWriter(str(active_path))

            writer.write_record({"new": True})

            lines = active_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["existing"], True)
            self.assertEqual(json.loads(lines[1])["new"], True)

    def test_rotates_by_age_before_next_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            clock = Clock(datetime(2026, 5, 12, 16, 0, 0, tzinfo=timezone.utc))
            writer = RotatingJsonlWriter(
                str(active_path),
                rotate_seconds=900,
                now_fn=clock.now,
            )

            writer.write_record({"seq": 1})
            clock.advance(seconds=900)
            result = writer.write_record({"seq": 2})

            self.assertIsNotNone(result.rotated_path)
            rotated_path = Path(result.rotated_path)
            self.assertEqual(rotated_path.name, "ecg-current-20260512T161500Z.jsonl")
            self.assertEqual(json.loads(rotated_path.read_text(encoding="utf-8"))["seq"], 1)
            self.assertEqual(json.loads(active_path.read_text(encoding="utf-8"))["seq"], 2)

    def test_rotates_by_size_before_next_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            clock = Clock(datetime(2026, 5, 12, 16, 0, 0, tzinfo=timezone.utc))
            writer = RotatingJsonlWriter(
                str(active_path),
                rotate_max_bytes=30,
                now_fn=clock.now,
            )

            writer.write_record({"seq": 1, "payload": "abcdef"})
            result = writer.write_record({"seq": 2, "payload": "abcdef"})

            self.assertIsNotNone(result.rotated_path)
            self.assertEqual(Path(result.rotated_path).name, "ecg-current-20260512T160000Z.jsonl")
            self.assertEqual(json.loads(Path(result.rotated_path).read_text(encoding="utf-8"))["seq"], 1)
            self.assertEqual(json.loads(active_path.read_text(encoding="utf-8"))["seq"], 2)

    def test_rotation_name_collision_uses_numeric_suffix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            collision_path = Path(tmpdir) / "ecg-current-20260512T160000Z.jsonl"
            collision_path.write_text('{"older":true}\n', encoding="utf-8")
            clock = Clock(datetime(2026, 5, 12, 16, 0, 0, tzinfo=timezone.utc))
            writer = RotatingJsonlWriter(
                str(active_path),
                rotate_max_bytes=30,
                now_fn=clock.now,
            )

            writer.write_record({"seq": 1, "payload": "abcdef"})
            result = writer.write_record({"seq": 2, "payload": "abcdef"})

            self.assertIsNotNone(result.rotated_path)
            self.assertEqual(
                Path(result.rotated_path).name,
                "ecg-current-20260512T160000Z-0001.jsonl",
            )
            self.assertEqual(json.loads(collision_path.read_text(encoding="utf-8"))["older"], True)

    def test_empty_active_file_is_not_rotated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            active_path.write_text("", encoding="utf-8")
            clock = Clock(datetime(2026, 5, 12, 16, 0, 0, tzinfo=timezone.utc))
            writer = RotatingJsonlWriter(
                str(active_path),
                rotate_seconds=1,
                now_fn=clock.now,
            )
            clock.advance(seconds=10)

            result = writer.write_record({"seq": 1})

            self.assertIsNone(result.rotated_path)
            self.assertEqual(len(list(Path(tmpdir).glob("*.jsonl"))), 0)
            self.assertEqual(json.loads(active_path.read_text(encoding="utf-8"))["seq"], 1)

    def test_from_config_uses_output_path_and_rotation_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active_path = Path(tmpdir) / "ecg-current.json"
            config = LiveParserConfig(
                output_json_file=str(active_path),
                rotate_seconds=10,
                rotate_max_bytes=99,
            )

            writer = RotatingJsonlWriter.from_config(config)

            self.assertEqual(writer.active_path, active_path)
            self.assertEqual(writer.rotate_seconds, 10)
            self.assertEqual(writer.rotate_max_bytes, 99)

    def test_rejects_invalid_rotation_policy(self):
        with self.assertRaises(ValueError):
            RotatingJsonlWriter("/tmp/ecg-current.json", rotate_seconds=0)

        with self.assertRaises(ValueError):
            RotatingJsonlWriter("/tmp/ecg-current.json", rotate_max_bytes=0)


if __name__ == "__main__":
    unittest.main()

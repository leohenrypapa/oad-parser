"""Unit tests for live storage pruning and disk-protection policy."""

from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import tempfile
import unittest

from oad_parser.config import LiveParserConfig
from oad_parser.live.storage import LiveStoragePolicy


DiskUsage = namedtuple("DiskUsage", "total used free")
FIXED_TIME = datetime(2026, 5, 12, 17, 0, 0, tzinfo=timezone.utc)


class DiskUsageSequence:
    def __init__(self, percents):
        self.percents = list(percents)
        self.calls = 0

    def __call__(self, path):
        index = min(self.calls, len(self.percents) - 1)
        self.calls += 1
        total = 1000
        used = int(total * (self.percents[index] / 100.0))
        return DiskUsage(total=total, used=used, free=total - used)


class LiveStoragePolicyTests(unittest.TestCase):
    def _write_file(self, path, content, modified_time):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        ts = modified_time.timestamp()
        os.utime(str(path), (ts, ts))

    def _policy(self, active_path, disk_percents=(10,), **kwargs):
        return LiveStoragePolicy(
            active_output_path=str(active_path),
            audit_path=str(active_path.parent / "ecg-audit.jsonl"),
            status_path=str(active_path.parent / "ecg-status.json"),
            now_fn=lambda: FIXED_TIME,
            disk_usage_fn=DiskUsageSequence(disk_percents),
            **kwargs,
        )

    def test_prunes_closed_files_older_than_retention_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            old_closed = output_dir / "ecg-current-20260512T010000Z.jsonl"
            fresh_closed = output_dir / "ecg-current-20260512T163000Z.jsonl"
            self._write_file(active, '{"active":true}\n', FIXED_TIME)
            self._write_file(old_closed, '{"old":true}\n', FIXED_TIME - timedelta(seconds=43201))
            self._write_file(fresh_closed, '{"fresh":true}\n', FIXED_TIME - timedelta(seconds=60))

            result = self._policy(
                active,
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            ).apply()

            self.assertEqual(result.files_pruned, 1)
            self.assertFalse(old_closed.exists())
            self.assertTrue(fresh_closed.exists())
            self.assertTrue(active.exists())
            self.assertFalse(result.writer_blocked)
            self.assertFalse(result.critical)
            self.assertIn(str(old_closed), result.pruned_paths)

    def test_high_water_prunes_oldest_closed_files_until_below_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            oldest = output_dir / "ecg-current-20260512T010000Z.jsonl"
            newest = output_dir / "ecg-current-20260512T020000Z.jsonl"
            self._write_file(active, '{"active":true}\n', FIXED_TIME)
            self._write_file(oldest, '{"oldest":true}\n', FIXED_TIME - timedelta(hours=2))
            self._write_file(newest, '{"newest":true}\n', FIXED_TIME - timedelta(hours=1))

            result = self._policy(
                active,
                disk_percents=(80, 80, 70, 70),
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            ).apply()

            self.assertEqual(result.files_pruned, 1)
            self.assertFalse(oldest.exists())
            self.assertTrue(newest.exists())
            self.assertTrue(active.exists())
            self.assertFalse(result.writer_blocked)
            self.assertFalse(result.critical)
            self.assertLess(result.disk_usage_percent, 75)

    def test_writer_blocked_when_pruning_cannot_reduce_below_high_water(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            closed = output_dir / "ecg-current-20260512T010000Z.jsonl"
            self._write_file(active, '{"active":true}\n', FIXED_TIME)
            self._write_file(closed, '{"closed":true}\n', FIXED_TIME - timedelta(hours=1))

            result = self._policy(
                active,
                disk_percents=(80, 80, 80, 80),
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            ).apply()

            self.assertEqual(result.files_pruned, 1)
            self.assertFalse(closed.exists())
            self.assertTrue(active.exists())
            self.assertTrue(result.writer_blocked)
            self.assertFalse(result.critical)
            self.assertGreaterEqual(result.disk_usage_percent, 75)

    def test_critical_threshold_is_reported_after_best_effort_pruning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            closed = output_dir / "ecg-current-20260512T010000Z.jsonl"
            self._write_file(active, '{"active":true}\n', FIXED_TIME)
            self._write_file(closed, '{"closed":true}\n', FIXED_TIME - timedelta(hours=1))

            result = self._policy(
                active,
                disk_percents=(96, 96, 96, 96),
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            ).apply()

            self.assertEqual(result.files_pruned, 1)
            self.assertFalse(closed.exists())
            self.assertTrue(active.exists())
            self.assertTrue(result.writer_blocked)
            self.assertTrue(result.critical)
            self.assertGreaterEqual(result.disk_usage_percent, 95)

    def test_active_audit_and_status_files_are_never_deleted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            audit = output_dir / "ecg-audit.jsonl"
            status = output_dir / "ecg-status.json"
            closed = output_dir / "ecg-current-20260512T010000Z.jsonl"
            unrelated = output_dir / "operator-notes.jsonl"
            old_time = FIXED_TIME - timedelta(days=1)

            for path in [active, audit, status, closed, unrelated]:
                self._write_file(path, '{"x":true}\n', old_time)

            policy = LiveStoragePolicy(
                active_output_path=str(active),
                audit_path=str(audit),
                status_path=str(status),
                now_fn=lambda: FIXED_TIME,
                disk_usage_fn=DiskUsageSequence((80, 70, 70)),
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            )
            result = policy.apply()

            self.assertFalse(closed.exists())
            self.assertTrue(active.exists())
            self.assertTrue(audit.exists())
            self.assertTrue(status.exists())
            self.assertTrue(unrelated.exists())
            self.assertEqual(result.files_pruned, 1)
            self.assertIn(str(active.resolve()), result.protected_paths)
            self.assertIn(str(audit.resolve()), result.protected_paths)
            self.assertIn(str(status.resolve()), result.protected_paths)

    def test_closed_output_files_are_sorted_oldest_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            active = output_dir / "ecg-current.json"
            older = output_dir / "ecg-current-20260512T010000Z.jsonl"
            newer = output_dir / "ecg-current-20260512T020000Z.jsonl"
            self._write_file(active, '{"active":true}\n', FIXED_TIME)
            self._write_file(newer, '{"newer":true}\n', FIXED_TIME - timedelta(hours=1))
            self._write_file(older, '{"older":true}\n', FIXED_TIME - timedelta(hours=2))

            files = self._policy(
                active,
                prune_after_seconds=43200,
                disk_high_water_percent=75,
                disk_critical_percent=95,
            ).closed_output_files()

            self.assertEqual([Path(item.path).name for item in files], [
                "ecg-current-20260512T010000Z.jsonl",
                "ecg-current-20260512T020000Z.jsonl",
            ])

    def test_from_config_uses_storage_policy_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active = Path(tmpdir) / "ecg-current.json"
            config = LiveParserConfig(
                output_json_file=str(active),
                prune_after_seconds=123,
                disk_high_water_percent=74,
                disk_critical_percent=96,
            )

            policy = LiveStoragePolicy.from_config(
                config,
                now_fn=lambda: FIXED_TIME,
                disk_usage_fn=DiskUsageSequence((10,)),
            )

            self.assertEqual(policy.active_output_path, active)
            self.assertEqual(policy.prune_after_seconds, 123)
            self.assertEqual(policy.disk_high_water_percent, 74)
            self.assertEqual(policy.disk_critical_percent, 96)

    def test_rejects_invalid_storage_thresholds(self):
        with self.assertRaises(ValueError):
            LiveStoragePolicy(active_output_path="/tmp/ecg-current.json", prune_after_seconds=-1)

        with self.assertRaises(ValueError):
            LiveStoragePolicy(active_output_path="/tmp/ecg-current.json", disk_high_water_percent=-1)

        with self.assertRaises(ValueError):
            LiveStoragePolicy(active_output_path="/tmp/ecg-current.json", disk_critical_percent=101)

        with self.assertRaises(ValueError):
            LiveStoragePolicy(
                active_output_path="/tmp/ecg-current.json",
                disk_high_water_percent=75,
                disk_critical_percent=75,
            )


if __name__ == "__main__":
    unittest.main()

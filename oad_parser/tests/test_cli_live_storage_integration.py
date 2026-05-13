"""CLI regression tests for production live storage protection wiring."""

from argparse import Namespace
from collections import namedtuple
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from oad_parser.cli import run_live
from oad_parser.config import LiveParserConfig
from oad_parser.live.records import LiveCaptureFrame
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


DiskUsage = namedtuple("DiskUsage", "total used free")


class LiveCliStorageIntegrationTests(unittest.TestCase):
    def _config(self, directory, *, high=75, critical=95):
        return LiveParserConfig(
            mode="live",
            interface="eno1",
            output_json=True,
            output_json_file=str(Path(directory) / "ecg-current.json"),
            audit_file=str(Path(directory) / "ecg-audit.jsonl"),
            status_file=str(Path(directory) / "ecg-status.json"),
            disk_high_water_percent=high,
            disk_critical_percent=critical,
            block_when_full=True,
        )

    def _frame(self):
        return LiveCaptureFrame(
            frame_bytes=build_ethernet_ipv4_udp_frame(build_ecg_payload()),
            interface="eno1",
            capture_time_utc=None,
        )

    def test_run_live_returns_nonzero_when_storage_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(tmp, high=75, critical=95)

            with patch("oad_parser.cli.load_live_parser_config", return_value=config):
                with patch(
                    "oad_parser.cli.iter_live_capture_frames_from_config",
                    return_value=iter([self._frame()]),
                ):
                    with patch(
                        "oad_parser.live.storage.shutil.disk_usage",
                        return_value=DiskUsage(total=100, used=96, free=4),
                    ):
                        code = run_live(
                            Namespace(
                                config=str(Path(tmp) / "ecg_conf.ini"),
                                interface="eno1",
                                max_frames=1,
                            )
                        )

            self.assertEqual(code, 3)
            self.assertFalse((Path(tmp) / "ecg-current.json").exists())
            self.assertTrue((Path(tmp) / "ecg-audit.jsonl").exists())
            self.assertTrue((Path(tmp) / "ecg-status.json").exists())

    def test_run_live_blocks_output_at_high_water_but_returns_zero_when_not_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self._config(tmp, high=75, critical=95)

            with patch("oad_parser.cli.load_live_parser_config", return_value=config):
                with patch(
                    "oad_parser.cli.iter_live_capture_frames_from_config",
                    return_value=iter([self._frame()]),
                ):
                    with patch(
                        "oad_parser.live.storage.shutil.disk_usage",
                        return_value=DiskUsage(total=100, used=80, free=20),
                    ):
                        code = run_live(
                            Namespace(
                                config=str(Path(tmp) / "ecg_conf.ini"),
                                interface="eno1",
                                max_frames=1,
                            )
                        )

            self.assertEqual(code, 0)
            self.assertFalse((Path(tmp) / "ecg-current.json").exists())
            status_text = (Path(tmp) / "ecg-status.json").read_text(encoding="utf-8")
            self.assertIn('"output_drops":1', status_text)
            self.assertIn('"disk_percent":80.0', status_text)


if __name__ == "__main__":
    unittest.main()

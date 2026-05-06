"""Unit tests for INI config loading."""

import tempfile
import unittest
from pathlib import Path

from oad_parser.config import load_parser_config


class ConfigTests(unittest.TestCase):
    def test_load_parser_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.ini"
            path.write_text(
                "\n".join(
                    [
                        "[output]",
                        "path = /tmp/out.jsonl",
                        "schema = legacy",
                        "",
                        "[capture]",
                        "interface = eth1",
                        "max_frames = 100",
                        "",
                        "[detectors]",
                        "enabled = true",
                        "discovery_window_records = 5",
                        "max_sequence_delta = 6",
                        "max_range_nm = 200.5",
                        "max_azimuth_jump_degrees = 33.5",
                        "max_router_time_delta_seconds = 2.5",
                        "max_radar_time_delta_seconds =",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_parser_config(path)

            self.assertEqual(config.output_path, "/tmp/out.jsonl")
            self.assertEqual(config.schema, "legacy")
            self.assertEqual(config.interface, "eth1")
            self.assertEqual(config.max_frames, 100)
            self.assertTrue(config.detectors_enabled)
            self.assertEqual(config.discovery_window_records, 5)
            self.assertEqual(config.max_sequence_delta, 6)
            self.assertEqual(config.max_range_nm, 200.5)
            self.assertEqual(config.max_azimuth_jump_degrees, 33.5)
            self.assertEqual(config.max_router_time_delta_seconds, 2.5)
            self.assertIsNone(config.max_radar_time_delta_seconds)

    def test_missing_config_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_parser_config("/no/such/config.ini")


if __name__ == "__main__":
    unittest.main()

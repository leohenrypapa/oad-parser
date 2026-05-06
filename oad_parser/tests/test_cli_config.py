"""Unit tests for CLI config resolution."""

import argparse
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import require_capture_max_frames, require_interface, require_output_path, resolved_config_from_args


class CliConfigTests(unittest.TestCase):
    def test_cli_overrides_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.ini"
            config_path.write_text(
                "\n".join(
                    [
                        "[output]",
                        "path = /tmp/from-config.jsonl",
                        "schema = ecs",
                        "",
                        "[capture]",
                        "interface = eth0",
                        "",
                        "[detectors]",
                        "enabled = false",
                    ]
                ),
                encoding="utf-8",
            )

            args = argparse.Namespace(
                config=str(config_path),
                output="/tmp/from-cli.jsonl",
                schema="legacy",
                interface="eth9",
                max_frames=25,
                detect=True,
                discovery_window_records=None,
                max_sequence_delta=None,
                max_range_nm=None,
                max_azimuth_jump_degrees=None,
                max_router_time_delta_seconds=None,
                max_radar_time_delta_seconds=None,
            )

            config = resolved_config_from_args(args)

            self.assertEqual(config.output_path, "/tmp/from-cli.jsonl")
            self.assertEqual(config.schema, "legacy")
            self.assertEqual(config.interface, "eth9")
            self.assertEqual(config.max_frames, 25)
            self.assertTrue(config.detectors_enabled)

    def test_require_output_path(self):
        args = argparse.Namespace(
            config=None,
            output=None,
            schema=None,
            interface=None,
            max_frames=None,
            detect=False,
            discovery_window_records=None,
            max_sequence_delta=None,
            max_range_nm=None,
            max_azimuth_jump_degrees=None,
            max_router_time_delta_seconds=None,
            max_radar_time_delta_seconds=None,
        )
        config = resolved_config_from_args(args)

        with self.assertRaises(ValueError):
            require_output_path(config)

    def test_require_interface(self):
        args = argparse.Namespace(
            config=None,
            output="/tmp/out.jsonl",
            schema=None,
            interface=None,
            max_frames=None,
            detect=False,
            discovery_window_records=None,
            max_sequence_delta=None,
            max_range_nm=None,
            max_azimuth_jump_degrees=None,
            max_router_time_delta_seconds=None,
            max_radar_time_delta_seconds=None,
        )
        config = resolved_config_from_args(args)

        with self.assertRaises(ValueError):
            require_interface(config)

    def test_require_capture_max_frames(self):
        args = argparse.Namespace(
            config=None,
            output="/tmp/out.jsonl",
            schema=None,
            interface="eth0",
            max_frames=None,
            detect=False,
            discovery_window_records=None,
            max_sequence_delta=None,
            max_range_nm=None,
            max_azimuth_jump_degrees=None,
            max_router_time_delta_seconds=None,
            max_radar_time_delta_seconds=None,
        )
        config = resolved_config_from_args(args)

        with self.assertRaises(ValueError):
            require_capture_max_frames(config)

        config.max_frames = 0
        with self.assertRaises(ValueError):
            require_capture_max_frames(config)

        config.max_frames = 1
        self.assertEqual(require_capture_max_frames(config), 1)



if __name__ == "__main__":
    unittest.main()

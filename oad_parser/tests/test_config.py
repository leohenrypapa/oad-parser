"""Unit tests for INI config loading."""

import tempfile
import unittest
from pathlib import Path

from oad_parser.config import load_live_parser_config, load_parser_config


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

    def test_existing_lowercase_sections_load_without_live_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "legacy-compatible.ini"
            path.write_text(
                "\n".join(
                    [
                        "[output]",
                        "path = /tmp/legacy.jsonl",
                        "schema = ecs",
                        "",
                        "[capture]",
                        "interface = eno1",
                        "max_frames = 10",
                        "",
                        "[detectors]",
                        "enabled = false",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_parser_config(path)

            self.assertEqual(config.output_path, "/tmp/legacy.jsonl")
            self.assertEqual(config.schema, "ecs")
            self.assertEqual(config.interface, "eno1")
            self.assertEqual(config.max_frames, 10)
            self.assertFalse(config.detectors_enabled)

    def test_existing_config_sections_ignore_absent_optional_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "minimal.ini"
            path.write_text(
                "\n".join(
                    [
                        "[output]",
                        "",
                        "[capture]",
                        "",
                        "[detectors]",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_parser_config(path)

            self.assertIsNone(config.output_path)
            self.assertEqual(config.schema, "ecs")
            self.assertIsNone(config.interface)
            self.assertIsNone(config.max_frames)
            self.assertFalse(config.detectors_enabled)

    def test_live_config_defaults_match_production_mvp(self):
        config = load_live_parser_config(None)

        self.assertEqual(config.output_json_file, "/nsm/ecg/ecg-current.json")
        self.assertEqual(config.output_csv_file, "/nsm/ecg/ecg.csv")
        self.assertTrue(config.output_json)
        self.assertFalse(config.output_csv)
        self.assertFalse(config.output_csv_requested)
        self.assertTrue(config.skip_headers)
        self.assertTrue(config.check_range)
        self.assertTrue(config.check_altitude)
        self.assertTrue(config.check_azimuth)
        self.assertTrue(config.check_site_discovery)
        self.assertTrue(config.check_time_delta)
        self.assertTrue(config.check_fingerprint)
        self.assertTrue(config.output_status)
        self.assertEqual(config.interface, "eno1")
        self.assertEqual(config.mode, "legacy_jsonl")
        self.assertEqual(config.rotate_seconds, 900)
        self.assertEqual(config.rotate_max_bytes, 536870912)
        self.assertEqual(config.receive_buffer_bytes, 134217728)
        self.assertEqual(config.status_interval_seconds, 60)
        self.assertEqual(config.metrics_interval_seconds, 60)
        self.assertEqual(config.output_dir, "/nsm/ecg")
        self.assertEqual(config.prune_after_seconds, 43200)
        self.assertEqual(config.disk_high_water_percent, 75)
        self.assertEqual(config.disk_critical_percent, 95)
        self.assertTrue(config.block_when_full)
        self.assertFalse(config.compress_archives)
        self.assertFalse(config.compress_archives_requested)
        self.assertEqual(config.audit_file, "/nsm/ecg/ecg-audit.jsonl")
        self.assertEqual(config.status_file, "/nsm/ecg/ecg-status.json")

    def test_live_config_loads_legacy_style_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ecg_conf.ini"
            path.write_text(
                "\n".join(
                    [
                        "[Outputs]",
                        "output_json_file = /tmp/ecg-current.json",
                        "output_csv_file = /tmp/ecg.csv",
                        "",
                        "[Options]",
                        "skip_headers = false",
                        "output_json = true",
                        "output_csv = true",
                        "check_range = false",
                        "check_altitude = true",
                        "check_azimuth = false",
                        "check_site_discovery = true",
                        "check_time_delta = false",
                        "check_fingerprint = true",
                        "output_status = false",
                        "",
                        "[Live]",
                        "interface = eno5",
                        "mode = legacy_jsonl",
                        "rotate_seconds = 901",
                        "rotate_max_bytes = 123456",
                        "receive_buffer_bytes = 65536",
                        "status_interval_seconds = 30",
                        "metrics_interval_seconds = 31",
                        "",
                        "[Storage]",
                        "output_dir = /tmp/ecg",
                        "prune_after_seconds = 3600",
                        "disk_high_water_percent = 70",
                        "disk_critical_percent = 90",
                        "block_when_full = false",
                        "compress_archives = true",
                        "",
                        "[Audit]",
                        "audit_file = /tmp/ecg-audit.jsonl",
                        "status_file = /tmp/ecg-status.json",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_live_parser_config(path)

            self.assertEqual(config.output_json_file, "/tmp/ecg-current.json")
            self.assertEqual(config.output_csv_file, "/tmp/ecg.csv")
            self.assertTrue(config.output_json)
            self.assertFalse(config.output_csv)
            self.assertTrue(config.output_csv_requested)
            self.assertFalse(config.skip_headers)
            self.assertFalse(config.check_range)
            self.assertTrue(config.check_altitude)
            self.assertFalse(config.check_azimuth)
            self.assertTrue(config.check_site_discovery)
            self.assertFalse(config.check_time_delta)
            self.assertTrue(config.check_fingerprint)
            self.assertFalse(config.output_status)
            self.assertEqual(config.interface, "eno5")
            self.assertEqual(config.mode, "legacy_jsonl")
            self.assertEqual(config.rotate_seconds, 901)
            self.assertEqual(config.rotate_max_bytes, 123456)
            self.assertEqual(config.receive_buffer_bytes, 65536)
            self.assertEqual(config.status_interval_seconds, 30)
            self.assertEqual(config.metrics_interval_seconds, 31)
            self.assertEqual(config.output_dir, "/tmp/ecg")
            self.assertEqual(config.prune_after_seconds, 3600)
            self.assertEqual(config.disk_high_water_percent, 70)
            self.assertEqual(config.disk_critical_percent, 90)
            self.assertFalse(config.block_when_full)
            self.assertFalse(config.compress_archives)
            self.assertTrue(config.compress_archives_requested)
            self.assertEqual(config.audit_file, "/tmp/ecg-audit.jsonl")
            self.assertEqual(config.status_file, "/tmp/ecg-status.json")

    def test_live_config_preserves_existing_ini_fallbacks_where_possible(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "existing.ini"
            path.write_text(
                "\n".join(
                    [
                        "[output]",
                        "path = /tmp/existing-output.jsonl",
                        "schema = ecs",
                        "",
                        "[capture]",
                        "interface = eno3",
                        "max_frames = 10",
                        "",
                        "[detectors]",
                        "enabled = false",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_live_parser_config(path)

            self.assertEqual(config.output_json_file, "/tmp/existing-output.jsonl")
            self.assertEqual(config.interface, "eno3")
            self.assertFalse(config.check_range)
            self.assertFalse(config.check_altitude)
            self.assertFalse(config.check_azimuth)
            self.assertFalse(config.check_site_discovery)
            self.assertFalse(config.check_time_delta)
            self.assertFalse(config.check_fingerprint)

    def test_live_example_config_loads(self):
        config = load_live_parser_config("config/ecg_conf.example.ini")

        self.assertEqual(config.output_json_file, "/nsm/ecg/ecg-current.json")
        self.assertFalse(config.output_csv)
        self.assertEqual(config.interface, "eno1")
        self.assertEqual(config.rotate_seconds, 900)
        self.assertEqual(config.rotate_max_bytes, 536870912)
        self.assertEqual(config.disk_high_water_percent, 75)
        self.assertEqual(config.disk_critical_percent, 95)
        self.assertFalse(config.compress_archives)

    def test_live_config_rejects_invalid_mvp_values(self):
        cases = [
            ("[Options]\noutput_json = false\n", "live JSON output"),
            ("[Live]\nmode = csv\n", "live mode"),
            ("[Live]\ninterface =    \n", "live interface"),
            ("[Live]\nrotate_seconds = 0\n", "rotate_seconds"),
            ("[Live]\nrotate_max_bytes = 0\n", "rotate_max_bytes"),
            ("[Live]\nreceive_buffer_bytes = 0\n", "receive_buffer_bytes"),
            ("[Live]\nstatus_interval_seconds = 0\n", "status_interval_seconds"),
            ("[Live]\nmetrics_interval_seconds = 0\n", "metrics_interval_seconds"),
            ("[Storage]\nprune_after_seconds = -1\n", "prune_after_seconds"),
            ("[Storage]\ndisk_high_water_percent = -1\n", "disk_high_water_percent"),
            ("[Storage]\ndisk_high_water_percent = 101\n", "disk_high_water_percent"),
            ("[Storage]\ndisk_critical_percent = -1\n", "disk_critical_percent"),
            ("[Storage]\ndisk_critical_percent = 101\n", "disk_critical_percent"),
            (
                "[Storage]\ndisk_high_water_percent = 75\ndisk_critical_percent = 75\n",
                "disk_critical_percent",
            ),
        ]

        for body, expected_text in cases:
            with self.subTest(expected_text=expected_text, body=body):
                with tempfile.TemporaryDirectory() as tmpdir:
                    path = Path(tmpdir) / "bad-live.ini"
                    path.write_text(body, encoding="utf-8")

                    with self.assertRaises(ValueError) as raised:
                        load_live_parser_config(path)

                    self.assertIn(expected_text, str(raised.exception))

    def test_live_config_rejects_unsafe_threshold_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.ini"
            path.write_text(
                "\n".join(
                    [
                        "[Storage]",
                        "disk_high_water_percent = 95",
                        "disk_critical_percent = 75",
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_live_parser_config(path)

    def test_missing_config_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_parser_config("/no/such/config.ini")

    def test_missing_live_config_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_live_parser_config("/no/such/live-config.ini")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for CD2 config profile fields."""

import tempfile
import unittest
from pathlib import Path

from oad_parser.config import load_parser_config


class Cd2ConfigTests(unittest.TestCase):
    def test_loads_cd2_profile_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.ini"
            path.write_text(
                "\n".join(
                    [
                        "[cd2]",
                        "add_remove_parity = true",
                        "receive_frame_size_words = 64",
                        "error_screening = true",
                        "data_inversion = true",
                        "parity_mode = even",
                        "decoder = beacon-candidate",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_parser_config(path)

        self.assertTrue(config.cd2_add_remove_parity)
        self.assertEqual(config.cd2_receive_frame_size_words, 64)
        self.assertTrue(config.cd2_error_screening)
        self.assertTrue(config.cd2_data_inversion)
        self.assertEqual(config.cd2_parity_mode, "even")
        self.assertEqual(config.cd2_decoder, "beacon-candidate")

    def test_rejects_invalid_cd2_frame_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ini"
            path.write_text("[cd2]\nreceive_frame_size_words = 0\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_parser_config(path)

    def test_rejects_invalid_cd2_parity_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ini"
            path.write_text("[cd2]\nparity_mode = mark\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_parser_config(path)

    def test_rejects_invalid_cd2_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ini"
            path.write_text("[cd2]\ndecoder = missing\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_parser_config(path)


if __name__ == "__main__":
    unittest.main()

"""CLI tests for CD2 decoder output."""

import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_decode_cd2_words
from oad_parser.parsers.cd2 import CD2_IDLE_WORD, calculate_parity_bit


def data_word(data_bits: int) -> int:
    return (data_bits << 1) | calculate_parity_bit(data_bits)


class Cd2CliDecoderTests(unittest.TestCase):
    def run_cli(self, decoder: str, data_words: list[int]) -> str:
        args = argparse.Namespace(
            config=None,
            input=None,
            from_bytes=False,
            json=False,
            decoder=decoder,
            words=[
                f"0x{CD2_IDLE_WORD:04x}",
                *[f"0x{data_word(word):04x}" for word in data_words],
                f"0x{CD2_IDLE_WORD:04x}",
            ],
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        return stdout.getvalue()

    def test_decode_cd2_words_raw12_decoder_output(self):
        output = self.run_cli("raw12", [1, 2])

        self.assertIn('"decoder": "raw12"', output)
        self.assertIn('"data_words_hex": [', output)
        self.assertIn('"0x001"', output)
        self.assertIn('"0x002"', output)

    def test_decode_cd2_words_beacon_candidate_output(self):
        output = self.run_cli(
            "beacon-candidate",
            [0, 80, 1024, 0, 0o1234, 0, 30],
        )

        self.assertIn('"decoder": "beacon-candidate"', output)
        self.assertIn('"status": "provisional"', output)
        self.assertIn('"range_nm": 10.0', output)
        self.assertIn('"azimuth_degrees": 90.0', output)
        self.assertIn('"mode_3_code": 1234', output)
        self.assertIn('"altitude_feet": 3000', output)

    def test_decode_cd2_words_lists_decoders(self):
        args = argparse.Namespace(
            config=None,
            input=None,
            from_bytes=False,
            json=False,
            decoder=None,
            list_decoders=True,
            words=[],
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        output = stdout.getvalue()
        self.assertIn("raw12:", output)
        self.assertIn("beacon-candidate:", output)

    def test_decode_cd2_words_uses_configured_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "profile.ini"
            config_path.write_text("[cd2]\ndecoder = raw12\n", encoding="utf-8")
            args = argparse.Namespace(
                config=str(config_path),
                input=None,
                from_bytes=False,
                json=False,
                decoder=None,
                list_decoders=False,
                words=[
                    f"0x{CD2_IDLE_WORD:04x}",
                    f"0x{data_word(1):04x}",
                    f"0x{CD2_IDLE_WORD:04x}",
                ],
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        self.assertIn('"decoder": "raw12"', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

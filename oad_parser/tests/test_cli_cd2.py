"""Unit tests for the CD2 decode CLI helpers."""

import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import parse_cd2_word_token, run_decode_cd2_words
from oad_parser.parsers.cd2 import CD2_IDLE_WORD, calculate_parity_bit


def data_word(data_bits: int) -> int:
    return (data_bits << 1) | calculate_parity_bit(data_bits)


class Cd2CliTests(unittest.TestCase):
    def test_parse_cd2_word_token_accepts_common_formats(self):
        self.assertEqual(parse_cd2_word_token("0x03ff"), CD2_IDLE_WORD)
        self.assertEqual(parse_cd2_word_token("03ff"), CD2_IDLE_WORD)
        self.assertEqual(parse_cd2_word_token("0b0001111111111"), CD2_IDLE_WORD)
        self.assertEqual(parse_cd2_word_token(str(CD2_IDLE_WORD)), CD2_IDLE_WORD)

    def test_decode_cd2_words_text_output(self):
        args = argparse.Namespace(
            config=None,
            input=None,
            from_bytes=False,
            json=False,
            words=[
                f"0x{CD2_IDLE_WORD:04x}",
                f"0x{data_word(1):04x}",
                f"0x{data_word(2):04x}",
                f"0x{CD2_IDLE_WORD:04x}",
            ],
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        output = stdout.getvalue()
        self.assertIn("frame_count=1", output)
        self.assertIn("words=2", output)
        self.assertIn("data_words=0x001 0x002", output)

    def test_decode_cd2_words_json_output(self):
        args = argparse.Namespace(
            config=None,
            input=None,
            from_bytes=False,
            json=True,
            words=[
                f"0x{CD2_IDLE_WORD:04x}",
                f"0x{data_word(3):04x}",
                f"0x{CD2_IDLE_WORD:04x}",
            ],
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        output = stdout.getvalue()
        self.assertIn('"data_words": [', output)
        self.assertIn("3", output)

    def test_decode_cd2_words_reads_input_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "words.txt"
            path.write_text(
                f"0x{CD2_IDLE_WORD:04x} 0x{data_word(4):04x} 0x{CD2_IDLE_WORD:04x}\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config=None,
                input=str(path),
                from_bytes=False,
                json=False,
                words=[],
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_decode_cd2_words(args)

        self.assertEqual(rc, 0)
        self.assertIn("data_words=0x004", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

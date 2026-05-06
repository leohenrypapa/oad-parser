"""Tests for decoder registry scaffolding."""

import unittest

from oad_parser.decoders.cd2_radar import decode_beacon_candidate_words
from oad_parser.decoders.registry import build_default_registry
from oad_parser.parsers.cd2 import CD2_IDLE_WORD, calculate_parity_bit, frame_13_bit_values


def data_word(data_bits: int) -> int:
    return (data_bits << 1) | calculate_parity_bit(data_bits)


def beacon_candidate_frame():
    return frame_13_bit_values(
        [
            CD2_IDLE_WORD,
            data_word(0),
            data_word(80),
            data_word(1024),
            data_word(0),
            data_word(0o1234),
            data_word(0),
            data_word(30),
            CD2_IDLE_WORD,
        ],
    )[0]


class DecoderRegistryTests(unittest.TestCase):
    def test_default_registry_has_expected_decoders(self):
        registry = build_default_registry()
        self.assertIn("raw12", registry.names())
        self.assertIn("beacon-candidate", registry.names())

    def test_raw12_decoder_preserves_frame_words(self):
        registry = build_default_registry()
        frame = frame_13_bit_values(
            [CD2_IDLE_WORD, data_word(1), data_word(2), CD2_IDLE_WORD],
        )[0]

        decoded = registry.decode("raw12", frame)

        self.assertEqual(decoded["decoder"], "raw12")
        self.assertEqual(decoded["word_count"], 2)
        self.assertEqual(decoded["data_words"], [1, 2])
        self.assertEqual(decoded["data_words_hex"], ["0x001", "0x002"])
        self.assertEqual(decoded["extended_error_status"], 0)
        self.assertEqual(decoded["errors"], [])

    def test_beacon_candidate_decoder_extracts_known_fields(self):
        registry = build_default_registry()

        decoded = registry.decode("beacon-candidate", beacon_candidate_frame())

        self.assertEqual(decoded["decoder"], "beacon-candidate")
        self.assertEqual(decoded["status"], "provisional")
        self.assertEqual(decoded["input_basis"], "framed_12bit_cd2_words")
        self.assertEqual(decoded["range_nm"], 10.0)
        self.assertEqual(decoded["acp"], 1024)
        self.assertEqual(decoded["azimuth_degrees"], 90.0)
        self.assertEqual(decoded["mode_3_code"], 1234)
        self.assertEqual(decoded["altitude_feet"], 3000)

    def test_beacon_candidate_words_decoder_supports_ecg_envelope_words(self):
        decoded = decode_beacon_candidate_words(
            [1600, 160, 1024, 0, 0o1234, 0, 30],
            input_basis="ecg_envelope_16bit_words",
        )

        self.assertEqual(decoded["decoder"], "beacon-candidate")
        self.assertEqual(decoded["input_basis"], "ecg_envelope_16bit_words")
        self.assertEqual(decoded["range_nm"], 20.0)
        self.assertEqual(decoded["azimuth_degrees"], 90.0)
        self.assertEqual(decoded["mode_3_code"], 1234)
        self.assertEqual(decoded["altitude_feet"], 3000)

    def test_unknown_decoder_raises_clear_error(self):
        registry = build_default_registry()
        frame = frame_13_bit_values([CD2_IDLE_WORD, data_word(1), CD2_IDLE_WORD])[0]

        with self.assertRaisesRegex(ValueError, "unknown decoder"):
            registry.decode("missing", frame)


if __name__ == "__main__":
    unittest.main()

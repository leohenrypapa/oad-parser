"""Unit tests for CD2 protocol helpers."""

import unittest

from oad_parser.parsers.cd2 import (
    CD2_IDLE_WORD,
    EXTENDED_ERROR_EOM,
    EXTENDED_ERROR_PARITY,
    Cd2LinkConfig,
    calculate_parity_bit,
    decode_client_data_area_word,
    decode_wire_word,
    extract_12_data_bits_from_client_word,
    extract_spec_data_bits_from_client_word,
    frame_13_bit_values,
    frame_byte_stream,
    is_idle_word,
    pack_13_bit_words_to_bytes,
    parity_is_valid,
)


def data_word(data_bits: int, parity_mode: str = "odd") -> int:
    return (data_bits << 1) | calculate_parity_bit(data_bits, parity_mode)


class Cd2Tests(unittest.TestCase):
    def test_idle_word(self):
        self.assertTrue(is_idle_word(CD2_IDLE_WORD))
        self.assertFalse(is_idle_word(0))

    def test_extract_data_bits_with_parity_present(self):
        word = 0b0000111111111000
        self.assertEqual(extract_12_data_bits_from_client_word(word, parity_present=True), 0x1FF)

    def test_extract_data_bits_without_parity_present(self):
        word = 0b0000111111110000
        self.assertEqual(extract_12_data_bits_from_client_word(word, parity_present=False), 0x0FF)

    def test_spec_client_word_extraction_with_parity_present(self):
        data_bits = 0xABC
        parity = calculate_parity_bit(data_bits, "odd")
        word = (data_bits << 1) | parity
        decoded = decode_client_data_area_word(word, config=Cd2LinkConfig())
        self.assertEqual(extract_spec_data_bits_from_client_word(word, parity_present=True), data_bits)
        self.assertEqual(decoded.data_bits, data_bits)
        self.assertEqual(decoded.parity_bit, parity)
        self.assertTrue(decoded.parity_valid)

    def test_spec_client_word_extraction_without_parity_present(self):
        data_bits = 0x321
        decoded = decode_client_data_area_word(
            data_bits,
            config=Cd2LinkConfig(add_remove_parity=True),
        )
        self.assertEqual(extract_spec_data_bits_from_client_word(data_bits, parity_present=False), data_bits)
        self.assertEqual(decoded.data_bits, data_bits)
        self.assertIsNone(decoded.parity_bit)
        self.assertIsNone(decoded.parity_valid)

    def test_parity_modes(self):
        self.assertEqual(calculate_parity_bit(0b000000000000, "odd"), 1)
        self.assertEqual(calculate_parity_bit(0b000000000000, "even"), 0)
        self.assertTrue(parity_is_valid(0b000000000001, 0, "odd"))
        self.assertTrue(parity_is_valid(0b000000000001, 1, "even"))

    def test_decode_wire_word(self):
        raw = data_word(0x155)
        decoded = decode_wire_word(raw)
        self.assertEqual(decoded.raw, raw)
        self.assertEqual(decoded.data_bits, 0x155)
        self.assertFalse(decoded.is_idle)
        self.assertTrue(decoded.parity_valid)

    def test_frame_13_bit_values_uses_idle_sync_and_eom(self):
        values = [CD2_IDLE_WORD, data_word(1), data_word(2), CD2_IDLE_WORD]
        frames = frame_13_bit_values(values)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].data_words, (1, 2))
        self.assertEqual(frames[0].start_word_index, 1)
        self.assertEqual(frames[0].end_word_index, 2)

    def test_frame_13_bit_values_ignores_unsynchronized_data(self):
        values = [data_word(99), CD2_IDLE_WORD, data_word(1), CD2_IDLE_WORD]
        frames = frame_13_bit_values(values)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].data_words, (1,))

    def test_frame_13_bit_values_reports_parity_error(self):
        good = data_word(0x111)
        bad = good ^ 0x1
        frames = frame_13_bit_values([CD2_IDLE_WORD, bad, CD2_IDLE_WORD])
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].extended_error_status & EXTENDED_ERROR_PARITY)
        self.assertTrue(frames[0].has_errors)

    def test_frame_13_bit_values_reports_eom_error(self):
        config = Cd2LinkConfig(receive_frame_size_words=1)
        frames = frame_13_bit_values(
            [CD2_IDLE_WORD, data_word(1), data_word(2), CD2_IDLE_WORD],
            config=config,
        )
        self.assertEqual(len(frames), 1)
        self.assertTrue(frames[0].extended_error_status & EXTENDED_ERROR_EOM)
        self.assertTrue(frames[0].has_errors)

    def test_frame_byte_stream_round_trip(self):
        values = [CD2_IDLE_WORD, data_word(0x010), data_word(0x020), CD2_IDLE_WORD]
        data = pack_13_bit_words_to_bytes(values)
        frames = frame_byte_stream(data)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].data_words, (0x010, 0x020))

    def test_data_inversion(self):
        raw = data_word(0x222)
        inverted = raw ^ ((1 << 13) - 1)
        decoded = decode_wire_word(inverted, config=Cd2LinkConfig(data_inversion=True))
        self.assertEqual(decoded.data_bits, 0x222)


if __name__ == "__main__":
    unittest.main()

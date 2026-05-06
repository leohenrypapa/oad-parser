"""Tests for source-specific protocol constant modules."""

import unittest

from oad_parser.decoders import provisional_beacon_constants as beacon
from oad_parser.parsers import ecg
from oad_parser.protocols import cd2_link_options, cd2_spec


class ProtocolConstantTests(unittest.TestCase):
    def test_cd2_spec_manual_derived_values(self):
        self.assertEqual(cd2_spec.CD2_MANUAL_ID, "DC-900-1607F")
        self.assertEqual(cd2_spec.CD2_WORD_BITS, 13)
        self.assertEqual(cd2_spec.CD2_DATA_BITS, 12)
        self.assertEqual(cd2_spec.CD2_IDLE_WORD, 0b0001111111111)
        self.assertEqual(cd2_spec.CD2_EXTENDED_ERROR_PARITY_SHIFT, 0)
        self.assertEqual(cd2_spec.CD2_EXTENDED_ERROR_EOM_SHIFT, 5)
        self.assertEqual(cd2_spec.CD2_PROTOCOL_SELECTION_CODE, 11)
        self.assertEqual(cd2_spec.CD2_DEFAULT_RECEIVE_FRAME_SIZE_WORDS, 32)

    def test_cd2_spec_provenance_covers_runtime_constants(self):
        for name in (
            "CD2_WORD_BITS",
            "CD2_DATA_BITS",
            "CD2_IDLE_WORD",
            "CD2_EXTENDED_ERROR_PARITY_SHIFT",
            "CD2_EXTENDED_ERROR_EOM_SHIFT",
            "CD2_PROTOCOL_SELECTION_CODE",
            "CD2_ADD_REMOVE_PARITY_OPTION_NUMBER",
            "CD2_RECEIVE_FRAME_SIZE_OPTION_NUMBER",
        ):
            with self.subTest(name=name):
                reference = cd2_spec.CD2_SPEC_PROVENANCE[name]
                self.assertEqual(reference.manual_id, "DC-900-1607F")
                self.assertTrue(reference.section)
                self.assertGreater(reference.page, 0)

    def test_cd2_link_option_metadata_matches_manual_values(self):
        self.assertEqual(cd2_link_options.CD2_LINK_OPTIONS_MANUAL_ID, "DC-900-1607F")
        self.assertEqual(cd2_link_options.get_cd2_link_option(-1).default, None)
        self.assertEqual(cd2_link_options.get_cd2_link_option(-1).allowed_values, (11,))
        self.assertEqual(cd2_link_options.get_cd2_link_option(1).default, 9600)
        self.assertEqual(cd2_link_options.get_cd2_link_option(2).default, 2)
        self.assertEqual(cd2_link_options.get_cd2_link_option(3).default, 2)
        self.assertEqual(cd2_link_options.get_cd2_link_option(22).default, 2)
        self.assertEqual(cd2_link_options.get_cd2_link_option(26).default, 32)
        self.assertEqual(cd2_link_options.get_cd2_link_option(36).default, 1000)

    def test_cd2_link_option_lookup_rejects_unknown_option(self):
        with self.assertRaises(ValueError):
            cd2_link_options.get_cd2_link_option(999)

    def test_cd2_link_statistics_word_indexes_are_manual_derived(self):
        self.assertEqual(cd2_spec.CD2_LINK_STATISTICS_WORDS["messages_received"], 3)
        self.assertEqual(cd2_spec.CD2_LINK_STATISTICS_WORDS["parity_errors"], 4)
        self.assertEqual(cd2_spec.CD2_LINK_STATISTICS_WORDS["eom_errors"], 13)
        self.assertEqual(cd2_spec.CD2_LINK_STATISTICS_WORDS["messages_transmitted"], 17)

    def test_provisional_beacon_constants_are_separate_from_cd2_spec(self):
        self.assertEqual(beacon.WORD_DATA_MASK, 0x0FFF)
        self.assertEqual(beacon.RANGE_WORD_INDEX, 1)
        self.assertEqual(beacon.MODE_3_WORD_INDEX, 4)
        self.assertEqual(beacon.ALTITUDE_WORD_INDEX, 6)
        self.assertEqual(beacon.BEACON_CANDIDATE_RANGE_NM_SCALE, 0.125)
        self.assertEqual(beacon.LEGACY_RANGE_NM_DIVISOR, 16.0)
        self.assertEqual(beacon.LEGACY_RANGE_WORD_MASK, 0x0FFE)
        self.assertEqual(beacon.LEGACY_ALTITUDE_WORD_MASK, 0x07FF)

    def test_ecg_legacy_projection_uses_shared_provisional_constants(self):
        self.assertEqual(ecg.RANGE_WORD_INDEX, beacon.RANGE_WORD_INDEX)
        self.assertEqual(ecg.RANGE_WORD_MASK, beacon.LEGACY_RANGE_WORD_MASK)
        self.assertEqual(ecg.RANGE_WORD_SHIFT, beacon.LEGACY_RANGE_WORD_SHIFT)
        self.assertEqual(ecg.RANGE_NM_SCALE, beacon.LEGACY_RANGE_NM_SCALE)
        self.assertEqual(ecg.ACP_WORD_INDEX, beacon.ACP_WORD_INDEX)
        self.assertEqual(ecg.ACP_WORD_MASK, beacon.WORD_DATA_MASK)
        self.assertEqual(ecg.MODE_3_WORD_INDEX, beacon.MODE_3_WORD_INDEX)
        self.assertEqual(ecg.MODE_3_WORD_MASK, beacon.WORD_DATA_MASK)
        self.assertEqual(ecg.ALTITUDE_WORD_INDEX, beacon.ALTITUDE_WORD_INDEX)
        self.assertEqual(ecg.ALTITUDE_WORD_MASK, beacon.LEGACY_ALTITUDE_WORD_MASK)
        self.assertEqual(ecg.ALTITUDE_FEET_SCALE, beacon.ALTITUDE_FEET_PER_COUNT)
        self.assertEqual(ecg.ALTITUDE_SIGN_MASK, beacon.ALTITUDE_SIGN_MASK)


if __name__ == "__main__":
    unittest.main()

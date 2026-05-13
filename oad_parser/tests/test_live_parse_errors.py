"""Tests for live ECG envelope parse-error behavior."""

import unittest

from oad_parser.parsers.ecg import (
    ECG_ERROR_LENGTH_MISMATCH,
    ECG_ERROR_MESSAGE_BLOCK_TRUNCATED,
    ECG_ERROR_SHORT_PAYLOAD,
    ECG_WARNING_UNKNOWN_MESSAGE_CODE,
    extract_ecg_messages,
    extract_ecg_messages_with_errors,
    looks_like_ecg_candidate_payload,
)
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


class LiveEcgParseErrorTests(unittest.TestCase):
    def test_valid_payload_matches_existing_extract_behavior(self):
        payload = build_ecg_payload()

        existing = extract_ecg_messages(payload, skip_headers=False)
        result = extract_ecg_messages_with_errors(payload, skip_headers=False)

        self.assertFalse(result.is_error)
        self.assertTrue(result.is_ecg_candidate)
        self.assertEqual(len(result.envelopes), len(existing))
        self.assertEqual(result.envelopes[0].site_id, existing[0].site_id)
        self.assertEqual(result.warnings, ())

    def test_valid_udp_frame_preserves_packet_metadata(self):
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)

        result = extract_ecg_messages_with_errors(frame)

        self.assertFalse(result.is_error)
        self.assertEqual(len(result.envelopes), 1)
        self.assertEqual(result.packet_metadata["source_ip"], "10.1.2.3")
        self.assertEqual(result.packet_metadata["destination_ip"], "10.4.5.6")
        self.assertEqual(result.packet_metadata["source_port"], 1000)
        self.assertEqual(result.packet_metadata["destination_port"], 2000)

    def test_non_ecg_payload_is_not_error(self):
        result = extract_ecg_messages_with_errors(b"not an ecg payload", skip_headers=False)

        self.assertFalse(result.is_error)
        self.assertFalse(result.is_ecg_candidate)
        self.assertEqual(result.envelopes, [])

    def test_ecg_short_payload_returns_structured_error(self):
        payload = bytearray(10)
        payload[0:2] = (20).to_bytes(2, "big")
        payload[4:7] = b"ZAB"
        payload[8] = 1

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertTrue(looks_like_ecg_candidate_payload(bytes(payload)))
        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_SHORT_PAYLOAD)
        self.assertEqual(result.error.parser_stage, "ecg_envelope")
        self.assertEqual(result.envelopes, [])

    def test_ecg_length_mismatch_returns_structured_error(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_LENGTH_MISMATCH)
        self.assertEqual(result.error.parser_stage, "ecg_envelope")
        self.assertIn("declared=999", result.error.message)

    def test_ecg_message_block_truncated_returns_structured_error(self):
        payload = bytearray(build_ecg_payload())
        payload[16:18] = (250).to_bytes(2, "big")
        payload[0:2] = (len(payload) - 16).to_bytes(2, "big")

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_MESSAGE_BLOCK_TRUNCATED)
        self.assertEqual(result.error.parser_stage, "ecg_message_block")

    def test_minimum_candidate_with_incomplete_block_header_is_error(self):
        payload = bytearray(20)
        payload[0:2] = (len(payload) - 16).to_bytes(2, "big")
        payload[4:7] = b"ZAB"
        payload[8] = 1

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertTrue(looks_like_ecg_candidate_payload(bytes(payload)))
        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_MESSAGE_BLOCK_TRUNCATED)
        self.assertEqual(result.error.parser_stage, "ecg_message_block")
        self.assertIn("header", result.error.message)

    def test_second_message_block_payload_truncation_is_error(self):
        payload = bytearray(build_ecg_payload())
        second_header = bytearray(16)
        second_header[0:2] = (10).to_bytes(2, "big")
        second_header[4:8] = b"ST2\x00"
        second_header[8] = 1
        payload.extend(second_header)
        payload[0:2] = (len(payload) - 16).to_bytes(2, "big")

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_MESSAGE_BLOCK_TRUNCATED)
        self.assertEqual(result.error.parser_stage, "ecg_message_block")
        self.assertIn("payload", result.error.message)

    def test_malformed_udp_candidate_preserves_packet_metadata(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")
        frame = build_ethernet_ipv4_udp_frame(bytes(payload))

        result = extract_ecg_messages_with_errors(frame)

        self.assertTrue(result.is_error)
        self.assertEqual(result.error.code, ECG_ERROR_LENGTH_MISMATCH)
        self.assertEqual(result.packet_metadata["source_ip"], "10.1.2.3")
        self.assertEqual(result.packet_metadata["destination_ip"], "10.4.5.6")
        self.assertEqual(result.packet_metadata["source_port"], 1000)
        self.assertEqual(result.packet_metadata["destination_port"], 2000)
        self.assertIn("ip_total_length", result.packet_metadata)

    def test_unknown_message_code_is_warning_not_parse_error(self):
        payload = bytearray(build_ecg_payload())
        payload[24] = 99

        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        self.assertFalse(result.is_error)
        self.assertEqual(len(result.envelopes), 1)
        self.assertEqual(result.envelopes[0].message_name, "none")
        self.assertEqual(len(result.warnings), 1)
        self.assertEqual(result.warnings[0].code, ECG_WARNING_UNKNOWN_MESSAGE_CODE)


if __name__ == "__main__":
    unittest.main()

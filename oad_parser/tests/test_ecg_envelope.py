"""Tests for ECG message-envelope extraction."""

import unittest

from oad_parser.parsers.ecg import extract_ecg_messages
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


class EcgEnvelopeTests(unittest.TestCase):
    def test_extract_raw_ecg_message_envelope(self):
        envelopes = extract_ecg_messages(build_ecg_payload(), skip_headers=False)

        self.assertEqual(len(envelopes), 1)
        envelope = envelopes[0]

        self.assertEqual(envelope.artcc, "ZAB")
        self.assertEqual(envelope.site_id, "ST1")
        self.assertEqual(envelope.ecg_message, 1)
        self.assertEqual(envelope.message_code, 1)
        self.assertEqual(envelope.message_name, "cd-2")
        self.assertEqual(envelope.message_type, "beacon")
        self.assertEqual(envelope.sequence, 7)
        self.assertEqual(envelope.channel, 2)
        self.assertEqual(envelope.router_timestamp, 12.34)
        self.assertEqual(envelope.radar_timestamp, 5.678)
        self.assertEqual(envelope.message_data_length, 14)
        self.assertEqual(envelope.data_words[1], 160)
        self.assertEqual(envelope.data_words[2], 1024)
        self.assertEqual(envelope.data_words[4], 0o1234)
        self.assertEqual(envelope.data_words[6], 30)
        self.assertTrue(envelope.modec_valid)

    def test_extract_ethernet_udp_ecg_message_envelope(self):
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)

        envelopes = extract_ecg_messages(frame)

        self.assertEqual(len(envelopes), 1)
        envelope = envelopes[0]
        self.assertEqual(envelope.source_ip, "10.1.2.3")
        self.assertEqual(envelope.destination_ip, "10.4.5.6")
        self.assertEqual(envelope.source_port, 1000)
        self.assertEqual(envelope.destination_port, 2000)

    def test_envelope_to_dict_is_json_ready(self):
        envelope = extract_ecg_messages(build_ecg_payload(), skip_headers=False)[0]
        data = envelope.to_dict()

        self.assertEqual(data["artcc"], "ZAB")
        self.assertEqual(data["site_id"], "ST1")
        self.assertEqual(data["data_words_hex"][1], "0x00a0")
        self.assertEqual(data["message_type"], "beacon")


if __name__ == "__main__":
    unittest.main()

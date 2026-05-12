"""Unit tests for legacy ECG live transformer."""

from datetime import datetime, timezone
import hashlib
import json
import unittest

from oad_parser.parsers.ecg import (
    ECG_ERROR_LENGTH_MISMATCH,
    extract_ecg_messages_with_errors,
)
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame
from oad_parser.transformers.legacy_ecg import (
    legacy_error_fields,
    legacy_fields_for_envelope,
    transform_envelope_to_legacy_record,
    transform_parse_error_to_legacy_record,
    transform_parse_result_to_legacy_records,
)


FIXED_TIME = datetime(2026, 5, 12, 13, 0, 0, tzinfo=timezone.utc)


class LegacyEcgTransformerTests(unittest.TestCase):
    def test_valid_envelope_record_uses_legacy_fields_and_payload_hash(self):
        payload = build_ecg_payload()
        result = extract_ecg_messages_with_errors(payload, skip_headers=False)
        envelope = result.envelopes[0]

        record = transform_envelope_to_legacy_record(
            envelope=envelope,
            timestamp_utc=FIXED_TIME,
            interface="eno1",
            ecg_payload=payload,
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:00Z")
        self.assertEqual(record["record_type"], "ecg_event")
        self.assertEqual(record["interface"], "eno1")
        self.assertEqual(record["artcc"], "ZAB")
        self.assertEqual(record["site_id"], "ST1")
        self.assertEqual(record["ecg_message"], 1)
        self.assertEqual(record["message_code"], 1)
        self.assertEqual(record["message"], "cd-2")
        self.assertEqual(record["message_type"], "beacon")
        self.assertEqual(record["sequence"], 7)
        self.assertEqual(record["channel"], 2)
        self.assertEqual(record["router_timestamp"], 12.34)
        self.assertEqual(record["radar_timestamp"], 5.678)
        self.assertEqual(record["message_data_length"], 14)
        self.assertTrue(record["modec_valid"])
        self.assertEqual(record["sha256_ecg_payload"], hashlib.sha256(payload).hexdigest())
        self.assertIsNone(record["range_nm"])
        self.assertIsNone(record["azimuth_degrees"])
        self.assertIsNone(record["altitude_feet"])
        self.assertIsNone(record["mode_3_code"])
        self.assertIsNone(record["acp"])
        self.assertIsNone(record["alert"])
        self.assertIsNone(record["alert_details"])
        self.assertNotIn("data_words_hex", record)
        self.assertNotIn("message_payload", record)
        json.dumps(record, sort_keys=True)

    def test_valid_udp_result_preserves_packet_metadata(self):
        payload = build_ecg_payload()
        frame = build_ethernet_ipv4_udp_frame(payload)
        result = extract_ecg_messages_with_errors(frame)

        records = transform_parse_result_to_legacy_records(
            result=result,
            timestamp_utc=FIXED_TIME,
            interface="eno2",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["interface"], "eno2")
        self.assertEqual(record["source_ip"], "10.1.2.3")
        self.assertEqual(record["destination_ip"], "10.4.5.6")
        self.assertEqual(record["source_port"], 1000)
        self.assertEqual(record["destination_port"], 2000)
        self.assertEqual(record["sha256_ecg_payload"], hashlib.sha256(payload).hexdigest())

    def test_error_record_includes_error_fields_and_payload_hash(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")
        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        record = transform_parse_error_to_legacy_record(
            result=result,
            timestamp_utc=FIXED_TIME,
            interface="eno3",
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:00Z")
        self.assertEqual(record["record_type"], "ecg_parse_error")
        self.assertEqual(record["interface"], "eno3")
        self.assertEqual(record["sha256_ecg_payload"], hashlib.sha256(bytes(payload)).hexdigest())
        self.assertEqual(record["error_code"], ECG_ERROR_LENGTH_MISMATCH)
        self.assertIn("declared=999", record["error_message"])
        self.assertEqual(record["parser_stage"], "ecg_envelope")
        self.assertIsNone(record["artcc"])
        self.assertEqual(record["site_id"], "unknown")
        self.assertEqual(record["message_type"], "unknown")
        self.assertIsNone(record["range_nm"])
        self.assertIsNone(record["azimuth_degrees"])
        self.assertIsNone(record["altitude_feet"])
        self.assertIsNone(record["alert"])
        self.assertIsNone(record["alert_details"])
        json.dumps(record, sort_keys=True)

    def test_error_result_through_batch_transformer_returns_one_error_record(self):
        payload = bytearray(build_ecg_payload())
        payload[0:2] = (999).to_bytes(2, "big")
        result = extract_ecg_messages_with_errors(bytes(payload), skip_headers=False)

        records = transform_parse_result_to_legacy_records(
            result=result,
            timestamp_utc=FIXED_TIME,
            interface="eno4",
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["record_type"], "ecg_parse_error")
        self.assertEqual(records[0]["interface"], "eno4")

    def test_non_ecg_result_returns_no_records(self):
        result = extract_ecg_messages_with_errors(b"not an ecg payload", skip_headers=False)

        records = transform_parse_result_to_legacy_records(
            result=result,
            timestamp_utc=FIXED_TIME,
            interface="eno1",
        )

        self.assertEqual(records, [])

    def test_known_unparsed_fields_are_null(self):
        payload = build_ecg_payload()
        envelope = extract_ecg_messages_with_errors(payload, skip_headers=False).envelopes[0]

        fields = legacy_fields_for_envelope(envelope, payload)

        expected_nulls = [
            "range_nm",
            "azimuth_degrees",
            "altitude_feet",
            "mode_3_code",
            "acp",
            "alert",
            "alert_details",
        ]
        for name in expected_nulls:
            with self.subTest(name=name):
                self.assertIsNone(fields[name])

    def test_unknown_is_limited_to_categorical_compatibility_fields_for_error(self):
        fields = legacy_error_fields()

        self.assertEqual(fields["site_id"], "unknown")
        self.assertEqual(fields["message_type"], "unknown")
        self.assertIsNone(fields["artcc"])
        self.assertIsNone(fields["message_code"])
        self.assertIsNone(fields["sequence"])
        self.assertIsNone(fields["radar_timestamp"])


if __name__ == "__main__":
    unittest.main()

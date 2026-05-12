"""Unit tests for live ECG parser record models."""

from datetime import datetime, timezone
import json
import unittest

from oad_parser.live.records import (
    EcgAuditRecord,
    EcgOutputRecord,
    EcgParseErrorRecord,
    EcgStatusSnapshot,
    LiveCaptureFrame,
    StoragePolicy,
    format_utc_timestamp,
    sha256_hex,
)


class LiveRecordTests(unittest.TestCase):
    def test_format_utc_timestamp_uses_z_suffix(self):
        stamp = datetime(2026, 5, 12, 13, 0, 0, 123456, tzinfo=timezone.utc)
        self.assertEqual(format_utc_timestamp(stamp), "2026-05-12T13:00:00.123456Z")

    def test_format_utc_timestamp_treats_naive_as_utc(self):
        stamp = datetime(2026, 5, 12, 13, 0, 0)
        self.assertEqual(format_utc_timestamp(stamp), "2026-05-12T13:00:00Z")

    def test_sha256_hex_hashes_payload_bytes(self):
        self.assertEqual(
            sha256_hex(b"ecg-payload"),
            "9364c99ce489baa99472afaac63f1cbaf344a4712024a242718375cfcf54be53",
        )

    def test_live_capture_frame_defaults_length_and_serializes_metadata(self):
        frame = LiveCaptureFrame(
            frame_bytes=b"abc",
            interface="eno1",
            capture_time_utc=datetime(2026, 5, 12, 13, 0, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(frame.frame_length, 3)
        self.assertEqual(
            frame.to_dict(),
            {
                "interface": "eno1",
                "capture_time_utc": "2026-05-12T13:00:00Z",
                "frame_length": 3,
            },
        )

    def test_ecg_output_record_serializes_legacy_fields(self):
        record = EcgOutputRecord(
            timestamp_utc=datetime(2026, 5, 12, 13, 0, 0, tzinfo=timezone.utc),
            interface="eno1",
            fields={
                "site_id": "unknown",
                "range_nm": None,
                "sha256_ecg_payload": "abc123",
                "alert": None,
                "alert_details": None,
            },
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:00Z")
        self.assertEqual(record["record_type"], "ecg_event")
        self.assertEqual(record["interface"], "eno1")
        self.assertEqual(record["site_id"], "unknown")
        self.assertIsNone(record["range_nm"])
        self.assertEqual(record["sha256_ecg_payload"], "abc123")
        json.dumps(record, sort_keys=True)

    def test_ecg_parse_error_record_serializes_required_fields(self):
        record = EcgParseErrorRecord(
            timestamp_utc=datetime(2026, 5, 12, 13, 0, 1, tzinfo=timezone.utc),
            interface="eno2",
            sha256_ecg_payload="abc123",
            error_code="ecg_short_payload",
            error_message="payload shorter than minimum ECG envelope",
            parser_stage="ecg_envelope",
            packet_metadata={"source_ip": "10.0.0.1"},
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:01Z")
        self.assertEqual(record["record_type"], "ecg_parse_error")
        self.assertEqual(record["interface"], "eno2")
        self.assertEqual(record["sha256_ecg_payload"], "abc123")
        self.assertEqual(record["error_code"], "ecg_short_payload")
        self.assertEqual(record["parser_stage"], "ecg_envelope")
        self.assertEqual(record["source_ip"], "10.0.0.1")
        json.dumps(record, sort_keys=True)

    def test_audit_record_serializes_event_type_and_fields(self):
        record = EcgAuditRecord(
            timestamp_utc=datetime(2026, 5, 12, 13, 0, 2, tzinfo=timezone.utc),
            event_type="metrics",
            interface="eno1",
            fields={"packets_received": 10},
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:02Z")
        self.assertEqual(record["record_type"], "ecg_audit")
        self.assertEqual(record["event_type"], "metrics")
        self.assertEqual(record["packets_received"], 10)
        json.dumps(record, sort_keys=True)

    def test_status_snapshot_serializes_counters(self):
        record = EcgStatusSnapshot(
            timestamp_utc=datetime(2026, 5, 12, 13, 0, 3, tzinfo=timezone.utc),
            interface="eno1",
            counters={"packets_received": 10},
            active_file="/nsm/ecg/ecg-current.json",
            disk_percent=41.2,
        ).to_dict()

        self.assertEqual(record["@timestamp"], "2026-05-12T13:00:03Z")
        self.assertEqual(record["record_type"], "ecg_status")
        self.assertEqual(record["counters"]["packets_received"], 10)
        self.assertEqual(record["active_file"], "/nsm/ecg/ecg-current.json")
        self.assertEqual(record["disk_percent"], 41.2)
        json.dumps(record, sort_keys=True)

    def test_storage_policy_defaults_match_live_design(self):
        policy = StoragePolicy()

        self.assertEqual(policy.output_dir, "/nsm/ecg")
        self.assertEqual(policy.active_output_file, "/nsm/ecg/ecg-current.json")
        self.assertEqual(policy.audit_file, "/nsm/ecg/ecg-audit.jsonl")
        self.assertEqual(policy.status_file, "/nsm/ecg/ecg-status.json")
        self.assertEqual(policy.rotate_seconds, 900)
        self.assertEqual(policy.rotate_max_bytes, 536870912)
        self.assertEqual(policy.prune_after_seconds, 43200)
        self.assertEqual(policy.high_water_percent, 75)
        self.assertEqual(policy.critical_percent, 95)
        self.assertTrue(policy.block_when_full)
        self.assertFalse(policy.compress_archives)
        json.dumps(policy.to_dict(), sort_keys=True)


if __name__ == "__main__":
    unittest.main()

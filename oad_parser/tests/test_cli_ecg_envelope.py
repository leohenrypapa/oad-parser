"""CLI tests for ECG message-envelope extraction."""

import argparse
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from oad_parser.cli import run_extract_ecg_messages
from oad_parser.tests.test_ecg import build_ecg_payload, build_ethernet_ipv4_udp_frame


def write_one_packet_pcap(path: Path, payload: bytes) -> None:
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    packet_header = struct.pack("<IIII", 1, 2, len(payload), len(payload))
    path.write_bytes(global_header + packet_header + payload)


class EcgEnvelopeCliTests(unittest.TestCase):
    def test_extract_ecg_messages_from_raw_payload_json_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(path),
                config=None,
                raw_payload=True,
                jsonl=False,
                decoder=None,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        records = json.loads(stdout.getvalue())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["artcc"], "ZAB")
        self.assertEqual(records[0]["site_id"], "ST1")
        self.assertEqual(records[0]["message_name"], "cd-2")
        self.assertEqual(records[0]["message_type"], "beacon")
        self.assertEqual(records[0]["data_words_hex"][1], "0x00a0")

    def test_extract_ecg_messages_from_raw_payload_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(path),
                config=None,
                raw_payload=True,
                jsonl=True,
                decoder=None,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["message_type"], "beacon")
        self.assertEqual(record["data_words_hex"][2], "0x0400")

    def test_extract_ecg_messages_with_beacon_candidate_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(path),
                config=None,
                raw_payload=True,
                jsonl=False,
                decoder="beacon-candidate",
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        records = json.loads(stdout.getvalue())
        decoded = records[0]["decoded"]
        self.assertEqual(decoded["decoder"], "beacon-candidate")
        self.assertEqual(decoded["status"], "provisional")
        self.assertEqual(decoded["range_nm"], 20.0)
        self.assertEqual(decoded["azimuth_degrees"], 90.0)
        self.assertEqual(decoded["mode_3_code"], 1234)
        self.assertEqual(decoded["altitude_feet"], 3000)

    def test_extract_ecg_messages_from_pcap_with_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.pcap"
            frame = build_ethernet_ipv4_udp_frame(build_ecg_payload())
            write_one_packet_pcap(path, frame)
            args = argparse.Namespace(
                input=str(path),
                config=None,
                raw_payload=False,
                jsonl=False,
                decoder="beacon-candidate",
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        records = json.loads(stdout.getvalue())
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["source_ip"], "10.1.2.3")
        self.assertEqual(record["destination_ip"], "10.4.5.6")
        self.assertEqual(record["source_port"], 1000)
        self.assertEqual(record["destination_port"], 2000)
        self.assertEqual(record["packet_timestamp"], "1970-01-01T00:00:01.000002+00:00")
        self.assertEqual(record["decoded"]["decoder"], "beacon-candidate")
        self.assertEqual(record["decoded"]["range_nm"], 20.0)

    def test_extract_ecg_messages_uses_configured_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload_path = Path(tmp) / "payload.bin"
            config_path = Path(tmp) / "profile.ini"
            payload_path.write_bytes(build_ecg_payload())
            config_path.write_text("[cd2]\ndecoder = raw12\n", encoding="utf-8")
            args = argparse.Namespace(
                input=str(payload_path),
                config=str(config_path),
                raw_payload=True,
                jsonl=False,
                decoder=None,
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        records = json.loads(stdout.getvalue())
        self.assertEqual(records[0]["decoded"]["decoder"], "raw12")
        self.assertEqual(records[0]["decoded"]["word_count"], 7)

    def test_extract_ecg_messages_cli_decoder_overrides_config_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload_path = Path(tmp) / "payload.bin"
            config_path = Path(tmp) / "profile.ini"
            payload_path.write_bytes(build_ecg_payload())
            config_path.write_text("[cd2]\ndecoder = raw12\n", encoding="utf-8")
            args = argparse.Namespace(
                input=str(payload_path),
                config=str(config_path),
                raw_payload=True,
                jsonl=False,
                decoder="beacon-candidate",
                output=None,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

        self.assertEqual(rc, 0)
        records = json.loads(stdout.getvalue())
        self.assertEqual(records[0]["decoded"]["decoder"], "beacon-candidate")
        self.assertEqual(records[0]["decoded"]["range_nm"], 20.0)

    def test_extract_ecg_messages_writes_json_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "payload.bin"
            output_path = Path(tmp) / "envelopes.json"
            input_path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(input_path),
                config=None,
                raw_payload=True,
                jsonl=False,
                decoder="raw12",
                output=str(output_path),
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

            self.assertEqual(rc, 0)
            self.assertIn("wrote 1 ECG message envelopes", stdout.getvalue())
            records = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(records[0]["message_type"], "beacon")
        self.assertEqual(records[0]["decoded"]["decoder"], "raw12")

    def test_extract_ecg_messages_writes_jsonl_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "payload.bin"
            output_path = Path(tmp) / "envelopes.jsonl"
            input_path.write_bytes(build_ecg_payload())
            args = argparse.Namespace(
                input=str(input_path),
                config=None,
                raw_payload=True,
                jsonl=True,
                decoder="beacon-candidate",
                output=str(output_path),
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = run_extract_ecg_messages(args)

            self.assertEqual(rc, 0)
            lines = [line for line in output_path.read_text(encoding="utf-8").splitlines() if line]
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])

        self.assertEqual(record["decoded"]["decoder"], "beacon-candidate")
        self.assertEqual(record["decoded"]["range_nm"], 20.0)


if __name__ == "__main__":
    unittest.main()

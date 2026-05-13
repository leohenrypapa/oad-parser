"""Static tests for Filebeat and Elastic Agent handoff documentation."""

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "ops" / "filebeat-elastic-agent-handoff.md"


class FilebeatElasticHandoffDocTests(unittest.TestCase):
    def test_handoff_doc_exists(self):
        self.assertTrue(DOC.exists(), DOC)

    def test_handoff_doc_states_version_and_mvp_files(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("Elastic Agent or Filebeat 8.17.3", text)
        self.assertIn("/nsm/ecg/ecg-current.json", text)
        self.assertIn("/nsm/ecg/ecg-audit.jsonl", text)
        self.assertIn("/nsm/ecg/ecg-status.json", text)
        self.assertIn("MVP central collection uses append-style files only", text)
        self.assertIn("Do not centrally collect this local-only file for MVP", text)

    def test_handoff_doc_explains_jsonl_suffix_behavior(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("keeps the `.json` suffix", text)
        self.assertIn("content is JSON Lines", text)
        self.assertIn("Each line is one complete JSON object", text)
        self.assertIn("ecg-current-YYYYmmddTHHMMSSZ.jsonl", text)
        self.assertIn("ecg-current-YYYYmmddTHHMMSSZ-0001.jsonl", text)

    def test_handoff_doc_defines_ownership_boundary_and_sanitization(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("Parser-owned behavior", text)
        self.assertIn("Filebeat or Elastic Agent owned behavior", text)
        self.assertIn("Logstash or SIEM owned behavior", text)
        self.assertIn("Do not commit any of the following", text)
        self.assertIn("Elastic enrollment tokens", text)
        self.assertIn("Operational packet captures", text)
        self.assertIn("Raw operational ECG payloads", text)

    def test_handoff_doc_excludes_site_specific_values(self):
        text = DOC.read_text(encoding="utf-8").lower()

        forbidden = [
            "api_key:",
            "password:",
            "secret:",
            "hosts: [",
            "ssl.certificate",
            "ssl.key",
        ]
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()

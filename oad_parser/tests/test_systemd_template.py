"""Static tests for the systemd live parser template and operator doc."""

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "deploy" / "systemd" / "ecg-parser@.service"
DOC = REPO_ROOT / "docs" / "ops" / "systemd-live-parser.md"


class SystemdTemplateTests(unittest.TestCase):
    def test_template_exists(self):
        self.assertTrue(TEMPLATE.exists(), TEMPLATE)

    def test_template_uses_instance_interface_and_live_command(self):
        text = TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("[Unit]", text)
        self.assertIn("[Service]", text)
        self.assertIn("[Install]", text)
        self.assertIn("Description=OAD ECG live parser on interface %i", text)
        self.assertIn("ExecStart=/usr/bin/python3.9 -m oad_parser live", text)
        self.assertIn("--config /etc/oad-parser/ecg_conf.ini", text)
        self.assertIn("--interface %i", text)
        self.assertNotIn("--max-frames", text)

    def test_template_runtime_user_and_restart_limits_are_explicit(self):
        text = TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("User=root", text)
        self.assertIn("Group=root", text)
        self.assertIn("Restart=on-failure", text)
        self.assertIn("RestartSec=10s", text)
        self.assertIn("StartLimitIntervalSec=300", text)
        self.assertIn("StartLimitBurst=5", text)

    def test_operator_doc_exists_and_covers_core_commands(self):
        text = DOC.read_text(encoding="utf-8")

        self.assertIn("ecg-parser@.service", text)
        self.assertIn("ecg-parser@eno1.service", text)
        self.assertIn("sudo systemctl start ecg-parser@eno1.service", text)
        self.assertIn("sudo systemctl status ecg-parser@eno1.service --no-pager", text)
        self.assertIn("sudo journalctl -u ecg-parser@eno1.service", text)
        self.assertIn("Do not use `--max-frames` in the production systemd template.", text)
        self.assertIn("/nsm/ecg/ecg-current.json", text)


if __name__ == "__main__":
    unittest.main()

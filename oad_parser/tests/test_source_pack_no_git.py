import tempfile
import unittest
from pathlib import Path
from unittest import mock

from oad_parser.source_pack import iter_source_pack_files


class SourcePackNoGitTests(unittest.TestCase):
    def test_tracked_only_mode_keeps_safe_filters_when_git_binary_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "index").write_bytes(b"placeholder")
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            (root / "CODEOWNERS").write_text("* @placeholder\n", encoding="utf-8")
            (root / "demo.sh").write_text("echo excluded\n", encoding="utf-8")
            (root / "reports").mkdir()
            (root / "reports" / "result.json").write_text("{}\n", encoding="utf-8")
            (root / "capture.pcap").write_bytes(b"pcap")

            with mock.patch("oad_parser.source_pack.shutil.which", return_value=None):
                files = iter_source_pack_files(root)

        self.assertIn("README.md", files)
        self.assertIn("CODEOWNERS", files)
        self.assertNotIn("demo.sh", files)
        self.assertNotIn("reports/result.json", files)
        self.assertNotIn("capture.pcap", files)

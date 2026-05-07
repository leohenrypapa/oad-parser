"""Tests for source-pack generation."""

import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from oad_parser.source_pack import (
    create_source_pack,
    iter_source_pack_files,
    should_include_source_pack_path,
)


class SourcePackTests(unittest.TestCase):
    def test_should_include_source_pack_path(self):
        self.assertTrue(should_include_source_pack_path("oad_parser/cli.py"))
        self.assertTrue(should_include_source_pack_path("docs/design/notes.md"))
        self.assertTrue(should_include_source_pack_path("docs/TROUBLESHOOTING.md"))
        self.assertTrue(should_include_source_pack_path("config/example.ini"))
        self.assertTrue(should_include_source_pack_path("README.md"))
        self.assertTrue(should_include_source_pack_path(".gitignore"))
        self.assertTrue(should_include_source_pack_path("CODEOWNERS"))
        self.assertTrue(should_include_source_pack_path("standards-manifest.json"))

        self.assertFalse(should_include_source_pack_path("demo.sh"))
        self.assertFalse(should_include_source_pack_path(".git/config"))
        self.assertFalse(should_include_source_pack_path("oad_parser/__pycache__/x.pyc"))
        self.assertFalse(should_include_source_pack_path("samples/private/sample.pcap"))
        self.assertFalse(should_include_source_pack_path("dist/source-pack.tar.gz"))
        self.assertFalse(should_include_source_pack_path("docs/private/notes.md"))

    def test_create_source_pack_excludes_sensitive_and_scratch_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "oad_parser").mkdir()
            (root / "oad_parser" / "cli.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "oad_parser" / "__pycache__").mkdir()
            (root / "oad_parser" / "__pycache__" / "cli.pyc").write_bytes(b"bad")
            (root / "docs" / "design").mkdir(parents=True)
            (root / "docs" / "design" / "notes.md").write_text("notes\n", encoding="utf-8")
            (root / "docs" / "TROUBLESHOOTING.md").write_text("help\n", encoding="utf-8")
            (root / "config").mkdir()
            (root / "config" / "example.ini").write_text("[x]\n", encoding="utf-8")
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            (root / ".gitignore").write_text("*.pcap\n", encoding="utf-8")
            (root / "demo.sh").write_text("scratch\n", encoding="utf-8")
            (root / "sample.pcap").write_bytes(b"pcap")
            output = root / "out" / "source-pack.tar.gz"

            result = create_source_pack(root, output, include_untracked=True)

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                manifest = json.loads(
                    archive.extractfile("SOURCE-PACK-MANIFEST.json").read().decode("utf-8")
                )

        self.assertIn("oad_parser/cli.py", names)
        self.assertIn("docs/design/notes.md", names)
        self.assertIn("docs/TROUBLESHOOTING.md", names)
        self.assertIn("config/example.ini", names)
        self.assertIn("README.md", names)
        self.assertIn(".gitignore", names)
        self.assertIn("SOURCE-PACK-MANIFEST.json", names)
        self.assertNotIn("demo.sh", names)
        self.assertNotIn("sample.pcap", names)
        self.assertNotIn("oad_parser/__pycache__/cli.pyc", names)
        self.assertEqual(result.file_count, 6)
        self.assertEqual(manifest["file_count"], 6)
        self.assertEqual(manifest["file_count_basis"], "packaged files excluding SOURCE-PACK-MANIFEST.json")
        self.assertNotIn("repo_root", manifest)
        self.assertNotIn("output_path", manifest)
        self.assertNotIn(str(root), json.dumps(manifest))
        self.assertNotIn(str(output), json.dumps(manifest))
        self.assertEqual(manifest["schema_version"], "2.0")
        self.assertEqual(manifest["selected_profile"], "parser-project")
        self.assertEqual(manifest["included_paths"], manifest["files"])
        self.assertIsInstance(manifest["byte_count"], int)
        self.assertGreater(manifest["byte_count"], 0)
        self.assertEqual(set(manifest["file_hashes"]), set(manifest["files"]))
        self.assertTrue(manifest["excluded_paths"])
        self.assertTrue(manifest["manual_controls"])
        self.assertEqual(manifest["validation"]["command_used"], "python3 -m oad_parser validate-platform")

    def test_create_source_pack_rejects_included_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            (root / "oad_parser").mkdir()
            outside = base / "outside.py"
            outside.write_text("print('outside')\n", encoding="utf-8")
            (root / "oad_parser" / "outside_link.py").symlink_to(outside)
            output = base / "source-pack.tar.gz"

            with self.assertRaises(ValueError) as context:
                create_source_pack(root, output, include_untracked=True)

        self.assertIn("source pack refuses symlink", str(context.exception))
        self.assertIn("oad_parser/outside_link.py", str(context.exception))

    def test_manifest_path_leakage_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            output = root / "out" / "source-pack.tar.gz"

            create_source_pack(root, output, include_untracked=True)

            with tarfile.open(output, "r:gz") as archive:
                manifest = json.loads(
                    archive.extractfile("SOURCE-PACK-MANIFEST.json").read().decode("utf-8")
                )

        manifest_text = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("repo_root", manifest)
        self.assertNotIn("output_path", manifest)
        self.assertNotIn(str(root), manifest_text)
        self.assertNotIn(str(output), manifest_text)
        self.assertIn("source_repository_identifier", manifest)
        self.assertIn("file_hashes", manifest)
        self.assertIn("manual_controls", manifest)

    def test_tracked_only_without_git_uses_source_pack_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "oad_parser").mkdir()
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            (root / "oad_parser" / "cli.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "oad_parser" / "local_note.py").write_text("scratch\n", encoding="utf-8")
            (root / "SOURCE-PACK-MANIFEST.json").write_text(
                json.dumps({"files": ["README.md", "oad_parser/cli.py"]}) + "\n",
                encoding="utf-8",
            )
            output = root / "out" / "source-pack.tar.gz"

            create_source_pack(root, output)

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())

        self.assertIn("README.md", names)
        self.assertIn("oad_parser/cli.py", names)
        self.assertNotIn("oad_parser/local_note.py", names)

    def test_tracked_only_without_git_or_manifest_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            output = root / "out" / "source-pack.tar.gz"

            with self.assertRaisesRegex(ValueError, "requires .git/index or SOURCE-PACK-MANIFEST.json"):
                create_source_pack(root, output)

    def test_iter_source_pack_files_current_repo_excludes_demo(self):
        files = iter_source_pack_files(Path.cwd())

        self.assertNotIn("demo.sh", files)
        self.assertTrue(any(item == "oad_parser/cli.py" for item in files))


if __name__ == "__main__":
    unittest.main()

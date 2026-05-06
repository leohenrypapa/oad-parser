"""Tests for the first-run quickstart script."""

import os
import subprocess
import unittest
from pathlib import Path


class QuickstartScriptTests(unittest.TestCase):
    def test_quickstart_script_help(self):
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "quickstart_check.sh"

        self.assertTrue(script.exists())
        self.assertTrue(os.access(script, os.X_OK))

        result = subprocess.run(
            [str(script), "--help"],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--with-tests", result.stdout)
        self.assertIn("does not require .git", result.stdout)


if __name__ == "__main__":
    unittest.main()

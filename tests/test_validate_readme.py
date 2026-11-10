"""Tests for scripts/validate_readme.py."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "scripts" / "validate_readme.py"


class ValidatorTest(unittest.TestCase):
    def run_validator(self, readme: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copy(VALIDATOR, root / "scripts" / "validate_readme.py")
            (root / "README.md").write_text(readme, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(root / "scripts" / "validate_readme.py"), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_valid_readme(self) -> None:
        result = self.run_validator("# Title\n\n## Section\n\n[link](#section)\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_links_inside_code_fences_are_ignored(self) -> None:
        result = self.run_validator(
            "# Title\n\n```text\n[missing](does-not-exist.md)\n```\n\n## Section\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_escaped_pipe_is_not_a_column(self) -> None:
        result = self.run_validator(
            "# Title\n\n| A | B |\n|---|---|\n| a \\| b | c |\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_path_traversal_is_rejected(self) -> None:
        result = self.run_validator("# Title\n\n[escape](../outside.md)\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes the repository", result.stdout)

    def test_missing_anchor_is_rejected(self) -> None:
        result = self.run_validator("# Title\n\n[missing](#nope)\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing anchor", result.stdout)

    def test_missing_image_is_rejected(self) -> None:
        result = self.run_validator("# Title\n\n![shot](docs/shot.png)\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not exist", result.stdout)


if __name__ == "__main__":
    unittest.main()

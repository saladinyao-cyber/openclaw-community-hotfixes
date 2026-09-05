#!/usr/bin/env python3

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE_ROOT = Path(__file__).resolve().parents[1]


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hotfix-validator-test-")
        self.root = Path(self.temp.name) / "repo"
        shutil.copytree(
            SOURCE_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            ["python3", "scripts/validate.py", "--root", str(self.root)],
            cwd=self.root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def assert_rejected(self, expected: str) -> None:
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stdout)

    def test_clean_repository_passes(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PASS: repository allowlist", result.stdout)

    def test_unknown_file_is_rejected(self) -> None:
        (self.root / "notes.txt").write_text("not allowlisted\n", encoding="utf-8")
        self.assert_rejected("repository allowlist mismatch")

    def test_secret_signature_is_rejected(self) -> None:
        fake_token = "ghp_" + ("A" * 40)
        with (self.root / "README.md").open("a", encoding="utf-8") as handle:
            handle.write(fake_token + "\n")
        self.assert_rejected("sensitive signature (GitHub token)")

    def test_patch_tampering_is_rejected(self) -> None:
        patch = self.root / "patches/0001-memory-core-avoid-full-retry-storm.patch"
        patch.write_bytes(patch.read_bytes() + b"\n")
        self.assert_rejected("SHA-256 mismatch")

    def test_symlink_is_rejected(self) -> None:
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to("manifest.json")
        self.assert_rejected("symlink forbidden")


if __name__ == "__main__":
    unittest.main()

"""End-to-end tests: run ``python -m passcheck`` in a real subprocess, as a user would."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def passcheck(*args, password):
    return subprocess.run(
        [sys.executable, "-m", "passcheck", "--stdin", *args],
        input=password + "\n",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
        check=False,
    )


class EndToEndTests(unittest.TestCase):
    def test_weak_password(self):
        proc = passcheck(password="letmein")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("Score: 0/100", proc.stdout)
        self.assertIn("most commonly used passwords", proc.stdout)

    def test_strong_password_json(self):
        proc = passcheck("--json", password="xK9#mQ2$vL7pR4!w")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result["passes"])
        self.assertEqual(result["label"], "Very strong")

    def test_usage_error(self):
        proc = passcheck(password="")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("passcheck: error:", proc.stderr)

    def test_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "passcheck", "--version"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertRegex(proc.stdout, r"^passcheck \d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()

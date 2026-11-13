"""`mintmap --version` prints the package version and exits 0."""
import os
import subprocess
import sys
import unittest

from mm_testutil import PROTO
from mintmap import __version__

CLI = os.path.join(PROTO, "tests", "_cli.py")


class VersionTests(unittest.TestCase):
    def test_version_flag(self):
        run = subprocess.run([sys.executable, "-I", CLI, "--version"], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout.strip(), f"mintmap {__version__}")

    def test_version_matches_pyproject(self):
        import tomllib
        with open(os.path.join(PROTO, "pyproject.toml"), "rb") as fh:
            self.assertEqual(tomllib.load(fh)["project"]["version"], __version__)

    def test_no_command_is_still_an_error(self):
        run = subprocess.run([sys.executable, "-I", CLI], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 128)

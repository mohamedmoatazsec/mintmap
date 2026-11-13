"""CLI reporting of large gap inventories, without changing detection results."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from mm_testutil import copy_fixture, scan
from mintmap.cli import main


class AllGapsCliTests(unittest.TestCase):
    def setUp(self):
        self.root = copy_fixture(self, "basic_project")
        self.report = scan(self.root)
        # A fixed gap inventory larger than the default display limit; this
        # isolates the CLI/report behavior from future analyzer heuristics.
        self.report["coverage"]["gaps"] = [
            {"type": "unresolved_view", "file": "proj/urls.py", "where": f"route_{i}",
             "detail": f"Unresolved view {i:02d}"}
            for i in range(45)
        ]
        self.report["coverage"]["gaps_by_type"] = {"unresolved_view": 45}

    def execute(self, *arguments):
        output = io.StringIO()
        with patch("mintmap.cli.run_scan", return_value=self.report):
            with contextlib.redirect_stdout(output):
                status = main(["scan", self.root, *arguments])
        self.assertEqual(status, 0)
        return output.getvalue()

    def test_default_lists_40_and_points_to_all_gaps(self):
        output = self.execute()
        self.assertEqual(output.count("  gap unresolved_view:"), 40)
        self.assertIn("Unresolved view 39", output)
        self.assertNotIn("Unresolved view 40", output)
        self.assertIn("... 5 more (see --json or --all-gaps)", output)

    def test_all_gaps_prints_entire_inventory_without_truncation(self):
        output = self.execute("--all-gaps")
        self.assertEqual(output.count("  gap unresolved_view:"), 45)
        self.assertIn("Unresolved view 44", output)
        self.assertNotIn("more (see --json", output)

    def test_all_gaps_does_not_change_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.json")
            self.execute("--all-gaps", "--json", target)
            with open(target, encoding="utf-8") as file:
                stored = json.load(file)
            self.assertEqual(len(stored["coverage"]["gaps"]), 45)
            self.assertEqual(stored["coverage"]["gaps"], self.report["coverage"]["gaps"])

    def test_scan_help_displays_option(self):
        stderr = io.StringIO()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exit_info:
                main(["scan", "--help"])
        self.assertEqual(exit_info.exception.code, 0)
        self.assertIn("--all-gaps", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

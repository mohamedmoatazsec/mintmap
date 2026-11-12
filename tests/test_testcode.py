"""v2 P3: test code is excluded by default, visibly, and --include-tests restores it."""
import json
import os
import subprocess
import sys
import unittest

from mm_testutil import FIXTURES, PROTO, scan, copy_fixture, write, accept_all, paths_for
from mintmap.core.lockfile import build_lock, diff, COVERAGE_REGRESSION
from mintmap.core.project import test_path_reason

TC = os.path.join(FIXTURES, "testcode_project")
EXCLUDED = {
    os.path.join("conftest.py"): "test file name",
    os.path.join("shop", "helpers_tests.py"): "test file name",
    os.path.join("shop", "test_models.py"): "test file name",
    os.path.join("shop", "tests.py"): "test file name",
    os.path.join("shop", "views_test.py"): "test file name",
    os.path.join("shop", "testing.py"): "test support module (TestCase subclass)",
    os.path.join("shop", "tests", "__init__.py"): "in a tests/ or test/ directory",
    os.path.join("shop", "tests", "test_login.py"): "in a tests/ or test/ directory",
    os.path.join("test", "helpers.py"): "in a tests/ or test/ directory",
}


class TestCodeExclusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(TC)
        cls.full = scan(TC, include_tests=True)

    def test_path_patterns(self):
        for rel in ("tests/x.py", "a/test/b.py", "a/test_x.py", "a/x_test.py", "a/x_tests.py", "a/tests.py",
                    "conftest.py"):
            self.assertTrue(test_path_reason(rel.replace("/", os.sep)), rel)
        for rel in ("a/testing.py", "a/test.py", "a/contest.py", "a/latest_views.py", "attestation/x.py"):
            self.assertIsNone(test_path_reason(rel.replace("/", os.sep)), rel)

    def test_excluded_by_default_and_counted_in_coverage(self):
        tc = self.report["coverage"]["test_code"]
        self.assertFalse(tc["included"])
        self.assertEqual(tc["excluded_files"], len(EXCLUDED))
        self.assertEqual(tc["excluded_by_reason"], {"test file name": 5, "in a tests/ or test/ directory": 3,
                                                    "test support module (TestCase subclass)": 1})
        files = {p["mint"]["site"]["file"] for p in self.report["paths"] if p["mint"]["site"]}
        self.assertFalse(files & set(EXCLUDED), files)
        self.assertEqual(self.report["coverage"]["files_seen"], 7)

    def test_test_named_production_module_imported_by_code_is_reincluded(self):
        tc = self.report["coverage"]["test_code"]
        self.assertEqual(tc["reincluded"], [{"file": os.path.join("shop", "test_hooks.py"),
                                            "imported_by": os.path.join("shop", "views.py"),
                                            "reason": "test file name"}])
        p = paths_for(self.report, "route:enter/")
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["mint"]["site"]["function"], "shop.test_hooks.admit")

    def test_test_py_without_testcase_is_production_code(self):
        self.assertEqual(len(paths_for(self.report, "unrouted:shop.test.coupon")), 1)

    def test_include_tests_restores_everything(self):
        tc = self.full["coverage"]["test_code"]
        self.assertTrue(tc["included"])
        self.assertEqual(tc["excluded_files"], 0)
        files = {p["mint"]["site"]["file"] for p in self.full["paths"] if p["mint"]["site"]}
        self.assertEqual(set(EXCLUDED) - files, {os.path.join("shop", "tests", "__init__.py")})

    def test_lock_written_with_tests_then_excluding_them_is_a_coverage_regression(self):
        root = copy_fixture(self, "testcode_project")
        lock = accept_all(build_lock(scan(root, include_tests=True)))
        findings, code = diff(lock, scan(root))
        self.assertTrue(code & COVERAGE_REGRESSION, findings)
        self.assertIn("test code was analysed", " ".join(f["message"] for f in findings))

    def test_new_test_file_does_not_change_the_lock_outcome(self):
        root = copy_fixture(self, "testcode_project")
        lock = accept_all(build_lock(scan(root)))
        write(root, os.path.join("shop", "tests", "test_more.py"),
              "from django.contrib.auth import login\n\n\ndef t(r, u):\n    login(r, u)\n")
        findings, code = diff(lock, scan(root))
        self.assertEqual(code, 0, findings)
        self.assertTrue(any(f["kind"] == "info" and "excluded test files" in f["message"] for f in findings))

    def test_cli_flag(self):
        cli = os.path.join(PROTO, "tests", "_cli.py")
        out = os.path.join(copy_fixture(self, "testcode_project"), "o.json")
        r = subprocess.run([sys.executable, "-I", cli, "scan", TC, "--include-tests", "--json", out],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("test code included", r.stdout)
        with open(out) as fh:
            self.assertTrue(json.load(fh)["coverage"]["test_code"]["included"])
        r = subprocess.run([sys.executable, "-I", cli, "scan", TC], capture_output=True, text=True, timeout=120)
        self.assertIn("test code excluded: 9 file(s)", r.stdout)


if __name__ == "__main__":
    unittest.main()

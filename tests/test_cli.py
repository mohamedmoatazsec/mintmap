"""End-to-end CLI behaviour and exit codes (runs the CLI in a subprocess)."""
import json
import os
import subprocess
import sys
import unittest

from mm_testutil import PROTO, copy_fixture, read, write

CLI = os.path.join(PROTO, "tests", "_cli.py")


def run(*args):
    return subprocess.run([sys.executable, "-I", CLI, *args], capture_output=True, text=True, timeout=120)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.root = copy_fixture(self, "basic_project")
        self.lock = os.path.join(self.root, "mintmap.lock")

    def test_scan_writes_json(self):
        out = os.path.join(self.root, "out.json")
        r = run("scan", self.root, "--json", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as fh:
            rep = json.load(fh)
        self.assertGreater(len(rep["paths"]), 0)
        self.assertIn("coverage", rep)

    def test_init_diff_accept_change_cycle(self):
        self.assertEqual(run("init", self.root, "--lock", self.lock).returncode, 0)
        self.assertEqual(run("init", self.root, "--lock", self.lock).returncode, 128)  # refuses to overwrite
        self.assertEqual(run("diff", self.root, "--lock", self.lock).returncode, 64)   # unreviewed
        with open(self.lock) as fh:
            lock = json.load(fh)
        for p in lock["paths"] + lock.get("settings", []):   # (v5, R7) settings groups are reviewed too
            p["review_status"], p["reviewer"] = "accepted", "cli-test"
        with open(self.lock, "w") as fh:
            json.dump(lock, fh)
        r = run("diff", self.root, "--lock", self.lock)
        self.assertEqual(r.returncode, 0, r.stdout)
        write(self.root, "accounts/helpers.py", read(self.root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n", "    return True\n"))
        out = os.path.join(self.root, "findings.json")
        r = run("diff", self.root, "--lock", self.lock, "--json", out)
        # v2: the verify-named helper that no longer contains any check is also reported as an
        # unrecognized_check_call gap (new gap -> coverage_regression, 32)
        self.assertEqual(r.returncode, 4 | 8 | 32, r.stdout)
        with open(out) as fh:
            self.assertEqual(json.load(fh)["exit_code"], 44)
        self.assertEqual(run("update", self.root, "--lock", self.lock).returncode, 0)
        self.assertEqual(run("diff", self.root, "--lock", self.lock).returncode, 64)  # changed path needs review

    def test_scan_all_gaps_lists_every_gap(self):
        # 45 views that call a `login` they received as a parameter: each is a possible_mint_call_unresolved gap
        for i in range(45):
            write(self.root, f"accounts/extra_{i}.py",
                  f"def start_{i}(request, user, login):\n    return login(request, user)\n")
        out = os.path.join(self.root, "out.json")
        default = run("scan", self.root, "--json", out)
        self.assertEqual(default.returncode, 0, default.stderr)
        with open(out) as fh:
            total = len(json.load(fh)["coverage"]["gaps"])
        self.assertGreater(total, 40)
        lines = default.stdout.splitlines()
        self.assertEqual(sum(1 for x in lines if x.startswith("  gap ")), 40)
        self.assertIn(f"  ... {total - 40} more (see --json, or use --all-gaps)", lines)
        full = run("scan", self.root, "--all-gaps")
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertEqual(sum(1 for x in full.stdout.splitlines() if x.startswith("  gap ")), total)
        self.assertNotIn("more (see --json", full.stdout)
        self.assertIn("--all-gaps", run("scan", "--help").stdout)

    def test_usage_and_input_errors_exit_128(self):
        self.assertEqual(run("diff").returncode, 128)
        self.assertEqual(run("diff", self.root, "--lock", os.path.join(self.root, "missing.lock")).returncode, 128)
        self.assertEqual(run("scan", os.path.join(self.root, "nope")).returncode, 128)


if __name__ == "__main__":
    unittest.main()

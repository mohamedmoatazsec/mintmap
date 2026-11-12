"""`mintmap accept`: recording review decisions in the lock without hand-editing JSON."""
import json
import os
import subprocess
import sys
import unittest

from mm_testutil import PROTO, copy_fixture

CLI = os.path.join(PROTO, "tests", "_cli.py")


def run(*args):
    return subprocess.run([sys.executable, "-I", CLI, *args], capture_output=True, text=True, timeout=120)


class AcceptTests(unittest.TestCase):
    def setUp(self):
        self.root = copy_fixture(self, "basic_project")
        self.lock = os.path.join(self.root, "mintmap.lock")
        self.assertEqual(run("init", self.root, "--lock", self.lock).returncode, 0)

    def load(self):
        with open(self.lock) as fh:
            return json.load(fh)

    def test_accept_all_makes_diff_clean_and_records_reviewer(self):
        self.assertEqual(run("diff", self.root, "--lock", self.lock).returncode, 64)
        r = run("accept", self.root, "--lock", self.lock, "--all", "--reviewer", "alice", "--note", "ok")
        self.assertEqual(r.returncode, 0, r.stderr)
        lock = self.load()
        for e in lock["paths"] + lock.get("settings", []):
            self.assertEqual((e["review_status"], e["reviewer"], e["policy_note"]), ("accepted", "alice", "ok"))
        self.assertEqual(run("diff", self.root, "--lock", self.lock).returncode, 0)

    def test_accept_one_id_by_unique_prefix(self):
        pid = self.load()["paths"][0]["id"]
        r = run("accept", self.root, "--lock", self.lock, pid[:8], "--reviewer", "bob")
        self.assertEqual(r.returncode, 0, r.stderr)
        accepted = [e["id"] for e in self.load()["paths"] if e["review_status"] == "accepted"]
        self.assertEqual(accepted, [pid])

    def test_unknown_id_is_an_error_and_lock_is_unchanged(self):
        before = self.load()
        r = run("accept", self.root, "--lock", self.lock, "does-not-exist", "--reviewer", "bob")
        self.assertEqual(r.returncode, 128)
        self.assertEqual(self.load(), before)

    def test_reviewer_is_required_and_some_selection_is_required(self):
        self.assertEqual(run("accept", self.root, "--lock", self.lock, "--all").returncode, 128)
        self.assertEqual(run("accept", self.root, "--lock", self.lock, "--reviewer", "x").returncode, 128)

    def test_accept_does_not_hide_later_code_changes(self):
        run("accept", self.root, "--lock", self.lock, "--all", "--reviewer", "alice")
        views = [os.path.join(d, f) for d, _, fs in os.walk(self.root) for f in fs if f == "views.py"]
        changed = False
        for v in views:
            with open(v) as fh:
                src = fh.read()
            if "login(" in src:
                with open(v, "a") as fh:
                    fh.write("\n\ndef _added_after_review(request, user):\n    return login(request, user)\n")
                changed = True
        self.assertTrue(changed)
        self.assertNotEqual(run("diff", self.root, "--lock", self.lock).returncode, 0)


if __name__ == "__main__":
    unittest.main()

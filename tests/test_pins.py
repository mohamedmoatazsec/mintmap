"""The action pins shown to users (README.md, examples/mintmap.yml) are the ones CI and the action use. Dependabot
updates only .github/workflows/ and action.yml, so the copies in the docs would otherwise go stale."""
import glob
import os
import re
import unittest

from mm_testutil import PROTO

PIN = re.compile(r"uses: (actions/[\w-]+)@([0-9a-f]{40}) # (v[\d.]+)")
WORKFLOWS = os.path.join(PROTO, ".github", "workflows")


def text(path):
    with open(os.path.join(PROTO, path), encoding="utf-8") as fh:
        return fh.read()


@unittest.skipUnless(os.path.isdir(WORKFLOWS), "needs a git checkout (the sdist has no .github)")
class PinTests(unittest.TestCase):
    def ci_pins(self):
        pins: dict = {}
        sources = sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))) + [os.path.join(PROTO, "action.yml")]
        for path in sources:
            for name, sha, tag in PIN.findall(text(path)):
                pins.setdefault(name, set()).add((sha, tag))
        return pins

    def test_ci_and_the_action_pin_one_version_of_each_action(self):
        pins = self.ci_pins()
        self.assertIn("actions/checkout", pins)
        self.assertIn("actions/setup-python", pins)
        for name, versions in pins.items():
            self.assertEqual(len(versions), 1, f"{name} is pinned to different commits: {sorted(versions)}")

    def test_docs_pin_the_same_actions_as_ci(self):
        ci = {name: next(iter(v)) for name, v in self.ci_pins().items()}
        for rel in ("README.md", "examples/mintmap.yml"):
            found = PIN.findall(text(rel))
            self.assertTrue(found, rel)
            for name, sha, tag in found:
                self.assertEqual((sha, tag), ci.get(name), f"{rel}: {name}")


if __name__ == "__main__":
    unittest.main()

"""scripts/pypi_readme.py: the README as PyPI shows it (absolute links, raw images, no Mermaid source)."""
import importlib.util
import os
import re
import unittest

from mm_testutil import PROTO

SCRIPT = os.path.join(PROTO, "scripts", "pypi_readme.py")


def load():
    spec = importlib.util.spec_from_file_location("pypi_readme", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(os.path.exists(SCRIPT), "needs scripts/pypi_readme.py")
class PypiReadmeTests(unittest.TestCase):
    def test_rewrite(self):
        absolute = load().absolute
        blob = "https://github.com/mohamedmoatazsec/mintmap/blob/v9/"
        raw = "https://raw.githubusercontent.com/mohamedmoatazsec/mintmap/v9/"
        text = ("See [docs](docs/A.md), [here](./docs/B.md), [top](#accuracy) and [web](https://example.org/x).\n"
                "![shot](docs/assets/x.png) <img src=\"docs/assets/demo.svg\" width=\"9\">\n"
                "```mermaid\nflowchart LR\n    a --> b\n```\n")
        out = absolute(text, "v9")
        self.assertIn(f"[docs]({blob}docs/A.md)", out)
        self.assertIn(f"[here]({blob}docs/B.md)", out)
        self.assertIn("[top](#accuracy)", out)                       # in-page links stay in-page
        self.assertIn("[web](https://example.org/x)", out)
        self.assertIn(f"![shot]({raw}docs/assets/x.png)", out)
        self.assertIn(f'<img src="{raw}docs/assets/demo.svg"', out)
        self.assertNotIn("mermaid", out)
        self.assertIn(f"({blob}README.md#how-it-works)", out)

    @unittest.skipUnless(os.path.isdir(os.path.join(PROTO, "docs")), "needs a git checkout (the sdist has no docs/)")
    def test_every_rewritten_target_of_the_readme_exists(self):
        with open(os.path.join(PROTO, "README.md"), encoding="utf-8") as fh:
            out = load().absolute(fh.read(), "v9")
        self.assertNotIn("```mermaid", out)
        targets = re.findall(r"github\.com/mohamedmoatazsec/mintmap/blob/v9/([^)#\s\"]+)", out) + \
            re.findall(r"raw\.githubusercontent\.com/mohamedmoatazsec/mintmap/v9/([^)#\s\"]+)", out)
        self.assertTrue(targets)
        for target in targets:
            self.assertTrue(os.path.exists(os.path.join(PROTO, target)), target)


if __name__ == "__main__":
    unittest.main()

"""(v8) Bounds on number-literal folding, as requested in issue #10 and the maintainer review of PR #13.

    BoundsTests        number_literal() and fold_numbers(): exponent range, 2**64 bound, non-finite results,
                       division by zero, bare negative literals
    FullScanTests      `mintmap scan` of a project whose settings hold each dangerous expression finishes within a
                       time bound and reports the value as dynamic
    PathStabilityTests scan path ids, path fingerprints, routes and candidates are the same as on upstream main
                       (tests/fixtures/demo_scan_paths_main.json); only settings-group fingerprints may change
"""
import ast
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from mm_testutil import PROTO  # noqa: F401  (puts src/ on sys.path)

from mintmap.cli import main
from mintmap.core.fingerprint import stable_dump
from mintmap.core.settings_extract import fold_numbers, number_literal

SRC = os.path.join(PROTO, "src")
DEMO = os.path.join(PROTO, "examples", "demo")
BASELINE = os.path.join(PROTO, "tests", "fixtures", "demo_scan_paths_main.json")
SCAN_LIMIT_S = 30          # generous for CI; the dangerous expressions take milliseconds
NUMBER_LIMIT_S = 10        # one number_literal() call in a child process


def expr(text):
    return ast.parse(text, mode="eval").body


def run_in_child(code, timeout):
    """Run `code` in a fresh interpreter (python -I) with MintMap on sys.path.  The timeout is enforced: a hang fails
    the test instead of blocking the test run."""
    script = "import sys; sys.path.insert(0, %r)\n%s" % (SRC, code)
    try:
        return subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"did not finish within {timeout}s (hang)")


def child_number_literal(text):
    code = ("import ast\nfrom mintmap.core.settings_extract import number_literal\n"
            "print(repr(number_literal(ast.parse(%r, mode='eval').body)))" % text)
    proc = run_in_child(code, NUMBER_LIMIT_S)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


class BoundsTests(unittest.TestCase):
    def test_exponent_must_be_an_int_from_0_to_64(self):
        for text in ("2 ** 65", "1 ** 65", "2 ** -1", "2 ** 2.0", "2 ** 0.5", "2 ** (-64)"):
            with self.subTest(text=text):
                self.assertIsNone(number_literal(expr(text)))
        self.assertEqual(number_literal(expr("0 ** 0")), 1)
        self.assertEqual(number_literal(expr("3 ** 40")), 3 ** 40)          # 3**40 < 2**64, so it folds

    def test_an_intermediate_int_of_2_to_the_64_stays_dynamic(self):
        self.assertIsNone(number_literal(expr("2 ** 64")))
        self.assertIsNone(number_literal(expr("2 ** 63 * 2")))
        self.assertIsNone(number_literal(expr("2 ** 64 - 1 + 1")))
        self.assertEqual(number_literal(expr("(2 ** 63 - 1) * 2 + 1")), 2 ** 64 - 1)

    def test_oversized_literals_stay_dynamic(self):
        self.assertIsNone(number_literal(expr("(10 ** 1000) ** 5")))
        self.assertIsNone(number_literal(expr("18446744073709551616 * 1")))      # 2**64 as a literal
        self.assertEqual(number_literal(expr("18446744073709551615 * 1")), 2 ** 64 - 1)

    def test_nested_powers_are_not_computed(self):
        for text in ("(10 ** 1000) ** 1000", "((10 ** 1000) ** 1000) ** 1000", "10 ** 10 ** 10"):
            with self.subTest(text=text):
                self.assertEqual(child_number_literal(text), "None")      # enforced by a timeout

    def test_deep_expression_scans_as_before_folding_was_added(self):
        # 950 terms: the scan finished on upstream main and must still finish (folding must not lower the limit)
        code = ("import sys\nfrom mintmap.cli import main\nsys.exit(main(['scan', %r, '--json', %r]))\n"
                % (self._deep_project(950), os.path.join(self._tmp, "deep.json")))
        proc = run_in_child(code, SCAN_LIMIT_S)
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])

    def _deep_project(self, terms):
        self._tmp = tempfile.mkdtemp(prefix="mintmap-v8-deep-")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        proj = os.path.join(self._tmp, "proj")
        os.makedirs(os.path.join(proj, "site"))
        for name, text in (("manage.py", "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'site.settings')\n"),
                           (os.path.join("site", "__init__.py"), ""),
                           (os.path.join("site", "urls.py"), "urlpatterns = []\n"),
                           (os.path.join("site", "settings.py"),
                            "ROOT_URLCONF = 'site.urls'\nPASSWORD_RESET_TIMEOUT = " + "+".join(["1"] * terms) + "\n")):
            with open(os.path.join(proj, name), "w") as f:
                f.write(text)
        return proj

    def test_non_finite_results_stay_dynamic(self):
        for text in ("1e308 * 10", "1e308 * 10 - 1e308 * 10", "(1e308 * 10) * 0", "1e400 + 1", "-1e308 * 10"):
            with self.subTest(text=text):
                self.assertIsNone(number_literal(expr(text)))

    def test_division_by_zero_stays_dynamic(self):
        for text in ("1 / 0", "1 // 0", "1 % 0", "0 ** -1", "0.0 / 0", "1.0 % 0.0"):
            with self.subTest(text=text):
                self.assertIsNone(number_literal(expr(text)))

    def test_bare_negative_literals_keep_their_dump(self):
        for text in ("-3600", "-3600.0", "+3600"):
            with self.subTest(text=text):
                node = expr(text)
                self.assertEqual(stable_dump(fold_numbers(node)), stable_dump(node))

    def test_folded_negative_values_have_the_same_dump_as_the_literal(self):
        self.assertEqual(stable_dump(fold_numbers(expr("-60 * 60"))), stable_dump(expr("-3600")))
        self.assertEqual(stable_dump(fold_numbers(expr("-(60 * 60)"))), stable_dump(expr("-3600")))
        self.assertEqual(stable_dump(fold_numbers(expr("60 * 60"))), stable_dump(expr("3600")))


class FullScanTests(unittest.TestCase):
    CASES = {
        "nested powers": "((10 ** 1000) ** 1000) ** 1000",
        "oversized result": "(10 ** 1000) ** 5",
        "power tower": "10 ** 10 ** 10",
        "non-finite float": "1e308 * 10",
        "division by zero": "1 / 0",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mintmap-v8-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.proj = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(self.proj, "site"))
        for name, text in (("manage.py", "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'site.settings')\n"),
                           (os.path.join("site", "__init__.py"), ""),
                           (os.path.join("site", "urls.py"), "urlpatterns = []\n")):
            with open(os.path.join(self.proj, name), "w") as f:
                f.write(text)
        self.settings = os.path.join(self.proj, "site", "settings.py")

    def write_settings(self, value):
        with open(self.settings, "w") as f:
            f.write("ROOT_URLCONF = 'site.urls'\nINSTALLED_APPS = ['django.contrib.auth']\n"
                    "MIDDLEWARE = ['django.contrib.auth.middleware.AuthenticationMiddleware']\n"
                    f"PASSWORD_RESET_TIMEOUT = {value}\n")

    def mintmap(self, *argv):
        code = "import sys\nfrom mintmap.cli import main\nsys.exit(main(sys.argv[1:]))\n"
        script = "import sys; sys.path.insert(0, %r)\n%s" % (SRC, code)
        try:
            proc = subprocess.run([sys.executable, "-I", "-c", script, *argv], capture_output=True, text=True,
                                  timeout=SCAN_LIMIT_S)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"mintmap {argv[0]} did not finish within {SCAN_LIMIT_S}s (hang)")
        return proc.returncode, proc.stdout + proc.stderr

    def test_dangerous_expressions_lock_and_diff_in_time(self):
        for name, text in self.CASES.items():
            with self.subTest(case=name):
                self.write_settings(text)
                start = time.monotonic()
                code, out = self.mintmap("init", self.proj)
                self.assertEqual(code, 0, out)
                code, out = self.mintmap("accept", self.proj, "--all", "--reviewer", "test")
                self.assertEqual(code, 0, out)
                code, out = self.mintmap("diff", self.proj)
                self.assertEqual(code, 0, out)
                self.assertLess(time.monotonic() - start, SCAN_LIMIT_S, name)
                os.remove(os.path.join(self.proj, "mintmap.lock"))

    def test_a_dynamic_power_still_counts_as_a_change(self):
        self.write_settings("10 ** 10 ** 10")
        self.assertEqual(self.mintmap("init", self.proj)[0], 0)
        self.assertEqual(self.mintmap("accept", self.proj, "--all", "--reviewer", "test")[0], 0)
        self.write_settings("1")
        code, out = self.mintmap("diff", self.proj)
        self.assertEqual(code, 4, out)
        self.assertIn("FINGERPRINT_CHANGED", out)


class PathStabilityTests(unittest.TestCase):
    def test_path_ids_and_fingerprints_match_upstream_main(self):
        tmp = tempfile.mkdtemp(prefix="mintmap-v8-paths-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        out_json = os.path.join(tmp, "scan.json")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = main(["scan", DEMO, "--json", out_json])
        self.assertEqual(code, 0, buf.getvalue())
        with open(out_json, encoding="utf-8") as f:
            now = json.load(f)
        with open(BASELINE, encoding="utf-8") as f:
            base = json.load(f)
        now_paths = [{"id": p["id"], "entry_id": p["entry"]["id"], "chain": p["chain"],
                      "fingerprint": p["fingerprint"], "gaps": p["gaps"]} for p in now["paths"]]
        self.assertEqual(now_paths, base["paths"])
        self.assertEqual(now["routes"], base["routes"])
        self.assertEqual(now["candidates"], base["candidates"])


class NegativeLiteralTests(unittest.TestCase):
    """A bare negative literal keeps the fingerprint it had on upstream main; `-60 * 60` matches `-3600`."""
    FIXTURE = os.path.join(PROTO, "tests", "fixtures", "negative_literal_fingerprints_main.json")

    def scan_fingerprints(self, settings_text):
        tmp = tempfile.mkdtemp(prefix="mintmap-v8-neg-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        proj = os.path.join(tmp, "proj")
        os.makedirs(os.path.join(proj, "site"))
        for name, text in (("manage.py", "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'site.settings')\n"),
                           (os.path.join("site", "__init__.py"), ""),
                           (os.path.join("site", "urls.py"), "urlpatterns = []\n"),
                           (os.path.join("site", "settings.py"), settings_text)):
            with open(os.path.join(proj, name), "w") as f:
                f.write(text)
        out = os.path.join(tmp, "scan.json")
        code = "import sys\nfrom mintmap.cli import main\nsys.exit(main(['scan', %r, '--json', %r]))\n" % (proj, out)
        proc = run_in_child(code, SCAN_LIMIT_S)
        self.assertEqual(proc.returncode, 0, proc.stderr[-300:])
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        fps = {}
        for g in data["settings_groups"]:
            fps.update(g["fingerprint"]["settings"])
        return fps

    def test_bare_negative_literal_keeps_its_upstream_fingerprint(self):
        with open(self.FIXTURE, encoding="utf-8") as f:
            fixture = json.load(f)
        fps = self.scan_fingerprints(fixture["settings_text"])
        for name, expected in fixture["fingerprints"].items():
            with self.subTest(setting=name):
                self.assertEqual(fps.get(name), expected)

    def test_folded_negative_matches_the_bare_literal(self):
        bare = self.scan_fingerprints("PASSWORD_RESET_TIMEOUT = -3600\n")
        folded = self.scan_fingerprints("PASSWORD_RESET_TIMEOUT = -60 * 60\n")
        self.assertEqual(folded["PASSWORD_RESET_TIMEOUT"], bare["PASSWORD_RESET_TIMEOUT"])


if __name__ == "__main__":
    unittest.main()

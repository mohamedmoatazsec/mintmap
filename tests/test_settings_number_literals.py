"""(v7) Arithmetic on number literals in a settings value is folded to its value before the settings group is
fingerprinted, so rewriting `60 * 60` as `3600` (or `365*60*24*60` as `60*60*24*365`) is not a change.  Only
literal arithmetic is folded: a name, a call, an attribute or a string is never evaluated, and a real change of
the number (`60 * 61`) still changes the fingerprint.

    NumberLiteralTests     number_literal() folds literal arithmetic and nothing else
    SettingsFingerprintTests  `mintmap diff` on a project whose PASSWORD_RESET_TIMEOUT is rewritten
"""
import ast
import contextlib
import io
import os
import shutil
import tempfile
import time
import unittest

from mm_testutil import PROTO  # noqa: F401  (puts src/ on sys.path)

from mintmap.cli import main
from mintmap.core.settings_extract import fold_numbers, number_literal


def expr(text):
    return ast.parse(text, mode="eval").body


class NumberLiteralTests(unittest.TestCase):
    def test_arithmetic_on_literals_is_folded(self):
        self.assertEqual(number_literal(expr("60 * 60")), 3600)
        self.assertEqual(number_literal(expr("365*60*24*60")), number_literal(expr("60*60*24*365")))
        self.assertEqual(number_literal(expr("-(-3600)")), 3600)
        self.assertEqual(number_literal(expr("2 ** 10")), 1024)
        self.assertEqual(number_literal(expr("7 // 2 + 7 % 3 - 1.5")), 3 + 1 - 1.5)
        self.assertEqual(number_literal(expr("1 + 2.5")), 3.5)

    def test_anything_else_is_not_evaluated(self):
        for text in ("NAME * 2", "f() + 1", "settings.X * 2", "'a' * 3", "True + 1", "1 + None",
                     "1 / 0", "5 % 0", "2 ** 0.5", "not 1", "~1", "[1] * 2"):
            with self.subTest(text=text):
                self.assertIsNone(number_literal(expr(text)))

    def test_huge_powers_are_not_computed(self):
        start = time.monotonic()
        self.assertIsNone(number_literal(expr("10 ** 10 ** 10")))
        self.assertLess(time.monotonic() - start, 5)

    def test_fold_numbers_keeps_statements_without_arithmetic_unchanged(self):
        stmt = ast.parse("X = 3600").body[0]
        self.assertIs(fold_numbers(stmt), stmt)

    def test_fold_numbers_replaces_only_the_literal_subtree(self):
        stmt = ast.parse("X = (60 * 60, NAME * 2)").body[0]
        folded = fold_numbers(stmt)
        self.assertIsNot(folded, stmt)
        self.assertEqual(ast.unparse(folded), "X = (3600, NAME * 2)")
        self.assertEqual(ast.unparse(stmt), "X = (60 * 60, NAME * 2)")       # the input is not changed


class SettingsFingerprintTests(unittest.TestCase):
    SETTINGS = (
        "ROOT_URLCONF = 'site.urls'\n"
        "INSTALLED_APPS = ['django.contrib.auth']\n"
        "MIDDLEWARE = ['django.contrib.auth.middleware.AuthenticationMiddleware']\n"
        "AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.ModelBackend']\n"
        "PASSWORD_RESET_TIMEOUT = {value}\n"
    )

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mintmap-v7-")
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
            f.write(self.SETTINGS.format(value=value))

    def cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def lock_with(self, locked_value):
        self.write_settings(locked_value)
        self.assertEqual(self.cli("init", self.proj)[0], 0)
        self.assertEqual(self.cli("accept", self.proj, "--all", "--reviewer", "test")[0], 0)

    def test_unchanged_value_passes(self):
        self.lock_with("60 * 60")
        self.assertEqual(self.cli("diff", self.proj)[0], 0)

    def test_literal_rewritten_to_its_value_passes(self):
        self.lock_with("60 * 60")
        self.write_settings("3600")
        code, out = self.cli("diff", self.proj)
        self.assertEqual(code, 0, out)
        self.assertNotIn("FINGERPRINT_CHANGED", out)

    def test_rewritten_arithmetic_with_the_same_value_passes(self):
        self.lock_with("365*60*24*60")
        self.write_settings("60*60*24*365")
        code, out = self.cli("diff", self.proj)
        self.assertEqual(code, 0, out)

    def test_a_different_number_still_changes_the_fingerprint(self):
        self.lock_with("60 * 60")
        self.write_settings("60 * 61")
        code, out = self.cli("diff", self.proj)
        self.assertEqual(code, 4, out)
        self.assertIn("FINGERPRINT_CHANGED", out)
        self.assertIn("PASSWORD_RESET_TIMEOUT", out)


if __name__ == "__main__":
    unittest.main()

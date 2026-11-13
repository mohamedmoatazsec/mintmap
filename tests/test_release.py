"""Release 0.5.0a1 review fixes: version-independent fingerprints, lock contents, fail-closed CLI, job-summary
escaping, and the GitHub Action running MintMap so that files in the pull request cannot replace it."""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from mm_testutil import PROTO, copy_fixture, read, scan, write
from mintmap.ci_summary import render
from mintmap.core.fingerprint import stable_dump, stable_unparse
from mintmap.core.lockfile import build_lock, diff, running_python

CLI = os.path.join(PROTO, "tests", "_cli.py")
LAUNCHER = os.path.join(PROTO, "scripts", "run_mintmap.py")
ACTION = os.path.join(PROTO, "action.yml")

SAMPLE = (
    "@login_required\n"
    "def f(request, *, otp=None) -> bool:\n"
    "    return verify(request.user, otp, 'caf\\u00e9 \\U00011b00', b'x', 1.5, None)\n"
    "class C(Base):\n"
    "    msg: str = f'{x!r:>{w}}'\n"
)
# The same text on every supported Python: no `type_params=[]` (3.12), no empty lists or None fields (3.12 and
# earlier), strings written with ascii() (repr() depends on the Unicode database), and no trailing Constant('')
# in an f-string format spec (3.12).
SAMPLE_DUMP = (
    "Module(body=[FunctionDef(name='f', args=arguments(args=[arg(arg='request')], kwonlyargs=[arg(arg='otp')], "
    "kw_defaults=[Constant(value=None)]), body=[Return(value=Call(func=Name(id='verify', ctx=Load()), "
    "args=[Attribute(value=Name(id='request', ctx=Load()), attr='user', ctx=Load()), Name(id='otp', ctx=Load()), "
    "Constant(value='caf\\xe9 \\U00011b00'), Constant(value=b'x'), Constant(value=1.5), Constant(value=None)]))], "
    "decorator_list=[Name(id='login_required', ctx=Load())], returns=Name(id='bool', ctx=Load())), "
    "ClassDef(name='C', bases=[Name(id='Base', ctx=Load())], body=[AnnAssign(target=Name(id='msg', ctx=Store()), "
    "annotation=Name(id='str', ctx=Load()), value=JoinedStr(values=[FormattedValue(value=Name(id='x', ctx=Load()), "
    "conversion=114, format_spec=JoinedStr(values=[Constant(value='>'), FormattedValue(value=Name(id='w', "
    "ctx=Load()), conversion=-1)]))]), simple=1)])])"
)


def run(*args, cwd=None):
    return subprocess.run([sys.executable, "-I", CLI, *args], capture_output=True, text=True, timeout=120, cwd=cwd)


def accepted_lock(root):
    lock = os.path.join(root, "mintmap.lock")
    assert run("init", root, "--lock", lock).returncode == 0
    assert run("accept", root, "--all", "--reviewer", "t", "--lock", lock).returncode == 0
    return lock


class StableDumpTests(unittest.TestCase):
    def test_dump_is_the_same_on_every_python_version(self):
        self.assertEqual(stable_dump(ast.parse(SAMPLE)), SAMPLE_DUMP)

    def test_unparse_of_fstrings_is_the_same_on_every_python_version(self):
        # gap keys and settings values quote unparsed code; stock ast.unparse on 3.12 writes f'{x['a']}'
        cases = {
            "f\"{('https' if SECURE else 'http')}://{DOMAIN}\"": "f\"{('https' if SECURE else 'http')}://{DOMAIN}\"",
            "f\"{config['path']}/\" if config['path'] else ''": "f\"{config['path']}/\" if config['path'] else ''",
            "f'{a[\"k\"]:{\"<\"}10}'": "f\"{a['k']:{'<'}10}\"",
            "f\"{x!r:>{w}} {y:%Y-%m-%d} \\n\"": "f'{x!r:>{w}} {y:%Y-%m-%d} \\n'",
        }
        for src, want in cases.items():
            tree = ast.parse(src, mode="eval")
            self.assertEqual(stable_unparse(tree), want, src)
            if sys.version_info[:2] == (3, 13):
                self.assertEqual(stable_unparse(tree), ast.unparse(tree), src)

    @unittest.skipUnless(sys.version_info[:2] == (3, 13), "the evaluated version (3.13) only")
    def test_equal_to_ast_dump_on_313_for_ascii_code(self):
        src = SAMPLE.replace("caf\\u00e9 \\U00011b00", "cafe")
        tree = ast.parse(src)
        self.assertEqual(stable_dump(tree), ast.dump(tree, include_attributes=False))


class LockContentTests(unittest.TestCase):
    def test_lock_records_python_and_no_absolute_library_paths(self):
        root = copy_fixture(self, "basic_project")
        lib = tempfile.mkdtemp(prefix="mintmap-lib-")
        self.addCleanup(shutil.rmtree, lib, ignore_errors=True)
        rep = scan(root, library_paths=[lib])
        lock = build_lock(rep)
        self.assertEqual(lock["tool"]["python"], running_python())
        self.assertNotIn("library_paths", lock["tool"])
        self.assertEqual(lock["tool"]["library_paths_count"], 1)
        self.assertNotIn(lib, json.dumps(lock))
        self.assertIn(os.path.abspath(lib), rep["tool"]["library_paths"])   # the scan report keeps them

    def test_python_version_mismatch_is_reported_as_info_only(self):
        root = copy_fixture(self, "basic_project")
        rep = scan(root)
        lock = build_lock(rep)
        for e in lock["paths"] + lock["settings"]:
            e["review_status"] = "accepted"
        lock["tool"]["python"] = "3.0"
        findings, code = diff(lock, rep)
        self.assertEqual(code, 0)
        self.assertTrue(any(f["kind"] == "info" and "Python 3.0" in f["message"] for f in findings), findings)


class FailClosedCliTests(unittest.TestCase):
    def setUp(self):
        self.root = copy_fixture(self, "basic_project")
        self.lock = os.path.join(self.root, "mintmap.lock")

    def write_lock(self, obj):
        with open(self.lock, "w") as fh:
            json.dump(obj, fh)

    def test_lock_that_is_not_a_mintmap_lock_exits_128(self):
        for bad in ([], {"paths": "x"}, {"paths": [1]}, {"settings": []}):
            self.write_lock(bad)
            for cmd in (("diff",), ("update",), ("accept", "--all", "--reviewer", "x")):
                r = run(cmd[0], self.root, "--lock", self.lock, *cmd[1:])
                self.assertEqual(r.returncode, 128, (bad, cmd, r.stderr))
                self.assertIn("not a MintMap lock", r.stderr)

    def test_internal_error_exits_128_not_1(self):
        self.write_lock({"paths": [{"id": "x"}]})       # valid shape, missing fields -> KeyError inside diff
        r = run("diff", self.root, "--lock", self.lock)
        self.assertEqual(r.returncode, 128, r.stderr)
        self.assertIn("mintmap: internal error", r.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_dangling_symlink_exits_128(self):
        accepted_lock(self.root)
        os.symlink(os.path.join(self.root, "does-not-exist.py"), os.path.join(self.root, "accounts", "extra.py"))
        r = run("diff", self.root, "--lock", self.lock)
        self.assertEqual(r.returncode, 128, r.stdout + r.stderr)

    def test_closed_output_pipe_exits_128(self):
        self.assertEqual(run("init", self.root, "--lock", self.lock).returncode, 0)
        p = subprocess.Popen([sys.executable, "-I", CLI, "diff", self.root, "--lock", self.lock],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdout.close()                                  # like `mintmap diff | true`
        err = p.stderr.read().decode()
        p.stderr.close()
        self.assertEqual(p.wait(timeout=120), 128, err)
        self.assertNotIn("Traceback", err)

    def test_accept_ids_after_options_and_hint(self):
        self.assertEqual(run("init", self.root, "--lock", self.lock).returncode, 0)
        with open(self.lock) as fh:
            ids = [e["id"] for e in json.load(fh)["paths"]][:2]
        r = run("accept", self.root, "--reviewer", "bob", ids[0], "--lock", self.lock, ids[1][:8])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("run `mintmap update` first", r.stdout)
        self.assertEqual(run("accept", self.root, "--reviewer", "bob", "--bogus", ids[0]).returncode, 128)
        self.assertEqual(run("diff", self.root, "--lock", self.lock, "extra-positional").returncode, 128)


class SummaryTests(unittest.TestCase):
    def test_pull_request_text_is_rendered_inside_code_spans(self):
        evil = ("login/x<h1>MintMap: no changes</h1><img src=x>[Approved](https://example.invalid) @octocat "
                "<details><summary>ok</summary> a|b ``tick`` ‮\x07" + "y" * 2000)
        out = render({"findings": [{"kind": "new_path", "path_id": "abc", "message": evil}]}, 1)
        rows = [ln for ln in out.splitlines() if ln.startswith("| new_path") or ln.startswith("| `")]
        self.assertEqual(len(rows), 1, out)
        cells = re.split(r"(?<!\\)\|", rows[0])[1:-1]
        detail = cells[2].strip()
        self.assertTrue(detail.startswith("```") and detail.endswith("```"), detail[:80])
        self.assertNotIn("‮", detail)
        self.assertNotIn("\x07", detail)
        self.assertLess(len(detail), 520)
        self.assertIn("a\\|b", detail)

    def test_advice_names_the_project_dir_and_error_advice(self):
        out = render({"findings": []}, 4)
        self.assertIn("mintmap accept <project_dir> <ids...> --reviewer <name>", out)
        err = render({"findings": []}, 128)
        self.assertIn("could not run", err)
        self.assertIn("mintmap init <project_dir>", err)

    def test_summary_size_is_capped(self):
        many = [{"kind": "new_path", "path_id": str(i), "message": "m" * 5000} for i in range(500)]
        self.assertLess(len(render({"findings": many}, 1)), 600 * 1024)


def _planted_checkout(root):
    """Files a pull request could add at the repository root to hijack `python -m ...` or a bare `import`."""
    marker = os.path.join(root, "PLANTED_CODE_RAN")
    payload = f"open({marker!r}, 'w').write('x')\n"
    write(root, "mintmap/__init__.py", payload)
    write(root, "mintmap/cli.py", payload + "def entry(argv=None):\n    print('exit 0 (ok)')\n    return 0\n")
    write(root, "mintmap/ci_summary.py", payload + "def main(argv=None):\n    return 0\n")
    write(root, "pip/__main__.py", payload)
    write(root, "json.py", payload)
    write(root, "argparse.py", payload)
    return marker


class LauncherTests(unittest.TestCase):
    def test_launcher_ignores_modules_planted_in_the_working_directory(self):
        root = copy_fixture(self, "basic_project")
        lock = accepted_lock(root)
        marker = _planted_checkout(root)
        write(root, "accounts/helpers.py", read(root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n", "    return True\n"))
        r = subprocess.run([sys.executable, "-I", LAUNCHER, "diff", ".", "--lock", lock], cwd=root,
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 4 | 8 | 32, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_launcher_refuses_to_run_without_isolated_mode(self):
        r = subprocess.run([sys.executable, LAUNCHER, "scan", "."], capture_output=True, text=True, timeout=60,
                           cwd=tempfile.gettempdir())
        self.assertEqual(r.returncode, 128)

    def _broken_checkout(self):
        """A copy of the launchers next to a mintmap package whose modules fail to import, as on an unsupported
        Python. An import error must exit 128 (MintMap could not run), never 1 (the new_path bit)."""
        tmp = tempfile.mkdtemp(prefix="mintmap-broken-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        os.makedirs(os.path.join(tmp, "scripts"))
        shutil.copy(LAUNCHER, os.path.join(tmp, "scripts", "run_mintmap.py"))
        pkg = os.path.join(PROTO, "src", "mintmap")
        for name in ("__init__.py", "__main__.py", "_launch.py"):
            write(tmp, f"src/mintmap/{name}", read(pkg, name))
        for name in ("cli.py", "ci_summary.py"):
            write(tmp, f"src/mintmap/{name}", 'raise AttributeError("simulated: this Python is not supported")\n')
        return tmp

    def test_launcher_exits_128_when_mintmap_cannot_be_imported(self):
        tmp = self._broken_checkout()
        for args in (["diff", "."], ["--version"], ["--summary", "findings.json", "0"]):
            r = subprocess.run([sys.executable, "-I", os.path.join(tmp, "scripts", "run_mintmap.py"), *args],
                               capture_output=True, text=True, timeout=60, cwd=tmp)
            self.assertEqual(r.returncode, 128, args)
            self.assertRegex(r.stderr, r"^mintmap: could not start on Python 3\.\d+\.\S*: AttributeError\(", args)

    def test_console_entry_point_exits_128_when_mintmap_cannot_be_imported(self):
        tmp = self._broken_checkout()
        src = os.path.join(tmp, "src")
        for code in ("from mintmap._launch import main; sys.exit(main())",
                     "import runpy; runpy.run_module('mintmap', run_name='__main__')"):
            r = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {src!r}); {code}"],
                               capture_output=True, text=True, timeout=60, cwd=tmp)
            self.assertEqual(r.returncode, 128, code + r.stderr)
            self.assertIn("mintmap: could not start on Python", r.stderr)

    def test_console_entry_point_runs(self):
        src = os.path.join(PROTO, "src")
        code = "sys.argv = ['mintmap', '--version']; from mintmap._launch import main; sys.exit(main())"
        r = subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {src!r}); {code}"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"^mintmap \d")


def _action_step_script():
    """The bash script of the action's `mintmap diff` step, as written in action.yml."""
    with open(ACTION) as fh:
        lines = fh.read().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "id: diff")
    run_at = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    body = []
    for ln in lines[run_at + 1:]:
        if ln.strip() and not ln.startswith(" " * 8):
            break
        body.append(ln[8:])
    return "\n".join(body) + "\n"


class ActionTests(unittest.TestCase):
    def test_every_python_call_in_action_is_isolated_and_nothing_is_installed(self):
        with open(ACTION) as fh:
            text = fh.read()
        self.assertNotRegex(text, r"pip install|python -m|python3 -m")
        calls = re.findall(r'"\$MM_PYTHON"[^\n]*', text)
        self.assertTrue(calls)
        for c in calls:
            self.assertRegex(c, r'^"\$MM_PYTHON" -I ')
        for uses in re.findall(r"uses:\s*(\S+)", text):
            self.assertRegex(uses, r"@[0-9a-f]{40}$", "pin actions to a full commit SHA")

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_action_step(self):
        script = _action_step_script()
        tmp = tempfile.mkdtemp(prefix="mintmap-action-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        def step(project, fail_on="255", lock=""):
            out, summary = os.path.join(tmp, "out"), os.path.join(tmp, "summary")
            for p in (out, summary):
                open(p, "w").close()
            env = dict(PATH=os.environ.get("PATH", "/usr/bin:/bin"), ACTION_PATH=PROTO, MM_PYTHON=sys.executable,
                       MM_PROJECT=".", MM_LOCK=lock, MM_LIBS="", MM_FAIL_ON=fail_on, RUNNER_TEMP=tmp,
                       GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summary)
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script], cwd=project,
                               env=env, capture_output=True, text=True, timeout=180)
            return r, read(tmp, "out"), read(tmp, "summary")

        root = copy_fixture(self, "basic_project")
        accepted_lock(root)
        r, out, summary = step(root)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("exit-code=0", out)
        self.assertIn("No changes", summary)
        # workflow commands are paused while MintMap prints text from the pull request, with a random token
        lines = r.stdout.splitlines()
        stop = [ln for ln in lines if re.fullmatch(r"::stop-commands::[0-9a-f]{32}", ln)]
        self.assertEqual(len(stop), 1, r.stdout)
        token = stop[0].rsplit("::", 1)[1]
        self.assertIn(f"::{token}::", lines)
        self.assertLess(lines.index(stop[0]), lines.index("exit 0 (ok)"))
        self.assertLess(lines.index("exit 0 (ok)"), lines.index(f"::{token}::"))
        r, out, _ = step(root, fail_on="08")              # decimal 8, not an octal error that skips the check
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("value too great", r.stderr)
        for bad in ("010x", "0x10", "256", "1000", "-1", ""):
            r, out, _ = step(root, fail_on=bad)
            self.assertEqual(r.returncode, 1, bad)
            self.assertNotIn("exit-code", out, bad)        # rejected before MintMap runs

        # a pull request that weakens the OTP check and plants modules at the repository root
        marker = _planted_checkout(root)
        write(root, "accounts/helpers.py", read(root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n", "    return True\n"))
        r, out, summary = step(root)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("exit-code=44", out)
        self.assertIn("fingerprint_changed", summary)
        self.assertFalse(os.path.exists(marker))
        r, out, _ = step(root, fail_on="010")             # decimal 10 = bits 2 and 8; the change sets bit 8
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        r, out, _ = step(root, fail_on="0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        # MintMap could not run (lock missing): bit 128 fails the job whatever fail-on says
        os.remove(os.path.join(root, "mintmap.lock"))
        r, out, summary = step(root, fail_on="63")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("exit-code=128", out)
        self.assertIn("could not run", r.stdout)
        self.assertIn("mintmap init <project_dir>", summary)
        self.assertNotIn("fingerprint_changed", summary)  # a fresh findings file per run, not the previous one


class OutputTests(unittest.TestCase):
    def test_text_from_the_project_cannot_start_an_output_line(self):
        # A route string (any text from the pull request) must not start a line that a CI runner reads as a
        # workflow command such as ::error:: or ::add-mask::.
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "demo")
            shutil.copytree(os.path.join(PROTO, "examples", "demo"), root)
            src = read(root, "members/urls.py")
            evil = '    path("x/\\n::error title=MintMap::no changes\\r\\n", views.sign_in, name="x"),\n'
            write(root, "members/urls.py", src.replace("urlpatterns = [\n", "urlpatterns = [\n" + evil, 1))
            r = run("diff", root)
            self.assertEqual(r.returncode & 1, 1, r.stdout + r.stderr)
            lines = (r.stdout + r.stderr).splitlines()
            self.assertFalse([ln for ln in lines if ln.lstrip().startswith("::")], r.stdout)
            self.assertIn("\\n::error", r.stdout)
            # the same for the text report of `scan` (route strings, entry ids, gap details, reasons)
            r = run("scan", root)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            lines = (r.stdout + r.stderr).splitlines()
            self.assertFalse([ln for ln in lines if ln.lstrip().startswith("::")], r.stdout)
            self.assertIn("\\n::error", r.stdout)
            self.assertIn("\\r\\n", r.stdout)


if __name__ == "__main__":
    unittest.main()

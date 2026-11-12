"""Shared helpers for MintMap tests (fixtures are synthetic; see tests/fixtures)."""
import os
import shutil
import sys
import tempfile

PROTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROTO, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from mintmap.core.analysis import Analysis  # noqa: E402
from mintmap.core.catalog import load_catalog  # noqa: E402
from mintmap.core.project import DEFAULT_EXCLUDED_DIRS  # noqa: E402

FIXTURES = os.path.join(PROTO, "tests", "fixtures")
# Older catalog versions, kept only so the regression tests of earlier rounds still run.
V2_CATALOG = os.path.join(PROTO, "tests", "data", "django_catalog_v2.json")
V1_CATALOG = os.path.join(PROTO, "tests", "data", "django_catalog_v1.json")
CATALOG = load_catalog()             # default: src/mintmap/data/django_catalog.json
CATALOG_V2 = load_catalog(V2_CATALOG)  # the v2 catalog (unchanged)
CATALOG_V1 = load_catalog(V1_CATALOG)  # the frozen v1 catalog (optional v2 overlay entries are skipped)


def scan(root, extra_excludes=(), catalog=None, include_tests=False, library_paths=None):
    return Analysis(root, catalog or CATALOG, excluded_dirs=set(DEFAULT_EXCLUDED_DIRS) | set(extra_excludes),
                    include_tests=include_tests, library_paths=library_paths).run()


def copy_fixture(testcase, name):
    tmp = tempfile.mkdtemp(prefix="mintmap-test-")
    testcase.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    dst = os.path.join(tmp, name)
    shutil.copytree(os.path.join(FIXTURES, name), dst)
    return dst


def paths_for(report, entry_id_prefix, api=None):
    out = [p for p in report["paths"] if p["entry"]["id"].startswith(entry_id_prefix)]
    if api:
        out = [p for p in out if p["mint"]["api"] == api]
    return out


def one_path(testcase, report, entry_id_prefix, api=None):
    ps = paths_for(report, entry_id_prefix, api)
    testcase.assertEqual(len(ps), 1, f"expected one path for {entry_id_prefix} {api}: {[p['entry']['id'] for p in ps]}")
    return ps[0]


def checks_by(path, check):
    return [c for c in path["evidence"]["checks"] if c["check"] == check]


def write(root, rel, text):
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)


def read(root, rel):
    with open(os.path.join(root, rel)) as fh:
        return fh.read()


def accept_all(lock):
    for p in lock["paths"] + lock.get("settings", []) + lock.get("candidates", []):
        p["review_status"] = "accepted"
        p["reviewer"] = "test-reviewer"
        p["policy_note"] = "fixture"
    return lock

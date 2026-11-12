"""v6: tests for the generalisation round (root causes of the round-3 fresh evaluation, see docs/DEVELOPMENT_HISTORY.md).

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    SessionKeyPatternTests     session keys built at run time (f-string / str.format / local / module constant) and
                               read back as a principal through a session alias are hand-rolled logins
    CandidateSessionTests      candidate tier `session_state`: re-key + hash, a session key handed to another session,
                               a new SessionStore handed out, step-up timestamps; UI state is set aside; grouping
    CandidateLockTests         candidate groups in the lock: accept, unchanged diff, new / changed / removed member,
                               a new entry point reaching a member, merge keeps reviews, CLI text
    RelatedManagerTests        `team.tokens.create(...)` (reverse relation) and CreateView saves of credential models
    LibraryFlowCallTests       a catalogued library function view called directly from a project view
    AdminSiteSwapTests         an admin site swapped inside a function (and via AdminConfig.default_site)
    UrlBuilderTests            catalogued URL builder functions; unknown helpers wrapping path()
    SettingsCallTests          settings computed by getter defaults and pass-through functions, comprehension
                               filters, conditional expressions
    MintingSubclassTests       an unregistered project subclass of a catalogued minting middleware
    PasswordAndLibraryCallTests  passwords set from request data; request handed to an uncatalogued auth function
    SignedValueTests           generic signing primitives are mints only for credential-like values
    ReceiverAndAdminTests      `if created:` post_save receivers; admin-chosen passwords; library secret generators
"""
import json
import os
import subprocess
import sys
import textwrap
import unittest

from mm_testutil import PROTO, scan, write, read, accept_all, one_path, paths_for
from test_v5 import project, run_diff, gaps

from mintmap.core.lockfile import build_lock, merge_lock, diff

CLI = os.path.join(PROTO, "tests", "_cli.py")


def replace_in(root, rel, old, new):
    text = read(root, rel)
    assert old in text, (old, rel)
    write(root, rel, text.replace(old, new))


def cands(report, group=None):
    return [c for c in report.get("candidates", []) if group is None or c["candidate"]["group"] == group]


def cand_for(tc, report, func_suffix, group=None):
    hits = [c for c in cands(report, group) if (c["mint"].get("site") or {}).get("function", "").endswith(func_suffix)
            or c["entry"]["view"].endswith(func_suffix)]
    tc.assertEqual(len(hits), 1, [c["entry"]["id"] for c in cands(report)])
    return hits[0]


# ============================================================================ settings computed by calls
SETTINGS_CALLS = """\
from conf.config import CONFIG, ensure_present

MIDDLEWARE = CONFIG.get("middleware", [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "club.mw.HeaderLoginMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
])
MIDDLEWARE = ensure_present(MIDDLEWARE, "django.middleware.csrf.CsrfViewMiddleware")
if DEBUG_TOOLBAR_OFF:
    MIDDLEWARE = [m for m in MIDDLEWARE if m != "debug_toolbar.middleware.DebugToolbarMiddleware"]
AUTHENTICATION_BACKENDS = CONFIG.get("backends", ["django.contrib.auth.backends.RemoteUserBackend"]) if CONFIG \\
    else ["django.contrib.auth.backends.ModelBackend"]
"""
HEADER_MW = """\
from django.conf import settings
from django.contrib.auth.middleware import RemoteUserMiddleware


class HeaderLoginMiddleware(RemoteUserMiddleware):
    header = "HTTP_X_USER"

    def process_request(self, request):
        if not settings.HEADER_LOGIN:
            return None
        return super().process_request(request)
"""


class SettingsCallTests(unittest.TestCase):
    def files(self):
        return {"conf/urls.py": "urlpatterns = []\n", "conf/config.py": "CONFIG = {}\n\n\n"
                "def ensure_present(items, item):\n    return list(items) + [item]\n", "club/mw.py": HEADER_MW}

    def test_getter_default_and_pass_through_keep_the_known_middleware(self):
        root = project(self, self.files(), init=("conf", "club"),
                       settings_extra="DEBUG_TOOLBAR_OFF = True\nHEADER_LOGIN = False\n" + SETTINGS_CALLS)
        rep = scan(root)
        p = one_path(self, rep, "middleware:club.mw.HeaderLoginMiddleware")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.middleware.RemoteUserMiddleware")
        keys = [g["key"] for g in gaps(rep, "setting_partially_unknown")]
        self.assertTrue(any("CONFIG.get('middleware'" in k for k in keys), keys)
        self.assertFalse([g for g in gaps(rep, "dynamic_setting") if "MIDDLEWARE" in g["key"]])
        self.assertIn("remote_user_external", rep["coverage"]["authentication_backends_factor"])
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/settings.py", "HEADER_LOGIN = False",
                                                                  "HEADER_LOGIN = True"))
        self.assertTrue(code & 4, findings)



"""v6 (second part): false-alarm reductions and generalisation rules of the v6 round.

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    PrefixTwinTests            routes that differ only by a leading run-time URL prefix (`if not PREFIX: urlpatterns =
                               x else: urlpatterns = [path(PREFIX, include(x))]`) are one entry
    FlowConditionTests         catalogued library flows switched off by the project's settings (catalog
                               `library_flow_conditions`) are not paths, are listed, and enabling one is a new path
"""
import json
import unittest

from mm_testutil import scan
from test_v5 import project, run_diff
from test_v6 import replace_in


# ============================================================================ URL-prefix twins
PREFIX_URLS = """\
from django.conf import settings
from django.urls import include, path

from shop import views

PREFIX = settings.SITE_PREFIX
site_patterns = [
    path("signin/", views.sign_in),
    path("about/", views.about),
]
if not PREFIX:
    urlpatterns = site_patterns
else:
    urlpatterns = [path(PREFIX, include(site_patterns))]
"""
PREFIX_VIEWS = """\
from django.contrib.auth import authenticate, login
from django.http import HttpResponse


def sign_in(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=403)
    login(request, user)
    return HttpResponse("ok")


def about(request):
    return HttpResponse("about")


def sign_in_fast(request):
    login(request, request.user)
    return HttpResponse("ok")
"""


class PrefixTwinTests(unittest.TestCase):
    def root(self, urls=PREFIX_URLS):
        return project(self, {"conf/urls.py": urls, "shop/views.py": PREFIX_VIEWS},
                       settings_extra='import os\nSITE_PREFIX = os.environ.get("PREFIX", "")\n')

    def test_prefixed_twin_is_one_entry(self):
        rep = scan(self.root())
        ps = [p for p in rep["paths"] if p["entry"]["view"] == "shop.views.sign_in"]
        self.assertEqual([p["entry"]["id"] for p in ps], ["route:signin/|shop.views.sign_in"], ps)
        self.assertEqual(ps[0]["entry"]["route"]["pattern"], "signin/")
        self.assertTrue([n for n in ps[0]["entry"]["notes"] if "run-time URL prefix" in n], ps[0]["entry"]["notes"])

    def test_a_route_only_in_the_prefixed_branch_is_still_a_path(self):
        urls = PREFIX_URLS.replace("include(site_patterns)",
                                   "include(site_patterns + [path('fast/', views.sign_in_fast)])")
        rep = scan(self.root(urls))
        fast = [p for p in rep["paths"] if p["entry"]["view"] == "shop.views.sign_in_fast"]
        self.assertEqual(len(fast), 1)
        self.assertTrue(fast[0]["entry"]["route"]["pattern"].endswith("}fast/"), fast[0]["entry"]["id"])
        self.assertEqual(len([p for p in rep["paths"] if p["entry"]["view"] == "shop.views.sign_in"]), 1)

    def test_a_different_view_in_the_prefixed_branch_is_detected(self):
        root = self.root()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "conf/urls.py", "urlpatterns = [path(PREFIX, include(site_patterns))]",
            "urlpatterns = [path(PREFIX, include(site_patterns + [path('signin/', views.sign_in_fast)]))]"))
        self.assertTrue(code & 1, findings)


# ============================================================================ flows switched off by settings
ALLAUTH_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "allauth", "allauth.account",
                  "allauth.socialaccount", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
"""
ALLAUTH_URLS = """\
from django.urls import include, path

urlpatterns = [path("accounts/", include("allauth.urls"))]
"""


class FlowConditionTests(unittest.TestCase):
    def root(self, extra=""):
        return project(self, {"conf/urls.py": ALLAUTH_URLS}, settings=ALLAUTH_SETTINGS, settings_extra=extra)

    @staticmethod
    def apis(rep):
        return {p["mint"]["api"] for p in rep["paths"] if p["entry"]["id"].startswith("route:accounts/|")}

    def test_library_defaults_switch_off_auto_logins_and_uninstalled_mfa(self):
        rep = scan(self.root())
        apis = self.apis(rep)
        self.assertIn("allauth.account.internal.flows.login.perform_login / resume_login", apis)
        self.assertIn("allauth.account.internal.flows.password_change.logout_on_password_change", apis)
        self.assertIn("allauth.socialaccount.internal.flows.login._login", apis)
        for off in ("allauth.account.internal.flows.password_reset.perform_password_reset_login",
                    "allauth.account.internal.flows.email_verification.login_on_verification",
                    "allauth.mfa.base.views.AuthenticateView.form_valid",
                    "allauth.mfa.internal.flows.trust.trust_browser"):
            self.assertNotIn(off, apis)
        listed = {d["mint"]: d["why"] for d in rep["coverage"]["library_flows_disabled_by_settings"]}
        self.assertIn("ACCOUNT_LOGIN_ON_PASSWORD_RESET unset",
                      listed["allauth.account.internal.flows.password_reset.perform_password_reset_login"])
        self.assertIn("allauth.mfa not in INSTALLED_APPS", listed["allauth.mfa.base.views.AuthenticateView.form_valid"])

    def test_headless_only_leaves_the_provider_callbacks(self):
        rep = scan(self.root("HEADLESS_ONLY = True\nACCOUNT_LOGOUT_ON_PASSWORD_CHANGE = True\n"))
        self.assertEqual(self.apis(rep), {"allauth.socialaccount.internal.flows.login._login"})

    def test_unknown_value_keeps_the_flow(self):
        rep = scan(self.root("import os\nACCOUNT_LOGIN_ON_PASSWORD_RESET = os.environ.get('X') == '1'\n"))
        self.assertIn("allauth.account.internal.flows.password_reset.perform_password_reset_login", self.apis(rep))

    def test_alternative_settings_modules_keep_the_flow_if_any_enables_it(self):
        root = self.root("if DEBUG_LOGIN:\n    ACCOUNT_LOGIN_ON_PASSWORD_RESET = True\n")
        self.assertIn("allauth.account.internal.flows.password_reset.perform_password_reset_login",
                      self.apis(scan(root)))

    def test_enabling_a_switched_off_flow_is_a_new_path(self):
        root = self.root("ACCOUNT_LOGIN_ON_PASSWORD_RESET = False\n")
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "conf/settings.py", "ACCOUNT_LOGIN_ON_PASSWORD_RESET = False", "ACCOUNT_LOGIN_ON_PASSWORD_RESET = True"))
        self.assertTrue(code & 1, findings)
        self.assertTrue([f for f in findings if f["kind"] == "new_path" and "perform_password_reset_login" in
                         json.dumps(f)], findings)


if __name__ == "__main__":
    unittest.main()

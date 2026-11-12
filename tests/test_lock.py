"""Lockfile, fingerprints (C6) and coverage regression (C7)."""
import copy
import unittest

from mm_testutil import scan, copy_fixture, write, read, accept_all, paths_for, one_path
from mintmap.core.lockfile import (build_lock, diff, merge_lock, NEW_PATH, REMOVED_PATH, FINGERPRINT_CHANGED,
                                   EVIDENCE_DOWNGRADED, PURPOSE_CHANGED, COVERAGE_REGRESSION, UNREVIEWED)

REFORMATTED_VIEWS = '''"""Views module docstring added."""
from django.contrib import auth
from django.contrib.auth import (
    aauthenticate,
    alogin,
    authenticate,
)
from django.contrib.auth import login as django_login
from django.http import HttpResponse
from django.views.generic import FormView
from django_otp import match_token

from .forms import EmailLoginForm
from .helpers import sign_in, verify_otp


def password_login(request):
    """Password login (docstring only)."""
    # a comment
    user = authenticate(
        request,
        username=request.POST['u'],
        password=request.POST['p'],
    )

    if user is None:
        return HttpResponse(status=401)   # trailing comment
    django_login(request, user)
    return HttpResponse('ok')


def otp_login_ignored(request):
    user = authenticate(request, username=request.POST['u'], password=request.POST['p'])
    if user is None:
        return HttpResponse(status=401)
    match_token(user, request.POST['otp'])
    django_login(request, user)
    return HttpResponse('ok')


def otp_login_wrapper(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    if not verify_otp(user,
                      request.POST["otp"]):
        return HttpResponse(status=401)
    sign_in(request, user)
    return HttpResponse("ok")


class EmailLoginView(FormView):
    """CBV docstring."""

    form_class = EmailLoginForm
    template_name = 'login.html'

    def form_valid(self, form):
        auth.login(self.request, form.get_user())
        return super().form_valid(form)


async def async_login(request):
    user = await aauthenticate(request, username='u', password='p')
    if (user is not None):
        await alogin(request, user)
    return HttpResponse('ok')
'''


class LockTests(unittest.TestCase):
    def setUp(self):
        self.root = copy_fixture(self, "basic_project")
        self.report = scan(self.root)
        self.lock = build_lock(self.report)

    def accepted(self):
        return accept_all(copy.deepcopy(self.lock))

    def kinds(self, findings, path_id=None):
        return {f["kind"] for f in findings if path_id is None or f["path_id"] == path_id}

    # ------------------------------------------------------------ review state
    def test_init_lock_is_unreviewed_and_fails(self):
        self.assertTrue(all(p["review_status"] == "unreviewed" for p in self.lock["paths"]))
        findings, code = diff(self.lock, scan(self.root))
        self.assertEqual(code, UNREVIEWED)

    def test_accepted_lock_unchanged_code_passes(self):
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, 0, findings)

    # ------------------------------------------------------------ fingerprints
    def test_formatting_only_change_keeps_fingerprints(self):
        before = {p["id"]: p["fingerprint"]["overall"] for p in self.report["paths"]}
        write(self.root, "accounts/views.py", REFORMATTED_VIEWS)
        after_report = scan(self.root)
        after = {p["id"]: p["fingerprint"]["overall"] for p in after_report["paths"]}
        self.assertEqual(before, after)
        findings, code = diff(self.accepted(), after_report)
        self.assertEqual(code, 0, findings)

    def test_helper_that_accepts_every_otp(self):
        helpers = read(self.root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n", "    return True\n")
        write(self.root, "accounts/helpers.py", helpers)
        findings, code = diff(self.accepted(), scan(self.root))
        otp_path = one_path(self, self.report, "route:login/otp/")["id"]
        self.assertTrue(code & FINGERPRINT_CHANGED and code & EVIDENCE_DOWNGRADED, findings)
        # v2: `verify_otp` (verification-looking name) now contains no check at all, so it is also reported
        # as an unrecognized_check_call gap on that path (coverage_regression)
        self.assertEqual(self.kinds(findings, otp_path),
                         {"fingerprint_changed", "evidence_downgraded", "coverage_regression"})
        changed = {f["path_id"] for f in findings if f["kind"] == "fingerprint_changed"}
        self.assertEqual(changed, {otp_path}, "only the path that uses the helper should need re-review")
        fc = [f for f in findings if f["kind"] == "fingerprint_changed"][0]
        # the helper is both a recognised check and a callee of the path; the path's own code is unchanged
        self.assertEqual(fc["components"], ["callees", "checks"])

    def test_helper_that_ignores_the_check_result(self):
        helpers = read(self.root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n",
            "    match_token(user, token)\n    return True\n")
        write(self.root, "accounts/helpers.py", helpers)
        new = scan(self.root)
        p = one_path(self, new, "route:login/otp/")
        c = [c for c in p["evidence"]["checks"] if c["check"] == "accounts.helpers.verify_otp"][0]
        self.assertEqual(c["relation"], "present_unproven")
        self.assertIn("can return success without the check", c["detail"])
        findings, code = diff(self.accepted(), new)
        self.assertTrue(code & EVIDENCE_DOWNGRADED)

    def test_settings_change_invalidates_every_path(self):
        # (v5, R7) changed expectation: a global settings change is ONE finding on the settings group entry
        # (v1-v5a: a fingerprint_changed finding on every path); no path depends on this middleware specifically
        s = read(self.root, "proj/settings.py").replace(
            '    "django_otp.middleware.OTPMiddleware",\n', "")
        write(self.root, "proj/settings.py", s)
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, FINGERPRINT_CHANGED)
        fc = [f for f in findings if f["kind"] == "fingerprint_changed"]
        self.assertEqual([f["path_id"] for f in fc], ["settings:MIDDLEWARE"])
        self.assertTrue(all(f["components"] == ["settings"] for f in fc))
        self.assertIn("OTPMiddleware", fc[0]["message"])

    def test_backend_setting_change_downgrades_password_factor(self):
        write(self.root, "accounts/backends.py",
              "class TrustingBackend:\n    def authenticate(self, request, username=None, password=None):\n"
              "        from django.contrib.auth.models import User\n"
              "        return User.objects.filter(username=username).first()\n")
        s = read(self.root, "proj/settings.py").replace(
            '"django.contrib.auth.backends.ModelBackend"', '"accounts.backends.TrustingBackend"')
        write(self.root, "proj/settings.py", s)
        new = scan(self.root)
        findings, code = diff(self.accepted(), new)
        self.assertTrue(code & EVIDENCE_DOWNGRADED, findings)
        p = one_path(self, new, "route:login/password/")
        self.assertEqual(p["evidence"]["status"], "guard_relies_on_unverified_check")

    def test_override_in_library_view_subclass_invalidates_library_path(self):
        root = copy_fixture(self, "edge_project")
        lock = accept_all(build_lock(scan(root)))
        av = read(root, "edge/auth_views.py").replace(
            '    template_name = "plain.html"\n',
            '    template_name = "plain.html"\n\n    def get_form_class(self):\n        return WeakForm\n')
        write(root, "edge/auth_views.py", av)
        findings, code = diff(lock, scan(root))
        plain = one_path(self, scan(root), "route:login/plain/")["id"]
        self.assertIn("fingerprint_changed", self.kinds(findings, plain))

    def test_library_upgrade_invalidates_paths_using_that_library(self):
        req = read(self.root, "requirements.txt").replace("django-allauth==65.16.1", "django-allauth==65.20.0")
        write(self.root, "requirements.txt", req)
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, FINGERPRINT_CHANGED)
        changed = [f for f in findings if f["kind"] == "fingerprint_changed"]
        self.assertTrue(changed and all(f["components"] == ["deps"] for f in changed))
        allauth_ids = {p["id"] for p in paths_for(self.report, "route:accounts/|allauth.urls")}
        self.assertEqual({f["path_id"] for f in changed}, allauth_ids)

    # ------------------------------------------------------------ new / removed
    def test_new_route_to_existing_wrapper_adds_path(self):
        write(self.root, "accounts/sso.py",
              "from .helpers import sign_in\n\n\ndef sso_callback(request):\n"
              "    user = request.session.get('pending_user')\n    sign_in(request, user)\n")
        urls = read(self.root, "accounts/urls.py").replace(
            "from . import views\n", "from . import sso, views\n").replace(
            "]\n", '    path("sso/callback/", sso.sso_callback),\n    path("login/otp-again/", views.otp_login_wrapper),\n]\n')
        write(self.root, "accounts/urls.py", urls)
        new = scan(self.root)
        findings, code = diff(self.accepted(), new)
        self.assertEqual(code, NEW_PATH, findings)
        new_ids = [f["path_id"] for f in findings if f["kind"] == "new_path"]
        self.assertEqual(len(new_ids), 2)
        sso = one_path(self, new, "route:sso/callback/")
        self.assertEqual(sso["evidence"]["status"], "no_check_found_in_analyzed_code")
        self.assertTrue(any("request.session" in n for n in sso["evidence"]["context"]))

    def test_removed_route_turns_mint_unrouted(self):
        # the view still exists and still mints: it is not dropped, it is re-reported as unrouted
        urls = read(self.root, "accounts/urls.py").replace(
            '    path("login/async/", views.async_login, name="async-login"),\n', "")
        write(self.root, "accounts/urls.py", urls)
        new = scan(self.root)
        findings, code = diff(self.accepted(), new)
        self.assertEqual(code, NEW_PATH | REMOVED_PATH, findings)
        self.assertEqual(len(paths_for(new, "unrouted:accounts.views.async_login")), 1)

    def test_removed_view_and_route(self):
        urls = read(self.root, "accounts/urls.py").replace(
            '    path("login/async/", views.async_login, name="async-login"),\n', "")
        write(self.root, "accounts/urls.py", urls)
        views = read(self.root, "accounts/views.py")
        write(self.root, "accounts/views.py", views[:views.index("async def async_login")])
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, REMOVED_PATH, findings)

    # ------------------------------------------------------------ coverage
    def test_new_parse_failure_is_coverage_regression(self):
        write(self.root, "accounts/broken.py", "def f(:\n    pass\n")
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, COVERAGE_REGRESSION, findings)

    def test_reduced_coverage_cannot_preserve_green(self):
        # the file that contains an approved mint stops parsing: the path disappears AND coverage drops
        write(self.root, "accounts/helpers.py", read(self.root, "accounts/helpers.py") + "\ndef oops(:\n")
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertTrue(code & COVERAGE_REGRESSION and code & REMOVED_PATH, findings)
        self.assertNotEqual(code, 0)

    def test_new_exclusion_is_coverage_regression(self):
        findings, code = diff(self.accepted(), scan(self.root, extra_excludes=["accounts"]))
        self.assertTrue(code & COVERAGE_REGRESSION)
        self.assertIn("new excluded directories", " ".join(f["message"] for f in findings))

    def test_new_unsupported_url_construct_is_regression(self):
        urls = read(self.root, "proj/urls.py").replace(
            "]\n", '    path("x/", build_view()),\n]\n')
        write(self.root, "proj/urls.py", urls)
        findings, code = diff(self.accepted(), scan(self.root))
        self.assertEqual(code, COVERAGE_REGRESSION, findings)

    # ------------------------------------------------------------ purpose / update
    def test_purpose_change_is_reported(self):
        lock = self.accepted()
        target = one_path(self, self.report, "route:login/password/")["id"]
        for p in lock["paths"]:
            if p["id"] == target:
                p["purpose"] = "mfa_challenge_state"  # simulate a catalog re-classification
        findings, code = diff(lock, scan(self.root))
        self.assertEqual(code, PURPOSE_CHANGED)

    def test_update_keeps_reviews_only_for_unchanged_paths(self):
        lock = self.accepted()
        helpers = read(self.root, "accounts/helpers.py").replace(
            "    device = match_token(user, token)\n    return device is not None\n", "    return True\n")
        write(self.root, "accounts/helpers.py", helpers)
        new_lock, notes = merge_lock(lock, scan(self.root))
        otp_path = one_path(self, self.report, "route:login/otp/")["id"]
        statuses = {p["id"]: p["review_status"] for p in new_lock["paths"]}
        self.assertEqual(statuses.pop(otp_path), "unreviewed")
        self.assertTrue(all(s == "accepted" for s in statuses.values()))
        changed = [p for p in new_lock["paths"] if p["id"] == otp_path][0]
        self.assertEqual(changed["previous_review"]["review_status"], "accepted")


if __name__ == "__main__":
    unittest.main()

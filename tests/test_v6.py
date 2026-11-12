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


# ============================================================================ session keys as patterns
PRINCIPAL_MODELS = """\
from django.db import models


class Patron(models.Model):
    email = models.EmailField()
    pin_hash = models.CharField(max_length=128)

    def get_session_auth_hash(self):
        return self.pin_hash[:8]
"""
SESSION_HELPERS = """\
import time

KEY_PREFIX = "patron_auth"


def patron_login(request, patron, club_id):
    key = f"{KEY_PREFIX}:{club_id}"
    request.session.cycle_key()
    request.session[key] = patron.pk
    request.session["patron_time:{}".format(club_id)] = int(time.time())


def current_patron(request, club_id):
    from club.models import Patron
    session = request.session
    key = f"{KEY_PREFIX}:{club_id}"
    return Patron.objects.filter(pk=session.get(key)).first()
"""
SESSION_VIEWS = """\
from django.http import HttpResponse
from club.models import Patron
from club.sessions import patron_login


def enter(request, club_id):
    patron = Patron.objects.get(email=request.POST["email"])
    if not patron.pin_hash.startswith(request.POST["pin"]):
        return HttpResponse(status=403)
    patron_login(request, patron, club_id)
    return HttpResponse("ok")
"""
SESSION_URLS = """\
from django.urls import path
from club import views
urlpatterns = [path("club/<int:club_id>/enter/", views.enter)]
"""


class SessionKeyPatternTests(unittest.TestCase):
    def files(self):
        return {"conf/urls.py": SESSION_URLS, "club/models.py": PRINCIPAL_MODELS, "club/sessions.py": SESSION_HELPERS,
                "club/views.py": SESSION_VIEWS}

    def test_computed_key_read_back_through_an_alias_is_a_confirmed_login(self):
        root = project(self, self.files(), init=("conf", "club"))
        rep = scan(root)
        p = one_path(self, rep, "route:club/<int:club_id>/enter/")
        self.assertEqual(p["mint"]["purpose"], "custom_session_login_candidate")
        self.assertEqual(p["mint"]["api"], "session[patron_auth:{}]")
        self.assertEqual(p["tier"], "confirmed")
        # the other writes of the same login function are part of that path, not separate candidates
        self.assertFalse(cands(rep))

    def test_removing_the_check_changes_the_path(self):
        root = project(self, self.files(), init=("conf", "club"))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", 'if not patron.pin_hash.startswith(request.POST["pin"]):', "if False:"))
        self.assertTrue(code & 4, findings)

    def test_key_nobody_reads_as_a_principal_is_not_confirmed(self):
        files = self.files()
        files["club/sessions.py"] = SESSION_HELPERS.split("def current_patron")[0]
        rep = scan(project(self, files, init=("conf", "club")))
        self.assertFalse(paths_for(rep, "route:club/<int:club_id>/enter/"))
        # still visible: a candidate (re-key + identifier under an auth-named key), reached from the route
        c = cand_for(self, rep, "patron_login", "session_state")
        self.assertEqual(c["candidate"]["rank"], "high")
        self.assertIn("route:club/<int:club_id>/enter/|club.views.enter", c["entry"]["reached_from"])


# ============================================================================ candidate tier: session state
HANDOFF = """\
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpResponse, HttpResponseForbidden


def accept_handoff(request):
    store = SessionStore(request.POST.get("handle"))
    data = store.load()
    parent = data.get("parent_key")
    if not parent:
        return HttpResponseForbidden()
    request.session["delegated_access"] = parent
    return HttpResponse("ok")


def start_handoff(request):
    otp = SessionStore()
    otp["parent_key"] = request.session.session_key
    otp.set_expiry(30)
    otp.save(must_create=True)
    return HttpResponse(otp.session_key)


def confirm_password_again(request):
    import time
    if not request.user.check_password(request.POST["password"]):
        return HttpResponseForbidden()
    request.session["reauth_done_at"] = time.time()
    return HttpResponse("ok")


def set_language(request):
    request.session["ui_language"] = request.POST["lang"]
    request.session["cart_id"] = request.POST["cart"]
    return HttpResponse("ok")
"""
HANDOFF_URLS = """\
from django.urls import path
from club import handoff
urlpatterns = [
    path("handoff/accept/", handoff.accept_handoff),
    path("handoff/start/", handoff.start_handoff),
    path("reauth/", handoff.confirm_password_again),
    path("lang/", handoff.set_language),
]
"""


class CandidateSessionTests(unittest.TestCase):
    def report(self, extra=None):
        files = {"conf/urls.py": HANDOFF_URLS, "club/handoff.py": HANDOFF}
        files.update(extra or {})
        self.root = project(self, files, init=("conf", "club"))
        return scan(self.root)

    def test_session_handoffs_are_high_rank_candidates(self):
        rep = self.report()
        a = cand_for(self, rep, "accept_handoff")
        self.assertEqual(a["candidate"]["rank"], "high")
        self.assertIn("session_value", a["candidate"]["signals"])
        s = cand_for(self, rep, "start_handoff")
        self.assertEqual(s["candidate"]["rank"], "high")
        self.assertIn("new_store_handed_out", s["candidate"]["signals"])
        self.assertEqual(a["tier"], "candidate")
        self.assertEqual(a["entry"]["kind"], "candidate_site")

    def test_step_up_timestamp_is_a_medium_candidate_and_ui_state_is_set_aside(self):
        rep = self.report()
        r = cand_for(self, rep, "confirm_password_again")
        self.assertEqual(r["candidate"]["rank"], "medium")
        self.assertIn("timestamp", r["candidate"]["signals"])
        self.assertFalse([c for c in cands(rep) if "set_language" in c["entry"]["id"]])
        aside = rep["coverage"]["candidates"]["set_aside"]
        self.assertTrue(any(x["function"].endswith("set_language") for x in aside), aside)
        # candidates are not confirmed paths and add no global gaps
        self.assertFalse([p for p in rep["paths"] if p.get("tier") == "candidate"])

    def test_one_review_entry_per_site_whatever_the_number_of_routes(self):
        urls = HANDOFF_URLS.replace('    path("lang/", handoff.set_language),',
                                    '    path("lang/", handoff.set_language),\n'
                                    '    path("handoff/accept2/", handoff.accept_handoff),')
        rep = self.report({"conf/urls.py": urls})
        a = cand_for(self, rep, "accept_handoff")
        self.assertEqual(len(a["entry"]["reached_from"]), 2)


class CandidateLockTests(unittest.TestCase):
    def setUp(self):
        self.root = project(self, {"conf/urls.py": HANDOFF_URLS, "club/handoff.py": HANDOFF}, init=("conf", "club"))

    def test_groups_in_the_lock_and_unchanged_diff(self):
        lock = build_lock(scan(self.root))
        ids = [g["id"] for g in lock["candidates"]]
        self.assertEqual(ids, ["candidates:session_state"])
        self.assertEqual(len(lock["candidates"][0]["members"]), 3)
        findings, code = diff(lock, scan(self.root))
        self.assertEqual(code, 64, findings)
        self.assertTrue(any(f["path_id"] == "candidates:session_state" for f in findings))
        findings, code = diff(accept_all(lock), scan(self.root))
        self.assertEqual(code, 0, findings)

    def test_member_changes_are_findings_naming_the_member(self):
        lock = accept_all(build_lock(scan(self.root)))
        replace_in(self.root, "club/handoff.py", "    if not parent:\n        return HttpResponseForbidden()\n", "")
        findings, code = diff(lock, scan(self.root))
        self.assertEqual(code, 4, findings)
        f = [f for f in findings if f["kind"] == "fingerprint_changed"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["tier"], "candidate")
        self.assertIn("accept_handoff", f[0]["message"])

    def test_new_entry_point_new_member_removed_member(self):
        lock = accept_all(build_lock(scan(self.root)))
        replace_in(self.root, "conf/urls.py", '    path("lang/", handoff.set_language),',
                   '    path("lang/", handoff.set_language),\n    path("handoff/again/", handoff.accept_handoff),')
        findings, code = diff(lock, scan(self.root))
        self.assertEqual(code, 4, findings)
        self.assertIn("now also reached from route:handoff/again/", findings[0]["message"])
        # a new candidate site is a new path; a vanished one a removed path
        write(self.root, "club/more.py", textwrap.dedent("""\
            from django.http import HttpResponse


            def impersonate(request, uid):
                request.session.cycle_key()
                request.session["impersonator_id"] = request.user.pk
                return HttpResponse("ok")
        """))
        replace_in(self.root, "conf/urls.py", "from club import handoff", "from club import handoff, more")
        replace_in(self.root, "conf/urls.py", '    path("lang/", handoff.set_language),',
                   '    path("lang/", handoff.set_language),\n    path("imp/<int:uid>/", more.impersonate),')
        replace_in(self.root, "conf/urls.py", '    path("reauth/", handoff.confirm_password_again),\n', "")
        replace_in(self.root, "club/handoff.py", 'request.session["reauth_done_at"] = time.time()', "pass")
        findings, code = diff(lock, scan(self.root))
        self.assertTrue(code & 1 and code & 2, findings)
        new = [f for f in findings if f["kind"] == "new_path"]
        self.assertTrue(new and "impersonator_id" in new[0]["message"], findings)

    def test_update_keeps_the_review_of_an_unchanged_group(self):
        lock = accept_all(build_lock(scan(self.root)))
        new, notes = merge_lock(lock, scan(self.root))
        self.assertEqual(new["candidates"][0]["review_status"], "accepted")
        replace_in(self.root, "club/handoff.py", "otp.set_expiry(30)", "otp.set_expiry(3000)")
        new, notes = merge_lock(lock, scan(self.root))
        self.assertEqual(new["candidates"][0]["review_status"], "unreviewed")

    def test_cli_lists_candidates_and_accepts_groups(self):
        r = subprocess.run([sys.executable, "-I", CLI, "scan", self.root], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("candidates:session_state", r.stdout)
        self.assertIn("accept_handoff", r.stdout)
        lockp = os.path.join(self.root, "mintmap.lock")
        self.assertEqual(subprocess.run([sys.executable, "-I", CLI, "init", self.root, "--lock", lockp],
                                        capture_output=True, text=True, timeout=120).returncode, 0)
        r = subprocess.run([sys.executable, "-I", CLI, "accept", self.root, "candidates:session_state", "--reviewer",
                            "t", "--lock", lockp], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("accepted candidates:session_state", r.stdout)
        r = subprocess.run([sys.executable, "-I", CLI, "diff", self.root, "--lock", lockp], capture_output=True,
                           text=True, timeout=120)
        self.assertNotIn("candidates:session_state", r.stdout)
        r = subprocess.run([sys.executable, "-I", CLI, "accept", self.root, "--all", "--reviewer", "t", "--lock",
                            lockp], capture_output=True, text=True, timeout=120)
        r = subprocess.run([sys.executable, "-I", CLI, "diff", self.root, "--lock", lockp], capture_output=True,
                           text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout)


# ============================================================================ related managers, CreateView
TEAM_MODELS = """\
from django.db import models
from django.conf import settings
from club.gen import new_secret


class Team(models.Model):
    name = models.CharField(max_length=20)


class TeamKey(models.Model):
    team = models.ForeignKey(Team, related_name="keys", on_delete=models.CASCADE)
    label = models.CharField(max_length=20)
    secret = models.CharField(max_length=64, default=new_secret)


class Gadget(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    pairing_secret = models.CharField(max_length=32, default=new_secret)
"""
TEAM_GEN = """\
import secrets


def new_secret():
    return secrets.token_hex(32)
"""
TEAM_VIEWS = """\
from django.http import HttpResponse
from django.views.generic.edit import CreateView
from club.models import Team, Gadget


def add_key(request, team_id):
    team = Team.objects.get(pk=team_id)
    key = team.keys.create(label=request.POST["label"])
    return HttpResponse(key.secret)


class GadgetCreate(CreateView):
    model = Gadget
    fields = ["owner"]

    def form_valid(self, form):
        form.instance.owner = self.request.user
        return super().form_valid(form)


class GadgetCreateNoSave(CreateView):
    model = Gadget
    fields = ["owner"]

    def form_valid(self, form):
        return HttpResponse("preview only")
"""
TEAM_URLS = """\
from django.urls import path
from club import views
urlpatterns = [
    path("team/<int:team_id>/keys/", views.add_key),
    path("gadgets/new/", views.GadgetCreate.as_view()),
    path("gadgets/preview/", views.GadgetCreateNoSave.as_view()),
]
"""


class RelatedManagerTests(unittest.TestCase):
    def setUp(self):
        self.root = project(self, {"conf/urls.py": TEAM_URLS, "club/models.py": TEAM_MODELS, "club/gen.py": TEAM_GEN,
                                   "club/views.py": TEAM_VIEWS}, init=("conf", "club"))
        self.rep = scan(self.root)

    def test_reverse_relation_create_of_a_credential_model(self):
        p = one_path(self, self.rep, "route:team/<int:team_id>/keys/")
        self.assertEqual(p["mint"]["api"], "club.models.TeamKey via keys.create")

    def test_create_view_saving_a_credential_model(self):
        p = one_path(self, self.rep, "route:gadgets/new/")
        self.assertEqual(p["mint"]["api"], "club.models.Gadget via django CreateView")
        self.assertFalse(paths_for(self.rep, "route:gadgets/preview/"))

    def test_weakening_the_generator_changes_both_paths(self):
        lock = accept_all(build_lock(self.rep))
        replace_in(self.root, "club/gen.py", "secrets.token_hex(32)", "secrets.token_hex(2)")
        findings, code = diff(lock, scan(self.root))
        self.assertTrue(code & 4, findings)
        self.assertEqual(len([f for f in findings if f["kind"] == "fingerprint_changed"]), 2, findings)


# ============================================================================ library flows called from project code
SOCIAL_VIEWS = """\
from django.views.decorators.csrf import csrf_exempt
from social_django.views import complete


@csrf_exempt
def finish_sso(request, backend):
    request.session["sso_started"] = False
    return complete(request, backend)
"""
SOCIAL_PIPELINE = """\
def require_known_domain(strategy, details, user=None, *args, **kwargs):
    if not details.get("email", "").endswith("@example.org"):
        raise ValueError("unknown domain")
"""


class LibraryFlowCallTests(unittest.TestCase):
    def test_function_view_called_directly_mints_at_the_calling_route_with_its_hooks(self):
        files = {"conf/urls.py": """\
                    from django.urls import path
                    from club.sso import finish_sso
                    urlpatterns = [path("sso/<str:backend>/done/", finish_sso)]
                 """, "club/sso.py": SOCIAL_VIEWS, "club/pipeline.py": SOCIAL_PIPELINE}
        settings = 'SOCIAL_AUTH_PIPELINE = ["social_core.pipeline.social_auth.social_details", ' \
                   '"club.pipeline.require_known_domain", "social_core.pipeline.user.user_details"]\n'
        root = project(self, files, init=("conf", "club"), settings_extra=settings)
        p = one_path(self, scan(root), "route:sso/<str:backend>/done/", "social_django.views.complete")
        self.assertIn("called directly from club.sso.finish_sso", p["mint"]["purpose_note"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/pipeline.py", 'raise ValueError("unknown domain")', "pass"))
        self.assertTrue(code & 4, findings)


# ============================================================================ admin site swapped in a function
ADMIN_SITE = """\
from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth import login as auth_login
from django.http import HttpResponse


class ClubAdminSite(AdminSite):
    def login(self, request, extra_context=None):
        user = self.find_user(request)
        if user is None:
            return HttpResponse(status=403)
        auth_login(request, user)
        return HttpResponse("ok")

    def find_user(self, request):
        return None


CLUB_SITE = ClubAdminSite()


def install_site():
    admin.site = CLUB_SITE
"""


class AdminSiteSwapTests(unittest.TestCase):
    def files(self):
        return {"conf/urls.py": """\
                    from django.contrib import admin
                    from django.urls import path
                    urlpatterns = [path("admin/", admin.site.urls)]
                """, "club/sites.py": ADMIN_SITE, "club/apps.py": """\
                    from django.apps import AppConfig


                    class ClubConfig(AppConfig):
                        name = "club"

                        def ready(self):
                            from club.sites import install_site
                            install_site()
                """}

    def test_swap_inside_a_function_runs_the_project_login(self):
        root = project(self, self.files(), init=("conf", "club"))
        rep = scan(root)
        apis = {p["mint"]["api"] for p in paths_for(rep, "route:admin/")}
        self.assertIn("django.contrib.auth.login", apis)
        self.assertNotIn("django.contrib.admin.sites.AdminSite.login", apis)
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/sites.py", "        if user is None:\n            return HttpResponse(status=403)\n", ""))
        self.assertTrue(code & 4, findings)

    def test_default_site_of_an_admin_config(self):
        files = self.files()
        files["club/apps.py"] = """\
            from django.contrib.admin.apps import AdminConfig


            class ClubAdminConfig(AdminConfig):
                default_site = "club.sites.ClubAdminSite"
        """
        settings = 'INSTALLED_APPS = ["club.apps.ClubAdminConfig", "django.contrib.auth", "club"]\n'
        rep = scan(project(self, files, init=("conf", "club"), settings_extra=settings))
        apis = {p["mint"]["api"] for p in paths_for(rep, "route:admin/")}
        self.assertIn("django.contrib.auth.login", apis)


# ============================================================================ URL builders and helpers
class UrlBuilderTests(unittest.TestCase):
    def report(self, client):
        files = {"conf/urls.py": f"""\
                    from allauth.headless.constants import Client
                    from allauth.headless.urls import build_urlpatterns
                    from django.urls import include, path
                    urlpatterns = [
                        path("api/auth/", include((build_urlpatterns(Client.{client}), "headless"), namespace="b")),
                    ]
                 """}
        return scan(project(self, files, init=("conf",)))

    def test_builder_exposes_the_catalogued_flows_narrowed_by_its_argument(self):
        rep = self.report("BROWSER")
        apis = {p["mint"]["api"] for p in paths_for(rep, "route:api/auth/|allauth.headless.urls")}
        self.assertIn("allauth.headless.account.views.LoginView.post", apis)
        self.assertFalse([a for a in apis if "JWTTokenStrategy" in a or "expose_session_token" in a], apis)
        self.assertFalse(gaps(rep, "unsupported_url_construct"))
        rep = self.report("APP")
        apis = {p["mint"]["api"] for p in paths_for(rep, "route:api/auth/|allauth.headless.urls")}
        self.assertTrue([a for a in apis if "JWTTokenStrategy" in a], apis)

    def test_unknown_library_helper_wrapping_path_is_read_as_a_conditional_route(self):
        files = {"conf/urls.py": """\
                    from django.urls import include
                    from flags.urls import flagged_path
                    urlpatterns = [flagged_path("OAUTH", "o/", include("oauth2_provider.urls"))]
                 """}
        rep = scan(project(self, files, init=("conf",)))
        ps = paths_for(rep, "route:o/|oauth2_provider.urls")
        self.assertTrue(ps)
        self.assertTrue(all(p["entry"]["route"]["conditional"] for p in ps))
        self.assertTrue(gaps(rep, "url_helper_read_as_path"))


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


class SettingsFactoryTests(unittest.TestCase):
    def test_settings_returned_by_a_project_factory_function_are_evaluated(self):
        files = {"conf/urls.py": "urlpatterns = []\n", "conf/api.py": """\
                    def api_settings(*, strict):
                        \"\"\"Shared DRF settings.\"\"\"
                        return {
                            "DEFAULT_AUTHENTICATION_CLASSES": [
                                "club.auth.KeyAuthentication",
                                "rest_framework.authentication.SessionAuthentication",
                            ],
                            "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
                        }
                 """, "club/auth.py": """\
                    from rest_framework.authentication import TokenAuthentication


                    class KeyAuthentication(TokenAuthentication):
                        keyword = "Key"
                 """}
        root = project(self, files, init=("conf", "club"),
                       settings_extra="from conf.api import api_settings\nREST_FRAMEWORK = api_settings(strict=True)\n")
        rep = scan(root)
        self.assertFalse([g for g in gaps(rep, "dynamic_setting") if "REST_FRAMEWORK" in g["key"]])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "conf/api.py", '"rest_framework.authentication.SessionAuthentication",',
            '"rest_framework.authentication.SessionAuthentication",\n'
            '                "rest_framework.authentication.BasicAuthentication",'))
        self.assertTrue(code & 4, findings)
        self.assertTrue(any("BasicAuthentication" in f["message"] for f in findings), findings)


# ============================================================================ unregistered minting subclasses
class MintingSubclassTests(unittest.TestCase):
    def test_subclass_nobody_registers_is_a_candidate_and_fingerprinted(self):
        files = {"conf/urls.py": "urlpatterns = []\n", "club/mw.py": HEADER_MW}
        settings = "HEADER_LOGIN = False\nimport os\nMIDDLEWARE = os.environ['MW'].split(',')\n"
        root = project(self, files, init=("conf", "club"), settings_extra=settings)
        rep = scan(root)
        c = [c for c in cands(rep, "minting_subclass") if c["entry"]["view"].endswith("HeaderLoginMiddleware")
             or "HeaderLoginMiddleware" in str(c["entry"]["reached_from"])]
        self.assertTrue(c, cands(rep))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/mw.py", "        if not settings.HEADER_LOGIN:\n            return None\n", ""))
        self.assertTrue(code & 4, findings)
        self.assertTrue(all(f.get("tier") == "candidate" for f in findings if f["kind"] != "info"), findings)


# ============================================================================ password set / auth library calls
PW_VIEWS = """\
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from allauth.account.internal.flows.reauthentication import reauthenticate_by_password


def admin_set_password(request, uid):
    user = get_user_model().objects.get(pk=uid)
    user.set_password(request.POST["password"])
    user.save()
    return HttpResponse("ok")


def change_own_password(request):
    request.user.set_password(request.POST["password"])
    request.user.save()
    return HttpResponse("ok")


def dummy_hash(request):
    get_user_model()().set_password(request.POST["password"])
    return HttpResponse("ok")


def step_up(request):
    reauthenticate_by_password(request)
    return HttpResponse("ok")
"""


class PasswordAndLibraryCallTests(unittest.TestCase):
    def setUp(self):
        urls = """\
            from django.urls import path
            from club import pw
            urlpatterns = [
                path("users/<int:uid>/pw/", pw.admin_set_password),
                path("me/pw/", pw.change_own_password),
                path("dummy/", pw.dummy_hash),
                path("stepup/", pw.step_up),
            ]
        """
        self.rep = scan(project(self, {"conf/urls.py": urls, "club/pw.py": PW_VIEWS}, init=("conf", "club")))

    def test_password_chosen_for_another_account_is_a_candidate(self):
        c = cand_for(self, self.rep, "admin_set_password", "password_set")
        self.assertIn("route:users/<int:uid>/pw/|club.pw.admin_set_password", c["entry"]["reached_from"])
        self.assertFalse([c for c in cands(self.rep, "password_set") if "change_own_password" in c["entry"]["id"]
                          or "dummy_hash" in c["entry"]["id"]])

    def test_request_handed_to_an_uncatalogued_auth_function(self):
        c = cand_for(self, self.rep, "step_up", "auth_library_call")
        self.assertIn("reauthenticate_by_password", c["candidate"]["reason"])


# ============================================================================ generic signing primitives
SIGN_VIEWS = """\
from django.core import signing
from django.http import HttpResponse


def order_link(request, order_id):
    return HttpResponse(signing.dumps({"order": order_id}))


def make_login_token(member):
    return signing.dumps({"m": member.pk})


def handoff(request):
    blob = signing.dumps({"user": request.user.pk})
    return HttpResponse(blob)


def send_link(request):
    return HttpResponse(make_login_token(request.user))
"""


class SignedValueTests(unittest.TestCase):
    def test_only_credential_like_signed_values_are_mints(self):
        urls = """\
            from django.urls import path
            from club import sign
            urlpatterns = [path("o/<int:order_id>/", sign.order_link), path("h/", sign.handoff),
                           path("s/", sign.send_link)]
        """
        rep = scan(project(self, {"conf/urls.py": urls, "club/sign.py": SIGN_VIEWS}, init=("conf", "club")))
        self.assertFalse(paths_for(rep, "route:o/<int:order_id>/"))
        one_path(self, rep, "route:h/")
        one_path(self, rep, "route:s/")
        aside = rep["coverage"]["custom_credentials"]["set_aside"]
        self.assertTrue(any(x["function"].endswith("order_link") for x in aside), aside)


# ============================================================================ receivers, admin passwords, generators
RECEIVER_MODELS = """\
import secrets
from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class AccessKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    secret = models.CharField(max_length=64)


class Member(models.Model):
    name = models.CharField(max_length=20)


@receiver(post_save, sender=Member)
def give_key(sender, instance, created=False, **kwargs):
    if created:
        AccessKey.objects.create(user_id=instance.pk, secret=secrets.token_hex(20))
"""
RECEIVER_VIEWS = """\
from django.http import HttpResponse
from club.models import Member


def rename(request, pk):
    m = Member.objects.get(pk=pk)
    m.name = request.POST["name"]
    m.save()
    return HttpResponse("ok")


def join(request):
    Member.objects.create(name=request.POST["name"])
    return HttpResponse("ok")
"""
APP_MODEL = """\
from django.db import models
from oauth2_provider.generators import generate_client_secret


class ClientApp(models.Model):
    name = models.CharField(max_length=20)
    client_secret = models.CharField(max_length=255)


def rotate(request, pk):
    from django.http import HttpResponse
    app = ClientApp.objects.get(pk=pk)
    app.client_secret = generate_client_secret()
    app.save()
    return HttpResponse(app.client_secret)
"""


class ReceiverAndAdminTests(unittest.TestCase):
    def test_created_guarded_receiver_runs_only_for_creations(self):
        urls = """\
            from django.urls import path
            from club import views
            urlpatterns = [path("m/<int:pk>/rename/", views.rename), path("join/", views.join)]
        """
        rep = scan(project(self, {"conf/urls.py": urls, "club/models.py": RECEIVER_MODELS,
                                  "club/views.py": RECEIVER_VIEWS}, init=("conf", "club")))
        self.assertTrue(paths_for(rep, "route:join/"))
        self.assertFalse(paths_for(rep, "route:m/<int:pk>/rename/"))

    def test_admin_add_view_is_an_admin_chosen_password(self):
        urls = """\
            from django.contrib import admin
            from django.urls import path
            urlpatterns = [path("admin/", admin.site.urls)]
        """
        rep = scan(project(self, {"conf/urls.py": urls}, init=("conf",)))
        p = [p for p in paths_for(rep, "route:admin/") if "UserAdmin.add_view" in p["mint"]["api"]]
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["mint"]["purpose"], "admin_chosen_password")

    def test_catalogued_library_secret_generator(self):
        urls = """\
            from django.urls import path
            from club import models
            urlpatterns = [path("apps/<int:pk>/rotate/", models.rotate)]
        """
        rep = scan(project(self, {"conf/urls.py": urls, "club/models.py": APP_MODEL}, init=("conf", "club")))
        p = one_path(self, rep, "route:apps/<int:pk>/rotate/")
        self.assertEqual(p["mint"]["api"], "oauth2_provider.generators.generate_client_secret")


if __name__ == "__main__":
    unittest.main()

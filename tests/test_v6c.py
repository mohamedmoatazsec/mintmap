"""v6 part B: precision, change detection and review cost.

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    ExtractMethodTests         "extract method" (`self._audit(request, user)` with the moved statements in a method of
                               the same class) and helpers called with attribute-chain arguments
                               (`_audit(user, request.META)`) keep the fingerprint; the helper's later changes are
                               detected; an override in a subclass, an argument the helper re-assigns, and a public
                               method of a class that inherits a library flow are still conservative
    CustomCredentialPrecisionTests  heuristic custom credentials: a callable named only by an action word
                               (`ctx.reset(...)`) or a predicate (`check_token(v)`) does not keep a credential; an
                               integration word (`webhook_token`) vetoes a strong head noun; `session` does not
                               qualify itself (`_session_wizard_prefix`); test-helper packages are test code
    SessionPrincipalTests      a session value that looks up an event / payment / workspace (also through
                               get_object_or_404) is flow state, not a hand-rolled login; a customer / account /
                               object attached to the request still is
    StartupOnlyTests           mint sites that only AppConfig.ready(), import-time calls (settings), management
                               commands or migration defaults reach are `candidates:startup_only` (low), not paths
    ReviewQueueTests           every path / candidate site carries a review block (group = credential kind or
                               candidate kind, risk, why); the text report is a review queue grouped by kind and entry
                               point; `accept --group` accepts one group; a lock written before v6b (no review block)
                               still diffs clean
"""
import json
import os
import textwrap
import unittest

from mm_testutil import scan, one_path, read, write
from test_v5 import project, run_diff
from test_v6 import replace_in


# ============================================================================ extract method / attribute arguments
CBV_VIEWS = """\
import logging

from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from django.http import HttpResponse, HttpResponseForbidden
from django.views import View

logger = logging.getLogger(__name__)


class SignIn(View):
    def post(self, request):
        user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
        if user is None:
            return HttpResponseForbidden()
        logger.info("sign-in %s", user.pk)
        stamp = {"ip": request.META.get("REMOTE_ADDR"), "agent": request.headers.get("user-agent")}
        logger.info("audit %s", stamp)
        login(request, user)
        return HttpResponse("ok")


class PortalLogin(LoginView):
    template_name = "portal/login.html"

    def get_success_url(self):
        target = self.request.GET.get("next") or "/"
        logger.info("redirect %s", target)
        return target
"""
CBV_URLS = """\
from django.urls import path
from shop.views import PortalLogin, SignIn
urlpatterns = [path("in/", SignIn.as_view()), path("portal/", PortalLogin.as_view())]
"""
SIGNIN_BLOCK = """\
        logger.info("sign-in %s", user.pk)
        stamp = {"ip": request.META.get("REMOTE_ADDR"), "agent": request.headers.get("user-agent")}
        logger.info("audit %s", stamp)
"""
SIGNIN_METHOD = """\
    def _audit(self, request, user):
        logger.info("sign-in %s", user.pk)
        stamp = {"ip": request.META.get("REMOTE_ADDR"), "agent": request.headers.get("user-agent")}
        logger.info("audit %s", stamp)

    def post(self, request):
"""
PORTAL_BLOCK = """\
        target = self.request.GET.get("next") or "/"
        logger.info("redirect %s", target)
        return target
"""


def cbv_project(tc, views=CBV_VIEWS, extra=None):
    files = {"conf/urls.py": CBV_URLS, "shop/views.py": views}
    files.update(extra or {})
    return project(tc, files)


class ExtractMethodTests(unittest.TestCase):
    def extract_signin(self, root, name="_audit"):
        text = read(root, "shop/views.py").replace(SIGNIN_BLOCK, f"        self.{name}(request, user)\n")
        text = text.replace("    def post(self, request):\n", SIGNIN_METHOD.replace("_audit", name), 1)
        write(root, "shop/views.py", text)

    def test_extract_method_keeps_the_fingerprint(self):
        root = cbv_project(self)
        findings, code = run_diff(self, root, lambda: self.extract_signin(root))
        self.assertEqual(code, 0, findings)

    def test_extract_public_method_with_a_return_value(self):
        root = cbv_project(self)

        def mutate():
            text = read(root, "shop/views.py").replace(
                '        stamp = {"ip": request.META.get("REMOTE_ADDR"), "agent": request.headers.get("user-agent")}\n',
                "        stamp = self.client_info(request)\n")
            text = text.replace("    def post(self, request):\n",
                                '    def client_info(self, request):\n'
                                '        return {"ip": request.META.get("REMOTE_ADDR"), '
                                '"agent": request.headers.get("user-agent")}\n\n'
                                "    def post(self, request):\n", 1)
            write(root, "shop/views.py", text)
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_a_later_change_of_the_extracted_method_is_detected(self):
        root = cbv_project(self)
        self.extract_signin(root)

        def mutate():
            replace_in(root, "shop/views.py", '        logger.info("audit %s", stamp)\n',
                       '        logger.info("audit %s", stamp)\n        request.session["trusted"] = user.pk\n')
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_method_overridden_in_a_subclass_is_not_inlined(self):
        sub = CBV_VIEWS + textwrap.dedent("""\


            class QuietSignIn(SignIn):
                def _audit(self, request, user):
                    pass
            """)
        root = cbv_project(self, sub)
        findings, code = run_diff(self, root, lambda: self.extract_signin(root))
        self.assertTrue(code & 4, findings)

    def test_attribute_chain_arguments_are_substituted(self):
        root = cbv_project(self)
        helper = textwrap.dedent('''\


            def _audit(user, meta, headers):
                logger.info("sign-in %s", user.pk)
                stamp = {"ip": meta.get("REMOTE_ADDR"), "agent": headers.get("user-agent")}
                logger.info("audit %s", stamp)
            ''')

        def mutate():
            text = read(root, "shop/views.py").replace(SIGNIN_BLOCK,
                                                       "        _audit(user, request.META, request.headers)\n")
            write(root, "shop/views.py", text + helper)
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_argument_whose_attribute_the_helper_assigns_is_not_substituted(self):
        root = cbv_project(self)
        helper = textwrap.dedent('''\


            def _audit(user, meta, headers):
                logger.info("sign-in %s", user.pk)
                user.META = {}
                stamp = {"ip": meta.get("REMOTE_ADDR"), "agent": headers.get("user-agent")}
                logger.info("audit %s", stamp)
            ''')

        def mutate():
            text = read(root, "shop/views.py").replace(SIGNIN_BLOCK,
                                                       "        _audit(user, request.META, request.headers)\n")
            write(root, "shop/views.py", text + helper)
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def extract_portal(self, root, name):
        text = read(root, "shop/views.py").replace(PORTAL_BLOCK, f"        return self.{name}()\n")
        text = text.replace("    def get_success_url(self):\n",
                            f"    def {name}(self):\n" + PORTAL_BLOCK + "\n    def get_success_url(self):\n", 1)
        write(root, "shop/views.py", text)

    def test_private_method_of_a_library_flow_class(self):
        # the whole class is hashed for a library flow; the private helper's body is in get_success_url's dump
        root = cbv_project(self)
        p = one_path(self, scan(root), "route:portal/")
        self.assertIn("LoginView", p["mint"]["api"])
        findings, code = run_diff(self, root, lambda: self.extract_portal(root, "_target"))
        self.assertEqual(code, 0, findings)

    def test_change_of_an_omitted_private_method_is_detected(self):
        root = cbv_project(self)
        self.extract_portal(root, "_target")
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/views.py", 'self.request.GET.get("next") or "/"', 'self.request.GET.get("next")'))
        self.assertTrue(code & 4, findings)

    def test_public_method_of_a_library_flow_class_is_conservative(self):
        # the library may call a public method by name (a hook it defines): adding one changes the class dump
        root = cbv_project(self)
        findings, code = run_diff(self, root, lambda: self.extract_portal(root, "pick_target"))
        self.assertTrue(code & 4, findings)

    def test_private_helper_called_from_elsewhere_stays_in_the_class_dump(self):
        root = cbv_project(self)
        self.extract_portal(root, "_target")

        def mutate():
            write(root, "shop/other.py", "def peek(view):\n    return view._target()\n")
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)



# ============================================================================ custom-credential precision
CRED_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
"""
CRED_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("a/", views.a), path("b/", views.b), path("c/", views.c), path("d/", views.d),
               path("e/", views.e)]
"""
CRED_VIEWS = """\
import contextvars
import uuid

from django.http import HttpResponse
from django.utils.crypto import get_random_string

from shop.helpers import check_token, store_reset_token

_trace = contextvars.ContextVar("trace", default=None)


def a(request):
    marker = _trace.set(uuid.uuid4().hex)
    try:
        return HttpResponse("ok")
    finally:
        _trace.reset(marker)


def b(request):
    if check_token(get_random_string(12)):
        return HttpResponse("ok")
    return HttpResponse("no")


def c(request):
    request.session["integration_webhook_token"] = get_random_string(32)
    return HttpResponse("ok")


def d(request):
    request._session_wizard_prefix = get_random_string(8)
    return HttpResponse("ok")


def e(request):
    store_reset_token(request.user, uuid.uuid4().hex)
    return HttpResponse("ok")
"""
CRED_HELPERS = """\
def check_token(value):
    return len(value) == 12


def store_reset_token(user, value):
    user.profile_note = value
"""


class CustomCredentialPrecisionTests(unittest.TestCase):
    def project(self, extra=None):
        files = {"conf/urls.py": CRED_URLS, "shop/views.py": CRED_VIEWS, "shop/helpers.py": CRED_HELPERS}
        files.update(extra or {})
        return project(self, files, settings=CRED_SETTINGS)

    def test_only_the_credential_named_store_is_a_mint(self):
        rep = scan(self.project())
        routes = sorted({p["entry"]["id"].split("|")[0] for p in rep["paths"]})
        self.assertEqual(routes, ["route:e/"], [(p["entry"]["id"], p["mint"]) for p in rep["paths"]])
        aside = " ".join(str(r) for r in rep["coverage"]["custom_credentials"]["set_aside"])
        self.assertIn("integration secret", aside)

    def test_test_helper_package_is_test_code(self):
        root = self.project({"shop/testutils/__init__.py": "",
                             "shop/testutils/tokens.py": "from django.utils.crypto import get_random_string\n\n\n"
                                                         "def make_api_token():\n"
                                                         "    return get_random_string(40)\n"})
        rep = scan(root)
        self.assertFalse([p for p in rep["paths"] if "testutils" in p["entry"]["id"]])
        self.assertIn("in a test-helper package (testutils/, test_utils/)",
                      rep["coverage"]["test_code"]["excluded_by_reason"])


# ============================================================================ session values that load a principal
SP_MODELS = """\
from django.db import models


class Event(models.Model):
    name = models.CharField(max_length=10)


class Customer(models.Model):
    email = models.EmailField()
"""
SP_VIEWS = """\
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

from shop.models import Customer, Event


def start_connect(request, pk):
    request.session["connect_event"] = pk
    return HttpResponse("ok")


def connect_return(request):
    event = get_object_or_404(Event, pk=request.session["connect_event"])
    return HttpResponse(event.name)


def customer_login(request, pk):
    request.session["portal_customer"] = pk
    return HttpResponse("ok")


def portal(request):
    customer = Customer.objects.filter(pk=request.session.get("portal_customer")).first()
    return HttpResponse(customer.email)
"""
SP_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("connect/<int:pk>/", views.start_connect), path("connect/return/", views.connect_return),
               path("portal/login/<int:pk>/", views.customer_login), path("portal/", views.portal)]
"""
SP_ATTACHED = """\
    request.event_visitor = get_object_or_404(Event, pk=request.session["connect_event"])
    return HttpResponse("ok")
"""


class SessionPrincipalTests(unittest.TestCase):
    def test_event_id_in_the_session_is_flow_state(self):
        root = project(self, {"conf/urls.py": SP_URLS, "shop/views.py": SP_VIEWS, "shop/models.py": SP_MODELS})
        rep = scan(root)
        apis = sorted(p["mint"]["api"] for p in rep["paths"])
        self.assertIn("session[portal_customer]", apis)
        self.assertNotIn("session[connect_event]", apis)
        aside = rep["coverage"]["custom_credentials"]["session_lookups_set_aside"]
        self.assertTrue([r for r in aside if r["key"] == "connect_event" and "Event" in r["reason"]], aside)

    def test_object_attached_to_the_request_is_a_principal(self):
        views = SP_VIEWS.replace('    event = get_object_or_404(Event, pk=request.session["connect_event"])\n'
                                 '    return HttpResponse(event.name)\n', SP_ATTACHED)
        root = project(self, {"conf/urls.py": SP_URLS, "shop/views.py": views, "shop/models.py": SP_MODELS})
        apis = sorted(p["mint"]["api"] for p in scan(root)["paths"])
        self.assertIn("session[connect_event]", apis)


# ============================================================================ start-up only mint sites
SU_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "rest_framework.authtoken",
                  "shop.apps.ShopConfig"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
from shop.keys import bootstrap_api_token
BOOTSTRAP_API_TOKEN = bootstrap_api_token()
"""
SU_APPS = """\
from django.apps import AppConfig


class ShopConfig(AppConfig):
    name = "shop"

    def ready(self):
        from shop.bootstrap import ensure_service_token
        ensure_service_token()
"""
SU_BOOT = """\
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token


def ensure_service_token():
    user = get_user_model().objects.get(username="service")
    Token.objects.get_or_create(user=user)
"""
SU_KEYS = """\
import secrets


def bootstrap_api_token():
    return secrets.token_hex(32)
"""
SU_CMD = """\
from django.core.management.base import BaseCommand
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    def handle(self, *args, **options):
        Token.objects.create(user_id=options["user"])
"""
SU_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("token/", views.issue)]
"""
SU_VIEWS = """\
from django.http import HttpResponse
from rest_framework.authtoken.models import Token


def issue(request):
    Token.objects.create(user=request.user)
    return HttpResponse("ok")
"""


class StartupOnlyTests(unittest.TestCase):
    def project(self):
        return project(self, {"conf/urls.py": SU_URLS, "shop/views.py": SU_VIEWS, "shop/apps.py": SU_APPS,
                              "shop/bootstrap.py": SU_BOOT, "shop/keys.py": SU_KEYS,
                              "shop/management/__init__.py": "", "shop/management/commands/__init__.py": "",
                              "shop/management/commands/maketoken.py": SU_CMD}, settings=SU_SETTINGS)

    def test_startup_sites_are_low_ranked_candidates(self):
        rep = scan(self.project())
        confirmed = sorted(p["entry"]["id"] for p in rep["paths"])
        self.assertEqual(confirmed, ["route:token/|shop.views.issue"], confirmed)
        startup = [c for c in rep["candidates"] if c["candidate"]["group"] == "startup_only"]
        where = {c["mint"]["site"]["function"]: c["candidate"] for c in startup}
        self.assertIn("shop.bootstrap.ensure_service_token", where)
        self.assertIn("shop.management.commands.maketoken.Command.handle", where)
        self.assertIn("shop.keys.bootstrap_api_token", where)
        self.assertTrue(all(c["rank"] == "low" for c in where.values()))
        self.assertIn("AppConfig.ready()", where["shop.bootstrap.ensure_service_token"]["reason"])

    def test_a_change_at_startup_is_still_a_finding(self):
        root = self.project()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/bootstrap.py", 'username="service"', 'username="admin"'))
        self.assertTrue(code & 4, findings)
        self.assertTrue([f for f in findings if f.get("group") == "candidates:startup_only"], findings)



# ============================================================================ review queue
RQ_VIEWS = """\
from django.contrib.auth import authenticate, login
from django.http import HttpResponse, HttpResponseForbidden
from rest_framework.authtoken.models import Token


def issue(request):
    Token.objects.create(user=request.user)
    return HttpResponse("ok")


def sign_in(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponseForbidden()
    login(request, user)
    return HttpResponse("ok")


def quick(request):
    login(request, request.user)
    return HttpResponse("ok")
"""
RQ_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("token/", views.issue), path("in/", views.sign_in), path("quick/", views.quick)]
"""


class ReviewQueueTests(unittest.TestCase):
    def project(self):
        return project(self, {"conf/urls.py": RQ_URLS, "shop/views.py": RQ_VIEWS, "shop/apps.py": SU_APPS,
                              "shop/bootstrap.py": SU_BOOT, "shop/keys.py": SU_KEYS}, settings=SU_SETTINGS)

    def cli(self, *args):
        import subprocess
        import sys
        from mm_testutil import PROTO
        import os
        return subprocess.run([sys.executable, "-I", os.path.join(PROTO, "tests", "_cli.py"), *args],
                              capture_output=True, text=True, timeout=120)

    def test_review_blocks_rank_by_kind_and_evidence(self):
        rep = scan(self.project())
        by_entry = {p["entry"]["id"].split("|")[0]: p["review"] for p in rep["paths"]}
        self.assertEqual(by_entry["route:quick/"]["group"], "kind:session")
        self.assertEqual(by_entry["route:quick/"]["risk"], "high")
        self.assertIn("no check found on the path", by_entry["route:quick/"]["why"])
        self.assertEqual(by_entry["route:in/"]["group"], "kind:session")
        self.assertNotEqual(by_entry["route:in/"]["risk"], "high")
        self.assertEqual(by_entry["route:token/"]["group"], "kind:token")
        cands = {c["review"]["group"] for c in rep["candidates"]}
        self.assertIn("candidates:startup_only", cands)
        self.assertEqual(rep["coverage"]["review_summary"]["kind:session"]["entries"], 2)

    def test_text_report_is_a_review_queue(self):
        root = self.project()
        r = self.cli("scan", root)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertIn("REVIEW QUEUE", out)
        self.assertLess(out.index("kind:session"), out.index("kind:token"))
        self.assertLess(out.index("kind:token"), out.index("candidates:startup_only"))
        # highest risk first inside a kind
        self.assertLess(out.index("route:quick/"), out.index("route:in/"))
        self.assertIn("why: ", out)

    def test_accept_group_then_diff(self):
        root = self.project()
        lock = os.path.join(root, "mintmap.lock")
        self.assertEqual(self.cli("init", root).returncode, 0)
        r = self.cli("accept", root, "--group", "kind:session", "--reviewer", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(lock) as fh:
            data = json.load(fh)
        acc = {p["review"]["group"] for p in data["paths"] if p["review_status"] == "accepted"}
        self.assertEqual(acc, {"kind:session"})
        self.assertEqual(self.cli("diff", root).returncode, 64)
        r = self.cli("accept", root, "--group", "kind:token", "--group", "candidates:startup_only", "--group",
                     "settings", "--reviewer", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.cli("diff", root).returncode, 0, self.cli("diff", root).stdout)
        bad = self.cli("accept", root, "--group", "kind:nonsense", "--reviewer", "alice")
        self.assertEqual(bad.returncode, 128)
        self.assertIn("groups in this lock", bad.stderr)

    def test_lock_without_review_blocks_still_works(self):
        root = self.project()
        lock = os.path.join(root, "mintmap.lock")
        self.assertEqual(self.cli("init", root).returncode, 0)
        with open(lock) as fh:
            data = json.load(fh)
        for p in data["paths"]:
            p.pop("review", None)
        with open(lock, "w") as fh:
            json.dump(data, fh)
        r = self.cli("accept", root, "--group", "kind:session", "--group", "kind:token", "--reviewer", "bob")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.cli("accept", root, "--all", "--reviewer", "bob").returncode, 0)
        self.assertEqual(self.cli("diff", root).returncode, 0)


if __name__ == "__main__":
    unittest.main()

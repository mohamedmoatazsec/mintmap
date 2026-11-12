"""v6 third part (v6c): fixes for two adversarial reviews of v6b (soundness and generalisation).

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    InlinerRebindTests        an attribute-chain argument (`request.workspace`, `self.account`) is not substituted
                              into an extracted helper that calls something able to rebind it (the base object is
                              passed to a call or is the receiver of a method)
    AppConfigNameTests        an INSTALLED_APPS item that is a project AppConfig subclass of a library config installs
                              that library app (Django compares AppConfig.name)
    DynamicSettingsTests      ALLAUTH_SETTING_GETTER, setattr(settings, ...) at run time and globals() / vars() /
                              sys.modules writes in a settings module keep library flows that a default would switch
                              off
    TestHelperReferenceTests  a test-helper module named by a dotted string (URLconf include(), MIDDLEWARE) is analysed
    StartupMigrationTests     a mint only a data migration reaches is a `startup_only` candidate, not dropped (also
                              through a historical model from apps.get_model())
    DynamicDispatchTests      a generator in a module that code dispatches into with getattr(module, <computed>) is
                              not dead code
    RequestAuthenticatorTests `request.user = ...` without a credential check is a high-ranked candidate; Channels
                              scope["user"], another framework's authenticate(self, request, ...) and a helper called
                              through SimpleLazyObject(lambda: ...) are covered
    UncataloguedAuthCallTests a function of a package the catalog does not cover whose name says it logs in or issues
                              a token, called with the request or a user, is an `auth_library_call` candidate
    PackageSettingsGroupTests DEBUG is an allauth setting only in a project that uses allauth, and only DEBUG itself
    SignedReaderTests         the code that reads a signed value back decides in both directions: a reader (same
                              salt, or same JWT key) that logs in or authenticates a request makes the value a mint
                              whatever it is called; a value is set aside only when every reader is analysed (callers
                              several levels up, callees several levels down, bare `loads` imports)
    SessionPrincipalV6cTests  `request.user = obj.owner` attaches a looked-up object; a session id written after a
                              PIN / secret check is a login whatever the model is called; SESSION_KEY constants
    IntegrationTokenTests     an integration-named field that a project authenticator looks requests up by is a
                              credential
    WeakWordReaderTests       a weak word (`code`) on a user-linked model is a credential only when project code reads
                              it back by that field (an e-mailed code, a ping key; not a reference nobody checks); a
                              random value kept in the session needs a reader of its key
    SessionVocabularyTests    principal nouns alone (`user_prefers_dark`) and UI words do not make a candidate;
                              a session write after a password re-check does, whatever the key is called
    CacheHandOffTests         a random nonce kept in a cache key that another view reads back to log the user in
    WatchedTierTests          what a precision rule sets aside (random values without a credential word, signed values,
                              session values that load a non-principal object, generators nothing references) is
                              watched: one low-ranked lock entry per rule (`watched:<kind>`), fingerprinted by the
                              site function and its entry points, diffed like candidates, accepted per group
    CustomManagerTests        `Model.objects.issue()` resolves to the project manager / queryset method
                              (`objects = M()`, `QS.as_manager()`, `Manager.from_queryset(QS)()`); `self.create(...)`
                              and `self.model(...)` in a manager create that model
    AuthHooksGroupTests       `settings:AUTH_HOOKS(project code)`: callables named by auth-named settings, receivers of
                              authentication-library signals and predicates registered with permission registries
    RoutingVisibilityTests    a URL list filled by a decorator at run time is a gap; class-based settings
                              (django-configurations) are read; unrouted paths are not ranked below routed ones
    MiddlewareConditionTests  the SECRET_KEY_FALLBACKS re-hash branch is a path only with fallbacks configured
    GroupedSiteTests          a new entry point reaching a grouped site is a NEW_PATH that names it; a catalogued mint
                              that six or more entry points reach through a signal receiver is one grouped entry
    NameFallbackTests         up to six project definitions of a method called on an untyped receiver are hashed;
                              more mark the fingerprint incomplete
    ExtractRefactorTests      moving the mint call into an inlined helper keeps the path; extract method in a class
                              named by a hook setting keeps the hook fingerprint
"""
import json
import textwrap
import unittest

from mm_testutil import scan, read, write
from test_v5 import project, run_diff, gaps
from test_v6 import replace_in, cands


ALLAUTH_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "allauth", "allauth.account", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
              "django.contrib.auth.middleware.AuthenticationMiddleware",
              "allauth.account.middleware.AccountMiddleware"]
ROOT_URLCONF = "conf.urls"
"""
ALLAUTH_URLS = """\
from django.urls import include, path
urlpatterns = [path("accounts/", include("allauth.urls"))]
"""
RESET_LOGIN = "allauth.account.internal.flows.password_reset.perform_password_reset_login"
SOCIAL_LOGIN = "allauth.socialaccount.internal.flows.login._login"


def flow_paths(report, ref):
    return [p for p in report["paths"] if p["mint"]["api"] == ref]


def disabled(report, ref):
    return [d for d in report["coverage"]["library_flows_disabled_by_settings"] if d["mint"] == ref]


# ============================================================================ inliner: rebinding calls
WS_VIEWS = """\
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from rest_framework.authtoken.models import Token

from shop.workspaces import select_workspace


def bot_token(request):
    select_workspace(request, request.POST["ws"])
    if request.workspace.owner_id != request.user.pk:
        raise PermissionDenied
    token, _ = Token.objects.get_or_create(user=request.workspace.bot)
    return JsonResponse({"token": token.key})
"""
WS_HELPER = """\
from shop.models import Workspace


def select_workspace(request, pk):
    request.workspace = Workspace.objects.get(pk=pk)
"""
WS_URLS = """\
from django.urls import path
from shop.views import bot_token
urlpatterns = [path("bot-token/", bot_token)]
"""


class InlinerRebindTests(unittest.TestCase):
    def ws_project(self):
        return project(self, {"conf/urls.py": WS_URLS, "shop/views.py": WS_VIEWS, "shop/workspaces.py": WS_HELPER})

    def test_check_moved_onto_the_object_before_the_switch_is_a_finding(self):
        # the extracted helper checks its parameter, i.e. request.workspace as it was BEFORE select_workspace()
        root = self.ws_project()

        def mutate():
            text = read(root, "shop/views.py").replace(
                '    select_workspace(request, request.POST["ws"])\n'
                '    if request.workspace.owner_id != request.user.pk:\n        raise PermissionDenied\n',
                '    _switch(request, request.workspace)\n')
            write(root, "shop/views.py", text + textwrap.dedent('''\


                def _switch(request, current):
                    select_workspace(request, request.POST["ws"])
                    if current.owner_id != request.user.pk:
                        raise PermissionDenied
                '''))
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_helper_that_only_reads_values_of_the_base_is_still_inlined(self):
        root = self.ws_project()

        def mutate():
            text = read(root, "shop/views.py").replace(
                '    if request.workspace.owner_id != request.user.pk:\n        raise PermissionDenied\n',
                '    _require_owner(request, request.workspace)\n')
            write(root, "shop/views.py", text + textwrap.dedent('''\


                def _require_owner(request, current):
                    if current.owner_id != request.user.pk:
                        raise PermissionDenied
                '''))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)


# ============================================================================ INSTALLED_APPS through an AppConfig
SOCIAL_APPS = """\
from allauth.socialaccount.apps import SocialAccountConfig


class ShopSocialConfig(SocialAccountConfig):
    verbose_name = "Social sign-in"
"""


class AppConfigNameTests(unittest.TestCase):
    def test_project_appconfig_subclass_installs_the_library_app(self):
        settings = ALLAUTH_SETTINGS.replace('"allauth.account", "shop"]',
                                            '"allauth.account", "shop.apps.ShopSocialConfig", "shop"]')
        root = project(self, {"conf/urls.py": ALLAUTH_URLS, "shop/apps.py": SOCIAL_APPS}, settings=settings)
        rep = scan(root)
        self.assertEqual(len(flow_paths(rep, SOCIAL_LOGIN)), 1)
        self.assertFalse(disabled(rep, SOCIAL_LOGIN))

    def test_adding_the_appconfig_is_a_new_path(self):
        root = project(self, {"conf/urls.py": ALLAUTH_URLS, "shop/apps.py": SOCIAL_APPS}, settings=ALLAUTH_SETTINGS)
        self.assertTrue(disabled(scan(root), SOCIAL_LOGIN))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "conf/settings.py", '"shop"]', '"shop.apps.ShopSocialConfig", "shop"]'))
        self.assertTrue(code & 1, findings)

    def test_a_project_config_with_its_own_name_is_that_app(self):
        settings = ALLAUTH_SETTINGS.replace('"shop"]', '"shop.apps.ShopConfig"]')
        apps = "from django.apps import AppConfig\n\n\nclass ShopConfig(AppConfig):\n    name = \"shop\"\n"
        root = project(self, {"conf/urls.py": ALLAUTH_URLS, "shop/apps.py": apps}, settings=settings)
        self.assertTrue(disabled(scan(root), SOCIAL_LOGIN))


# ============================================================================ settings assigned dynamically
class DynamicSettingsTests(unittest.TestCase):
    def base(self, settings=ALLAUTH_SETTINGS, extra=None):
        files = {"conf/urls.py": ALLAUTH_URLS}
        files.update(extra or {})
        return project(self, files, settings=settings)

    def test_default_switches_the_flow_off(self):
        rep = scan(self.base())
        self.assertTrue(disabled(rep, RESET_LOGIN))
        self.assertFalse(flow_paths(rep, RESET_LOGIN))

    def test_allauth_setting_getter_keeps_the_flow(self):
        root = self.base()
        getter = "def read(name, default):\n    return True if name.startswith('ACCOUNT_LOGIN_ON') else default\n"
        findings, code = run_diff(self, root, lambda: (
            write(root, "conf/getter.py", getter),
            replace_in(root, "conf/settings.py", 'ROOT_URLCONF', 'ALLAUTH_SETTING_GETTER = "conf.getter.read"\n'
                                                                'ROOT_URLCONF')))
        self.assertTrue(code & 1, findings)
        self.assertTrue(any(RESET_LOGIN in f["message"] for f in findings if f["kind"] == "new_path"), findings)

    def test_setattr_on_settings_at_run_time(self):
        apps = textwrap.dedent("""\
            from django.apps import AppConfig
            from django.conf import settings


            class ShopConfig(AppConfig):
                name = "shop"

                def ready(self):
                    setattr(settings, "ACCOUNT_LOGIN_ON_PASSWORD_RESET", True)
            """)
        root = self.base()
        findings, code = run_diff(self, root, lambda: write(root, "shop/apps.py", apps))
        self.assertTrue(code & 1, findings)

    def test_setattr_with_a_computed_name_may_assign_any_setting(self):
        apps = textwrap.dedent("""\
            from django.apps import AppConfig
            from django.conf import settings


            class ShopConfig(AppConfig):
                name = "shop"

                def ready(self):
                    for name, value in self.overrides():
                        setattr(settings, name, value)
            """)
        rep = scan(self.base(extra={"shop/apps.py": apps}))
        self.assertTrue(gaps(rep, "dynamic_setting"))
        self.assertTrue(flow_paths(rep, RESET_LOGIN))

    def test_namespace_writes_in_a_settings_module(self):
        for line in ("globals().update(load_overrides())",
                     "for _k, _v in load_overrides().items():\n    globals()[_k] = _v",
                     "vars()['ACCOUNT_' + 'LOGIN_ON_PASSWORD_RESET'] = True",
                     "locals().update(load_overrides())",
                     "import sys\nsetattr(sys.modules[__name__], 'ACCOUNT_LOGIN_ON_PASSWORD_RESET', True)"):
            with self.subTest(line=line):
                settings = ALLAUTH_SETTINGS + "from conf.env import load_overrides\n" + line + "\n"
                env = "import os\n\n\ndef load_overrides():\n    return {k: v for k, v in os.environ.items()}\n"
                rep = scan(self.base(settings=settings, extra={"conf/env.py": env}))
                self.assertTrue(gaps(rep, "dynamic_setting"), line)
                self.assertTrue(flow_paths(rep, RESET_LOGIN), line)

    def test_namespace_update_with_known_keys(self):
        # the dict a project function builds has constant keys: only those settings become unknown
        env = textwrap.dedent("""\
            import os


            def directory_settings():
                conf = {"AUTH_LDAP_SERVER_URI": os.environ.get("LDAP_URI", "")}
                conf["AUTH_LDAP_BIND_DN"] = os.environ.get("LDAP_DN", "")
                return conf


            def reset_settings():
                return {"ACCOUNT_LOGIN_ON_PASSWORD_RESET": os.environ.get("AUTO", "") == "1"}
            """)
        settings = ALLAUTH_SETTINGS + "from conf.env import directory_settings\nglobals().update(directory_settings())\n"
        rep = scan(self.base(settings=settings, extra={"conf/env.py": env}))
        self.assertFalse(gaps(rep, "dynamic_setting"))
        self.assertTrue(disabled(rep, RESET_LOGIN))
        settings = ALLAUTH_SETTINGS + "from conf.env import reset_settings\nglobals().update(reset_settings())\n"
        rep = scan(self.base(settings=settings, extra={"conf/env.py": env}))
        self.assertTrue(flow_paths(rep, RESET_LOGIN))


# ============================================================================ test helpers named by strings
DEV_URLS = """\
from django.conf import settings
from django.urls import include, path

urlpatterns = []
if settings.DEBUG:
    urlpatterns += [path("dev/", include("shop.test_utils.urls"))]
"""
DEV_HELPER_URLS = """\
from django.urls import path
from shop.test_utils.views import sign_in_as
urlpatterns = [path("as/<int:uid>/", sign_in_as)]
"""
DEV_HELPER_VIEWS = """\
from django.contrib.auth import get_user_model, login
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse


def sign_in_as(request, uid):
    if not request.user.is_superuser:
        raise PermissionDenied
    login(request, get_user_model().objects.get(pk=uid), backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse("ok")
"""
DEV_MIDDLEWARE = """\
from django.contrib.auth import get_user_model, login


class LocalAutoLogin:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.META.get("REMOTE_ADDR") == "127.0.0.1" and "X-As" in request.headers:
            login(request, get_user_model().objects.get(username=request.headers["X-As"]),
                  backend="django.contrib.auth.backends.ModelBackend")
        return self.get_response(request)
"""


class TestHelperReferenceTests(unittest.TestCase):
    def test_include_of_a_test_helper_urlconf(self):
        root = project(self, {"conf/urls.py": DEV_URLS, "shop/test_utils/__init__.py": "",
                              "shop/test_utils/urls.py": DEV_HELPER_URLS,
                              "shop/test_utils/views.py": DEV_HELPER_VIEWS})
        rep = scan(root)
        self.assertTrue([p for p in rep["paths"] if p["entry"]["id"].startswith("route:dev/as/")],
                        [p["entry"]["id"] for p in rep["paths"]])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/test_utils/views.py", "    if not request.user.is_superuser:\n        raise PermissionDenied\n",
            ""))
        self.assertTrue(code & 4, findings)

    def test_middleware_in_a_testutils_module(self):
        settings = textwrap.dedent("""\
            SECRET_KEY = "fixture-only"
            INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware",
                          "shop.testutils.LocalAutoLogin"]
            ROOT_URLCONF = "conf.urls"
            """)
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/testutils.py": DEV_MIDDLEWARE},
                       settings=settings)
        rep = scan(root)
        self.assertTrue([p for p in rep["paths"] if p["entry"]["id"] == "middleware:shop.testutils.LocalAutoLogin"])
        self.assertFalse(gaps(rep, "middleware_not_in_catalog"))

    def test_test_runner_setting_does_not_reinclude_tests(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n",
                              "shop/tests/__init__.py": "", "shop/tests/runner.py": "class Runner:\n    pass\n"},
                       settings_extra='TEST_RUNNER = "shop.tests.runner.Runner"\n')
        rep = scan(root)
        self.assertFalse(rep["coverage"]["test_code"]["reincluded"])


# ============================================================================ data migrations
MIGRATION = """\
from django.db import migrations
from rest_framework.authtoken.models import Token


def service_account(apps, schema_editor):
    User = apps.get_model("auth", "User")
    bot = User.objects.create(username="deploy-bot", is_superuser=True)
    Token.objects.create(user=bot)


class Migration(migrations.Migration):
    dependencies = []
    operations = [migrations.RunPython(service_account)]
"""


class StartupMigrationTests(unittest.TestCase):
    def test_mint_reached_only_from_a_migration_is_a_startup_candidate(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/migrations/__init__.py": "",
                              "shop/migrations/0002_bot.py": MIGRATION})
        rep = scan(root)
        hit = [c for c in cands(rep, "startup_only") if "service_account" in c["entry"]["id"]]
        self.assertEqual(len(hit), 1, [c["entry"]["id"] for c in cands(rep)])
        self.assertIn("migration", hit[0]["candidate"]["reason"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/migrations/0002_bot.py", "Token.objects.create(user=bot)",
            'Token.objects.create(user=bot, key="0" * 40)'))
        self.assertTrue(code & 4, findings)

    def test_historical_model_from_apps_get_model(self):
        mig = MIGRATION.replace("from rest_framework.authtoken.models import Token\n", "").replace(
            '    User = apps.get_model("auth", "User")\n',
            '    User = apps.get_model("auth", "User")\n    Token = apps.get_model("authtoken", "Token")\n')
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/migrations/__init__.py": "",
                              "shop/migrations/0002_bot.py": mig})
        hit = [c for c in cands(scan(root), "startup_only") if "service_account" in c["entry"]["id"]]
        self.assertEqual([c["mint"]["api"] for c in hit], ["rest_framework.authtoken.models.Token.objects.create"])


# ============================================================================ dynamic dispatch
KEYS = """\
import secrets


def make_api_token():
    return secrets.token_urlsafe(32)


def make_feed_token():
    return secrets.token_urlsafe(24)
"""
KEY_VIEWS = """\
from django.http import JsonResponse

from shop import keys
from shop.models import Credential


def issue(request, kind):
    generator = getattr(keys, f"make_{kind}_token")
    cred = Credential.objects.create(owner=request.user, kind=kind, token=generator())
    return JsonResponse({"token": cred.token})
"""
KEY_MODELS = """\
from django.db import models


class Credential(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    kind = models.CharField(max_length=20)
    token = models.CharField(max_length=64)
"""


class DynamicDispatchTests(unittest.TestCase):
    def test_generators_reached_by_getattr_on_their_module_are_not_dead_code(self):
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import issue\n"
                                              "urlpatterns = [path('issue/<str:kind>/', issue)]\n",
                              "shop/keys.py": KEYS, "shop/views.py": KEY_VIEWS, "shop/models.py": KEY_MODELS})
        rep = scan(root)
        self.assertFalse(rep["coverage"]["custom_credentials"]["unreferenced_functions_set_aside"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/keys.py", "secrets.token_urlsafe(32)", "secrets.token_urlsafe(2)"))
        self.assertTrue(code, findings)


# ============================================================================ request authenticators
HEADER_VIEW = """\
from django.contrib.auth import get_user_model
from django.http import HttpResponse


def export(request):
    request.user = get_user_model().objects.get(username=request.headers.get("X-Export-User"))
    return HttpResponse(request.user.username)
"""
CHANNELS_AUTH = """\
from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser

from shop.models import Pass


@database_sync_to_async
def holder(raw):
    found = Pass.objects.filter(code=raw, active=True).first()
    return found.holder if found else AnonymousUser()


class PassMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        scope["user"] = await holder(dict(scope["headers"]).get(b"x-pass", b"").decode())
        return await super().__call__(scope, receive, send)
"""
CHANNELS_ASGI = """\
from channels.routing import ProtocolTypeRouter, URLRouter

from shop.realtime import PassMiddleware

application = ProtocolTypeRouter({"websocket": PassMiddleware(URLRouter([]))})
"""
NINJA_API = """\
from ninja import NinjaAPI
from ninja.security import HttpBearer

from shop.models import Pass


class PassBearer(HttpBearer):
    def authenticate(self, request, token):
        found = Pass.objects.filter(code=token, active=True).first()
        return found.holder if found else None


api = NinjaAPI(auth=PassBearer())
"""
LAZY_MW = """\
from django.utils.functional import SimpleLazyObject

from shop.cookies import user_from_cookie


class CookieLogin:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            request.user = SimpleLazyObject(lambda: user_from_cookie(request))
        return self.get_response(request)
"""
LAZY_HELPER = """\
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.signing import BadSignature


def user_from_cookie(request):
    try:
        uid = request.get_signed_cookie("stay", salt="stay-signed-in", max_age=86400)
    except (KeyError, BadSignature):
        return AnonymousUser()
    return get_user_model().objects.filter(pk=uid).first() or AnonymousUser()
"""
PASS_MODEL = """\
from django.db import models


class Pass(models.Model):
    holder = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    code = models.CharField(max_length=64)
    active = models.BooleanField(default=True)
"""


class RequestAuthenticatorTests(unittest.TestCase):
    def test_trusting_a_header_without_a_check_is_a_high_candidate(self):
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import export\n"
                                              "urlpatterns = [path('export/', export)]\n",
                              "shop/views.py": HEADER_VIEW})
        hit = cands(scan(root), "request_authenticator")
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["candidate"]["rank"], "high")
        self.assertIn("no credential read or check", hit[0]["candidate"]["reason"])

    def test_assigning_an_anonymous_user_is_not_a_candidate(self):
        view = HEADER_VIEW.replace('get_user_model().objects.get(username=request.headers.get("X-Export-User"))',
                                   "get_anonymous_user()").replace(
            "from django.http import HttpResponse", "from django.http import HttpResponse\n"
                                                    "from shop.users import get_anonymous_user")
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import export\n"
                                              "urlpatterns = [path('export/', export)]\n",
                              "shop/views.py": view, "shop/users.py": "def get_anonymous_user():\n    return None\n"})
        self.assertFalse(cands(scan(root), "request_authenticator"))

    def test_channels_scope_user_and_its_helper(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "conf/asgi.py": CHANNELS_ASGI,
                              "shop/realtime.py": CHANNELS_AUTH, "shop/models.py": PASS_MODEL})
        hit = cands(scan(root), "request_authenticator")
        self.assertEqual([c["entry"]["view"] for c in hit], ["shop.realtime.PassMiddleware.__call__"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/realtime.py", "filter(code=raw, active=True)", "filter(active=True)"))
        self.assertTrue(code & 4, findings)

    def test_other_framework_authentication_class(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/api.py": NINJA_API,
                              "shop/models.py": PASS_MODEL})
        hit = cands(scan(root), "request_authenticator")
        self.assertEqual(len(hit), 1)
        self.assertIn("PassBearer.authenticate", hit[0]["entry"]["view"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/api.py", "filter(code=token, active=True)", "filter(active=True)"))
        self.assertTrue(code & 4, findings)

    def test_helper_called_through_a_lazy_object_in_another_module(self):
        settings = textwrap.dedent("""\
            SECRET_KEY = "fixture-only"
            INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware",
                          "shop.middleware.CookieLogin"]
            ROOT_URLCONF = "conf.urls"
            """)
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/middleware.py": LAZY_MW,
                              "shop/cookies.py": LAZY_HELPER}, settings=settings)
        self.assertEqual(len(cands(scan(root), "request_authenticator")), 1)
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/cookies.py", 'request.get_signed_cookie("stay", salt="stay-signed-in", max_age=86400)',
            'request.COOKIES["stay"]'))
        self.assertTrue(code & 4, findings)


# ============================================================================ uncatalogued authentication packages
class UncataloguedAuthCallTests(unittest.TestCase):
    def test_login_function_of_an_uncatalogued_package(self):
        views = textwrap.dedent("""\
            from django.contrib.admin.views.decorators import staff_member_required
            from django.contrib.auth import get_user_model
            from django.shortcuts import get_object_or_404, redirect
            from switchuser.helpers import sign_in_as


            @staff_member_required
            def become(request, pk):
                sign_in_as(request, get_object_or_404(get_user_model(), pk=pk))
                return redirect("/")
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import become\n"
                                              "urlpatterns = [path('become/<int:pk>/', become)]\n",
                              "shop/views.py": views})
        hit = cands(scan(root), "auth_library_call")
        self.assertEqual([c["mint"]["api"] for c in hit], ["switchuser.helpers.sign_in_as"])

    def test_token_for_a_user_from_an_uncatalogued_package(self):
        views = textwrap.dedent("""\
            from django.contrib.auth import authenticate
            from django.http import JsonResponse
            from tokenkit.shortcuts import token_for


            def obtain(request):
                person = authenticate(request, username=request.POST["u"], password=request.POST["p"])
                if person is None:
                    return JsonResponse({}, status=401)
                return JsonResponse({"token": token_for(person)})
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import obtain\n"
                                              "urlpatterns = [path('obtain/', obtain)]\n",
                              "shop/views.py": views})
        hit = cands(scan(root), "auth_library_call")
        self.assertEqual([c["mint"]["api"] for c in hit], ["tokenkit.shortcuts.token_for"])

    def test_check_or_logout_of_such_a_package_is_not_a_candidate(self):
        views = textwrap.dedent("""\
            from django.http import HttpResponse
            from switchuser.helpers import verify_token, logout_as


            def leave(request):
                verify_token(request)
                logout_as(request)
                return HttpResponse("ok")
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import leave\n"
                                              "urlpatterns = [path('leave/', leave)]\n",
                              "shop/views.py": views})
        self.assertFalse(cands(scan(root), "auth_library_call"))


# ============================================================================ package settings groups
class PackageSettingsGroupTests(unittest.TestCase):
    def test_debug_is_not_an_allauth_group_without_allauth(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n"},
                       settings_extra="DEBUG = False\nDEBUG_TOOLBAR_CONFIG = {}\n")
        ids = [g["id"] for g in scan(root)["settings_groups"]]
        self.assertNotIn("settings:package:allauth", ids)
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/settings.py", "DEBUG = False",
                                                                 "DEBUG = True"))
        self.assertEqual(code, 0, findings)

    def test_debug_is_part_of_the_allauth_group_with_allauth(self):
        root = project(self, {"conf/urls.py": ALLAUTH_URLS},
                       settings=ALLAUTH_SETTINGS + "DEBUG = False\nDEBUG_TOOLBAR_CONFIG = {}\n")
        grp = [g for g in scan(root)["settings_groups"] if g["id"] == "settings:package:allauth"]
        self.assertEqual(grp[0]["names"], ["DEBUG"])


# ============================================================================ signed values and their readers
LINK_CODEC = """\
from django.core import signing

LINK_SALT = "entry.link"


def encode(person):
    return signing.dumps({"p": person.pk}, salt=LINK_SALT)


def decode(blob):
    return signing.loads(blob, salt=LINK_SALT, max_age=600)
"""
LINK_SERVICE = """\
from django.contrib.auth import get_user_model

from shop.codec import decode


def person_for(blob):
    return get_user_model().objects.get(pk=decode(blob)["p"])
"""
LINK_VIEWS = """\
from django.contrib.auth import get_user_model, login
from django.core.mail import send_mail
from django.http import HttpResponse

from shop.codec import encode
from shop.service import person_for


def send(request):
    p = get_user_model().objects.get(email=request.POST["email"])
    send_mail("Enter", "/enter/?b=" + encode(p), None, [p.email])
    return HttpResponse("sent")


def enter(request):
    login(request, person_for(request.GET["b"]), backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse("in")
"""
LINK_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("send/", views.send), path("enter/", views.enter)]
"""


def signing_paths(report):
    return [p for p in report["paths"] if p["mint"]["api"] == "django.core.signing.dumps"]


class SignedReaderTests(unittest.TestCase):
    def test_layered_reader_two_levels_below_the_login(self):
        root = project(self, {"conf/urls.py": LINK_URLS, "shop/codec.py": LINK_CODEC, "shop/service.py": LINK_SERVICE,
                              "shop/views.py": LINK_VIEWS})
        ps = signing_paths(scan(root))
        self.assertEqual([p["entry"]["id"] for p in ps], ["route:send/|shop.views.send"])
        self.assertIn("read back", ps[0]["mint"]["purpose_basis"])

        def mutate():
            replace_in(root, "shop/views.py", "def enter(request):",
                       "def peek(request):\n    return HttpResponse(encode(get_user_model().objects.get("
                       "pk=request.GET['id'])))\n\n\ndef enter(request):")
            replace_in(root, "conf/urls.py", 'path("enter/", views.enter)]',
                       'path("enter/", views.enter), path("peek/", views.peek)]')
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 1, findings)

    def test_unnamed_value_whose_reader_logs_in_is_a_mint(self):
        views = textwrap.dedent("""\
            from django.contrib.auth import get_user_model, login
            from django.core import signing
            from django.core.mail import send_mail
            from django.http import HttpResponse


            def send(request):
                u = get_user_model().objects.get(email=request.POST["email"])
                send_mail("Enter", "/enter/?s=" + signing.dumps({"n": u.pk}, salt="one-click"), None, [u.email])
                return HttpResponse("sent")


            def enter(request):
                data = signing.loads(request.GET["s"], salt="one-click", max_age=300)
                login(request, get_user_model().objects.get(pk=data["n"]),
                      backend="django.contrib.auth.backends.ModelBackend")
                return HttpResponse("in")
            """)
        root = project(self, {"conf/urls.py": LINK_URLS, "shop/views.py": views})
        self.assertEqual(len(signing_paths(scan(root))), 1)

    def test_bare_loads_import_is_a_reader(self):
        views = LINK_VIEWS.replace("from shop.service import person_for\n", "from django.core.signing import loads\n")
        views = views.replace("person_for(request.GET[\"b\"])",
                              "get_user_model().objects.get(pk=loads(request.GET['b'], salt='entry.link')['p'])")
        root = project(self, {"conf/urls.py": LINK_URLS, "shop/codec.py": LINK_CODEC, "shop/views.py": views})
        self.assertEqual(len(signing_paths(scan(root))), 1)

    def test_reader_far_below_keeps_the_mint(self):
        # the login is five calls below the reader: the reader's reach is followed without a depth limit
        chain = textwrap.dedent("""\
            from django.contrib.auth import login


            def a(request, data):
                return b(request, data)


            def b(request, data):
                return c(request, data)


            def c(request, data):
                return d(request, data)


            def d(request, data):
                return e(request, data)


            def e(request, data):
                login(request, data, backend="django.contrib.auth.backends.ModelBackend")
            """)
        views = LINK_VIEWS.replace("from shop.service import person_for\n", "from shop.chain import a\n"
                                   "from shop.codec import decode\n")
        views = views.replace('    login(request, person_for(request.GET["b"]), '
                              'backend="django.contrib.auth.backends.ModelBackend")\n',
                              '    a(request, decode(request.GET["b"]))\n')
        codec = LINK_CODEC.replace('{"p": person.pk}', '{"user": person.pk}')
        root = project(self, {"conf/urls.py": LINK_URLS, "shop/codec.py": codec, "shop/chain.py": chain,
                              "shop/views.py": views})
        self.assertEqual(len(signing_paths(scan(root))), 1)

    def test_principal_link_from_a_user_model_method(self):
        models = textwrap.dedent("""\
            from django.contrib.auth.models import AbstractUser
            from django.core.signing import TimestampSigner


            class Person(AbstractUser):
                def entry(self):
                    return "/enter/?t=" + TimestampSigner(salt="person.entry").sign(str(self.pk))
            """)
        views = textwrap.dedent("""\
            from django.http import HttpResponse

            from shop.models import Person


            def send(request):
                p = Person.objects.get(email=request.POST["email"])
                return HttpResponse(p.entry())
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('send/', views.send)]\n",
                              "shop/models.py": models, "shop/views.py": views},
                       settings_extra='AUTH_USER_MODEL = "shop.Person"\n')
        ps = [p for p in scan(root)["paths"] if "sign" in p["mint"]["api"]]
        self.assertEqual(len(ps), 1, [p["mint"]["api"] for p in scan(root)["paths"]])

    def test_jwt_whose_decoder_authenticates_requests(self):
        util = textwrap.dedent("""\
            import jwt
            from django.conf import settings


            def pack(payload):
                return jwt.encode(payload, settings.APP_JWT_KEY, algorithm="HS256")


            def unpack(raw):
                return jwt.decode(raw, settings.APP_JWT_KEY, algorithms=["HS256"])
            """)
        auth = textwrap.dedent("""\
            from django.contrib.auth import get_user_model
            from rest_framework.authentication import BaseAuthentication

            from shop.util import unpack


            class AppBearer(BaseAuthentication):
                def authenticate(self, request):
                    raw = request.headers.get("Authorization", "")[7:]
                    return get_user_model().objects.get(pk=unpack(raw)["s"]), None
            """)
        views = textwrap.dedent("""\
            import time

            from django.contrib.auth import authenticate
            from django.http import JsonResponse

            from shop.util import pack


            def obtain(request):
                who = authenticate(request, username=request.POST["u"], password=request.POST["p"])
                if who is None:
                    return JsonResponse({}, status=401)
                return JsonResponse({"access": pack({"s": who.pk, "exp": time.time() + 300})})
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('obtain/', views.obtain)]\n",
                              "shop/util.py": util, "shop/auth.py": auth, "shop/views.py": views},
                       settings_extra='APP_JWT_KEY = "k"\nREST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": '
                                      '["shop.auth.AppBearer"]}\n')
        ps = [p for p in scan(root)["paths"] if p["mint"]["api"] == "jwt.encode"]
        self.assertEqual([p["entry"]["id"] for p in ps], ["route:obtain/|shop.views.obtain"])
        findings, code = run_diff(self, root, lambda: replace_in(root, "shop/views.py", "time.time() + 300",
                                                                 "time.time() + 300 * 10**6"))
        self.assertTrue(code & 4, findings)


# ============================================================================ session values that load a principal
DEVICE_MODELS = """\
from django.db import models


class Terminal(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    pairing_code = models.CharField(max_length=12)
"""
DEVICE_VIEWS = """\
import hmac

from django.http import HttpResponse, HttpResponseForbidden

from shop.models import Terminal


def pair(request):
    t = Terminal.objects.get(pk=request.POST["t"])
    if not hmac.compare_digest(t.pairing_code, request.POST["code"]):
        return HttpResponseForbidden()
    request.session["terminal"] = t.pk
    return HttpResponse("paired")
"""
DEVICE_MW = """\
from shop.models import Terminal


class TerminalLogin:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if "terminal" in request.session:
            t = Terminal.objects.get(pk=request.session["terminal"])
            request.user = t.owner
        return self.get_response(request)
"""
KIOSK = """\
from django.http import HttpResponse, HttpResponseForbidden

from shop.models import Worker


def badge_in(request):
    w = Worker.objects.filter(badge=request.POST.get("badge")).first()
    if w is None or w.pin != request.POST.get("pin"):
        return HttpResponseForbidden()
    request.session["worker_ref"] = w.pk
    return HttpResponse("ok")


def shift(request):
    w = Worker.objects.get(pk=request.session["worker_ref"])
    return HttpResponse(str(w.pk))
"""
KIOSK_MODELS = """\
from django.db import models


class Worker(models.Model):
    badge = models.CharField(max_length=20)
    pin = models.CharField(max_length=6)
"""


def session_paths(report, key):
    return [p for p in report["paths"] if p["mint"]["api"] == f"session[{key}]"]


class SessionPrincipalV6cTests(unittest.TestCase):
    def test_request_user_from_an_attribute_of_the_looked_up_object(self):
        settings = textwrap.dedent("""\
            SECRET_KEY = "fixture-only"
            INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware", "shop.middleware.TerminalLogin"]
            ROOT_URLCONF = "conf.urls"
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop.views import pair\n"
                                              "urlpatterns = [path('pair/', pair)]\n",
                              "shop/models.py": DEVICE_MODELS, "shop/views.py": DEVICE_VIEWS,
                              "shop/middleware.py": DEVICE_MW}, settings=settings)
        self.assertEqual(len(session_paths(scan(root), "terminal")), 1)
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/views.py", '    if not hmac.compare_digest(t.pairing_code, request.POST["code"]):\n'
                                   '        return HttpResponseForbidden()\n', ""))
        self.assertTrue(code, findings)

    def test_session_id_written_after_a_pin_check_is_a_login(self):
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('in/', views.badge_in), path('shift/', "
                                              "views.shift)]\n",
                              "shop/models.py": KIOSK_MODELS, "shop/views.py": KIOSK})
        rep = scan(root)
        self.assertEqual(len(session_paths(rep, "worker_ref")), 1)
        self.assertFalse(rep["coverage"]["custom_credentials"]["session_lookups_set_aside"])

    def test_session_key_constant_of_django(self):
        views = textwrap.dedent("""\
            from django.contrib.auth import SESSION_KEY, get_user_model
            from django.core.cache import cache
            from django.http import HttpResponse


            def handoff(request):
                uid = cache.get("handoff:" + request.GET["n"])
                request.session.cycle_key()
                request.session[SESSION_KEY] = str(get_user_model().objects.get(pk=uid).pk)
                return HttpResponse("in")
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('h/', views.handoff)]\n",
                              "shop/views.py": views})
        self.assertEqual(len(session_paths(scan(root), "_auth_user_id")), 1)


# ============================================================================ integration-named inbound credentials
class IntegrationTokenTests(unittest.TestCase):
    def test_integration_field_used_by_an_authenticator_is_a_credential(self):
        models = textwrap.dedent("""\
            from django.db import models


            class Profile(models.Model):
                user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
                integration_token = models.CharField(max_length=64, blank=True)
            """)
        views = textwrap.dedent("""\
            import secrets

            from django.http import JsonResponse


            def rotate(request):
                profile = request.user.profile
                profile.integration_token = secrets.token_urlsafe(32)
                profile.save()
                return JsonResponse({"token": profile.integration_token})
            """)
        auth = textwrap.dedent("""\
            from rest_framework.authentication import BaseAuthentication

            from shop.models import Profile


            class IntegrationAuth(BaseAuthentication):
                def authenticate(self, request):
                    raw = request.headers.get("X-Integration", "")
                    profile = Profile.objects.filter(integration_token=raw).first()
                    return (profile.user, None) if profile else None
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('rotate/', views.rotate)]\n",
                              "shop/models.py": models, "shop/views.py": views, "shop/auth.py": auth},
                       settings_extra='REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": '
                                      '["shop.auth.IntegrationAuth"]}\n')
        ps = [p for p in scan(root)["paths"] if p["entry"]["id"].startswith("route:rotate/")]
        self.assertEqual(len(ps), 1)

    def test_outbound_webhook_secret_is_still_set_aside(self):
        models = "from django.db import models\n\n\nclass Hook(models.Model):\n    url = models.URLField()\n" \
                 "    owner = models.ForeignKey('auth.User', on_delete=models.CASCADE)\n" \
                 "    webhook_token = models.CharField(max_length=64)\n"
        views = textwrap.dedent("""\
            import secrets

            from django.http import JsonResponse

            from shop.models import Hook


            def add_hook(request):
                h = Hook.objects.create(owner=request.user, url=request.POST["url"],
                                        webhook_token=secrets.token_hex(16))
                return JsonResponse({"secret": h.webhook_token})
            """)
        root = project(self, {"conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('hook/', views.add_hook)]\n",
                              "shop/models.py": models, "shop/views.py": views})
        self.assertFalse([p for p in scan(root)["paths"] if p["entry"]["id"].startswith("route:hook/")])


# ============================================================================ weak words need a credential reader
WEAK_MODELS = """\
from django.db import models


class Reservation(models.Model):
    guest = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    code = models.CharField(max_length=8)


class MailCode(models.Model):
    person = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
"""
WEAK_VIEWS = """\
import secrets

from django.contrib.auth import get_user_model, login
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.utils.crypto import get_random_string

from shop.models import MailCode, Reservation


def reserve(request):
    r = Reservation.objects.create(guest=request.user, code=get_random_string(8))
    return JsonResponse({"ref": r.code})


def send_code(request):
    u = get_user_model().objects.get(email=request.POST["email"])
    MailCode.objects.create(person=u, code=f"{secrets.randbelow(10**6):06d}")
    send_mail("Code", "see app", None, [u.email])
    return HttpResponse("sent")


def check_code(request):
    hit = MailCode.objects.filter(person__email=request.POST["email"], code=request.POST["code"]).first()
    if hit is None:
        return HttpResponse(status=403)
    login(request, hit.person, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse("in")
"""
WEAK_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("reserve/", views.reserve), path("code/", views.send_code), path("check/", views.check_code)]
"""


class WeakWordReaderTests(unittest.TestCase):
    def test_reference_nobody_checks_is_not_a_credential_but_an_emailed_code_is(self):
        rep = scan(project(self, {"conf/urls.py": WEAK_URLS, "shop/models.py": WEAK_MODELS,
                                  "shop/views.py": WEAK_VIEWS}))
        routes = sorted(p["entry"]["id"] for p in rep["paths"] if p["mint"]["kind"] == "heuristic_custom_credential")
        self.assertEqual(routes, ["route:code/|shop.views.send_code"])
        aside = [r for r in rep["coverage"]["custom_credentials"]["set_aside"] if r["function"] == "shop.views.reserve"]
        self.assertTrue(aside and "looks it up" in aside[0]["reasons"][0], aside)

    def test_session_value_nobody_reads_back(self):
        views = textwrap.dedent("""\
            import secrets

            from django.http import HttpResponse


            def checkout(request):
                request.session["basket_token"] = secrets.token_urlsafe(16)
                return HttpResponse("ok")


            def resume(request):
                return HttpResponse(request.session.get("resume_token", ""))


            def start(request):
                request.session["resume_token"] = secrets.token_urlsafe(16)
                return HttpResponse("ok")
            """)
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [path('c/', views.checkout), " \
               "path('r/', views.resume), path('s/', views.start)]\n"
        rep = scan(project(self, {"conf/urls.py": urls, "shop/views.py": views}))
        routes = sorted(p["entry"]["id"] for p in rep["paths"] if p["mint"]["kind"] == "heuristic_custom_credential")
        self.assertEqual(routes, ["route:s/|shop.views.start"])
        self.assertEqual([w["entry"]["view"] for w in watched(rep, "random_value")], ["shop.views.checkout"])


# ============================================================================ session vocabulary
class SessionVocabularyTests(unittest.TestCase):
    def test_ui_keys_with_principal_nouns_are_not_candidates(self):
        views = ["from django.http import HttpResponse", "", ""]
        keys = [("user_prefers_dark", "True"), ("account_tab_open", "True"), ("member_sidebar_collapsed", "True"),
                ("login_tip_dismissed", "True"), ("user_selected_team", "request.team.pk"),
                ("auth_help_opened", "True")]
        for i, (k, v) in enumerate(keys):
            views += [f"def ui_{i}(request):", f"    request.session[{k!r}] = {v}", "    return HttpResponse('ok')",
                      "", ""]
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [" + ", ".join(
            f"path('ui/{i}/', views.ui_{i})" for i in range(len(keys))) + "]\n"
        rep = scan(project(self, {"conf/urls.py": urls, "shop/views.py": "\n".join(views)}))
        self.assertFalse(cands(rep, "session_state"), [c["candidate"]["keys"] for c in cands(rep)])

    def test_principal_id_and_state_words_still_are(self):
        views = textwrap.dedent("""\
            import time

            from django.http import HttpResponse


            def a(request):
                request.session["member_id"] = request.member.pk
                return HttpResponse("ok")


            def b(request):
                request.session["mfa_verified"] = True
                return HttpResponse("ok")
            """)
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [path('a/', views.a), " \
               "path('b/', views.b)]\n"
        rep = scan(project(self, {"conf/urls.py": urls, "shop/views.py": views}))
        self.assertEqual(len(cands(rep, "session_state")), 2)

    def test_write_after_a_password_recheck_whatever_the_key(self):
        views = textwrap.dedent("""\
            import time

            from django.http import HttpResponse, HttpResponseForbidden


            def confirm(request):
                if not request.user.check_password(request.POST.get("password", "")):
                    return HttpResponseForbidden()
                request.session["recheck_last_seen"] = time.time()
                return HttpResponse("ok")
            """)
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [path('c/', views.confirm)]\n"
        rep = scan(project(self, {"conf/urls.py": urls, "shop/views.py": views}))
        hit = cands(rep, "session_state")
        self.assertEqual(len(hit), 1)
        self.assertIn("after_secret_check", hit[0]["candidate"]["signals"])


# ============================================================================ cache hand-off
class CacheHandOffTests(unittest.TestCase):
    def test_nonce_in_a_cache_key_read_back_by_a_login(self):
        views = textwrap.dedent("""\
            import secrets

            from django.contrib.auth import get_user_model, login
            from django.core.cache import cache
            from django.http import HttpResponse, HttpResponseForbidden
            from django.shortcuts import redirect


            def leave(request):
                n = secrets.token_urlsafe(24)
                cache.set(f"jump:{n}", request.user.pk, timeout=30)
                return redirect(f"https://other.example.com/arrive/?n={n}")


            def arrive(request):
                uid = cache.get(f"jump:{request.GET.get('n', '')}")
                if uid is None:
                    return HttpResponseForbidden()
                login(request, get_user_model().objects.get(pk=uid),
                      backend="django.contrib.auth.backends.ModelBackend")
                return HttpResponse("in")
            """)
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [path('leave/', views.leave), " \
               "path('arrive/', views.arrive)]\n"
        root = project(self, {"conf/urls.py": urls, "shop/views.py": views})
        ps = [p for p in scan(root)["paths"] if p["entry"]["id"].startswith("route:leave/")]
        self.assertEqual(len(ps), 1)
        self.assertIn("read back from the cache", ps[0]["mint"]["purpose_note"])


# ============================================================================ watched tier
W_MODELS = """\
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
    grant = models.CharField(max_length=64, blank=True)


class Event(models.Model):
    name = models.CharField(max_length=40)
    door_code = models.CharField(max_length=8)
"""
W_VIEWS = """\
import secrets

from django.core import signing
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse

from shop.models import Event, Profile


def issue_grant(request):
    profile = Profile.objects.get(user=request.user)
    profile.grant = secrets.token_urlsafe(32)
    profile.save()
    return JsonResponse({"grant": profile.grant})


def preview(request):
    return HttpResponse(signing.dumps({"layout": request.GET.get("l", "")}, salt="preview"))


def enter_event(request):
    ev = Event.objects.get(pk=request.POST["event"])
    if ev.door_code != request.POST.get("door"):
        return HttpResponseForbidden()
    request.session["event_pk"] = ev.pk
    return HttpResponse("ok")


def event_page(request):
    ev = Event.objects.get(pk=request.session["event_pk"])
    return HttpResponse(ev.name)
"""
W_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("grant/", views.issue_grant), path("preview/", views.preview), path("event/in/", views.enter_event),
               path("event/", views.event_page)]
"""


def watched(report, group=None):
    return [w for w in report.get("watched", []) if group is None or w["watch"]["group"] == group]


class WatchedTierTests(unittest.TestCase):
    def w_project(self):
        return project(self, {"conf/urls.py": W_URLS, "shop/models.py": W_MODELS, "shop/views.py": W_VIEWS})

    def test_set_aside_sites_are_watched_not_reported(self):
        rep = scan(self.w_project())
        self.assertFalse([p for p in rep["paths"] if p["entry"]["id"].startswith(("route:grant/", "route:preview/"))])
        self.assertEqual([w["entry"]["view"] for w in watched(rep, "random_value")], ["shop.views.issue_grant"])
        self.assertEqual([w["entry"]["view"] for w in watched(rep, "signed_value")], ["shop.views.preview"])
        # the door code is checked first: event_pk is a login now (session lookups after a secret check), so
        # nothing is watched for it; the watched sites carry their entry points and a reason
        w = watched(rep, "random_value")[0]
        self.assertEqual(w["entry"]["reached_from"], ["route:grant/|shop.views.issue_grant"])
        self.assertIn("no credential word", w["watch"]["reason"])
        self.assertEqual(w["review"]["group"], "watched:random_value")

    def test_session_lookup_writer_is_watched(self):
        views = W_VIEWS.replace('    if ev.door_code != request.POST.get("door"):\n        return HttpResponseForbidden()\n', "")
        rep = scan(project(self, {"conf/urls.py": W_URLS, "shop/models.py": W_MODELS, "shop/views.py": views}))
        self.assertEqual([w["entry"]["view"] for w in watched(rep, "session_lookup")], ["shop.views.enter_event"])

    def test_weakened_watched_generator_is_a_finding(self):
        root = self.w_project()
        findings, code = run_diff(self, root, lambda: replace_in(root, "shop/views.py", "secrets.token_urlsafe(32)",
                                                                 "secrets.token_urlsafe(2)"))
        self.assertEqual(code, 4, findings)
        self.assertEqual([f["tier"] for f in findings if f["kind"] == "fingerprint_changed"], ["watched"])

    def test_new_route_to_a_watched_site_is_a_finding(self):
        root = self.w_project()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "conf/urls.py", 'path("event/", views.event_page)]',
            'path("event/", views.event_page), path("v2/grant/", views.issue_grant)]'))
        self.assertTrue(code & 4, findings)
        self.assertIn("now also reached from route:v2/grant/", " ".join(f["message"] for f in findings))

    def test_edits_elsewhere_on_the_path_are_not(self):
        root = self.w_project()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/views.py", "def event_page(request):", "def unrelated():\n    return 1\n\n\n"
                                                               "def event_page(request):"))
        self.assertEqual(code, 0, findings)

    def test_unreferenced_generator_is_watched(self):
        keys = "import secrets\n\n\ndef spare_api_token():\n    return secrets.token_urlsafe(40)\n"
        rep = scan(project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/keys.py": keys}))
        self.assertEqual([w["entry"]["view"] for w in watched(rep, "unreferenced")], ["shop.keys.spare_api_token"])

    def test_cli_report_and_accept_group(self):
        import os
        import subprocess
        import sys
        from mm_testutil import PROTO
        root = self.w_project()

        def cli(*args):
            return subprocess.run([sys.executable, "-I", os.path.join(PROTO, "tests", "_cli.py"), *args],
                                  capture_output=True, text=True, timeout=120)
        out = cli("scan", root).stdout
        self.assertIn("watched:random_value", out)
        self.assertIn("set aside: ", out)
        self.assertEqual(cli("init", root).returncode, 0)
        r = cli("accept", root, "--all", "--reviewer", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(cli("diff", root).returncode, 0)
        with open(os.path.join(root, "mintmap.lock")) as fh:
            lock = json.load(fh)
        self.assertEqual(sorted(g["id"] for g in lock["watched"]), ["watched:random_value", "watched:signed_value"])
        r = cli("accept", root, "--group", "watched:signed_value", "--reviewer", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)


# ============================================================================ custom managers
MGR_MODELS = """\
import secrets

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone


class Member(AbstractBaseUser):
    email = models.EmailField(unique=True)
    is_superuser = models.BooleanField(default=False)
    USERNAME_FIELD = "email"
    objects = None


class MemberManager(BaseUserManager):
    def create_user(self, email, password=None, **extra):
        member = self.model(email=self.normalize_email(email), **extra)
        member.set_password(password)
        member.save()
        return member


Member.add_to_class("objects", MemberManager())


class KeyManager(models.Manager):
    def issue(self, owner, label):
        return self.create(owner=owner, label=label, secret=secrets.token_hex(24))


class ApiKey(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    label = models.CharField(max_length=40)
    secret = models.CharField(max_length=64)
    objects = KeyManager()


class LinkQuerySet(models.QuerySet):
    def usable(self):
        return self.filter(used=False, expires__gt=timezone.now())


class EntryLink(models.Model):
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    code = models.CharField(max_length=64)
    used = models.BooleanField(default=False)
    expires = models.DateTimeField()
    objects = LinkQuerySet.as_manager()
"""
MGR_VIEWS = """\
from django.contrib.auth import login
from django.http import HttpResponse, JsonResponse

from shop.models import ApiKey, EntryLink


def new_key(request):
    key = ApiKey.objects.issue(request.user, request.POST["label"])
    return JsonResponse({"key": key.secret})


def enter(request):
    link = EntryLink.objects.usable().filter(code=request.GET["c"]).first()
    if link is None:
        return HttpResponse(status=403)
    login(request, link.owner, backend="django.contrib.auth.backends.ModelBackend")
    return HttpResponse("in")
"""
MGR_URLS = """\
from django.urls import path
from shop import views
urlpatterns = [path("keys/", views.new_key), path("enter/", views.enter)]
"""


class CustomManagerTests(unittest.TestCase):
    def mgr_project(self):
        return project(self, {"conf/urls.py": MGR_URLS, "shop/models.py": MGR_MODELS, "shop/views.py": MGR_VIEWS})

    def test_manager_method_minting_a_token_is_routed(self):
        rep = scan(self.mgr_project())
        ps = [p for p in rep["paths"] if p["entry"]["id"].startswith("route:keys/")]
        self.assertEqual(len(ps), 1, [p["entry"]["id"] for p in rep["paths"]])
        self.assertIn("shop.models.KeyManager.issue", ps[0]["chain"])

    def test_weakened_manager_generator_is_a_finding(self):
        root = self.mgr_project()
        findings, code = run_diff(self, root, lambda: replace_in(root, "shop/models.py", "secrets.token_hex(24)",
                                                                 "str(owner.pk)"))
        self.assertTrue(code, findings)

    def test_queryset_check_on_a_login_path_is_fingerprinted(self):
        root = self.mgr_project()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/models.py", "return self.filter(used=False, expires__gt=timezone.now())", "return self.all()"))
        self.assertTrue(code & 4, findings)

    def test_from_queryset_manager(self):
        models = MGR_MODELS.replace("objects = LinkQuerySet.as_manager()",
                                    "objects = models.Manager.from_queryset(LinkQuerySet)()")
        root = project(self, {"conf/urls.py": MGR_URLS, "shop/models.py": models, "shop/views.py": MGR_VIEWS})
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/models.py", "return self.filter(used=False, expires__gt=timezone.now())", "return self.all()"))
        self.assertTrue(code & 4, findings)


# ============================================================================ AUTH_HOOKS settings group
HOOK_FILES = {
    "conf/urls.py": "urlpatterns = []\n",
    "shop/perms.py": "def may_impersonate(request, target):\n    return request.user.is_superuser and "
                     "not target.is_superuser\n",
    "shop/signals.py": textwrap.dedent("""\
        from django.dispatch import receiver
        from directory_auth.backend import user_synced


        @receiver(user_synced)
        def grant_flags(sender, user=None, entry=None, **kwargs):
            user.is_staff = "ops" in entry.groups
        """),
    "shop/rules.py": textwrap.dedent("""\
        import rulebook


        @rulebook.predicate
        def is_owner(user, obj):
            return obj is not None and obj.owner_id == user.pk


        rulebook.add_perm("shop.rotate_key", is_owner)
        """),
}


class AuthHooksGroupTests(unittest.TestCase):
    def hooks_project(self):
        return project(self, HOOK_FILES, settings_extra='IMPERSONATE_PERMISSION_CHECK = "shop.perms.may_impersonate"\n'
                                                       'CACHE_TIMEOUT_HELPER = "shop.perms.may_impersonate"\n')

    def test_group_lists_the_three_kinds_of_hooks(self):
        rep = scan(self.hooks_project())
        grp = [g for g in rep["settings_groups"] if g["id"] == "settings:AUTH_HOOKS(project code)"]
        self.assertEqual(len(grp), 1)
        self.assertEqual(sorted(grp[0]["fingerprint"]["sources"]),
                         ["shop.perms.may_impersonate", "shop.rules.is_owner", "shop.signals.grant_flags"])

    def test_each_hook_change_is_a_finding(self):
        for rel, old, new in (("shop/perms.py", "and not target.is_superuser", ""),
                              ("shop/signals.py", '"ops" in entry.groups', "True"),
                              ("shop/rules.py", "obj is not None and obj.owner_id == user.pk", "True")):
            with self.subTest(rel=rel):
                root = self.hooks_project()
                findings, code = run_diff(self, root, lambda: replace_in(root, rel, old, new))
                self.assertEqual(code, 4, findings)
                self.assertIn("AUTH_HOOKS", findings[0]["path_id"])


# ============================================================================ routing visibility
REG_URLS = "from shop import views  # noqa: F401\nfrom shop.registry import ROUTES\n\nurlpatterns = list(ROUTES)\n"
REG = textwrap.dedent("""\
    from django.urls import path

    ROUTES = []


    def page(pattern):
        def deco(fn):
            ROUTES.append(path(pattern, fn))
            return fn
        return deco
    """)
REG_VIEWS = textwrap.dedent("""\
    from django.contrib.auth import authenticate, login
    from django.http import HttpResponse

    from shop.registry import page


    @page("in/")
    def sign_in(request):
        user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
        if user is None:
            return HttpResponse(status=403)
        login(request, user)
        return HttpResponse("ok")
    """)
CLASS_SETTINGS = textwrap.dedent("""\
    from configurations import Configuration


    class Common(Configuration):
        SECRET_KEY = "fixture-only"
        ROOT_URLCONF = "conf.urls"
        INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
        MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                      "django.contrib.auth.middleware.AuthenticationMiddleware", "shop.middleware.HeaderLogin"]


    class Production(Common):
        DEBUG = False


    class Staging(Common):
        DEBUG = True
    """)
HEADER_MW = textwrap.dedent("""\
    from django.contrib.auth import authenticate, login


    class HeaderLogin:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            who = request.headers.get("X-User")
            if who:
                user = authenticate(request, remote_user=who)
                if user is not None:
                    login(request, user)
            return self.get_response(request)
    """)


class RoutingVisibilityTests(unittest.TestCase):
    def test_decorator_registry_is_a_gap_and_the_login_is_not_low(self):
        rep = scan(project(self, {"conf/urls.py": REG_URLS, "shop/registry.py": REG, "shop/views.py": REG_VIEWS}))
        self.assertTrue(gaps(rep, "url_list_filled_at_run_time"))
        p = [p for p in rep["paths"] if p["mint"]["api"] == "django.contrib.auth.login"]
        self.assertEqual(p[0]["entry"]["kind"], "unrouted")
        self.assertNotEqual(p[0]["review"]["risk"], "low")

    def test_class_based_settings_are_read(self):
        rep = scan(project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/middleware.py": HEADER_MW},
                           settings=CLASS_SETTINGS))
        self.assertTrue([p for p in rep["paths"] if p["entry"]["id"] == "middleware:shop.middleware.HeaderLogin"])
        self.assertFalse([g for g in gaps(rep, "missing_setting") if g["where"] == "MIDDLEWARE"])


# ============================================================================ middleware flows switched off by settings
class MiddlewareConditionTests(unittest.TestCase):
    FALLBACK = "django.contrib.auth.get_user (SECRET_KEY_FALLBACKS re-hash branch)"

    def run_with(self, extra):
        settings = textwrap.dedent("""\
            SECRET_KEY = "fixture-only"
            INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
            MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware",
                          "django.contrib.auth.middleware.AuthenticationMiddleware"]
            ROOT_URLCONF = "conf.urls"
            """) + extra
        return project(self, {"conf/urls.py": "urlpatterns = []\n"}, settings=settings)

    def test_rehash_branch_needs_fallbacks(self):
        rep = scan(self.run_with(""))
        self.assertFalse(flow_paths(rep, self.FALLBACK))
        self.assertTrue(disabled(rep, self.FALLBACK))
        root = self.run_with("")
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/settings.py", 'ROOT_URLCONF',
                                                                 'SECRET_KEY_FALLBACKS = ["old"]\nROOT_URLCONF'))
        self.assertTrue(code & 1, findings)


# ============================================================================ grouped heuristic sites
class GroupedSiteTests(unittest.TestCase):
    def test_new_entry_point_is_a_new_path(self):
        helper = textwrap.dedent("""\
            import secrets

            from shop.models import Pass


            def give_pass(user):
                return Pass.objects.create(holder=user, token=secrets.token_urlsafe(32))
            """)
        views = "from django.http import HttpResponse\n\nfrom shop.passes import give_pass\n\n\n" + "".join(
            f"def v{i}(request):\n    give_pass(request.user)\n    return HttpResponse('ok')\n\n\n"
            for i in range(4))
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [" + ", ".join(
            f"path('p{i}/', views.v{i})" for i in range(3)) + "]\n"
        root = project(self, {"conf/urls.py": urls, "shop/passes.py": helper, "shop/views.py": views,
                              "shop/models.py": PASS_MODEL.replace("code = models.CharField(max_length=64)",
                                                                   "token = models.CharField(max_length=64)")})
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/urls.py", "path('p2/', views.v2)]",
                                                                 "path('p2/', views.v2), path('p3/', views.v3)]"))
        self.assertTrue(code & 1, findings)
        self.assertIn("route:p3/", " ".join(f["message"] for f in findings if f["kind"] == "new_path"))


    def test_catalog_mint_behind_a_signal_receiver_is_one_entry(self):
        models = textwrap.dedent("""\
            from django.db import models
            from django.db.models.signals import post_save
            from django.dispatch import receiver
            from rest_framework.authtoken.models import Token


            class Bot(models.Model):
                user = models.OneToOneField("auth.User", on_delete=models.CASCADE)


            @receiver(post_save, sender=Bot)
            def give_token(sender, instance, created, **kwargs):
                if created:
                    Token.objects.create(user=instance.user)
            """)
        views = "from django.http import HttpResponse\n\nfrom shop.models import Bot\n\n\n" + "".join(
            f"def v{i}(request):\n    Bot.objects.create(user=request.user)\n"
            f"    return HttpResponse('ok')\n\n\n" for i in range(7))
        urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [" + ", ".join(
            f"path('b{i}/', views.v{i})" for i in range(6)) + "]\n"
        root = project(self, {"conf/urls.py": urls, "shop/views.py": views, "shop/models.py": models})
        rep = scan(root)
        tok = [p for p in rep["paths"] if p["mint"]["api"] == "rest_framework.authtoken.models.Token.objects.create"]
        self.assertEqual(len(tok), 1, [p["entry"]["id"] for p in tok])
        self.assertEqual(len(tok[0]["entry"]["reached_from"]), 6)
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/urls.py", "path('b5/', views.v5)]",
                                                                 "path('b5/', views.v5), path('b6/', views.v6)]"))
        self.assertTrue(code & 1, findings)


# ============================================================================ name fallback
def registry_project(tc, n):
    backends = "from django.contrib.auth import get_user_model\n\n\n" + "".join(
        f"class B{i}:\n    def check_entry(self, request, data):\n"
        f"        user = get_user_model().objects.filter(email=data['e']).first()\n"
        f"        if user is not None and user.check_password(data['p'] + '{i}'):\n"
        f"            return user\n        return None\n\n\n" for i in range(n))
    backends += "def pick(request):\n    return [" + ", ".join(f"B{i}" for i in range(n)) + \
                "][int(request.POST['b'])]()\n"
    views = textwrap.dedent("""\
        from django.contrib.auth import login
        from django.http import HttpResponse

        from shop.backends import pick


        def sign_in(request):
            user = pick(request).check_entry(request, request.POST)
            if user is None:
                return HttpResponse(status=403)
            login(request, user)
            return HttpResponse("ok")
        """)
    return project(tc, {"conf/urls.py": "from django.urls import path\nfrom shop.views import sign_in\n"
                                        "urlpatterns = [path('in/', sign_in)]\n",
                        "shop/backends.py": backends, "shop/views.py": views})


class NameFallbackTests(unittest.TestCase):
    def test_four_definitions_are_hashed(self):
        root = registry_project(self, 4)
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "shop/backends.py", "user.check_password(data['p'] + '3')", "True"))
        self.assertTrue(code & 4, findings)

    def test_more_than_the_limit_marks_the_fingerprint_incomplete(self):
        rep = scan(registry_project(self, 8))
        p = [p for p in rep["paths"] if p["entry"]["id"].startswith("route:in/")][0]
        self.assertFalse(p["fingerprint_complete"])
        self.assertTrue([g for g in p["gaps"] if g.startswith("fingerprint_name_fallback_limit|")])


# ============================================================================ extract refactors
class ExtractRefactorTests(unittest.TestCase):
    def test_mint_moved_into_a_private_method_or_module_helper(self):
        views = textwrap.dedent("""\
            import secrets

            from django.http import JsonResponse
            from django.views import View

            from shop.models import Pass


            class Issue(View):
                def post(self, request):
                    p = Pass.objects.create(holder=request.user, token=secrets.token_urlsafe(32))
                    return JsonResponse({"t": p.token})
            """)
        model = PASS_MODEL.replace("code = models.CharField(max_length=64)", "token = models.CharField(max_length=64)")
        urls = "from django.urls import path\nfrom shop.views import Issue\nurlpatterns = [path('i/', Issue.as_view())]\n"
        for name, edit in (
                ("method", lambda t: t.replace(
                    "        p = Pass.objects.create(holder=request.user, token=secrets.token_urlsafe(32))\n",
                    "        p = self._make(request.user)\n").replace(
                    "    def post(self, request):",
                    "    def _make(self, holder):\n        return Pass.objects.create(holder=holder, "
                    "token=secrets.token_urlsafe(32))\n\n    def post(self, request):")),
                ("module", lambda t: t.replace(
                    "        p = Pass.objects.create(holder=request.user, token=secrets.token_urlsafe(32))\n",
                    "        p = _make(request.user)\n").replace(
                    "class Issue(View):", "def _make(holder):\n    return Pass.objects.create(holder=holder, "
                                          "token=secrets.token_urlsafe(32))\n\n\nclass Issue(View):"))):
            with self.subTest(name=name):
                root = project(self, {"conf/urls.py": urls, "shop/views.py": views, "shop/models.py": model})
                findings, code = run_diff(self, root, lambda: write(root, "shop/views.py",
                                                                    edit(read(root, "shop/views.py"))))
                self.assertEqual(code, 0, findings)

    def test_extract_method_in_a_hook_class(self):
        validator = textwrap.dedent("""\
            from django.contrib.auth import authenticate
            from oauth2_provider.oauth2_validators import OAuth2Validator


            class OrgValidator(OAuth2Validator):
                def validate_user(self, username, password, client, request, *args, **kwargs):
                    who = authenticate(request=request, username=username, password=password)
                    if who is not None and who.is_active and who.org_id == client.org_id:
                        request.user = who
                        return True
                    return False
            """)
        settings_extra = 'OAUTH2_PROVIDER = {"OAUTH2_VALIDATOR_CLASS": "shop.validators.OrgValidator"}\n'
        urls = "from django.urls import include, path\nurlpatterns = [path('o/', include('oauth2_provider.urls'))]\n"
        root = project(self, {"conf/urls.py": urls, "shop/validators.py": validator}, settings_extra=settings_extra)

        def mutate():
            t = read(root, "shop/validators.py").replace(
                "if who is not None and who.is_active and who.org_id == client.org_id:",
                "if who is not None and self._same_org(who, client):")
            write(root, "shop/validators.py", t + "\n    def _same_org(self, who, client):\n"
                                                  "        return who.is_active and who.org_id == client.org_id\n")
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)


if __name__ == "__main__":
    unittest.main()

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
    StartupMigrationTests     a mint only a data migration reaches is a `startup_only` candidate, not dropped
    DynamicDispatchTests      a generator in a module that code dispatches into with getattr(module, <computed>) is
                              not dead code
    RequestAuthenticatorTests `request.user = ...` without a credential check is a high-ranked candidate; Channels
                              scope["user"], another framework's authenticate(self, request, ...) and a helper called
                              through SimpleLazyObject(lambda: ...) are covered
    UncataloguedAuthCallTests a function of a package the catalog does not cover whose name says it logs in or issues
                              a token, called with the request or a user, is an `auth_library_call` candidate
    PackageSettingsGroupTests DEBUG is an allauth setting only in a project that uses allauth, and only DEBUG itself
"""
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
                rep = scan(self.base(settings=settings, extra={"conf/env.py": "def load_overrides():\n"
                                                                              "    return {}\n"}))
                self.assertTrue(gaps(rep, "dynamic_setting"), line)
                self.assertTrue(flow_paths(rep, RESET_LOGIN), line)


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


if __name__ == "__main__":
    unittest.main()

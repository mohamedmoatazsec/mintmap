"""v5 part B: tests for the remaining root causes of the held-out evaluation of v4 (round 2, summarised in docs/EVALUATION.md):
R3 custom credential generators, R5 project hooks called by library flows, R7 coarse settings fingerprint,
R8 refactor false alarms (alpha-renaming, extracted helpers).

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

R7  SettingsGroupTests         global auth settings are one lock entry per group (one finding per change); paths
                               still change when they depend on a setting specifically (authenticate() and the
                               backends, DRF defaults, settings read by path code, catalog flow settings, the
                               conditions that include a middleware); new middleware is still a new path
R5  HookTests                  project code named by library hook settings (allauth adapter / token strategy,
                               DRF default permission classes, social pipeline, AUTHENTICATION_BACKENDS for
                               library login flows) is fingerprinted (`hooks`) and listed in the evidence; a mint
                               inside a hook is linked to the library routes; a dynamic hook setting is a gap
R3  CustomCredentialTests      values of randomness sources kept as credentials (model attribute in save(), model
                               field default -> creation sites, cache/session store, credential-named function) are
                               heuristic mint paths, also through DRF serializer.save() / library create flows;
                               OAuth state, file names, identifiers, outbound webhook secrets, random unusable
                               passwords, update saves and unsaved instances are set aside
R8  AlphaRenamingTests         renaming function-local variables keeps every fingerprint and gap key; swapping
                               variables, renaming attributes / parameters / keyword arguments is still a change
    ExtractFunctionTests       conservative inlining of extracted same-module helpers (statement helper, hoisted
                               helper with a return value, single-expression helper); a later change of the
                               helper is detected; helpers that do not meet the conditions are not inlined
"""
import textwrap
import unittest

from mm_testutil import scan, write, read, one_path, paths_for, accept_all
from test_v5 import project, run_diff, gaps

from mintmap.core.lockfile import build_lock, merge_lock, diff

VIEWS_BASE = """\
import logging

from django.contrib.auth import authenticate, login
from django.http import HttpResponse, HttpResponseForbidden

from shop.flags import get_flag

logger = logging.getLogger(__name__)
MAINTENANCE = False


def sign_in(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponseForbidden()
    enabled = get_flag("login")
    if not enabled:
        return HttpResponseForbidden()
    if MAINTENANCE:
        logger.warning("maintenance")
        audit = {"user": user.pk, "ip": request.META.get("REMOTE_ADDR")}
        logger.info("audit %s", audit)
    login(request, user)
    return HttpResponse("ok")
"""
FLAGS = """\
def get_flag(name):
    return name != "off"
"""
URLS = """\
from django.urls import path
from shop.views import sign_in
urlpatterns = [path("in/", sign_in)]
"""


def r8_project(tc, views=VIEWS_BASE):
    return project(tc, {"conf/urls.py": URLS, "shop/views.py": views, "shop/flags.py": FLAGS})


def replace_in(root, rel, old, new):
    text = read(root, rel)
    assert old in text, old
    write(root, rel, text.replace(old, new))


# ============================================================================ R3
R3_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
"""
R3_MODELS = """\
import secrets
import string
import uuid

from django.db import models

ALPHABET = string.ascii_letters + string.digits


def new_device_secret():
    return secrets.token_hex(20)


class AccessKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    secret = models.CharField(max_length=40, blank=True)

    def save(self, *args, **kwargs):
        if not self.secret:
            self.secret = self.make_secret()
        return super().save(*args, **kwargs)

    @staticmethod
    def make_secret(length=40):
        return "".join(secrets.choice(ALPHABET) for _ in range(length))


class Device(models.Model):
    code = models.UUIDField(default=uuid.uuid4, unique=True)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    device_secret = models.CharField(max_length=40, default=new_device_secret)


class Hook(models.Model):
    target = models.URLField()
    secret = models.CharField(max_length=40, default=new_device_secret)
"""
R3_SERIALIZERS = """\
from rest_framework import serializers

from shop.models import AccessKey, Device


class AccessKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessKey
        fields = ["owner"]

    def create(self, validated_data):
        return super().create(validated_data)


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["owner"]
"""
R3_VIEWS = """\
import secrets
import uuid

from django.core.cache import cache
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from shop.models import AccessKey, Device, Hook
from shop.serializers import AccessKeySerializer, DeviceSerializer


class KeyProvisionView(APIView):
    def post(self, request):
        serializer = AccessKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(status=201)

    def perform_create(self, serializer):
        serializer.save()


class DeviceViewSet(ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer


def pair_device(request):
    Device.objects.create(owner=request.user)
    return HttpResponse("ok")


def send_login_code(request):
    code = str(secrets.randbelow(900000) + 100000)
    cache.set(f"login:{request.POST['email']}", {"code": code, "tries": 0}, 600)
    return HttpResponse("sent")


def start_oauth(request):
    state = uuid.uuid4().hex
    request.session["oauth_state"] = state
    return HttpResponse(state)


def upload_avatar(request):
    upload = Device.objects.get(pk=request.POST["pk"])
    upload.filename = uuid.uuid4().hex + ".png"
    upload.save()
    return HttpResponse("ok")


def disable_password(request):
    request.user.set_password(secrets.token_urlsafe(32))
    request.user.save()
    return HttpResponse("ok")


def reset_password_by_mail(request):
    new_password = secrets.token_urlsafe(12)
    request.user.set_password(new_password)
    request.user.save()
    request.user.email_user("new password", new_password)
    return HttpResponse("ok")


def add_hook(request):
    Hook.objects.create(target=request.POST["url"])
    return HttpResponse("ok")


def preview_device(request):
    tmp = Device(owner=request.user)
    return HttpResponse(tmp.code)


def rename_device(request, pk):
    serializer = DeviceSerializer(Device.objects.get(pk=pk), data=request.POST)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return HttpResponse("ok")
"""
R3_URLS = """\
from django.urls import path
from rest_framework.routers import DefaultRouter

from shop import views

router = DefaultRouter()
router.register("devices", views.DeviceViewSet)
urlpatterns = [
    path("keys/provision/", views.KeyProvisionView.as_view()),
    path("devices/pair/", views.pair_device),
    path("login/code/", views.send_login_code),
    path("oauth/start/", views.start_oauth),
    path("avatar/", views.upload_avatar),
    path("password/disable/", views.disable_password),
    path("password/mail/", views.reset_password_by_mail),
    path("hooks/", views.add_hook),
    path("devices/preview/", views.preview_device),
    path("devices/<int:pk>/rename/", views.rename_device),
] + router.urls
"""


def r3_project(tc):
    return project(tc, {"conf/urls.py": R3_URLS, "shop/models.py": R3_MODELS, "shop/serializers.py": R3_SERIALIZERS,
                        "shop/views.py": R3_VIEWS}, settings=R3_SETTINGS)


def heuristic(report, entry_prefix=None):
    return [p for p in report["paths"] if p["mint"].get("kind") == "heuristic_custom_credential"
            and (entry_prefix is None or p["entry"]["id"].startswith(entry_prefix))]


class CustomCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tc = unittest.TestCase()
        cls.root = None

    def report(self):
        self.root = r3_project(self)
        return scan(self.root)

    def test_secret_generated_in_model_save_reached_through_drf(self):
        rep = self.report()
        ps = heuristic(rep, "route:keys/provision/")
        self.assertEqual(len(ps), 1, [p["entry"]["id"] for p in heuristic(rep)])
        p = ps[0]
        self.assertEqual(p["mint"]["site"]["function"], "shop.models.AccessKey.make_secret")
        self.assertEqual(p["mint"]["api"], "secrets.choice")
        self.assertTrue(p["mint"]["purpose"].startswith("custom_") and p["mint"]["purpose"].endswith("_candidate"))
        self.assertEqual(p["mint"]["provided_by"], "project_code")
        self.assertIn("shop.models.AccessKey.save", p["chain"])
        cands = {c["function"] for c in rep["coverage"]["custom_credentials"]["candidates"]}
        self.assertIn("shop.models.AccessKey.make_secret", cands)

    def test_model_default_creation_sites_and_drf_library_create(self):
        rep = self.report()
        models = rep["coverage"]["custom_credentials"]["models_with_credential_defaults"]
        self.assertEqual(sorted(models), ["shop.models.Device"])
        self.assertEqual([f["field"] for f in models["shop.models.Device"]], ["device_secret"])
        pair = heuristic(rep, "route:devices/pair/")
        self.assertEqual([p["mint"]["api"] for p in pair], ["shop.models.Device.objects.create"])
        lib = [p for p in heuristic(rep, "route:devices/") if p["mint"]["provided_by"] == "library"]
        self.assertEqual(len(lib), 1, [p["entry"]["id"] for p in heuristic(rep)])
        self.assertIn("rest_framework create", lib[0]["mint"]["api"])

    def test_one_time_code_in_cache_and_emailed_password(self):
        rep = self.report()
        code = heuristic(rep, "route:login/code/")
        self.assertEqual(len(code), 1)
        self.assertEqual(code[0]["mint"]["purpose"], "custom_one_time_code_candidate")
        mailed = heuristic(rep, "route:password/mail/")
        self.assertEqual([p["mint"]["purpose"] for p in mailed], ["custom_password_candidate"])

    def test_non_credential_randomness_is_set_aside(self):
        rep = self.report()
        for prefix in ("route:oauth/start/", "route:avatar/", "route:password/disable/", "route:hooks/",
                       "route:devices/preview/", "route:devices/<int:pk>/rename/"):
            with self.subTest(route=prefix):
                self.assertEqual(heuristic(rep, prefix), [])
        aside = " ".join(str(r) for r in rep["coverage"]["custom_credentials"]["set_aside"])
        self.assertIn("state", aside)
        self.assertIn("nobody is given it", aside)
        self.assertIn("outbound integration secret", aside)
        self.assertIn("primary key", aside)
        self.assertIn("UUIDField", aside)

    def test_new_route_to_a_token_view_and_generator_change_fail_ci(self):
        root = r3_project(self)

        def add_route():
            write(root, "conf/urls.py", read(root, "conf/urls.py").replace(
                '    path("keys/provision/", views.KeyProvisionView.as_view()),\n',
                '    path("keys/provision/", views.KeyProvisionView.as_view()),\n'
                '    path("api/keys/compat/", views.KeyProvisionView.as_view()),\n'))
        findings, code = run_diff(self, root, add_route)
        self.assertTrue(code & 1, findings)
        self.assertTrue(any("api/keys/compat/" in f["message"] and "secrets.choice" in f["message"]
                            for f in findings if f["kind"] == "new_path"), findings)
        root = r3_project(self)

        def weaken():
            write(root, "shop/models.py", read(root, "shop/models.py").replace("range(length)", "range(4)"))
        findings, code = run_diff(self, root, weaken)
        self.assertTrue(code & 4, findings)


# ============================================================================ R7
R7_SETTINGS = """\
import os
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "shop"]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
if os.environ.get("HEADER_LOGIN", "off") == "on":
    MIDDLEWARE.append("shop.middleware.HeaderLogin")
AUTHENTICATION_BACKENDS = ["shop.backends.PinBackend"]
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}
ROOT_URLCONF = "conf.urls"
"""
R7_FILES = {
    "conf/urls.py": """\
        from django.urls import path
        from shop import views
        urlpatterns = [path("in/", views.sign_in), path("token/", views.TokenView.as_view()),
                       path("token2/", views.OpenTokenView.as_view())]
    """,
    "shop/backends.py": """\
        class PinBackend:
            def authenticate(self, request, username=None, pin=None):
                from shop.models import Member
                member = Member.objects.filter(name=username).first()
                if member is not None and member.check_password(pin):
                    return member
                return None
    """,
    "shop/middleware.py": """\
        from django.conf import settings
        from django.contrib.auth import login


        class HeaderLogin:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                if settings.TRUST_HEADER and request.headers.get("X-User"):
                    login(request, request.headers["X-User"])
                return self.get_response(request)
    """,
    "shop/views.py": """\
        from django.contrib.auth import authenticate, login
        from django.http import HttpResponse
        from rest_framework.authtoken.models import Token
        from rest_framework.permissions import AllowAny
        from rest_framework.response import Response
        from rest_framework.views import APIView


        def sign_in(request):
            user = authenticate(request, username=request.POST["u"], pin=request.POST["p"])
            if user is None:
                return HttpResponse(status=403)
            login(request, user)
            return HttpResponse("ok")


        class TokenView(APIView):
            def post(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return Response({"token": token.key})


        class OpenTokenView(APIView):
            permission_classes = [AllowAny]

            def post(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return Response({"token": token.key})
    """,
}


def r7_project(tc, settings_extra=""):
    return project(tc, R7_FILES, settings=R7_SETTINGS, settings_extra=settings_extra)


def findings_by(findings, kind=None):
    return sorted((f["path_id"] or "-") for f in findings if kind is None or f["kind"] == kind)


class SettingsGroupTests(unittest.TestCase):
    def ids(self, root):
        rep = scan(root)
        return {p["entry"]["id"].split("|")[0]: p["id"] for p in rep["paths"]}, rep

    def test_lock_has_one_entry_per_settings_group(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        lock = build_lock(scan(root))
        self.assertEqual(sorted(g["id"] for g in lock["settings"]),
                         ["settings:AUTHENTICATION_BACKENDS", "settings:INSTALLED_APPS(auth)", "settings:MIDDLEWARE",
                          "settings:REST_FRAMEWORK"])
        self.assertEqual({g["review_status"] for g in lock["settings"]}, {"unreviewed"})
        _f, code = diff(lock, scan(root))
        self.assertEqual(code, 64)
        self.assertEqual(diff(accept_all(lock), scan(root))[1], 0)

    def test_global_middleware_change_is_one_finding(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')

        def mutate():
            write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
                '    "django.contrib.auth.middleware.AuthenticationMiddleware",\n',
                '    "django.contrib.auth.middleware.AuthenticationMiddleware",\n'
                '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n'))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 4, findings)
        self.assertEqual(findings_by(findings), ["settings:MIDDLEWARE"])
        self.assertIn("+'django.middleware.clickjacking.XFrameOptionsMiddleware'", findings[0]["message"])

    def test_new_minting_middleware_is_still_a_new_path(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')

        def mutate():
            write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
                '    "django.contrib.auth.middleware.AuthenticationMiddleware",\n',
                '    "django.contrib.auth.middleware.AuthenticationMiddleware",\n'
                '    "django.contrib.auth.middleware.RemoteUserMiddleware",\n'))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 1 | 4, findings)
        self.assertEqual(len([f for f in findings if f["kind"] == "new_path"]), 1)

    def test_backend_code_changes_the_paths_that_call_authenticate(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        ids, rep = self.ids(root)
        p = one_path(self, rep, "route:in/")
        self.assertIn("group:AUTHENTICATION_BACKENDS", p["fingerprint"]["settings_dependencies"])

        def mutate():
            write(root, "shop/backends.py", read(root, "shop/backends.py").replace(
                " and member.check_password(pin)", ""))
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)
        self.assertIn(ids["route:in/"], findings_by(findings))
        self.assertIn("settings:AUTHENTICATION_BACKENDS", findings_by(findings))
        self.assertNotIn(ids["route:token/"], findings_by(findings))

    def test_drf_default_classes_are_a_dependency_of_views_that_use_them(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        ids, rep = self.ids(root)
        self.assertIn("rf:DEFAULT_PERMISSION_CLASSES",
                      one_path(self, rep, "route:token/|")["fingerprint"]["settings_dependencies"])
        self.assertNotIn("rf:DEFAULT_PERMISSION_CLASSES",
                         one_path(self, rep, "route:token2/")["fingerprint"]["settings_dependencies"])

        def mutate():
            write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
                "rest_framework.permissions.IsAuthenticated", "rest_framework.permissions.AllowAny"))
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)
        got = findings_by(findings)
        self.assertIn(ids["route:token/"], got)
        self.assertIn("settings:REST_FRAMEWORK", got)
        self.assertNotIn(ids["route:token2/"], got)
        self.assertNotIn(ids["route:in/"], got)

    def test_non_authentication_rest_framework_key_is_not_a_change(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        findings, code = run_diff(self, root, lambda: write(root, "conf/settings.py", read(
            root, "conf/settings.py").replace("JSONRenderer", "BrowsableAPIRenderer")))
        self.assertEqual(code, 0, findings)

    def test_setting_read_by_path_code_and_middleware_condition(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        ids, rep = self.ids(root)
        mw = one_path(self, rep, "middleware:shop.middleware.HeaderLogin")
        deps = mw["fingerprint"]["settings_dependencies"]
        self.assertIn("setting:TRUST_HEADER", deps)
        self.assertIn("item:MIDDLEWARE:shop.middleware.HeaderLogin", deps)
        for old, new in (("TRUST_HEADER = False", "TRUST_HEADER = True"),
                         ('"HEADER_LOGIN", "off"', '"HEADER_LOGIN", "on"')):
            with self.subTest(change=new):
                root = r7_project(self, 'TRUST_HEADER = False\n')
                findings, code = run_diff(self, root, lambda: write(root, "conf/settings.py", read(
                    root, "conf/settings.py").replace(old, new)))
                self.assertTrue(code & 4, findings)
                self.assertIn(ids["middleware:shop.middleware.HeaderLogin"], findings_by(findings))
                self.assertNotIn(ids["route:in/"], findings_by(findings))

    def test_catalog_flow_setting_is_a_dependency_of_that_flow_only(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import include, path
            urlpatterns = [path("accounts/", include("allauth.urls"))]
        """}, settings_extra='ACCOUNT_LOGIN_TIMEOUT = 900\nACCOUNT_EMAIL_REQUIRED = True\n')
        rep = scan(root)
        # (v6) the flow setting used to be ACCOUNT_LOGIN_ON_PASSWORD_RESET; since v6 a False value switches that flow
        # off (catalog `library_flow_conditions`), so the test uses the stashed-login timeout of the login stages
        reset = [p for p in rep["paths"] if "stash_login" in p["mint"]["api"]]
        self.assertEqual(len(reset), 1)

        def mutate():
            write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
                "ACCOUNT_LOGIN_TIMEOUT = 900", "ACCOUNT_LOGIN_TIMEOUT = 3600"))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 4, findings)
        self.assertEqual(findings_by(findings), sorted([reset[0]["id"], "settings:package:allauth"]))

    def test_update_keeps_the_review_of_unchanged_settings_groups(self):
        root = r7_project(self, 'TRUST_HEADER = False\n')
        lock = accept_all(build_lock(scan(root)))
        write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
            "rest_framework.permissions.IsAuthenticated", "rest_framework.permissions.AllowAny"))
        new, _notes = merge_lock(lock, scan(root))
        status = {g["id"]: g["review_status"] for g in new["settings"]}
        self.assertEqual(status["settings:REST_FRAMEWORK"], "unreviewed")
        self.assertEqual(status["settings:MIDDLEWARE"], "accepted")


# ============================================================================ R5
HOOK_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "allauth", "allauth.account",
                  "allauth.headless", "rest_framework", "rest_framework.authtoken", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
ACCOUNT_ADAPTER = "shop.adapters.ClosedAdapter"
HEADLESS_TOKEN_STRATEGY = "shop.adapters.ApiTokenStrategy"
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["shop.permissions.StaffOnly"]}
"""
HOOK_FILES = {
    "conf/urls.py": """\
        from django.urls import include, path
        from shop import views
        urlpatterns = [
            path("accounts/", include("allauth.urls")),
            path("api/auth/", include("allauth.headless.urls")),
            path("api/token/", views.TokenView.as_view()),
            path("api/token2/", views.OwnPermTokenView.as_view()),
        ]
    """,
    "shop/adapters.py": """\
        from allauth.account.adapter import DefaultAccountAdapter
        from allauth.headless.tokens.base import AbstractTokenStrategy
        from rest_framework.authtoken.models import Token


        class ClosedAdapter(DefaultAccountAdapter):
            def pre_authenticate(self, request, **credentials):
                if _password_login_disabled():
                    raise PermissionError("password login disabled")
                return super().pre_authenticate(request, **credentials)


        def _password_login_disabled():
            return True


        class ApiTokenStrategy(AbstractTokenStrategy):
            def create_access_token(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return token.key
    """,
    "shop/permissions.py": """\
        from rest_framework.permissions import BasePermission


        class StaffOnly(BasePermission):
            def has_permission(self, request, view):
                return bool(request.user and request.user.is_staff)
    """,
    "shop/views.py": """\
        from rest_framework.authtoken.models import Token
        from rest_framework.permissions import IsAuthenticated
        from rest_framework.response import Response
        from rest_framework.views import APIView


        class TokenView(APIView):
            def post(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return Response({"token": token.key})


        class OwnPermTokenView(APIView):
            permission_classes = [IsAuthenticated]

            def post(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return Response({"token": token.key})
    """,
}


class HookTests(unittest.TestCase):
    def hook_project(self, settings=HOOK_SETTINGS):
        return project(self, HOOK_FILES, settings=settings)

    def test_allauth_adapter_is_fingerprinted_on_allauth_flows(self):
        root = self.hook_project()
        rep = scan(root)
        allauth = [p for p in rep["paths"] if p["mint"]["provided_by"] == "library" and
                   p["mint"]["api"].startswith("allauth.")]
        self.assertTrue(allauth)
        for p in allauth:
            hooks = {h["setting"]: h for h in p["evidence"]["hooks"]}
            self.assertIn("ACCOUNT_ADAPTER", hooks)
            self.assertIn("shop.adapters._password_login_disabled", hooks["ACCOUNT_ADAPTER"]["functions"])
        others = [p for p in rep["paths"] if p["entry"]["id"].startswith("route:api/token")]
        self.assertTrue(all("ACCOUNT_ADAPTER" not in {h["setting"] for h in p["evidence"]["hooks"]} for p in others))

        def mutate():   # the adapter's gate now lets every password login through
            write(root, "shop/adapters.py", read(root, "shop/adapters.py").replace(
                "def _password_login_disabled():\n    return True", "def _password_login_disabled():\n    return False"))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 4, findings)
        changed = {f["path_id"] for f in findings}
        self.assertTrue({p["id"] for p in allauth} <= changed)
        self.assertFalse({p["id"] for p in others} & changed)

    def test_mint_inside_a_token_strategy_is_linked_to_the_library_routes(self):
        rep = scan(self.hook_project())
        strat = [p for p in rep["paths"] if (p["mint"]["site"] or {}).get("function") ==
                 "shop.adapters.ApiTokenStrategy.create_access_token"]
        self.assertTrue(strat)
        self.assertTrue(all(p["entry"]["kind"] != "unrouted" for p in strat), [p["entry"]["id"] for p in strat])
        self.assertIn("route:api/auth/|allauth.headless.urls", {p["entry"]["id"] for p in strat})

    def test_drf_default_permission_class_is_fingerprinted_on_views_that_use_it(self):
        root = self.hook_project()
        rep = scan(root)
        default_view = one_path(self, rep, "route:api/token/|")
        own_view = one_path(self, rep, "route:api/token2/")
        self.assertIn("REST_FRAMEWORK[DEFAULT_PERMISSION_CLASSES]",
                      {h["setting"] for h in default_view["evidence"]["hooks"]})
        self.assertNotIn("REST_FRAMEWORK[DEFAULT_PERMISSION_CLASSES]",
                         {h["setting"] for h in own_view["evidence"]["hooks"]})

        def mutate():
            write(root, "shop/permissions.py", read(root, "shop/permissions.py").replace(
                "return bool(request.user and request.user.is_staff)", "return True"))
        findings, code = run_diff(self, root, mutate)
        changed = {f["path_id"] for f in findings}
        self.assertIn(default_view["id"], changed)
        self.assertNotIn(own_view["id"], changed)
        self.assertIn("settings:REST_FRAMEWORK", changed)

    def test_social_pipeline_and_backends_for_library_login_flows(self):
        settings = HOOK_SETTINGS + ('SOCIAL_AUTH_PIPELINE = ["social_core.pipeline.social_auth.social_details",'
                                    ' "shop.pipeline.only_staff"]\n'
                                    'AUTHENTICATION_BACKENDS = ["shop.backends.LdapLike"]\n')
        files = dict(HOOK_FILES)
        files["conf/urls.py"] = """\
            from django.contrib.auth.views import LoginView
            from django.urls import include, path
            urlpatterns = [path("social/", include("social_django.urls")), path("login/", LoginView.as_view())]
        """
        files["shop/pipeline.py"] = """\
            def only_staff(backend, user=None, **kwargs):
                if user is not None and not user.is_staff:
                    raise PermissionError("staff only")
        """
        files["shop/backends.py"] = """\
            class LdapLike:
                def authenticate(self, request, username=None, password=None):
                    return None
        """
        root = project(self, files, settings=settings)
        rep = scan(root)
        social = [p for p in rep["paths"] if p["entry"]["id"].startswith("route:social/")]
        login = one_path(self, rep, "route:login/")
        self.assertTrue(social)
        self.assertIn("SOCIAL_AUTH_PIPELINE", {h["setting"] for p in social for h in p["evidence"]["hooks"]})
        self.assertIn("AUTHENTICATION_BACKENDS", {h["setting"] for h in login["evidence"]["hooks"]})

        def mutate():
            write(root, "shop/pipeline.py", read(root, "shop/pipeline.py").replace(
                '        raise PermissionError("staff only")', "        pass"))
            write(root, "shop/backends.py", read(root, "shop/backends.py").replace(
                "return None", "return username"))
        findings, code = run_diff(self, root, mutate)
        changed = {f["path_id"] for f in findings}
        self.assertTrue({p["id"] for p in social} <= changed)
        self.assertIn(login["id"], changed)

    def test_dynamic_hook_setting_is_a_gap(self):
        settings = HOOK_SETTINGS.replace('ACCOUNT_ADAPTER = "shop.adapters.ClosedAdapter"',
                                         'import os\nACCOUNT_ADAPTER = os.environ["ADAPTER"]')
        rep = scan(self.hook_project(settings))
        self.assertTrue(gaps(rep, "hook_setting_not_static"))
        allauth = [p for p in rep["paths"] if p["mint"]["provided_by"] == "library" and
                   p["mint"]["api"].startswith("allauth.")]
        self.assertTrue(allauth and all(not p["analysis_complete"] for p in allauth))
        self.assertTrue(all(any(g.startswith("hook_setting_not_static|") for g in p["gaps"]) for p in allauth))


# ============================================================================ R8
class AlphaRenamingTests(unittest.TestCase):
    def test_renaming_locals_keeps_the_fingerprint(self):
        root = r8_project(self)

        def mutate():
            text = read(root, "shop/views.py")
            text = text.replace("user = authenticate", "account = authenticate").replace(
                "if user is None", "if account is None").replace('"user": user.pk', '"user": account.pk').replace(
                "login(request, user)", "login(request, account)").replace("enabled", "switch_on").replace(
                "audit", "record").replace('"record %s", record', '"audit %s", record')
            write(root, "shop/views.py", text)
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_swapping_variables_is_a_change(self):
        root = r8_project(self, VIEWS_BASE.replace(
            "    login(request, user)\n", "    other = request.user\n    login(request, user)\n"))

        def mutate():
            replace_in(root, "shop/views.py", "    login(request, user)\n", "    login(request, other)\n")
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_renaming_an_attribute_or_keyword_or_parameter_is_a_change(self):
        for old, new in (('request.POST["p"]', 'request.GET["p"]'), ("password=request", "secret=request"),
                         ("def sign_in(request):", "def sign_in(req, request=None):")):
            with self.subTest(old=old):
                root = r8_project(self)
                findings, code = run_diff(self, root, lambda: replace_in(root, "shop/views.py", old, new))
                self.assertNotEqual(code, 0, findings)

    def test_renamed_receiver_of_an_unresolved_call_is_not_a_new_gap(self):
        views = VIEWS_BASE.replace('    enabled = get_flag("login")\n',
                                   '    holder = request.session\n    enabled = holder.get_flag("login")\n')
        root = r8_project(self, views)
        rep = scan(root)
        self.assertTrue([g for g in gaps(rep, "unresolved_call_on_path") if "holder.get_flag" in g["detail"]])

        def mutate():
            write(root, "shop/views.py", read(root, "shop/views.py").replace("holder", "store"))
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_locals_observed_by_locals_call_are_not_renamed(self):
        root = r8_project(self, VIEWS_BASE.replace("    login(request, user)\n",
                                                   "    logger.debug('%(enabled)s', locals())\n"
                                                   "    login(request, user)\n"))
        findings, code = run_diff(self, root, lambda: replace_in(root, "shop/views.py", "enabled", "flag_on"))
        self.assertTrue(code & 4, findings)


class ExtractFunctionTests(unittest.TestCase):
    STMT_HELPER = '''\


def _note_maintenance(user, request):
    if MAINTENANCE:
        logger.warning("maintenance")
        entry = {"user": user.pk, "ip": request.META.get("REMOTE_ADDR")}
        logger.info("audit %s", entry)
'''
    MAINT_BLOCK = '''\
    if MAINTENANCE:
        logger.warning("maintenance")
        audit = {"user": user.pk, "ip": request.META.get("REMOTE_ADDR")}
        logger.info("audit %s", audit)
'''

    def extract_statements(self, root, call="    _note_maintenance(user, request)\n", helper=None):
        text = read(root, "shop/views.py").replace(self.MAINT_BLOCK, call)
        write(root, "shop/views.py", text + (helper if helper is not None else self.STMT_HELPER))

    def test_extracted_statement_helper_keeps_the_fingerprint(self):
        root = r8_project(self)
        p = one_path(self, scan(root), "route:in/")
        self.assertNotIn("shop.views._note_maintenance", p["fingerprint"]["callee_functions"])
        findings, code = run_diff(self, root, lambda: self.extract_statements(root))
        self.assertEqual(code, 0, findings)
        p = one_path(self, scan(root), "route:in/")
        # the helper is listed (its code is fingerprinted inside the caller's dump)
        self.assertIn("shop.views._note_maintenance", p["fingerprint"]["callee_functions"])

    def test_extracted_helper_with_a_return_value_used_in_a_test(self):
        root = r8_project(self)

        def mutate():
            replace_in(root, "shop/views.py", '    enabled = get_flag("login")\n    if not enabled:\n',
                       "    if not _login_enabled():\n")
            write(root, "shop/views.py", read(root, "shop/views.py") +
                  '\n\ndef _login_enabled():\n    enabled = get_flag("login")\n    return bool(enabled)\n')
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_single_expression_helper_anywhere(self):
        root = r8_project(self)

        def mutate():
            replace_in(root, "shop/views.py", 'request.META.get("REMOTE_ADDR")', "_client_ip(request)")
            write(root, "shop/views.py", read(root, "shop/views.py") +
                  '\n\ndef _client_ip(req):\n    return req.META.get("REMOTE_ADDR")\n')
        findings, code = run_diff(self, root, mutate)
        self.assertEqual(code, 0, findings)

    def test_a_later_change_of_the_inlined_helper_is_detected(self):
        root = r8_project(self)
        self.extract_statements(root)

        def mutate():
            replace_in(root, "shop/views.py", '        logger.warning("maintenance")\n',
                       '        logger.warning("maintenance")\n        login(request, user)\n')
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_helper_that_would_capture_a_caller_local_is_not_inlined(self):
        # the helper's free name `audit` would mean the caller's local variable once inlined
        root = r8_project(self, VIEWS_BASE.replace("import logging\n", "import logging\naudit = None\n"))
        helper = self.STMT_HELPER.replace('logger.info("audit %s", entry)', 'logger.info("audit %s", audit)')

        def mutate():
            self.extract_statements(root, helper=helper)
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_expression_argument_or_other_module_is_not_inlined(self):
        for variant in ("expr_arg", "other_module"):
            with self.subTest(variant=variant):
                root = r8_project(self)
                if variant == "expr_arg":
                    def mutate():
                        self.extract_statements(root, call="    _note_maintenance(user, request.user and request)\n")
                else:
                    def mutate():
                        text = read(root, "shop/views.py").replace(
                            self.MAINT_BLOCK, "    _note_maintenance(user, request)\n").replace(
                            "from shop.flags import get_flag\n",
                            "from shop.flags import get_flag\nfrom shop.audit import _note_maintenance\n")
                        write(root, "shop/views.py", text)
                        write(root, "shop/audit.py", "import logging\nlogger = logging.getLogger(__name__)\n"
                                                     "MAINTENANCE = False\n" + self.STMT_HELPER)
                findings, code = run_diff(self, root, mutate)
                self.assertTrue(code & 4, findings)

    def test_helper_with_early_return_is_not_inlined(self):
        root = r8_project(self)
        helper = textwrap.dedent('''\


            def _note_maintenance(user, request):
                if not MAINTENANCE:
                    return
                logger.warning("maintenance")
                entry = {"user": user.pk, "ip": request.META.get("REMOTE_ADDR")}
                logger.info("audit %s", entry)
            ''')
        findings, code = run_diff(self, root, lambda: self.extract_statements(root, helper=helper))
        self.assertTrue(code & 4, findings)


if __name__ == "__main__":
    unittest.main()

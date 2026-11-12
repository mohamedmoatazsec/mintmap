"""v6 (second part): false-alarm reductions and generalisation rules of the v6 round.

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    PrefixTwinTests            routes that differ only by a leading run-time URL prefix (`if not PREFIX: urlpatterns =
                               x else: urlpatterns = [path(PREFIX, include(x))]`) are one entry
    FlowConditionTests         catalogued library flows switched off by the project's settings (catalog
                               `library_flow_conditions`) are not paths, are listed, and enabling one is a new path
    UpdateIsNotCreationTests   read-only DRF viewsets have no create flow; perform_update / UpdateView saves and
                               perform_destroy(instance).save() update an existing row; a generator function nothing
                               calls or names is set aside until something does
    PredicateCallTests         `did_*` / `was_*` predicates of an authentication package are not auth_library_call
                               candidates
    RequestAuthenticatorTests  candidate tier `request_authenticator`: project DRF authentication classes (settings
                               default or a view attribute) and `request.user = ...` in project code are reviewed and
                               fingerprinted; weakening one is a finding
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


# ============================================================================ updates are not creations
DEVICE_MODELS = """\
import secrets

from django.db import models


def new_device_key():
    return secrets.token_urlsafe(24)


def spare_secret():
    return secrets.token_hex(16)


class Device(models.Model):
    name = models.CharField(max_length=40)
    active = models.BooleanField(default=True)
    api_key = models.CharField(max_length=40, default=new_device_key)
"""
DEVICE_API = """\
from django.views.generic.edit import UpdateView
from rest_framework import serializers, viewsets

from club.models import Device


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ["name"]


class DeviceBrowse(viewsets.ReadOnlyModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer


class DeviceAdmin(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer

    def perform_update(self, serializer):
        serializer.save(name=serializer.validated_data["name"].strip())

    def perform_destroy(self, instance):
        instance.active = False
        instance.save()


class DeviceRename(UpdateView):
    model = Device
    fields = ["name"]

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)
"""
DEVICE_URLS = """\
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from club import api

router = DefaultRouter()
router.register("browse", api.DeviceBrowse)
router.register("devices", api.DeviceAdmin)
urlpatterns = [path("api/", include(router.urls)), path("rename/<int:pk>/", api.DeviceRename.as_view())]
"""


class UpdateIsNotCreationTests(unittest.TestCase):
    def setUp(self):
        self.root = project(self, {"conf/urls.py": DEVICE_URLS, "club/models.py": DEVICE_MODELS,
                                   "club/api.py": DEVICE_API}, init=("conf", "club"))
        self.rep = scan(self.root)

    def mints(self):
        return sorted((p["entry"]["id"], p["mint"]["api"], (p["mint"].get("site") or {}).get("function"))
                      for p in self.rep["paths"])

    def test_only_the_create_flow_creates(self):
        ms = self.mints()
        self.assertEqual([m for m in ms if "Device" in m[1]],
                         [("route:api/devices/|club.api.DeviceAdmin", "club.models.Device via rest_framework create",
                           None)], ms)

    def test_unreferenced_generator_is_set_aside_until_called(self):
        self.assertFalse([m for m in self.mints() if m[2] == "club.models.spare_secret"])
        aside = self.rep["coverage"]["custom_credentials"]["unreferenced_functions_set_aside"]
        self.assertEqual([a["function"] for a in aside], ["club.models.spare_secret"])
        findings, code = run_diff(self, self.root, lambda: replace_in(
            self.root, "club/api.py", "        instance.active = False\n",
            "        instance.active = False\n        from club.models import spare_secret\n"
            "        instance.name = spare_secret()\n"))
        self.assertTrue(code & 1, findings)


# ============================================================================ predicates of auth packages
PREDICATE_VIEWS = """\
from django.http import HttpResponse
from allauth.account.internal.flows.reauthentication import did_recently_authenticate, reauthenticate_by_password


def sensitive(request):
    if not did_recently_authenticate(request):
        return HttpResponse(status=401)
    return HttpResponse("ok")


def step_up(request):
    reauthenticate_by_password(request)
    return HttpResponse("ok")
"""


class PredicateCallTests(unittest.TestCase):
    def test_predicate_is_not_a_candidate_but_a_flow_is(self):
        urls = """\
            from django.urls import path
            from club import pv
            urlpatterns = [path("sensitive/", pv.sensitive), path("stepup/", pv.step_up)]
        """
        rep = scan(project(self, {"conf/urls.py": urls, "club/pv.py": PREDICATE_VIEWS}, init=("conf", "club")))
        calls = [c["mint"]["api"] for c in rep["candidates"] if c["candidate"]["group"] == "auth_library_call"]
        self.assertEqual(calls, ["allauth.account.internal.flows.reauthentication.reauthenticate_by_password"])


# ============================================================================ request authenticators
AUTH_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "club"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["club.auth.KeyAuth"]}
"""
AUTH_CLASSES = """\
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

from club.models import AccessKey


class KeyAuth(authentication.TokenAuthentication):
    keyword = "Key"

    def authenticate_credentials(self, key):
        try:
            found = AccessKey.objects.select_related("owner").get(value=key)
        except AccessKey.DoesNotExist:
            raise exceptions.AuthenticationFailed("bad key")
        if not found.owner.is_active:
            raise exceptions.AuthenticationFailed("inactive")
        return found.owner, found


class HeaderAuth(authentication.BaseAuthentication):
    def authenticate(self, request):
        name = request.META.get("HTTP_X_MACHINE")
        if not name:
            return None
        return get_user_model().objects.get(username=name), None
"""
AUTH_MODELS = """\
from django.conf import settings
from django.db import models


class AccessKey(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    value = models.CharField(max_length=64)
"""
AUTH_VIEWS = """\
import base64

from django.contrib.auth import authenticate
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.views import APIView

from club.auth import HeaderAuth


class MachineStatus(APIView):
    authentication_classes = [HeaderAuth]

    def get(self, request):
        return Response({"user": request.user.username})


def git_endpoint(request):
    raw = base64.b64decode(request.META.get("HTTP_AUTHORIZATION", "").split(" ")[-1]).decode()
    name, _, secret = raw.partition(":")
    user = authenticate(request, username=name, password=secret)
    if user is None:
        return HttpResponse(status=401)
    request.user = user
    return HttpResponse("refs")


def leave(request):
    request.user = AnonymousUser()
    return HttpResponse("bye")
"""
AUTH_URLS = """\
from django.urls import path

from club import views

urlpatterns = [path("machine/", views.MachineStatus.as_view()), path("git/", views.git_endpoint),
               path("leave/", views.leave)]
"""


class RequestAuthenticatorTests(unittest.TestCase):
    def setUp(self):
        self.root = project(self, {"conf/urls.py": AUTH_URLS, "club/auth.py": AUTH_CLASSES,
                                   "club/models.py": AUTH_MODELS, "club/views.py": AUTH_VIEWS},
                            settings=AUTH_SETTINGS, init=("conf", "club"))
        self.rep = scan(self.root)

    def sites(self):
        return {c["mint"]["site"]["function"]: c for c in self.rep["candidates"]
                if c["candidate"]["group"] == "request_authenticator"}

    def test_authenticators_are_candidates(self):
        sites = self.sites()
        self.assertEqual(sorted(sites), ["club.auth.HeaderAuth.authenticate", "club.auth.KeyAuth.authenticate_credentials",
                                         "club.views.git_endpoint"])
        self.assertEqual(sites["club.auth.KeyAuth.authenticate_credentials"]["entry"]["reached_from"],
                         ["drf_auth_class:club.auth.KeyAuth"])
        self.assertEqual(sites["club.views.git_endpoint"]["entry"]["reached_from"], ["route:git/|club.views.git_endpoint"])

    def test_weakening_an_authenticator_is_a_finding(self):
        findings, code = run_diff(self, self.root, lambda: replace_in(
            self.root, "club/auth.py", "        if not found.owner.is_active:\n"
                                       "            raise exceptions.AuthenticationFailed(\"inactive\")\n", ""))
        self.assertTrue(code & 4, findings)
        self.assertTrue([f for f in findings if f.get("group") == "candidates:request_authenticator"], findings)


if __name__ == "__main__":
    unittest.main()

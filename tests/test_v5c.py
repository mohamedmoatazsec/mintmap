"""v5 review round: regression tests for the findings of two adversarial reviews of v5 part B.

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code and no reviewer fixture is copied.

    InlineCoverageTests        (R8 soundness) a helper reached only through inlined calls is hashed somewhere:
                               nested helpers the outer caller cannot inline (caller-local import, depth budget)
    ComprehensionScopeTests    (R8 soundness) comprehension variables are their own scope for alpha-renaming
    SettingsInPlaceTests       (R4) item `+=`, `.setdefault(k, d).append(...)`, `.get(k).append(...)` on an auth
                               setting are evaluated; a change MintMap cannot follow is a partially-unknown gap
    SplitSettingsTests         several settings modules: differing values are alternatives (every hook bound,
                               dicts merged); leaf settings modules not named by DJANGO_SETTINGS_MODULE are analysed
                               as alternatives, test settings modules are listed in a gap
    CoreSettingsTests          Django session-credential settings and project password hashers / session
                               serializers are part of the settings:AUTH_CORE entry
    InjectedCodeTests          project code handed to a library flow (as_view(**kwargs) of a library view, any class
                               attribute of a view inheriting library code, e.g. authentication_form) is analysed
                               and fingerprinted; confirm_login_allowed is a validation method
    LibraryKnowledgeTests      hook targets in uncatalogued packages, admin site class swaps, dependency versions the
                               catalog was not read in, legacy dj-rest-auth settings, catalog v3 additions
    ModuleValueTests           module-level values read by path code (a flag computed from a setting at import time,
                               a module constant gating a mint) are fingerprinted / settings dependencies
    UrlconfRootTests           per-request URLconfs (request.urlconf, *_URLCONF settings) are roots; an unreached
                               URLconf is still inventoried (paths carry a gap); a regular `apps/` package on
                               sys.path is importable by its short name
    CredentialShapeTests       (R3) hashed key stored as a digest on a credential-named model, a token stored by a
                               helper that receives it as a parameter (also with the model passed in), an
                               attribute of an untyped object, a pre_save receiver, an activation key, a
                               random.choices OTP in a per-user cache key; weak words alone (coupon / gift-card
                               codes) are set aside; the field default generator is fingerprinted
    SessionLoginTests          a session key that project code uses to load a principal: writing it is a mint
    LibraryTokenTests          catalog v3 library credential models (django-oauth-toolkit AccessToken), uncatalogued
                               library credential creation (heuristic), Django Channels websocket login and routes
    ReviewNoiseTests           a heuristic credential site reached from many entry points is one lock entry (one
                               finding per change); the callee-depth limit only clears `fingerprint_complete`
"""
import textwrap
import unittest

from mm_testutil import scan, write, read, one_path, paths_for, accept_all
from test_v5 import project, run_diff, gaps, path_gaps

from mintmap.core.lockfile import build_lock, merge_lock, diff


def replace_in(root, rel, old, new):
    text = read(root, rel)
    assert old in text, (old, rel)
    write(root, rel, text.replace(old, new))


MODELS = """\
from django.db import models


class Member(models.Model):
    handle = models.CharField(max_length=20)
    enabled = models.BooleanField(default=True)
"""
URLS_ENTER = """\
from django.urls import path
from club.views import enter
urlpatterns = [path("enter/", enter)]
"""


def club(tc, files, settings_extra=""):
    base = {"conf/urls.py": URLS_ENTER, "club/models.py": MODELS}
    base.update(files)
    return project(tc, base, settings_extra=settings_extra, init=("conf", "club"))


# ============================================================================ R8 inline coverage
NESTED_LOCAL_IMPORT = """\
from django.contrib.auth import login
from django.http import HttpResponse, HttpResponseForbidden

from club.models import Member


def _find(handle):
    return Member.objects.get(handle=handle, enabled=True)


def _member_for(handle):
    return _find(handle)


def enter(request):
    from club.models import Member
    handle = request.POST["h"]
    member = _member_for(handle)
    if not member.check_password(request.POST["pw"]):
        return HttpResponseForbidden()
    login(request, member)
    return HttpResponse("in")
"""

DEEP_CHAIN = """\
from django.contrib.auth import login
from django.http import HttpResponse, HttpResponseForbidden

from club.models import Member


def _l7(h):
    return Member.objects.get(handle=h, enabled=True)


def _l6(h):
    return _l7(h)


def _l5(h):
    return _l6(h)


def _l4(h):
    return _l5(h)


def _l3(h):
    return _l4(h)


def _l2(h):
    return _l3(h)


def _l1(h):
    return _l2(h)


def enter(request):
    h = request.POST["h"]
    member = _l1(h)
    if not member.check_password(request.POST["pw"]):
        return HttpResponseForbidden()
    login(request, member)
    return HttpResponse("in")
"""


class InlineCoverageTests(unittest.TestCase):
    def test_nested_helper_not_inlined_by_the_outer_caller_is_hashed(self):
        # the view's own `Member` import shadows the module-level name the inner helper uses: the outer dump
        # inlines _member_for but keeps the call of _find; _find must be hashed on its own
        root = club(self, {"club/views.py": NESTED_LOCAL_IMPORT})
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", "return Member.objects.get(handle=handle, enabled=True)",
            "return Member.objects.filter(enabled=False).first()"))
        self.assertTrue(code & 4, findings)

    def test_helper_chain_deeper_than_the_inline_budget_is_hashed(self):
        root = club(self, {"club/views.py": DEEP_CHAIN})
        p = one_path(self, scan(root), "route:enter/", "django.contrib.auth.login")
        self.assertIn("club.views._l7", p["fingerprint"]["callee_functions"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", "return Member.objects.get(handle=h, enabled=True)",
            "return Member.objects.order_by('pk').first()"))
        self.assertTrue(code & 4, findings)

    def test_extracting_a_single_helper_still_keeps_the_fingerprint(self):
        # control: the R8 normalisation itself still works (no false alarm for one extracted helper)
        inline = DEEP_CHAIN.replace("    member = _l1(h)\n", "    member = Member.objects.get(handle=h, enabled=True)\n")
        root = club(self, {"club/views.py": inline})
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", "    member = Member.objects.get(handle=h, enabled=True)\n",
            "    member = _l7(h)\n"))
        self.assertEqual(code, 0, findings)


# ============================================================================ R8 comprehension scope
COMP_VIEW = """\
from django.contrib.auth import login
from django.http import HttpResponse, HttpResponseForbidden

from club.models import Member


def pin_matches(member, pin):
    return member.check_password(pin)


def always(member, pin):
    return True


def enter(request):
    member = Member.objects.get(handle=request.POST["h"])
    tags = [pin_matches for pin_matches in request.POST.getlist("tag")]
    if not pin_matches(member, request.POST["pin"]):
        return HttpResponseForbidden()
    login(request, member)
    return HttpResponse(str(len(tags)))
"""


class ComprehensionScopeTests(unittest.TestCase):
    def test_comprehension_variable_does_not_hide_a_global_call(self):
        root = club(self, {"club/views.py": COMP_VIEW})

        def mutate():
            replace_in(root, "club/views.py", "    tags = [pin_matches for pin_matches in",
                       "    tags = [always for always in")
            replace_in(root, "club/views.py", "    if not pin_matches(member,", "    if not always(member,")
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_renaming_a_comprehension_variable_keeps_the_fingerprint(self):
        root = club(self, {"club/views.py": COMP_VIEW})
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", "[pin_matches for pin_matches in", "[t for t in"))
        self.assertEqual(code, 0, findings)

    def test_renaming_a_comprehension_variable_in_a_gap_key(self):
        root = club(self, {"club/views.py": COMP_VIEW.replace(
            "    tags = [pin_matches for pin_matches in request.POST.getlist(\"tag\")]\n",
            "    tags = [t.always(member, 1) for t in request.POST.getlist(\"tag\")]\n")})
        rep = scan(root)
        self.assertTrue([g for g in gaps(rep, "unresolved_call_on_path") if "%c.0.always" in g["key"]])
        findings, code = run_diff(self, root, lambda: replace_in(root, "club/views.py", "[t.always(member, 1) for t in",
                                                                 "[tag.always(member, 1) for tag in"))
        self.assertEqual(code, 0, findings)

    def test_walrus_in_comprehension_binds_in_the_function(self):
        from mintmap.core.fingerprint import normalize
        import ast
        a = ast.parse("def f(xs):\n    ys = [(last := x) for x in xs]\n    return last\n").body[0]
        b = ast.parse("def f(xs):\n    ys = [(final := x) for x in xs]\n    return final\n").body[0]
        c = ast.parse("def f(xs):\n    ys = [(final := x) for x in xs]\n    return last\n").body[0]
        self.assertEqual(normalize(a), normalize(b))
        self.assertNotEqual(normalize(a), normalize(c))


# ============================================================================ settings in place
DRF_SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "rest_framework", "rest_framework.authtoken",
                  "club"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}
"""
DRF_FILES = {
    "conf/urls.py": """\
        from django.urls import path
        from club.views import KeyView
        urlpatterns = [path("key/", KeyView.as_view())]
    """,
    "club/views.py": """\
        from rest_framework.authtoken.models import Token
        from rest_framework.response import Response
        from rest_framework.views import APIView


        class KeyView(APIView):
            def post(self, request):
                token, _ = Token.objects.get_or_create(user=request.user)
                return Response({"key": token.key})
    """,
}
BASIC = '"rest_framework.authentication.BasicAuthentication"'


def drf_club(tc, settings=DRF_SETTINGS):
    return project(tc, DRF_FILES, settings=settings, init=("conf", "club"))


class SettingsInPlaceTests(unittest.TestCase):
    def check_detected(self, extra):
        root = drf_club(self)
        findings, code = run_diff(self, root, lambda: write(root, "conf/settings.py",
                                                            read(root, "conf/settings.py") + extra))
        self.assertTrue(code & 4, findings)
        self.assertTrue([f for f in findings if f.get("path_id") == "settings:REST_FRAMEWORK"], findings)
        return findings

    def test_item_augmented_assignment(self):
        self.check_detected(f'REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] += [{BASIC}]\n')

    def test_setdefault_then_append(self):
        f = self.check_detected(f'REST_FRAMEWORK.setdefault("DEFAULT_AUTHENTICATION_CLASSES", []).append({BASIC})\n')
        self.assertTrue(any("BasicAuthentication" in x.get("message", "") for x in f), f)

    def test_get_then_append(self):
        self.check_detected(f'REST_FRAMEWORK.get("DEFAULT_AUTHENTICATION_CLASSES").append({BASIC})\n')

    def test_value_is_evaluated(self):
        root = drf_club(self, DRF_SETTINGS + f'REST_FRAMEWORK.setdefault("X", {{}}).setdefault("Y", []).append(1)\n'
                        f'REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] += ({BASIC},)\n')
        rep = scan(root)
        p = one_path(self, rep, "route:key/")
        self.assertFalse(gaps(rep, "setting_partially_unknown"))
        rf = [g for g in rep["settings_groups"] if g["id"] == "settings:REST_FRAMEWORK"][0]
        self.assertIn("BasicAuthentication", rf["values"]["REST_FRAMEWORK"])

    def test_unfollowed_change_is_a_gap(self):
        root = drf_club(self, DRF_SETTINGS + f'REST_FRAMEWORK.copy().update(X=1)\n'
                        f'REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"][0:0] = [{BASIC}]\n')
        rep = scan(root)
        self.assertEqual(len(gaps(rep, "setting_partially_unknown")), 2, rep["coverage"]["gaps"])


# ============================================================================ several settings modules
SPLIT_BASE = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "allauth", "allauth.account", "rest_framework",
                  "club"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
ACCOUNT_ADAPTER = "club.adapters.BaseAdapter"
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"]}
"""
SPLIT_FILES = {
    "conf/urls.py": """\
        from django.urls import include, path
        urlpatterns = [path("accounts/", include("allauth.urls"))]
    """,
    "conf/settings/__init__.py": "",
    "conf/settings/dev.py": """\
        from .base import *  # noqa
        ACCOUNT_ADAPTER = "club.adapters.DevAdapter"
    """,
    "conf/settings/live.py": """\
        from .base import *  # noqa
        ACCOUNT_ADAPTER = "club.adapters.LiveAdapter"
        REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] = [
            "rest_framework.authentication.SessionAuthentication", "club.auth.HeaderAuth"]
    """,
    "conf/settings/test.py": """\
        from .base import *  # noqa
        ACCOUNT_ADAPTER = "club.adapters.TestAdapter"
    """,
    "conf/wsgi.py": """\
        import os
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "conf.settings.dev")
    """,
    "club/adapters.py": """\
        from allauth.account.adapter import DefaultAccountAdapter


        class BaseAdapter(DefaultAccountAdapter):
            pass


        class DevAdapter(BaseAdapter):
            pass


        class LiveAdapter(BaseAdapter):
            def is_open_for_signup(self, request):
                return bool(request.session.get("invited"))


        class TestAdapter(BaseAdapter):
            pass
    """,
    "club/auth.py": """\
        from django.contrib.auth import get_user_model, login
        from rest_framework.authentication import BaseAuthentication


        class HeaderAuth(BaseAuthentication):
            def authenticate(self, request):
                user = get_user_model().objects.filter(username=request.headers.get("X-User")).first()
                if user is None:
                    return None
                login(request._request, user)
                return (user, None)
    """,
}


def split_project(tc):
    files = dict(SPLIT_FILES)
    files["conf/settings/base.py"] = SPLIT_BASE
    root = project(tc, files, init=("conf", "club"))
    import os
    os.remove(os.path.join(root, "conf/settings.py"))
    return root


class SplitSettingsTests(unittest.TestCase):
    def test_unselected_settings_module_is_analysed_as_an_alternative(self):
        root = split_project(self)
        rep = scan(root)
        self.assertEqual(sorted(rep["coverage"]["settings_modules"]), ["conf.settings.dev", "conf.settings.live"])
        self.assertTrue([g for g in gaps(rep, "settings_module_not_analyzed") if "conf.settings.test" in g["detail"]])
        allauth = [p for p in rep["paths"] if "allauth.urls" in p["entry"]["id"]]
        self.assertTrue(allauth)
        for p in allauth:
            bound = [c for h in p["fingerprint"]["hooks"] for c in h["project_code"]]
            self.assertIn("club.adapters.LiveAdapter", bound)
            self.assertIn("club.adapters.DevAdapter", bound)
            self.assertNotIn("club.adapters.TestAdapter", bound)
        # the live module's REST_FRAMEWORK change is kept (merged key by key): the minting class is an entry
        self.assertTrue(paths_for(rep, "drf_auth_class:club.auth.HeaderAuth"))

    def test_change_in_the_unselected_module_is_detected(self):
        root = split_project(self)
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/adapters.py", 'return bool(request.session.get("invited"))', "return True"))
        self.assertTrue(code & 4, findings)

    def test_differing_scalar_in_one_module_under_if_keeps_both(self):
        from mintmap.core.settings_extract import Alternatives
        root = project(self, {"conf/urls.py": "urlpatterns = []\n"}, settings_extra=(
            'import os\nif os.environ.get("LIVE"):\n    ACCOUNT_ADAPTER = "a.A"\nelse:\n'
            '    ACCOUNT_ADAPTER = "b.B"\n'))
        from mintmap.core.analysis import Analysis
        from mm_testutil import CATALOG
        a = Analysis(root, CATALOG)
        self.assertEqual(a.settings.values["ACCOUNT_ADAPTER"], Alternatives(["a.A", "b.B"]))


# ============================================================================ Django core session settings
class CoreSettingsTests(unittest.TestCase):
    def test_session_lifetime_change_is_a_finding(self):
        root = drf_club(self, DRF_SETTINGS + "SESSION_COOKIE_AGE = 3600\n")
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/settings.py", "SESSION_COOKIE_AGE = 3600",
                                                                 "SESSION_COOKIE_AGE = 10 * 365 * 86400"))
        self.assertEqual(code, 4, findings)
        self.assertEqual([f["path_id"] for f in findings if f["kind"] == "fingerprint_changed"], ["settings:AUTH_CORE"])

    def test_project_password_hasher_source_is_hashed(self):
        hasher = """\
            from django.contrib.auth.hashers import PBKDF2PasswordHasher


            class SaltyHasher(PBKDF2PasswordHasher):
                algorithm = "salty"

                def verify(self, password, encoded):
                    return super().verify(password + "pepper", encoded)
        """
        root = project(self, dict(DRF_FILES, **{"club/hashers.py": hasher}), init=("conf", "club"),
                       settings=DRF_SETTINGS + 'PASSWORD_HASHERS = ["club.hashers.SaltyHasher"]\n')
        core = [g for g in scan(root)["settings_groups"] if g["id"] == "settings:AUTH_CORE"][0]
        self.assertIn("club.hashers.SaltyHasher", core["fingerprint"]["sources"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/hashers.py", 'return super().verify(password + "pepper", encoded)', "return True"))
        self.assertEqual(code, 4, findings)


# ============================================================================ injected code
KEY_SERIALIZER = """\
    from rest_framework import serializers
    from rest_framework.authtoken.models import Token


    class KeySerializer(serializers.Serializer):
        username = serializers.CharField()

        def create(self, validated_data):
            token, _ = Token.objects.get_or_create(user=self.context["request"].user)
            return token
"""


class InjectedCodeTests(unittest.TestCase):
    def test_project_serializer_given_to_a_non_minting_library_view_is_analysed(self):
        files = {"conf/urls.py": """\
                    from django.urls import path
                    from rest_framework.generics import CreateAPIView
                    from rest_framework.permissions import AllowAny
                    urlpatterns = [path("x/", CreateAPIView.as_view(serializer_class=None))]
                 """, "club/serializers.py": KEY_SERIALIZER}
        root = project(self, files, settings=DRF_SETTINGS, init=("conf", "club"))

        def mutate():
            write(root, "conf/urls.py", textwrap.dedent("""\
                from django.urls import path
                from rest_framework.generics import CreateAPIView
                from rest_framework.permissions import AllowAny
                from club.serializers import KeySerializer
                urlpatterns = [path("x/", CreateAPIView.as_view(serializer_class=None)),
                               path("open/", CreateAPIView.as_view(serializer_class=KeySerializer,
                                                                   permission_classes=[AllowAny]))]
            """))
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 1, findings)
        p = one_path(self, scan(root), "route:open/")
        self.assertIn("club.serializers.KeySerializer.create", p["chain"])

    LOGIN_FORMS = """\
        from django.contrib.auth.forms import AuthenticationForm
        from django.core.exceptions import ValidationError


        class StaffLoginForm(AuthenticationForm):
            def confirm_login_allowed(self, user):
                super().confirm_login_allowed(user)
                if not user.is_staff:
                    raise ValidationError("staff only")


        class LockoutForm(AuthenticationForm):
            def clean(self):
                if self.request.session.get("locked"):
                    raise ValidationError("locked")
                return super().clean()
    """

    def test_login_form_given_through_as_view_kwarg(self):
        files = {"conf/urls.py": """\
                    from django.contrib.auth.views import LoginView
                    from django.urls import path
                    from club.forms import StaffLoginForm
                    urlpatterns = [path("staff/login/", LoginView.as_view(authentication_form=StaffLoginForm))]
                 """, "club/forms.py": self.LOGIN_FORMS}
        root = project(self, files, init=("conf", "club"))
        p = paths_for(scan(root), "route:staff/login/")[0]
        self.assertIn("club.forms.StaffLoginForm.confirm_login_allowed", p["evidence"]["validation_methods"])
        findings, code = run_diff(self, root, lambda: replace_in(root, "club/forms.py", "        if not user.is_staff:\n"
                                                                 '            raise ValidationError("staff only")\n', ""))
        self.assertTrue(code & 4, findings)

    def test_login_form_given_through_any_class_attribute(self):
        files = {"conf/urls.py": """\
                    from django.urls import path
                    from club.views import GuardedLogin
                    urlpatterns = [path("login/", GuardedLogin.as_view())]
                 """, "club/forms.py": self.LOGIN_FORMS, "club/views.py": """\
                    from django.contrib.auth.views import LoginView
                    from club.forms import LockoutForm


                    class GuardedLogin(LoginView):
                        authentication_form = LockoutForm
                 """}
        root = project(self, files, init=("conf", "club"))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/forms.py", '        if self.request.session.get("locked"):\n'
                                   '            raise ValidationError("locked")\n', ""))
        self.assertTrue(code & 4, findings)


# ============================================================================ library knowledge
class LibraryKnowledgeTests(unittest.TestCase):
    def test_hook_target_in_an_uncatalogued_package_is_a_path_gap(self):
        root = project(self, {"conf/urls.py": """\
                    from django.urls import include, path
                    urlpatterns = [path("accounts/", include("allauth.urls"))]
                 """}, init=("conf", "club"), settings_extra=(
            'INSTALLED_APPS += ["allauth", "allauth.account"]\nACCOUNT_ADAPTER = "vendorsso.adapter.SsoAdapter"\n'))
        rep = scan(root)
        self.assertTrue(gaps(rep, "hook_target_not_in_catalog"))
        allauth = [p for p in rep["paths"] if "allauth.urls" in p["entry"]["id"]]
        self.assertTrue(allauth)
        self.assertTrue(all(path_gaps(p, "hook_target_not_in_catalog") for p in allauth))

    def admin_project(self):
        return project(self, {"conf/urls.py": """\
                    from django.contrib import admin
                    from django.urls import path
                    from club.admin_site import StrictSite
                    admin.site.__class__ = StrictSite
                    urlpatterns = [path("admin/", admin.site.urls)]
                 """, "club/admin_site.py": """\
                    from django.contrib.admin import AdminSite


                    class StrictSite(AdminSite):
                        def has_permission(self, request):
                            return request.user.is_active and request.user.is_superuser
                 """}, init=("conf", "club"))

    def test_admin_site_class_swap_is_fingerprinted(self):
        root = self.admin_project()
        p = paths_for(scan(root), "route:admin/")[0]
        self.assertTrue([n for n in p["entry"]["notes"] if "changes the admin site" in n])
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/urls.py",
                                                                 "admin.site.__class__ = StrictSite\n", ""))
        self.assertTrue(code & 4, findings)
        root = self.admin_project()
        findings, code = run_diff(self, root, lambda: replace_in(root, "club/admin_site.py",
                                                                 " and request.user.is_superuser", ""))
        self.assertTrue(code & 4, findings)

    def test_dependency_version_outside_the_catalog_is_a_gap(self):
        root = drf_club(self)
        write(root, "requirements.txt", "djangorestframework==2.4.8\nDjango>=5.2\n")
        rep = scan(root)
        self.assertEqual([g["where"] for g in gaps(rep, "dependency_version_not_verified")], ["djangorestframework"])
        write(root, "requirements.txt", "djangorestframework==3.18.3\nDjango>=5.2\n")
        self.assertFalse(gaps(scan(root), "dependency_version_not_verified"))

    def test_legacy_dj_rest_auth_serializer_setting_is_a_hook(self):
        root = project(self, {"conf/urls.py": """\
                    from django.urls import include, path
                    urlpatterns = [path("auth/", include("dj_rest_auth.urls"))]
                 """, "club/serializers.py": """\
                    from dj_rest_auth.serializers import LoginSerializer


                    class TeamLogin(LoginSerializer):
                        def validate(self, attrs):
                            attrs = super().validate(attrs)
                            if not attrs["user"].is_active:
                                raise ValueError("inactive")
                            return attrs
                 """}, init=("conf", "club"), settings_extra=(
            'INSTALLED_APPS += ["rest_framework", "rest_framework.authtoken", "dj_rest_auth"]\n'
            'REST_AUTH_SERIALIZERS = {"LOGIN_SERIALIZER": "club.serializers.TeamLogin"}\n'))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/serializers.py", '        if not attrs["user"].is_active:\n'
                                         '            raise ValueError("inactive")\n', ""))
        self.assertTrue(code & 4, findings)

    def test_catalog_v3_declares_common_components(self):
        root = drf_club(self, DRF_SETTINGS.replace(
            '"rest_framework.authentication.SessionAuthentication"]',
            '"rest_framework.authentication.SessionAuthentication", '
            '"rest_framework_simplejwt.authentication.JWTAuthentication"]').replace(
            'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]',
            'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware", '
            '"allauth.account.middleware.AccountMiddleware"]'))
        rep = scan(root)
        self.assertFalse(gaps(rep, "middleware_not_in_catalog"))
        self.assertFalse(gaps(rep, "drf_auth_class_not_in_catalog"))


# ============================================================================ module-level values
HEADER_MW = """\
    from django.conf import settings
    from django.contrib.auth import get_user_model, login

    HEADER_LOGIN = getattr(settings, "HEADER_LOGIN", False)
    TRUSTED = ("10.0.0.1",)


    class HeaderLogin:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            if HEADER_LOGIN and request.META.get("REMOTE_ADDR") in TRUSTED:
                user = get_user_model().objects.filter(username=request.headers.get("X-User")).first()
                if user is not None:
                    login(request, user)
            return self.get_response(request)
"""


class ModuleValueTests(unittest.TestCase):
    def mw_project(self):
        return project(self, {"conf/urls.py": "urlpatterns = []\n", "club/mw.py": HEADER_MW}, init=("conf", "club"),
                       settings_extra='MIDDLEWARE += ["club.mw.HeaderLogin"]\nHEADER_LOGIN = False\n')

    def test_setting_read_at_import_time_is_a_dependency(self):
        root = self.mw_project()
        p = one_path(self, scan(root), "middleware:club.mw.HeaderLogin")
        self.assertIn("setting:HEADER_LOGIN", p["fingerprint"]["settings_dependencies"])
        findings, code = run_diff(self, root, lambda: replace_in(root, "conf/settings.py", "HEADER_LOGIN = False",
                                                                 "HEADER_LOGIN = True"))
        self.assertTrue(code & 4, findings)

    def test_module_constant_change_is_detected(self):
        root = self.mw_project()
        findings, code = run_diff(self, root, lambda: replace_in(root, "club/mw.py", 'TRUSTED = ("10.0.0.1",)',
                                                                 'TRUSTED = ("10.0.0.1", "0.0.0.0")'))
        self.assertTrue(code & 4, findings)
        root = self.mw_project()
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/mw.py", 'HEADER_LOGIN = getattr(settings, "HEADER_LOGIN", False)', "HEADER_LOGIN = True"))
        self.assertTrue(code & 4, findings)


# ============================================================================ URLconf roots
class UrlconfRootTests(unittest.TestCase):
    def test_per_request_urlconf_is_a_root(self):
        files = {
            "conf/urls.py": "urlpatterns = []\n",
            "conf/urls_staff.py": """\
                from django.urls import include, path
                urlpatterns = [path("", include("django.contrib.auth.urls"))]
            """,
            "conf/urls_partner.py": """\
                from django.contrib.auth.views import LoginView
                from django.urls import path
                urlpatterns = [path("login/", LoginView.as_view())]
            """,
            "club/mw.py": """\
                from django.conf import settings


                class PickUrls:
                    def __init__(self, get_response):
                        self.get_response = get_response

                    def __call__(self, request):
                        if request.get_host().startswith("staff."):
                            request.urlconf = "conf.urls_staff"
                        return self.get_response(request)
            """}
        root = project(self, files, init=("conf", "club"),
                       settings_extra='MIDDLEWARE += ["club.mw.PickUrls"]\nPARTNER_URLCONF = "conf.urls_partner"\n')
        rep = scan(root)
        self.assertEqual(sorted(rep["coverage"]["root_urlconfs"]), ["conf.urls", "conf.urls_partner",
                                                                    "conf.urls_staff"])
        self.assertTrue(paths_for(rep, "route:login/|django.contrib.auth.views.LoginView"))
        self.assertTrue(paths_for(rep, "route:|django.contrib.auth.urls"))
        self.assertFalse(gaps(rep, "urlconf_not_reached_from_root"))

    def test_unreached_urlconf_is_inventoried_with_a_gap(self):
        files = {"conf/urls.py": "urlpatterns = []\n", "club/urls.py": """\
                    from django.contrib.auth.views import LoginView
                    from django.urls import path
                    urlpatterns = [path("login/", LoginView.as_view())]
                 """}
        root = project(self, files, init=("conf", "club"))
        rep = scan(root)
        p = paths_for(rep, "route:login/")[0]
        self.assertFalse(p["analysis_complete"])
        self.assertTrue(path_gaps(p, "urlconf_not_reached_from_root"))

        def mutate():
            write(root, "club/urls.py", read(root, "club/urls.py").replace(
                'urlpatterns = [path("login/", LoginView.as_view())]',
                'from django.contrib.auth.views import PasswordResetConfirmView\n'
                'urlpatterns = [path("login/", LoginView.as_view()), '
                'path("r/<uidb64>/<token>/", PasswordResetConfirmView.as_view(post_reset_login=True))]'))
        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 1, findings)

    def test_regular_package_directory_on_sys_path(self):
        files = {
            "conf/urls.py": """\
                from django.urls import include, path
                urlpatterns = [path("people/", include("people.urls"))]
            """,
            "apps/__init__.py": "",
            "apps/people/__init__.py": "",
            "apps/people/urls.py": """\
                from django.urls import path
                from people import views
                urlpatterns = [path("enter/", views.enter)]
            """,
            "apps/people/forms.py": """\
                from django import forms
                from django.contrib.auth import authenticate


                class EnterForm(forms.Form):
                    name = forms.CharField()
                    pw = forms.CharField()

                    def clean(self):
                        self.user = authenticate(username=self.cleaned_data.get("name"),
                                                 password=self.cleaned_data.get("pw"))
                        if self.user is None:
                            raise forms.ValidationError("no")
                        return self.cleaned_data
            """,
            "apps/people/views.py": """\
                from django.contrib.auth import login
                from django.http import HttpResponse
                from people.forms import EnterForm


                def enter(request):
                    form = EnterForm(request.POST)
                    if form.is_valid():
                        login(request, form.user)
                    return HttpResponse("ok")
            """}
        root = project(self, files, init=("conf",), settings_extra=(
            'import os, sys\nBASE_DIR = os.path.dirname(os.path.dirname(__file__))\n'
            'sys.path.insert(0, os.path.join(BASE_DIR, "apps"))\n'))
        rep = scan(root)
        p = one_path(self, rep, "route:people/enter/", "django.contrib.auth.login")
        self.assertEqual(p["gaps"], [])
        self.assertIn("apps.people.forms.EnterForm.clean", p["evidence"]["validation_methods"])
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "apps/people/forms.py", "        if self.user is None:\n            raise forms.ValidationError(\"no\")\n",
            ""))
        self.assertTrue(code & 4, findings)


# ============================================================================ R3 shapes
CRED_MODELS = """\
    import secrets
    import uuid

    from django.conf import settings
    from django.db import models
    from django.db.models.signals import pre_save
    from django.dispatch import receiver


    def new_secret():
        return secrets.token_urlsafe(24)


    class ServiceKey(models.Model):
        owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
        lookup = models.CharField(max_length=8)
        digest = models.CharField(max_length=64)


    class StoredSecret(models.Model):
        owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
        value = models.CharField(max_length=64)


    class Enrollment(models.Model):
        email = models.EmailField()
        activation_key = models.CharField(max_length=64)


    class MachineKey(models.Model):
        label = models.CharField(max_length=40)
        key = models.CharField(max_length=40, blank=True)


    class Voucher(models.Model):
        code = models.CharField(max_length=12)


    class Invite(models.Model):
        secret = models.CharField(max_length=64, default=new_secret)


    @receiver(pre_save, sender=MachineKey)
    def fill_machine_key(sender, instance, **kwargs):
        if not instance.key:
            instance.key = secrets.token_hex(20)
"""
CRED_SERVICES = """\
    import hashlib
    import random
    import secrets
    import string
    import uuid

    from django.core.cache import cache

    from club.creds import Enrollment, ServiceKey, StoredSecret, Voucher


    def issue_service_key(owner):
        raw = secrets.token_urlsafe(32)
        ServiceKey.objects.create(owner=owner, lookup=raw[:8], digest=hashlib.sha256(raw.encode()).hexdigest())
        return raw


    def _keep(model, owner, value):
        model.objects.create(owner=owner, value=value)


    def roll(owner):
        fresh = secrets.token_hex(20)
        _keep(StoredSecret, owner, fresh)
        return fresh


    def enroll(email):
        return Enrollment.objects.create(email=email, activation_key=uuid.uuid4().hex)


    def phone_code(user):
        code = "".join(random.choices(string.digits, k=6))
        cache.set(f"phone-otp:{user.pk}", code, 300)
        return code


    def voucher():
        return Voucher.objects.create(code=secrets.token_hex(4))
"""
CRED_VIEWS = """\
    import secrets

    from django.http import JsonResponse

    from club.creds import Invite, MachineKey
    from club.services import enroll, issue_service_key, phone_code, roll, voucher


    def v_service(request):
        return JsonResponse({"k": issue_service_key(request.user)})


    def v_roll(request):
        return JsonResponse({"k": roll(request.user)})


    def v_profile(request):
        user = request.user
        user.feed_token = secrets.token_hex(16)
        user.save()
        return JsonResponse({"k": user.feed_token})


    def v_machine(request):
        mk = MachineKey(label=request.POST["label"])
        mk.save()
        return JsonResponse({"k": mk.key})


    def v_enroll(request):
        return JsonResponse({"id": enroll(request.POST["email"]).pk})


    def v_phone(request):
        phone_code(request.user)
        return JsonResponse({})


    def v_voucher(request):
        return JsonResponse({"c": voucher().code})


    def v_invite(request):
        return JsonResponse({"s": Invite.objects.create().secret})
"""
CRED_URLS = """\
    from django.urls import path
    from club import views
    urlpatterns = [path(f"{n}/", getattr(views, "v_" + n)) for n in ()] + [
        path("service/", views.v_service), path("roll/", views.v_roll), path("profile/", views.v_profile),
        path("machine/", views.v_machine), path("enroll/", views.v_enroll), path("phone/", views.v_phone),
        path("voucher/", views.v_voucher), path("invite/", views.v_invite),
    ]
"""


def cred_project(tc):
    return project(tc, {"conf/urls.py": CRED_URLS, "club/creds.py": CRED_MODELS, "club/services.py": CRED_SERVICES,
                        "club/views.py": CRED_VIEWS}, init=("conf", "club"))


class CredentialShapeTests(unittest.TestCase):
    def routes(self, rep):
        return {p["entry"]["id"].split("|")[0]: p for p in rep["paths"]
                if p["mint"]["kind"] == "heuristic_custom_credential"}

    def test_shapes_are_found_and_weak_only_codes_set_aside(self):
        rep = scan(cred_project(self))
        got = sorted(self.routes(rep))
        for r in ("service/", "roll/", "profile/", "machine/", "enroll/", "phone/", "invite/"):
            self.assertIn("route:" + r, got)
        self.assertNotIn("route:voucher/", got)
        self.assertTrue([x for x in rep["coverage"]["custom_credentials"]["set_aside"]
                         if any("weak credential word" in y for y in x["reasons"])])

    def check_flagged(self, rel, old, new):
        root = cred_project(self)
        findings, code = run_diff(self, root, lambda: replace_in(root, rel, old, new))
        self.assertTrue(code & 4, findings)

    def test_outbound_secret_on_a_fetched_or_untyped_object_is_set_aside(self):
        root = project(self, {"conf/urls.py": """\
                    from django.urls import path
                    from club import hooks
                    urlpatterns = [path("a/", hooks.rotate_a), path("b/", hooks.rotate_b)]
                 """, "club/hooks.py": """\
                    import secrets
                    from django.db import models
                    from django.http import JsonResponse


                    class Endpoint(models.Model):
                        secret = models.CharField(max_length=64)


                    def rotate_a(request):
                        webhook = Endpoint.objects.get(pk=request.POST["pk"])
                        webhook.secret = secrets.token_hex(16)
                        webhook.save()
                        return JsonResponse({})


                    def rotate_b(request):
                        webhook = request.webhook_endpoint
                        webhook.signing_secret = secrets.token_hex(16)
                        return JsonResponse({})
                 """}, init=("conf", "club"))
        rep = scan(root)
        self.assertFalse([p for p in rep["paths"] if p["mint"]["kind"] == "heuristic_custom_credential"])

    def test_weakened_hashed_key(self):
        self.check_flagged("club/services.py", "raw = secrets.token_urlsafe(32)", "raw = secrets.token_urlsafe(2)")

    def test_weakened_value_stored_by_a_helper(self):
        self.check_flagged("club/services.py", "fresh = secrets.token_hex(20)", "fresh = secrets.token_hex(1)")

    def test_weakened_signal_receiver(self):
        self.check_flagged("club/creds.py", "instance.key = secrets.token_hex(20)", "instance.key = secrets.token_hex(1)")

    def test_weakened_default_generator(self):
        self.check_flagged("club/creds.py", "return secrets.token_urlsafe(24)", "return secrets.token_urlsafe(1)")

    def test_extracting_the_store_into_a_helper_keeps_the_path(self):
        root = cred_project(self)
        self.assertIn("route:service/", self.routes(scan(root)))
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/services.py",
            "    ServiceKey.objects.create(owner=owner, lookup=raw[:8], digest=hashlib.sha256(raw.encode()).hexdigest())\n",
            "    _save_key(ServiceKey, owner, raw)\n"
            "    return raw\n\n\ndef _save_key(model, owner, raw):\n"
            "    model.objects.create(owner=owner, lookup=raw[:8], digest=hashlib.sha256(raw.encode()).hexdigest())\n"))
        self.assertFalse(code & 2, findings)


# ============================================================================ session logins
class SessionLoginTests(unittest.TestCase):
    FILES = {
        "conf/urls.py": """\
            from django.urls import path
            from club import views
            urlpatterns = [path("member/login/", views.member_login)]
        """,
        "club/members.py": """\
            from django.db import models


            class Patron(models.Model):
                email = models.EmailField()
                pin_hash = models.CharField(max_length=128)

                def check_pin(self, pin):
                    from django.contrib.auth.hashers import check_password
                    return check_password(pin, self.pin_hash)
        """,
        "club/views.py": """\
            from django.http import JsonResponse
            from club.members import Patron


            def member_login(request):
                patron = Patron.objects.filter(email=request.POST.get("email")).first()
                if patron is None or not patron.check_pin(request.POST.get("pin", "")):
                    return JsonResponse({}, status=401)
                request.session.cycle_key()
                request.session["patron"] = patron.pk
                return JsonResponse({})
        """,
        "club/mw.py": """\
            from club.members import Patron


            class PatronMiddleware:
                def __init__(self, get_response):
                    self.get_response = get_response

                def __call__(self, request):
                    pid = request.session.get("patron")
                    request.patron = Patron.objects.filter(pk=pid).first() if pid else None
                    return self.get_response(request)
        """}

    def test_session_key_read_back_as_a_principal_is_a_mint(self):
        root = project(self, self.FILES, init=("conf", "club"), settings_extra='MIDDLEWARE += ["club.mw.PatronMiddleware"]\n')
        p = one_path(self, scan(root), "route:member/login/")
        self.assertEqual(p["mint"]["purpose"], "custom_session_login_candidate")
        findings, code = run_diff(self, root, lambda: replace_in(
            root, "club/views.py", " or not patron.check_pin(request.POST.get(\"pin\", \"\"))", ""))
        self.assertTrue(code & 4, findings)

    def test_session_key_nobody_reads_as_a_principal_is_not(self):
        files = dict(self.FILES)
        del files["club/mw.py"]
        rep = scan(project(self, files, init=("conf", "club")))
        self.assertFalse(paths_for(rep, "route:member/login/"))


# ============================================================================ library tokens
class LibraryTokenTests(unittest.TestCase):
    def test_oauth_access_token_creation_is_a_catalog_mint(self):
        root = project(self, {"conf/urls.py": """\
                    from django.urls import path
                    from club.views import PatView
                    urlpatterns = [path("pat/", PatView.as_view())]
                 """, "club/views.py": """\
                    from oauth2_provider.models import AccessToken
                    from oauthlib.common import generate_token
                    from rest_framework.permissions import IsAuthenticated
                    from rest_framework.response import Response
                    from rest_framework.views import APIView


                    class PatView(APIView):
                        permission_classes = [IsAuthenticated]

                        def post(self, request):
                            t = AccessToken.objects.create(user=request.user, token=generate_token(), scope="read")
                            return Response({"t": t.token})
                 """}, settings=DRF_SETTINGS, init=("conf", "club"))
        p = paths_for(scan(root), "route:pat/", "oauth2_provider.models.AccessToken.objects.create")
        self.assertTrue(p)
        self.assertEqual(p[0]["mint"]["catalog_ref"], "oauth2_provider.models.AccessToken")

    def test_uncatalogued_library_key_creation_is_heuristic(self):
        root = project(self, {"conf/urls.py": """\
                    from django.urls import path
                    from club.views import issue
                    urlpatterns = [path("svc/", issue)]
                 """, "club/views.py": """\
                    from django.http import JsonResponse
                    from keyvault.models import ServiceToken


                    def issue(request):
                        _obj, key = ServiceToken.objects.create_key(name=request.POST["name"])
                        return JsonResponse({"key": key})
                 """}, init=("conf", "club"))
        p = paths_for(scan(root), "route:svc/")
        self.assertEqual([x["mint"]["purpose"] for x in p], ["custom_library_credential_candidate"])

    def test_channels_websocket_login_is_routed(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "conf/asgi.py": """\
                    from channels.routing import ProtocolTypeRouter, URLRouter
                    from django.urls import path
                    from club.ws import RoomSocket
                    application = ProtocolTypeRouter({"websocket": URLRouter([path("ws/room/", RoomSocket.as_asgi())])})
                 """, "club/ws.py": """\
                    from channels.auth import login
                    from channels.generic.websocket import AsyncJsonWebsocketConsumer
                    from django.contrib.auth import get_user_model


                    class RoomSocket(AsyncJsonWebsocketConsumer):
                        async def receive_json(self, content, **kwargs):
                            user = get_user_model().objects.get(username=content["name"])
                            await login(self.scope, user)
                 """}, init=("conf", "club"))
        p = one_path(self, scan(root), "asgi:ws/room/|club.ws.RoomSocket", "channels.auth.login")
        self.assertEqual(p["mint"]["purpose"], "full_session")


# ============================================================================ review noise
class ReviewNoiseTests(unittest.TestCase):
    N = 7

    def shared_project(self, n=None):
        n = n or self.N
        views = "from django.http import JsonResponse\nfrom club.svc import new_member\n\n" + "".join(
            f"\n\ndef v{i}(request):\n    return JsonResponse({{'id': new_member(request.POST['e']).pk}})\n"
            for i in range(n))
        urls = "from django.urls import path\nfrom club import views\nurlpatterns = [\n" + "".join(
            f"    path('m{i}/', views.v{i}),\n" for i in range(n)) + "]\n"
        return project(self, {"conf/urls.py": urls, "club/views.py": views, "club/svc.py": """\
                    import logging
                    from club.creds import Invite

                    log = logging.getLogger(__name__)


                    def new_member(email):
                        log.info("new member %s", email)
                        return Invite.objects.create()
                 """, "club/creds.py": CRED_MODELS}, init=("conf", "club"))

    def test_widely_shared_site_is_one_entry(self):
        root = self.shared_project()
        rep = scan(root)
        heur = [p for p in rep["paths"] if p["mint"]["kind"] == "heuristic_custom_credential" and
                "Invite" in p["mint"]["api"]]
        self.assertEqual([p["entry"]["kind"] for p in heur], ["heuristic_site"])
        self.assertEqual(len(heur[0]["entry"]["reached_from"]), self.N)
        findings, code = run_diff(self, root, lambda: replace_in(root, "club/svc.py", '"new member %s"',
                                                                 '"member created %s"'))
        self.assertEqual(code, 4, findings)
        self.assertEqual(len([f for f in findings if f["kind"] == "fingerprint_changed"]), 1)

    def test_new_entry_point_changes_the_group(self):
        root = self.shared_project()
        findings, code = run_diff(self, root, lambda: (
            write(root, "club/views.py", read(root, "club/views.py") +
                  "\n\ndef extra(request):\n    return JsonResponse({'id': new_member('x').pk})\n"),
            replace_in(root, "conf/urls.py", "]\n", "    path('extra/', views.extra),\n]\n")))
        self.assertTrue(code & 4, findings)

    def test_few_entry_points_keep_one_path_each(self):
        # (v6) the group threshold is 3 entry points (was 6): two entry points keep one path each
        rep = scan(self.shared_project(2))
        heur = [p for p in rep["paths"] if p["mint"]["kind"] == "heuristic_custom_credential" and
                "Invite" in p["mint"]["api"]]
        self.assertEqual(sorted(p["entry"]["kind"] for p in heur), ["route"] * 2)

    def test_depth_limit_only_clears_fingerprint_complete(self):
        root = club(self, {"club/views.py": DEEP_CHAIN.replace("    member = _l1(h)\n",
                                                              "    member = _l1(h) if h else _deep(h)\n") +
                           "".join(f"\n\ndef _d{i}(x):\n    if x:\n        return _d{i + 1}(x)\n    return x\n"
                                   for i in range(8)) + "\n\ndef _d8(x):\n    return x\n\n\ndef _deep(x):\n"
                                                        "    if x:\n        return _d0(x)\n    return None\n"})
        p = one_path(self, scan(root), "route:enter/", "django.contrib.auth.login")
        self.assertTrue([g for g in p["gaps"] if g.startswith("fingerprint_depth_limit")])
        self.assertTrue(p["analysis_complete"])
        self.assertFalse(p["fingerprint_complete"])


if __name__ == "__main__":
    unittest.main()

"""v5: tests for the fixes of the held-out evaluation of v4 (round 2 in docs/EVALUATION.md; root causes R1, R2, R4, R6).

Every test writes a small synthetic project (and, where needed, a synthetic "library" directory standing in for
site-packages) into a temporary directory.  The code is written for these tests; no development-project code is
copied.  Library directories are only read by MintMap (--library-path), never imported.

R1  NamespacePackageTests      module names for directories without __init__.py (PEP 420), source roots from
                               manage.py / imports / settings dotted paths, ambiguity gap, aliases
R2  LibraryViewTests           unmapped symbols of catalogued packages: alias resolution (catalog v3, library
                               source), subclasses, gaps instead of silence; views invoked from project code
    LibraryIncludeTests        per-include `complete` flag (catalog v3): incomplete lists are path gaps
    AdminRegistrationTests     library ModelAdmin registrations (DRF TokenAdmin) under admin.site.urls; undeclared
                               apps are one gap
    MiddlewareAuthClassTests   catalogued-package middleware / DRF auth classes: declared no-mint, knox renewal mint,
                               library subclass of a catalog middleware (library source), gaps otherwise
    LibraryCallAndBaseTests    library re-export of a catalog mint (library source), possible library mint gap,
                               unknown library base class, unknown view decorator
R4  SettingsFunctionTests      functions called at module level (`global X`, in-place changes), partially unknown
                               extend / +=, uncalled setting functions, nested dict lists, conditions fingerprinted,
                               match
R6  SubscriptedBaseTests       Base[Any] / Generic[T] bases resolve; an unresolvable base is a path gap
"""
import os
import shutil
import tempfile
import textwrap
import unittest

from mm_testutil import scan, write, read, accept_all, one_path, paths_for, CATALOG_V2

from mintmap.core.lockfile import build_lock, diff

SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
"""


def tmpdir(tc, prefix="mintmap-v5-"):
    d = tempfile.mkdtemp(prefix=prefix)
    tc.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d


def project(tc, files, settings=SETTINGS, settings_extra="", init=("conf", "shop")):
    root = tmpdir(tc)
    for pkg in init:
        write(root, f"{pkg}/__init__.py", "")
    write(root, "conf/settings.py", textwrap.dedent(settings) + textwrap.dedent(settings_extra))
    for rel, text in files.items():
        write(root, rel, textwrap.dedent(text))
    return root


def library(tc, files):
    """A synthetic site-packages directory (read by --library-path only)."""
    root = tmpdir(tc, "mintmap-v5-lib-")
    for rel, text in files.items():
        write(root, rel, textwrap.dedent(text))
    return root


def gaps(report, typ):
    return [g for g in report["coverage"]["gaps"] if g["type"] == typ]


def path_gaps(path, typ):
    return [g for g in path["gaps"] if g.startswith(typ + "|")]


def unrouted(report):
    return [p["entry"]["id"] for p in report["paths"] if p["entry"]["kind"] == "unrouted"]


def run_diff(tc, root, mutate, **scan_kw):
    lock = accept_all(build_lock(scan(root, **scan_kw)))
    tc.assertEqual(diff(lock, scan(root, **scan_kw))[1], 0)
    mutate()
    return diff(lock, scan(root, **scan_kw))


# ============================================================================ R1
NS_VIEWS = """\
from django.http import HttpResponse

from portal.accounts.utils.sessions import start_session


def sign_in(request):
    user = request.POST["user"]
    start_session(request, user)
    return HttpResponse("ok")
"""
NS_HELPER = """\
from django.contrib.auth import login


def start_session(request, user):
    login(request, user)
"""


class NamespacePackageTests(unittest.TestCase):
    def ns_project(self, extra=None):
        files = {
            "manage.py": 'import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "conf.settings")\n',
            "conf/urls.py": """\
                from django.urls import path
                from portal.accounts import views
                urlpatterns = [path("sign-in/", views.sign_in)]
            """,
            "portal/__init__.py": "",
            "portal/accounts/__init__.py": "",
            "portal/accounts/views.py": NS_VIEWS,
            # utils/ has NO __init__.py: a PEP 420 namespace package
            "portal/accounts/utils/sessions.py": NS_HELPER,
            # same stem in another namespace directory: must not collide
            "portal/billing/utils/sessions.py": "def start_session(request, user):\n    return None\n",
        }
        files.update(extra or {})
        return project(self, files, init=("conf",))

    def test_namespace_module_is_named_from_the_project_root_and_routed(self):
        rep = scan(self.ns_project())
        self.assertEqual(unrouted(rep), [])
        p = one_path(self, rep, "route:sign-in/", "django.contrib.auth.login")
        self.assertEqual(p["mint"]["site"]["function"], "portal.accounts.utils.sessions.start_session")
        self.assertEqual(gaps(rep, "module_name_collision"), [])
        self.assertEqual(gaps(rep, "module_name_ambiguous"), [])

    def test_v4_naming_would_have_left_the_mint_unrouted(self):
        # control: the same project with __init__.py added everywhere gives the identical path
        root = self.ns_project({"portal/accounts/utils/__init__.py": "", "portal/billing/utils/__init__.py": ""})
        rep = scan(root)
        self.assertEqual(one_path(self, rep, "route:sign-in/", "django.contrib.auth.login")["mint"]["site"]["function"],
                         "portal.accounts.utils.sessions.start_session")

    def test_ambiguous_name_between_two_roots_is_a_gap(self):
        # two manage.py roots; a namespace module under the inner one that nothing imports has two valid names
        root = self.ns_project({"svc/manage.py": "", "svc/tools/collect.py": "def run():\n    return 1\n"})
        rep = scan(root)
        amb = gaps(rep, "module_name_ambiguous")
        self.assertEqual(len(amb), 1, amb)
        self.assertEqual(amb[0]["file"], os.path.join("svc", "tools", "collect.py"))
        self.assertIn("tools.collect", amb[0]["detail"])
        self.assertIn("svc.tools.collect", amb[0]["detail"])

    def test_imported_name_decides_and_other_evidenced_name_is_an_alias(self):
        root = self.ns_project({
            "svc/manage.py": "",
            "svc/tools/grant.py": "from django.contrib.auth import login\n\n\ndef grant(request, u):\n"
                                  "    login(request, u)\n",
            "svc/app/__init__.py": "",
            # inside the svc root the module is imported as tools.grant ...
            "svc/app/views.py": "from tools.grant import grant\n\n\ndef inner(request):\n"
                                "    grant(request, request.POST['u'])\n",
            # ... and from the outer root as svc.tools.grant
            "portal/accounts/admin_views.py": "from svc.tools.grant import grant\n\n\ndef outer(request):\n"
                                              "    grant(request, request.POST['u'])\n",
            "conf/urls.py": """\
                from django.urls import path
                from portal.accounts import views, admin_views
                urlpatterns = [path("sign-in/", views.sign_in), path("outer/", admin_views.outer)]
            """,
        })
        rep = scan(root)
        self.assertEqual(gaps(rep, "module_name_ambiguous"), [])
        p = one_path(self, rep, "route:outer/", "django.contrib.auth.login")
        self.assertTrue(p["mint"]["site"]["function"].endswith("tools.grant.grant"))

    def test_root_from_settings_dotted_paths_without_manage_py(self):
        # project dir = repository root; the Django project lives under src/ and only wsgi.py names it
        root = tmpdir(self)
        write(root, "src/site_conf/__init__.py", "")
        write(root, "src/site_conf/wsgi.py",
              'import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "site_conf.settings")\n')
        write(root, "src/site_conf/settings.py", 'INSTALLED_APPS = ["django.contrib.auth"]\nMIDDLEWARE = []\n'
                                                 'ROOT_URLCONF = "site_conf.urls"\n')
        write(root, "src/site_conf/urls.py", "from django.urls import path\nfrom site_conf.flows.entry import go\n"
                                             "urlpatterns = [path('go/', go)]\n")
        # flows/ is a namespace directory
        write(root, "src/site_conf/flows/entry.py", "from django.contrib.auth import login\n\n\ndef go(request):\n"
                                                    "    login(request, request.user)\n")
        rep = scan(root)
        self.assertEqual(rep["coverage"]["settings_modules"], ["site_conf.settings"])
        self.assertEqual(rep["coverage"]["root_urlconfs"], ["site_conf.urls"])
        p = one_path(self, rep, "route:go/", "django.contrib.auth.login")
        self.assertEqual(p["mint"]["site"]["function"], "site_conf.flows.entry.go")


# ============================================================================ R2
ALLAUTH_LIB = {
    "allauth/__init__.py": "",
    "allauth/account/__init__.py": "",
    "allauth/account/views.py": """\
        from django.views.generic.edit import FormView


        class LoginView(FormView):
            def form_valid(self, form):
                return None


        class FancyLoginView(LoginView):
            template_name = "fancy.html"


        class OverridingLoginView(LoginView):
            def form_valid(self, form):
                return None


        quick_login = LoginView.as_view(template_name="quick.html")
        fancy_login = FancyLoginView.as_view()
        own_login = OverridingLoginView.as_view()
    """,
    "allauth/account/shortcuts.py": "from allauth.account.internal.flows.login import perform_login\n",
    "acme_sso/__init__.py": "",
    "acme_sso/middleware.py": """\
        from django.contrib.auth.middleware import RemoteUserMiddleware


        class HeaderLogin(RemoteUserMiddleware):
            header = "HTTP_X_USER"
    """,
}


class LibraryViewTests(unittest.TestCase):
    def proj(self, route_target):
        return project(self, {"conf/urls.py": f"""\
            from django.urls import path
            from allauth.account import views as acc
            urlpatterns = [path("login/", {route_target})]
        """})

    def test_unmapped_alias_in_catalogued_package_is_a_gap_not_silence(self):
        rep = scan(self.proj("acc.quick_login"))
        self.assertEqual(rep["paths"], [])
        g = gaps(rep, "library_view_not_in_catalog")
        self.assertEqual(len(g), 1)
        self.assertIn("allauth.account.views.quick_login", g[0]["detail"])
        self.assertIn("catalogued package", g[0]["detail"])

    def test_alias_resolved_from_library_source(self):
        lib = library(self, ALLAUTH_LIB)
        rep = scan(self.proj("acc.quick_login"), library_paths=[lib])
        self.assertEqual(gaps(rep, "library_view_not_in_catalog"), [])
        ps = paths_for(rep, "route:login/")
        self.assertEqual(sorted(p["mint"]["catalog_ref"] for p in ps), sorted([
            "allauth.account.internal.flows.login.perform_login / resume_login",
            "allauth.account.stages.LoginStageController.handle + internal.stagekit.stash_login"]))
        notes = " ".join(ps[0]["entry"]["notes"])
        self.assertIn("quick_login = LoginView.as_view", notes)

    def test_catalog_v3_alias_without_library_path(self):
        # allauth.mfa.base.views.authenticate = AuthenticateView.as_view() is a catalog v3 alias row
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from allauth.mfa.base import views as mfa
            urlpatterns = [path("2fa/", mfa.authenticate)]
        """})
        rep = scan(root)
        p = one_path(self, rep, "route:2fa/")
        self.assertEqual(p["mint"]["catalog_ref"], "allauth.mfa.base.views.AuthenticateView.form_valid")
        # with the v2 catalog (no alias rows) the same route is a gap, not silence
        rep2 = scan(root, catalog=CATALOG_V2)
        self.assertEqual(rep2["paths"], [])
        self.assertEqual(len(gaps(rep2, "library_view_not_in_catalog")), 1)

    def test_library_subclass_of_catalog_view(self):
        lib = library(self, ALLAUTH_LIB)
        rep = scan(self.proj("acc.fancy_login"), library_paths=[lib])
        self.assertEqual(len(paths_for(rep, "route:login/")), 2)
        rep = scan(self.proj("acc.own_login"), library_paths=[lib])
        self.assertEqual(rep["paths"], [])
        g = gaps(rep, "library_view_not_in_catalog")
        self.assertEqual(len(g), 1)
        self.assertIn("OverridingLoginView", g[0]["detail"])

    def test_declared_no_mint_view_has_no_gap(self):
        rep = scan(self.proj("acc.logout"))   # catalog v3: allauth.account.views.logout mints nothing
        self.assertEqual(rep["paths"], [])
        self.assertEqual(gaps(rep, "library_view_not_in_catalog"), [])

    def test_unmapped_library_view_invoked_from_project_code_is_a_gap(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from shop.views import entry
            urlpatterns = [path("e/", entry)]
        """, "shop/views.py": """\
            from allauth.account.views import EmailView


            def entry(request):
                return EmailView.as_view()(request)
        """})
        rep = scan(root)
        g = gaps(rep, "library_view_not_in_catalog")
        self.assertEqual([x["where"] for x in g], ["shop.views.entry"])

    def test_new_route_to_unmapped_alias_fails_ci(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from shop.views import home
            urlpatterns = [path("", home)]
        """, "shop/views.py": "from django.contrib.auth import login\n\n\ndef home(request):\n"
                              "    login(request, request.user)\n"})

        def mutate():
            write(root, "conf/urls.py", read(root, "conf/urls.py").replace(
                'urlpatterns = [path("", home)]',
                'from allauth.account import views as acc\nurlpatterns = [path("", home), '
                'path("q/", acc.quick_login)]'))

        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 32, findings)


class LibraryIncludeTests(unittest.TestCase):
    def proj(self, include):
        return project(self, {"conf/urls.py": f"""\
            from django.urls import include, path
            urlpatterns = [path("auth/", include("{include}"))]
        """})

    def test_incomplete_include_is_a_path_gap(self):
        rep = scan(self.proj("social_django.urls"))
        p = one_path(self, rep, "route:auth/")
        self.assertFalse(p["analysis_complete"])
        self.assertEqual(len(path_gaps(p, "library_include_mints_incomplete")), 1)

    def test_complete_include_has_no_gap(self):
        rep = scan(self.proj("knox.urls"))
        p = one_path(self, rep, "route:auth/")
        self.assertTrue(p["analysis_complete"])
        self.assertEqual(rep["coverage"]["gaps"], [])

    def test_unmapped_include_of_catalogued_package_is_a_gap(self):
        rep = scan(self.proj("allauth.mfa.webauthn.urls"))
        self.assertEqual(rep["paths"], [])
        self.assertEqual([g["detail"] for g in gaps(rep, "library_include_not_in_catalog")],
                         ["allauth.mfa.webauthn.urls"])


class AdminRegistrationTests(unittest.TestCase):
    def proj(self, apps):
        settings = SETTINGS.replace('INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]',
                                    f"INSTALLED_APPS = {apps!r}")
        return project(self, {"conf/urls.py": """\
            from django.contrib import admin
            from django.urls import path
            urlpatterns = [path("admin/", admin.site.urls)]
        """}, settings=settings)

    def test_library_token_admin_is_a_mint_path(self):
        rep = scan(self.proj(["django.contrib.admin", "django.contrib.auth", "django.contrib.sites",
                              "rest_framework", "rest_framework.authtoken", "shop"]))
        refs = sorted(p["mint"]["catalog_ref"] for p in paths_for(rep, "route:admin/"))
        self.assertIn("rest_framework.authtoken.models.Token.save / generate_key", refs)
        self.assertIn("django.contrib.auth.views.PasswordChangeView.form_valid", refs)   # admin password_change
        self.assertEqual(gaps(rep, "library_admin_not_in_catalog"), [])

    def test_undeclared_library_apps_are_one_gap_on_admin_paths(self):
        rep = scan(self.proj(["django.contrib.admin", "django.contrib.auth", "thirdparty_widgets",
                              "acme_billing.apps.BillingConfig", "shop.apps.ShopConfig"]))
        g = gaps(rep, "library_admin_not_in_catalog")
        self.assertEqual(len(g), 1)
        self.assertIn("acme_billing, thirdparty_widgets", g[0]["detail"])
        self.assertNotIn("shop", g[0]["detail"])
        for p in paths_for(rep, "route:admin/"):
            self.assertFalse(p["analysis_complete"])

    def test_project_admin_registration_of_a_token_model(self):
        settings = SETTINGS.replace('"shop"]', '"django.contrib.admin", "shop"]')
        root = project(self, {"conf/urls.py": """\
            from django.contrib import admin
            from django.urls import path
            urlpatterns = [path("admin/", admin.site.urls)]
        """, "shop/admin.py": """\
            from django.contrib import admin
            from rest_framework.authtoken.models import Token


            @admin.register(Token)
            class StaffTokenAdmin(admin.ModelAdmin):
                fields = ("user",)
        """}, settings=settings)
        refs = [p["mint"]["catalog_ref"] for p in paths_for(scan(root), "route:admin/")]
        self.assertIn("rest_framework.authtoken.models.Token.save / generate_key", refs)

    def test_library_path_shows_an_app_without_admin_module(self):
        lib = library(self, {"thirdparty_widgets/__init__.py": "", "thirdparty_widgets/fields.py": "X = 1\n"})
        root = self.proj(["django.contrib.admin", "django.contrib.auth", "thirdparty_widgets"])
        self.assertEqual(gaps(scan(root, library_paths=[lib]), "library_admin_not_in_catalog"), [])


class MiddlewareAuthClassTests(unittest.TestCase):
    def test_catalogued_package_middleware_not_declared_is_a_gap(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n"}, settings_extra="""\
            MIDDLEWARE = ["django.middleware.csrf.CsrfViewMiddleware",
                          "allauth.usersessions.middleware.UserSessionsMiddleware"]
        """)
        rep = scan(root)
        self.assertEqual([g["detail"] for g in gaps(rep, "middleware_not_in_catalog")],
                         ["allauth.usersessions.middleware.UserSessionsMiddleware"])

    def test_library_subclass_of_catalog_middleware_found_in_library_source(self):
        lib = library(self, ALLAUTH_LIB)
        root = project(self, {"conf/urls.py": "urlpatterns = []\n"}, settings_extra="""\
            MIDDLEWARE = ["acme_sso.middleware.HeaderLogin"]
        """)
        self.assertEqual(scan(root)["paths"], [])
        rep = scan(root, library_paths=[lib])
        p = one_path(self, rep, "middleware:acme_sso.middleware.HeaderLogin")
        self.assertEqual(p["mint"]["catalog_ref"], "django.contrib.auth.middleware.RemoteUserMiddleware")
        self.assertFalse(p["analysis_complete"])

    def test_drf_auth_classes(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n"}, settings_extra="""\
            REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": [
                "rest_framework.authentication.TokenAuthentication",
                "knox.auth.TokenAuthentication",
                "rest_framework_simplejwt.authentication.JWTTokenUserAuthentication"]}
        """)
        rep = scan(root)
        p = one_path(self, rep, "drf_auth_class:knox.auth.TokenAuthentication")
        self.assertEqual(p["mint"]["catalog_ref"], "knox.auth.TokenAuthentication.renew_token")
        self.assertEqual([g["detail"] for g in gaps(rep, "drf_auth_class_not_in_catalog")],
                         ["rest_framework_simplejwt.authentication.JWTTokenUserAuthentication"])


class LibraryCallAndBaseTests(unittest.TestCase):
    def test_library_reexport_of_catalog_mint(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from shop.views import go
            urlpatterns = [path("go/", go)]
        """, "shop/views.py": """\
            from allauth.account.shortcuts import perform_login


            def go(request):
                return perform_login(request, request.session["pending"])
        """})
        rep = scan(root)
        self.assertEqual(rep["paths"], [])
        self.assertEqual(len(gaps(rep, "library_call_may_mint")), 1)
        rep = scan(root, library_paths=[library(self, ALLAUTH_LIB)])
        p = one_path(self, rep, "route:go/")
        self.assertEqual(p["mint"]["api"], "allauth.account.internal.flows.login.perform_login")
        self.assertEqual(gaps(rep, "library_call_may_mint"), [])

    def test_unknown_library_base_and_decorator_make_the_path_incomplete(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from ratelimiter.decorators import throttle
            from shop.views import Enter
            urlpatterns = [path("enter/", throttle(Enter.as_view()))]
        """, "shop/views.py": """\
            from django.contrib.auth import login
            from widgets.views import WizardView


            class Enter(WizardView):
                def post(self, request):
                    login(request, request.user)
        """})
        p = one_path(self, scan(root), "route:enter/")
        self.assertFalse(p["analysis_complete"])
        self.assertEqual(len(path_gaps(p, "library_base_not_in_catalog")), 1)
        self.assertEqual(len(path_gaps(p, "view_decorator_not_in_catalog")), 1)

    def test_known_generic_bases_are_not_gaps(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from django.views.decorators.csrf import csrf_exempt
            from shop.views import Enter
            urlpatterns = [path("enter/", csrf_exempt(Enter.as_view()))]
        """, "shop/views.py": """\
            from django.contrib.auth import login
            from django.contrib.auth.mixins import LoginRequiredMixin
            from django.views.generic import View


            class Enter(LoginRequiredMixin, View):
                def post(self, request):
                    login(request, request.user)
        """})
        p = one_path(self, scan(root), "route:enter/")
        self.assertTrue(p["analysis_complete"], p["gaps"])


class FingerprintReachTests(unittest.TestCase):
    """(v5) project code that a path depends on but v4 did not fingerprint (changes passed CI silently)."""

    def test_serializer_of_a_project_subclass_of_a_library_view(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from shop.views import TokenObtain
            urlpatterns = [path("token/", TokenObtain.as_view())]
        """, "shop/views.py": """\
            from rest_framework import serializers
            from rest_framework.authtoken.views import ObtainAuthToken


            class CodeSerializer(serializers.Serializer):
                def validate(self, attrs):
                    if not attrs.get("code") == "expected":
                        raise serializers.ValidationError("bad code")
                    return attrs


            class TokenObtain(ObtainAuthToken):
                serializer_class = CodeSerializer
        """})
        p = one_path(self, scan(root), "route:token/")
        self.assertIn("shop.views.CodeSerializer.validate", p["evidence"]["validation_methods"])

        def mutate():
            write(root, "shop/views.py", read(root, "shop/views.py").replace(
                '            raise serializers.ValidationError("bad code")\n', "            pass\n"))

        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)

    def test_subclass_override_called_from_a_base_class_method(self):
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from shop.views import sign_in
            urlpatterns = [path("in/", sign_in)]
        """, "shop/providers.py": """\
            class Provider:
                def run(self):
                    self.check()
                    return self.user

                def check(self):
                    return None


            class PinProvider(Provider):
                def __init__(self, user, pin):
                    self.user, self.pin = user, pin

                def check(self):
                    if self.pin != self.user.pin:
                        raise ValueError("wrong pin")
        """, "shop/views.py": """\
            from django.contrib.auth import login
            from shop.providers import PinProvider


            def sign_in(request):
                provider = PinProvider(request.user, request.POST["pin"])
                user = provider.run()
                login(request, user)
        """})
        p = one_path(self, scan(root), "route:in/")
        self.assertIn("shop.providers.PinProvider.check", p["fingerprint"]["callee_functions"])

        def mutate():
            write(root, "shop/providers.py", read(root, "shop/providers.py").replace(
                '            raise ValueError("wrong pin")', "            pass"))

        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)


class LibraryPathCliTests(unittest.TestCase):
    def test_library_path_option_end_to_end(self):
        import json
        import subprocess
        import sys
        from mm_testutil import PROTO
        lib = library(self, ALLAUTH_LIB)
        root = project(self, {"conf/urls.py": """\
            from django.urls import path
            from allauth.account import views as acc
            urlpatterns = [path("login/", acc.quick_login)]
        """})
        out = os.path.join(root, "out.json")
        r = subprocess.run([sys.executable, "-I", os.path.join(PROTO, "tests", "_cli.py"), "scan", root,
                            "--library-path", lib, "--json", out], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as fh:
            rep = json.load(fh)
        self.assertEqual(rep["tool"]["library_paths"], [os.path.abspath(lib)])
        from mintmap.core.analysis import TOOL_VERSION
        self.assertEqual(rep["tool"]["version"], TOOL_VERSION)
        self.assertEqual(len(rep["paths"]), 2)


# ============================================================================ R4
MW_FILES = {
    "conf/urls.py": "urlpatterns = []\n",
    "shop/mw.py": """\
        from django.contrib.auth import login


        class HeaderLoginMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                login(request, request.user)
                return self.get_response(request)
    """,
}


class SettingsFunctionTests(unittest.TestCase):
    def mw_paths(self, rep):
        return paths_for(rep, "middleware:shop.mw.HeaderLoginMiddleware")

    def test_global_in_function_called_at_module_level(self):
        root = project(self, MW_FILES, settings_extra="""\
            import os


            def _remote_user_settings():
                global MIDDLEWARE, AUTHENTICATION_BACKENDS
                enabled = os.environ.get("SSO") == "1"
                if enabled:
                    MIDDLEWARE.append("shop.mw.HeaderLoginMiddleware")
                    AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.RemoteUserBackend"]
                return "HTTP_REMOTE_USER"


            HEADER = _remote_user_settings()
        """)
        rep = scan(root)
        self.assertEqual(len(self.mw_paths(rep)), 1)
        self.assertEqual(gaps(rep, "settings_function_not_evaluated"), [])
        self.assertTrue(any(g["where"] == "MIDDLEWARE" for g in gaps(rep, "conditional_setting")))

    def test_in_place_change_without_global(self):
        root = project(self, MW_FILES, settings_extra="""\
            def add_sso():
                MIDDLEWARE.insert(0, "shop.mw.HeaderLoginMiddleware")


            add_sso()
        """)
        self.assertEqual(len(self.mw_paths(scan(root))), 1)

    def test_setting_function_not_called_at_module_level_is_a_gap(self):
        root = project(self, MW_FILES, settings_extra="""\
            def add_sso():
                MIDDLEWARE.append("shop.mw.HeaderLoginMiddleware")


            for step in [add_sso]:
                step()
        """)
        rep = scan(root)
        self.assertEqual([g["where"] for g in gaps(rep, "settings_function_not_evaluated")], ["add_sso"])

    def test_extend_with_unknown_keeps_known_items(self):
        root = project(self, MW_FILES, settings_extra="""\
            from shop.plugins import plugin_middleware
            MIDDLEWARE = ["shop.mw.HeaderLoginMiddleware"]
            MIDDLEWARE.extend(plugin_middleware())
            MIDDLEWARE += load_more()
        """)
        rep = scan(root)
        self.assertEqual(len(self.mw_paths(rep)), 1)
        partial = gaps(rep, "setting_partially_unknown")
        self.assertEqual(len(partial), 2, partial)
        self.assertEqual(gaps(rep, "dynamic_setting"), [])

    def test_nested_dict_list_changed_in_function(self):
        root = project(self, {"conf/urls.py": "urlpatterns = []\n", "shop/auth.py": """\
            from django.contrib.auth import login


            class HeaderAuth:
                def authenticate(self, request):
                    login(request, request.user)
                    return (request.user, None)
        """}, settings_extra="""\
            REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"]}


            def _api_sso(on):
                if on:
                    REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"].insert(0, "shop.auth.HeaderAuth")


            _api_sso(True)
        """)
        self.assertEqual(len(paths_for(scan(root), "drf_auth_class:shop.auth.HeaderAuth")), 1)

    def test_condition_deciding_a_setting_is_fingerprinted(self):
        root = project(self, MW_FILES, settings_extra="""\
            import os
            AUTO_USER = os.getenv("AUTO_USER", "")
            if AUTO_USER:
                MIDDLEWARE.append("shop.mw.HeaderLoginMiddleware")
        """)

        def mutate():
            write(root, "conf/settings.py", read(root, "conf/settings.py").replace(
                'os.getenv("AUTO_USER", "")', 'os.getenv("AUTO_USER", "admin")'))

        findings, code = run_diff(self, root, mutate)
        self.assertTrue(code & 4, findings)
        self.assertTrue(all("settings" in f.get("components", []) for f in findings if f["kind"] ==
                            "fingerprint_changed"))

    def test_exec_in_settings_is_a_gap(self):
        root = project(self, MW_FILES, settings_extra="""\
            exec(open("local_settings.py").read())
        """)
        g = [x for x in gaps(scan(root), "dynamic_setting") if x["where"] == "<settings>"]
        self.assertEqual(len(g), 1)

    def test_match_cases_are_alternatives(self):
        root = project(self, MW_FILES, settings_extra="""\
            import os
            match os.environ.get("MODE"):
                case "sso":
                    MIDDLEWARE = MIDDLEWARE + ["shop.mw.HeaderLoginMiddleware"]
                case _:
                    pass
        """)
        self.assertEqual(len(self.mw_paths(scan(root))), 1)


# ============================================================================ R6
class SubscriptedBaseTests(unittest.TestCase):
    URLS = """\
        from django.urls import path
        from shop.views import TokenView
        urlpatterns = [path("token/", TokenView.as_view())]
    """

    def test_subscripted_bases_keep_the_drf_permission_gate(self):
        root = project(self, {"conf/urls.py": self.URLS, "shop/views.py": """\
            from typing import Any, Generic, TypeVar

            from rest_framework.authtoken.models import Token
            from rest_framework.generics import GenericAPIView
            from rest_framework.permissions import IsAuthenticated

            T = TypeVar("T")


            class Base(GenericAPIView[Any], Generic[T]):
                permission_classes = [IsAuthenticated]


            class TokenView(Base[int]):
                def post(self, request):
                    return Token.objects.create(user=request.user)
        """})
        p = one_path(self, scan(root), "route:token/")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertTrue(any(f.startswith("prior_authentication:") for f in p["evidence"]["factors"]))
        self.assertTrue(p["analysis_complete"], p["gaps"])

    def test_unresolvable_base_is_a_path_gap(self):
        root = project(self, {"conf/urls.py": self.URLS, "shop/views.py": """\
            from rest_framework.authtoken.models import Token
            from shop.factory import make_base


            class TokenView(make_base("api")):
                def post(self, request):
                    return Token.objects.create(user=request.user)
        """, "shop/factory.py": "def make_base(kind):\n    return object\n"})
        p = one_path(self, scan(root), "route:token/")
        self.assertFalse(p["analysis_complete"])
        self.assertEqual(len(path_gaps(p, "class_base_unresolved")), 1)


if __name__ == "__main__":
    unittest.main()

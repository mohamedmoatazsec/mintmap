"""v4: regression tests for the eight findings of the adversarial review of v3.

Every test builds a small synthetic project in a temporary directory (written for these tests; no
development-project code is copied).  One class per finding:

F1  CheckArgumentTests       jwt.decode verification switched off through a constant, dict(), **kwargs, a
                             positional argument or `|`; arguments that cannot be evaluated; constants are
                             fingerprinted
F2  TryExceptTests           try body and except handler are alternatives (both routed, conditional)
F3  ConditionalImportTests   a name imported in one branch and bound to [] in another keeps both alternatives
F4  ImportedListTests        .append/.extend/+= on a URL list imported from another module
F5  RouteVariantTests        the same pattern+view routed twice with different wrappers: both are analysed
F6  LoopControlTests         break/continue in unrolled URL loops (and comprehension filters)
F7  BackendFactorTests       a project backend is judged on its recognised checks only
F8  LibraryClassTypingTests  all-caps library classes known to the catalog (pyotp TOTP/HOTP, django_otp TOTP)
"""
import shutil
import tempfile
import textwrap
import unittest

from mm_testutil import scan, write, read, accept_all, one_path, paths_for, CATALOG_V1

from mintmap.core.lockfile import build_lock, diff

SETTINGS = """\
SECRET_KEY = "fixture-only"
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "shop"]
MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
ROOT_URLCONF = "conf.urls"
"""

PASSWORD_VIEWS = """\
from django.contrib.auth import authenticate, login


def password_login(request):
    account = authenticate(request, username=request.POST["name"], password=request.POST["secret"])
    if account is None:
        return None
    login(request, account)


def landing(request):
    return None
"""


def project(tc, files, settings_extra=""):
    root = tempfile.mkdtemp(prefix="mintmap-v4-")
    tc.addCleanup(shutil.rmtree, root, ignore_errors=True)
    write(root, "conf/__init__.py", "")
    write(root, "conf/settings.py", SETTINGS + textwrap.dedent(settings_extra))
    write(root, "shop/__init__.py", "")
    for rel, text in files.items():
        write(root, rel, textwrap.dedent(text))
    return root


def routes(report, pattern=None, target=None):
    return [r for r in report["routes"] if (pattern is None or r["pattern"] == pattern)
            and (target is None or r["target"] == target)]


def gaps(report, typ):
    return [g for g in report["coverage"]["gaps"] if g["type"] == typ]


def unrouted(report):
    return [p["entry"]["id"] for p in report["paths"] if p["entry"]["kind"] == "unrouted"]


def by_path(findings):
    out = {}
    for f in findings:
        out.setdefault(f["path_id"], set()).add(f["kind"])
    return out


# ============================================================================ F1
JWT_VIEWS = """\
import jwt
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User

from shop.jwtconf import SHARED_OPTIONS

RELAXED = {"verify_signature": False, "verify_exp": False}
CHECKED = {"require": ["exp", "sub"]}
PATCHED = {"require": ["sub"]}
PATCHED["verify_signature"] = False


def load_options():
    return {}


def by_constant(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=RELAXED)
    login(request, User.objects.get(pk=claims["sub"]))


def by_dict_call(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=dict(CHECKED, verify_signature=False))
    login(request, User.objects.get(pk=claims["sub"]))


def by_kwargs(request):
    extra = {"options": {**CHECKED, "verify_signature": False}}
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], **extra)
    login(request, User.objects.get(pk=claims["sub"]))


def by_position(request):
    claims = jwt.decode(request.GET["t"], "k", ["HS256"], {"verify_signature": False})
    login(request, User.objects.get(pk=claims["sub"]))


def by_union(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=CHECKED | {"verify_signature": 0})
    login(request, User.objects.get(pk=claims["sub"]))


def by_imported_constant(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=SHARED_OPTIONS)
    login(request, User.objects.get(pk=claims["sub"]))


def strict(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=CHECKED)
    login(request, User.objects.get(pk=claims["sub"]))


def from_parameter(request, opts=None):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=opts)
    login(request, User.objects.get(pk=claims["sub"]))


def from_call(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=load_options())
    login(request, User.objects.get(pk=claims["sub"]))


def from_mutated_constant(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], options=PATCHED)
    login(request, User.objects.get(pk=claims["sub"]))


def from_settings_kwargs(request):
    claims = jwt.decode(request.GET["t"], "k", algorithms=["HS256"], **settings.TOKEN_DECODE_KWARGS)
    login(request, User.objects.get(pk=claims["sub"]))


def read_token(token):
    return jwt.decode(token, "k", algorithms=["HS256"], options=RELAXED)


def through_wrapper(request):
    claims = read_token(request.GET["t"])
    login(request, User.objects.get(pk=claims["sub"]))
"""

JWT_VIEW_NAMES = ["by_constant", "by_dict_call", "by_kwargs", "by_position", "by_union", "by_imported_constant",
                  "strict", "from_parameter", "from_call", "from_mutated_constant", "from_settings_kwargs",
                  "through_wrapper"]


def jwt_project(tc):
    urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [\n" + "".join(
        f'    path("{n}/", views.{n}),\n' for n in JWT_VIEW_NAMES) + "]\n"
    return project(tc, {"shop/views.py": JWT_VIEWS, "shop/jwtconf.py": 'SHARED_OPTIONS = {"verify_signature": False}\n',
                        "conf/urls.py": urls})


class CheckArgumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tc = unittest.TestCase()
        cls._cleanup = tc
        cls.root = jwt_project(tc)
        cls.report = scan(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls._cleanup.doCleanups()

    def path(self, name):
        return one_path(self, self.report, f"route:{name}/|shop.views.{name}")

    def test_verification_switched_off_by_any_static_form_is_not_a_guard(self):
        for name in ("by_constant", "by_dict_call", "by_kwargs", "by_position", "by_union", "by_imported_constant"):
            p = self.path(name)
            self.assertEqual(p["evidence"]["status"], "check_present_relationship_unproven", name)
            self.assertEqual(p["evidence"]["factors"], {"jwt_possession": "present_unproven"}, name)
            self.assertIn("verification disabled: options['verify_signature']", p["evidence"]["checks"][0]["detail"],
                          name)
            self.assertTrue(p["analysis_complete"], name)

    def test_strict_constant_is_a_guard(self):
        p = self.path("strict")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertEqual(p["evidence"]["factors"], {"jwt_possession": "guards_mint"})

    def test_arguments_that_cannot_be_evaluated_are_unproven_with_a_gap(self):
        for name in ("from_parameter", "from_call", "from_mutated_constant", "from_settings_kwargs"):
            p = self.path(name)
            self.assertEqual(p["evidence"]["status"], "check_present_relationship_unproven", name)
            self.assertIn("verification options not statically known", p["evidence"]["checks"][0]["detail"], name)
            self.assertFalse(p["analysis_complete"], name)
            self.assertTrue(any(k.startswith("check_argument_not_static|shop/views.py|shop.views." + name)
                                for k in p["gaps"]), (name, p["gaps"]))

    def test_wrapper_around_a_disabled_check_is_unfaithful(self):
        p = self.path("through_wrapper")
        self.assertEqual(p["evidence"]["status"], "check_present_relationship_unproven")
        self.assertIn("verification disabled", p["evidence"]["checks"][0]["detail"])

    def test_changing_only_the_constant_is_detected(self):
        root = jwt_project(self)
        lock = accept_all(build_lock(scan(root)))
        pid = [p["id"] for p in lock["paths"] if p["entry_point"]["id"] == "route:strict/|shop.views.strict"][0]
        src = read(root, "shop/views.py")
        write(root, "shop/views.py", src.replace('CHECKED = {"require": ["exp", "sub"]}',
                                                 'CHECKED = {"require": ["exp", "sub"], "verify_signature": False}'))
        findings, code = diff(lock, scan(root))
        self.assertEqual(by_path(findings)[pid], {"fingerprint_changed", "evidence_downgraded"})
        comps = [f["components"] for f in findings if f["path_id"] == pid and f["kind"] == "fingerprint_changed"]
        # (v5 review) the view reads the module constant itself, so its statement is also part of `code`
        self.assertEqual(comps, [["checks", "code"]])
        self.assertEqual(code & (4 | 8), 4 | 8)

    def test_benign_constant_change_changes_only_the_checks_fingerprint(self):
        root = jwt_project(self)
        lock = accept_all(build_lock(scan(root)))
        pid = [p["id"] for p in lock["paths"] if p["entry_point"]["id"] == "route:strict/|shop.views.strict"][0]
        write(root, "shop/views.py", read(root, "shop/views.py").replace(
            'CHECKED = {"require": ["exp", "sub"]}', 'CHECKED = {"require": ["exp"]}'))
        findings, _ = diff(lock, scan(root))
        self.assertEqual(by_path(findings)[pid], {"fingerprint_changed"})


# ============================================================================ F2
class TryExceptTests(unittest.TestCase):
    def test_try_body_and_handler_are_both_routed(self):
        root = project(self, {"shop/views.py": PASSWORD_VIEWS, "conf/urls.py": """\
            from django.urls import path
            from shop import views

            try:
                from optional_feature import marker  # an optional dependency
                urlpatterns = [path("login/", views.password_login)]
            except ImportError:
                urlpatterns = [path("home/", views.landing)]
            """})
        report = scan(root)
        self.assertTrue(routes(report, "login/", "shop.views.password_login")[0]["conditional"])
        self.assertTrue(routes(report, "home/", "shop.views.landing")[0]["conditional"])
        p = one_path(self, report, "route:login/|shop.views.password_login")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertEqual(unrouted(report), [])

    def test_handler_that_reraises_is_not_an_alternative(self):
        root = project(self, {"shop/views.py": PASSWORD_VIEWS, "conf/urls.py": """\
            from django.urls import path
            from shop import views

            try:
                from optional_feature import marker
                urlpatterns = [path("login/", views.password_login)]
            except ImportError as exc:
                raise RuntimeError("the feature is required") from exc
            """})
        report = scan(root)
        self.assertFalse(routes(report, "login/", "shop.views.password_login")[0]["conditional"])


# ============================================================================ F3
class ConditionalImportTests(unittest.TestCase):
    URLS = """\
        from django.conf import settings
        from django.urls import include, path
        from shop import views

        if settings.WITH_SECOND_FACTOR:
            from two_factor.urls import urlpatterns as mfa_routes
        else:
            mfa_routes = []

        try:
            from shop.extra_urls import urlpatterns as extra_routes
        except ImportError:
            extra_routes = []

        if settings.WITH_SECOND_FACTOR:
            from shop.views import password_login as entry_view
        else:
            from shop.views import landing as entry_view

        urlpatterns = [
            path("", include(mfa_routes)),
            path("extra/", include(extra_routes)),
            path("go/", entry_view),
            path("home/", views.landing),
        ]
        """

    @classmethod
    def setUpClass(cls):
        cls._tc = unittest.TestCase()
        root = project(cls._tc, {
            "shop/views.py": PASSWORD_VIEWS, "conf/urls.py": cls.URLS,
            "shop/extra_urls.py": "from django.urls import path\nfrom shop import views\n"
                                  "urlpatterns = [path('signin/', views.password_login)]\n"},
            "WITH_SECOND_FACTOR = True\n")
        cls.report = scan(root)

    @classmethod
    def tearDownClass(cls):
        cls._tc.doCleanups()

    def test_library_include_imported_in_one_branch_is_kept(self):
        r = routes(self.report, "", "two_factor.urls")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["kind"], "library_include")
        self.assertTrue(r[0]["conditional"])
        apis = {p["mint"]["api"] for p in paths_for(self.report, "route:|two_factor.urls")}
        self.assertIn("two_factor.views.core.LoginView.done", apis)

    def test_project_list_imported_in_try_is_routed(self):
        p = one_path(self, self.report, "route:extra/signin/|shop.views.password_login")
        self.assertTrue(p["entry"]["route"]["conditional"])
        self.assertEqual(unrouted(self.report), [])
        self.assertEqual(gaps(self.report, "urlconf_not_reached_from_root"), [])

    def test_view_imported_differently_in_branches_gives_both_routes(self):
        self.assertTrue(routes(self.report, "go/", "shop.views.password_login")[0]["conditional"])
        self.assertTrue(routes(self.report, "go/", "shop.views.landing")[0]["conditional"])
        self.assertEqual(gaps(self.report, "unsupported_url_construct"), [])


# ============================================================================ F4
class ImportedListTests(unittest.TestCase):
    BASE = "from django.urls import path\nfrom shop import views\nurlpatterns = [path('home/', views.landing)]\n"

    def scan_with(self, urls):
        root = project(self, {"shop/views.py": PASSWORD_VIEWS, "conf/base_urls.py": self.BASE,
                              "conf/urls.py": urls})
        return scan(root)

    def assertBothRouted(self, report):
        self.assertEqual(len(routes(report, "home/", "shop.views.landing")), 1)
        p = one_path(self, report, "route:login/|shop.views.password_login")
        self.assertFalse(p["entry"]["route"]["conditional"])
        self.assertEqual(unrouted(report), [])
        self.assertEqual(gaps(report, "unsupported_url_construct"), [])
        self.assertEqual(gaps(report, "urlconf_not_reached_from_root"), [])

    def test_append_to_imported_list(self):
        self.assertBothRouted(self.scan_with(
            "from django.urls import path\nfrom conf.base_urls import urlpatterns\nfrom shop import views\n"
            "urlpatterns.append(path('login/', views.password_login))\n"))

    def test_extend_imported_list(self):
        self.assertBothRouted(self.scan_with(
            "from django.urls import path\nfrom conf.base_urls import urlpatterns\nfrom shop import views\n"
            "urlpatterns.extend([path('login/', views.password_login)])\n"))

    def test_augmented_assignment_after_star_import(self):
        self.assertBothRouted(self.scan_with(
            "from django.urls import path\nfrom conf.base_urls import *\nfrom shop import views\n"
            "urlpatterns += [path('login/', views.password_login)]\n"))

    def test_insert_into_list_imported_under_another_name(self):
        report = self.scan_with(
            "from django.urls import path\nfrom conf.base_urls import urlpatterns as base\nfrom shop import views\n"
            "base.insert(0, path('login/', views.password_login))\nurlpatterns = base\n")
        self.assertBothRouted(report)


# ============================================================================ F5
DECORATED_VIEWS = """\
from django.contrib.auth import login, update_session_auth_hash
from django.contrib.auth.models import User


def auto_signin(view):
    def wrapped(request, *args, **kwargs):
        login(request, User.objects.get(username="demo-terminal"))
        return view(request, *args, **kwargs)
    return wrapped


def board(request):
    return None


def change_secret(request):
    request.user.set_password(request.POST["secret"])
    update_session_auth_hash(request, request.user)
"""


class RouteVariantTests(unittest.TestCase):
    def check_wrapped_variant(self, report):
        p = one_path(self, report, "route:board/|shop.views.board", "django.contrib.auth.login")
        self.assertEqual(p["mint"]["site"]["function"], "shop.views.auto_signin.wrapped")
        self.assertEqual(len(p["entry"]["route_variants"]), 1)
        self.assertNotIn("unrouted:shop.views.auto_signin.wrapped", unrouted(report))
        self.assertTrue(any(g["detail"] == "shop.views.auto_signin"
                            for g in gaps(report, "project_view_decorator_not_analyzed")))

    def test_wrapped_and_plain_route_in_if_else(self):
        for first, second in (("views.auto_signin(views.board)", "views.board"),
                              ("views.board", "views.auto_signin(views.board)")):
            root = project(self, {"shop/views.py": DECORATED_VIEWS, "conf/urls.py": f"""\
                from django.conf import settings
                from django.urls import path
                from shop import views

                if settings.DEMO_MODE:
                    urlpatterns = [path("board/", {first})]
                else:
                    urlpatterns = [path("board/", {second})]
                """}, "DEMO_MODE = False\n")
            self.check_wrapped_variant(scan(root))

    def test_wrapped_route_under_an_alternative_root_urlconf(self):
        root = project(self, {
            "shop/views.py": DECORATED_VIEWS,
            "conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                            "urlpatterns = [path('board/', views.board)]\n",
            "conf/demo_urls.py": "from django.urls import path\nfrom shop import views\n"
                                 "urlpatterns = [path('board/', views.auto_signin(views.board))]\n"},
            "import os\nif os.environ.get('DEMO'):\n    ROOT_URLCONF = 'conf.demo_urls'\n")
        self.check_wrapped_variant(scan(root))

    def test_a_gate_counts_only_if_every_variant_has_it(self):
        def run(second):
            root = project(self, {"shop/views.py": DECORATED_VIEWS, "conf/urls.py": f"""\
                from django.conf import settings
                from django.contrib.auth.decorators import login_required
                from django.urls import path
                from shop import views

                if settings.LOCKED:
                    urlpatterns = [path("secret/", login_required(views.change_secret))]
                else:
                    urlpatterns = [path("secret/", {second})]
                """}, "LOCKED = True\n")
            return one_path(self, scan(root), "route:secret/|shop.views.change_secret")
        mixed = run("views.change_secret")
        self.assertEqual(mixed["entry"]["gates"], [])
        self.assertNotIn("prior_authentication:session", mixed["evidence"]["factors"])
        self.assertTrue(any("are not on every definition" in n for n in mixed["entry"]["notes"]))
        both = run("login_required(views.change_secret)")
        self.assertIn("prior_authentication:session", both["evidence"]["factors"])

    def test_route_code_of_every_variant_is_fingerprinted(self):
        urls = """\
            from django.conf import settings
            from django.urls import path
            from shop import views

            if settings.DEMO_MODE:
                urlpatterns = [path("board/", views.auto_signin(views.board))]
            else:
                urlpatterns = [path("board/", views.board)]
            """
        root = project(self, {"shop/views.py": DECORATED_VIEWS, "conf/urls.py": urls}, "DEMO_MODE = False\n")
        lock = accept_all(build_lock(scan(root)))
        self.assertEqual(diff(lock, scan(root))[1], 0)
        write(root, "conf/urls.py", read(root, "conf/urls.py").replace(
            'path("board/", views.board)', 'path("board/", views.board, name="board")'))
        findings, _ = diff(lock, scan(root))
        self.assertEqual([f["components"] for f in findings if f["kind"] == "fingerprint_changed"], [["code"]])


# ============================================================================ F6
class LoopControlTests(unittest.TestCase):
    def scan_urls(self, urls):
        return scan(project(self, {"shop/views.py": PASSWORD_VIEWS, "conf/urls.py": urls}))

    def test_static_break_and_continue_do_not_invent_routes(self):
        report = self.scan_urls("""\
            from django.urls import path
            from shop import views

            urlpatterns = []
            for section in ["news", "team"]:
                if section == "team":
                    break
                urlpatterns.append(path(f"{section}/", views.landing))
            for section in ("faq", "login"):
                if section in ("login",):
                    continue
                urlpatterns.append(path(f"{section}/", views.landing))
            urlpatterns += [path("team/", views.password_login), path("login/", views.password_login)]
            """)
        self.assertEqual(sorted((r["pattern"], r["target"], r["conditional"]) for r in report["routes"]), [
            ("faq/", "shop.views.landing", False), ("login/", "shop.views.password_login", False),
            ("news/", "shop.views.landing", False), ("team/", "shop.views.password_login", False)])
        for pat in ("team/", "login/"):
            p = one_path(self, report, f"route:{pat}|shop.views.password_login")
            self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertEqual(report["coverage"]["paths_shadowed"], 0)

    def test_break_on_an_unknown_condition_makes_later_iterations_conditional(self):
        report = self.scan_urls("""\
            from django.conf import settings
            from django.urls import path
            from shop import views

            urlpatterns = []
            for section in ["news", "team"]:
                if settings.SECTION_FLAGS.get(section):
                    break
                urlpatterns.append(path(f"{section}/", views.landing))
            urlpatterns.append(path("team/", views.password_login))
            """)
        self.assertTrue(routes(report, "team/", "shop.views.landing")[0]["conditional"])
        self.assertTrue(routes(report, "news/", "shop.views.landing")[0]["conditional"])
        p = one_path(self, report, "route:team/|shop.views.password_login")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertIsNotNone(p["entry"]["route"].get("may_be_shadowed_by"))

    def test_comprehension_filter_decided_statically(self):
        report = self.scan_urls("""\
            from django.urls import path
            from shop import views

            urlpatterns = [path(f"{s}/", views.landing) for s in ["help", "login"] if s != "login"]
            urlpatterns += [path("login/", views.password_login)]
            """)
        self.assertEqual(routes(report, "login/", "shop.views.landing"), [])
        self.assertFalse(routes(report, "help/", "shop.views.landing")[0]["conditional"])
        self.assertEqual(report["coverage"]["paths_shadowed"], 0)


# ============================================================================ F7
BACKENDS = """\
from django.contrib.auth import get_user_model


class MailBackend:
    def authenticate(self, request, mail=None, secret=None):
        account = get_user_model().objects.filter(email=mail).first()
        if account is None or not self.check_client_network(request):
            return None
        if account.check_password(secret):
            return account
        return None

    def check_client_network(self, request):
        return request.META.get("REMOTE_ADDR", "").startswith("10.")


class TokenOrPasswordBackend:
    def authenticate(self, request, mail=None, secret=None, token=None):
        account = get_user_model().objects.filter(email=mail).first()
        if account is None:
            return None
        if token is not None and self.check_token(account, token):
            return account
        if account.check_password(secret):
            return account
        return None

    def check_token(self, account, token):
        return token == account.last_name
"""

MAIL_VIEWS = """\
from django.contrib.auth import authenticate, login


def mail_login(request):
    account = authenticate(request, mail=request.POST["mail"], secret=request.POST["secret"])
    if account is None:
        return None
    login(request, account)
"""


class BackendFactorTests(unittest.TestCase):
    def build(self, backend):
        return project(self, {"shop/views.py": MAIL_VIEWS, "shop/backends.py": BACKENDS,
                              "conf/urls.py": "from django.urls import path\nfrom shop import views\n"
                                              "urlpatterns = [path('login/', views.mail_login)]\n"},
                       f"AUTHENTICATION_BACKENDS = ['shop.backends.{backend}']\n")

    def test_extra_unrecognized_helper_does_not_hide_the_password_check(self):
        report = scan(self.build("MailBackend"))
        p = one_path(self, report, "route:login/|shop.views.mail_login")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertEqual(set(p["evidence"]["factors"]), {"password"})
        self.assertTrue(any(k.startswith("unrecognized_check_call|shop/backends.py|shop.backends.MailBackend.authenticate")
                            for k in p["gaps"]), p["gaps"])

    def test_success_exit_guarded_only_by_an_unrecognized_call_is_unverified(self):
        report = scan(self.build("TokenOrPasswordBackend"))
        p = one_path(self, report, "route:login/|shop.views.mail_login")
        self.assertEqual(p["evidence"]["status"], "guard_relies_on_unverified_check")
        self.assertEqual(set(p["evidence"]["factors"]),
                         {"unverified_project_backend:shop.backends.TokenOrPasswordBackend"})

    def test_removing_the_password_check_is_an_evidence_downgrade(self):
        root = self.build("MailBackend")
        lock = accept_all(build_lock(scan(root)))
        write(root, "shop/backends.py", read(root, "shop/backends.py").replace(
            "        if account.check_password(secret):\n            return account\n        return None\n\n"
            "    def check_client_network",
            "        return account\n\n    def check_client_network"))
        findings, code = diff(lock, scan(root))
        self.assertEqual(code & 8, 8, findings)
        msg = [f["message"] for f in findings if f["kind"] == "evidence_downgraded"][0]
        self.assertIn("factor password", msg)


# ============================================================================ F8
OTP_HELPERS = """\
import pyotp
from pyotp import HOTP
from django_otp.oath import TOTP as OathTOTP
from django.core.exceptions import PermissionDenied


def via_local(seed, pin):
    generator = pyotp.TOTP(seed)
    if not generator.verify(pin):
        raise PermissionDenied("pin")


def via_chained_call(seed, pin):
    if not pyotp.totp.TOTP(seed).verify(pin):
        raise PermissionDenied("pin")


def via_from_import(seed, pin, counter):
    if not HOTP(seed).verify(pin, counter):
        raise PermissionDenied("pin")


def via_django_otp(key, pin):
    if not OathTOTP(key).verify(pin):
        raise PermissionDenied("pin")
"""

OTP_FORMS = """\
import pyotp
from django import forms


class PinForm(forms.Form):
    pin = forms.CharField()

    def __init__(self, account, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.generator = pyotp.TOTP(account.otp_seed)

    def clean_pin(self):
        value = self.cleaned_data["pin"]
        if not self.generator.verify(value):
            raise forms.ValidationError("wrong pin")
        return value
"""

OTP_VIEWS = """\
from django.contrib.auth import login
from django.contrib.auth.models import User

from shop import otp
from shop.forms import PinForm


def pending(request):
    return User.objects.get(pk=request.session["pending_account"])


def step_local(request):
    account = pending(request)
    otp.via_local(account.otp_seed, request.POST["pin"])
    login(request, account)


def step_chained(request):
    account = pending(request)
    otp.via_chained_call(account.otp_seed, request.POST["pin"])
    login(request, account)


def step_hotp(request):
    account = pending(request)
    otp.via_from_import(account.otp_seed, request.POST["pin"], account.counter)
    login(request, account)


def step_django_otp(request):
    account = pending(request)
    otp.via_django_otp(account.otp_key, request.POST["pin"])
    login(request, account)


def step_form(request):
    account = pending(request)
    form = PinForm(account, request.POST)
    if form.is_valid():
        login(request, account)
"""

OTP_STEPS = ["step_local", "step_chained", "step_hotp", "step_django_otp", "step_form"]


def otp_project(tc):
    urls = "from django.urls import path\nfrom shop import views\nurlpatterns = [\n" + "".join(
        f'    path("{n}/", views.{n}),\n' for n in OTP_STEPS) + "]\n"
    return project(tc, {"shop/otp.py": OTP_HELPERS, "shop/forms.py": OTP_FORMS, "shop/views.py": OTP_VIEWS,
                        "conf/urls.py": urls})


class LibraryClassTypingTests(unittest.TestCase):
    def test_constructed_library_otp_objects_are_typed(self):
        report = scan(otp_project(self))
        for name in OTP_STEPS:
            p = one_path(self, report, f"route:{name}/|shop.views.{name}")
            self.assertEqual(p["evidence"]["status"], "check_guards_mint", name)
            self.assertEqual(p["evidence"]["factors"], {"otp": "guards_mint"}, name)
            self.assertTrue(p["analysis_complete"], (name, p["gaps"]))
        self.assertEqual(gaps(report, "unrecognized_check_call"), [])

    def test_v1_catalog_names_the_library_method(self):
        # without the pyotp catalog entries the call is still typed: the gap names pyotp, not `?.verify`
        report = scan(otp_project(self), catalog=CATALOG_V1)
        p = one_path(self, report, "route:step_local/|shop.views.step_local")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        self.assertEqual([u["target"] for u in p["evidence"]["unrecognized_checks"]], ["pyotp.TOTP.verify"])

    def test_form_accepting_every_pin_is_flagged(self):
        root = otp_project(self)
        lock = accept_all(build_lock(scan(root)))
        write(root, "shop/forms.py", read(root, "shop/forms.py").replace(
            '        if not self.generator.verify(value):\n            raise forms.ValidationError("wrong pin")\n', ""))
        findings, code = diff(lock, scan(root))
        self.assertEqual(code & (4 | 8), 4 | 8, findings)
        msg = [f["message"] for f in findings if f["kind"] == "evidence_downgraded"][0]
        self.assertIn("factor otp", msg)


if __name__ == "__main__":
    unittest.main()

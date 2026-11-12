"""v6 part B: precision, change detection and review cost.

Every test writes a small synthetic project into a temporary directory (helpers from test_v5.py).  The code is
written for these tests; no development-project code is copied.

    ExtractMethodTests         "extract method" (`self._audit(request, user)` with the moved statements in a method of
                               the same class) and helpers called with attribute-chain arguments
                               (`_audit(user, request.META)`) keep the fingerprint; the helper's later changes are
                               detected; an override in a subclass, an argument the helper re-assigns, and a public
                               method of a class that inherits a library flow are still conservative
"""
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


if __name__ == "__main__":
    unittest.main()

"""Check evidence (C4): is the mint control-dependent on check success, for the same user?"""
import os
import unittest

from mm_testutil import FIXTURES, scan, one_path, checks_by


class BasicEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(os.path.join(FIXTURES, "basic_project"))

    def test_early_return_guard(self):
        p = one_path(self, self.report, "route:login/password/")
        c = checks_by(p, "django.contrib.auth.authenticate")[0]
        self.assertEqual(c["relation"], "guards_mint")
        self.assertEqual(c["same_user"], "shown")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")

    def test_ignored_otp_result(self):
        p = one_path(self, self.report, "route:login/otp-ignored/")
        c = checks_by(p, "django_otp.match_token")[0]
        self.assertEqual(c["relation"], "result_ignored")
        self.assertEqual(p["evidence"]["factors"]["otp"], "not_enforced")
        # the password check still guards: status is about the strongest guard, factors carry the detail
        self.assertEqual(p["evidence"]["factors"]["password"], "guards_mint+same_user_shown")

    def test_wrapper_check_across_modules_and_same_user(self):
        p = one_path(self, self.report, "route:login/otp/")
        c = checks_by(p, "accounts.helpers.verify_otp")[0]
        self.assertEqual((c["via"], c["relation"], c["same_user"]), ("wrapper", "guards_mint", "shown"))
        self.assertEqual(p["evidence"]["factors"]["otp"], "guards_mint+same_user_shown")

    def test_cbv_framework_gate(self):
        p = one_path(self, self.report, "route:login/email/")
        c = checks_by(p, "accounts.forms.EmailLoginForm.is_valid")[0]
        self.assertEqual((c["via"], c["factor"], c["relation"], c["same_user"]),
                         ("framework", "password", "guards_mint", "shown"))


class EdgeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(os.path.join(FIXTURES, "edge_project"))

    def rel(self, prefix, check):
        p = one_path(self, self.report, prefix)
        return checks_by(p, check)[0], p

    def test_verification_for_a_different_user(self):
        c, p = self.rel("route:wrong-user/", "django_otp.match_token")
        self.assertEqual(c["relation"], "guards_mint")
        self.assertEqual(c["same_user"], "unproven")
        self.assertEqual(p["evidence"]["factors"]["otp"], "guards_mint")  # not '+same_user_shown'

    def test_disjunction_is_not_a_guard(self):
        c, _ = self.rel("route:disjunction/", "django_otp.match_token")
        self.assertEqual(c["relation"], "present_unproven")
        self.assertIn("does not constrain", c["detail"])

    def test_assert_only_guard_is_flagged(self):
        c, p = self.rel("route:assert/", "django_otp.match_token")
        self.assertEqual(c["relation"], "guards_mint_assert_only")
        self.assertNotEqual(p["evidence"]["status"], "check_guards_mint")

    def test_tuple_returning_check_used_as_condition(self):
        c, p = self.rel("route:tuple/", "verify_is_allowed")
        self.assertEqual(c["relation"], "condition_always_truthy")
        self.assertEqual(p["evidence"]["status"], "check_result_not_enforced")

    def test_check_after_mint(self):
        c, _ = self.rel("route:after/", "django_otp.match_token")
        self.assertEqual(c["relation"], "present_unproven")
        self.assertIn("after the mint", c["detail"])

    def test_swallowed_exception(self):
        c, _ = self.rel("route:swallowed/", "dj_rest_auth.mfa.utils.verify_ephemeral_token")
        self.assertEqual(c["relation"], "present_unproven")
        self.assertIn("swallows", c["detail"])

    def test_reassigned_result_does_not_guard(self):
        c, _ = self.rel("route:stale/", "django_otp.verify_token")
        self.assertEqual(c["relation"], "present_unproven")

    def test_unverified_project_backend_is_not_a_verified_guard(self):
        c, p = self.rel("route:backend/", "django.contrib.auth.authenticate")
        self.assertEqual(c["relation"], "guards_mint")
        self.assertTrue(c["factor"].startswith("unverified_project_backend"))
        self.assertEqual(p["evidence"]["status"], "guard_relies_on_unverified_check")

    def test_walrus_binding(self):
        c, _ = self.rel("route:walrus/", "django.contrib.auth.authenticate")
        self.assertEqual((c["relation"], c["same_user"]), ("guards_mint", "shown"))

    def test_drf_serializer_raise_exception_guard(self):
        c, p = self.rel("route:api/token/", "rest_framework.authtoken.serializers.AuthTokenSerializer.is_valid")
        self.assertEqual((c["relation"], c["factor"], c["same_user"]), ("guards_mint", "password", "shown"))

    def test_request_user_mint_is_described_as_exchange(self):
        p = [p for p in self.report["paths"] if p["entry"]["id"].startswith("route:api/jwt/|")
             and p["mint"]["purpose"] == "jwt_refresh"][0]
        self.assertEqual(p["evidence"]["status"], "no_check_found_in_analyzed_code")
        self.assertTrue(any("request.user" in n for n in p["evidence"]["context"]))

    def test_drf_permission_gate_for_request_user(self):
        p = one_path(self, self.report, "route:api/sessions/")
        self.assertEqual(p["evidence"]["factors"],
                         {"prior_authentication:SessionAuthentication": "guards_mint+same_user_shown"})

    def test_login_required_gate_for_request_user(self):
        p = one_path(self, self.report, "route:exchange/", api="rest_framework_simplejwt.tokens.RefreshToken.for_user")
        self.assertEqual(p["evidence"]["factors"], {"prior_authentication:session": "guards_mint+same_user_shown"})

    def test_super_form_valid_keeps_framework_gate(self):
        p = one_path(self, self.report, "route:login/audited/")
        c = checks_by(p, "django.contrib.auth.forms.AuthenticationForm.is_valid")[0]
        self.assertEqual((c["via"], c["relation"], c["factor"]), ("framework", "guards_mint", "password"))

    def test_no_check_label_is_scoped_to_analyzed_code(self):
        labels = {p["evidence"]["status"] for p in self.report["paths"]}
        self.assertNotIn("no_checks", labels)
        self.assertIn("no_check_found_in_analyzed_code", labels)


if __name__ == "__main__":
    unittest.main()

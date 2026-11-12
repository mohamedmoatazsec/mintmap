"""Inventory (C1/C2/C3) on the synthetic basic_project fixture."""
import os
import unittest

from mm_testutil import FIXTURES, scan, one_path, paths_for, checks_by


class BasicInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(os.path.join(FIXTURES, "basic_project"))

    def test_alias_import_resolves_to_django_login(self):
        # `from django.contrib.auth import login as django_login`
        p = one_path(self, self.report, "route:login/password/")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.login")
        self.assertEqual(p["mint"]["site"]["call"], "django_login")
        self.assertEqual(p["mint"]["purpose"], "full_session")

    def test_module_alias_attribute_access(self):
        # `from django.contrib import auth; auth.login(...)`
        p = one_path(self, self.report, "route:login/email/")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.login")
        self.assertEqual(p["mint"]["site"]["call"], "auth.login")

    def test_wrapper_function_in_another_module(self):
        p = one_path(self, self.report, "route:login/otp/")
        self.assertEqual(p["mint"]["site"]["function"], "accounts.helpers.sign_in")
        self.assertEqual(p["mint"]["site"]["file"], os.path.join("accounts", "helpers.py"))
        self.assertEqual(p["chain"], ["accounts.views.otp_login_wrapper", "accounts.helpers.sign_in"])

    def test_cbv_form_valid_login(self):
        p = one_path(self, self.report, "route:login/email/")
        self.assertEqual(p["mint"]["site"]["function"], "accounts.views.EmailLoginView.form_valid")
        self.assertIn("accounts.views.EmailLoginView.form_valid (framework_hook)", p["entry"]["functions"])

    def test_async_alogin(self):
        p = one_path(self, self.report, "route:login/async/")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.alogin")
        self.assertEqual(p["mint"]["purpose"], "full_session")
        self.assertEqual(checks_by(p, "django.contrib.auth.aauthenticate")[0]["relation"], "guards_mint")

    def test_remote_user_middleware_in_settings(self):
        p = one_path(self, self.report, "middleware:django.contrib.auth.middleware.RemoteUserMiddleware")
        self.assertEqual(p["mint"]["provided_by"], "library")
        self.assertEqual(p["mint"]["purpose"], "full_session")
        self.assertEqual(p["evidence"]["status"], "library_flow_checks_not_analyzed")

    def test_include_allauth_urls_library_entry_points(self):
        ps = paths_for(self.report, "route:accounts/|allauth.urls")
        purposes = {p["mint"]["purpose"] for p in ps}
        self.assertTrue({"full_session", "mfa_challenge_state", "password_reset_token"} <= purposes, purposes)
        self.assertTrue(all(p["mint"]["provided_via"] == "allauth.urls" for p in ps))
        self.assertTrue(all(p["mint"]["catalog_ref"] for p in ps))

    def test_every_inventory_entry_has_catalog_basis(self):
        for p in self.report["paths"]:
            self.assertTrue(p["mint"]["purpose_basis"].startswith(("catalog:", "overlay override", "heuristic")))

    def test_dependency_pins_read(self):
        specs = self.report["coverage"]["dependency_specs"]
        self.assertEqual(specs["allauth"], "==65.16.1@requirements.txt")
        self.assertNotIn("requests", specs)

    def test_clean_fixture_has_no_gaps(self):
        cov = self.report["coverage"]
        # v5 (R2b): the only gap is that catalog v3 does not declare allauth.urls' mint list complete
        # (before v5: no gap at all; an incomplete catalogued include was silently treated as fully known)
        self.assertEqual([g["key"].split("|")[0] + "|" + g["detail"].split(":")[0] for g in cov["gaps"]],
                         ["library_include_mints_incomplete|allauth.urls"])
        self.assertEqual(cov["files_parsed"], cov["files_seen"])
        self.assertEqual(cov["settings_modules"], ["proj.settings"])
        self.assertEqual(cov["root_urlconfs"], ["proj.urls"])


class EdgeInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(os.path.join(FIXTURES, "edge_project"))

    def gap_types(self):
        return self.report["coverage"]["gaps_by_type"]

    def test_project_middleware_mint(self):
        p = one_path(self, self.report, "middleware:edge.middleware.HeaderLoginMiddleware")
        self.assertEqual(p["mint"]["site"]["function"], "edge.middleware.HeaderLoginMiddleware.__call__")
        self.assertEqual(p["evidence"]["status"], "no_check_found_in_analyzed_code")
        self.assertIn("edge.middleware.lookup_header_user", p["fingerprint"]["callee_functions"])

    def test_jwt_refresh_and_access_purposes(self):
        ps = paths_for(self.report, "route:api/jwt/|")
        self.assertEqual({p["mint"]["purpose"] for p in ps}, {"jwt_refresh", "jwt_access"})

    def test_drf_token_get_or_create(self):
        p = one_path(self, self.report, "route:api/token/")
        self.assertEqual(p["mint"]["purpose"], "api_token")

    def test_post_reset_login_flag_controls_library_mint(self):
        self.assertEqual(len(paths_for(self.report, "route:reset/<uidb64>/<token>/")), 1)
        self.assertEqual(paths_for(self.report, "route:reset-plain/"), [])

    def test_invitation_subclass_keeps_catalog_purpose_with_note(self):
        p = one_path(self, self.report, "route:invite/")
        self.assertEqual(p["mint"]["purpose"], "password_reset_token")
        self.assertIn("InvitationTokenGenerator", p["mint"]["purpose_note"])

    def test_unrouted_mint_is_inventoried_not_dropped(self):
        p = one_path(self, self.report, "unrouted:edge.signals.on_external_event")
        self.assertEqual(p["entry"]["kind"], "unrouted")

    def test_login_passed_as_parameter_is_a_gap(self):
        gaps = [g for g in self.report["coverage"]["gaps"] if g["type"] == "possible_mint_call_unresolved"]
        self.assertEqual([g["where"] for g in gaps], ["edge.signals.run_pipeline"])

    def test_drf_router_viewset_action(self):
        p = one_path(self, self.report, "route:api/sessions/")
        self.assertEqual(p["entry"]["route"]["kind"], "viewset")
        self.assertEqual(p["mint"]["api"], "knox.models.AuthToken.objects.create")
        self.assertEqual(p["mint"]["site"]["function"], "api.viewsets.SessionViewSet.renew")

    def test_routed_library_views(self):
        p = one_path(self, self.report, "route:api/token-auth/")  # function alias obtain_auth_token
        self.assertEqual((p["mint"]["provided_by"], p["mint"]["purpose"]), ("library", "api_token"))
        p = one_path(self, self.report, "route:api/jwt/refresh/")
        self.assertEqual(p["mint"]["purpose"], "jwt_refresh_exchange")

    def test_library_view_subclass_inherits_mint(self):
        p = one_path(self, self.report, "route:login/plain/")
        self.assertEqual(p["mint"]["provided_by"], "library")
        self.assertEqual(p["mint"]["catalog_ref"], "django.contrib.auth.views.LoginView")

    def test_library_view_subclass_super_call_is_project_mint_site(self):
        p = one_path(self, self.report, "route:login/audited/")
        self.assertEqual(p["mint"]["provided_by"], "project_code")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.views.LoginView.form_valid")

    def test_custom_signed_token_has_unknown_purpose(self):
        p = one_path(self, self.report, "route:exchange/", api="django.core.signing.dumps")
        self.assertEqual(p["mint"]["purpose"], "unknown")
        self.assertTrue(p["mint"]["purpose_basis"].startswith("heuristic"))

    def test_derived_mint_wrappers_listed(self):
        wrappers = {w["function"]: w for w in self.report["derived_mint_wrappers"]}
        self.assertTrue(wrappers["edge.signals.on_external_event"]["direct"])
        self.assertIn("django.contrib.auth.login", wrappers["edge.middleware.HeaderLoginMiddleware.__call__"]["mints"])

    def test_dynamic_setting_unknown_include_unsupported_url_parse_failure(self):
        t = self.gap_types()
        for k in ("dynamic_setting", "conditional_setting", "library_include_not_in_catalog",
                  "unsupported_view_expr", "parse_failure"):
            self.assertIn(k, t)
        self.assertEqual(self.report["coverage"]["parse_failures"][0]["file"], os.path.join("legacy", "broken.py"))


if __name__ == "__main__":
    unittest.main()

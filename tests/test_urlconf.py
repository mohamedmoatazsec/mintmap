"""v3: URL lists built in steps, project URL helper functions (P4) and first-match shadowing (P5).

Fixture: tests/fixtures/urlbuild_project (synthetic).  site_cfg/urls.py builds its URL list with a
copy, `+=`, `.extend()`, `.append()`, `.insert()`, list concatenation, `i18n_patterns(*list)`, a loop
over a settings list with f-string includes and `import_string`, a settings-conditional block,
conditional expressions, comprehensions, and project helpers in site_cfg/urlkit.py; it also contains
literal-equal routes in several orders.
"""
import json
import os
import unittest

from mm_testutil import FIXTURES, scan, copy_fixture, one_path, paths_for, write, read, accept_all

from mintmap.core.lockfile import build_lock, diff
from mintmap.core.urlconf import _norm_key

FIX = os.path.join(FIXTURES, "urlbuild_project")


def _route(report, pattern, target):
    rs = [r for r in report["routes"] if r["pattern"] == pattern and r["target"] == target]
    return rs[0] if rs else None


def _gaps(report, typ):
    return [g for g in report["coverage"]["gaps"] if g["type"] == typ]


class UrlListConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(FIX)

    def test_every_mint_is_linked_to_a_route(self):
        self.assertEqual([p["entry"]["id"] for p in self.report["paths"] if p["entry"]["kind"] == "unrouted"], [])
        self.assertEqual(self.report["coverage"]["paths_unrouted"], 0)

    def test_conditional_root_urlconf_keeps_both_alternatives(self):
        # ROOT_URLCONF reassigned under `if os.environ.get(...)`: both URLconfs serve requests in some process
        self.assertEqual(self.report["coverage"]["root_urlconfs"], ["site_cfg.urls", "site_cfg.stream_urls"])
        one_path(self, self.report, "route:stream/signin/|web.views.stream_signin")

    def test_helper_view_resolved_through_its_parameters(self):
        p = one_path(self, self.report, "route:signin/|web.views.password_signin")
        self.assertEqual(p["entry"]["route"]["url_helpers"], ["site_cfg.urlkit.page"])
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.login")
        self.assertIn("route built by project URL helper(s) site_cfg.urlkit.page", p["entry"]["notes"])

    def test_helper_that_returns_a_list_built_in_a_loop(self):
        for v in ("v1", "v2"):
            p = one_path(self, self.report, f"route:api/{v}/sso/|web.views.sso_signin")
            self.assertFalse(p["entry"]["route"]["conditional"], "a loop over a literal tuple always runs")

    def test_views_passed_to_a_dispatcher_in_route_kwargs(self):
        p = one_path(self, self.report, "route:api/token/|web.views.token_signin")
        self.assertEqual(p["entry"]["route"]["dispatched_by"], {"view": "web.dispatch.by_method", "kwarg": "POST"})
        self.assertFalse(p["analysis_complete"])
        self.assertTrue(any(k.startswith("view_dispatcher_not_analyzed|web/dispatch.py|web.dispatch.by_method")
                            for k in p["gaps"]), p["gaps"])
        # the dispatcher route itself is an entry too
        self.assertIsNotNone(_route(self.report, "api/token/", "web.dispatch.by_method"))

    def test_include_of_a_list_sees_later_in_place_additions(self):
        # `routes += [path("api/", include(api))]` comes before `api.append(...)`
        one_path(self, self.report, "route:api/late/|web.views.late_signin")

    def test_list_copy_is_a_snapshot(self):
        # `routes = list(localized)` then `localized.append(...)`: only the i18n copy has the route
        one_path(self, self.report, "route:{lang}/localized-only/|web.views.localized_only_signin")
        self.assertEqual(paths_for(self.report, "route:localized-only/"), [])

    def test_i18n_patterns_add_a_language_prefix(self):
        one_path(self, self.report, "route:{lang}/signin/|web.views.password_signin")
        one_path(self, self.report, "route:{lang}/welcome/login/|web.views.page_with_library_login")

    def test_extend_and_insert(self):
        one_path(self, self.report, "route:magic/<str:key>/|web.views.magic_signin")
        admin_login = _route(self.report, "admin/login/", "web.views.password_signin")
        admin_site = _route(self.report, "admin/", "django.contrib.admin.site.urls")
        self.assertIsNotNone(admin_login)
        self.assertIsNotNone(admin_site)

    def test_loop_over_settings_list_with_fstring_include_and_import_string(self):
        for app, view in (("billing", "plugins.billing.views.billing_signin"),
                          ("shop", "plugins.shop.views.shop_signin")):
            p = one_path(self, self.report, f"route:{app}/signin/|{view}")
            self.assertTrue(p["entry"]["route"]["conditional"], "a settings value may differ in a deployment")
            self.assertIsNotNone(_route(self.report, f"{{lang}}/{app}/welcome/", f"plugins.{app}.views.welcome"))

    def test_include_of_patterns_app_name_tuple(self):
        one_path(self, self.report, "route:reports/signin/|plugins.reports.views.reports_signin")
        self.assertFalse(any("reports" in g["detail"] for g in _gaps(self.report, "unsupported_url_construct")))

    def test_settings_conditional_block_and_conditional_expressions(self):
        self.assertTrue(one_path(self, self.report, "route:legacy/|web.views.legacy_signin_a")
                        ["entry"]["route"]["conditional"])
        self.assertTrue(one_path(self, self.report, "route:beta/|web.views.beta_signin")["entry"]["route"]["conditional"])
        for v in ("choice_a", "choice_b"):
            self.assertTrue(one_path(self, self.report, f"route:choose/|web.views.{v}")["entry"]["route"]["conditional"])

    def test_comprehension_over_literal_values_is_unrolled(self):
        one_path(self, self.report, "route:north/|web.views.named_signin")
        one_path(self, self.report, "route:south/|web.views.named_signin")

    def test_values_that_cannot_be_enumerated_are_explicit_gaps(self):
        details = [g["detail"] for g in _gaps(self.report, "unsupported_url_construct")]
        self.assertTrue(any("settings.REDIRECT_RULES" in d and "comprehension over values" in d for d in details),
                        details)
        self.assertTrue(any("settings.EXTRA_ROUTES" in d and "iterable not statically known" in d for d in details),
                        details)
        dyn = [g["detail"] for g in _gaps(self.report, "dynamic_route_pattern")]
        self.assertIn("r.old", dyn)
        self.assertIn("extra", dyn)

    def test_project_function_that_modifies_the_list_in_place(self):
        # `add_status_routes(routes)` appends to the caller's list
        self.assertIsNotNone(_route(self.report, "status/", "web.views.redirect_view"))

    def test_list_passed_to_an_unknown_callable_is_a_gap(self):
        details = [g["detail"] for g in _gaps(self.report, "unsupported_url_construct")]
        self.assertIn("attach_plugin_routes(routes): URL list passed to urlplugins_lib.attach_plugin_routes "
                      "(a callable MintMap cannot follow), which may modify it", details)

    def test_runtime_chosen_prefix_is_a_named_placeholder(self):
        p = one_path(self, self.report, "route:{prefix}portal/|web.views.portal_signin")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertTrue(any(g["detail"] == "f'{prefix}portal/'" for g in _gaps(self.report, "dynamic_route_pattern")))

    def test_library_view_run_from_project_code(self):
        p = one_path(self, self.report, "route:welcome/login/|web.views.page_with_library_login")
        self.assertEqual(p["mint"]["api"], "django.contrib.auth.views.LoginView")
        self.assertEqual(p["mint"]["provided_by"], "library")
        self.assertIn("invoked from web.views.page_with_library_login", p["mint"]["purpose_note"])


class ShadowingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = scan(FIX)

    def assertShadowed(self, entry_id, by_pattern, by_target, api=None, status_if_reachable=None):
        p = one_path(self, self.report, entry_id, api)
        ev = p["evidence"]
        self.assertTrue(p["shadowed"])
        self.assertEqual(ev["status"], "shadowed_by_earlier_route")
        self.assertEqual((ev["shadowed_by"]["pattern"], ev["shadowed_by"]["target"]), (by_pattern, by_target))
        if status_if_reachable:
            self.assertEqual(ev["status_if_reachable"], status_if_reachable)
        self.assertTrue(any("not reachable through this route" in c for c in ev["context"]), ev["context"])
        return p

    def assertReachable(self, entry_id, api=None):
        p = one_path(self, self.report, entry_id, api)
        self.assertFalse(p["shadowed"], p["evidence"].get("shadowed_by"))
        self.assertNotEqual(p["evidence"]["status"], "shadowed_by_earlier_route")
        return p

    def test_later_literal_equal_route_is_shadowed(self):
        p = self.assertShadowed("route:signin/|django.contrib.auth.views.LoginView", "signin/",
                                "web.views.password_signin", status_if_reachable="library_flow_checks_not_analyzed")
        self.assertTrue(any(n.startswith("shadowed: the earlier pattern 'signin/'") for n in p["entry"]["notes"]))
        self.assertShadowed("route:{lang}/signin/|django.contrib.auth.views.LoginView", "{lang}/signin/",
                            "web.views.password_signin")
        self.assertReachable("route:signin/|web.views.password_signin")

    def test_earlier_project_route_shadows_only_the_matching_library_admin_flow(self):
        self.assertShadowed("route:admin/|django.contrib.admin.site.urls", "admin/login/", "web.views.password_signin",
                            api="django.contrib.admin.sites.AdminSite.login")
        self.assertReachable("route:admin/|django.contrib.admin.site.urls",
                             api="django.contrib.auth.admin.UserAdmin.user_change_password")
        p = self.assertReachable("route:admin/login/|web.views.password_signin")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")

    def test_earlier_library_include_shadows_a_later_project_route(self):
        self.assertShadowed("route:accounts/login/|web.views.custom_account_login", "accounts/login/",
                            "django.contrib.auth.urls", status_if_reachable="check_guards_mint")
        for p in paths_for(self.report, "route:accounts/|django.contrib.auth.urls"):
            self.assertFalse(p["shadowed"])

    def test_conditional_earlier_route_only_may_shadow(self):
        p = self.assertReachable("route:legacy/|web.views.legacy_signin_b")
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertEqual(p["entry"]["route"]["may_be_shadowed_by"]["target"], "web.views.legacy_signin_a")
        self.assertTrue(any(c.startswith("may be shadowed by the earlier conditional pattern 'legacy/'")
                            for c in p["evidence"]["context"]))

    def test_same_runtime_placeholder_compares_equal(self):
        self.assertShadowed("route:{prefix}portal/|web.views.second_portal_signin", "{prefix}portal/",
                            "web.views.portal_signin")
        self.assertReachable("route:{prefix}portal/|web.views.portal_signin")

    def test_converter_parameter_names_do_not_matter(self):
        self.assertShadowed("route:u/<int:uid>/signin/|web.views.user_signin_dup", "u/<int:pk>/signin/",
                            "web.views.user_signin")
        self.assertEqual(_norm_key("u/<int:pk>/<slug>/", False), _norm_key("u/<int:id>/<str:s>/", False))
        self.assertNotEqual(_norm_key("u/<int:pk>/", False), _norm_key("u/<slug:pk>/", False))

    def test_different_or_non_comparable_patterns_are_not_shadowed(self):
        for eid in ("route:x/signin|web.views.slash_a", "route:x/signin/|web.views.slash_b",
                    "route:^r/signin/$|web.views.regex_a", "route:r/signin/|web.views.regex_b",
                    "route:north/|web.views.named_signin", "route:stream/signin/|web.views.stream_signin"):
            self.assertReachable(eid)

    def test_coverage_counts(self):
        cov = self.report["coverage"]
        self.assertEqual(cov["paths_shadowed"], sum(1 for p in self.report["paths"] if p["shadowed"]))
        self.assertEqual(cov["paths_shadowed"], 6)
        self.assertEqual(cov["library_subroutes_shadowed"], 1)
        self.assertEqual(cov["routes_may_be_shadowed"], 1)


class LockAndFingerprintTests(unittest.TestCase):
    def _base(self):
        root = copy_fixture(self, "urlbuild_project")
        lock = accept_all(build_lock(scan(root)))
        return root, lock

    @staticmethod
    def _by_path(findings):
        out = {}
        for f in findings:
            out.setdefault(f["path_id"], set()).add(f["kind"])
        return out

    def test_unchanged_project_diffs_clean(self):
        root, lock = self._base()
        findings, code = diff(lock, scan(root))
        self.assertEqual(code, 0, findings)

    def test_removing_the_shadowing_route_reports_the_now_reachable_path(self):
        root, lock = self._base()
        old = {p["entry_point"]["id"]: p["id"] for p in lock["paths"]}
        src = read(root, "site_cfg/urls.py")
        write(root, "site_cfg/urls.py", src.replace('path("u/<int:pk>/signin/", views.user_signin), ', ""))
        findings, code = diff(lock, scan(root))
        dup = old["route:u/<int:uid>/signin/|web.views.user_signin_dup"]
        kinds = self._by_path(findings)
        self.assertEqual(kinds[dup], {"fingerprint_changed", "evidence_downgraded"})
        msg = [f["message"] for f in findings if f["path_id"] == dup and f["kind"] == "evidence_downgraded"][0]
        self.assertIn("shadowed_by_earlier_route -> check_guards_mint", msg)
        self.assertIn("no longer shadowed", msg)
        self.assertEqual(kinds[old["route:u/<int:pk>/signin/|web.views.user_signin"]], {"removed_path"})
        self.assertEqual(code & (2 | 4 | 8), 2 | 4 | 8)

    def test_removing_the_route_that_shadows_a_library_flow(self):
        root, lock = self._base()
        ids = {(p["entry_point"]["id"], p["mint_site"]["api"]): p["id"] for p in lock["paths"]}
        src = read(root, "site_cfg/urls.py")
        write(root, "site_cfg/urls.py", src.replace('routes.insert(0, path("admin/login/", views.password_signin))\n', ""))
        findings, code = diff(lock, scan(root))
        kinds = self._by_path(findings)
        admin_login = ids[("route:admin/|django.contrib.admin.site.urls", "django.contrib.admin.sites.AdminSite.login")]
        self.assertEqual(kinds[admin_login], {"fingerprint_changed", "evidence_downgraded"})
        msg = [f["message"] for f in findings if f["path_id"] == admin_login and f["kind"] == "evidence_downgraded"]
        self.assertIn("shadowed_by_earlier_route -> library_flow_checks_not_analyzed", msg[0])
        other = ids[("route:admin/|django.contrib.admin.site.urls",
                     "django.contrib.auth.admin.UserAdmin.user_change_password")]
        self.assertNotIn(other, kinds)
        self.assertEqual(code & 8, 8)

    def test_newly_shadowed_path_is_a_fingerprint_change_not_a_downgrade(self):
        root, lock = self._base()
        old = {p["entry_point"]["id"]: p["id"] for p in lock["paths"]}
        src = read(root, "site_cfg/urls.py")
        write(root, "site_cfg/urls.py", src.replace('path("x/signin", views.slash_a)', 'path("x/signin/", views.slash_a)'))
        report = scan(root)
        findings, code = diff(lock, report)
        kinds = self._by_path(findings)
        slash_b = old["route:x/signin/|web.views.slash_b"]
        self.assertEqual(kinds[slash_b], {"fingerprint_changed"})
        self.assertEqual([f["components"] for f in findings if f["path_id"] == slash_b], [["code"]])
        self.assertTrue(one_path(self, report, "route:x/signin/|web.views.slash_b")["shadowed"])
        self.assertEqual(code & 8, 0)

    def test_url_helper_and_dispatcher_code_are_fingerprinted(self):
        root, lock = self._base()
        old = {p["entry_point"]["id"]: p for p in lock["paths"]}
        write(root, "web/dispatch.py", read(root, "web/dispatch.py").replace(
            "    handler = handlers.get(request.method)\n",
            "    handler = handlers.get(request.method.upper())\n"))
        findings, _ = diff(lock, scan(root))
        changed = {f["path_id"]: f["components"] for f in findings if f["kind"] == "fingerprint_changed"}
        self.assertEqual(changed, {old["route:api/token/|web.views.token_signin"]["id"]: ["code"]})

        root, lock = self._base()
        write(root, "site_cfg/urlkit.py", read(root, "site_cfg/urlkit.py").replace(
            "    return path(route, view, name=name)\n", "    return path(route, view, name=name or route)\n"))
        findings, _ = diff(lock, scan(root))
        changed = {f["path_id"] for f in findings if f["kind"] == "fingerprint_changed"}
        helper_paths = {p["id"] for p in lock["paths"]
                        if "site_cfg.urlkit.page" in (p["entry_point"].get("route") or {}).get("url_helpers", [])}
        self.assertTrue(helper_paths)
        self.assertEqual(changed, helper_paths)

    def test_lock_records_shadowing(self):
        root, lock = self._base()
        entry = [p for p in lock["paths"] if p["entry_point"]["id"] == "route:signin/|django.contrib.auth.views.LoginView"]
        self.assertEqual(entry[0]["evidence"]["status"], "shadowed_by_earlier_route")
        self.assertEqual(entry[0]["evidence"]["shadowed_by"]["target"], "web.views.password_signin")
        json.dumps(lock)


if __name__ == "__main__":
    unittest.main()

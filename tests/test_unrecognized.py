"""v2: catalog v2 verifier APIs, unrecognized verification-looking calls (P1) and validation
methods in the check fingerprint (P2), on the synthetic verify_project fixture."""
import os
import unittest

from mm_testutil import (FIXTURES, CATALOG, CATALOG_V1, scan, one_path, checks_by, copy_fixture, read, write,
                         accept_all)
from mintmap.core.lockfile import (build_lock, diff, FINGERPRINT_CHANGED, EVIDENCE_DOWNGRADED, COVERAGE_REGRESSION,
                                   NEW_PATH)

VP = os.path.join(FIXTURES, "verify_project")


def gaps_of(path, gtype="unrecognized_check_call"):
    return [g for g in path["gaps"] if g.startswith(gtype + "|")]


class CatalogV2CheckTests(unittest.TestCase):
    """(a) verifier APIs added in catalog v2 (each cites library source in the catalog)."""

    @classmethod
    def setUpClass(cls):
        cls.report = scan(VP)

    def test_default_catalog_is_v2_superset(self):
        # v5: the default is catalog v3, a strict superset of v2 (was: v2)
        self.assertTrue(CATALOG.path.endswith(os.path.join("data", "django_catalog.json")))
        for ref in ("pyotp.totp.TOTP.verify", "fido2.server.Fido2Server.authenticate_complete",
                    "django.core.signing.loads / Signer.unsign / unsign_object / TimestampSigner.unsign"):
            self.assertIn(ref, CATALOG.entries_by_ref)
            self.assertTrue(CATALOG.entries_by_ref[ref]["source_location"])
        self.assertEqual(self.report["tool"]["overlay_entries_skipped"], [])

    def test_pyotp_verify_in_form_clean_method_via_typed_self_attribute(self):
        # self.generator is typed from the annotated __init__ parameter (pyotp.TOTP re-export)
        p = one_path(self, self.report, "route:mfa/totp/")
        c = checks_by(p, "mfa.forms.OneTimeCodeForm.is_valid")[0]
        self.assertEqual((c["factor"], c["relation"]), ("otp", "guards_mint"))
        self.assertEqual(p["evidence"]["status"], "check_guards_mint")
        self.assertTrue(p["analysis_complete"])
        self.assertIn("mfa.forms.OneTimeCodeForm.clean_code", p["fingerprint"]["check_functions"])

    def test_fido2_assertion_in_project_helper_class(self):
        p = one_path(self, self.report, "route:mfa/key/")
        c = checks_by(p, "mfa.keys.KeyChecker.assertion_ok")[0]
        self.assertEqual((c["factor"], c["via"], c["relation"]), ("webauthn", "wrapper", "guards_mint"))
        # authenticate_begin only generates a challenge (catalog v2 non_check_apis): not reported
        self.assertEqual(p["evidence"]["unrecognized_checks"], [])
        self.assertTrue(p["analysis_complete"])

    def test_jwt_decode_and_disabled_signature_verification(self):
        p = one_path(self, self.report, "route:mfa/remote/")
        self.assertEqual(p["evidence"]["factors"], {"jwt_possession": "guards_mint"})
        p = one_path(self, self.report, "route:mfa/unsafe/")
        c = checks_by(p, "jwt.decode")[0]
        self.assertEqual(c["relation"], "present_unproven")
        self.assertIn("verify_signature", c["detail"])
        self.assertEqual(p["evidence"]["status"], "check_present_relationship_unproven")

    def test_django_signing_loads_is_a_check(self):
        p = one_path(self, self.report, "route:mfa/signed/")
        self.assertEqual(p["evidence"]["factors"], {"signed_token_possession": "guards_mint"})

    def test_v1_catalog_skips_optional_overlay_entries_and_falls_back_to_unrecognized(self):
        rep = scan(VP, catalog=CATALOG_V1)
        self.assertIn("pyotp.totp.TOTP.verify", rep["tool"]["overlay_entries_skipped"])
        p = one_path(self, rep, "route:mfa/totp/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        # the factor names the symbol as resolved (`from pyotp import TOTP` -> the public re-export)
        self.assertEqual(p["evidence"]["factors"], {"unrecognized:pyotp.TOTP.verify": "guards_mint"})
        self.assertFalse(p["analysis_complete"])
        self.assertTrue(any("pyotp.TOTP.verify" in g for g in gaps_of(p)))


class UnrecognizedCheckTests(unittest.TestCase):
    """(b) verification-looking calls that are not catalog checks."""

    @classmethod
    def setUpClass(cls):
        cls.report = scan(VP)

    def test_unknown_library_verifier_in_form_clean_method(self):
        p = one_path(self, self.report, "route:mfa/recovery/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        self.assertEqual(p["evidence"]["factors"], {"unrecognized:acme_tokens.CodeBook.check_code": "guards_mint"})
        self.assertFalse(p["analysis_complete"])
        g = gaps_of(p)
        self.assertEqual(len(g), 1)
        self.assertIn("mfa.forms.RecoveryCodeForm.clean_code|acme_tokens.CodeBook.check_code", g[0])
        u = p["evidence"]["unrecognized_checks"][0]
        self.assertEqual((u["function"], u["call"]), ("mfa.forms.RecoveryCodeForm.clean_code", "self.book.check_code"))
        self.assertIn("mfa.forms.RecoveryCodeForm.clean_code", p["fingerprint"]["check_functions"])

    def test_gap_is_global_coverage_gap(self):
        types = self.report["coverage"]["gaps_by_type"]
        self.assertEqual(types.get("unrecognized_check_call"), 5)

    def test_unresolved_receiver_in_serializer_validate_method(self):
        p = one_path(self, self.report, "route:mfa/api/pin-token/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        self.assertEqual(p["evidence"]["factors"], {"unrecognized:?.verify_pin": "guards_mint"})
        # super().validate(attrs) inside validate() is delegation, not a check
        self.assertEqual([u["call"] for u in p["evidence"]["unrecognized_checks"]], ["PinPad.default().verify_pin"])

    def test_project_function_with_verification_name_but_no_check(self):
        p = one_path(self, self.report, "route:mfa/link/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        c = checks_by(p, "confirm_link")[0]
        self.assertEqual((c["via"], c["relation"]), ("unrecognized", "guards_mint"))
        self.assertIn("mfa.helpers.confirm_link", p["fingerprint"]["check_functions"])

    def test_call_in_try_with_exiting_handlers_is_treated_as_raising(self):
        p = one_path(self, self.report, "route:mfa/ledger/")
        self.assertEqual(p["evidence"]["factors"], {"unrecognized:acme_tokens.Ledger.verify_entry": "guards_mint"})

    def test_helper_whose_outcome_ignores_the_call_is_not_a_check(self):
        p = one_path(self, self.report, "route:mfa/audited/")
        self.assertEqual(p["evidence"]["status"], "no_check_found_in_analyzed_code")
        self.assertEqual(p["evidence"]["unrecognized_checks"], [])

    def test_wrapper_depth_limit(self):
        # chain function -> deep_mid -> deep_inner -> verify_blob: within the limit (2 wrapper levels)
        p = one_path(self, self.report, "route:mfa/mid/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        # one more level (deep_outer) is beyond the limit: documented miss
        p = one_path(self, self.report, "route:mfa/deep/")
        self.assertEqual(p["evidence"]["status"], "no_check_found_in_analyzed_code")

    def test_mint_wrapper_with_check_like_name_is_not_a_check(self):
        p = one_path(self, self.report, "route:mfa/wrapped/")
        self.assertEqual(p["evidence"]["unrecognized_checks"], [])
        self.assertTrue(p["analysis_complete"])

    def test_format_validator_from_catalog_non_check_list_is_ignored(self):
        p = one_path(self, self.report, "route:mfa/pin/")
        self.assertEqual(p["evidence"]["unrecognized_checks"], [])  # validate_slug in NicknameForm


class ValidationMethodFingerprintTests(unittest.TestCase):
    """P2 and implied edges for forms that are not recognised as checks."""

    @classmethod
    def setUpClass(cls):
        cls.report = scan(VP)

    def test_unrecognised_forms_get_implied_edges_and_are_fingerprinted(self):
        # `form` holds PinForm or NicknameForm (conflicting assignments); neither is a recognised check
        p = one_path(self, self.report, "route:mfa/pin/")
        self.assertEqual(p["evidence"]["status"], "no_check_found_in_analyzed_code")
        self.assertEqual(p["evidence"]["validation_methods"],
                         ["mfa.forms.NicknameForm.clean_nickname", "mfa.forms.PinForm.clean_pin"])
        self.assertTrue({"mfa.forms.NicknameForm.clean_nickname", "mfa.forms.PinForm.clean_pin"}
                        <= set(p["fingerprint"]["check_functions"]))

    def test_none_placeholder_does_not_hide_the_form_type(self):
        p = one_path(self, self.report, "route:mfa/totp/")  # `form = None` before `form = OneTimeCodeForm(...)`
        self.assertEqual(p["evidence"]["validation_methods"], ["mfa.forms.OneTimeCodeForm.clean_code"])


class MutationDetectionTests(unittest.TestCase):
    """The Healthchecks-style silent miss, reproduced on synthetic code."""

    def setUp(self):
        self.root = copy_fixture(self, "verify_project")

    def _lock(self, catalog=None):
        return accept_all(build_lock(scan(self.root, catalog=catalog)))

    def _path_id(self, report, prefix):
        return one_path(self, report, prefix)["id"]

    def test_recognised_clean_method_accepting_every_code_is_flagged(self):
        lock = self._lock()
        write(self.root, "mfa/forms.py", read(self.root, "mfa/forms.py").replace(
            "if not self.generator.verify(value, valid_window=1):",
            "if False and not self.generator.verify(value, valid_window=1):"))
        new = scan(self.root)
        findings, code = diff(lock, new)
        pid = self._path_id(new, "route:mfa/totp/")
        kinds = {f["kind"] for f in findings if f["path_id"] == pid}
        self.assertTrue({"fingerprint_changed", "evidence_downgraded"} <= kinds, findings)
        fc = [f for f in findings if f["path_id"] == pid and f["kind"] == "fingerprint_changed"][0]
        self.assertIn("checks", fc["components"])
        self.assertTrue(code & FINGERPRINT_CHANGED and code & EVIDENCE_DOWNGRADED)

    def test_unrecognised_clean_method_accepting_every_code_is_flagged(self):
        # catalog v1 does not know pyotp: the check is unrecognized, yet the change is still caught
        lock = self._lock(catalog=CATALOG_V1)
        write(self.root, "mfa/forms.py", read(self.root, "mfa/forms.py").replace(
            "if not self.generator.verify(value, valid_window=1):",
            "if False and not self.generator.verify(value, valid_window=1):"))
        findings, code = diff(lock, scan(self.root, catalog=CATALOG_V1))
        self.assertTrue(code & FINGERPRINT_CHANGED and code & EVIDENCE_DOWNGRADED, findings)
        msgs = " ".join(f["message"] for f in findings if f["kind"] == "evidence_downgraded")
        # clean_code no longer depends on the call, so it stops being a (provisional) check wrapper
        self.assertIn("unrecognized:pyotp.TOTP.verify: guards_mint -> absent", msgs)
        # the call itself is still on the path: the gap and the status stay
        p = one_path(self, scan(self.root, catalog=CATALOG_V1), "route:mfa/totp/")
        self.assertEqual(p["evidence"]["status"], "unrecognized_check_present")
        self.assertTrue(gaps_of(p))

    def test_change_in_unrecognised_plain_comparison_form_changes_checks_fingerprint(self):
        lock = self._lock()
        write(self.root, "mfa/forms.py", read(self.root, "mfa/forms.py").replace(
            'if self.cleaned_data["pin"] != self.expected:', 'if False and self.cleaned_data["pin"] != self.expected:'))
        new = scan(self.root)
        findings, code = diff(lock, new)
        pid = self._path_id(new, "route:mfa/pin/")
        fc = [f for f in findings if f["path_id"] == pid and f["kind"] == "fingerprint_changed"]
        self.assertEqual(len(fc), 1, findings)
        self.assertEqual(fc[0]["components"], ["checks"])
        self.assertEqual(code, FINGERPRINT_CHANGED)

    def test_new_unrecognised_verification_call_is_a_coverage_regression(self):
        lock = self._lock()
        write(self.root, "mfa/views.py", read(self.root, "mfa/views.py").replace(
            "def audited_step(request):\n    user = pending_user(request)\n",
            "def audited_step(request):\n    user = pending_user(request)\n"
            "    if not request.vault.verify_session_hint(user):\n        return HttpResponse(status=403)\n"))
        new = scan(self.root)
        findings, code = diff(lock, new)
        pid = self._path_id(new, "route:mfa/audited/")
        self.assertTrue(code & COVERAGE_REGRESSION and code & FINGERPRINT_CHANGED, findings)
        self.assertFalse(code & NEW_PATH)
        self.assertEqual(one_path(self, new, "route:mfa/audited/")["evidence"]["status"], "unrecognized_check_present")
        self.assertTrue(any(f["path_id"] == pid and f["kind"] == "coverage_regression" for f in findings))


if __name__ == "__main__":
    unittest.main()

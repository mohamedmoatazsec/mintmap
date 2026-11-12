"""Machine-readable overlay for the bundled catalog (src/mintmap/data/django_catalog.json).

The catalog's qualnames are human-readable ("X.login / alogin", "... (property)",
"allauth password-reset key generation").  This file maps them to concrete
import paths that the AST resolver can match.  Every entry carries `ref`, the
exact catalog qualname it derives from; catalog.py refuses to load an entry whose
ref is missing from the catalog, and reports every catalog entry that no overlay
entry references (so unmapped catalog knowledge is visible, not silently lost).

Purposes and factors are NOT invented here: purpose comes from the catalog entry.
The only exceptions are marked `purpose_override` and carry a `basis` string that
quotes the catalog semantics they rely on.  Entries marked `heuristic=True` are
not from the catalog at all and are reported as such.

Additional symbols that are not catalog qualnames themselves (public re-exports,
manager methods, instance aliases) were checked by reading the unpacked library
source of the versions listed in the catalog; the `verified` field cites file:line.
"""

# ---------------------------------------------------------------------------
# Mint APIs that application code calls directly.
#   symbol:   fully qualified name after import resolution
#   user_arg: (positional index, keyword name) of the principal argument, or None
#   returns:  qualname of the returned object's class (enables x = f(); x.attr)
# ---------------------------------------------------------------------------
MINT_CALLS = [
    dict(symbol="django.contrib.auth.login", ref="django.contrib.auth.login", user_arg=(1, "user")),
    dict(symbol="django.contrib.auth.alogin", ref="django.contrib.auth.alogin", user_arg=(1, "user")),
    dict(symbol="django.contrib.auth.update_session_auth_hash",
         ref="django.contrib.auth.update_session_auth_hash", user_arg=(1, "user")),
    dict(symbol="django.contrib.auth.aupdate_session_auth_hash",
         ref="django.contrib.auth.aupdate_session_auth_hash", user_arg=(1, "user")),
    dict(symbol="django.contrib.auth.forms.PasswordResetForm.save",
         ref="django.contrib.auth.forms.PasswordResetForm.save", user_arg=None),
    dict(symbol="django.contrib.auth.tokens.PasswordResetTokenGenerator.make_token",
         ref="django.contrib.auth.tokens.PasswordResetTokenGenerator.make_token", user_arg=(0, "user")),
    dict(symbol="rest_framework.authtoken.models.Token.save",
         ref="rest_framework.authtoken.models.Token.save / generate_key", user_arg=None),
    dict(symbol="rest_framework.authtoken.models.Token.generate_key",
         ref="rest_framework.authtoken.models.Token.save / generate_key", user_arg=None),
    dict(symbol="rest_framework.authtoken.models.Token.objects.create",
         ref="rest_framework.authtoken.models.Token.save / generate_key", user_arg=(None, "user"),
         verified="catalog semantics: 'any Token(...).save() / objects.create without a key generates'"),
    dict(symbol="rest_framework.authtoken.models.Token.objects.get_or_create",
         ref="rest_framework.authtoken.models.Token.save / generate_key", user_arg=(None, "user"),
         verified="get_or_create creates via save(); djoser utils.py:17 uses it"),
    dict(symbol="rest_framework_simplejwt.tokens.Token.for_user",
         ref="rest_framework_simplejwt.tokens.Token.for_user", user_arg=(0, "user"),
         returns="rest_framework_simplejwt.tokens.Token"),
    dict(symbol="rest_framework_simplejwt.tokens.RefreshToken.for_user",
         ref="rest_framework_simplejwt.tokens.BlacklistMixin.for_user", user_arg=(0, "user"),
         returns="rest_framework_simplejwt.tokens.RefreshToken",
         verified="tokens.py:376 class RefreshToken(BlacklistMixin, Token)"),
    dict(symbol="rest_framework_simplejwt.tokens.AccessToken.for_user",
         ref="rest_framework_simplejwt.tokens.Token.for_user", user_arg=(0, "user"),
         returns="rest_framework_simplejwt.tokens.AccessToken",
         purpose_override="jwt_access",
         basis="catalog Token.for_user semantics: 'purpose depends on the receiver class ... "
               "AccessToken.for_user -> access token (372)'"),
    dict(symbol="rest_framework_simplejwt.tokens.SlidingToken.for_user",
         ref="rest_framework_simplejwt.tokens.BlacklistMixin.for_user", user_arg=(0, "user"),
         returns="rest_framework_simplejwt.tokens.SlidingToken",
         purpose_override="jwt_access",
         basis="catalog Token.for_user semantics: 'SlidingToken.for_user -> sliding token (356)'; "
               "catalog lists sliding obtain view as jwt_access"),
    dict(symbol="knox.models.AuthTokenManager.create", ref="knox.models.AuthTokenManager.create",
         user_arg=(0, "user")),
    dict(symbol="knox.models.AuthToken.objects.create", ref="knox.models.AuthTokenManager.create",
         user_arg=(0, "user"), verified="knox/models.py:51 objects = AuthTokenManager(); :72 AuthToken"),
    dict(symbol="sesame.utils.get_query_string",
         ref="sesame.utils.get_query_string / get_parameters / get_token", user_arg=(0, "user")),
    dict(symbol="sesame.utils.get_parameters",
         ref="sesame.utils.get_query_string / get_parameters / get_token", user_arg=(0, "user")),
    dict(symbol="sesame.utils.get_token",
         ref="sesame.utils.get_query_string / get_parameters / get_token", user_arg=(0, "user")),
    dict(symbol="sesame.utils.get_user", ref="sesame.utils.get_user", user_arg=None),
    dict(symbol="social_core.actions.do_complete", ref="social_core.actions.do_complete", user_arg=None),
    dict(symbol="social_django.views._do_login", ref="social_django.views._do_login", user_arg=(1, "user")),
    dict(symbol="allauth.account.adapter.DefaultAccountAdapter.login",
         ref="allauth.account.adapter.DefaultAccountAdapter.login", user_arg=(1, "user")),
    dict(symbol="allauth.account.internal.flows.login.perform_login",
         ref="allauth.account.internal.flows.login.perform_login / resume_login", user_arg=(1, "login")),
    dict(symbol="allauth.account.internal.flows.login.resume_login",
         ref="allauth.account.internal.flows.login.perform_login / resume_login", user_arg=(1, "login")),
    dict(symbol="allauth.account.utils.perform_login",
         ref="allauth.account.internal.flows.login.perform_login / resume_login", user_arg=(1, "user"),
         verified="allauth/account/utils.py:77-94 public wrapper -> flows.login.perform_login"),
    dict(symbol="allauth.account.internal.flows.signup.complete_signup",
         ref="allauth.account.internal.flows.signup.complete_signup", user_arg=(1, "user")),
    dict(symbol="allauth.account.utils.complete_signup",
         ref="allauth.account.internal.flows.signup.complete_signup", user_arg=(1, "user"),
         verified="allauth/account/utils.py:97 public wrapper"),
    dict(symbol="allauth.account.internal.flows.password_reset.perform_password_reset_login",
         ref="allauth.account.internal.flows.password_reset.perform_password_reset_login", user_arg=(1, "user")),
    dict(symbol="allauth.account.internal.flows.email_verification.login_on_verification",
         ref="allauth.account.internal.flows.email_verification.login_on_verification", user_arg=None),
    dict(symbol="allauth.socialaccount.internal.flows.login._login",
         ref="allauth.socialaccount.internal.flows.login._login", user_arg=None),
    dict(symbol="allauth.mfa.webauthn.internal.flows.perform_passwordless_login",
         ref="allauth.mfa.webauthn.internal.flows.perform_passwordless_login", user_arg=None),
    dict(symbol="allauth.mfa.internal.flows.trust.trust_browser",
         ref="allauth.mfa.internal.flows.trust.trust_browser", user_arg=None),
    dict(symbol="allauth.account.internal.flows.login.record_authentication",
         ref="allauth.account.internal.flows.login.record_authentication", user_arg=None),
    dict(symbol="allauth.account.internal.flows.password_change.logout_on_password_change",
         ref="allauth.account.internal.flows.password_change.logout_on_password_change", user_arg=(1, "user")),
    dict(symbol="allauth.headless.internal.sessionkit.expose_session_token",
         ref="allauth.headless.internal.sessionkit.expose_session_token", user_arg=None),
    dict(symbol="django_otp.login", ref="django_otp.login", user_arg=None),
    dict(symbol="dj_rest_auth.utils.jwt_encode", ref="dj_rest_auth.utils.jwt_encode", user_arg=(0, "user")),
    dict(symbol="dj_rest_auth.mfa.utils.create_ephemeral_token",
         ref="dj_rest_auth.mfa.utils.create_ephemeral_token", user_arg=(0, "user")),
    dict(symbol="djoser.utils.login_user", ref="djoser.utils.login_user", user_arg=(1, "user")),
    # Heuristic, NOT from the catalog: generic signing/JWT primitives that projects use to
    # build custom tokens.  Purpose is 'unknown' by construction.
    dict(symbol="django.core.signing.dumps", ref=None, heuristic=True, user_arg=None),
    dict(symbol="django.core.signing.TimestampSigner.sign", ref=None, heuristic=True, user_arg=None),
    dict(symbol="django.core.signing.TimestampSigner.sign_object", ref=None, heuristic=True, user_arg=None),
    dict(symbol="django.core.signing.Signer.sign", ref=None, heuristic=True, user_arg=None),
    dict(symbol="django.core.signing.Signer.sign_object", ref=None, heuristic=True, user_arg=None),
    dict(symbol="jwt.encode", ref=None, heuristic=True, user_arg=None),
]

# Attribute reads that mint (properties).  Matched when the receiver variable's
# inferred type is `receiver`.
PROPERTY_MINTS = [
    dict(receiver="rest_framework_simplejwt.tokens.RefreshToken", attr="access_token",
         ref="rest_framework_simplejwt.tokens.RefreshToken.access_token (property)"),
]

# Library module-level instances: qualname -> class qualname.
LIBRARY_INSTANCES = {
    "django.contrib.auth.tokens.default_token_generator":
        "django.contrib.auth.tokens.PasswordResetTokenGenerator",  # tokens.py:132
}

# Return types of library functions (for chained calls such as get_adapter().login()).
LIBRARY_RETURNS = {
    "allauth.account.adapter.get_adapter": "allauth.account.adapter.DefaultAccountAdapter",
}

# Library class bases we need for method lookup / framework guards (read in source).
LIBRARY_BASES = {
    "rest_framework_simplejwt.tokens.RefreshToken": ["rest_framework_simplejwt.tokens.BlacklistMixin",
                                                     "rest_framework_simplejwt.tokens.Token"],
    "rest_framework_simplejwt.tokens.AccessToken": ["rest_framework_simplejwt.tokens.Token"],
    "rest_framework_simplejwt.tokens.SlidingToken": ["rest_framework_simplejwt.tokens.BlacklistMixin",
                                                     "rest_framework_simplejwt.tokens.Token"],
    "django_otp.forms.OTPAuthenticationForm": ["django_otp.forms.OTPAuthenticationFormMixin",
                                               "django.contrib.auth.forms.AuthenticationForm"],
    "django_otp.forms.OTPTokenForm": ["django_otp.forms.OTPAuthenticationFormMixin"],
    "two_factor.forms.AuthenticationTokenForm": ["django_otp.forms.OTPAuthenticationFormMixin"],
    "two_factor.forms.BackupTokenForm": ["two_factor.forms.AuthenticationTokenForm"],
    "django.contrib.admin.forms.AdminAuthenticationForm": ["django.contrib.auth.forms.AuthenticationForm"],
    "django.contrib.auth.views.LoginView": ["django.views.generic.edit.FormView"],
    "django.contrib.auth.views.PasswordChangeView": ["django.views.generic.edit.FormView"],
    "django.contrib.auth.views.PasswordResetView": ["django.views.generic.edit.FormView"],
    "django.contrib.auth.views.PasswordResetConfirmView": ["django.views.generic.edit.FormView"],
    "django.views.generic.FormView": ["django.views.generic.edit.FormView"],
    "django.views.generic.CreateView": ["django.views.generic.edit.CreateView"],
    "django.views.generic.UpdateView": ["django.views.generic.edit.UpdateView"],
    # catalog v2 verifier libraries: public re-exports / subclasses (treated as subclasses so that
    # method lookups expand to the catalog symbol)
    "pyotp.TOTP": ["pyotp.totp.TOTP"],                    # pyotp/__init__.py:10
    "pyotp.HOTP": ["pyotp.hotp.HOTP"],                    # pyotp/__init__.py:8
    "pyotp.contrib.steam.Steam": ["pyotp.totp.TOTP"],     # pyotp/contrib/steam.py:10
    "pyotp.contrib.Steam": ["pyotp.totp.TOTP"],
    "jwt.PyJWT": ["jwt.api_jwt.PyJWT"],                   # jwt/__init__.py:9
    "django.core.signing.TimestampSigner": ["django.core.signing.Signer"],  # signing.py:294
}

# Library classes whose `post` calls form_valid() only after form.is_valid()
# (django/views/generic/edit.py ProcessFormView.post, cited in the catalog's
# AuthenticationForm.clean entry: "Gate is control-dependent on ProcessFormView.post").
FORM_PROCESSING_VIEWS = {
    "django.views.generic.edit.FormView", "django.views.generic.edit.BaseFormView",
    "django.views.generic.edit.ProcessFormView", "django.views.generic.edit.CreateView",
    "django.views.generic.edit.UpdateView", "django.views.generic.edit.BaseCreateView",
    "django.views.generic.edit.BaseUpdateView",
}

# Default form classes of library form views (django/contrib/auth/views.py).
LIBRARY_VIEW_FORM_CLASS = {
    "django.contrib.auth.views.LoginView": "django.contrib.auth.forms.AuthenticationForm",
    "django.contrib.auth.views.PasswordChangeView": "django.contrib.auth.forms.PasswordChangeForm",
}

# ---------------------------------------------------------------------------
# Check APIs.
#   ret: 'bool' | 'subject_or_none' (truthy iff success) | 'raises' | 'tuple' (always truthy!)
#   subject: where the verified principal is: 'return', 'arg0', 'arg1', 'receiver', None
#   match: 'qualname' (default) or 'method_name' (receiver type unknown; lower confidence)
# ---------------------------------------------------------------------------
CHECK_CALLS = [
    dict(symbol="django.contrib.auth.authenticate", ref="django.contrib.auth.authenticate / aauthenticate",
         factor="backend_dispatch", ret="subject_or_none", subject="return"),
    dict(symbol="django.contrib.auth.aauthenticate", ref="django.contrib.auth.authenticate / aauthenticate",
         factor="backend_dispatch", ret="subject_or_none", subject="return"),
    dict(symbol="django.contrib.auth.backends.ModelBackend.authenticate",
         ref="django.contrib.auth.backends.ModelBackend.authenticate", factor="password",
         ret="subject_or_none", subject="return"),
    dict(symbol="django.contrib.auth.backends.RemoteUserBackend.authenticate",
         ref="django.contrib.auth.backends.RemoteUserBackend.authenticate", factor="remote_user_external",
         ret="subject_or_none", subject="return"),
    dict(symbol="django.contrib.auth.check_password_with_timing_attack_mitigation",
         ref="django.contrib.auth.check_password_with_timing_attack_mitigation", factor="password",
         ret="bool", subject="arg0"),
    dict(symbol="django.contrib.auth.acheck_password_with_timing_attack_mitigation",
         ref="django.contrib.auth.check_password_with_timing_attack_mitigation", factor="password",
         ret="bool", subject="arg0"),
    dict(symbol="check_password", match="method_name",
         ref="django.contrib.auth.base_user.AbstractBaseUser.check_password / acheck_password",
         factor="password", ret="bool", subject="receiver"),
    dict(symbol="acheck_password", match="method_name",
         ref="django.contrib.auth.base_user.AbstractBaseUser.check_password / acheck_password",
         factor="password", ret="bool", subject="receiver"),
    dict(symbol="django.contrib.auth.tokens.PasswordResetTokenGenerator.check_token",
         ref="django.contrib.auth.tokens.PasswordResetTokenGenerator.check_token",
         factor="reset_token_possession", ret="bool", subject="arg0"),
    dict(symbol="rest_framework_simplejwt.tokens.Token.verify",
         ref="rest_framework_simplejwt.tokens.Token.__init__ / verify / verify_token_type",
         factor="jwt_possession", ret="raises", subject=None),
    dict(symbol="rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token",
         ref="rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token / get_user",
         factor="jwt_possession", ret="raises", subject=None),
    dict(symbol="sesame.tokens_v2.parse_token",
         ref="sesame.backends.SesameBackendMixin.authenticate / sesame.tokens_v2.parse_token",
         factor="magic_link_possession", ret="subject_or_none", subject="return"),
    dict(symbol="social_core.utils.user_is_active", ref="social_core.utils.user_is_active",
         factor="account_state", ret="bool", subject="arg0"),
    dict(symbol="allauth.mfa.totp.internal.auth.TOTP.validate_code",
         ref="allauth.mfa.totp.internal.auth.TOTP.validate_code", factor="otp", ret="bool", subject=None),
    dict(symbol="allauth.mfa.recovery_codes.internal.auth.RecoveryCodes.validate_code",
         ref="allauth.mfa.recovery_codes.internal.auth.RecoveryCodes.validate_code",
         factor="recovery_code", ret="bool", subject=None),
    dict(symbol="allauth.mfa.webauthn.internal.auth.complete_authentication",
         ref="allauth.mfa.webauthn.internal.auth.complete_authentication", factor="webauthn",
         ret="raises", subject="arg0"),
    dict(symbol="allauth.headless.tokens.strategies.jwt.internal.validate_access_token",
         ref="allauth.headless.tokens.strategies.jwt.internal.validate_access_token / validate_refresh_token",
         factor="jwt_possession", ret="subject_or_none", subject="return"),
    dict(symbol="allauth.headless.tokens.strategies.jwt.internal.validate_refresh_token",
         ref="allauth.headless.tokens.strategies.jwt.internal.validate_access_token / validate_refresh_token",
         factor="jwt_possession", ret="subject_or_none", subject="return"),
    dict(symbol="django_otp.verify_token", ref="django_otp.verify_token", factor="otp",
         ret="subject_or_none", subject="arg0"),
    dict(symbol="django_otp.match_token", ref="django_otp.match_token", factor="otp",
         ret="subject_or_none", subject="arg0"),
    dict(symbol="verify_token", match="method_name",
         ref="django_otp.models.Device.verify_token (+ plugins)", factor="otp", ret="bool", subject=None),
    dict(symbol="verify_is_allowed", match="method_name",
         ref="django_otp.models.Device.verify_is_allowed / ThrottlingMixin.verify_is_allowed",
         factor="throttling", ret="tuple", subject=None),
    dict(symbol="is_verified", match="method_name",
         ref="django_otp.middleware.is_verified / OTPMiddleware._finalize_device",
         factor="session_mfa_state", ret="bool", subject="receiver"),
    dict(symbol="two_factor.views.utils.validate_remember_device_cookie",
         ref="two_factor.views.utils.validate_remember_device_cookie", factor="remembered_mfa_cookie",
         ret="bool", subject=None),
    dict(symbol="webauthn.verify_authentication_response", ref="webauthn.verify_authentication_response",
         factor="webauthn", ret="raises", subject=None),
    dict(symbol="mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token",
         ref="mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token", factor="idp_assertion",
         ret="raises", subject=None),
    dict(symbol="dj_rest_auth.mfa.totp.TOTP.validate_code", ref="dj_rest_auth.mfa.totp.TOTP.validate_code",
         factor="otp", ret="bool", subject="arg0"),
    dict(symbol="dj_rest_auth.mfa.utils.verify_ephemeral_token", ref="dj_rest_auth.mfa.utils.verify_ephemeral_token",
         factor="challenge_token_possession", ret="raises", subject="return"),
    dict(symbol="hijack.permissions.superusers_only",
         ref="hijack.permissions.superusers_only / superusers_and_staff (HIJACK_PERMISSION_CHECK)",
         factor="authorization", ret="bool", subject=None),
    dict(symbol="hijack.permissions.superusers_and_staff",
         ref="hijack.permissions.superusers_only / superusers_and_staff (HIJACK_PERMISSION_CHECK)",
         factor="authorization", ret="bool", subject=None),
    # ---- catalog v2 additions (optional=True: skipped, and listed in tool.overlay_entries_skipped, when the
    # catalog in use does not have the ref, e.g. when running with the v1 catalog) ----
    dict(symbol="pyotp.totp.TOTP.verify", ref="pyotp.totp.TOTP.verify", factor="otp", ret="bool", subject=None,
         optional=True, verified="pyotp/totp.py:68; re-export pyotp.TOTP via LIBRARY_BASES (pyotp/__init__.py:10)"),
    dict(symbol="pyotp.hotp.HOTP.verify", ref="pyotp.hotp.HOTP.verify", factor="otp", ret="bool", subject=None,
         optional=True, verified="pyotp/hotp.py:47; re-export pyotp.HOTP (pyotp/__init__.py:8)"),
    dict(symbol="fido2.server.Fido2Server.authenticate_complete",
         ref="fido2.server.Fido2Server.authenticate_complete", factor="webauthn", ret="raises", subject=None,
         optional=True, verified="fido2/server.py:324 (raises ValueError 347-376)"),
    *[dict(symbol=s, ref="jwt.api_jwt.PyJWT.decode / jwt.decode / decode_complete", factor="jwt_possession",
           ret="raises", subject="return", optional=True,
           # (v4) `pos`: positional index of the argument (decode(jwt, key, algorithms, options, verify, ...),
           # jwt/api_jwt.py:305-312); a value MintMap cannot evaluate makes the check unproven (see analysis)
           disabled_if=[dict(kw="options", key="verify_signature", value=False, pos=3),
                        dict(kw="verify", value=False, pos=4)],
           verified="jwt/api_jwt.py:305, module aliases 591-595, re-export jwt/__init__.py:9")
      for s in ("jwt.decode", "jwt.decode_complete", "jwt.api_jwt.decode", "jwt.api_jwt.decode_complete",
                "jwt.api_jwt.PyJWT.decode", "jwt.api_jwt.PyJWT.decode_complete", "jwt.PyJWT.decode",
                "jwt.PyJWT.decode_complete")],
    *[dict(symbol=s, ref="django.core.signing.loads / Signer.unsign / unsign_object / TimestampSigner.unsign",
           factor="signed_token_possession", ret="raises", subject="return", optional=True,
           verified="django/core/signing.py:195 loads, :246 Signer.unsign, :280 unsign_object, :302 TimestampSigner")
      for s in ("django.core.signing.loads", "django.core.signing.Signer.unsign",
                "django.core.signing.Signer.unsign_object", "django.core.signing.TimestampSigner.unsign")],
    dict(symbol="django.contrib.auth.hashers.check_password",
         ref="django.contrib.auth.hashers.check_password / acheck_password", factor="password", ret="bool",
         subject=None, optional=True, verified="django/contrib/auth/hashers.py:75"),
    dict(symbol="django.contrib.auth.hashers.acheck_password",
         ref="django.contrib.auth.hashers.check_password / acheck_password", factor="password", ret="bool",
         subject=None, optional=True, verified="django/contrib/auth/hashers.py:89"),
    dict(symbol="django.contrib.auth.hashers.verify_password", ref="django.contrib.auth.hashers.verify_password",
         factor="password", ret="tuple", subject=None, optional=True,
         verified="django/contrib/auth/hashers.py:39 returns (is_correct, must_update)"),
    dict(symbol="django_otp.oath.TOTP.verify", ref="django_otp.oath.TOTP.verify", factor="otp", ret="bool",
         subject=None, optional=True, verified="django_otp/oath.py:171"),
    dict(symbol="webauthn.authentication.verify_authentication_response.verify_authentication_response",
         ref="webauthn.verify_authentication_response", factor="webauthn", ret="raises", subject=None,
         verified="webauthn/__init__.py:6-8 re-exports this module-level function"),
]

# Library calls that look like verification by name but are NOT authentication checks
# (catalog v2 `non_check_apis`).  The "unrecognized check" heuristic skips them.
#   prefix: matched against the resolved library symbol
NON_CHECK_PREFIXES = [
    dict(prefix="django.core.validators.",
         ref="django.core.validators (validate_* callables, *Validator classes)", optional=True),
    dict(prefix="django.contrib.auth.password_validation.validate_password",
         ref="django.contrib.auth.password_validation.validate_password", optional=True),
    dict(prefix="fido2.server.Fido2Server.authenticate_begin",
         ref="fido2.server.Fido2Server.authenticate_begin / register_begin", optional=True),
    dict(prefix="fido2.server.Fido2Server.register_begin",
         ref="fido2.server.Fido2Server.authenticate_begin / register_begin", optional=True),
]

# Instantiating these classes with a token argument verifies it (raises on failure).
CHECK_CONSTRUCTORS = [
    dict(symbol=s, ref="rest_framework_simplejwt.tokens.Token.__init__ / verify / verify_token_type",
         factor="jwt_possession", ret="raises", subject=None)
    for s in ("rest_framework_simplejwt.tokens.RefreshToken", "rest_framework_simplejwt.tokens.AccessToken",
              "rest_framework_simplejwt.tokens.SlidingToken", "rest_framework_simplejwt.tokens.UntypedToken")
]

# Form / serializer classes whose validation (is_valid) performs a check.
# `method` is the method that implements the check (overriding it without super() loses it).
FORM_CHECKS = [
    dict(cls="django.contrib.auth.forms.AuthenticationForm", method="clean",
         ref="django.contrib.auth.forms.AuthenticationForm.clean (+ confirm_login_allowed)",
         factor="password", subject_via="get_user"),
    dict(cls="django.contrib.auth.forms.PasswordChangeForm", method="clean_old_password",
         ref="django.contrib.auth.forms.PasswordChangeForm.clean_old_password", factor="password_reentry",
         subject_via="user"),
    dict(cls="rest_framework.authtoken.serializers.AuthTokenSerializer", method="validate",
         ref="rest_framework.authtoken.serializers.AuthTokenSerializer.validate", factor="password",
         subject_via="validated_data"),
    dict(cls="rest_framework_simplejwt.serializers.TokenObtainSerializer", method="validate",
         ref="rest_framework_simplejwt.serializers.TokenObtainSerializer.validate", factor="password",
         subject_via="validated_data"),
    dict(cls="allauth.mfa.base.forms.BaseAuthenticateForm", method="clean_code",
         ref="allauth.mfa.base.forms.BaseAuthenticateForm.clean_code", factor="otp_or_recovery_code",
         subject_via="user"),
    dict(cls="allauth.account.forms.BaseConfirmCodeForm", method="clean_code",
         ref="allauth.account.forms.BaseConfirmCodeForm.clean_code", factor="one_time_code",
         subject_via="user"),
    dict(cls="django_otp.forms.OTPAuthenticationFormMixin", method="clean_otp",
         ref="django_otp.forms.OTPAuthenticationFormMixin.clean_otp / _chosen_device / _verify_token",
         factor="otp", subject_via="user"),
    dict(cls="two_factor.forms.AuthenticationTokenForm", method="clean",
         ref="two_factor.forms.AuthenticationTokenForm.clean", factor="otp", subject_via="user"),
    dict(cls="dj_rest_auth.mfa.serializers.MFAVerifySerializer", method="validate",
         ref="dj_rest_auth.mfa.serializers.MFAVerifySerializer.validate",
         factor="challenge_token_possession+otp_or_recovery_code", subject_via="validated_data"),
    dict(cls="dj_rest_auth.serializers.LoginSerializer", method="validate",
         ref="dj_rest_auth.serializers.LoginSerializer.validate", factor="password", subject_via="validated_data"),
    dict(cls="djoser.serializers.TokenCreateSerializer", method="validate",
         ref="djoser.serializers.TokenCreateSerializer.validate", factor="password", subject_via="user"),
]

# View decorators that mint (catalog: sesame.decorators.authenticate [full_session]).
MINT_DECORATORS = {"sesame.decorators.authenticate": ["sesame.decorators.authenticate"]}

# Route-level decorators that gate resource access (not the mint itself).
VIEW_GATE_DECORATORS = {
    "django_otp.decorators.otp_required":
        "django_otp.decorators.otp_required / django_otp.admin.OTPAdminSite.has_permission",
}

# ---------------------------------------------------------------------------
# Library-provided mint entry points.
# ---------------------------------------------------------------------------
# Library views routed directly or subclassed by project code.
#   mint_methods: methods that perform the mint (overriding them without super()
#                 means the library mint may not happen -> reported).
#   requires_attr: (attr, value) that must hold for the mint to happen.
LIBRARY_VIEWS = [
    dict(symbol="django.contrib.auth.views.LoginView", refs=["django.contrib.auth.views.LoginView"],
         mint_methods=["form_valid"]),
    dict(symbol="django.contrib.auth.views.PasswordResetConfirmView",
         refs=["django.contrib.auth.views.PasswordResetConfirmView.form_valid (post_reset_login=True)"],
         mint_methods=["form_valid"], requires_attr=("post_reset_login", True)),
    dict(symbol="django.contrib.auth.views.PasswordChangeView",
         refs=["django.contrib.auth.views.PasswordChangeView.form_valid"], mint_methods=["form_valid"]),
    dict(symbol="django.contrib.auth.views.PasswordResetView",
         refs=["django.contrib.auth.forms.PasswordResetForm.save"], mint_methods=["form_valid"],
         verified="django/contrib/auth/views.py:231 form_valid -> form.save()"),
    dict(symbol="rest_framework.authtoken.views.ObtainAuthToken",
         refs=["rest_framework.authtoken.views.ObtainAuthToken.post"], mint_methods=["post"]),
    dict(symbol="rest_framework.authtoken.views.obtain_auth_token",
         refs=["rest_framework.authtoken.views.ObtainAuthToken.post"], mint_methods=[], function_alias=True),
    dict(symbol="rest_framework_simplejwt.views.TokenObtainPairView",
         refs=["rest_framework_simplejwt.views.TokenObtainPairView"], mint_methods=["post"]),
    dict(symbol="rest_framework_simplejwt.views.TokenRefreshView",
         refs=["rest_framework_simplejwt.views.TokenRefreshView"], mint_methods=["post"]),
    dict(symbol="rest_framework_simplejwt.views.TokenObtainSlidingView",
         refs=["rest_framework_simplejwt.views.TokenObtainSlidingView / TokenObtainSlidingSerializer.validate"],
         mint_methods=["post"]),
    dict(symbol="rest_framework_simplejwt.views.TokenRefreshSlidingView",
         refs=["rest_framework_simplejwt.views.TokenRefreshSlidingView / TokenRefreshSlidingSerializer.validate"],
         mint_methods=["post"]),
    dict(symbol="knox.views.LoginView", refs=["knox.views.LoginView.post"], mint_methods=["post"]),
    dict(symbol="sesame.views.LoginView", refs=["sesame.views.LoginView.get"], mint_methods=["get"]),
    dict(symbol="social_django.views.complete", refs=["social_django.views.complete"], mint_methods=[],
         function_alias=True),
    dict(symbol="allauth.account.views.LoginView",
         refs=["allauth.account.internal.flows.login.perform_login / resume_login",
               "allauth.account.stages.LoginStageController.handle + internal.stagekit.stash_login"],
         mint_methods=["form_valid"]),
    dict(symbol="allauth.account.views.login",
         refs=["allauth.account.internal.flows.login.perform_login / resume_login",
               "allauth.account.stages.LoginStageController.handle + internal.stagekit.stash_login"],
         mint_methods=[], function_alias=True, verified="allauth/account/views.py:133"),
    dict(symbol="allauth.account.views.SignupView",
         refs=["allauth.account.internal.flows.signup.complete_signup"], mint_methods=["form_valid"]),
    dict(symbol="allauth.account.views.signup",
         refs=["allauth.account.internal.flows.signup.complete_signup"], mint_methods=[], function_alias=True),
    dict(symbol="allauth.account.views.ConfirmEmailView",
         refs=["allauth.account.internal.flows.email_verification.login_on_verification"], mint_methods=["post"]),
    dict(symbol="allauth.account.views.PasswordResetView", refs=["allauth password-reset key generation"],
         mint_methods=["form_valid"]),
    dict(symbol="allauth.account.views.PasswordResetFromKeyView",
         refs=["allauth.account.internal.flows.password_reset.perform_password_reset_login"],
         mint_methods=["form_valid"]),
    dict(symbol="allauth.account.views.ConfirmLoginCodeView",
         refs=["allauth.account.internal.flows.login_by_code.LoginCodeVerificationProcess.finish"],
         mint_methods=["form_valid"]),
    dict(symbol="allauth.mfa.base.views.AuthenticateView",
         refs=["allauth.mfa.base.views.AuthenticateView.form_valid"], mint_methods=["form_valid"]),
    dict(symbol="allauth.mfa.base.views.TrustView", refs=["allauth.mfa.internal.flows.trust.trust_browser"],
         mint_methods=["form_valid"]),
    dict(symbol="allauth.headless.account.views.LoginView",
         refs=["allauth.headless.account.views.LoginView.post"], mint_methods=["post"]),
    dict(symbol="django_otp.views.LoginView", refs=["django_otp.views.LoginView"], mint_methods=["form_valid"]),
    dict(symbol="two_factor.views.core.LoginView",
         refs=["two_factor.views.core.LoginView.done",
               "two_factor.views.utils.LoginStorage.authenticated_user (setter)"], mint_methods=["done"]),
    dict(symbol="two_factor.views.LoginView",
         refs=["two_factor.views.core.LoginView.done",
               "two_factor.views.utils.LoginStorage.authenticated_user (setter)"], mint_methods=["done"],
         verified="two_factor/views/__init__.py:1-2 re-export"),
    dict(symbol="hijack.views.AcquireUserView", refs=["hijack.views.AcquireUserView.post"], mint_methods=["post"]),
    dict(symbol="hijack.views.ReleaseUserView", refs=["hijack.views.ReleaseUserView.post"], mint_methods=["post"]),
    dict(symbol="oauth2_provider.views.AuthorizationView",
         refs=["oauth2_provider.views.base.AuthorizationView"], mint_methods=["post", "get"]),
    dict(symbol="oauth2_provider.views.base.AuthorizationView",
         refs=["oauth2_provider.views.base.AuthorizationView"], mint_methods=["post", "get"]),
    dict(symbol="oauth2_provider.views.TokenView", refs=["oauth2_provider.views.base.TokenView.post"],
         mint_methods=["post"]),
    dict(symbol="oauth2_provider.views.base.TokenView", refs=["oauth2_provider.views.base.TokenView.post"],
         mint_methods=["post"]),
    dict(symbol="mozilla_django_oidc.views.OIDCAuthenticationCallbackView",
         refs=["mozilla_django_oidc.views.OIDCAuthenticationCallbackView.get"], mint_methods=["get"]),
    dict(symbol="dj_rest_auth.views.LoginView", refs=["dj_rest_auth.views.LoginView.login"],
         mint_methods=["login", "post"]),
    dict(symbol="dj_rest_auth.registration.views.RegisterView",
         refs=["dj_rest_auth.registration.views.RegisterView.perform_create"], mint_methods=["perform_create"]),
    dict(symbol="dj_rest_auth.registration.views.SocialLoginView",
         refs=["dj_rest_auth.registration.views.SocialLoginView.process_login (+ SocialLoginSerializer.validate)"],
         mint_methods=["process_login", "login", "post"]),
    dict(symbol="dj_rest_auth.mfa.views.MFALoginView", refs=["dj_rest_auth.mfa.views.MFALoginView.login"],
         mint_methods=["login", "post"]),
    dict(symbol="dj_rest_auth.mfa.views.MFAVerifyView", refs=["dj_rest_auth.mfa.views.MFAVerifyView.post"],
         mint_methods=["post"]),
    dict(symbol="djoser.views.TokenCreateView", refs=["djoser.views.TokenCreateView"], mint_methods=["_action"]),
    dict(symbol="djoser.webauthn.views.LoginView", refs=["djoser.webauthn.views.LoginView.post"],
         mint_methods=["post"]),
]

# Library URL modules passed to include().  Paths are settings-dependent inside
# several libraries (allauth MFA_ENABLED, dj-rest-auth USE_JWT ...); MintMap does
# not evaluate those conditions and lists every catalog mint the module can expose.
LIBRARY_INCLUDES = {
    "django.contrib.auth.urls": ["django.contrib.auth.urls (urlpatterns)",
                                 "django.contrib.auth.views.PasswordChangeView.form_valid",
                                 "django.contrib.auth.forms.PasswordResetForm.save"],
    "rest_framework.urls": ["rest_framework.urls (browsable API login)"],
    "allauth.urls": ["allauth.account.internal.flows.login.perform_login / resume_login",
                     "allauth.account.stages.LoginStageController.handle + internal.stagekit.stash_login",
                     "allauth.mfa.stages.AuthenticateStage.handle",
                     "allauth.mfa.base.views.AuthenticateView.form_valid",
                     "allauth.account.internal.flows.login_by_code.LoginCodeVerificationProcess.finish",
                     "allauth.account.internal.flows.password_reset.perform_password_reset_login",
                     "allauth password-reset key generation",
                     "allauth.account.internal.flows.signup.complete_signup",
                     "allauth.account.internal.flows.email_verification.login_on_verification",
                     "allauth.socialaccount.internal.flows.login._login",
                     "allauth.mfa.webauthn.internal.flows.perform_passwordless_login",
                     "allauth.mfa.internal.flows.trust.trust_browser",
                     "allauth.account.internal.flows.password_change.logout_on_password_change"],
    "allauth.account.urls": ["allauth.account.internal.flows.login.perform_login / resume_login",
                             "allauth.account.stages.LoginStageController.handle + internal.stagekit.stash_login",
                             "allauth.account.internal.flows.login_by_code.LoginCodeVerificationProcess.finish",
                             "allauth.account.internal.flows.password_reset.perform_password_reset_login",
                             "allauth password-reset key generation",
                             "allauth.account.internal.flows.signup.complete_signup",
                             "allauth.account.internal.flows.email_verification.login_on_verification",
                             "allauth.account.internal.flows.password_change.logout_on_password_change"],
    "allauth.mfa.urls": ["allauth.mfa.base.views.AuthenticateView.form_valid",
                         "allauth.mfa.internal.flows.trust.trust_browser"],
    "allauth.socialaccount.urls": ["allauth.socialaccount.internal.flows.login._login"],
    "allauth.headless.urls": ["allauth.headless.account.views.LoginView.post",
                              "allauth.headless.mfa.views.AuthenticateView / LoginWebAuthnView",
                              "allauth.headless.tokens.strategies.jwt.strategy.JWTTokenStrategy.create_access_token / create_access_token_payload",
                              "allauth.headless.tokens.strategies.jwt.strategy.JWTTokenStrategy.refresh_token",
                              "allauth.headless.internal.sessionkit.expose_session_token"],
    "allauth.idp.urls": ["allauth.idp.oidc OAuth/OIDC provider (AuthorizationView, TokenView, save_bearer_token)"],
    "social_django.urls": ["social_django.views.complete"],
    "two_factor.urls": ["two_factor.views.core.LoginView.done",
                        "two_factor.views.utils.LoginStorage.authenticated_user (setter)",
                        "two_factor.views.core.SetupView.done",
                        "two_factor remember-device cookie (get_remember_device_cookie + set_cookie in done)"],
    "hijack.urls": ["hijack.views.AcquireUserView.post", "hijack.views.ReleaseUserView.post"],
    "oauth2_provider.urls": ["oauth2_provider.views.base.AuthorizationView", "oauth2_provider.views.base.TokenView.post"],
    "mozilla_django_oidc.urls": ["mozilla_django_oidc.views.OIDCAuthenticationCallbackView.get"],
    "knox.urls": ["knox.views.LoginView.post"],
    "dj_rest_auth.urls": ["dj_rest_auth.views.LoginView.login",
                          "dj_rest_auth.serializers.PasswordChangeSerializer.save (update_session_auth_hash)",
                          "dj_rest_auth.jwt_auth.get_refresh_view (RefreshViewWithCookieSupport)"],
    "dj_rest_auth.registration.urls": ["dj_rest_auth.registration.views.RegisterView.perform_create"],
    "dj_rest_auth.mfa.urls": ["dj_rest_auth.mfa.views.MFALoginView.login", "dj_rest_auth.mfa.views.MFAVerifyView.post"],
    "djoser.urls": ["djoser.views.UserViewSet.set_password (update_session_auth_hash)",
                    "djoser.email (activation / password-reset / username-reset tokens)"],
    "djoser.urls.base": ["djoser.views.UserViewSet.set_password (update_session_auth_hash)",
                         "djoser.email (activation / password-reset / username-reset tokens)"],
    "djoser.urls.authtoken": ["djoser.views.TokenCreateView"],
    "djoser.urls.jwt": ["djoser.urls.jwt (jwt/create, jwt/refresh)"],
    "djoser.webauthn.urls": ["djoser.webauthn.views.LoginView.post"],
    "djoser.social.urls": ["djoser.social ProviderAuthSerializer.create / TokenStrategy.obtain"],
}

# `path('admin/', admin.site.urls)` -- library-provided admin login.
ADMIN_SITE_URLS = {
    "django.contrib.admin.site.urls": ["django.contrib.admin.sites.AdminSite.login",
                                       "django.contrib.auth.admin.UserAdmin.user_change_password"],
}

# Middleware that mints or rotates credentials on requests (catalog implicit flows (1)).
LIBRARY_MIDDLEWARE = {
    "django.contrib.auth.middleware.RemoteUserMiddleware": ["django.contrib.auth.middleware.RemoteUserMiddleware"],
    "django.contrib.auth.middleware.PersistentRemoteUserMiddleware":
        ["django.contrib.auth.middleware.PersistentRemoteUserMiddleware"],
    "django.contrib.auth.middleware.AuthenticationMiddleware":
        ["django.contrib.auth.get_user (SECRET_KEY_FALLBACKS re-hash branch)"],
    "sesame.middleware.AuthenticationMiddleware": ["sesame.middleware.AuthenticationMiddleware"],
    "oauth2_provider.middleware.OAuth2TokenMiddleware": ["oauth2_provider.middleware.OAuth2TokenMiddleware"],
    "mozilla_django_oidc.middleware.SessionRefresh": ["mozilla_django_oidc.middleware.SessionRefresh"],
}

# Top-level import names of the packages the catalog covers.  A library view or
# include from one of these packages that is not listed above is treated as
# "covered by the catalog, no mint"; anything else is reported as a gap.
CATALOG_PACKAGES = {
    "django", "rest_framework", "rest_framework_simplejwt", "allauth", "django_otp", "two_factor",
    "formtools", "knox", "sesame", "social_django", "social_core", "dj_rest_auth", "djoser", "hijack",
    "oauth2_provider", "mozilla_django_oidc", "guardian", "webauthn",
    "channels",     # (v5 review) channels.auth.login (catalog v3 library_mint_calls)
}

# Settings that change what library flows check or mint (catalog implicit flows (4)).
# Global settings feed every path's fingerprint; prefixed settings feed paths whose
# mint/check APIs come from the matching package.
GLOBAL_AUTH_SETTINGS = ["MIDDLEWARE", "AUTHENTICATION_BACKENDS", "REST_FRAMEWORK", "AUTH_USER_MODEL",
                        "SESSION_ENGINE", "SECRET_KEY_FALLBACKS"]
PACKAGE_SETTING_PREFIXES = {
    "django": ["LOGIN_", "PASSWORD_RESET_TIMEOUT", "PASSWORD_HASHERS"],
    "rest_framework": ["REST_FRAMEWORK"],
    "rest_framework_simplejwt": ["SIMPLE_JWT"],
    "allauth": ["ACCOUNT_", "MFA_", "SOCIALACCOUNT_", "HEADLESS_", "IDP_", "DEBUG"],
    "django_otp": ["OTP_"],
    "two_factor": ["TWO_FACTOR_"],
    "knox": ["REST_KNOX"],
    "sesame": ["SESAME_"],
    "social_django": ["SOCIAL_AUTH_"],
    "social_core": ["SOCIAL_AUTH_"],
    "dj_rest_auth": ["REST_AUTH", "JWT_AUTH_"],
    "djoser": ["DJOSER"],
    "hijack": ["HIJACK_"],
    "oauth2_provider": ["OAUTH2_PROVIDER"],
    "mozilla_django_oidc": ["OIDC_"],
}

# Library base classes that do NOT define these methods (so a project CBV that
# derives only from them has no library `post` that would dispatch form hooks).
_VERBS = {"get", "post", "put", "patch", "delete", "create", "update", "partial_update", "destroy",
          "list", "retrieve"}
LIBRARY_CLASS_LACKS = {
    "django.views.View": _VERBS, "django.views.generic.View": _VERBS, "django.views.generic.base.View": _VERBS,
    "rest_framework.views.APIView": _VERBS, "rest_framework.generics.GenericAPIView": _VERBS,
    "rest_framework.viewsets.ViewSet": _VERBS, "rest_framework.viewsets.GenericViewSet": _VERBS,
    "rest_framework.viewsets.ViewSetMixin": _VERBS,
    "django.views.generic.TemplateView": _VERBS - {"get"},
    "django.views.generic.base.TemplateView": _VERBS - {"get"},
    "object": _VERBS,
    "builtins.object": _VERBS,
}

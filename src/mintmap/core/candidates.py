"""(v6) Candidate tier: lower-confidence mint sites, reported so that new shapes are at least VISIBLE.

The confirmed tiers (catalog APIs, library flows, the R3 custom-credential heuristic, hand-rolled session logins whose
key is read back as a principal) are precise but, on code MintMap was not developed against, about a third of the real
credential paths were outside all of them and nothing pointed at them.  A *candidate* is a site that has a general,
structural reason to be reviewed, without enough evidence to be called a mint:

  session_state      a project function writes state into a session (or into a SessionStore it creates) that looks
                     like login / MFA / step-up / impersonation / cross-domain hand-off state: it re-keys the session
                     (`cycle_key()` / `flush()` / `rotate_token()`) while writing an identifier, a hash or an auth-named
                     key; it copies a session key (or a value read from another session) into a session; it creates a
                     new SessionStore whose key it hands out; it writes an identifier, a hash, a timestamp or a flag
                     under a key named after authentication state; or it creates a record bound to the session key.
  password_set       a password is set from a value that is not generated (`x.set_password(v)`, `make_password(v)`
                     stored in a `password` field): sign-up, password change, an administrator choosing a password.
  auth_library_call  project code hands the HTTP request to a function of an authentication package that the catalog
                     does not describe (a library flow called directly).
  minting_subclass   a project subclass of a catalogued minting middleware or view that MintMap did not see
                     registered or routed (MIDDLEWARE computed at run time, a view built dynamically).
  request_authenticator  (v6, second part) project code that authenticates a request from a credential it reads:
                     the `authenticate` / `authenticate_credentials` method of a project DRF authentication class,
                     or a function that assigns `request.user = ...` itself.  A request-scoped login: weakening it
                     lets requests in, but no confirmed path has to contain it.

Candidates are traced to entry points like any mint, fingerprinted and diffed, but they are kept apart from the
confirmed paths: one review entry per candidate SITE (whatever the number of entry points reaching it, all listed),
grouped by kind in the lock (`candidates:<kind>`), each with a rank (high / medium) and the reason.  Writes that match
none of the rules are counted in `coverage.candidates.set_aside` (not reviewed, not fingerprinted).
"""
from __future__ import annotations

import ast
import re

from .catalog import MintAPI
from .credentials import words, _leaf

CANDIDATE_KIND = "candidate"
GROUPS = {
    "session_state": "session state that may log someone in, keep MFA / step-up / impersonation state, or hand a "
                     "session to another site",
    "password_set": "a password set from a value that is not generated (user- or administrator-chosen)",
    "auth_library_call": "the HTTP request handed to an authentication-package function the catalog does not describe",
    "minting_subclass": "a project subclass of a catalogued minting middleware / view that MintMap did not see "
                        "registered or routed",
    "request_authenticator": "project code that authenticates a request from a credential it reads (a DRF "
                             "authentication class, `request.user = ...`): a request-scoped login",
    "startup_only": "a mint site that only start-up, deploy or command-line code reaches (AppConfig.ready(), "
                    "settings / import-time calls, management commands, migration defaults): not a request path",
}
PURPOSES = {"session_state": "candidate_session_state", "password_set": "candidate_password_set",
            "auth_library_call": "candidate_library_auth_flow", "minting_subclass": "candidate_minting_subclass",
            "request_authenticator": "candidate_request_authentication", "startup_only": "candidate_startup_only"}
RANK_ORDER = {"high": 0, "medium": 1, "low": 2}

# words of a session key that name authentication state (identifier parts, lower case)
AUTH_STATE_WORDS = {
    "auth", "authenticated", "authentication", "login", "logged", "signin", "user", "customer", "account", "member",
    "principal", "identity", "verified", "verification", "mfa", "2fa", "otp", "totp", "factor", "impersonate",
    "impersonation", "impersonator", "impersonated", "hijack", "hijacker", "hijacked", "sudo", "staff", "elevated",
    "elevation", "reauth", "reauthenticate", "reauthenticated", "reauthentication", "access", "token", "permission",
    "grant", "granted", "trusted", "trust", "device", "password", "reset", "invite", "invitation", "recovery",
    "superuser", "admin"}
# (v6c) principal nouns: alone (`user_prefers_dark`, `account_tab_open`) they do not make a key authentication state;
# they count with an identifier / hash / signed value whose key ends in a principal noun (`member_id`, `user_pk`)
PRINCIPAL_KEY_WORDS = {"user", "customer", "account", "member", "principal", "identity", "staff", "admin",
                       "superuser", "device"}
# words of a session key that mark ordinary UI / flow state (they veto the medium rule)
NOT_AUTH_STATE_WORDS = {
    "cart", "basket", "language", "lang", "locale", "theme", "message", "messages", "redirect", "next", "url", "return",
    "captcha", "csrf", "nonce", "state", "search", "filter", "sort", "page", "form", "wizard", "draft", "preview",
    "tmp", "temp", "cache", "notification", "notifications", "banner", "tour", "consent", "cookie", "attempts",
    "count", "counter", "agent", "country", "ip", "geo", "timezone", "tz", "expiry", "expires", "age", "scope",
    "last", "seen", "activity", "visit", "visited",
    # one-shot UI notices ("show the 'password changed' banner")
    "enabled", "disabled", "changed", "show", "shown", "display", "success", "notice", "notify", "flash", "toast",
    # (v6c) UI preferences, hints and onboarding
    "prefers", "preference", "preferences", "tab", "tabs", "sidebar", "collapsed", "compact", "layout",
    "dismissed", "closed", "opened", "tip", "tips", "hint", "help", "onboarding"}
# words of a model name that mark a log / file / cache record rather than an elevation bound to the session
NOT_BOUND_RECORD_WORDS = {"audit", "log", "logs", "history", "file", "files", "cached", "cache", "export", "download",
                          "upload", "report", "event", "events", "notification"}
REKEY_LEAVES = {"cycle_key", "flush", "acycle_key", "aflush"}
SIGNING_LEAVES = {"sign", "sign_object", "dumps", "encode"}
TIME_LEAVES = {"time", "now", "timestamp", "monotonic", "utcnow", "time_ns"}
# request-taking library functions that only read or build objects (accessors, predicates, loaders)
ACCESSOR_PREFIXES = ("get_", "is_", "has_", "load_", "build_", "reverse", "render", "format_", "can_", "should_",
                     "did_", "was_", "_")
# packages whose purpose is authentication (catalogued); Django and DRF are described function by function instead
AUTH_PACKAGES = {"allauth", "django_otp", "two_factor", "knox", "sesame", "social_django", "social_core",
                 "dj_rest_auth", "djoser", "hijack", "oauth2_provider", "mozilla_django_oidc",
                 "rest_framework_simplejwt"}


def candidate_api(group: str, symbol: str, basis: str) -> MintAPI:
    return MintAPI(symbol=symbol, ref=None, purpose=PURPOSES[group], purpose_basis=basis, kind=CANDIDATE_KIND,
                   heuristic=True, source_location=None)


def _key_words(kexpr, pats) -> set:
    ws = set()
    for p in pats:
        if p != "?":
            ws |= words(p.replace("{}", " "))
    for n in ast.walk(kexpr):
        if isinstance(n, ast.Name):
            ws |= words(n.id)
        elif isinstance(n, ast.Attribute):
            ws |= words(n.attr)
    return ws - {"session", "key", "keys", "self", "request"}


class CandidateFinder:
    def __init__(self, analysis):
        self.a = analysis
        self.p = analysis.p
        self.cred = analysis.cred
        self.set_aside: list = []
        self._memo: dict = {}
        self._seen_aside: set = set()

    # ------------------------------------------------------------------ per function
    def function_sites(self, fq) -> list:
        """[(pseudo call site, MintAPI, note, candidate info)] for one project function (memoised)."""
        if fq in self._memo:
            return self._memo[fq]
        out = []
        if fq in self.p.functions:
            info = self.p.functions[fq]
            seen = self.cred.mentions(info)
            if seen & {"session", "SessionStore", "session_key"}:
                out += self._session_state(info)
            if seen & {"set_password", "aset_password", "make_password", "amake_password"}:
                out += self._password_set(info)
            out += self._request_authenticator(info, seen)
        self._memo[fq] = out
        return out

    DRF_AUTH_METHODS = ("authenticate", "authenticate_credentials")
    NOT_A_USER = {"AnonymousUser", "None"}

    CREDENTIAL_CHECK_LEAVES = {"authenticate", "aauthenticate", "check_password", "acheck_password",
                               "get_authorization_header", "verify_token", "check_token"}
    REQUEST_INPUTS = {"META", "headers", "GET", "POST", "COOKIES", "query_params", "data"}
    CREDENTIAL_LOOKUP_WORDS = {"token", "key", "apikey", "secret", "password", "digest"}
    CREDENTIAL_INPUT_WORDS = {"authorization", "token", "key", "apikey", "secret", "password", "auth", "remote",
                              "bearer", "signature"}

    def _reads_credential(self, info) -> bool:
        """(v6) The function verifies a credential (authenticate(), check_password(), a token check, a lookup by a
        credential-named field) or reads one from the request (`request.META["HTTP_AUTHORIZATION"]`,
        `request.headers.get("X-Api-Key")`, a `token` query parameter)."""
        def key_words(e):
            return words(e.value) if isinstance(e, ast.Constant) and isinstance(e.value, str) else set()

        def is_input(e):
            return isinstance(e, ast.Attribute) and e.attr in self.REQUEST_INPUTS

        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Call):
                if _leaf(n.func) in self.CREDENTIAL_CHECK_LEAVES:
                    return True
                if any(k.arg and words(k.arg.replace("__", "_")) & self.CREDENTIAL_LOOKUP_WORDS for k in n.keywords):
                    return True     # a lookup by a credential (`User.objects.get(auth_token__key=code)`)
                if isinstance(n.func, ast.Attribute) and n.func.attr == "get" and is_input(n.func.value) and \
                        n.args and key_words(n.args[0]) & self.CREDENTIAL_INPUT_WORDS:
                    return True
            elif isinstance(n, ast.Subscript) and is_input(n.value) and \
                    key_words(n.slice) & self.CREDENTIAL_INPUT_WORDS:
                return True
        return False

    def _is_drf_auth_class(self, cls) -> bool:
        cat = self.a.catalog
        return any(c.startswith("rest_framework.authentication.") or c in cat.library_drf_auth or
                   c in cat.drf_auth_no_mint for c in self.p.mro(cls))

    AUTH_LIBRARY_EXCLUDED = ("django.contrib.auth.backends.",)

    def _is_other_auth_class(self, cls) -> bool:
        """(v6c) A project class with an `authenticate(self, request, ...)` method and a LIBRARY base other than a
        Django authentication backend: the authentication class of a framework the catalog does not describe
        (django-ninja `APIKeyHeader` / `HttpBearer`, a GraphQL or RPC framework's auth hook).  Classes named in
        AUTHENTICATION_BACKENDS are backends (their checks are part of authenticate()'s evidence)."""
        backends = set(self.a.settings.str_list("AUTHENTICATION_BACKENDS"))
        if cls in {self.a.resolve_dotted(b) for b in backends}:
            return False
        libs = [c for c in self.p.mro(cls)[1:] if c not in self.p.classes and c not in ("object", "builtins.object")]
        return bool(libs) and not any(c.startswith(self.AUTH_LIBRARY_EXCLUDED) for c in libs)

    def _request_authenticator(self, info, seen) -> list:
        """(v6) A request-scoped login in project code: a DRF authentication method that returns something (the
        (user, auth) pair), or an assignment `request.user = <user>` (not AnonymousUser / None).
        (v6c) Also the `authenticate(self, request, ...)` method of a project class deriving from another
        framework's authentication base (django-ninja), and `scope["user"] = ...` (an ASGI / Channels middleware).
        A `request.user` / `scope["user"]` assignment no longer needs a visible credential read: trusting a header
        or a parameter with no check is the riskiest form (rank high); one after a credential read or check is
        medium."""
        leaf = info.qualname.rsplit(".", 1)[-1]
        hit, text, signal, rank = None, "", "", "medium"
        params = info.params[1:] if info.cls and info.params[:1] == ["self"] else info.params
        if info.cls and leaf in self.DRF_AUTH_METHODS and self._is_drf_auth_class(info.cls):
            signal = "drf_authentication"
        elif info.cls and leaf == "authenticate" and params[:1] == ["request"] and \
                self._is_other_auth_class(info.cls):
            signal = "authentication_class"
        if signal:
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Return) and n.value is not None and not (
                        isinstance(n.value, ast.Constant) and n.value.value is None):
                    hit, text = n, f"{info.cls.rsplit('.', 1)[-1]}.{leaf}() returns {_short_src(n.value)}"
                    break
        elif ("user" in seen and "request" in seen) or "scope" in seen:
            for n in self.p.walk_function_body(info.node):
                if not isinstance(n, ast.Assign):
                    continue
                for t in n.targets:
                    is_req = isinstance(t, ast.Attribute) and t.attr in ("user", "_cached_user", "_force_auth_user") \
                        and _is_request(t.value)
                    is_scope = isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and \
                        t.slice.value == "user" and ((isinstance(t.value, ast.Name) and t.value.id == "scope") or
                                                     (isinstance(t.value, ast.Attribute) and t.value.attr == "scope"))
                    if not (is_req or is_scope):
                        continue
                    v = n.value
                    names = {x.id for x in ast.walk(v) if isinstance(x, ast.Name)} | \
                            {x.attr for x in ast.walk(v) if isinstance(x, ast.Attribute)}
                    if (isinstance(v, ast.Constant) and v.value is None) or names & self.NOT_A_USER or \
                            any("anonymous" in x.lower() for x in names) or \
                            (isinstance(v, ast.Attribute) and _is_request(v.value)):
                        continue      # logs out, or copies a request's own user
                    hit, text = n, f"{_short_src(t)} = {_short_src(v)}"
                    signal = "scope_user_assignment" if is_scope else "request_user_assignment"
                    rank = "medium" if self._reads_credential(info) else "high"
                    break
                if hit is not None:
                    break
        if hit is None:
            return []
        for site in self.a.cg.sites(info.qualname):
            if self.a.mint_of(site, self.a.cg.resolve(site, info.cls)):
                return []     # a confirmed mint (login() ...) in the same function: that path covers it
        reason = f"authenticates the request itself: {text}"
        if rank == "high":
            reason += " (no credential read or check in this function: the user may come from an untrusted value)"
        site = _pseudo_site(info.qualname, hit, text, "request_authenticator")
        api = candidate_api("request_authenticator", f"request_authenticator[{info.qualname.rsplit('.', 2)[-2]}."
                            f"{leaf}]" if info.cls else f"request_authenticator[{leaf}]",
                            "candidate: " + GROUPS["request_authenticator"])
        return [(site, api, reason, dict(group="request_authenticator", rank=rank, reason=reason,
                                          signals=[signal], keys=[text]))]

    def _value_signals(self, v, info, local, depth=0) -> set:
        sig = set()
        if v is None or depth > 2:
            return sig
        for n in ast.walk(v):
            if isinstance(n, ast.Attribute):
                if n.attr == "session_key":
                    # the key of a session (`request.session.session_key`, `store.session_key`), not an attribute
                    # that merely has that name (`self.session_key` of a view)
                    if self.cred.is_session_expr(n.value, info) or (isinstance(n.value, ast.Call) and
                                                                     _leaf(n.value.func) == "SessionStore"):
                        sig.add("session_key")
                elif n.attr in ("pk", "id") or n.attr.endswith(("_id", "_pk")):
                    sig.add("principal")
            elif isinstance(n, ast.Call):
                leaf = _leaf(n.func).lower()
                if isinstance(n.func, ast.Attribute) and n.func.attr in ("get", "pop", "load") and \
                        self._is_other_store(n.func.value, info, local):
                    sig.add("session_value")
                elif "hash" in leaf or "hmac" in leaf:
                    sig.add("auth_hash")
                elif leaf in SIGNING_LEAVES:
                    sig.add("signed")       # a signed value kept in the session (`sudo = signer.sign("active")`)
                elif leaf in TIME_LEAVES:
                    sig.add("timestamp")
            elif isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load) and \
                    self._is_other_store(n.value, info, local):
                sig.add("session_value")
            elif isinstance(n, ast.Constant) and n.value is True:
                sig.add("flag")
            elif isinstance(n, ast.Name) and n.id in local and depth < 2:
                for src in local[n.id]:
                    sig |= self._value_signals(src, info, local, depth + 1)
        return sig

    def _is_other_store(self, e, info, local) -> bool:
        """A SessionStore object (`s = SessionStore(key)`), or a dict loaded from one (`data = s.load()`): a value
        read from it comes from ANOTHER session than the request's."""
        _sess, stores = self.cred.session_aliases(info)
        if isinstance(e, ast.Name):
            if e.id in stores:
                return True
            for src in local.get(e.id, []):
                if isinstance(src, ast.Call) and isinstance(src.func, ast.Attribute) and src.func.attr == "load" and \
                        isinstance(src.func.value, ast.Name) and src.func.value.id in stores:
                    return True
        return isinstance(e, ast.Call) and _leaf(e.func) == "SessionStore"

    def _session_state(self, info) -> list:
        if self.cred.session_login_stores(info.qualname):
            # a confirmed hand-rolled login in this function: its other session writes are part of that path
            return []
        writes = self.cred.session_writes(info)
        creates = self._session_bound_creates(info)
        if not writes and not creates:
            return []
        body = list(self.p.walk_function_body(info.node))
        local: dict = {}
        for n in body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        local.setdefault(t.id, []).append(n.value)
        rekey = any(isinstance(n, ast.Call) and (
            (isinstance(n.func, ast.Attribute) and n.func.attr in REKEY_LEAVES and
             self.cred.is_session_expr(n.func.value, info)) or _leaf(n.func) == "rotate_token") for n in body)
        fresh = set()
        for n in body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and \
                    isinstance(n.value, ast.Call) and _leaf(n.value.func) == "SessionStore" and \
                    not n.value.args and not n.value.keywords:
                fresh.add(n.targets[0].id)
        escaping = {x for x in fresh if any(
            (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and
             n.func.value.id == x and n.func.attr in ("save", "create", "asave", "acreate")) or
            (isinstance(n, ast.Attribute) and n.attr == "session_key" and isinstance(n.value, ast.Name) and
             n.value.id == x) for n in body)}
        hits = []      # (rank, statement, key text, signals)
        # (v6c) a session write after the function verified a secret (a password re-check, a PIN, a code) is
        # authentication state whatever the key is called (`sudo_expires`, `reauth_last`, `twofa_seen`)
        after_check = self.cred.verifies_secret(info.qualname) and not any(
            self.a.mint_of(s, self.a.cg.resolve(s, info.cls)) for s in self.a.cg.sites(info.qualname))
        for st, kexpr, vexpr in writes:
            pats = self.cred.key_patterns(kexpr, info)
            kws = _key_words(kexpr, pats)
            neg = kws & NOT_AUTH_STATE_WORDS
            state = kws & (AUTH_STATE_WORDS - PRINCIPAL_KEY_WORDS)
            heads = {w for p in pats if p != "?" for w in [_head_word(p)] if w}
            principal_key = bool(kws & PRINCIPAL_KEY_WORDS) and bool(heads & PRINCIPAL_KEY_WORDS)
            auth = state or (kws & PRINCIPAL_KEY_WORDS if principal_key else set())
            vsig = self._value_signals(vexpr, info, local)
            tgt = st.targets[0] if isinstance(st, ast.Assign) else getattr(st, "target", None)
            to_fresh = isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name) and tgt.value.id in escaping
            signals = sorted(vsig | ({"rekey"} if rekey else set()) | ({"new_store_handed_out"} if to_fresh else set())
                             | ({"auth_named_key"} if auth else set()))
            ktext = "|".join(sorted(p for p in pats if p != "?")) or _short_src(kexpr)
            if to_fresh and vsig & {"session_key", "session_value", "principal"}:
                rank = "high"
            elif vsig & {"session_key", "session_value"}:
                rank = "high"
            elif rekey and (vsig & {"principal", "auth_hash"} or auth):
                rank = "high"
            elif state and not neg and vsig & {"principal", "auth_hash", "timestamp", "flag", "signed"}:
                rank = "medium"
            elif principal_key and not neg and vsig & {"principal", "auth_hash", "signed"}:
                rank = "medium"
            elif after_check and vsig & {"principal", "auth_hash", "timestamp", "flag", "signed"}:
                rank = "medium"
                signals = sorted(set(signals) | {"after_secret_check"})
            else:
                key = (info.qualname, st.lineno)
                if key not in self._seen_aside:
                    self._seen_aside.add(key)
                    self.set_aside.append(dict(function=info.qualname, line=st.lineno, key=ktext,
                                               signals=signals, negative_words=sorted(neg)))
                continue
            hits.append((rank, st, ktext, signals))
        for st, model in creates:
            hits.append(("medium", st, f"{model} record with session_key", ["session_key", "bound_record"]))
        if not hits:
            return []
        hits.sort(key=lambda h: (RANK_ORDER[h[0]], h[1].lineno))
        rank, st, _k, _s = hits[0]
        keys = []
        for _r, _st, k, _sg in sorted(hits, key=lambda h: h[1].lineno):
            if k not in keys:
                keys.append(k)
        sigs = sorted({x for h in hits for x in h[3]})
        reason = (f"writes {', '.join(repr(k) for k in keys[:6])}{' ...' if len(keys) > 6 else ''} "
                  f"(signals: {', '.join(sigs)})")
        site = _pseudo_site(info.qualname, st, f"session state: {keys[0]}", "session_state")
        api = candidate_api("session_state", f"session_state[{keys[0]}]", "candidate: " + GROUPS["session_state"])
        return [(site, api, reason, dict(group="session_state", rank=rank, reason=reason, signals=sigs,
                                          keys=keys))]

    def _session_bound_creates(self, info) -> list:
        """`M.objects.create(..., session_key=request.session.session_key)`: a record bound to the session."""
        out = []
        for n in self.p.walk_function_body(info.node):
            if not isinstance(n, ast.Call):
                continue
            if not any(isinstance(x, ast.Attribute) and x.attr == "session_key" and
                       self.cred.is_session_expr(x.value, info) for k in n.keywords for x in ast.walk(k.value)):
                continue
            model, _how = self.cred._creation_model(n, info, info.cls)
            if model and not model.startswith(("param:", "related:")):
                mw = words(model.rsplit(".", 1)[-1])
                if mw & AUTH_STATE_WORDS and not mw & NOT_BOUND_RECORD_WORDS:
                    out.append((n, model.rsplit(".", 1)[-1]))
        return out

    def _password_set(self, info) -> list:
        hits = []
        for n in self.p.walk_function_body(info.node):
            if not isinstance(n, ast.Call):
                continue
            leaf = _leaf(n.func)
            if leaf in ("set_password", "aset_password") and isinstance(n.func, ast.Attribute) and n.args:
                arg = n.args[0]
                if isinstance(arg, ast.Constant) and arg.value is None:
                    continue    # same as set_unusable_password
                if self.cred_source(arg, info):
                    continue    # a generated value: the R3 heuristic decides
                if isinstance(n.func.value, ast.Call):
                    continue    # `Model().set_password(x)`: a throw-away instance (timing equaliser), never saved
                if self._own_principal(n.func.value, info):
                    continue    # the signed-in principal changes its own password (a re-key, not an issuance)
                hits.append((n, f"{_short_src(n.func.value)}.set_password({_short_src(arg)})"))
            elif leaf in ("make_password", "amake_password") and n.args and not self.cred_source(n.args[0], info):
                # only when the hash is stored in a password field of a creation / save
                parent_kw = self._kw_of(info, n)
                if parent_kw and "password" in words(parent_kw):
                    hits.append((n, f"{parent_kw}=make_password({_short_src(n.args[0])})"))
        if not hits:
            return []
        n, text = hits[0]
        reason = "sets a password from a value it does not generate: " + "; ".join(t for _n, t in hits[:4])
        site = _pseudo_site(info.qualname, n, text, "password_set")
        api = candidate_api("password_set", f"password_set[{_leaf(n.func)}]", "candidate: " + GROUPS["password_set"])
        return [(site, api, reason, dict(group="password_set", rank="medium", reason=reason, signals=[],
                                          keys=[t for _n, t in hits]))]

    def _uncatalogued_auth_call(self, site, res, lib) -> list:
        from .analysis import STDLIB_TOP
        from . import overlay
        top = lib.split(".")[0]
        if top in overlay.CATALOG_PACKAGES or top in STDLIB_TOP or self.p.is_project(lib) or res.via == "super":
            return []
        if res.receiver_type and res.receiver_type in self.p.classes:
            return []
        parts = lib.split(".")
        leaf = parts[-1]
        ws = set().union(*(words(x) for x in parts))
        for part in parts:
            seq = [w.lower() for w in _WORD_SPLIT.split(part) if w]
            if any((a, b) in (("sign", "in"), ("log", "in"), ("log", "on"), ("sign", "on"))
                   for a, b in zip(seq, seq[1:])):
                ws = ws | {"login"}       # `sign_in_as`, `log_in`
        if not ws & AUTH_LIB_WORDS or ws & CONSUMER_LIB_WORDS or leaf[:1].isupper():
            return []
        call = site.node
        args = list(call.args) + [k.value for k in call.keywords]
        info = self.p.functions.get(site.func)
        if info is None:
            return []
        if any(_is_request(a) for a in args):
            why = "receives the HTTP request"
        elif words(leaf) & CREDENTIAL_NOUNS and any(_user_like(a, info, self.p) for a in args):
            why = "receives a user and names a credential"
        else:
            return []
        if leaf.startswith(ACCESSOR_PREFIXES) and not words(leaf) & CREDENTIAL_NOUNS:
            return []
        reason = (f"calls {lib}() of a package the catalog does not cover; the name says it authenticates or issues "
                  f"a credential and it {why}")
        api = candidate_api("auth_library_call", lib, "candidate: " + GROUPS["auth_library_call"])
        return [(api, reason, dict(group="auth_library_call", rank="medium", reason=reason,
                                    signals=["uncatalogued_package"], keys=[lib]))]

    def _own_principal(self, recv, info) -> bool:
        """`request.user`, `self.request.user` or a local assigned from `request.<x>` / `self.request.<x>`."""
        def from_request(e):
            while isinstance(e, ast.Attribute):
                if isinstance(e.value, ast.Name) and e.value.id == "request":
                    return True
                if isinstance(e.value, ast.Attribute) and e.value.attr == "request":
                    return True
                e = e.value
            return False
        if from_request(recv):
            return True
        if isinstance(recv, ast.Name):
            srcs = [n.value for n in self.p.walk_function_body(info.node) if isinstance(n, ast.Assign)
                    and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == recv.id]
            return bool(srcs) and all(from_request(v) for v in srcs)
        return False

    def unrouted_allowed(self, fq, cinfo) -> bool:
        """Candidates no entry point reaches are reported only where the framework (not a route) runs the code:
        session state (middleware helpers, context processors, signal receivers) and form / serializer methods
        that set a password (clean / save / create / update / validate).  A password set in a manager method or a
        request-taking library call with no route are command-line / internal code."""
        if cinfo["group"] == "session_state":
            return True
        if cinfo["group"] == "request_authenticator":
            # (v6) DRF runs authentication classes named by views / settings in library code; a `request.user =`
            # nothing routes to is a task, a command or a test helper building a request.  (v6c) Likewise for
            # another framework's authentication class and an ASGI middleware setting scope["user"] (run by the
            # ASGI application, which MintMap does not route)
            return cinfo["signals"][:1] in (["drf_authentication"], ["authentication_class"],
                                            ["scope_user_assignment"])
        if cinfo["group"] == "auth_library_call":
            # (v6c) a package the catalog does not cover may route the code itself (a GraphQL mutation, an RPC
            # handler): visible even when MintMap found no route
            return cinfo["signals"] == ["uncatalogued_package"]
        if cinfo["group"] == "password_set":
            info = self.p.functions.get(fq)
            leaf = fq.rsplit(".", 1)[-1]
            return bool(info and info.cls and leaf.startswith(("clean", "save", "create", "update", "validate")) and
                        any(c.startswith(("django.forms", "rest_framework.serializers"))
                            for c in self.p.mro(info.cls)))
        return False

    def cred_source(self, e, info) -> bool:
        for x in ast.walk(e):
            if isinstance(x, ast.Call):
                q = self.cred._resolve_static(info.module, x.func, info)
                if q in ("django.contrib.auth.models.BaseUserManager.make_random_password",) or \
                        (q or "").split(".")[0] in ("secrets", "uuid") or _leaf(x.func) in (
                        "get_random_string", "token_urlsafe", "token_hex", "make_random_password"):
                    return True
        return False

    def _kw_of(self, info, call):
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Call):
                for k in n.keywords:
                    if k.value is call and k.arg:
                        return k.arg
        return None

    # ------------------------------------------------------------------ call sites
    def call_candidate(self, site, res) -> list:
        """A call that hands the HTTP request to an uncatalogued function of an authentication package.  (v6c) Also
        a function of a package the catalog does not cover at all whose dotted name says it authenticates
        (`loginas.utils.login_as(user, request)`, `graphql_jwt.shortcuts.get_token(user)`): it receives the
        request or a user."""
        lib = res.library or ""
        if lib and isinstance(site.node, ast.Call) and lib.split(".")[0] not in AUTH_PACKAGES:
            return self._uncatalogued_auth_call(site, res, lib)
        if not lib or lib.split(".")[0] not in AUTH_PACKAGES or not isinstance(site.node, ast.Call):
            return []
        if res.receiver_type and res.receiver_type in self.p.classes:
            return []
        if res.via == "super":
            return []      # the library base of a project subclass: covered by that class's own analysis
        leaf = lib.rsplit(".", 1)[-1]
        if leaf.startswith(ACCESSOR_PREFIXES) or leaf[:1].isupper() or ".signals." in f".{lib}." or \
                leaf in ("send", "send_robust", "connect") or any(f".{x}." in f".{lib}." for x in (
                    "settings", "app_settings", "conf")):
            return []      # an accessor / predicate / loader, a class (instantiation), a signal, a settings object
        cat = self.a.catalog
        if lib in cat.mint_calls or lib in cat.check_calls or lib in cat.library_views or cat.view_no_mint(lib) or \
                lib in getattr(cat, "non_check_calls", {}):
            return []
        call = site.node
        if not any(_is_request(a) for a in list(call.args) + [k.value for k in call.keywords]):
            return []
        reason = f"passes the HTTP request to {lib}(), which the catalog does not describe"
        api = candidate_api("auth_library_call", lib, "candidate: " + GROUPS["auth_library_call"])
        return [(api, reason, dict(group="auth_library_call", rank="medium", reason=reason, signals=["request_arg"],
                                    keys=[lib]))]


_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
# (v6c) words of a library function's dotted name that say it authenticates or issues a credential
AUTH_LIB_WORDS = {"auth", "login", "loginas", "signin", "token", "tokens", "jwt", "session", "sso", "saml",
                  "saml2", "oidc", "oauth", "oauth2", "otp", "totp", "mfa", "2fa", "impersonate", "impersonation",
                  "hijack", "credential", "credentials", "password", "passwordless", "magic", "apikey", "sesame"}
# ... and words that say it only reads, checks or ends one (consumers are not mints)
CONSUMER_LIB_WORDS = {"logout", "revoke", "delete", "verify", "check", "validate", "decode", "is", "has",
                      "require", "required", "decorator", "decorators", "exempt", "middleware", "settings",
                      "conf", "signals", "exceptions", "errors", "utils_test", "testing", "tests"}
CREDENTIAL_NOUNS = {"token", "tokens", "jwt", "key", "secret", "otp", "password", "session", "credential",
                    "ticket"}
USER_SOURCE_LEAVES = {"authenticate", "aauthenticate", "get_user", "aget_user", "create_user", "acreate_user",
                      "create_superuser", "get_user_model"}


def _user_like(e, info, p) -> bool:
    """(v6c) An argument that is a user: `request.user` / `info.context.user`, a name that says so (`user`,
    `target_user`, `member`), or a local assigned from authenticate() / get_user() / create_user() /
    get_object_or_404(<user model>, ...)."""
    if isinstance(e, ast.Attribute) and e.attr == "user":
        return True
    if isinstance(e, ast.Name):
        if words(e.id) & {"user", "member", "account", "customer", "principal"}:
            return True
        for n in p.walk_function_body(info.node):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == e.id for t in n.targets):
                for x in ast.walk(n.value):
                    if isinstance(x, ast.Call) and _leaf(x.func) in USER_SOURCE_LEAVES:
                        return True
    return False


def _head_word(pattern: str) -> str:
    """(v6c) The head noun of a session key pattern: its last word, skipping identifier suffixes (`member_id` ->
    member, `auth_user_pk` -> user)."""
    ws = [w.lower() for w in _WORD_SPLIT.split(pattern.replace("{}", " ")) if w]
    while ws and ws[-1] in ("id", "pk", "ids", "uuid", "key"):
        ws.pop()
    return ws[-1] if ws else ""


def _is_request(e) -> bool:
    return (isinstance(e, ast.Name) and e.id == "request") or (isinstance(e, ast.Attribute) and e.attr == "request")


def _short_src(e) -> str:
    from .fingerprint import stable_unparse
    try:
        s = stable_unparse(e)
    except Exception:  # pragma: no cover - defensive
        s = type(e).__name__
    return s if len(s) <= 80 else s[:77] + "..."


def _pseudo_site(func, node, text, leaf):
    from .callgraph import CallSite
    return CallSite(func=func, node=node, line=node.lineno, text=text, leaf=leaf)

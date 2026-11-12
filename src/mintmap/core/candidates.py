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

Candidates are traced to entry points like any mint, fingerprinted and diffed, but they are kept apart from the
confirmed paths: one review entry per candidate SITE (whatever the number of entry points reaching it, all listed),
grouped by kind in the lock (`candidates:<kind>`), each with a rank (high / medium) and the reason.  Writes that match
none of the rules are counted in `coverage.candidates.set_aside` (not reviewed, not fingerprinted).
"""
from __future__ import annotations

import ast

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
}
PURPOSES = {"session_state": "candidate_session_state", "password_set": "candidate_password_set",
            "auth_library_call": "candidate_library_auth_flow", "minting_subclass": "candidate_minting_subclass"}
RANK_ORDER = {"high": 0, "medium": 1}

# words of a session key that name authentication state (identifier parts, lower case)
AUTH_STATE_WORDS = {
    "auth", "authenticated", "authentication", "login", "logged", "signin", "user", "customer", "account", "member",
    "principal", "identity", "verified", "verification", "mfa", "2fa", "otp", "totp", "factor", "impersonate",
    "impersonation", "impersonator", "impersonated", "hijack", "hijacker", "hijacked", "sudo", "staff", "elevated",
    "elevation", "reauth", "reauthenticate", "reauthenticated", "reauthentication", "access", "token", "permission",
    "grant", "granted", "trusted", "trust", "device", "password", "reset", "invite", "invitation", "recovery",
    "superuser", "admin"}
# words of a session key that mark ordinary UI / flow state (they veto the medium rule)
NOT_AUTH_STATE_WORDS = {
    "cart", "basket", "language", "lang", "locale", "theme", "message", "messages", "redirect", "next", "url", "return",
    "captcha", "csrf", "nonce", "state", "search", "filter", "sort", "page", "form", "wizard", "draft", "preview",
    "tmp", "temp", "cache", "notification", "notifications", "banner", "tour", "consent", "cookie", "attempts",
    "count", "counter", "agent", "country", "ip", "geo", "timezone", "tz", "expiry", "expires", "age", "scope",
    "last", "seen", "activity", "visit", "visited",
    # one-shot UI notices ("show the 'password changed' banner")
    "enabled", "disabled", "changed", "show", "shown", "display", "success", "notice", "notify", "flash", "toast"}
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
        self._memo[fq] = out
        return out

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
        for st, kexpr, vexpr in writes:
            pats = self.cred.key_patterns(kexpr, info)
            kws = _key_words(kexpr, pats)
            auth = kws & AUTH_STATE_WORDS
            neg = kws & NOT_AUTH_STATE_WORDS
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
            elif auth and not neg and vsig & {"principal", "auth_hash", "timestamp", "flag", "signed"}:
                rank = "medium"
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
        """A call that hands the HTTP request to an uncatalogued function of an authentication package."""
        lib = res.library or ""
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

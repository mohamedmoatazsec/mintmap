"""(v5 part B, R3) Heuristic custom credential mints: project code that creates a credential WITHOUT a catalog mint API.

A value is a *credential candidate* when it comes from a randomness source that is commonly used to make secrets
(`secrets.token_hex/token_urlsafe/token_bytes/choice/randbelow/randbits`, `secrets.SystemRandom`, `uuid.uuid4`,
`os.urandom`, `django.utils.crypto.get_random_string`; anything computed from them: `binascii.hexlify(...)`,
`str(...)`, `"".join(...)`, `.hex`, f-strings, digests) and it reaches a place where a credential is kept:

(i)   stored: an attribute of a project model instance (`self.key = ...` in a model method, `obj.token = ...` on a
      typed model), a keyword of a model creation (`M.objects.create/get_or_create/update_or_create(...)`, `M(...)`,
      `serializer.save(field=...)`, `defaults={...}`), a cache / session store (`cache.set(k, v)`,
      `redis.set/setex/hset(...)`, `request.session[k] = v`), or a credential-named callable
      (`user.set_password(v)`, `store_token(v)`);
(ii)  a model field `default=` (a generator callable, a lambda, or a project function returning such a value):
      every project creation of that model (constructor, manager create, ModelSerializer / ModelForm save, the
      DRF create flow of a view whose serializer is a ModelSerializer of that model) is a candidate mint;
(iii) returned from a function whose name indicates a credential (token, key, secret, code, otp, pin, password,
      api_key ...).

Values flow through local variables (flow-insensitive, every assignment counts) and through project functions
that return them (`self.generate()`), never through attributes, containers or parameters.

Non-credential randomness is filtered by GENERAL name rules on the place the value is kept (the field /
attribute / keyword / cache-key / dict-key / function name): it must contain a credential word (`POSITIVE`) and
must not contain a word that marks an identifier, a file, a cache key, a CSRF nonce or an outbound/webhook
secret (`NEGATIVE`).  Context names (the local variables that hold the value, the generator functions, the model
class) can supply the credential word but never veto.  What passes is reported as a mint path with
`mint.kind = heuristic_custom_credential` and a `custom_*_candidate` purpose; reviewers decide.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .catalog import MintAPI
from .fingerprint import stable_unparse

SOURCES = {
    "secrets.token_hex", "secrets.token_urlsafe", "secrets.token_bytes", "secrets.choice", "secrets.randbelow",
    "secrets.randbits", "secrets.SystemRandom", "uuid.uuid4", "os.urandom",
    "django.utils.crypto.get_random_string", "random.SystemRandom",
    # (v5 review) the non-cryptographic PRNG is also used to make codes (a credential made with it is still a
    # credential, and a weak one), and library token generators that are not catalog mints
    "random.choice", "random.choices", "random.randint", "random.randrange", "random.random", "random.sample",
    "random.getrandbits", "random.randbytes", "oauthlib.common.generate_token", "oauthlib.common.generate_client_id",
}
CREATE_METHODS = {"create", "get_or_create", "update_or_create", "bulk_create", "acreate", "aget_or_create",
                  "aupdate_or_create"}
MANAGER_ATTRS = {"objects", "_default_manager", "_base_manager"}
STORE_METHODS = {"set", "setex", "psetex", "set_many", "hset", "hmset", "hsetnx", "mset", "add", "setnx"}
MODEL_BASES = {"django.db.models.Model", "django.db.models.base.Model", "django.contrib.auth.models.AbstractUser",
               "django.contrib.auth.models.AbstractBaseUser", "django.contrib.auth.base_user.AbstractBaseUser",
               "django.contrib.auth.models.PermissionsMixin", "django.contrib.auth.models.User"}

# credential words (identifier parts, lower case).  STRONG words count wherever they occur (the place the value is
# kept, the variables that hold it, the generator functions, the model); WEAK words (also common in identifiers:
# `country_code`, `cache_key`, `session_id`) count only in the name of the place the value is kept, and never for
# a function's return value
STRONG = {"token", "tokens", "secret", "secrets", "otp", "totp", "hotp", "password", "passwd", "pwd", "passcode",
          "passphrase", "apikey", "credential", "credentials", "magic", "invite", "invitation", "reset",
          "verification", "recovery", "sesame", "bearer",
          # (v5 review) standard names of e-mail confirmation / account activation secrets
          "activation", "confirmation"}
WEAK = {"key", "keys", "code", "codes", "pin", "session"}
POSITIVE = STRONG | WEAK
# (v6b) words that say what a value IS (nouns); the other strong words (`reset`, `verification`, `recovery`,
# `magic`, `activation`, `confirmation`) qualify a credential but do not name one: a callable named only by them
# (`reset(v)`) is not a place where a credential is kept
CALL_NOUNS = POSITIVE - {"reset", "verification", "recovery", "magic", "activation", "confirmation"}
# (v6b) callables that consume / compare a value rather than keep it
CONSUMER_VERBS = {"check", "verify", "validate", "compare", "is", "has", "match", "matches", "test", "confirm"}
# a weak word next to one of these is strong: `session_key`, `api_key`, `login_code`, `auth_key`, `device_pin`
QUALIFIERS = {"session", "api", "auth", "access", "login", "signin", "signup", "account", "device", "backup"}
# sources that are mostly identifier generators: a value from them needs a strong credential word
IDENTIFIER_SOURCES = {"uuid.uuid4"}
# owner names (model class, class of an attribute) that mark an outbound integration secret (it signs calls the
# application makes, it does not let anyone log in): such values are set aside
NEGATIVE_OWNER = {"webhook", "webhooks", "hook", "hooks", "callback", "outbound", "integration"}
# words that mark a non-credential use of randomness at the place the value is kept
NEGATIVE = {"id", "ids", "uuid", "guid", "pk", "slug", "name", "filename", "file", "files", "path", "dir", "folder",
            "url", "uri", "label", "title", "color", "colour", "cache", "idempotency", "trace", "correlation",
            "etag", "version", "checksum", "sort", "order", "index", "upload", "tmp", "temp", "csrf", "nonce",
            "public", "country", "status", "error", "zip", "postal", "currency", "lang", "language", "http",
            "response", "exit", "extension", "ext", "boundary", "avatar", "image", "img", "photo", "thumbnail",
            "lock", "mutex", "event", "message", "msg", "webhook", "hook", "callback", "outbound", "signing",
            "storage", "bucket", "s3", "filepath", "request", "job", "task", "celery", "channel", "room",
            "anchor", "dom", "element", "widget", "html", "css", "seed", "sample", "random", "state", "asset",
            "assets", "attachment", "attachments", "media", "blob", "variant", "username", "handle"}
PURPOSE_FAMILIES = [
    ("custom_password_reset_token_candidate", {"reset"}),
    ("custom_invitation_token_candidate", {"invite", "invitation"}),
    ("custom_recovery_code_candidate", {"recovery"}),
    ("custom_one_time_code_candidate", {"otp", "totp", "hotp", "code", "codes", "pin", "passcode", "magic"}),
    ("custom_password_candidate", {"password", "passwd", "pwd", "passphrase"}),
    ("custom_session_token_candidate", {"session"}),
    ("custom_api_token_candidate", {"apikey"}),
]
GENERIC_PURPOSE = "custom_token_candidate"
HEURISTIC_KIND = "heuristic_custom_credential"
# (v6c) Django's session key constants (django/contrib/auth/__init__.py:16-18, Django 6.1.2): a hand-rolled login
# that writes `session[SESSION_KEY]` writes "_auth_user_id"
DJANGO_SESSION_KEYS = {"django.contrib.auth.SESSION_KEY": "_auth_user_id",
                       "django.contrib.auth.BACKEND_SESSION_KEY": "_auth_user_backend",
                       "django.contrib.auth.HASH_SESSION_KEY": "_auth_user_hash"}
_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def words(name: str) -> set:
    out = set()
    for part in _SPLIT.split(name or ""):
        if part:
            out.add(part.lower())
    return out


@dataclass
class Sink:
    kind: str                 # attribute | model_create | serializer_save | cache | session | credential_call | return
    func: str
    line: int
    names: list               # where the value is kept (field / attribute / keyword / cache key / function name)
    context: list             # local variables, model class, generator functions (supporting evidence only)
    labels: frozenset
    detail: str
    owner: str = ""           # model class / class that owns the attribute (outbound-integration rule)
    # (v5 review) the place is tied to a principal: a session, a per-subject cache key, a user model or a model
    # with a relation to the user model (a weak credential word alone is accepted only then)
    principal: bool = False
    owner_param: str = ""     # (v5 review) the model is a parameter of the function (`model.objects.create`)
    receiver: str = ""        # (v5 review) the expression the attribute is set on (`webhook` in webhook.secret = ...)


@dataclass
class FnTaint:
    sources: list = field(default_factory=list)   # [(call node, symbol, line, assigned names)]
    returns: frozenset = frozenset()
    sinks: list = field(default_factory=list)
    locals: dict = field(default_factory=dict)
    param_locals: dict = field(default_factory=dict)   # (v5 review) including parameter labels


@dataclass
class Candidate:
    func: str
    node: ast.AST
    symbol: str
    line: int
    purpose: str
    sinks: list
    names: list
    kind: str                 # source | creation


class CredentialHeuristics:
    def __init__(self, analysis):
        self.a = analysis
        self.p = analysis.p
        self.cg = analysis.cg
        self._fn: dict = {}
        self._models: dict = {}
        self._ret_cache: dict = {}
        self.candidates: dict = {}       # id(call node) -> Candidate
        self.default_models: dict = {}   # model qualname -> [(field, generator description, purpose)]
        self.rejected: list = []         # (where, line, names, reason) for the coverage report
        self.session_lookups_set_aside: list = []   # (v6b) session ids of non-principal objects
        self.default_field_nodes: dict = {}   # (v5 review) model class -> [(field, field statement, generator)]
        self._default_gen_seen: set = set()
        self._relevant = None
        self._done = False

    # ------------------------------------------------------------------ helpers
    def is_model(self, cls_qn) -> bool:
        if cls_qn not in self._models:
            self._models[cls_qn] = cls_qn in self.p.classes and any(
                c in MODEL_BASES or (c.startswith("django.db.models") and c.endswith(".Model"))
                for c in self.p.mro(cls_qn))
        return self._models[cls_qn]

    def _resolve_static(self, module, expr, info=None):
        if not isinstance(expr, (ast.Name, ast.Attribute)):
            return None
        q = self.p.resolve_expr_static(module, expr, info)
        return self.p.canonical(q) if q else None

    def _sites(self, qn):
        return {id(s.node): s for s in self.cg.sites(qn)}

    def model_meta(self, cls_qn):
        """Meta.model of a project ModelSerializer / ModelForm class (through its project MRO)."""
        for c in self.p.mro(cls_qn):
            meta = f"{c}.Meta"
            if meta in self.p.classes and "model" in self.p.classes[meta].attrs:
                q = self._resolve_static(self.p.classes[meta].module, self.p.classes[meta].attrs["model"])
                return q if q in self.p.classes else None
        return None

    # ------------------------------------------------------------------ per-function taint
    def fn(self, qn) -> FnTaint:
        hit = self._fn.get(qn)
        if hit is not None:
            return hit
        t = FnTaint()
        self._fn[qn] = t        # recursion guard
        info = self.p.functions[qn]
        sites = self._sites(qn)
        ctx = info.cls

        def call_labels(c, local):
            labs = set()
            sym = self._resolve_static(info.module, c.func, info)
            if (sym in SOURCES or sym in self.a.catalog.secret_generators) and self._is_generator_call(c, sym, info):
                return {("src", qn, id(c))}
            site = sites.get(id(c))
            res = self.cg.resolve(site, ctx) if site is not None else None
            if res is not None and res.targets and not res.instantiates:
                # a project function: its RETURN value (never its parameters) carries the labels
                return {("ret", tq) for tq, _ in res.targets if tq in self.p.functions}
            if res is not None and res.instantiates:
                return set()          # a constructor (model, form ...) is not a transformation of its arguments
            model, _how = self._creation_model(c, info, ctx)
            if model:
                return set()
            # a library / builtin call or a method of a tainted value: str(), hexlify(), "".join(), .hex(),
            # .lower(), make_password(), json.dumps() ... transform their arguments / receiver
            parts = list(c.args) + [k.value for k in c.keywords]
            if isinstance(c.func, ast.Attribute):
                parts.append(c.func.value)
            for a in parts:
                labs |= lab(a, local)
            return labs

        def lab(e, local):
            if e is None or isinstance(e, (ast.Lambda, ast.Compare, ast.Constant)):
                return set()
            if isinstance(e, ast.Call):
                return call_labels(e, local)
            if isinstance(e, ast.Name):
                return set(local.get(e.id, ())) if isinstance(e.ctx, ast.Load) else set()
            if isinstance(e, (ast.Attribute, ast.Subscript, ast.Starred, ast.Await, ast.FormattedValue,
                              ast.UnaryOp)):
                v = e.value if not isinstance(e, ast.UnaryOp) else e.operand
                return lab(v, local)
            if isinstance(e, ast.IfExp):
                return lab(e.body, local) | lab(e.orelse, local)
            if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                return lab(e.elt, local)
            if isinstance(e, ast.DictComp):
                return lab(e.value, local)
            out = set()
            for ch in ast.iter_child_nodes(e):
                if isinstance(ch, ast.expr):
                    out |= lab(ch, local)
            return out

        body = list(self.p.walk_function_body(info.node))
        for n in body:
            if isinstance(n, ast.Call):
                sym = self._resolve_static(info.module, n.func, info)
                if (sym in SOURCES or sym in self.a.catalog.secret_generators) and \
                        self._is_generator_call(n, sym, info):
                    t.sources.append((n, sym, n.lineno))
        # (v5 review) parameters carry a "param" label: a credential passed to a helper that stores it is found
        # at the caller (`_persist(owner, raw)`); "param" labels are never sources themselves
        local: dict = {p: {("param", qn, p)} for p in info.params if p not in ("self", "cls")}
        for _ in range(6):
            changed = False
            for n in body:
                pairs = []
                if isinstance(n, ast.Assign):
                    pairs = [(tg, n.value) for tg in n.targets]
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    pairs = [(n.target, n.value)]
                elif isinstance(n, ast.NamedExpr):
                    pairs = [(n.target, n.value)]
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    pairs = [(n.target, n.iter)]
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    pairs = [(it.optional_vars, it.context_expr) for it in n.items if it.optional_vars is not None]
                for tg, val in pairs:
                    labs = lab(val, local) if not isinstance(n, (ast.For, ast.AsyncFor)) else lab(val, local)
                    if not labs:
                        continue
                    for nm in ast.walk(tg):
                        if isinstance(nm, ast.Name) and isinstance(nm.ctx, ast.Store):
                            before = local.get(nm.id, set())
                            if not labs <= before:
                                local[nm.id] = before | labs
                                changed = True
            if not changed:
                break
        t.locals = {k: v for k, v in local.items() if any(lb[0] != "param" for lb in v)}
        t.param_locals = local
        rets = set()
        for n in body:
            if isinstance(n, ast.Return) and n.value is not None:
                rets |= lab(n.value, local)
        t.returns = frozenset(rets)
        holders = {k for k, v in local.items() if any(lb[0] != "param" for lb in v)}
        fname = qn.rsplit(".", 1)[-1]
        cls_name = ctx.rsplit(".", 1)[-1] if ctx else ""
        for n in body:
            # (i) attribute of a model instance
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                labs = lab(n.value, local)
                if labs:
                    for tg in tgts:
                        if isinstance(tg, ast.Attribute):
                            owner = self._attr_owner_model(tg.value, info, ctx)
                            if owner:
                                t.sinks.append(Sink("attribute", qn, n.lineno, [tg.attr],
                                                    _ctx_names(n.value, holders), frozenset(labs),
                                                    f"{_u(tg)} = ... on model {owner}",
                                                    owner=owner.rsplit(".", 1)[-1],
                                                    principal=self.links_user(owner),
                                                    receiver=_u(tg.value).replace(".", "_")))
                            elif not (isinstance(tg.value, ast.Name) and tg.value.id in ("self", "cls") and
                                      info.cls and not self.is_model(info.cls)):
                                # (v5 review) an attribute of an object MintMap cannot type (`user = request.user;
                                # user.api_token = ...`): decided by the attribute name; the receiver's own name
                                # stands for the owner in the outbound-integration rule (`webhook.secret = ...`)
                                rname = _u(tg.value).replace(".", "_")
                                t.sinks.append(Sink("attribute", qn, n.lineno, [tg.attr],
                                                    _ctx_names(n.value, holders), frozenset(labs),
                                                    f"{_u(tg)} = ... (object of unknown type)",
                                                    owner=rname if words(rname) & NEGATIVE_OWNER else ""))
                        elif isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Attribute) and \
                                tg.value.attr == "session":
                            k = tg.slice.value if isinstance(tg.slice, ast.Constant) and \
                                isinstance(tg.slice.value, str) else ""
                            t.sinks.append(Sink("session", qn, n.lineno, [k] if k else [],
                                                _ctx_names(n.value, holders), frozenset(labs),
                                                f"{_u(tg)} = ... (session)", principal=True))
            if isinstance(n, ast.Call):
                self._call_sinks(n, info, ctx, local, holders, lab, t)
                self._param_sinks(n, info, ctx, sites, local, holders, lab, t)
        if _words_hit(words(fname), POSITIVE) and rets:
            ret_vars = [x.id for r in body if isinstance(r, ast.Return) and r.value is not None
                        for x in ast.walk(r.value) if isinstance(x, ast.Name) and x.id in holders]
            t.sinks.append(Sink("return", qn, info.node.lineno, [fname], ret_vars + ([cls_name] if cls_name else []),
                                frozenset(rets), f"returned by credential-named function {qn}"))
        return t

    def _is_generator_call(self, call, sym, info) -> bool:
        """(v5 review) `random.choice/choices/sample(population)` makes a secret only when it draws from characters
        (a string literal, a `string.*` alphabet, a range, or a name bound to one); drawing from a list of
        objects (`random.sample(emojis, 3)`) is a selection, not a credential generator."""
        if sym not in RANDOM_SELECTORS:
            return True
        if not call.args:
            return False
        pop = call.args[0]
        for _ in range(3):
            if isinstance(pop, ast.Name):
                vals = [n.value for n in self.p.walk_function_body(info.node) if isinstance(n, ast.Assign) and
                        any(isinstance(t, ast.Name) and t.id == pop.id for t in n.targets)]
                if not vals:
                    vals = self.p.modules[info.module].assigns.get(pop.id, [])
                if len(vals) != 1:
                    return False
                pop = vals[0]
            else:
                break

        def chars(e):
            if isinstance(e, ast.Constant):
                return isinstance(e.value, str)
            if isinstance(e, ast.Attribute):
                return (self._resolve_static(info.module, e, info) or "").startswith("string.")
            if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
                return chars(e.left) and chars(e.right)
            if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id in ("range", "list", "str"):
                return e.func.id == "range" or (bool(e.args) and chars(e.args[0]))
            return False
        return chars(pop)

    def relevant_functions(self) -> set:
        """Functions that can hold a generator value: those that call a source, and (transitively) those that call
        a function returning one.  A cheap name pre-filter (call leaf == a generator's name) is confirmed by
        resolution in fn(); everything else cannot see a credential value and is not analysed."""
        if self._relevant is not None:
            return self._relevant
        leaves: dict = {}
        for qn, info in self.p.functions.items():
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Call):
                    f = n.func
                    lf = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
                    if lf:
                        leaves.setdefault(lf, set()).add(qn)
        rel = set()
        for leaf in SOURCE_LEAVES | {"SystemRandom"} | {g.rsplit(".", 1)[-1] for g in self.a.catalog.secret_generators}:
            rel |= leaves.get(leaf, set())
        rel = {q for q in rel if self.fn(q).sources}
        frontier = {q for q in rel if self.sources_of(self.fn(q).returns)}
        seen_gens = set(frontier)
        while frontier:
            nxt = set()
            for g in frontier:
                for caller in leaves.get(g.rsplit(".", 1)[-1], ()):
                    if caller in rel:
                        continue
                    t = self.fn(caller)
                    if any(lb == ("ret", g) for s in t.sinks for lb in s.labels) or \
                            any(("ret", g) in v for v in t.locals.values()) or ("ret", g) in t.returns:
                        rel.add(caller)
                        if self.sources_of(t.returns) and caller not in seen_gens:
                            seen_gens.add(caller)
                            nxt.add(caller)
            frontier = nxt
        self._relevant = rel
        return rel

    def _attr_owner_model(self, recv, info, ctx):
        if isinstance(recv, ast.Name) and info.cls and info.params and recv.id == info.params[0]:
            return ctx if ctx and self.is_model(ctx) else None
        if isinstance(recv, ast.Name):
            typ = self.cg.var_types(info.qualname, ctx).get(recv.id)
            if typ and self.is_model(typ):
                return typ
            # (v5 review) `@receiver(pre_save, sender=M) def f(sender, instance, **kw)`: instance is an M
            if recv.id == "instance" or (len(info.params) > 1 and recv.id == info.params[1]):
                for m in self.signal_senders(info.qualname):
                    return m
            # (v5 review) `x = M.objects.get(...)` / `M.objects.filter(...).first()` / `get_object_or_404(M, ...)`
            return self._fetched_model(recv.id, info)
        return None

    def _fetched_model(self, var, info):
        found = None
        for n in self.p.walk_function_body(info.node):
            if not (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == var for t in n.targets)):
                continue
            v = n.value
            m = None
            if isinstance(v, ast.Call) and isinstance(v.func, (ast.Name, ast.Attribute)) and \
                    (v.func.attr if isinstance(v.func, ast.Attribute) else v.func.id) in ("get_object_or_404",
                                                                                            "aget_object_or_404") \
                    and v.args:
                m = self._resolve_static(info.module, v.args[0], info)
            else:
                e = v
                while isinstance(e, (ast.Call, ast.Attribute, ast.Await)):
                    if isinstance(e, ast.Attribute) and e.attr in MANAGER_ATTRS:
                        m = self._resolve_static(info.module, e.value, info)
                        break
                    e = e.func if isinstance(e, ast.Call) else e.value
            if m and self.is_model(m):
                if found and found != m:
                    return None
                found = m
        return found

    def signal_senders(self, qn) -> list:
        """(v5 review) Project models a function is a pre_save/post_save receiver for (`@receiver(sig, sender=M)`
        or `sig.connect(f, sender=M)`)."""
        return sorted(m for m, fs in self.signal_receivers().items() if qn in fs)

    def signal_receivers(self) -> dict:
        """(v5 review) {project model: [receiver functions]} for Django's pre_save / post_save signals."""
        hit = getattr(self, "_signal_receivers", None)
        if hit is not None:
            return hit
        out: dict = {}
        sigs = {"django.db.models.signals.pre_save", "django.db.models.signals.post_save"}

        def sender_of(call, module, info=None):
            for k in call.keywords:
                if k.arg == "sender":
                    m = self._resolve_static(module, k.value, info)
                    if m and self.is_model(m):
                        return m
            return None
        for qn, info in self.p.functions.items():
            for d in info.node.decorator_list:
                if isinstance(d, ast.Call) and self._resolve_static(info.module, d.func) == "django.dispatch.receiver" \
                        and d.args:
                    sig_args = d.args[0].elts if isinstance(d.args[0], (ast.List, ast.Tuple)) else [d.args[0]]
                    if any(self._resolve_static(info.module, a) in sigs for a in sig_args):
                        m = sender_of(d, info.module)
                        if m:
                            out.setdefault(m, set()).add(qn)
        for mname, mod in self.p.modules.items():
            for n in ast.walk(mod.tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "connect" and \
                        n.args and self._resolve_static(mname, n.func.value) in sigs:
                    f = self._resolve_static(mname, n.args[0])
                    m = sender_of(n, mname)
                    if f in self.p.functions and m:
                        out.setdefault(m, set()).add(f)
        self._signal_receivers = {k: sorted(v) for k, v in out.items()}
        return self._signal_receivers

    def is_user_model(self, cls_qn) -> bool:
        return any(c in ("django.contrib.auth.models.AbstractUser", "django.contrib.auth.models.AbstractBaseUser",
                         "django.contrib.auth.base_user.AbstractBaseUser", "django.contrib.auth.models.User")
                   for c in self.p.mro(cls_qn)) if cls_qn else False

    def links_user(self, model_qn) -> bool:
        """(v5 review) The model is the user model, or one of its fields relates to the user model
        (ForeignKey / OneToOneField / ManyToManyField to settings.AUTH_USER_MODEL, get_user_model(), "auth.User" or
        a project user model): a value kept on it belongs to a principal."""
        memo = self.__dict__.setdefault("_links_user", {})
        if model_qn in memo:
            return memo[model_qn]
        memo[model_qn] = False
        ok = self.is_user_model(model_qn)
        for c in self.p.mro(model_qn) if not ok else []:
            if c not in self.p.classes:
                continue
            cc = self.p.classes[c]
            for st in cc.node.body:
                if not (isinstance(st, (ast.Assign, ast.AnnAssign)) and isinstance(st.value, ast.Call)):
                    continue
                f = st.value.func
                leaf = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                if leaf not in ("ForeignKey", "OneToOneField", "ManyToManyField") or not (
                        st.value.args or any(k.arg == "to" for k in st.value.keywords)):
                    continue
                to = st.value.args[0] if st.value.args else next(k.value for k in st.value.keywords if k.arg == "to")
                if isinstance(to, ast.Constant) and isinstance(to.value, str):
                    if to.value.lower() in ("auth.user", "user") or to.value.lower().endswith(".user"):
                        ok = True
                elif isinstance(to, ast.Attribute) and to.attr == "AUTH_USER_MODEL":
                    ok = True
                elif isinstance(to, ast.Call) and isinstance(to.func, (ast.Name, ast.Attribute)) and \
                        (to.func.attr if isinstance(to.func, ast.Attribute) else to.func.id) == "get_user_model":
                    ok = True
                else:
                    q = self._resolve_static(cc.module, to)
                    ok = ok or self.is_user_model(q) or q == "django.contrib.auth.models.User"
                if ok:
                    break
            if ok:
                break
        memo[model_qn] = ok
        return ok

    def related_models(self, attr) -> list:
        """(v6) Project models reachable through a reverse relation accessor named `attr`: the `related_name` of a
        ForeignKey / OneToOneField / ManyToManyField declared on a project model (`%(class)s` expanded), or Django's
        default `<model>_set`.  `team.tokens.create(...)` creates the model that declares
        `team = ForeignKey(Team, related_name="tokens")`."""
        rm = self.__dict__.get("_related_map")
        if rm is None:
            rm = {}
            for cq in sorted(self.p.classes):
                if not self.is_model(cq):
                    continue
                cc = self.p.classes[cq]
                short = cq.rsplit(".", 1)[-1].lower()
                for st in cc.node.body:
                    if not (isinstance(st, (ast.Assign, ast.AnnAssign)) and isinstance(st.value, ast.Call)):
                        continue
                    fn = st.value.func
                    leaf = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
                    if leaf not in RELATION_FIELDS:
                        continue
                    rel = next((k.value for k in st.value.keywords if k.arg == "related_name"), None)
                    if isinstance(rel, ast.Constant) and isinstance(rel.value, str):
                        if rel.value.endswith("+"):
                            continue
                        name = rel.value.replace("%(class)s", short).replace("%(app_label)s", "")
                    elif rel is None:
                        name = f"{short}_set"
                    else:
                        continue
                    rm.setdefault(name, set()).add(cq)
            rm = {k: sorted(v) for k, v in rm.items()}
            self._related_map = rm
        return rm.get(attr, [])

    def _related_creation(self, f, info):
        """(v6) `<instance expr>.<accessor>.<create>(...)` where <accessor> is a reverse relation of a project model:
        (model, how) | ("related:<accessor>", how) when the accessor names no project model (a library model's
        relation, e.g. `device.token_set`) | (None, None) when the receiver is a class / module (`M.objects` is
        handled by the caller, `stripe.Customer.create` is not a relation)."""
        if not (isinstance(f, ast.Attribute) and f.attr in CREATE_METHODS and isinstance(f.value, ast.Attribute)):
            return None, None
        acc = f.value
        if acc.attr in MANAGER_ATTRS or acc.attr.startswith("_"):
            return None, None
        recv = acc.value
        on_self = isinstance(recv, ast.Name) and recv.id in ("self", "cls") or (
            isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id == "self")
        q = self._resolve_static(info.module, recv, info) if isinstance(recv, (ast.Name, ast.Attribute)) else None
        if q and not on_self and (q in self.p.classes or q in self.p.modules or not self.p.is_project(q)):
            return None, None       # a class / module attribute (`M.objects` is handled by the caller), a library
        models = self.related_models(acc.attr)
        if len(models) > 1:
            with_defaults = [m for m in models if m in self.default_models]
            models = with_defaults if len(with_defaults) == 1 else models
        if len(models) == 1:
            return models[0], f"{acc.attr}.{f.attr}"
        if not models and (acc.attr.endswith("_set") or acc.attr.endswith("s")):
            return "related:" + acc.attr, f"{acc.attr}.{f.attr}"
        return None, None

    def _creation_model(self, call, info, ctx):
        """Project model created by this call: `M(...)`, `M.objects.<create>(...)` (also `M.objects.filter(...)
        .<create>`), (v6) `<instance>.<reverse accessor>.<create>(...)`."""
        f = call.func
        q = self._resolve_static(info.module, f, info)
        if q and q in self.p.classes and self.is_model(q):
            return q, "constructor"
        mgr = ctx or info.cls
        models = self.cg.manager_models().get(mgr, []) if mgr else []
        if len(models) == 1 and isinstance(f, ast.Attribute):
            # (v6c) inside a project manager / queryset: `self.create(...)`, `self.get_queryset().create(...)`,
            # `self.model(...)` create the model that declares it
            base = f.value
            if isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute) and \
                    base.func.attr in ("get_queryset", "all", "filter", "using") and \
                    isinstance(base.func.value, ast.Name) and base.func.value.id == "self":
                base = base.func.value
            if isinstance(base, ast.Name) and base.id == "self" and f.attr in CREATE_METHODS:
                return models[0], f.attr
            if isinstance(base, ast.Name) and base.id == "self" and f.attr == "model":
                return models[0], "constructor"
        model, how = self._related_creation(f, info)
        if model:
            return model, how
        if isinstance(f, ast.Attribute) and f.attr in CREATE_METHODS:
            v = f.value
            while isinstance(v, (ast.Call, ast.Attribute)):
                if isinstance(v, ast.Attribute) and v.attr in MANAGER_ATTRS:
                    m = self._resolve_static(info.module, v.value, info)
                    if m and (self.is_model(m) or m in self.p.classes):   # a project class with a manager: a model
                        return m, f.attr
                    if isinstance(v.value, ast.Name) and info.params and v.value.id in ("self", "cls") and ctx \
                            and self.is_model(ctx):
                        return ctx, f.attr
                    if isinstance(v.value, ast.Name) and v.value.id in info.params:
                        # (v5 review) the model class is a parameter (`def _store(model, ...): model.objects.create`)
                        return "param:" + v.value.id, f.attr
                    return None, None
                v = v.func if isinstance(v, ast.Call) else v.value
        return None, None

    def _call_sinks(self, n, info, ctx, local, holders, lab, t):
        qn = info.qualname
        kw_tainted = [(k.arg, k.value) for k in n.keywords if k.arg and lab(k.value, local)]
        model, how = self._creation_model(n, info, ctx)
        if model:
            # one sink per field: each field's name decides for the value stored in it
            fields = [(k, v) for k, v in kw_tainted if k != "defaults"]
            for k in n.keywords:
                if k.arg == "defaults" and isinstance(k.value, ast.Dict):
                    fields += [(str(dk.value), dv) for dk, dv in zip(k.value.keys, k.value.values)
                               if dk is not None and isinstance(dk, ast.Constant) and lab(dv, local)]
            pm = model[6:] if model.startswith("param:") else ""
            rel = model[8:] if model.startswith("related:") else ""
            for k, v in fields:
                what = 'the model passed as ' + pm if pm else (f"the model behind the relation {rel}" if rel else model)
                t.sinks.append(Sink("model_create", qn, n.lineno, [k], _ctx_names(v, holders),
                                    frozenset(lab(v, local)), f"{_u(n.func)}({k}=...) creates {what}",
                                    owner="" if pm else (rel if rel else model.rsplit(".", 1)[-1]),
                                    principal=False if (pm or rel) else self.links_user(model), owner_param=pm))
            return
        leaf = n.func.attr if isinstance(n.func, ast.Attribute) else (n.func.id if isinstance(n.func, ast.Name) else "")
        if leaf == "save" and kw_tainted:
            labs = set().union(*(lab(v, local) for _, v in kw_tainted))
            t.sinks.append(Sink("serializer_save", qn, n.lineno, [k for k, _ in kw_tainted],
                                _ctx_names(n, holders), frozenset(labs), f"{_u(n.func)}(...)"))
            return
        if leaf in STORE_METHODS and isinstance(n.func, ast.Attribute):
            args = list(n.args) + [k.value for k in n.keywords]
            tainted = [a for a in args if lab(a, local)]
            if tainted and len(n.args) >= 2:
                names = []
                k0 = n.args[0]
                if isinstance(k0, ast.Constant) and isinstance(k0.value, str):
                    names.append(k0.value)
                elif isinstance(k0, (ast.JoinedStr, ast.BinOp, ast.Call)):
                    # (v5 review) f"login-otp:{user.pk}", "otp:" + email, "k:{}".format(x): the constant parts
                    names += [c.value for c in ast.walk(k0) if isinstance(c, ast.Constant) and isinstance(c.value, str)
                              and c.value.strip(":-_/. ")]
                for a in tainted:
                    names += _dict_keys_holding(a, local, lab)
                labs = set().union(*(lab(a, local) for a in tainted))
                # a key computed per subject (user id, e-mail) ties the value to a principal
                per_subject = not isinstance(k0, ast.Constant)
                pats = {k for k in self.key_patterns(k0, info) if self.pattern_usable(k)}
                if pats:
                    self.__dict__.setdefault("_cache_sink_patterns", {})[(qn, n.lineno)] = pats
                t.sinks.append(Sink("cache", qn, n.lineno, names, _ctx_names(n, holders), frozenset(labs),
                                    f"{_u(n.func)}(...)", principal=per_subject))
            return
        if leaf and _words_hit(words(leaf), CALL_NOUNS) and leaf not in SOURCE_LEAVES and \
                _first_word(leaf) not in CONSUMER_VERBS:
            # (v6b) a callable is a place where a credential is kept only when its name says WHAT it keeps (a
            # credential noun: `store_token`, `set_password`); an action word alone (`reset(...)`, `ContextVar.reset`)
            # is not, and a predicate (`check_token(v)`, `verify_code(v)`) consumes a value, it does not keep one
            args = list(n.args) + [k.value for k in n.keywords]
            labs = set()
            for a in args:
                labs |= lab(a, local)
            if labs:
                t.sinks.append(Sink("credential_call", qn, n.lineno, [leaf], _ctx_names(n, holders),
                                    frozenset(labs), f"passed to {_u(n.func)}()"))

    def _param_sinks(self, n, info, ctx, sites, local, holders, lab, t):
        """(v5 review) A value passed to a project function whose parameter reaches a sink there (a helper that
        stores it: `_persist(owner, raw)` -> `Token.objects.create(value=value)`): the sink, seen from the caller,
        with the caller's labels.  Followed through nested helpers (each callee's own param sinks), cycles cut."""
        site = sites.get(id(n))
        if site is None:
            return
        res = self.cg.resolve(site, ctx)
        if not res.targets or res.instantiates:
            return
        for tq, _tctx in res.targets:
            if tq not in self.p.functions or tq == info.qualname:
                continue
            tinfo = self.p.functions[tq]
            params = [p for p in tinfo.params]
            if tinfo.cls and params and params[0] in ("self", "cls") and isinstance(n.func, ast.Attribute):
                params = params[1:]
            bound = {}
            for i, a in enumerate(n.args):
                if isinstance(a, ast.Starred):
                    break
                if i < len(params):
                    bound[params[i]] = a
            for k in n.keywords:
                if k.arg and k.arg in params:
                    bound[k.arg] = k.value
            tainted = {p: lab(a, local) for p, a in bound.items()}
            tainted = {p: v for p, v in tainted.items() if v}
            if not tainted:
                continue
            callee = self.fn(tq)
            for s in callee.sinks:
                for p, labs in tainted.items():
                    if ("param", tq, p) in s.labels:
                        owner, principal, owner_param = s.owner, s.principal, ""
                        if s.owner_param:
                            # the caller says which model the helper creates
                            arg = bound.get(s.owner_param)
                            m = None
                            if isinstance(arg, ast.Name) and arg.id in ("cls", "self") and ctx and self.is_model(ctx):
                                m = ctx
                            elif arg is not None:
                                q = self._resolve_static(info.module, arg, info)
                                m = q if q and self.is_model(q) else None
                                if m is None and isinstance(arg, ast.Name) and arg.id in info.params:
                                    owner_param = arg.id
                            if m:
                                owner, principal = m.rsplit(".", 1)[-1], self.links_user(m)
                        t.sinks.append(Sink(s.kind, info.qualname, n.lineno, list(s.names),
                                            sorted(set(s.context) | set(_ctx_names(n, holders))), frozenset(labs),
                                            f"{s.detail} (via {tq.rsplit('.', 1)[-1]}({p}=...))", owner=owner,
                                            principal=principal, owner_param=owner_param))

    # ------------------------------------------------------------------ (v5 review) hand-rolled session logins
    # (v6) keys are compared as PATTERNS: a literal key is itself; an f-string / str.format / % / + key, or a key
    # held in a local variable or a module constant, is its constant text with "{}" for each computed part
    # (`f"customer_auth_id:{org.pk}"` -> "customer_auth_id:{}").  A session is `<x>.session`, a local alias of
    # one (`session = request.session`) or a SessionStore object (`s = SessionStore(key)`).
    def mentions(self, info) -> set:
        """Attribute and name identifiers used in a function body (one walk, cached): a cheap pre-filter."""
        memo = self.__dict__.setdefault("_mentions", {})
        hit = memo.get(info.qualname)
        if hit is None:
            hit = set()
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Attribute):
                    hit.add(n.attr)
                elif isinstance(n, ast.Name):
                    hit.add(n.id)
            memo[info.qualname] = hit
        return hit

    def local_assignments(self, info) -> dict:
        """{local name: [assigned value expressions]} for single-target `name = value` statements (cached)."""
        memo = self.__dict__.setdefault("_local_assigns", {})
        hit = memo.get(info.qualname)
        if hit is None:
            hit = {}
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    hit.setdefault(n.targets[0].id, []).append(n.value)
            memo[info.qualname] = hit
        return hit

    def session_aliases(self, info) -> tuple:
        """({local names bound to a session}, {local names bound to a SessionStore object})."""
        memo = self.__dict__.setdefault("_sess_alias", {})
        if info.qualname in memo:
            return memo[info.qualname]
        sess, store = set(), set()
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                v = n.value
                if isinstance(v, ast.Attribute) and v.attr == "session":
                    sess.add(n.targets[0].id)
                elif isinstance(v, ast.Call) and _leaf(v.func) == "SessionStore":
                    store.add(n.targets[0].id)
        memo[info.qualname] = (sess, store)
        return sess, store

    def is_session_expr(self, e, info) -> bool:
        if isinstance(e, ast.Attribute) and e.attr == "session":
            return True
        if isinstance(e, ast.Name):
            sess, store = self.session_aliases(info)
            return e.id in sess or e.id in store
        return False

    def key_patterns(self, e, info, _depth=0) -> set:
        """Patterns of a session key expression (see above); "?" for a key MintMap cannot read."""
        if _depth > 4:
            return {"?"}
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return {e.value}
        if isinstance(e, ast.JoinedStr):
            parts = []
            for v in e.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue) and isinstance(v.value, (ast.Name, ast.Attribute)) and \
                        v.format_spec is None and self.module_str_constant(info.module, v.value, info) is not None:
                    parts.append(self.module_str_constant(info.module, v.value, info))   # f"{PREFIX}:{x}"
                else:
                    parts.append("{}")
            return {"".join(parts)}
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format" and \
                isinstance(e.func.value, ast.Constant) and isinstance(e.func.value.value, str):
            return {re.sub(r"\{[^{}]*\}", "{}", e.func.value.value)}
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mod) and isinstance(e.left, ast.Constant) and \
                isinstance(e.left.value, str):
            return {re.sub(r"%[-#0 +]*\d*(?:\.\d+)?[sdirfx]", "{}", e.left.value)}
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            out = set()
            for x in self.key_patterns(e.left, info, _depth + 1):
                for y in self.key_patterns(e.right, info, _depth + 1):
                    out.add((x if x != "?" else "{}") + (y if y != "?" else "{}"))
            return out
        if isinstance(e, ast.Name):
            vals = self.local_assignments(info).get(e.id, [])
            if vals:
                out = set()
                for v in vals:
                    out |= self.key_patterns(v, info, _depth + 1)
                return out
        if isinstance(e, (ast.Name, ast.Attribute)):
            c = self.module_str_constant(info.module, e, info)
            if c is not None:
                return {c}
            q = self._resolve_static(info.module, e, info)
            if q in DJANGO_SESSION_KEYS:
                return {DJANGO_SESSION_KEYS[q]}     # (v6c) `request.session[SESSION_KEY] = ...`
        return {"?"}

    def module_str_constant(self, module, e, info=None, _depth=0):
        """The string value of a module-level constant (`KEY = "..."`, also imported), else None."""
        q = self._resolve_static(module, e, info) if isinstance(e, (ast.Name, ast.Attribute)) else None
        if not q or _depth > 3:
            return None
        m, rest = self.p.module_prefix(q)
        if not m or len(rest) != 1:
            return None
        vals = []
        for st in self.p._top_level_statements(self.p.modules[m].tree.body):
            if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == rest[0] for t in st.targets):
                vals.append(st.value)
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.target.id == rest[0] \
                    and st.value is not None:
                vals.append(st.value)
        if len(vals) != 1:
            return None
        v = vals[0]
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return v.value
        if isinstance(v, (ast.Name, ast.Attribute)):
            return self.module_str_constant(m, v, None, _depth + 1)
        return None

    @staticmethod
    def pattern_usable(pat) -> bool:
        """A pattern names a key only if it has some constant text (a key that is entirely computed matches
        nothing)."""
        return pat != "?" and len(pat.replace("{}", "")) >= 3

    def session_key_read(self, e, info) -> set:
        """Key patterns read by `sess.get(K)` / `sess.pop(K)` / `sess[K]` (sess: a session, alias or store)."""
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr in ("get", "pop") and \
                e.args and self.is_session_expr(e.func.value, info):
            return {k for k in self.key_patterns(e.args[0], info) if self.pattern_usable(k)}
        if isinstance(e, ast.Subscript) and isinstance(e.ctx, ast.Load) and self.is_session_expr(e.value, info):
            return {k for k in self.key_patterns(e.slice, info) if self.pattern_usable(k)}
        return set()

    def principal_models(self) -> set:
        """(v6) Project models looked up by a key read from the session (`Customer.objects.get(pk=session[K])`,
        also through a reverse relation `org.customers.get(...)`): the second kinds of principal the project
        authenticates (reported in the coverage; not used to accept weak credential words: an order linked to a
        customer is not a credential holder)."""
        self.auth_session_keys()
        return self.__dict__.get("_principal_models", set())

    def auth_session_keys(self) -> dict:
        """{session key pattern: [functions that use it to load a principal]}: a value read from `x.session.get(K)`
        / `x.session[K]` (also through a session alias or a SessionStore object, and with a computed key, see
        key_patterns) that (directly or through a local variable) is a `pk=` / `id=` / `*_id=` lookup argument
        is how the project authenticates a second kind of principal (`request.customer = Customer.objects
        .filter(pk=request.session.get("customer_id")).first()`).  Django's own SESSION_KEY is always one."""
        hit = getattr(self, "_auth_session_keys", None)
        if hit is not None:
            return hit
        out = {"_auth_user_id": ["django.contrib.auth (SESSION_KEY written without login())"]}
        principals = set()
        self._auth_session_keys = out          # recursion guard (related_models -> is_model only)
        for qn, info in self.p.functions.items():
            if not self.mentions(info) & {"session", "SessionStore"}:
                continue
            body = list(self.p.walk_function_body(info.node))
            held = {}
            for n in body:
                if isinstance(n, ast.Assign):
                    ks = set()
                    for x in ast.walk(n.value):
                        ks |= self.session_key_read(x, info)
                    for tg in n.targets:
                        if isinstance(tg, ast.Name) and ks:
                            held.setdefault(tg.id, set()).update(ks)
            for n in body:
                if not isinstance(n, ast.Call):
                    continue
                for k in n.keywords:
                    if not k.arg or not (k.arg in ("pk", "id") or k.arg.endswith(("_id", "_pk", "__pk", "__id"))):
                        continue
                    ks = set()
                    for x in ast.walk(k.value):
                        ks |= self.session_key_read(x, info)
                    ks |= {kk for x in ast.walk(k.value) if isinstance(x, ast.Name) for kk in held.get(x.id, ())}
                    if not ks:
                        continue
                    m = self._lookup_model(n.func, info) or self._shortcut_model(n, info)
                    why = self._not_a_principal_lookup(k.arg, m, n, info, keys=ks)
                    if why:
                        # (v6b) the session holds the id of an event, a payment, a workspace ...: flow state
                        for key in ks:
                            self.session_lookups_set_aside.append(dict(function=qn, line=n.lineno, key=key,
                                                                       reason=why))
                        continue
                    for key in ks:
                        if qn not in out.setdefault(key, []):
                            out[key].append(qn)
                    if k.arg in ("pk", "id") and m:
                        principals.add(m)
        self._principal_models = principals
        return out

    PRINCIPAL_MODEL_NOUNS = {"user", "users", "customer", "customers", "member", "members", "account", "accounts",
                             "principal", "owner", "staff", "admin", "person", "identity", "profile"}
    PASSWORD_ATTRS = {"password", "password_hash", "hashed_password", "passcode", "pin_hash"}

    def principal_like(self, model) -> bool:
        """(v6b) A model that can be the principal of a session: the user model, a model named after a principal
        (`Customer`, `Member`, `Account`), or one that keeps a password (a field or `check_password`)."""
        if not model:
            return False
        if self.is_user_model(model):
            return True
        if words(model.rsplit(".", 1)[-1]) & self.PRINCIPAL_MODEL_NOUNS:
            return True
        for c in self.p.mro(model):
            ci = self.p.classes.get(c)
            if ci is not None and (set(ci.attrs) & self.PASSWORD_ATTRS or
                                   {"check_password", "set_password"} & set(ci.methods)):
                return True
        return False

    def _not_a_principal_lookup(self, kwarg, model, call, info, keys=()) -> str:
        """(v6b) Why a lookup by a value read from the session does NOT load a principal ('' when it may): the
        looked-up model is a project model that is not principal-like (an event, a payment, a workspace), the
        lookup keyword names no principal (`event_id=`), the object is not attached to the request
        (`request.customer = ...`, (v6c) also `request.user = obj.owner` or anything else derived from it), and
        (v6c) no function that writes the key verifies a secret first (`emp.pin != request.POST["pin"]`,
        check_password(), compare_digest()): a value written after a credential check is a login, whatever the
        model is called."""
        if kwarg not in ("pk", "id") and words(kwarg) & self.PRINCIPAL_MODEL_NOUNS:
            return ""
        if model is None or not self.is_model(model) or self.principal_like(model):
            return ""
        if self._attached_to_request(call, info):
            return ""
        for key in keys:
            for w in self.session_key_writers().get(key, ()):
                if self.verifies_secret(w):
                    return ""
        return f"looks up {model.rsplit('.', 1)[-1]} (not a user / customer / account model) by `{kwarg}=`"

    def _attached_to_request(self, call, info) -> bool:
        """The looked-up object, or anything derived from it (`obj.owner`, `obj.get_user()`, `obj["user"]`), is
        assigned to an attribute of the request (`request.device = obj`, `request.user = obj.owner`)."""
        parents = self._parents(info)
        node, stmt = call, None
        while node is not None:
            node = parents.get(id(node))
            if isinstance(node, ast.stmt):
                stmt = node
                break
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] \
            if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)) else []
        names = {t.id for t in targets if isinstance(t, ast.Name)}

        def on_request(t):
            return isinstance(t, ast.Attribute) and "request" in _u(t.value)
        if any(on_request(t) for t in targets):
            return True
        if names:
            # names derived from the object (one level of `x = obj.attr`), then any request attribute assignment
            # whose value mentions one of them
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id in names
                                                     for x in ast.walk(n.value)):
                    names |= {t.id for t in n.targets if isinstance(t, ast.Name)}
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Assign) and any(on_request(t) for t in n.targets) and \
                        any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(n.value)):
                    return True
        return False

    def session_key_writers(self) -> dict:
        """(v6c) {session key pattern: [functions that write it]} (cached)."""
        hit = self.__dict__.get("_key_writers")
        if hit is None:
            hit = {}
            for qn, info in self.p.functions.items():
                for _st, kexpr, _v in self.session_writes(info):
                    for k in self.key_patterns(kexpr, info):
                        if self.pattern_usable(k) and qn not in hit.setdefault(k, []):
                            hit[k].append(qn)
            self._key_writers = hit
        return hit

    SECRET_CHECK_LEAVES = {"check_password", "acheck_password", "authenticate", "aauthenticate", "compare_digest",
                           "constant_time_compare", "verify", "verify_token", "check_token", "verify_password",
                           "checkpw", "check_password_hash"}
    SECRET_ATTR_WORDS = {"pin", "password", "passcode", "code", "token", "secret", "otp", "key", "passphrase"}

    def verifies_secret(self, fq) -> bool:
        """(v6c) The function verifies a secret: a catalogued-style check call (check_password(), authenticate(),
        compare_digest(), a verify / check_token method) or a comparison of a credential-named attribute with a
        request value (`emp.pin != request.POST.get("pin")`, `obj.code == form.cleaned_data["code"]`)."""
        memo = self.__dict__.setdefault("_verifies", {})
        if fq in memo:
            return memo[fq]
        info = self.p.functions.get(fq)
        hit = False
        for n in self.p.walk_function_body(info.node) if info else ():
            if isinstance(n, ast.Call) and _leaf(n.func) in self.SECRET_CHECK_LEAVES:
                hit = True
                break
            if isinstance(n, ast.Compare) and any(isinstance(o, (ast.Eq, ast.NotEq)) for o in n.ops):
                sides = [n.left] + list(n.comparators)
                secret = any(isinstance(x, ast.Attribute) and words(x.attr) & self.SECRET_ATTR_WORDS for x in sides)
                inbound = any(isinstance(y, ast.Attribute) and y.attr in ("POST", "GET", "data", "headers",
                                                                          "cleaned_data", "query_params", "META")
                              for x in sides for y in ast.walk(x))
                if secret and inbound:
                    hit = True
                    break
        memo[fq] = hit
        return hit

    SHORTCUTS = {"get_object_or_404", "get_list_or_404", "aget_object_or_404", "aget_list_or_404"}

    def _shortcut_model(self, call, info):
        """(v6b) The model of `get_object_or_404(M, pk=...)` (also a queryset `M.objects.filter(...)`)."""
        leaf = call.func.attr if isinstance(call.func, ast.Attribute) else \
            call.func.id if isinstance(call.func, ast.Name) else ""
        if leaf not in self.SHORTCUTS or not call.args:
            return None
        a = call.args[0]
        if isinstance(a, (ast.Name, ast.Attribute)):
            m = self._resolve_static(info.module, a, info)
            if m and self.is_model(m):
                return m
        if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute):
            return self._lookup_model(a.func, info)
        return None

    def _lookup_model(self, f, info):
        """The project model a `.get/.filter(...)` lookup reads: `M.objects.get`, `<x>.<reverse accessor>.get`."""
        v = f.value if isinstance(f, ast.Attribute) else None
        while isinstance(v, (ast.Call, ast.Attribute)):
            if isinstance(v, ast.Attribute) and v.attr in MANAGER_ATTRS:
                m = self._resolve_static(info.module, v.value, info)
                return m if m and self.is_model(m) else None
            if isinstance(v, ast.Attribute):
                ms = self.related_models(v.attr)
                if len(ms) == 1:
                    return ms[0]
                v = v.value
                continue
            v = v.func
        return None

    def session_writes(self, info) -> list:
        """[(statement, key expression, value expression)] for `sess[K] = V` / `sess.setdefault(K, V)` /
        `sess.update({K: V})` in a function (sess: a session, alias or SessionStore object)."""
        out = []
        if not self.mentions(info) & {"session", "SessionStore"}:
            return out
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for tg in tgts:
                    if isinstance(tg, ast.Subscript) and self.is_session_expr(tg.value, info) and n.value is not None:
                        out.append((n, tg.slice, n.value))
            elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and \
                    isinstance(n.value.func, ast.Attribute) and self.is_session_expr(n.value.func.value, info):
                c = n.value
                if c.func.attr == "setdefault" and len(c.args) >= 2:
                    out.append((n, c.args[0], c.args[1]))
                elif c.func.attr == "update" and c.args and isinstance(c.args[0], ast.Dict):
                    for k, v in zip(c.args[0].keys, c.args[0].values):
                        if k is not None:
                            out.append((n, k, v))
        return out

    def session_login_stores(self, qn) -> list:
        """[(statement, key, consumers)]: `x.session[K] = v` in `qn` where K is an authentication session key."""
        keys = self.auth_session_keys()
        info = self.p.functions[qn]
        out = []
        for st, kexpr, _v in self.session_writes(info):
            for k in sorted(self.key_patterns(kexpr, info)):
                if k in keys and (self.pattern_usable(k) or k == "_auth_user_id"):
                    out.append((st, k, keys[k]))
                    break
        return out

    # ------------------------------------------------------------------ (v6) generic signing / JWT primitives
    PRINCIPAL_NOUNS = {"user", "users", "customer", "member", "account", "principal", "owner", "staff", "admin"}
    PRINCIPAL_ATTRS = {"pk", "id", "email", "username", "uuid"}
    STRING_BUILDERS = {"str", "quote", "quote_plus", "urlencode", "format", "join", "encode", "decode"}

    def signed_value_decision(self, site):
        """(v6) A generic signing / JWT primitive (`signing.dumps`, `Signer.sign`, `jwt.encode` ...) is a credential
        mint only when its value is kept where a credential is (a name with a STRONG credential word: returned
        from `make_token`, stored as `login_token`, passed as `token=`), or when it signs an identifier of a
        principal (`{"user": user.pk}`, `request.user.email`, `self.pk` in a method of a principal-like model): an
        identity assertion.  (v6c) The code that reads the value back decides in both directions: a value that a
        reader with the same salt (or, for JWT, the same key) uses to log someone in or to authenticate a request
        is a mint whatever its naming; a value that looked like a credential is set aside only when every such
        reader is fully analysed (callers up to READER_UP levels) and none of them, at any depth,
        issues a session or credential.  Set-aside values are listed in coverage.custom_credentials.set_aside and
        watched (see analysis.watched_sites).  -> (purpose, why) | (None, reason)"""
        memo = self.__dict__.setdefault("_signed_memo", {})
        key = id(site.node)
        if key in memo:
            return memo[key]
        memo[key] = (None, "being decided")       # recursion guard
        info = self.p.functions[site.func]
        call = site.node
        names = self._kept_names(info, call)
        sink = Sink("signed", info.qualname, site.line, names, [], frozenset(), f"{site.text}(...)")
        purpose, reason = self.decide(sink, strong_only=True) if names else (None, "value not kept under a name")
        out = (purpose, f"signed value kept as {names}") if purpose else None
        if out is None:
            ident = self._principal_payload(call, info)
            if ident:
                out = (GENERIC_PURPOSE, f"signs a principal identifier ({ident})")
        readers = self.signed_readers(call, info)
        issuing, unknown = [], []
        for r in readers:
            issues, complete, reaches = self.reader_issues(r)
            if issues:
                issuing.append(r)
            elif reaches or not complete:
                unknown.append(r)
        what = "key" if self._is_jwt(call, info) else "salt"
        if out is None and issuing:
            out = (GENERIC_PURPOSE, f"read back (same {what}) by {', '.join(issuing[:3])}, which logs someone in "
                                    f"or authenticates a request with it")
        elif out is not None and readers and not issuing and not unknown:
            # (v6b) every reader is analysed and none of them issues anything: integrity-protected state (a
            # confirmation payload, an OAuth-like state, a redirect proof), not a credential
            out = None
            reason = (f"read back (same {what}) only by {', '.join(readers[:3])}, which neither log anyone in nor "
                      f"issue a credential (nor do their callers, up to {self.READER_UP} levels)")
        if out is None:
            out = (None, f"{reason}; the signed payload names no principal identifier" if "read back" not in reason
                   else reason)
            self.rejected.append(dict(function=info.qualname, line=site.line, source=site.text,
                                      reasons=[f"generic signing primitive: {out[1]}"], watch="signed_value"))
        memo[key] = out
        return out

    READ_BACK_LEAVES = {"loads", "unsign", "unsign_object", "aunsign"}
    ISSUING_LEAVES = {"login", "alogin", "set_password", "aset_password", "update_session_auth_hash"}
    READER_UP, READER_DOWN = 4, 4

    def _salt_signature(self, e, info):
        """(v6b) A comparable form of a `salt=` expression: a string constant (also a module constant), or the
        constant parts of an f-string / concatenation; None when nothing constant is left."""
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            return "s:" + e.value
        if isinstance(e, (ast.Name, ast.Attribute)):
            v = self.module_str_constant(info.module, e, info)
            if v is not None:
                return "s:" + v
            return "n:" + (e.id if isinstance(e, ast.Name) else e.attr)
        if isinstance(e, (ast.JoinedStr, ast.BinOp)):
            parts = [c.value for c in ast.walk(e) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            if "".join(parts).strip(":-_/. "):
                return "f:" + "|".join(parts)
        return None

    def _is_jwt(self, call, info) -> bool:
        q = self._resolve_static(info.module, call.func, info) if isinstance(call.func, (ast.Name, ast.Attribute)) \
            else None
        return bool(q) and q.split(".")[0] == "jwt" and q.rsplit(".", 1)[-1] in ("encode", "decode")

    def _value_key_signature(self, call, info):
        """(v6c) The salt of a signing call (`salt=` of the call or of the Signer it is called on), or the key
        of a PyJWT encode / decode call (second argument or `key=`), in comparable form."""
        if self._is_jwt(call, info):
            k = next((x.value for x in call.keywords if x.arg == "key"), None)
            if k is None and len(call.args) >= 2:
                k = call.args[1]
            sig = self._salt_signature(k, info) if k is not None else None
            return "jwt:" + sig if sig else None
        k = next((x.value for x in call.keywords if x.arg == "salt"), None)
        if k is None and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
            k = next((x.value for x in call.func.value.keywords if x.arg == "salt"), None)
        return self._salt_signature(k, info) if k is not None else None

    def signed_readers(self, call, info) -> list:
        """(v6b) Project functions that read a signed value back with the same salt (`signing.loads(v, salt=S)`,
        `Signer(salt=S).unsign(v)`, (v6c) also a bare `loads(v, salt=S)` imported from django.core.signing, and
        `jwt.decode(v, KEY, ...)` for a `jwt.encode(p, KEY, ...)`); [] when the salt / key is not comparable or
        nothing reads it back."""
        sig = self._value_key_signature(call, info)
        if sig is None:
            return []
        index = self.__dict__.get("_reader_index")
        if index is None:
            index = {}
            for fq, finfo in self.p.functions.items():
                for n in self.p.walk_function_body(finfo.node):
                    if not isinstance(n, ast.Call):
                        continue
                    leaf = _leaf(n.func)
                    if leaf in self.READ_BACK_LEAVES:
                        if isinstance(n.func, ast.Name):
                            q = self._resolve_static(finfo.module, n.func, finfo) or ""
                            if not q.startswith("django.core.signing."):
                                continue
                        elif not isinstance(n.func, ast.Attribute):
                            continue
                    elif not (leaf == "decode" and self._is_jwt(n, finfo)):
                        continue
                    ks = self._value_key_signature(n, finfo)
                    if ks and fq not in index.setdefault(ks, []):
                        index[ks].append(fq)
            self._reader_index = index
        return sorted(index.get(sig, []))

    def _callers(self) -> dict:
        hit = self.__dict__.get("_callers_map")
        if hit is None:
            hit = {}
            for fq, finfo in self.p.functions.items():
                for site in self.a.cg.sites(fq):
                    for t, _ in self.a.cg.resolve(site, finfo.cls).targets:
                        hit.setdefault(t, set()).add(fq)
            self._callers_map = hit
        return hit

    def reader_issues(self, fq) -> tuple:
        """(v6c) (issues, complete, reaches) for a function that reads a value back.  `issues`: it, or a function
        that calls it (up to READER_UP levels: codec -> service -> view), reaches within READER_DOWN calls code
        that logs someone in, sets a password, calls a catalogued mint, writes a hand-rolled session login or
        authenticates the request (`request.user = ...`, `scope["user"] = ...`, the `authenticate()` of an
        authentication class).  `reaches`: the same at any depth.  `complete` is False when callers remain beyond
        READER_UP levels.  Promoting a value to a mint needs `issues`; setting a credential-looking value aside
        needs `complete` and not `reaches`."""
        memo = self.__dict__.setdefault("_reader_memo", {})
        if fq in memo:
            return memo[fq]
        callers = self._callers()
        seen, level = {fq}, {fq}
        for _ in range(self.READER_UP):
            nxt = set()
            for f in level:
                nxt |= callers.get(f, set()) - seen
            seen |= nxt
            level = nxt
            if not level:
                break
        complete = not any(callers.get(f, set()) - seen for f in level)
        dist = self.issuing_distance()
        best = min((dist[f] for f in seen if f in dist), default=None)
        memo[fq] = (best is not None and best <= self.READER_DOWN, complete, best is not None)
        return memo[fq]

    def issuing_distance(self) -> dict:
        """(v6c) {project function: number of resolved project calls to the nearest code that issues (see
        reader_issues)} for every function that reaches such code (0 = issues itself; computed once over the
        whole call graph)."""
        hit = self.__dict__.get("_issuing_dist")
        if hit is not None:
            return hit
        self._issuing_dist = {}          # recursion guard
        dist = {fq: 0 for fq in self.p.functions if self._issues_directly(fq)}
        callers = self._callers()
        level = list(dist)
        d = 0
        while level:
            d += 1
            nxt = []
            for n in level:
                for c in callers.get(n, ()):
                    if c not in dist:
                        dist[c] = d
                        nxt.append(c)
            level = nxt
        self._issuing_dist = dist
        return dist

    def _issues_directly(self, fq) -> bool:
        finfo = self.p.functions[fq]
        if self._authenticates_request(fq) or self.session_login_stores(fq):
            return True       # authenticates the request, or a hand-rolled session login (`session[SESSION_KEY]`)
        for site in self.a.cg.sites(fq):
            if site.leaf in self.ISSUING_LEAVES:
                return True
            res = self.a.cg.resolve(site, finfo.cls)
            for c in (res.library_candidates or ([res.library] if res.library else [])):
                api = self.a.catalog.mint_calls.get(c)
                if api is not None and not (api.heuristic and api.ref is None):
                    return True
        return False

    def _issues_credential(self, fq) -> bool:
        return self.reader_issues(fq)[0]

    def _authenticates_request(self, fq) -> bool:
        """(v6c) `request.user = <not None>` / `scope["user"] = ...` in the function, or the `authenticate` /
        `authenticate_credentials` method of a class with a library base returning a value."""
        info = self.p.functions.get(fq)
        if info is None:
            return False
        leaf = fq.rsplit(".", 1)[-1]
        if info.cls and leaf in ("authenticate", "authenticate_credentials") and \
                any(c not in self.p.classes for c in self.p.mro(info.cls)[1:]):
            return any(isinstance(n, ast.Return) and n.value is not None and
                       not (isinstance(n.value, ast.Constant) and n.value.value is None)
                       for n in self.p.walk_function_body(info.node))
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Assign) and not (isinstance(n.value, ast.Constant) and n.value.value is None):
                for t in n.targets:
                    if isinstance(t, ast.Attribute) and t.attr == "user" and "request" in _u(t.value):
                        return True
                    if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and \
                            t.slice.value == "user" and "scope" in _u(t.value):
                        return True
        return False

    LOOKUP_LEAVES = ("get", "filter", "aget", "afilter", "exclude", "get_object_or_404", "aget_object_or_404",
                     "get_or_create", "exists")

    def field_readers(self) -> dict:
        """(v6c) {field name: [functions]} for lookups by a field (`M.objects.get(code=v)`, `filter(user=u,
        code=v)`) and comparisons of a field with a request value (`obj.code == request.POST["code"]`)."""
        hit = self.__dict__.get("_field_readers")
        if hit is not None:
            return hit
        out: dict = {}
        inbound = ("POST", "GET", "data", "headers", "cleaned_data", "query_params", "META", "COOKIES")
        for fq, info in self.p.functions.items():
            for n in self.p.walk_function_body(info.node):
                fields, model = [], ""
                if isinstance(n, ast.Call) and _leaf(n.func) in self.LOOKUP_LEAVES:
                    m = self._lookup_model(n.func, info) or self._shortcut_model(n, info)
                    model = m.rsplit(".", 1)[-1] if m else ""
                    for k in n.keywords:
                        if k.arg:
                            parts = k.arg.split("__")
                            while len(parts) > 1 and parts[-1] in ("exact", "iexact", "in"):
                                parts.pop()
                            if len(parts) == 1:
                                fields.append(parts[-1])
                elif isinstance(n, ast.Compare):
                    sides = [n.left] + list(n.comparators)
                    if any(isinstance(y, ast.Attribute) and y.attr in inbound for x in sides for y in ast.walk(x)):
                        fields += [x.attr for x in sides if isinstance(x, ast.Attribute)]
                for f in fields:
                    row = out.setdefault(f, [])
                    if (fq, model) not in row:
                        row.append((fq, model))
        self._field_readers = out
        return out

    def weak_value_readers(self, names, owner="") -> str:
        """(v6c) '' when a value kept under `names` (on model `owner`) may be a credential by how it is read back;
        otherwise why not: no project code looks it up by that field (a lookup of that model, or of a model
        MintMap cannot name) or compares it with a request value.  Any reader keeps it: a key that authorises an
        action (ping-by-key, an API capability) is consumed without a login."""
        readers = sorted({r for n in names for r, m in self.field_readers().get(n, []) if not m or not owner or
                          m == owner})
        if not readers:
            return "no project code looks it up or compares it by that field (it is not checked as a credential)"
        return ""

    CACHE_READ_LEAVES = ("get", "pop", "get_many", "aget", "hget", "hgetall", "getdel")

    def _cache_reader_issuing(self, sink):
        """(v6c) A project function that reads the cache key pattern of this cache sink back
        (`cache.get(f"xfer:{n}")`) and that itself, or what it calls (READER_DOWN levels), logs someone in /
        authenticates a request / issues a credential; None otherwise.  Unlike signed values (often decoded in a
        codec layer), the caller of a cache reader is not considered: it may log someone in for other reasons."""
        pats = (self.__dict__.get("_cache_sink_patterns") or {}).get((sink.func, sink.line))
        if not pats:
            return None
        index = self.__dict__.get("_cache_reader_index")
        if index is None:
            index = {}
            for fq, info in self.p.functions.items():
                if "cache" not in " ".join(self.mentions(info)).lower() and "redis" not in \
                        " ".join(self.mentions(info)).lower():
                    continue
                for n in self.p.walk_function_body(info.node):
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                            n.func.attr in self.CACHE_READ_LEAVES and n.args:
                        for k in self.key_patterns(n.args[0], info):
                            if self.pattern_usable(k) and fq not in index.setdefault(k, []):
                                index[k].append(fq)
            self._cache_reader_index = index
        for pat in sorted(pats):
            for r in index.get(pat, []):
                d = self.issuing_distance().get(r)
                if r != sink.func and d is not None and d <= self.READER_DOWN:
                    return r      # the reader itself (or what it calls) issues: no caller-side guessing here
        return None

    def authenticator_lookup_fields(self) -> set:
        """(v6c) {(model short name or '' when unknown, field)} that project code authenticating requests looks a
        value up by (`Profile.objects.filter(integration_token=raw)`) in a function that sets request.user /
        scope["user"] or is the `authenticate()` of an authentication class."""
        hit = self.__dict__.get("_auth_lookup_fields")
        if hit is not None:
            return hit
        out = set()
        self._auth_lookup_fields = out
        for fq, info in self.p.functions.items():
            if not self.mentions(info) & {"user", "authenticate", "authenticate_credentials", "scope"}:
                continue
            if not self._authenticates_request(fq):
                continue
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Call) and _leaf(n.func) in ("get", "filter", "aget", "afilter", "first",
                                                                  "get_object_or_404", "exclude"):
                    m = self._lookup_model(n.func, info) or self._shortcut_model(n, info)
                    for k in n.keywords:
                        if k.arg and k.arg not in ("pk", "id") and "__" not in k.arg.replace("__exact", ""):
                            out.add((m.rsplit(".", 1)[-1] if m else "", k.arg.replace("__exact", "")))
        return out

    def looked_up_by_authenticator(self, sink) -> bool:
        """(v6c) A field of this sink's model is how a project authenticator finds the requester."""
        owner = sink.owner or ""
        # a known model must match; a sink whose model MintMap could not type matches by the field name
        return any(f in sink.names and (m == owner or not owner) for m, f in self.authenticator_lookup_fields())

    def _parents(self, info) -> dict:
        memo = self.__dict__.setdefault("_parent_maps", {})
        hit = memo.get(info.qualname)
        if hit is None:
            hit = {}
            for n in self.p.walk_function_body(info.node):
                for ch in ast.iter_child_nodes(n):
                    hit[id(ch)] = n
            memo[info.qualname] = hit
        return hit

    def _kept_names(self, info, call, _depth=0) -> list:
        """Names of the places a call's value is kept: assignment targets, the enclosing function when it is
        returned, keyword / dict-key names, the callee it is handed to (through string building)."""
        par = self._parents(info)
        node, names = call, []
        for _ in range(8):
            up = par.get(id(node))
            if up is None:
                break
            if isinstance(up, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)) or (
                    isinstance(up, ast.Call) and node in up.args and _leaf(up.func) in self.STRING_BUILDERS):
                node = up
                continue
            if isinstance(up, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                tgts = up.targets if isinstance(up, ast.Assign) else [up.target]
                for t in tgts:
                    if isinstance(t, ast.Name):
                        names.append(t.id)
                        if _depth == 0:
                            names += self._uses_of(info, t.id)
                    elif isinstance(t, ast.Attribute):
                        names.append(t.attr)
                    elif isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and \
                            isinstance(t.slice.value, str):
                        names.append(t.slice.value)
            elif isinstance(up, ast.Return):
                names.append(info.qualname.rsplit(".", 1)[-1])
            elif isinstance(up, ast.keyword) and up.arg:
                names.append(up.arg)
            elif isinstance(up, ast.Dict):
                for k, v in zip(up.keys, up.values):
                    if v is node and isinstance(k, ast.Constant) and isinstance(k.value, str):
                        names.append(k.value)
            elif isinstance(up, ast.Call):
                leaf = _leaf(up.func)
                if leaf in ("set_cookie", "set_signed_cookie") and up.args and up.args[0] is not node:
                    k0 = up.args[0]
                    c = k0.value if isinstance(k0, ast.Constant) and isinstance(k0.value, str) else \
                        self.module_str_constant(info.module, k0, info)
                    names.append(c or _leaf(k0) if isinstance(k0, (ast.Name, ast.Attribute)) else (c or "cookie"))
                elif leaf:
                    names.append(leaf)
            break
        return [n for n in names if n]

    def _uses_of(self, info, var) -> list:
        """Where a local holding the value goes next (one level): returned, a keyword, a dict key, a callee."""
        out = []
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Name) and n.id == var and isinstance(n.ctx, ast.Load):
                out += [x for x in self._kept_names(info, n, _depth=1) if x != var]
        return out

    def _principal_payload(self, call, info):
        if not call.args:
            return None
        roots = [call.args[0]]
        if isinstance(call.args[0], ast.Name):        # `payload = {...}; signer.sign_object(payload)`
            roots += self.local_assignments(info).get(call.args[0].id, [])
        for n in (x for r in roots for x in ast.walk(r)):
            if isinstance(n, ast.Dict):
                # (v6c) a payload key that names a principal (`{"user": p.pk}`, `{"uid": u.pk}`, a JWT `sub`)
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and \
                            (words(k.value) & self.PRINCIPAL_NOUNS or k.value in ("uid", "sub")) and \
                            isinstance(v, ast.Attribute) and v.attr in self.PRINCIPAL_ATTRS:
                        return f"{k.value!r}: {_u(v)}"
            if isinstance(n, ast.Attribute) and n.attr in self.PRINCIPAL_ATTRS:
                base = n.value
                chain = []
                while isinstance(base, ast.Attribute):
                    chain.append(base.attr)
                    base = base.value
                if isinstance(base, ast.Name):
                    chain.append(base.id)
                if any(words(c) & self.PRINCIPAL_NOUNS for c in chain):
                    return _u(n)
                if chain == ["self"] and info.cls and self.is_model(info.cls) and self.principal_like(info.cls):
                    # (v6c) `self.pk` in a method of the user model (or another principal-like model)
                    return f"{_u(n)} of {info.cls.rsplit('.', 1)[-1]}"
        return None

    # ------------------------------------------------------------------ label expansion
    def sources_of(self, labels, _seen=None) -> set:
        out = set()
        _seen = set() if _seen is None else _seen
        for lb in labels:
            if lb[0] == "src":
                out.add(lb)
            elif lb[0] == "ret" and lb[1] not in _seen:
                _seen.add(lb[1])
                if lb[1] in self._ret_cache:
                    out |= self._ret_cache[lb[1]]
                    continue
                r = self.sources_of(self.fn(lb[1]).returns, _seen)
                self._ret_cache[lb[1]] = r
                out |= r
        return out

    def generator_functions(self, labels) -> list:
        return sorted({lb[1] for lb in labels if lb[0] == "ret"})

    # ------------------------------------------------------------------ decision
    def decide(self, sink: Sink, extra_context=(), strong_only=False):
        """(purpose, "") when the value kept at this sink looks like a credential, else (None, reason)."""
        sink_words = _qualified(set().union(*(words(x) for x in sink.names)) if sink.names else set())
        ctx_words = set().union(*(words(x) for x in list(sink.context) + list(extra_context))) \
            if (sink.context or extra_context) else set()
        owner_words = words(sink.owner) if sink.owner else set()
        if self.looked_up_by_authenticator(sink):
            # (v6c) a project authentication class / request authenticator looks requests up by this field
            # (`Profile.objects.get(integration_token=raw)` -> request.user): an inbound credential, whatever
            # integration word its name carries
            sink_words = sink_words | {"token"}
        elif (owner_words | words(sink.receiver)) & NEGATIVE_OWNER:
            return None, f"kept on {sink.owner} ({', '.join(sorted(owner_words & NEGATIVE_OWNER))}: an outbound " \
                         f"integration secret, not a login credential)"
        if sink_words & NEGATIVE_OWNER and not self.looked_up_by_authenticator(sink):
            # (v6b) `webhook_token`, `callback_secret`: the integration word qualifies the credential noun, whatever
            # the head noun is (an integration secret, not a login credential)
            return None, f"kept as {sink.names} ({', '.join(sorted(sink_words & NEGATIVE_OWNER))}: an " \
                         f"integration secret, not a login credential)"
        neg = sorted(sink_words & NEGATIVE)
        # the head noun (last word) of a compound name decides between a credential word and a non-credential word:
        # `uuid_owner_secret` is a secret, `secret_key_name` / `cache_key` / `job_id` are not credentials
        heads = {_head(x) for x in sink.names}
        if neg and not (heads & STRONG and not heads & NEGATIVE):
            return None, f"kept as {sink.names} ({', '.join(neg)}: not a credential name)"
        ctx_words = _qualified(ctx_words)
        # (v5 review) the owner's name qualifies like the field's (`AccessKey.digest`, `ApiKey.prefix`)
        owner_q = _qualified(owner_words)
        strong = (sink_words | ctx_words | owner_q) & STRONG
        weak = (sink_words & WEAK) if sink.kind != "return" and not strong_only else set()
        owner_head = _head(sink.owner) if sink.owner else ""
        if owner_head in WEAK and sink.kind != "return" and not strong_only:
            # (v5 review) a model named after a credential (`ServiceKey`, `DeviceKey`, `LoginCode`): any field of it
            # that keeps the value (`digest`, `prefix`, `value`) holds that credential
            weak = weak | {owner_head}
        if not strong and not weak:
            if strong_only and sink_words & WEAK:
                return None, f"kept as {sink.names}: a uuid4 value needs a strong credential word (uuid4 is " \
                             f"mostly an identifier generator)"
            return None, f"kept as {sink.names or '?'}: no credential word where it is kept"
        if not strong and weak:
            # (v5 review) a weak word alone (`code`, `key`, `pin`, `session`; no qualifier such as api_/login_)
            # counts only where the value belongs to a principal (a session, a per-subject cache key, the user model
            # or a model related to it) or on a model named after a credential (`DeployKey.key`); a coupon / gift
            # card / room / short-link code is not a login credential
            if not (sink.principal or owner_head in POSITIVE):
                return None, f"kept as {sink.names} on {sink.owner or 'an object of unknown type'}: a weak " \
                             f"credential word ({', '.join(sorted(weak))}) without a qualifier, a credential-named " \
                             f"owner or a link to a user"
            if sink.kind in ("model_create", "attribute") and owner_head not in POSITIVE:
                # (v6c) a weak word on a model linked to a user (a booking reference, a coupon code) is a credential
                # only if project code reads it back by that field (a lookup or a comparison with a request value)
                why = self.weak_value_readers(sink.names, sink.owner)
                if why:
                    return None, f"kept as {sink.names} on {sink.owner}: a weak credential word " \
                                 f"({', '.join(sorted(weak))}) and {why}"
        allw = sink_words | ctx_words | owner_words
        if "api" in allw and allw & {"key", "keys", "token", "tokens"}:
            allw = allw | {"apikey"}
        for purpose, fam in PURPOSE_FAMILIES:
            if allw & fam:
                return purpose, ""
        return GENERIC_PURPOSE, ""

    # ------------------------------------------------------------------ whole project
    def run(self):
        if self._done:
            return
        self._done = True
        self._model_defaults()
        default_gens = {g for v in self.default_models.values() for _f, g, _p in v} | self._default_gen_seen
        by_source: dict = {}
        for qn in sorted(self.relevant_functions()):
            t = self.fn(qn)
            for s in t.sinks:
                gens = [g.rsplit(".", 1)[-1] for g in self.generator_functions(s.labels)]
                for src in self.sources_of(s.labels):
                    by_source.setdefault(src, []).append((s, gens))
        pos = {}
        for (_k, fq, nid) in by_source:
            src = next(((n, sym, line) for n, sym, line in self.fn(fq).sources if id(n) == nid), None)
            if src is not None:
                pos[(fq, nid)] = (src[2], getattr(src[0], "col_offset", 0))
        for (_k, fq, nid), sinks in sorted(by_source.items(), key=lambda kv: (kv[0][1], pos.get((kv[0][1], kv[0][2]),
                                                                                              (0, 0)))):
            src = next(((n, sym, line) for n, sym, line in self.fn(fq).sources if id(n) == nid), None)
            if src is None:
                continue
            node, sym, line = src
            held = [k for k, v in self.fn(fq).locals.items() if ("src", fq, nid) in v]
            kept, why = [], []
            for s, gens in sinks:
                purpose, reason = self.decide(s, extra_context=held + gens, strong_only=sym in IDENTIFIER_SOURCES)
                if purpose:
                    kept.append((SINK_RANK.get(s.kind, 9), purpose == GENERIC_PURPOSE, purpose, s))
                else:
                    why.append(reason)
            if kept and all(s.kind == "return" and s.func in default_gens for *_x, s in kept):
                # the function is a model field default: its use is reported at the model's creation sites
                self.rejected.append(dict(function=fq, line=line, source=sym, reasons=[
                    "only returned by a model field default generator (reported at the creation sites)"]))
                continue
            if kept and self._only_consumers(fq, nid, UNUSABLE_PASSWORD_CALLS):
                self.rejected.append(dict(function=fq, line=line, source=sym, reasons=[
                    "a random password that only set_password/make_password receive (nobody is given it: it "
                    "disables password login)"]))
                continue
            if not kept:
                # (v6c) a value kept in a cache (in the key, `cache.set(f"xfer:{nonce}", ...)`, or as the value)
                # that project code reads back with the same key pattern to log someone in or authenticate a
                # request is a credential whatever it is called (a cross-domain hand-off nonce)
                for s_, _gens in sinks:
                    issuer = self._cache_reader_issuing(s_) if s_.kind == "cache" else None
                    if issuer:
                        kept.append((SINK_RANK.get(s_.kind, 9), True, GENERIC_PURPOSE, s_))
                        s_.detail += f"; read back from the cache by {issuer}, which logs someone in"
                        break
            if not kept:
                row = dict(function=fq, line=line, source=sym, reasons=sorted(set(why))[:3])
                named = {w for s_, _g in sinks for n in s_.names for w in words(n)}
                if any(watchable_rejection(r) for r in why) or named & (STRONG | AUTH_NAME_WORDS):
                    # (v6c) set aside by a judgement (no credential word, a weak word nobody checks, an
                    # integration word ...), not by an identifier name: watched (fingerprinted and diffed)
                    row["watch"] = "random_value"
                self.rejected.append(row)
                continue
            if any(c.func == fq and c.line == line for c in self.candidates.values()):
                continue      # several sources in one statement (`uuid4().hex + uuid4().hex`): one mint site
            if "migrations" in self.p.modules[self.p.functions[fq].module].path.replace("\\", "/").split("/"):
                self.rejected.append(dict(function=fq, line=line, source=sym, reasons=[
                    "in a Django migration (runs once at deploy time, not on a request)"]))
                continue
            kept.sort(key=lambda x: (x[0], x[1]))
            purpose = kept[0][2]
            ks = [x[3] for x in kept]
            self.candidates[nid] = Candidate(fq, node, sym, line, purpose, ks,
                                             sorted({nm for x in ks for nm in x.names}), "source")

    def _only_consumers(self, fq, nid, leaves) -> bool:
        """True when every use of the value of source `nid` in `fq` (the source call itself, and every read of a
        variable holding it) sits inside a call to one of `leaves` (e.g. make_password / set_password): the value
        is never returned, stored elsewhere, sent or rendered."""
        t = self.fn(fq)
        holders = {k for k, v in t.locals.items() if ("src", fq, nid) in v}
        info = self.p.functions[fq]
        parent = {}
        for n in self.p.walk_function_body(info.node):
            for ch in ast.iter_child_nodes(n):
                parent[id(ch)] = n
        uses = []
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in holders:
                uses.append(n)
            elif id(n) == nid:
                p = parent.get(id(n))
                while isinstance(p, (ast.Attribute, ast.Call, ast.Subscript)) and not _is_leaf_call(p, leaves):
                    p = parent.get(id(p))
                if not (isinstance(p, (ast.Assign, ast.AnnAssign)) and all(
                        isinstance(tg, ast.Name) and tg.id in holders
                        for tg in (p.targets if isinstance(p, ast.Assign) else [p.target]))):
                    uses.append(n)
        found = False
        for u in uses:
            p = parent.get(id(u))
            while p is not None and not isinstance(p, ast.stmt):
                if _is_leaf_call(p, leaves):
                    found = True
                    break
                p = parent.get(id(p))
            else:
                return False
        return found

    # ------------------------------------------------------------------ (ii) model field defaults
    def _model_defaults(self):
        per_class: dict = {}
        for cq in sorted(self.p.classes):
            if not self.is_model(cq):
                continue
            found = []
            for c in self.p.mro(cq):
                if c not in self.p.classes:
                    continue
                if c not in per_class:
                    per_class[c] = self._class_defaults(c)
                found += [x for x in per_class[c] if x[0] not in {f for f, _g, _p in found}]
            if found:
                self.default_models[cq] = found

    def _class_defaults(self, c) -> list:
        """[(field, generator, purpose)] for the fields a model class declares with a credential generator as
        default (fields of base models are collected by the caller)."""
        out = []
        cc = self.p.classes[c]
        for st in cc.node.body:
            if not (isinstance(st, (ast.Assign, ast.AnnAssign)) and isinstance(st.value, ast.Call)):
                continue
            tgt = st.targets[0] if isinstance(st, ast.Assign) else st.target
            if not isinstance(tgt, ast.Name):
                continue
            d = next((k.value for k in st.value.keywords if k.arg == "default"), None)
            if d is None:
                continue
            gen = self._default_generator(d, cc.module)
            if not gen:
                continue
            if gen in self.p.functions:
                self._default_gen_seen.add(gen)
            ftype = st.value.func.attr if isinstance(st.value.func, ast.Attribute) else (
                st.value.func.id if isinstance(st.value.func, ast.Name) else "")
            if any(k.arg == "primary_key" and isinstance(k.value, ast.Constant) and k.value.value
                   for k in st.value.keywords):
                self.rejected.append(dict(function=c, line=st.lineno, source=gen,
                                          reasons=[f"default of the primary key {tgt.id}"]))
                continue
            if ftype == "UUIDField" and not (words(tgt.id) & STRONG):
                self.rejected.append(dict(function=c, line=st.lineno, source=gen, reasons=[
                    f"{tgt.id} is a UUIDField whose name has no strong credential word: an identifier"]))
                continue
            sink = Sink("model_default", c, st.lineno, [tgt.id], [], frozenset(),
                        f"{c}.{tgt.id} = ...(default={_u(d)})", owner=c.rsplit(".", 1)[-1],
                        principal=self.links_user(c))
            self.default_field_nodes.setdefault(c, []).append((tgt.id, st, gen))
            purpose, reason = self.decide(sink, extra_context=[gen.rsplit(".", 1)[-1]],
                                          strong_only=gen in IDENTIFIER_SOURCES)
            if purpose:
                out.append((tgt.id, gen, purpose))
            else:
                self.rejected.append(dict(function=c, line=st.lineno, source=gen, reasons=[reason]))
        return out

    def default_field_code(self, model) -> list:
        """(v5 review) Text parts for the fingerprint of a path that creates `model` with a credential default: the
        field declarations (with their default) and the source of project generator functions (and what those
        call), so weakening the generator changes the path."""
        out = []
        for c in self.p.mro(model):
            for fname, st, gen in self.default_field_nodes.get(c, []):
                out.append(f"default_field:{c}.{fname}:" + _dump(st))
                if gen in self.p.functions:
                    closure, _trunc = self.a.project_closure([gen], self.a.fp_depth)
                    for q in sorted(closure | {gen}):
                        if q in self.p.functions:
                            out.append(f"default_gen:{q}:" + self.a.inliner.function_dump(q))
        return out

    def _default_generator(self, d, module):
        """Description of a credential generator used as a field default, or None."""
        if isinstance(d, ast.Lambda):
            for n in ast.walk(d.body):
                if isinstance(n, ast.Call):
                    g = self._default_generator(n.func, module)
                    if g:
                        return g
            return None
        if isinstance(d, ast.Call):
            g = self._default_generator(d.func, module)
            if g:
                return g
            for a in d.args:
                g = self._default_generator(a, module)
                if g:
                    return g
            return None
        q = self._resolve_static(module, d)
        if q in SOURCES or q in self.a.catalog.secret_generators:
            return q
        if q in self.p.functions and self.sources_of(self.fn(q).returns):
            return q
        return None

    def _built_on_instance(self, info, var) -> bool:
        """`var = SomeSerializer(obj, data=...)` / `SomeForm(..., instance=obj)` in the function: an update."""
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == var for t in n.targets) and \
                    isinstance(n.value, ast.Call):
                c = n.value
                if any(k.arg == "instance" for k in c.keywords):
                    return True
                q = self._resolve_static(info.module, c.func, info)
                if q in self.p.classes and c.args and any(
                        b.startswith("rest_framework.serializers") for b in self.p.mro(q)):
                    return True
        return False

    UPDATE_VIEWS = ("django.views.generic.UpdateView", "django.views.generic.edit.UpdateView",
                    "django.views.generic.edit.BaseUpdateView")

    def _update_hook_param(self, info, var) -> bool:
        """(v6) the serializer DRF passes to `perform_update(self, serializer)` (built on the instance being
        updated, rest_framework/mixins.py:63-78), or the form Django passes to `form_valid(self, form)` of an
        UpdateView (built with instance=self.object, django/views/generic/edit.py:110-115, 200-206): save() updates."""
        args = [a.arg for a in info.node.args.posonlyargs + info.node.args.args]
        if len(args) < 2 or args[1] != var or not info.cls:
            return False
        leaf = info.qualname.rsplit(".", 1)[-1]
        if leaf == "perform_update":
            return True
        return leaf == "form_valid" and any(c in self.UPDATE_VIEWS for c in self.p.mro(info.cls))

    # ------------------------------------------------------------------ mints at call sites
    def creation_candidate(self, site, res, ctx):
        """(ii) a project call that creates a model whose field default is a credential generator."""
        if not self.default_models or not isinstance(site.node, ast.Call):
            return None
        info = self.p.functions[site.func]
        model, how = self._creation_model(site.node, info, ctx)
        if model and model.startswith("param:"):
            return None
        if model is None:
            # serializer / form save, or super().create() inside a ModelSerializer: the library creates Meta.model
            leaf = site.leaf
            owner = None
            if leaf == "save" and res.receiver_type in self.p.classes:
                owner = res.receiver_type
                r = self.p.lookup_method(owner, "create")
                if r and r[0] == "project":
                    owner = None      # the project create() is analysed instead
                elif res.receiver_var and (self._built_on_instance(info, res.receiver_var) or
                                           self._update_hook_param(info, res.receiver_var)):
                    owner = None      # Serializer(instance, data=...) / Form(instance=...): save() updates
            elif leaf in ("create", "save") and res.via == "super" and info.cls:
                owner = ctx or info.cls
            if owner:
                model = self.model_meta(owner)
                how = f"{owner.rsplit('.', 1)[-1]}.{leaf}"
        if model and model in self.default_models:
            if how == "constructor" and not self._constructed_instance_escapes(info, site.node):
                return None
            fields = self.default_models[model]
            return model, how, fields
        return None

    def _constructed_instance_escapes(self, info, call) -> bool:
        """`x = M(...)` creates a row only when `x` is saved, returned or handed to a collection / bulk_create; a
        temporary instance used for its attribute defaults is not a creation.  A constructor that is not assigned
        to a plain name is counted (conservative)."""
        var = None
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is call:
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                if len(tgts) == 1 and isinstance(tgts[0], ast.Name):
                    var = tgts[0].id
                break
        if var is None:
            return True
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Return) and n.value is not None and any(
                    isinstance(x, ast.Name) and x.id == var
                    for x in ([n.value] + (list(n.value.elts) if isinstance(n.value, (ast.Tuple, ast.List)) else []))):
                return True     # the instance itself is returned (not just an attribute of it)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr in ("save", "asave", "full_clean") and isinstance(n.func.value, ast.Name) and \
                        n.func.value.id == var:
                    return True
                if n.func.attr in ESCAPE_CALLS and any(isinstance(x, ast.Name) and x.id == var
                                                       for a in n.args for x in ast.walk(a)):
                    return True
        return False


SOURCE_LEAVES = {s.rsplit(".", 1)[-1] for s in SOURCES}
RANDOM_SELECTORS = {"random.choice", "random.choices", "random.sample"}
# a value kept at several places is reported once; its purpose comes from the most specific place
SINK_RANK = {"attribute": 0, "model_create": 0, "serializer_save": 0, "model_default": 0, "session": 1, "cache": 1,
             "return": 2, "credential_call": 3}
UNUSABLE_PASSWORD_CALLS = {"set_password", "make_password"}
ESCAPE_CALLS = {"bulk_create", "abulk_create", "append", "extend", "add", "insert", "save", "create"}
TRANSFORM_LEAVES = {"hex", "lower", "upper", "decode", "encode", "strip", "replace", "join", "hexlify", "b64encode",
                    "urlsafe_b64encode", "zfill"}


RELATION_FIELDS = {"ForeignKey", "OneToOneField", "ManyToManyField", "ParentalKey"}


# (v6c) words that make a name vetoed as an identifier / URL / nonce worth watching (`magic_url`, `signin_nonce`)
AUTH_NAME_WORDS = {"signin", "login", "auth", "sso", "handoff", "session", "access"}


def watchable_rejection(reason: str) -> bool:
    """(v6c) A rejection of a random value that is a judgement MintMap may get wrong on unseen code (the value is
    watched), as opposed to a name that says it is an identifier, a file, a cache key ... (`... not a credential
    name`)."""
    return "not a credential name" not in reason


def _leaf(f) -> str:
    return f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")


def _first_word(name: str) -> str:
    parts = [p for p in _SPLIT.split(name or "") if p]
    return parts[0].lower() if parts else ""


def _head(name: str) -> str:
    parts = [p for p in _SPLIT.split(name or "") if p]
    return parts[-1].lower() if parts else ""


def _is_leaf_call(n, leaves) -> bool:
    if not isinstance(n, ast.Call):
        return False
    leaf = n.func.attr if isinstance(n.func, ast.Attribute) else (n.func.id if isinstance(n.func, ast.Name) else "")
    return leaf in leaves


def _qualified(ws: set) -> set:
    """A weak credential word next to a qualifier is strong (`session_key` -> + sessionkey/secret marker).
    (v6b) The qualifier must be another word: `session` is both, and `_session_wizard_prefix` is not qualified."""
    weak, qual = ws & WEAK, ws & QUALIFIERS
    if weak and qual and len(weak | qual) >= 2:
        return ws | {"credential"}
    return ws


def _words_hit(ws, vocab) -> bool:
    return bool(ws & vocab)


def _ctx_names(expr, holders) -> list:
    return sorted({n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and n.id in holders})


def _dict_keys_holding(expr, local, lab) -> list:
    out = []
    for n in ast.walk(expr):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and lab(v, local):
                    out.append(k.value)
    return out


def _dump(n) -> str:
    from .fingerprint import normalize
    return normalize(n)


def _u(n) -> str:
    try:
        s = stable_unparse(n)
    except Exception:  # pragma: no cover - defensive
        s = type(n).__name__
    return s if len(s) <= 100 else s[:97] + "..."


def heuristic_api(symbol, purpose, basis, note="") -> MintAPI:
    return MintAPI(symbol=symbol, ref=None, purpose=purpose, purpose_basis=basis, kind=HEURISTIC_KIND,
                   heuristic=True, source_location=None)

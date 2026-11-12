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
            if sym in SOURCES and self._is_generator_call(c, sym, info):
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
                if sym in SOURCES and self._is_generator_call(n, sym, info):
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
        for leaf in SOURCE_LEAVES | {"SystemRandom"}:
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

    def _creation_model(self, call, info, ctx):
        """Project model created by this call: `M(...)`, `M.objects.<create>(...)` (also `M.objects.filter(...)
        .<create>`)."""
        f = call.func
        q = self._resolve_static(info.module, f, info)
        if q and q in self.p.classes and self.is_model(q):
            return q, "constructor"
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
            for k, v in fields:
                t.sinks.append(Sink("model_create", qn, n.lineno, [k], _ctx_names(v, holders),
                                    frozenset(lab(v, local)), f"{_u(n.func)}({k}=...) creates "
                                                              f"{model if not pm else 'the model passed as ' + pm}",
                                    owner="" if pm else model.rsplit(".", 1)[-1],
                                    principal=False if pm else self.links_user(model), owner_param=pm))
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
                t.sinks.append(Sink("cache", qn, n.lineno, names, _ctx_names(n, holders), frozenset(labs),
                                    f"{_u(n.func)}(...)", principal=per_subject))
            return
        if leaf and _words_hit(words(leaf), POSITIVE) and leaf not in SOURCE_LEAVES:
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
    def auth_session_keys(self) -> dict:
        """{session key: [functions that use it to load a principal]}: a value read from `x.session.get(K)` /
        `x.session[K]` that (directly or through a local variable) is a `pk=` / `id=` / `*_id=` lookup argument
        is how the project authenticates a second kind of principal (`request.customer = Customer.objects
        .filter(pk=request.session.get("customer_id")).first()`).  Django's own SESSION_KEY is always one."""
        hit = getattr(self, "_auth_session_keys", None)
        if hit is not None:
            return hit
        out = {"_auth_user_id": ["django.contrib.auth (SESSION_KEY written without login())"]}

        def session_key_read(e):
            if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr in ("get", "pop") and \
                    isinstance(e.func.value, ast.Attribute) and e.func.value.attr == "session" and e.args and \
                    isinstance(e.args[0], ast.Constant) and isinstance(e.args[0].value, str):
                return e.args[0].value
            if isinstance(e, ast.Subscript) and isinstance(e.ctx, ast.Load) and isinstance(e.value, ast.Attribute) \
                    and e.value.attr == "session" and isinstance(e.slice, ast.Constant) and \
                    isinstance(e.slice.value, str):
                return e.slice.value
            return None
        for qn, info in self.p.functions.items():
            body = list(self.p.walk_function_body(info.node))
            if not any(isinstance(n, ast.Attribute) and n.attr == "session" for n in body):
                continue
            held = {}
            for n in body:
                if isinstance(n, ast.Assign):
                    ks = {session_key_read(x) for x in ast.walk(n.value)} - {None}
                    for tg in n.targets:
                        if isinstance(tg, ast.Name) and ks:
                            held.setdefault(tg.id, set()).update(ks)
            for n in body:
                if not isinstance(n, ast.Call):
                    continue
                for k in n.keywords:
                    if not k.arg or not (k.arg in ("pk", "id") or k.arg.endswith(("_id", "_pk", "__pk", "__id"))):
                        continue
                    ks = {session_key_read(x) for x in ast.walk(k.value)} - {None}
                    ks |= {kk for x in ast.walk(k.value) if isinstance(x, ast.Name) for kk in held.get(x.id, ())}
                    for key in ks:
                        if qn not in out.setdefault(key, []):
                            out[key].append(qn)
        self._auth_session_keys = out
        return out

    def session_login_stores(self, qn) -> list:
        """[(statement, key, consumers)]: `x.session[K] = v` in `qn` where K is an authentication session key."""
        keys = self.auth_session_keys()
        out = []
        for n in self.p.walk_function_body(self.p.functions[qn].node):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for tg in tgts:
                    if isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Attribute) and \
                            tg.value.attr == "session" and isinstance(tg.slice, ast.Constant) and \
                            tg.slice.value in keys:
                        out.append((n, tg.slice.value, keys[tg.slice.value]))
        return out

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
        if (owner_words | words(sink.receiver)) & NEGATIVE_OWNER:
            return None, f"kept on {sink.owner} ({', '.join(sorted(owner_words & NEGATIVE_OWNER))}: an outbound " \
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
                self.rejected.append(dict(function=fq, line=line, source=sym, reasons=sorted(set(why))[:3]))
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
        if q in SOURCES:
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
                elif res.receiver_var and self._built_on_instance(info, res.receiver_var):
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


def _head(name: str) -> str:
    parts = [p for p in _SPLIT.split(name or "") if p]
    return parts[-1].lower() if parts else ""


def _is_leaf_call(n, leaves) -> bool:
    if not isinstance(n, ast.Call):
        return False
    leaf = n.func.attr if isinstance(n.func, ast.Attribute) else (n.func.id if isinstance(n.func, ast.Name) else "")
    return leaf in leaves


def _qualified(ws: set) -> set:
    """A weak credential word next to a qualifier is strong (`session_key` -> + sessionkey/secret marker)."""
    if ws & WEAK and ws & QUALIFIERS:
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

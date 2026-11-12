"""Static URLconf extraction (no imports, no execution).

v3 (P4, P5).  The statements of a URLconf module are evaluated *in order* by a small abstract
interpreter instead of being pattern-matched one by one:

* a URL list is an object (`UList`) whose identity matters: `include(x)` sees later in-place
  changes of `x` (`x += [...]`, `x.extend()`, `x.append()`, `x.insert()`), while copies
  (`list(x)`, `x + y`, `[*x]`, `i18n_patterns(*x)`) take a snapshot at the point where they are made;
* `if`/`else` blocks, `match` cases and both arms of `a if c else b` are all evaluated (their patterns
  are marked `conditional`), `try`/`with` blocks are entered, and `for` loops (and comprehensions) are
  unrolled when the iterable is a statically known list of strings (a literal, a module constant or a
  literal settings value; a loop over a settings value is `conditional`, a literal one is not);
  otherwise the body is evaluated once with the loop variable unknown and an explicit gap is recorded;
* project **URL helper functions** (`def api_path(route, **handlers): return path(route, dispatch,
  handlers)`) are expanded by binding their parameters to the call-site arguments and evaluating the
  body with the same interpreter, so the route and view resolve through the helper's parameters;
  a project function called as a statement with a URL list argument (`add_routes(urlpatterns)`) is run
  with its parameter bound to the same list object; any other callee receiving a URL list is a gap;
* `(patterns, app_name)` tuples are unwrapped wherever a pattern list is expected;
* callables passed in a route's extra-kwargs dict (`path(r, dispatcher, {"POST": view})`) become
  **dispatch targets** of that route (the dispatcher is recorded and its code is fingerprinted);
* route strings are evaluated symbolically: literals, f-strings, `+`, module constants, literal
  settings values; a value chosen at runtime becomes a named placeholder (`{prefix}admin/`), which
  still allows two routes built from the same placeholder to be compared (P5);
* `i18n_patterns()` adds a `{lang}/` prefix (it was a plain pass-through before);
* `mark_shadowing()` models Django's first-match resolution for literal-equal routes (P5).

Every construct that is still not understood produces an explicit gap.
"""
from __future__ import annotations

import ast
import dataclasses
import itertools
import re
from dataclasses import dataclass, field

from .fingerprint import stable_unparse
from .project import Project, Gap

PATH_FUNCS = {"django.urls.path", "django.urls.re_path", "django.conf.urls.url", "django.conf.urls.re_path",
              "django.urls.conf.path", "django.urls.conf.re_path"}
REGEX_FUNCS = {"django.urls.re_path", "django.conf.urls.url", "django.conf.urls.re_path", "django.urls.conf.re_path"}
INCLUDE_FUNCS = {"django.urls.include", "django.conf.urls.include", "django.urls.conf.include"}
I18N_FUNCS = {"django.conf.urls.i18n.i18n_patterns"}
PASSTHROUGH_FIRST_FUNCS = {"rest_framework.urlpatterns.format_suffix_patterns"}
NON_AUTH_PATTERN_FUNCS = {"django.conf.urls.static.static",
                          "django.contrib.staticfiles.urls.staticfiles_urlpatterns"}
COPY_FUNCS = {"builtins.list", "builtins.tuple", "builtins.sorted"}
IMPORT_STRING_FUNCS = {"django.utils.module_loading.import_string"}
SETTINGS_OBJECTS = ("django.conf.settings",)
MAX_UNROLL = 64           # loop / comprehension iterations unrolled
MAX_HELPER_DEPTH = 4      # nested URL helper expansions
MAX_DEPTH = 40            # recursion guard for value evaluation
LIST_MUTATORS = ("append", "extend", "insert")
# route kinds that are a single endpoint (compared for first-match shadowing)
ENDPOINT_KINDS = ("project_function", "project_class", "library_view")


def _u(n) -> str:
    try:
        s = stable_unparse(n)
    except Exception:
        s = type(n).__name__
    return s if len(s) <= 100 else s[:97] + "..."


# ------------------------------------------------------------------ route text
def _join(prefix: str, route: str) -> str:
    if prefix and route.startswith("^"):
        route = route[1:]
    if prefix.endswith("$"):
        prefix = prefix[:-1]
    return prefix + route


@dataclass(frozen=True)
class RT:
    """A (partially) evaluated route / string.

    text  -- what is shown (`{prefix}admin/`, `<dynamic>login/`)
    key   -- comparison key; placeholders are qualified (`{hc.urls.prefix#1}`), None if a part is
             an unknown runtime value (then the route is never claimed to be literal-equal)
    dyn   -- contains a part chosen at runtime (a gap is recorded for the route)
    regex -- built with re_path()/url() somewhere along the include chain
    """
    text: str
    key: str | None
    dyn: bool = False
    regex: bool = False

    def join(self, other: "RT") -> "RT":
        key = _join(self.key, other.key) if self.key is not None and other.key is not None else None
        return RT(_join(self.text, other.text), key, self.dyn or other.dyn, self.regex or other.regex)

    def concat(self, other: "RT") -> "RT":
        key = self.key + other.key if self.key is not None and other.key is not None else None
        return RT(self.text + other.text, key, self.dyn or other.dyn, self.regex or other.regex)

    @property
    def literal(self) -> bool:
        return not self.dyn and self.key == self.text


EMPTY = RT("", "")
DYN = RT("<dynamic>", None, True)


def lit(s: str) -> RT:
    return RT(s, s)


# ------------------------------------------------------------------ values
class _Missing:
    def __repr__(self):
        return "MISSING"


MISSING = _Missing()


class UList:
    """A URL pattern list object.  `ops` are pattern descriptions (Elt/RouterOp/LibOp/GapOp)."""
    __slots__ = ("ops", "origin")

    def __init__(self, ops=None, origin=""):
        self.ops = list(ops or [])
        self.origin = origin


@dataclass(frozen=True)
class Bound:
    """An expression bound to a name, evaluated lazily in the context where it was written."""
    expr: ast.AST
    ctx: "Ctx"


@dataclass(frozen=True)
class Unknown:
    why: str


@dataclass(frozen=True)
class KwDict:
    items: tuple                 # ((key, value), ...)
    complete: bool = True


@dataclass(frozen=True)
class Seq:
    items: tuple                 # (RT, ...)


@dataclass(frozen=True)
class Ref:
    """(v4) A name bound by an `import` statement executed by the interpreter: a reference to the
    qualified name `q` (resolved lazily; a project module's list keeps its identity)."""
    q: str


@dataclass(frozen=True)
class Alts:
    """(v4) A name whose value differs between alternatives (if/else, try/except, match): every
    alternative is evaluated, and what it produces is conditional."""
    values: tuple


@dataclass(frozen=True)
class Flow:
    """(v4) How a statement (block) ended.  `stopped`: every path left it abruptly (the rest of the
    enclosing block is dead); `sigs`: abrupt exits that did or may happen (break/continue/return/raise)."""
    stopped: bool = False
    sigs: frozenset = frozenset()


NORMAL = Flow()
# an exit on SOME path makes the statements after it conditional; `raise` does not, because a module
# (or helper) that raises produces no URL patterns at all
COND_SIGS = frozenset({"break", "continue", "return"})


class Ctx:
    """Evaluation context: module for name resolution, local env (copy-on-write snapshot),
    the module env for helper bodies, and the FunctionInfo for function-local imports."""
    __slots__ = ("mod", "env", "outer", "func")

    def __init__(self, mod, env, outer=None, func=None):
        self.mod, self.env, self.outer, self.func = mod, env, outer, func


# ------------------------------------------------------------------ ops
@dataclass(frozen=True)
class Elt:
    expr: ast.AST
    ctx: Ctx
    cond: bool
    prefix: RT = EMPTY


@dataclass(frozen=True)
class RouterOp:
    mod: str
    var: str
    cond: bool
    prefix: RT = EMPTY


@dataclass(frozen=True)
class LibOp:
    module: str
    ctx: Ctx
    expr: ast.AST
    cond: bool
    prefix: RT = EMPTY


@dataclass(frozen=True)
class GapOp:
    type: str
    mod: str
    where: str
    detail: str
    line: int = 0
    cond: bool = False
    prefix: RT = EMPTY


def _with(op, cond, prefix: RT):
    if not cond and prefix == EMPTY:
        return op
    return dataclasses.replace(op, cond=op.cond or cond, prefix=prefix.join(op.prefix))


# ------------------------------------------------------------------ routes
@dataclass
class Route:
    pattern: str
    name: str | None
    kind: str          # project_function | project_class | viewset | library_view | library_include | admin_site
    target: str
    file: str
    line: int
    node: ast.AST | None = None
    as_view_kwargs: dict = field(default_factory=dict)
    actions: dict | None = None
    decorators: list = field(default_factory=list)
    wrapper_funcs: list = field(default_factory=list)
    conditional: bool = False
    via: list = field(default_factory=list)
    # v3
    key: str | None = None            # comparison key (None: runtime-dependent part)
    regex: bool = False
    seq: int = 0                      # ordinal of the path() call in first-match order (per root)
    root: str = ""
    helpers: list = field(default_factory=list)       # project URL helper functions expanded
    dispatcher: str | None = None     # view that dispatches to this target via the route kwargs
    dispatch_key: str | None = None
    shadowed_by: dict | None = None   # earlier literal-equal route that Django matches first
    may_be_shadowed_by: dict | None = None   # ... but that earlier route is conditional
    library_shadowed: dict = field(default_factory=dict)   # catalog ref -> shadow info (includes)
    library_routes: dict = field(default_factory=dict)     # catalog ref -> [full pattern text]

    def describe(self) -> dict:
        d = dict(pattern=self.pattern, name=self.name, kind=self.kind, target=self.target, file=self.file,
                 line=self.line, decorators=self.decorators, conditional=self.conditional,
                 urlconf_chain=self.via)
        if self.helpers:
            d["url_helpers"] = list(self.helpers)
        if self.dispatcher:
            d["dispatched_by"] = dict(view=self.dispatcher, kwarg=self.dispatch_key)
        if self.shadowed_by:
            d["shadowed_by"] = self.shadowed_by
        if self.may_be_shadowed_by:
            d["may_be_shadowed_by"] = self.may_be_shadowed_by
        return d

    def shadow_info(self, pattern=None) -> dict:
        return dict(pattern=pattern or self.pattern, target=self.target, kind=self.kind, file=self.file,
                    line=self.line, conditional=self.conditional)


class _State:
    """Mutable interpreter state for a block of statements (module body or helper body)."""

    def __init__(self, mod, env, outer=None, func=None, returns=None):
        self.mod, self.env, self.outer, self.func = mod, env, outer, func
        self.returns = returns

    def ctx(self) -> Ctx:
        return Ctx(self.mod, self.env, self.outer, self.func)

    def bind(self, name, value):
        self.env = {**self.env, name: value}


class UrlConfParser:
    def __init__(self, project: Project, settings_values=None, url_builders=None):
        self.p = project
        self.settings = settings_values or {}
        # (v6) catalogued library URL-list builders: {symbol: catalog row}
        self.url_builders = url_builders or {}
        self.routes: list[Route] = []
        self.gaps: list[Gap] = []
        self.reached: set = set()
        self.dispatchers: dict = {}          # dispatcher qualname -> set of targets
        self._visiting: set = set()
        self._including: set = set()
        self._envs: dict = {}
        self._env_building: set = set()
        self._routers: dict = {}
        self._sym = itertools.count(1)
        self._seq = 0
        self._root = ""
        self._settings_reads = 0             # counts settings lookups (a loop over a settings value is conditional)
        self._list_mutators: list = []       # project functions being run with a URL list argument

    # ------------------------------------------------------------ helpers
    def _gap(self, typ, modname, where, detail, line=0):
        mod = self.p.modules.get(modname)
        self.gaps.append(Gap(typ, mod.path if mod else modname, where, detail, line))

    def has_urlpatterns(self, modname) -> bool:
        mod = self.p.modules.get(modname)
        return bool(mod) and "urlpatterns" in mod.assigns

    @staticmethod
    def lookup(ctx: Ctx, name):
        v = ctx.env.get(name, MISSING)
        if v is MISSING and ctx.outer is not None:
            v = ctx.outer.get(name, MISSING)
        return v

    @staticmethod
    def alt_ctxs(ctx: Ctx, name, alts: Alts):
        """One context per alternative value of `name` (each evaluated as if it were the only one)."""
        for v in alts.values:
            yield Ctx(ctx.mod, {**ctx.env, name: v}, ctx.outer, ctx.func)

    def deref(self, q, _depth=0):
        """(v4) Final module-level value of the qualified name `q` in a project module (following
        imports of imports), or MISSING.  Returns (value, qualified name)."""
        q = self.p.canonical(q)
        if _depth > MAX_DEPTH or not q:
            return MISSING, q
        m2, rest = self.p.module_prefix(q)
        if not m2 or len(rest) != 1:
            return MISSING, q
        v = self.module_env(m2).get(rest[0], MISSING)
        if isinstance(v, Ref):
            return self.deref(v.q, _depth + 1)
        if v is MISSING:
            q2 = self.static_ref(Ctx(m2, {}), rest[0])
            if q2 and q2 != q:
                return self.deref(q2, _depth + 1)
        return v, q

    def static_ref(self, ctx: Ctx, name) -> str | None:
        """(v4) Qualified name that `name` refers to through the static import tables (explicit and
        star imports), when the interpreter has no value for it; None if it is not an import."""
        q = self.p.resolve_expr_static(ctx.mod, ast.Name(name), ctx.func)
        own = f"{ctx.mod}.{name}"
        if q and q != own:
            return self.p.canonical(q)
        mod = self.p.modules.get(ctx.mod)
        for src in (mod.star_imports if mod else ()):
            if src in self.p.modules:
                r = self.p.lookup_symbol(src, name)
                if r:
                    return self.p.canonical(r)
        return None

    def qname(self, ctx: Ctx, expr, _depth=0) -> str | None:
        """Qualified (canonical) name of a Name/Attribute, following names bound to other names."""
        if _depth > MAX_DEPTH:
            return None
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, Ref):
                return self.p.canonical(v.q)
            if isinstance(v, Bound):
                if isinstance(v.expr, (ast.Name, ast.Attribute)):
                    return self.qname(v.ctx, v.expr, _depth + 1)
                if ctx.func is not None and expr.id in ctx.env:
                    return None          # helper parameter / local bound to a non-name expression
                # module-level name bound to an expression: its static name (view aliases, instances)
            elif v is not MISSING:
                return None
            q = self.p.resolve_expr_static(ctx.mod, expr, ctx.func)
            return self.p.canonical(q) if q else None
        if isinstance(expr, ast.Attribute):
            base = self.qname(ctx, expr.value, _depth + 1)
            return self.p.canonical(f"{base}.{expr.attr}") if base else None
        return None

    def routers(self, modname) -> dict:
        """router var -> [(prefix, viewset expr, line)] registered at module level."""
        if modname in self._routers:
            return self._routers[modname]
        mod = self.p.modules[modname]
        out = {}
        self._routers[modname] = out
        for st in self.p._top_level_statements(mod.tree.body):
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
                q = self.p.resolve_expr_static(modname, st.value.func)
                fq = self.p.canonical(q) if q else ""
                if fq.rsplit(".", 1)[-1].endswith("Router"):
                    for t in st.targets:
                        if isinstance(t, ast.Name):
                            out.setdefault(t.id, [])
        for st in self.p._top_level_statements(mod.tree.body):
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                f = st.value.func
                if isinstance(f, ast.Attribute) and f.attr == "register" and isinstance(f.value, ast.Name) \
                        and f.value.id in out:
                    args = st.value.args
                    if len(args) >= 2:
                        out[f.value.id].append((args[0], args[1], st.lineno))
                    else:
                        self._gap("unsupported_url_construct", modname, "router.register", _u(st.value), st.lineno)
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and \
                        isinstance(f.value.value, ast.Name) and f.value.value.id in out:
                    self._gap("unsupported_url_construct", modname, "router", _u(st.value), st.lineno)
        # (v5) registrations inside module-level loops / functions are not unrolled: a gap, not silence
        for st in mod.tree.body:
            if isinstance(st, (ast.For, ast.While, ast.AsyncFor, ast.FunctionDef, ast.AsyncFunctionDef)):
                for n in ast.walk(st):
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "register" \
                            and isinstance(n.func.value, ast.Name) and n.func.value.id in out:
                        self._gap("unsupported_url_construct", modname, "router.register",
                                  f"{_u(n)} inside a loop or function: not evaluated", n.lineno)
        return out

    # ------------------------------------------------------------ module evaluation
    def module_env(self, modname) -> dict:
        """Final module-level environment of a module (its statements evaluated in order)."""
        if modname in self._envs:
            return self._envs[modname]
        if modname in self._env_building or modname not in self.p.modules:
            return {}
        self._env_building.add(modname)
        try:
            st = _State(modname, {})
            self.exec_body(self.p.modules[modname].tree.body, st, False)
            self._envs[modname] = st.env
        finally:
            self._env_building.discard(modname)
        return self._envs[modname]

    def exec_body(self, body, st: _State, cond: bool) -> Flow:
        """Evaluate statements in order.  (v4) After a statement that may `break`/`continue`/`return`
        on some path, the rest of the block is conditional; after one that always exits, it is dead."""
        sigs = set()
        for s in body:
            f = self.exec_stmt(s, st, cond) or NORMAL
            sigs |= f.sigs
            if f.stopped:
                return Flow(True, frozenset(sigs))
            if f.sigs & COND_SIGS:
                cond = True
        return Flow(False, frozenset(sigs))

    def exec_stmt(self, s, st: _State, cond: bool) -> Flow:
        if isinstance(s, (ast.Assign, ast.AnnAssign)):
            if s.value is None:
                return NORMAL
            targets = s.targets if isinstance(s, ast.Assign) else [s.target]
            val = self.assign_value(s.value, st.ctx(), cond)
            for t in targets:
                if isinstance(t, ast.Name):
                    st.bind(t.id, val)
                elif isinstance(t, (ast.Tuple, ast.List)):
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            st.bind(n.id, Unknown(f"unpacked from {_u(s.value)}"))
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                    cur = self.lookup(st.ctx(), t.value.id)
                    if isinstance(cur, UList):
                        cur.ops.append(GapOp("unsupported_url_construct", st.mod, t.value.id,
                                             f"item assignment {_u(s)}", s.lineno, cond))
            return NORMAL
        if isinstance(s, ast.AugAssign) and isinstance(s.target, ast.Name):
            name = s.target.id
            ctx = st.ctx()
            cur = self.lookup(ctx, name)
            if isinstance(s.op, ast.Add) and isinstance(cur, RT):
                add = self.str_value(s.value, ctx)
                st.bind(name, cur.concat(add) if add is not None else DYN)
                return NORMAL
            if not isinstance(s.op, ast.Add):
                if isinstance(cur, UList):
                    cur.ops.append(GapOp("unsupported_url_construct", st.mod, name, _u(s), s.lineno, cond))
                return NORMAL
            ul = self._as_list(name, cur, st, cond, s)
            ul.ops.extend(self.struct(s.value, ctx, cond))      # in place: aliases see it
            return NORMAL
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Attribute) \
                and isinstance(s.value.func.value, ast.Name):
            name, meth, args = s.value.func.value.id, s.value.func.attr, s.value.args
            ctx = st.ctx()
            cur = self.lookup(ctx, name)
            if meth in LIST_MUTATORS:
                # (v4) also a list imported from another module (`from x import urlpatterns`, or a star
                # import): Python mutates that module's list object
                listlike = isinstance(cur, (UList, Bound, Ref, Alts)) or \
                    (cur is MISSING and self.static_ref(ctx, name) is not None)
            else:
                listlike = isinstance(cur, UList)
            if not listlike:
                self.exec_call_stmt(s.value, st, cond)
                return NORMAL
            ul = self._as_list(name, cur, st, cond, s)
            if meth == "append" and len(args) == 1:
                ul.ops.append(Elt(args[0], ctx, cond))
            elif meth == "extend" and len(args) == 1:
                ul.ops.extend(self.struct(args[0], ctx, cond))
            elif meth == "insert" and len(args) == 2:
                idx = args[0].value if isinstance(args[0], ast.Constant) and isinstance(args[0].value, int) else None
                new = Elt(args[1], ctx, cond)
                if idx is None:
                    ul.ops.append(new)
                    ul.ops.append(GapOp("unsupported_url_construct", st.mod, name,
                                        f"{_u(s.value)}: insert position not static (order assumed last)",
                                        s.lineno, cond))
                else:
                    ul.ops.insert(idx if idx >= 0 else max(len(ul.ops) + idx, 0), new)
            elif meth in ("copy", "index", "count"):
                return NORMAL
            else:
                ul.ops.append(GapOp("unsupported_url_construct", st.mod, name, _u(s.value), s.lineno, cond))
            return NORMAL
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
            self.exec_call_stmt(s.value, st, cond)
            return NORMAL
        if isinstance(s, ast.Import):
            # (v4) imports bind names in this block (so an import in an if/try branch is an alternative)
            for a in s.names:
                if a.asname:
                    st.bind(a.asname, Ref(a.name))
                else:
                    top = a.name.split(".")[0]
                    st.bind(top, Ref(top))
            return NORMAL
        if isinstance(s, ast.ImportFrom):
            mod = self.p.modules.get(st.mod)
            src = self.p._resolve_relative(mod, s.level, s.module) if s.level and mod else (s.module or "")
            src = self.p.unalias(src)      # (v5 review fix) module names relative to another sys.path root
            for a in s.names:
                if a.name != "*":     # star imports are resolved through the static import tables
                    st.bind(a.asname or a.name, Ref(f"{src}.{a.name}" if src else a.name))
            return NORMAL
        if isinstance(s, ast.If):
            truth = self.static_truth(s.test, st.ctx())
            if truth is not None:
                # (v4) a test MintMap can decide from code alone (a literal, a loop variable or module
                # constant compared with a literal); settings values are never decided
                return self.exec_body(s.body if truth else s.orelse, st, cond)
            return self.exec_branches([s.body, s.orelse], st)
        if isinstance(s, ast.Match):
            # every case (and "no case matched") is a possible branch
            return self.exec_branches([c.body for c in s.cases] + [[]], st)
        if isinstance(s, (ast.For, ast.AsyncFor)):
            return self.exec_for(s, st, cond)
        if isinstance(s, ast.While):
            if self.static_truth(s.test, st.ctx()) is False:
                return self.exec_body(s.orelse, st, cond)
            f = self.exec_unknown_loop(s, st, None, f"while {_u(s.test)}")
            self.exec_body(s.orelse, st, True)
            return f
        if isinstance(s, ast.Try) or (hasattr(ast, "TryStar") and isinstance(s, ast.TryStar)):
            # (v4) the try body (+ else) and each handler are ALTERNATIVES (a handler runs when the body
            # failed, e.g. an optional import); a handler that always re-raises is not an alternative
            handlers = [h.body for h in s.handlers if not _ends_in_raise(h.body)]
            if handlers:
                f = self.exec_branches([list(s.body) + list(s.orelse)] + handlers, st)
            else:
                f = self.exec_body(list(s.body) + list(s.orelse), st, cond)
            if f.stopped:
                return f
            f2 = self.exec_body(s.finalbody, st, cond or bool(f.sigs & COND_SIGS))
            return Flow(f2.stopped, f.sigs | f2.sigs)
        if isinstance(s, (ast.With, ast.AsyncWith)):
            return self.exec_body(s.body, st, cond)
        if isinstance(s, ast.Return):
            if st.returns is not None and s.value is not None:
                st.returns.append((s.value, st.ctx(), cond))
            return Flow(True, frozenset({"return"}))
        if isinstance(s, ast.Raise):
            return Flow(True, frozenset({"raise"}))
        if isinstance(s, ast.Break):
            return Flow(True, frozenset({"break"}))
        if isinstance(s, ast.Continue):
            return Flow(True, frozenset({"continue"}))
        if isinstance(s, ast.Delete):
            for t in s.targets:
                base = t.value if isinstance(t, ast.Subscript) else t
                if isinstance(base, ast.Name) and isinstance(self.lookup(st.ctx(), base.id), UList):
                    self.lookup(st.ctx(), base.id).ops.append(
                        GapOp("unsupported_url_construct", st.mod, base.id, _u(s), s.lineno, cond))
            return NORMAL
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and s.name in st.env:
            st.bind(s.name, MISSING)
        return NORMAL

    def exec_call_stmt(self, call, st: _State, cond):
        """`fn(urlpatterns, ...)` as a statement: a project function is run with its parameter bound to the
        same list object (in-place additions are kept); any other callee may modify the list -> gap."""
        ctx = st.ctx()
        lists = [a.id for a in list(call.args) + [k.value for k in call.keywords]
                 if isinstance(a, ast.Name) and isinstance(self._list_object(ctx, a.id), UList)]
        if not lists:
            return
        fq = self.qname(ctx, call.func)
        info = self.p.functions.get(fq) if fq else None
        why = ""
        if info is None:
            why = "a callable MintMap cannot follow"
        elif info.is_async or info.cls is not None:
            why = "an async function or a method"
        elif fq in self._list_mutators or len(self._list_mutators) >= MAX_HELPER_DEPTH:
            why = "a recursive or too deeply nested function"
        if not why:
            self._list_mutators.append(fq)
            try:
                sub = _State(info.module, self.bind_args(info, call, ctx), self.module_env(info.module), info,
                             returns=[])
                self.exec_body(info.node.body, sub, cond)
            finally:
                self._list_mutators.pop()
            return
        for name in lists:
            self._list_object(ctx, name).ops.append(GapOp(
                "unsupported_url_construct", st.mod, name,
                f"{_u(call)}: URL list passed to {fq or _u(call.func)} ({why}), which may modify it",
                call.lineno, cond))

    def _note_list_use(self, modname, name):
        """(v4) A module's `urlpatterns` list used by another URLconf (imported list, star import): that
        module's patterns are reached even though the module itself is never include()d."""
        if modname and name == "urlpatterns":
            self.reached.add(modname)

    def _list_object(self, ctx, name):
        """The URL list object a name refers to: a local UList, or (v4) a project module's list it imports."""
        v = self.lookup(ctx, name)
        if isinstance(v, Ref):
            v, _q = self.deref(v.q)
        return v if isinstance(v, UList) else None

    def _as_list(self, name, cur, st, cond, s) -> UList:
        """The UList bound to `name`, converting a lazily bound / imported / unknown value first."""
        if isinstance(cur, UList):
            return cur
        ctx = st.ctx()
        if cur is MISSING:
            q = self.static_ref(ctx, name)
            cur = Ref(q) if q else MISSING
        if isinstance(cur, Ref):
            v, q = self.deref(cur.q)
            if isinstance(v, UList):
                ul = v          # another project module's list: the same object (Python mutates it in place)
                m2, rest = self.p.module_prefix(q)
                self._note_list_use(m2, rest[0] if rest else "")
            else:
                ul = UList(self.struct_ref(q, ctx, False, EMPTY, ast.Name(name), 0), origin=name)
        elif isinstance(cur, Bound):
            ul = UList(self.struct(cur.expr, cur.ctx, False), origin=name)
        elif isinstance(cur, Alts):
            ops = []
            for actx in self.alt_ctxs(ctx, name, cur):
                ops += self.struct(ast.Name(name), actx, True)
            ul = UList(ops, origin=name)
        else:
            ul = UList([GapOp("unsupported_url_construct", st.mod, name,
                              f"{_u(s)}: {name} is not a list MintMap can evaluate", s.lineno, cond)], origin=name)
        st.bind(name, ul)
        return ul

    def exec_branches(self, bodies, st: _State) -> Flow:
        env0 = st.env
        results = []
        for body in bodies:
            st.env = env0
            f = self.exec_body(body, st, True)
            results.append((st.env, f))
        # a branch that always raises does not continue to the following statements
        live = [env for env, f in results if not (f.stopped and f.sigs <= {"raise"})] or [env for env, _ in results]
        merged = {}
        for n in set().union(*[set(e) for e in live]):
            vals = [e.get(n, MISSING) for e in live]
            first = vals[0]
            if all(v is first for v in vals):
                merged[n] = first
                continue
            merged[n] = self.merge_values(n, vals, st)
        st.env = merged
        flows = [f for _, f in results]
        return Flow(all(f.stopped for f in flows), frozenset().union(*[f.sigs for f in flows]))

    def merge_values(self, name, vals, st):
        present = [v for v in vals if v is not MISSING]
        if len(present) == 1:
            return present[0]
        if all(isinstance(v, UList) for v in present):
            ids = [{id(o) for o in v.ops} for v in present]
            common = set.intersection(*ids)
            ops, seen = [], set()
            for v in present:
                for o in v.ops:
                    if id(o) not in seen:
                        seen.add(id(o))
                        ops.append(o if id(o) in common else _with(o, True, EMPTY))
            return UList(ops, origin=name)
        if all(isinstance(v, RT) for v in present):
            if all(v == present[0] for v in present):
                return present[0]
            return RT("{" + name + "}", "{" + f"{st.mod}.{name}#{next(self._sym)}" + "}", True)
        # (v4) different kinds of values (an imported list vs a literal list, two imported views ...):
        # keep every alternative instead of an unknown value
        uniq = []
        for v in present:
            for x in (v.values if isinstance(v, Alts) else (v,)):
                if not any(x is u or (isinstance(x, Ref) and x == u) for u in uniq):
                    uniq.append(x)
        if len(uniq) == 1:
            return uniq[0]
        if len(uniq) > MAX_UNROLL:
            return Unknown(f"{name} differs between branches")
        return Alts(tuple(uniq))

    def exec_for(self, s, st: _State, cond) -> Flow:
        reads = self._settings_reads
        vals = self.seq_value(s.iter, st.ctx()) if isinstance(s.target, ast.Name) else None
        sigs, broke = set(), False
        if vals is not None and len(vals) <= MAX_UNROLL:
            # a literal list always runs the body; a settings value may differ in a deployment
            body_cond = cond or self._settings_reads != reads
            for v in vals:
                st.bind(s.target.id, v)
                f = self.exec_body(s.body, st, body_cond)
                sigs |= f.sigs
                if f.stopped and "break" in f.sigs and f.sigs <= {"break", "raise"}:
                    broke = True           # (v4) every path of this iteration breaks: no further iterations
                    break
                if f.stopped and f.sigs <= {"return", "raise"}:
                    return Flow(True, frozenset(f.sigs))
                if f.sigs & {"break", "return"}:
                    body_cond = True       # (v4) the loop may have ended here: later iterations are conditional
        else:
            sigs |= self.exec_unknown_loop(s, st, s.target, f"for {_u(s.target)} in {_u(s.iter)}").sigs
        if not broke:
            self.exec_body(s.orelse, st, True if sigs & {"break", "return"} else cond)
        return Flow(False, frozenset(sigs & {"return", "raise"}))

    def exec_unknown_loop(self, s, st: _State, target, text) -> Flow:
        if target is not None:
            for n in ast.walk(target):
                if isinstance(n, ast.Name):
                    st.bind(n.id, Unknown(f"loop variable of `{text}`"))
        before = {id(v): (v, len(v.ops)) for v in list(st.env.values()) + list((st.outer or {}).values())
                  if isinstance(v, UList)}
        f = self.exec_body(s.body, st, True)
        for v in st.env.values():
            if isinstance(v, UList) and (id(v) not in before or len(v.ops) != before[id(v)][1]):
                v.ops.append(GapOp("unsupported_url_construct", st.mod, v.origin or "urlpatterns",
                                   f"`{text}`: iterable not statically known; the loop body was evaluated once "
                                   f"with the loop variable unknown", s.lineno, True))
        return Flow(False, frozenset(f.sigs & {"return", "raise"}))

    # ------------------------------------------------------------ static conditions (v4)
    def static_truth(self, test, ctx: Ctx):
        """True/False when a condition can be decided from code alone, else None.  Decided: literals,
        `not`/`and`/`or`, and `==`/`!=`/`in`/`not in` between strings MintMap knows exactly (literals,
        unrolled loop variables, module constants).  Anything that reads a settings value is NOT decided
        (a deployment can override settings)."""
        reads = self._settings_reads
        try:
            v = self._truth(test, ctx, 0)
        except Exception:      # pragma: no cover - defensive: never let a test decide on an error
            return None
        return None if self._settings_reads != reads else v

    def _truth(self, e, ctx, depth):
        if depth > MAX_DEPTH:
            return None
        if isinstance(e, ast.Constant) and (e.value is None or isinstance(e.value, (bool, int, str))):
            return bool(e.value)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            t = self._truth(e.operand, ctx, depth + 1)
            return None if t is None else not t
        if isinstance(e, ast.BoolOp):
            ts = [self._truth(v, ctx, depth + 1) for v in e.values]
            if isinstance(e.op, ast.And):
                return False if False in ts else (True if all(t is True for t in ts) else None)
            return True if True in ts else (False if all(t is False for t in ts) else None)
        if isinstance(e, ast.Compare) and len(e.ops) == 1:
            op, right = e.ops[0], e.comparators[0]
            left = self._exact_str(e.left, ctx)
            if left is None:
                return None
            if isinstance(op, (ast.Eq, ast.NotEq)):
                r = self._exact_str(right, ctx)
                if r is None:
                    return None
                return (left == r) == isinstance(op, ast.Eq)
            if isinstance(op, (ast.In, ast.NotIn)):
                seq = self.seq_value(right, ctx)
                if seq is None or not all(x.literal for x in seq):
                    return None
                return (left in {x.text for x in seq}) == isinstance(op, ast.In)
        return None

    def _exact_str(self, e, ctx) -> str | None:
        v = self.str_value(e, ctx)
        return v.text if v is not None and v.literal else None

    # ------------------------------------------------------------ expression evaluation
    def assign_value(self, expr, ctx: Ctx, cond):
        if _strish(expr):
            v = self.str_value(expr, ctx)
            if v is not None:
                return v
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, (UList, RT, KwDict, Seq, Unknown, Ref, Alts)):
                return v                       # alias: same object
        if self._listish(expr, ctx):
            return UList(self.struct(expr, ctx, cond))
        return Bound(expr, ctx)

    def _listish(self, expr, ctx) -> bool:
        if isinstance(expr, (ast.List, ast.Tuple, ast.ListComp, ast.GeneratorExp)):
            return True
        if isinstance(expr, ast.IfExp):
            return self._listish(expr.body, ctx) or self._listish(expr.orelse, ctx)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._listish(expr.left, ctx) or self._listish(expr.right, ctx) or \
                any(isinstance(x, ast.Name) and isinstance(self._list_object(ctx, x.id), UList)
                    for x in (expr.left, expr.right))
        if isinstance(expr, ast.Call):
            fq = self.qname(ctx, expr.func) or ""
            return fq in COPY_FUNCS | I18N_FUNCS | PASSTHROUGH_FIRST_FUNCS | NON_AUTH_PATTERN_FUNCS | \
                IMPORT_STRING_FUNCS
        return False

    def struct(self, expr, ctx: Ctx, cond, prefix: RT = EMPTY, _depth=0) -> list:
        """Structure of a pattern-list expression -> list of ops (copies are snapshots)."""
        if _depth > MAX_DEPTH:
            return [GapOp("url_include_cycle", ctx.mod, "urlpatterns", f"{_u(expr)}: evaluation too deep",
                          getattr(expr, "lineno", 0), cond, prefix)]
        if isinstance(expr, (ast.List, ast.Tuple)):
            if isinstance(expr, ast.Tuple) and len(expr.elts) == 2 and _strish(expr.elts[1]) and \
                    not isinstance(expr.elts[0], ast.Starred):
                # `(patterns, app_name)`: a URL list never contains a string, so this is the include() tuple form
                return self.struct(expr.elts[0], ctx, cond, prefix, _depth + 1)
            out = []
            for e in expr.elts:
                if isinstance(e, ast.Starred):
                    out += self.struct(e.value, ctx, cond, prefix, _depth + 1)
                else:
                    out.append(Elt(e, ctx, cond, prefix))
            return out
        if isinstance(expr, (ast.ListComp, ast.GeneratorExp)):
            return self.struct_comp(expr, ctx, cond, prefix)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self.struct(expr.left, ctx, cond, prefix, _depth + 1) + \
                self.struct(expr.right, ctx, cond, prefix, _depth + 1)
        if isinstance(expr, ast.IfExp):
            # `a if settings.X else b`: both alternatives, each conditional
            return self.struct(expr.body, ctx, True, prefix, _depth + 1) + \
                self.struct(expr.orelse, ctx, True, prefix, _depth + 1)
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, UList):
                return [_with(o, cond, prefix) for o in v.ops]
            if isinstance(v, Bound):
                return self.struct(v.expr, v.ctx, cond, prefix, _depth + 1)
            if isinstance(v, Ref):
                return self.struct_ref(self.p.canonical(v.q), ctx, cond, prefix, expr, _depth + 1)
            if isinstance(v, Alts):
                out = []
                for actx in self.alt_ctxs(ctx, expr.id, v):
                    out += self.struct(expr, actx, True, prefix, _depth + 1)
                return out
            if v is not MISSING:
                why = v.why if isinstance(v, Unknown) else "not a URL pattern list"
                return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns", f"{_u(expr)}: {why}",
                              getattr(expr, "lineno", 0), cond, prefix)]
            if expr.id in self.routers(ctx.mod):
                return [RouterOp(ctx.mod, expr.id, cond, prefix)]
            return self.struct_ref(self.qname(ctx, expr), ctx, cond, prefix, expr, _depth)
        if isinstance(expr, ast.Attribute):
            if expr.attr == "urls":
                r = self._router_ref(ctx, expr.value)
                if r:
                    return [RouterOp(r[0], r[1], cond, prefix)]
            return self.struct_ref(self.qname(ctx, expr), ctx, cond, prefix, expr, _depth)
        if isinstance(expr, ast.Call):
            fq = self.qname(ctx, expr.func) or ""
            if fq in I18N_FUNCS:
                pdl = next((k.value for k in expr.keywords if k.arg == "prefix_default_language"), None)
                if pdl is None or (isinstance(pdl, ast.Constant) and pdl.value is True):
                    lang = RT("{lang}/", "{i18n}/")
                else:   # default language unprefixed: not comparable with other routes
                    lang = RT("{lang?}/", None)
                out = []
                for a in expr.args:
                    sub = a.value if isinstance(a, ast.Starred) else a
                    out += self.struct(sub, ctx, cond, prefix.join(lang), _depth + 1) if isinstance(a, ast.Starred) \
                        else [Elt(a, ctx, cond, prefix.join(lang))]
                return out
            if fq in PASSTHROUGH_FIRST_FUNCS:
                return self.struct(expr.args[0], ctx, cond, prefix, _depth + 1) if expr.args else []
            if fq in NON_AUTH_PATTERN_FUNCS:
                view = next((k.value for k in expr.keywords if k.arg == "view"), None)
                if view is not None and self.qname(ctx, view) in self.p.functions:
                    return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns",
                                  f"{_u(expr)}: static-file route served by a project view", expr.lineno, cond,
                                  prefix)]
                return []
            if fq in COPY_FUNCS:
                return self.struct(expr.args[0], ctx, cond, prefix, _depth + 1) if expr.args else []
            if fq in self.url_builders:
                # (v6) a catalogued library function that builds a URL list: its flows are the catalogued
                # include's (the route keeps the call, so the arguments can narrow them)
                return [LibOp(self.url_builders[fq]["same_flows_as"], ctx, expr, cond, prefix)]
            if fq in IMPORT_STRING_FUNCS and expr.args:
                s = self.str_value(expr.args[0], ctx)
                if s is not None and s.literal:
                    return self.struct_ref(self.p.canonical(s.text), ctx, cond, prefix, expr, _depth)
                return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns",
                              f"{_u(expr)}: dotted path not static", expr.lineno, cond, prefix)]
            return [Elt(expr, ctx, cond, prefix)]
        return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns", _u(expr), getattr(expr, "lineno", 0),
                      cond, prefix)]

    def struct_ref(self, q, ctx, cond, prefix, expr, _depth) -> list:
        """A URL list referenced by qualified name (another module's list, or a library list)."""
        if q:
            m2, rest = self.p.module_prefix(q)
            if m2 and len(rest) == 1:
                v = self.module_env(m2).get(rest[0], MISSING)
                if isinstance(v, UList):
                    self._note_list_use(m2, rest[0])
                    return [_with(o, cond, prefix) for o in v.ops]
                if isinstance(v, Bound):
                    return self.struct(v.expr, v.ctx, cond, prefix, _depth + 1)
                if isinstance(v, (Ref, Alts)) and _depth <= MAX_DEPTH:
                    # (v4) a name that module imported (or binds differently in alternatives)
                    return self.struct(ast.Name(rest[0]), Ctx(m2, self.module_env(m2)), cond, prefix, _depth + 1)
                if v is MISSING:
                    q2 = self.p.resolve_expr_static(m2, ast.Name(rest[0]))
                    q2 = self.p.canonical(q2) if q2 else None
                    if q2 and q2 != q and q2 != f"{m2}.{rest[0]}":
                        return self.struct_ref(q2, ctx, cond, prefix, expr, _depth + 1)
            elif m2 and len(rest) == 2 and rest[1] == "urls" and rest[0] in self.routers(m2):
                # (v6) `api_urls = router.urls` in another module, referenced as `mod.api_urls` (the static
                # resolver follows the alias to `mod.router.urls`)
                return [RouterOp(m2, rest[0], cond, prefix)]
            elif not m2:
                module = q[:-len(".urlpatterns")] if q.endswith(".urlpatterns") else q
                return [LibOp(module, ctx, expr, cond, prefix)]
        return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns", _u(expr), getattr(expr, "lineno", 0),
                      cond, prefix)]

    def _router_ref(self, ctx, expr):
        if isinstance(expr, ast.Name) and (self.lookup(ctx, expr.id) is MISSING or
                                           isinstance(self.lookup(ctx, expr.id), (Bound, Ref))):
            if expr.id in self.routers(ctx.mod):
                return ctx.mod, expr.id
        q = self.qname(ctx, expr)
        if q:
            m2, rest = self.p.module_prefix(q)
            if m2 and len(rest) == 1 and rest[0] in self.routers(m2):
                return m2, rest[0]
        return None

    def struct_comp(self, expr, ctx, cond, prefix) -> list:
        """A list comprehension of patterns: unrolled when every iterable is a static list of strings."""
        gens = expr.generators
        # [x for x in some_url_list (if ...)] -> a (filtered) copy
        if len(gens) == 1 and isinstance(expr.elt, ast.Name) and isinstance(gens[0].target, ast.Name) and \
                gens[0].target.id == expr.elt.id and not gens[0].is_async:
            it = gens[0].iter
            if self._listish(it, ctx) or (isinstance(it, ast.Name) and isinstance(self.lookup(ctx, it.id), UList)):
                return self.struct(it, ctx, cond or bool(gens[0].ifs), prefix)
        combos = [{}]
        reads = self._settings_reads
        for g in gens:
            vals = self.seq_value(g.iter, ctx) if isinstance(g.target, ast.Name) else None
            if vals is None or len(combos) * len(vals) > MAX_UNROLL:
                combos = None
                break
            combos = [dict(c, **{g.target.id: v}) for c in combos for v in vals]
        if combos is not None:
            from_settings = self._settings_reads != reads
            out = []
            for c in combos:
                cctx = Ctx(ctx.mod, {**ctx.env, **c}, ctx.outer, ctx.func)
                # (v4) a filter decided from code alone drops the element or keeps it unconditionally
                truths = [self.static_truth(t, cctx) for g in gens for t in g.ifs]
                if False in truths:
                    continue
                out.append(Elt(expr.elt, cctx, cond or from_settings or None in truths, prefix))
            return out
        env = dict(ctx.env)
        for g in gens:
            for n in ast.walk(g.target):
                if isinstance(n, ast.Name):
                    env[n.id] = Unknown(f"comprehension variable over {_u(g.iter)}")
        return [GapOp("unsupported_url_construct", ctx.mod, "urlpatterns",
                      f"{_u(expr)}: comprehension over values MintMap cannot enumerate; its element is analysed "
                      f"once with the loop variables unknown", expr.lineno, True, prefix),
                Elt(expr.elt, Ctx(ctx.mod, env, ctx.outer, ctx.func), True, prefix)]

    def settings_value(self, q):
        for so in SETTINGS_OBJECTS:
            if q and q.startswith(so + "."):
                name = q[len(so) + 1:]
                if "." not in name:
                    self._settings_reads += 1
                    return name, self.settings.get(name, MISSING)
        return None, MISSING

    def str_value(self, expr, ctx: Ctx, _depth=0) -> RT | None:
        """Symbolic value of a string expression (None: not a string expression)."""
        if _depth > MAX_DEPTH:
            return DYN
        if isinstance(expr, ast.Constant):
            return lit(expr.value) if isinstance(expr.value, str) else None
        if isinstance(expr, ast.JoinedStr):
            out = EMPTY
            for part in expr.values:
                if isinstance(part, ast.Constant):
                    out = out.concat(lit(str(part.value)))
                elif isinstance(part, ast.FormattedValue) and part.format_spec is None and \
                        part.conversion in (-1, 115):
                    out = out.concat(self.str_value(part.value, ctx, _depth + 1) or DYN)
                else:
                    out = out.concat(DYN)
            return out
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            a, b = self.str_value(expr.left, ctx, _depth + 1), self.str_value(expr.right, ctx, _depth + 1)
            if a is None and b is None:
                return None
            return (a or DYN).concat(b or DYN)
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, RT):
                return v
            if isinstance(v, Bound):
                return self.str_value(v.expr, v.ctx, _depth + 1)
            if isinstance(v, (UList, KwDict, Seq)):
                return None
            if isinstance(v, Unknown):
                return DYN
        if isinstance(expr, (ast.Name, ast.Attribute)):
            q = self.qname(ctx, expr)
            name, sv = self.settings_value(q)
            if name is not None:
                if isinstance(sv, str):
                    return lit(sv)
                # one runtime value per process: comparable with itself
                return RT("{settings." + name + "}", "{settings." + name + "}", True)
            if q:
                m2, rest = self.p.module_prefix(q)
                if m2 and len(rest) == 1 and m2 != ctx.mod:
                    v, _q = self.deref(q)
                    if isinstance(v, RT):
                        return v
                    if isinstance(v, Bound):
                        return self.str_value(v.expr, v.ctx, _depth + 1)
            return DYN
        return DYN

    def seq_value(self, expr, ctx: Ctx, _depth=0) -> list | None:
        """A statically known list of strings (for loop unrolling), else None."""
        if _depth > MAX_DEPTH:
            return None
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            vals = [self.str_value(e, ctx) for e in expr.elts]
            return vals if all(v is not None and not v.dyn for v in vals) else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            a, b = self.seq_value(expr.left, ctx, _depth + 1), self.seq_value(expr.right, ctx, _depth + 1)
            return a + b if a is not None and b is not None else None
        if isinstance(expr, ast.Call) and expr.args and (self.qname(ctx, expr.func) or "") in COPY_FUNCS:
            return self.seq_value(expr.args[0], ctx, _depth + 1)
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if v is not MISSING and not isinstance(v, Ref):
                return self._seq_of(v, _depth)
        if isinstance(expr, (ast.Name, ast.Attribute)):
            q = self.qname(ctx, expr)
            name, sv = self.settings_value(q)
            if name is not None:
                if isinstance(sv, (list, tuple)) and all(isinstance(x, str) for x in sv):
                    return [lit(x) for x in sv]
                return None
            if q:
                m2, rest = self.p.module_prefix(q)
                if m2 and len(rest) == 1 and m2 != ctx.mod:
                    v, _q = self.deref(q)
                    if v is not MISSING:
                        return self._seq_of(v, _depth)
        return None

    def _seq_of(self, v, _depth) -> list | None:
        if isinstance(v, Seq):
            return list(v.items)
        if isinstance(v, Bound):
            return self.seq_value(v.expr, v.ctx, _depth + 1)
        if isinstance(v, UList):
            vals = [self.str_value(o.expr, o.ctx) if isinstance(o, Elt) else None for o in v.ops]
            return vals if vals and all(x is not None and not x.dyn for x in vals) else None
        return None

    def kw_dict(self, expr, ctx, _depth=0) -> KwDict | None:
        if _depth > MAX_DEPTH or expr is None:
            return None
        if isinstance(expr, ast.Dict):
            items, complete = [], True
            for k, v in zip(expr.keys, expr.values):
                if k is None:
                    sub = self.kw_dict(v, ctx, _depth + 1)
                    if sub is None:
                        complete = False
                    else:
                        items += list(sub.items)
                        complete = complete and sub.complete
                    continue
                ks = self.str_value(k, ctx)
                if ks is not None and ks.literal:
                    items.append((ks.text, Bound(v, ctx)))
                else:
                    complete = False
            return KwDict(tuple(items), complete)
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, KwDict):
                return v
            if isinstance(v, Bound):
                return self.kw_dict(v.expr, v.ctx, _depth + 1)
            return None
        if isinstance(expr, ast.Call) and (self.qname(ctx, expr.func) or "") == "builtins.dict":
            items = [(k.arg, Bound(k.value, ctx)) for k in expr.keywords if k.arg]
            return KwDict(tuple(items), all(k.arg for k in expr.keywords) and not expr.args)
        return None

    # ------------------------------------------------------------ helpers (project URL helper functions)
    def bind_args(self, info, call: ast.Call, ctx: Ctx):
        a = info.node.args
        menv = self.module_env(info.module)
        mctx = Ctx(info.module, menv, None, None)
        pos = a.posonlyargs + a.args
        env: dict = {}
        varargs, extra, complete = [], [], True
        for i, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                complete = False
                break
            if i < len(pos):
                env[pos[i].arg] = self._arg_value(arg, ctx)
            else:
                varargs.append(Bound(arg, ctx))
        names = {p.arg for p in pos} | {p.arg for p in a.kwonlyargs}
        for k in call.keywords:
            if k.arg is None:
                sub = self.kw_dict(k.value, ctx)
                if sub is None:
                    complete = False
                    continue
                for kk, vv in sub.items:
                    if kk in names:
                        env[kk] = vv
                    else:
                        extra.append((kk, vv))
                complete = complete and sub.complete
            elif k.arg in names:
                env[k.arg] = self._arg_value(k.value, ctx)
            else:
                extra.append((k.arg, Bound(k.value, ctx)))
        if a.defaults:
            for p, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
                env.setdefault(p.arg, Bound(d, mctx))
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if d is not None:
                env.setdefault(p.arg, Bound(d, mctx))
        for p in pos + a.kwonlyargs:
            env.setdefault(p.arg, Unknown(f"parameter {p.arg} of {info.qualname} not bound at the call site"))
        if a.vararg:
            env[a.vararg.arg] = UList([Elt(b.expr, b.ctx, False) for b in varargs], origin=a.vararg.arg) \
                if complete else Unknown(f"*{a.vararg.arg} of {info.qualname}")
        if a.kwarg:
            env[a.kwarg.arg] = KwDict(tuple(extra), complete)
        return env

    def _arg_value(self, arg, ctx):
        """Value bound to a helper parameter: the caller's list object itself (in-place changes made by
        the helper are visible to the caller), else the argument expression, evaluated lazily."""
        if isinstance(arg, ast.Name):
            v = self._list_object(ctx, arg.id)
            if isinstance(v, UList):
                return v
        return Bound(arg, ctx)

    def expand_helper(self, fq, call, ctx, cond, helpers):
        """Ops produced by a call to a project URL helper function, or (None, why)."""
        if fq in helpers or len(helpers) >= MAX_HELPER_DEPTH:
            return None, "recursive or too deeply nested URL helper"
        info = self.p.functions[fq]
        if info.is_async:
            return None, "async function"
        if info.cls is not None:
            return None, "method (only module-level helper functions are expanded)"
        env = self.bind_args(info, call, ctx)
        st = _State(info.module, env, self.module_env(info.module), info, returns=[])
        self.exec_body(info.node.body, st, False)
        if not st.returns:
            return None, "no return value"
        multi = len(st.returns) > 1
        ops = []
        for value, rctx, rcond in st.returns:
            if isinstance(value, ast.Constant) and value.value is None:
                continue
            ops += self.struct(value, rctx, cond or rcond or multi) if self._listish(value, rctx) or \
                isinstance(value, ast.Name) else [Elt(value, rctx, cond or rcond or multi)]
        return ops, ""

    # ------------------------------------------------------------ walking
    def parse_root(self, root_module: str):
        self._root = root_module
        self.walk_module(root_module, EMPTY, [])

    def walk_module(self, modname, prefix: RT, chain, cond=False):
        """Routes of a URLconf module mounted at `prefix` (`cond`: the include itself is conditional)."""
        key = (modname, prefix.text)
        if key in self._visiting:
            self._gap("url_include_cycle", modname, modname, " -> ".join(chain + [modname]))
            return
        self._visiting.add(key)
        self.reached.add(modname)
        try:
            env = self.module_env(modname)
            ctx = Ctx(modname, env)
            v = env.get("urlpatterns", MISSING)
            if isinstance(v, UList):
                ops = list(v.ops)
            elif v is MISSING:
                q = self.p.resolve_expr_static(modname, ast.Name("urlpatterns"))
                q = self.p.canonical(q) if q else None
                if q and q != f"{modname}.urlpatterns":
                    ops = self.struct_ref(q, ctx, False, EMPTY, ast.Name("urlpatterns"), 0)
                else:
                    ops = []
                    self._gap("unsupported_url_construct", modname, "urlpatterns",
                              "module has no static urlpatterns")
            else:
                ops = self.struct(ast.Name("urlpatterns"), ctx, False)
            for op in ops:
                self.process_op(op, prefix, chain + [modname], cond=cond)
        finally:
            self._visiting.discard(key)

    def process_op(self, op, prefix: RT, chain, site=None, helpers=(), cond=False):
        if cond and not op.cond and not isinstance(op, GapOp):
            op = dataclasses.replace(op, cond=True)
        if isinstance(op, GapOp):
            self._gap(op.type, op.mod, op.where, op.detail, op.line)
            return
        pfx = prefix.join(op.prefix)
        if isinstance(op, RouterOp):
            self._seq += 1
            for pfx_expr, vs_expr, line in self.routers(op.mod)[op.var]:
                rt = self.str_value(pfx_expr, Ctx(op.mod, self.module_env(op.mod)))
                seg = rt.text.rstrip("/") + "/" if rt is not None and rt.literal else "<dynamic>/"
                pattern = pfx.join(lit(seg) if rt is not None and rt.literal else RT(seg, None, True))
                q = self.p.resolve_expr_static(op.mod, vs_expr)
                target = self.p.canonical(q) if q else None
                file = self.p.modules[op.mod].path
                kind = "viewset" if target and target in self.p.classes else "library_view"
                if target:
                    self.routes.append(self._route(pattern, None, kind, target, file, line, vs_expr, op.cond, chain,
                                                   self._seq))
                else:
                    self._gap("unresolved_view", op.mod, pattern.text, _u(vs_expr), line)
            return
        if isinstance(op, LibOp):
            self._seq += 1
            mod = self.p.modules.get(op.ctx.mod)
            self.routes.append(self._route(pfx, None, "library_include", op.module, mod.path if mod else op.ctx.mod,
                                           getattr(op.expr, "lineno", 0), op.expr, op.cond, chain, self._seq))
            return
        if isinstance(op, Elt):
            if site is None:
                site = (op.ctx.mod, op.expr)
            self.process_elt(op.expr, op.ctx, op.cond, pfx, chain, site, helpers)

    def _route(self, pattern: RT, name, kind, target, file, line, node, cond, chain, seq, **extra) -> Route:
        return Route(pattern.text, name, kind, target, file, line, node, conditional=cond, via=list(chain),
                     key=pattern.key, regex=pattern.regex, seq=seq, root=self._root, **extra)

    def process_elt(self, expr, ctx, cond, prefix: RT, chain, site, helpers, _depth=0):
        where = prefix.text or "/"
        if _depth > MAX_DEPTH:
            self._gap("url_include_cycle", ctx.mod, where, _u(expr), getattr(expr, "lineno", 0))
            return
        if isinstance(expr, ast.Name):
            v = self.lookup(ctx, expr.id)
            if isinstance(v, Bound):
                return self.process_elt(v.expr, v.ctx, cond, prefix, chain, site, helpers, _depth + 1)
            if isinstance(v, Alts):
                for actx in self.alt_ctxs(ctx, expr.id, v):
                    self.process_elt(expr, actx, True, prefix, chain, site, helpers, _depth + 1)
                return
            if v is MISSING or isinstance(v, Ref):
                q = self.qname(ctx, expr)
                if q:
                    m2, rest = self.p.module_prefix(q)
                    if m2 and len(rest) == 1:
                        v2, _q = self.deref(q)
                        if isinstance(v2, Bound):
                            return self.process_elt(v2.expr, v2.ctx, cond, prefix, chain, site, helpers, _depth + 1)
            why = v.why if isinstance(v, Unknown) else "not a URL pattern"
            self._gap("unsupported_url_construct", site[0], where, f"{_u(expr)}: {why}", getattr(expr, "lineno", 0))
            return
        if isinstance(expr, ast.IfExp):
            for alt in (expr.body, expr.orelse):
                if not (isinstance(alt, ast.Constant) and alt.value is None):
                    self.process_elt(alt, ctx, True, prefix, chain, site, helpers, _depth + 1)
            return
        if isinstance(expr, ast.Call):
            fq = self.qname(ctx, expr.func)
            leaf = expr.func.id if isinstance(expr.func, ast.Name) else getattr(expr.func, "attr", "")
            if fq in PATH_FUNCS or (fq is None and leaf in ("path", "re_path", "url") and
                                    self.lookup(ctx, leaf) is MISSING):
                self.handle_path(expr, ctx, cond, prefix, chain, site, helpers,
                                 regex=(fq in REGEX_FUNCS) if fq else leaf != "path")
                return
            if fq and fq in self.p.functions:
                ops, why = self.expand_helper(fq, expr, ctx, cond, helpers)
                if ops is None:
                    self._gap("unsupported_url_construct", site[0], where,
                              f"{_u(site[1])}: URL helper {fq} not understood ({why})", getattr(site[1], "lineno", 0))
                    return
                for op in ops:
                    self.process_op(op, prefix, chain, site, helpers + (fq,), cond=cond)
                return
            pair = self._helper_route_args(expr, ctx) if fq not in (self.p.functions or {}) else None
            if pair is not None:
                # (v6) a library helper that wraps path() (feature-flag / conditional route helpers such as
                # `flagged_path(FLAG, "x/", include(...))`): read as path(route, view) and kept CONDITIONAL; the
                # assumption is a gap, so the routes behind it are visible instead of lost
                route_expr, view_expr = pair
                fake = ast.Call(func=ast.Name(id="path", ctx=ast.Load()), args=[route_expr, view_expr], keywords=[])
                ast.copy_location(fake, expr)
                self._gap("url_helper_read_as_path", site[0], where,
                          f"{_u(expr)}: library helper {fq or leaf} read as path({_u(route_expr)}, ...), conditional",
                          getattr(site[1], "lineno", 0))
                self.handle_path(fake, ctx, True, prefix, chain, site, helpers + (fq or leaf,),
                                 regex="re_path" in leaf or leaf in ("url",))
                return
        self._gap("unsupported_url_construct", site[0], where, _u(expr) if expr is site[1] else
                  f"{_u(site[1])} -> {_u(expr)}", getattr(site[1], "lineno", 0))

    def _helper_route_args(self, call, ctx):
        """(route expression, view expression) when an unknown call takes a string route followed by an include()
        or a view (`helper(..., "prefix/", include(...))`, `helper("x/", View.as_view())`), else None."""
        args = list(call.args)
        for i in range(len(args) - 1):
            r, v = args[i], args[i + 1]
            if not (isinstance(r, ast.Constant) and isinstance(r.value, str)):
                continue
            if isinstance(v, ast.Call):
                fq = self.qname(ctx, v.func) or ""
                leaf = v.func.attr if isinstance(v.func, ast.Attribute) else getattr(v.func, "id", "")
                if fq in INCLUDE_FUNCS or leaf in ("include", "as_view"):
                    return r, v
            elif isinstance(v, (ast.Name, ast.Attribute)) and not (isinstance(v, ast.Attribute) and
                                                                    v.attr in ("urls",)) and \
                    (self.qname(ctx, v) or "") in self.p.functions:
                return r, v
        return None

    def handle_path(self, call, ctx, cond, prefix: RT, chain, site, helpers, regex=False):
        smod, snode = site
        where = prefix.text or "/"
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            self._gap("unsupported_url_construct", smod, where, _u(snode), getattr(snode, "lineno", 0))
            return
        args = list(call.args)
        kw = {k.arg: k.value for k in call.keywords}
        route_expr = args[0] if args else kw.get("route")
        view_expr = args[1] if len(args) > 1 else kw.get("view")
        kwargs_expr = args[2] if len(args) > 2 else kw.get("kwargs")
        name_expr = args[3] if len(args) > 3 else kw.get("name")
        rt = self.str_value(route_expr, ctx) if route_expr is not None else None
        if rt is None or rt.dyn:
            self._gap("dynamic_route_pattern", smod, where,
                      _u(self._display(route_expr, ctx)) if route_expr is not None else "?",
                      getattr(snode, "lineno", 0))
            if rt is None:
                rt = DYN
        rt = RT(rt.text, rt.key, rt.dyn, regex)
        nv = self.str_value(name_expr, ctx) if name_expr is not None else None
        name = nv.text if nv is not None and nv.literal else None
        if view_expr is None:
            self._gap("unsupported_url_construct", smod, rt.text, _u(snode), getattr(snode, "lineno", 0))
            return
        self._seq += 1
        seq = self._seq
        pattern = prefix.join(rt)
        target = self.handle_view(view_expr, ctx, pattern, name, cond, chain, site, [], [], helpers, seq)
        if kwargs_expr is not None and target:
            self.dispatch_targets(kwargs_expr, ctx, pattern, name, cond, chain, site, helpers, seq, target)

    def _display(self, expr, ctx):
        """The expression as written at the call site (helper parameters followed back)."""
        for _ in range(MAX_HELPER_DEPTH + 1):
            if isinstance(expr, ast.Name) and isinstance(self.lookup(ctx, expr.id), Bound) and ctx.func is not None \
                    and expr.id in ctx.env:
                b = self.lookup(ctx, expr.id)
                expr, ctx = b.expr, b.ctx
            else:
                break
        return expr

    def dispatch_targets(self, kwargs_expr, ctx, pattern, name, cond, chain, site, helpers, seq, dispatcher):
        kd = self.kw_dict(kwargs_expr, ctx)
        if kd is None:
            return
        file, line = self.p.modules[site[0]].path, getattr(site[1], "lineno", 0)
        for key, val in kd.items:
            t = self.callable_target(val)
            if not t:
                continue
            kind, target, extra = t
            self.routes.append(self._route(pattern, name, kind, target, file, line, site[1], cond, chain, seq,
                                           helpers=list(helpers), dispatcher=dispatcher, dispatch_key=key, **extra))
            self.dispatchers.setdefault(dispatcher, set()).add(target)

    def callable_target(self, val, _depth=0):
        """(kind, target, extra) for a view callable passed as a value, else None."""
        if not isinstance(val, Bound) or _depth > MAX_DEPTH:
            return None
        e, ctx = val.expr, val.ctx
        if isinstance(e, (ast.Tuple, ast.List)) and e.elts:
            return self.callable_target(Bound(e.elts[0], ctx), _depth + 1)
        if isinstance(e, ast.Name) and isinstance(self.lookup(ctx, e.id), Bound):
            return self.callable_target(self.lookup(ctx, e.id), _depth + 1)
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "as_view":
            cq = self.qname(ctx, e.func.value)
            if cq:
                kwargs = {k.arg: k.value for k in e.keywords if k.arg}
                return ("project_class" if cq in self.p.classes else "library_view"), cq, dict(as_view_kwargs=kwargs)
            return None
        if isinstance(e, (ast.Name, ast.Attribute)):
            q = self.qname(ctx, e)
            if q and q in self.p.functions:
                return "project_function", q, {}
        return None

    def handle_view(self, v, ctx, pattern: RT, name, cond, chain, site, decorators, wrappers, helpers, seq,
                    _depth=0):
        """Record route(s) for a view expression; returns the resolved view target (or None)."""
        smod, snode = site
        file = self.p.modules[smod].path
        line = getattr(snode, "lineno", 0)
        ptext = pattern.text

        def add(kind, target, **extra):
            self.routes.append(self._route(pattern, name, kind, target, file, line, snode, cond, chain, seq,
                                           decorators=list(decorators), wrapper_funcs=list(wrappers),
                                           helpers=list(helpers), **extra))
            return target

        if _depth > MAX_DEPTH:
            self._gap("unsupported_view_expr", smod, ptext, _u(v), line)
            return None
        if isinstance(v, ast.IfExp):
            # `view_a if settings.X else view_b`: a route for each alternative, both conditional
            first = None
            for alt in (v.body, v.orelse):
                t = self.handle_view(alt, ctx, pattern, name, True, chain, site, decorators, wrappers, helpers, seq,
                                     _depth + 1)
                first = first or t
            return first
        if isinstance(v, ast.Name):
            b = self.lookup(ctx, v.id)
            if isinstance(b, Bound):
                return self.handle_view(b.expr, b.ctx, pattern, name, cond, chain, site, decorators, wrappers,
                                        helpers, seq, _depth + 1)
            if isinstance(b, Alts):
                first = None
                for actx in self.alt_ctxs(ctx, v.id, b):
                    t = self.handle_view(v, actx, pattern, name, True, chain, site, decorators, wrappers, helpers,
                                         seq, _depth + 1)
                    first = first or t
                return first
            if b is not MISSING and not isinstance(b, Ref):
                self._gap("unresolved_view", smod, ptext, f"{_u(v)}: {b.why if isinstance(b, Unknown) else 'value'}",
                          line)
                return None
        if isinstance(v, ast.Call):
            fq = self.qname(ctx, v.func)
            if fq in INCLUDE_FUNCS or (fq is None and isinstance(v.func, ast.Name) and v.func.id == "include"):
                if not v.args:
                    self._gap("unsupported_url_construct", smod, ptext, _u(v), line)
                    return None
                self.handle_include(v.args[0], ctx, pattern, cond, chain, site, add, helpers)
                return None
            if isinstance(v.func, ast.Attribute) and v.func.attr == "as_view":
                cq = self.qname(ctx, v.func.value)
                kwargs = {k.arg: k.value for k in v.keywords if k.arg}
                actions = None
                if v.args and isinstance(v.args[0], ast.Dict):
                    actions = {k.value: val.value for k, val in zip(v.args[0].keys, v.args[0].values)
                               if isinstance(k, ast.Constant) and isinstance(val, ast.Constant)}
                if cq and cq in self.p.classes:
                    return add("viewset" if actions else "project_class", cq, as_view_kwargs=kwargs, actions=actions)
                if cq:
                    return add("library_view", cq, as_view_kwargs=kwargs, actions=actions)
                self._gap("unresolved_view", smod, ptext, _u(v), line)
                return None
            if v.args:  # decorator-style wrapper: csrf_exempt(view), login_required(View.as_view())
                if fq and fq in self.p.functions:
                    wrappers = wrappers + [fq]
                if fq is None and isinstance(v.func, ast.Call):
                    # (v5) a decorator factory: cache_page(60)(view) -> name the factory
                    fq2 = self.qname(ctx, v.func.func)
                    decorators = decorators + [fq2 or _u(v.func)]
                else:
                    decorators = decorators + [fq or _u(v.func)]
                return self.handle_view(v.args[0], ctx, pattern, name, cond, chain, site, decorators, wrappers,
                                        helpers, seq, _depth + 1)
            if fq and fq in self.p.classes and not v.keywords:
                # (v6) an instance of a project class used as the view (`path("feed/", CalendarFeed())`): Django
                # calls instance(request, ...), i.e. its __call__
                r = self.p.lookup_method(fq, "__call__")
                if r and r[0] == "project":
                    return add("project_function", r[1])
            self._gap("unsupported_view_expr", smod, ptext, _u(v), line)
            return None
        if isinstance(v, (ast.Name, ast.Attribute)):
            q = self.qname(ctx, v)
            if q is None:
                self._gap("unresolved_view", smod, ptext, _u(v), line)
                return None
            if q == "django.contrib.admin.site.urls" or q.endswith("admin.site.urls"):
                return add("admin_site", "django.contrib.admin.site.urls")
            if q in self.p.functions:
                return add("project_function", q)
            m2, rest = self.p.module_prefix(q)
            if m2 and len(rest) == 1 and rest[0] in self.p.modules[m2].view_aliases:
                cq, call = self.p.modules[m2].view_aliases[rest[0]]
                kwargs = {k.arg: k.value for k in call.keywords if k.arg}
                return add("project_class" if cq in self.p.classes else "library_view", cq, as_view_kwargs=kwargs)
            if m2 and len(rest) == 1:
                b = self.module_env(m2).get(rest[0], MISSING)
                if isinstance(b, Bound) and m2 != ctx.mod:
                    return self.handle_view(b.expr, b.ctx, pattern, name, cond, chain, site, decorators, wrappers,
                                            helpers, seq, _depth + 1)
            if m2:
                self._gap("unresolved_view", smod, ptext, f"{_u(v)} -> {q}", line)
                return None
            return add("library_view", q)
        self._gap("unsupported_view_expr", smod, ptext, _u(v), line)
        return None

    def handle_include(self, arg, ctx, pattern: RT, cond, chain, site, add, helpers, _depth=0):
        smod, snode = site
        line = getattr(snode, "lineno", 0)
        if isinstance(arg, ast.Tuple) and arg.elts:
            arg = arg.elts[0]
        if _depth > MAX_DEPTH:
            self._gap("url_include_cycle", smod, pattern.text, _u(arg), line)
            return
        s = None
        if isinstance(arg, ast.Name):
            b = self.lookup(ctx, arg.id)
            if isinstance(b, Alts):
                for actx in self.alt_ctxs(ctx, arg.id, b):
                    self.handle_include(arg, actx, pattern, True, chain, site, add, helpers, _depth + 1)
                return
            if isinstance(b, RT):
                s = b
            elif isinstance(b, Bound) and not self._listish(b.expr, b.ctx):
                # a parameter / module name bound to a module string, a module object or another name
                return self.handle_include(b.expr, b.ctx, pattern, cond, chain, site, add, helpers, _depth + 1)
            elif isinstance(b, Unknown):
                self._gap("unsupported_url_construct", smod, pattern.text, f"include({_u(arg)}): {b.why}", line)
                return
        if s is None and _strish(arg):
            s = self.str_value(arg, ctx)
        if s is not None:
            if not s.literal:
                self._gap("unsupported_url_construct", smod, pattern.text, f"include({_u(self._display(arg, ctx))}): "
                          f"module name is not static ({s.text})", line)
                return
            if s.text in self.p.modules:
                self.walk_module(s.text, pattern, chain, cond)
            elif self.p.unalias(s.text) in self.p.modules:
                # (v5 review fix) a module named relative to another sys.path root (`apps/` on sys.path)
                self.walk_module(self.p.unalias(s.text), pattern, chain, cond)
            else:
                add("library_include", s.text)
            return
        if isinstance(arg, (ast.Name, ast.Attribute)) and not (isinstance(arg, ast.Name) and
                                                                self.lookup(ctx, arg.id) is not MISSING and
                                                                not isinstance(self.lookup(ctx, arg.id), Ref)):
            q = self.qname(ctx, arg)
            if q and q in self.p.modules:
                self.walk_module(q, pattern, chain, cond)
                return
            if q and (q == "django.contrib.admin.site.urls" or q.endswith("admin.site.urls")):
                add("admin_site", "django.contrib.admin.site.urls")
                return
        bound = self.lookup(ctx, arg.id) if isinstance(arg, ast.Name) else MISSING
        key = (id(bound) if bound is not MISSING else id(arg), pattern.text)
        if key in self._including:
            self._gap("url_include_cycle", smod, pattern.text, _u(arg), line)
            return
        self._including.add(key)
        try:
            for op in self.struct(arg, ctx, cond):
                self.process_op(op, pattern, chain + [f"{ctx.mod}:<list>"], cond=cond)
        finally:
            self._including.discard(key)


def _ends_in_raise(body) -> bool:
    """A block whose last statement is `raise` (an except handler that re-raises)."""
    return bool(body) and isinstance(body[-1], ast.Raise)


def _strish(expr) -> bool:
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, str)
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _strish(expr.left) or _strish(expr.right)
    return False


# ------------------------------------------------------------------ first-match shadowing (P5)
_CONVERTER = re.compile(r"<(?:(\w+):)?\w+>")


def _norm_key(r_key: str | None, regex: bool):
    """Comparison key of a full route.  For path() routes the parameter names are dropped
    (`<int:pk>` and `<int:id>` match exactly the same URLs; `<x>` is `<str:x>`); regex routes are
    compared as written."""
    if r_key is None:
        return None
    if regex:
        return "re:" + r_key
    return "p:" + _CONVERTER.sub(lambda m: "<" + (m.group(1) or "str") + ">", r_key)


def mark_shadowing(routes: list, library_subroutes: dict | None = None) -> None:
    """Django tries URL patterns in order and dispatches to the FIRST match.  For every root URLconf,
    an endpoint route whose full pattern is literally equal (same text up to converter parameter names,
    same placeholders, same path/regex kind) to an earlier endpoint route from a different path() call
    can never be reached: mark it `shadowed_by` (or `may_be_shadowed_by` when the earlier route is
    conditional).  Routes whose pattern contains a part MintMap cannot evaluate are never compared.
    Library includes take part through the catalog's known sub-routes of their mint flows
    (`library_subroutes`: include symbol -> {catalog ref: [sub-route, ...]}): in both directions, an
    earlier library sub-route shadows a later project route, and a library mint flow is shadowed when
    EVERY sub-route listed for it is shadowed by earlier unconditional routes."""
    library_subroutes = library_subroutes or {}
    by_root: dict = {}
    for r in routes:
        by_root.setdefault(r.root, []).append(r)
    for rs in by_root.values():
        seen: dict = {}   # key -> [(route, pattern_text)] in first-match order

        def earlier(r, key):
            prev = [(pr, pt) for pr, pt in seen.get(key, []) if pr.seq != r.seq]
            hard = next(((pr, pt) for pr, pt in prev if not pr.conditional), None)
            soft = next(((pr, pt) for pr, pt in prev if pr.conditional), None)
            return hard, soft

        for r in rs:
            if r.kind in ENDPOINT_KINDS:
                key = _norm_key(r.key, r.regex)
                if key is None:
                    continue
                hard, soft = earlier(r, key)
                if hard:
                    r.shadowed_by = r.shadowed_by or hard[0].shadow_info(hard[1])
                    continue
                if soft:
                    r.may_be_shadowed_by = r.may_be_shadowed_by or soft[0].shadow_info(soft[1])
                seen.setdefault(key, []).append((r, r.pattern))
            elif r.kind in ("library_include", "admin_site"):
                for ref, subs in sorted(library_subroutes.get(r.target, {}).items()):
                    shadows = []
                    for sub in subs:
                        full = r.pattern if r.regex else _join(r.pattern, sub)
                        r.library_routes.setdefault(ref, []).append(full)
                        key = None if r.key is None or r.regex else _norm_key(_join(r.key, sub), False)
                        if key is None:
                            shadows.append(None)
                            continue
                        hard, _soft = earlier(r, key)
                        shadows.append(hard[0].shadow_info(hard[1]) if hard else None)
                        if not hard:
                            seen.setdefault(key, []).append((r, full))
                    if shadows and all(shadows):
                        r.library_shadowed.setdefault(ref, shadows[0])


# ------------------------------------------------------------------ roots
def collect_string_includes(project: Project, modname: str) -> set:
    out = set()
    mod = project.modules[modname]
    for n in ast.walk(mod.tree):
        if isinstance(n, ast.Call) and n.args:
            f = n.func
            if (isinstance(f, ast.Name) and f.id == "include") or (isinstance(f, ast.Attribute) and f.attr == "include"):
                a = n.args[0]
                if isinstance(a, ast.Tuple) and a.elts:
                    a = a.elts[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    out.add(a.value)
                    out.add(project.unalias(a.value))
                elif isinstance(a, (ast.Name, ast.Attribute)):
                    q = project.resolve_expr_static(modname, a)
                    if q:
                        out.add(project.canonical(q))
    return out


def find_root_urlconfs(project: Project, settings_values) -> tuple[list, list]:
    gaps = []
    ru = settings_values.get("ROOT_URLCONF")
    roots = []
    for v in (ru if isinstance(ru, list) else [ru]):
        if isinstance(v, str):
            if v in project.modules:
                roots.append(v)
            else:
                gaps.append(Gap("root_urlconf_not_found", "-", "ROOT_URLCONF", v))
    if roots:
        return roots, gaps
    cands = [m for m in project.modules if (m == "urls" or m.endswith(".urls")) and
             "urlpatterns" in project.modules[m].assigns]
    included = set()
    for m in cands:
        included |= collect_string_includes(project, m)
    roots = sorted(m for m in cands if m not in included)
    if roots:
        gaps.append(Gap("root_urlconf_inferred", "-", "ROOT_URLCONF", ",".join(roots)))
    return roots, gaps

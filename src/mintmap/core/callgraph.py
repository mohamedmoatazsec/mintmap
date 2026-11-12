"""Call-site extraction and context-sensitive call resolution.

A function is analysed once (its call sites), and each call site is resolved
under a *context class*: the concrete class a CBV/method runs as.  This makes
`self.helper()` and `super().form_valid()` resolve against the routed class's
MRO rather than the class that happens to define the method.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .fingerprint import stable_unparse
from .project import Project, FunctionInfo

# Method names too generic to be worth reporting when unresolved.
GENERIC_LEAVES = {
    "get", "post", "put", "patch", "delete", "save", "create", "update", "filter", "exclude", "all", "first",
    "last", "count", "exists", "values", "values_list", "order_by", "select_related", "prefetch_related",
    "get_or_create", "update_or_create", "append", "extend", "insert", "pop", "items", "keys", "join", "split",
    "strip", "lower", "upper", "format", "replace", "startswith", "endswith", "encode", "decode", "dumps",
    "loads", "sign", "unsign", "copy", "add", "remove", "discard", "setdefault", "is_valid", "clean",
    "full_clean", "send", "send_mail", "render", "render_to_response", "info", "debug", "warning", "error",
    "exception", "critical", "log", "__init__", "super", "done", "finish", "handle", "redirect", "reverse",
    "set_cookie", "delete_cookie", "flush", "cycle_key", "set_expiry", "set_password", "set_unusable_password",
    "using", "none", "aggregate", "annotate", "distinct", "bulk_create", "in_bulk", "iterator", "latest",
    "earliest", "refresh_from_db", "full_name", "is_authenticated", "is_anonymous", "has_perm",
}


@dataclass
class CallSite:
    func: str
    node: ast.AST            # ast.Call, or ast.Attribute for property reads
    line: int
    text: str                # unparsed callee expression
    leaf: str                # last name component of the callee
    is_property: bool = False


@dataclass
class Resolution:
    targets: list = field(default_factory=list)   # [(func_qn, ctx_cls)] project functions
    library: str | None = None                    # canonical library qualname
    library_candidates: list = field(default_factory=list)  # library MRO expansions of `library`
    receiver_type: str | None = None
    receiver_var: str | None = None               # simple Name receiver, if any
    instantiates: str | None = None               # class qualname for constructor calls
    unresolved: str | None = None                 # text, when nothing could be resolved
    via: str = ""                                 # how it was resolved (for reports)


def _is_class_like(project: Project, qn: str | None, known=frozenset()) -> bool:
    """Is a called name a class (so the call is a constructor and its result has that type)?  Project
    classes and (v4) library classes the catalog/overlay know (`known`, e.g. pyotp `TOTP`, whose all-caps
    name the CapWords heuristic rejects) are; otherwise a CapWords name that is not all upper case."""
    if not qn:
        return False
    if qn in project.classes or qn in known:
        return True
    last = qn.rsplit(".", 1)[-1]
    return last[:1].isupper() and not last.isupper()


def known_library_classes(project: Project, catalog) -> frozenset:
    """(v4) Library classes named by the catalog and the overlay: overlay bases (re-export aliases such as
    `pyotp.TOTP` -> `pyotp.totp.TOTP` included), declared return types, the classes of catalog methods
    (`pkg.mod.Cls.method` with a capitalised `Cls`), and catalog check constructors, forms, views,
    middleware and property-mint receivers."""
    out = set(project.library_bases) | {b for bs in project.library_bases.values() for b in bs}
    out |= {t for t in project.library_returns.values() if t}
    if catalog is not None:
        for sym in list(catalog.check_calls) + list(catalog.mint_calls):
            cls = sym.rpartition(".")[0]
            if cls and cls.rsplit(".", 1)[-1][:1].isupper():
                out.add(cls)
        out |= {m.returns for m in catalog.mint_calls.values() if getattr(m, "returns", None)}
        out |= set(catalog.check_constructors) | set(catalog.form_checks) | set(catalog.library_views)
        out |= set(catalog.library_middleware) | {r for r, _attr in catalog.property_mints}
    return frozenset(x for x in out if isinstance(x, str))


class CallGraph:
    def __init__(self, project: Project, catalog):
        self.p = project
        self.catalog = catalog
        self._sites: dict[str, list[CallSite]] = {}
        self._types: dict[tuple, dict] = {}
        self._cands: dict[tuple, dict] = {}
        self._attr_types: dict[tuple, str | None] = {}
        self._self_assign_cache: dict[str, dict] = {}
        self._self_calls: dict = {}
        self._class_self: dict = {}
        self._resolved: dict = {}
        self.known_classes = known_library_classes(project, catalog)

    # ----------------------------------------------------------------- sites
    def sites(self, func_qn: str) -> list[CallSite]:
        if func_qn in self._sites:
            return self._sites[func_qn]
        info = self.p.functions[func_qn]
        out = []
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Call):
                text = _safe_unparse(n.func)
                leaf = n.func.attr if isinstance(n.func, ast.Attribute) else (
                    n.func.id if isinstance(n.func, ast.Name) else "")
                out.append(CallSite(func_qn, n, n.lineno, text, leaf))
            elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and isinstance(n.value, ast.Name):
                if any(attr == n.attr for (_, attr) in self.catalog.property_mints):
                    out.append(CallSite(func_qn, n, n.lineno, _safe_unparse(n), n.attr, is_property=True))
        out.sort(key=lambda s: (s.line, getattr(s.node, "col_offset", 0)))
        self._sites[func_qn] = out
        return out

    # ----------------------------------------------------------------- types
    def class_attr_type(self, ctx: str | None, attr: str) -> str | None:
        if not ctx:
            return None
        owner, expr = self.p.class_attr(ctx, attr)
        if expr is None:
            # library default (e.g. LoginView.form_class = AuthenticationForm)
            from .overlay import LIBRARY_VIEW_FORM_CLASS
            if attr == "form_class":
                for c in self.p.mro(ctx):
                    if c in LIBRARY_VIEW_FORM_CLASS:
                        return LIBRARY_VIEW_FORM_CLASS[c]
            return None
        q = self.p.resolve_expr_static(self.p.classes[owner].module, expr)
        return self.p.canonical(q) if q else None

    def var_types(self, func_qn: str, ctx: str | None) -> dict:
        key = (func_qn, ctx)
        if key in self._types:
            return self._types[key]
        info = self.p.functions[func_qn]
        types: dict = {}
        self._types[key] = types  # recursion guard
        cls_ctx = ctx or info.cls
        args = info.node.args.posonlyargs + info.node.args.args + info.node.args.kwonlyargs
        if info.cls and args and args[0].arg in ("self", "cls"):
            types[args[0].arg] = cls_ctx
        for a in args:
            if a.annotation is not None:
                q = self.annotation_type(info.module, a.annotation, info)
                if q:
                    types[a.arg] = q
        name = info.qualname.rsplit(".", 1)[-1]
        if info.cls and name in ("form_valid", "form_invalid") and len(args) >= 2:
            t = self.class_attr_type(cls_ctx, "form_class")
            if t:
                types.setdefault(args[1].arg, t)
        if info.cls and name in ("perform_create", "perform_update") and len(args) >= 2:
            # (v5, R3) DRF passes the view's serializer (serializer_class) to these hooks; (v6) perform_destroy
            # receives the model instance being deleted (rest_framework/mixins.py:94), not the serializer
            t = self.class_attr_type(cls_ctx, "serializer_class")
            if t:
                types.setdefault(args[1].arg, t)
        if info.cls and args and args[0].arg in ("self", "cls"):
            # (v5, R3) an unannotated parameter that every `self.<name>(...)` call in the class hierarchy passes
            # an instance of the same project class (e.g. a view's post() passing its serializer to
            # self.perform_create(serializer))
            for pname, t in self._param_types_from_self_calls(info, cls_ctx, name, args).items():
                types.setdefault(pname, t)
        cands: dict = {}
        self._cands[key] = cands
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                v = n.targets[0].id
                if _is_none(n.value):
                    continue  # `form = None` placeholder: does not decide the variable's type
                t = self.expr_type(n.value, info, cls_ctx, types)
                if t:
                    cands.setdefault(v, set()).add(t)
                if v in types and types[v] != t:
                    types[v] = None
                else:
                    types[v] = t
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                t = self.annotation_type(info.module, n.annotation, info)
                if t is None and n.value is not None and not _is_none(n.value):
                    t = self.expr_type(n.value, info, cls_ctx, types)
                if t:
                    cands.setdefault(n.target.id, set()).add(t)
                types[n.target.id] = t if (n.target.id not in types or types[n.target.id] == t) else None
            elif isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                types[n.target.id] = self.expr_type(n.value, info, cls_ctx, types)
                if types[n.target.id]:
                    cands.setdefault(n.target.id, set()).add(types[n.target.id])
        return types

    def _self_call_index(self, cls_ctx: str) -> dict:
        """method name -> [(caller qualname, Call)] for `self.<name>(...)` calls in the project MRO of cls_ctx."""
        hit = self._self_calls.get(cls_ctx)
        if hit is not None:
            return hit
        out: dict = {}
        for c in self.p.mro(cls_ctx):
            if c not in self.p.classes:
                continue
            for name, lst in self._class_self_calls(c).items():
                out.setdefault(name, []).extend(lst)
        self._self_calls[cls_ctx] = out
        return out

    def _class_self_calls(self, c: str) -> dict:
        hit = self._class_self.get(c)
        if hit is not None:
            return hit
        out: dict = {}
        for mq in self.p.classes[c].methods.values():
            fi = self.p.functions[mq]
            if not fi.params or fi.params[0] not in ("self", "cls"):
                continue
            for n in self.p.walk_function_body(fi.node):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                        isinstance(n.func.value, ast.Name) and n.func.value.id == fi.params[0]:
                    out.setdefault(n.func.attr, []).append((mq, n))
        self._class_self[c] = out
        return out

    def _param_types_from_self_calls(self, info, cls_ctx, name, args) -> dict:
        calls = self._self_call_index(cls_ctx).get(name, [])
        if not calls:
            return {}
        params = [a.arg for a in args[1:]]
        seen: dict = {}
        for caller, call in calls:
            if caller == info.qualname:
                continue
            ctypes = self.var_types(caller, cls_ctx)
            given = {}
            for i, a in enumerate(call.args):
                if isinstance(a, ast.Starred):
                    return {}
                if i < len(params):
                    given[params[i]] = a
            for k in call.keywords:
                if k.arg in params:
                    given[k.arg] = k.value
            for pn in params:
                a = given.get(pn)
                t = ctypes.get(a.id) if isinstance(a, ast.Name) else None
                seen.setdefault(pn, set()).add(t if t in self.p.classes else None)
        return {pn: next(iter(ts)) for pn, ts in seen.items() if len(ts) == 1 and None not in ts}

    def var_type_candidates(self, func_qn: str, ctx: str | None) -> dict:
        """var -> every class type assigned to it in the function (unknown values ignored).
        Used where over-approximation is wanted (framework-implied validation edges)."""
        self.var_types(func_qn, ctx)
        return self._cands.get((func_qn, ctx), {})

    def annotation_type(self, module: str, ann, info: FunctionInfo | None) -> str | None:
        """`T`, `mod.T`, `"T"`, `T | None`, `Optional[T]` -> canonical qualname of T."""
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            try:
                ann = ast.parse(ann.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            parts = [x for x in (ann.left, ann.right) if not _is_none(x)]
            return self.annotation_type(module, parts[0], info) if len(parts) == 1 else None
        if isinstance(ann, ast.Subscript):
            base = self.p.resolve_expr_static(module, ann.value, info) or ""
            if base.rsplit(".", 1)[-1] == "Optional":
                return self.annotation_type(module, ann.slice, info)
            return None
        if isinstance(ann, (ast.Name, ast.Attribute)):
            q = self.p.resolve_expr_static(module, ann, info)
            return self.p.canonical(q) if q else None
        return None

    def _self_assigns(self, cls_qn: str) -> dict:
        """attr -> [(method qualname, value expr | None, annotation | None)] for every `self.<attr> = ...`
        in the methods of one project class, plus class-level annotations (method None).  Cached."""
        hit = self._self_assign_cache.get(cls_qn)
        if hit is not None:
            return hit
        out: dict = {}
        ci = self.p.classes[cls_qn]
        for st in ci.node.body:
            if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                out.setdefault(st.target.id, []).append((None, None, st.annotation))
        for mq in ci.methods.values():
            info = self.p.functions[mq]
            if not info.params or any(_u(d) == "staticmethod" for d in info.node.decorator_list):
                continue
            selfname = info.params[0]
            for n in self.p.walk_function_body(info.node):
                if isinstance(n, ast.Assign) and len(n.targets) == 1:
                    target, value, ann = n.targets[0], n.value, None
                elif isinstance(n, ast.AnnAssign):
                    target, value, ann = n.target, n.value, n.annotation
                else:
                    continue
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and \
                        target.value.id == selfname:
                    out.setdefault(target.attr, []).append((mq, value, ann))
        self._self_assign_cache[cls_qn] = out
        return out

    def attr_type(self, cls_ctx: str | None, attr: str) -> str | None:
        """Type of `self.<attr>` for instances of cls_ctx: every `self.<attr> = value` (or annotated
        assignment) in a method of a project class in the MRO, plus class-level annotations.  Known
        only when all assignments agree; an assignment of unknown type makes it unknown.  `None`
        placeholders are ignored."""
        if not cls_ctx:
            return None
        key = (cls_ctx, attr)
        if key in self._attr_types:
            return self._attr_types[key]
        self._attr_types[key] = None  # recursion guard
        found, unknown = set(), False
        for c in self.p.mro(cls_ctx):
            if c not in self.p.classes:
                continue
            for mq, value, ann in self._self_assigns(c).get(attr, ()):
                info = self.p.functions[mq] if mq else None
                module = info.module if info else self.p.classes[c].module
                t = self.annotation_type(module, ann, info) if ann is not None else None
                if t is None and value is not None and info is not None:
                    if _is_none(value):
                        continue
                    t = self.expr_type(value, info, cls_ctx, self.var_types(mq, cls_ctx))
                if t:
                    found.add(t)
                elif mq is not None:
                    unknown = True
        out = next(iter(found)) if len(found) == 1 and not unknown else None
        self._attr_types[key] = out
        return out

    def expr_type(self, expr, info: FunctionInfo, ctx: str | None, types: dict) -> str | None:
        if isinstance(expr, ast.Await):
            return self.expr_type(expr.value, info, ctx, types)
        if isinstance(expr, ast.Name):
            return types.get(expr.id)
        if isinstance(expr, ast.IfExp):
            a = self.expr_type(expr.body, info, ctx, types)
            b = None if _is_none(expr.orelse) else self.expr_type(expr.orelse, info, ctx, types)
            return a if (a and (b == a or _is_none(expr.orelse))) else None
        if (isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name) and info.cls and info.params
                and expr.value.id == info.params[0] and expr.value.id in ("self", "cls")):
            return self.attr_type(ctx or info.cls, expr.attr)
        if isinstance(expr, ast.Call):
            f = expr.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self" and ctx:
                if f.attr in ("get_serializer",):
                    return self.class_attr_type(ctx, "serializer_class")
                if f.attr in ("get_form",):
                    return self.class_attr_type(ctx, "form_class")
            q = self.p.resolve_expr_static(info.module, f, info)
            q = self.p.canonical(q) if q else None
            if q:
                mint = self.catalog.mint_calls.get(q)
                if mint and mint.returns:
                    return mint.returns
                if q in self.p.library_returns:
                    return self.p.library_returns[q]
                if _is_class_like(self.p, q, self.known_classes):
                    return q
            return None
        return None

    # ------------------------------------------------------------ resolution
    def _library_expansions(self, qn: str) -> list:
        """'lib.Cls.meth' -> ['lib.Cls.meth', 'lib.Base.meth', ...] using overlay bases."""
        cls, _, meth = qn.rpartition(".")
        out = [qn]
        if cls in self.p.library_bases:
            for c in self.p.mro(cls)[1:]:
                out.append(f"{c}.{meth}")
        return out

    def _method_on_type(self, typ: str, meth: str, res: Resolution, after: str | None = None):
        if typ in self.p.classes or after is not None:
            r = self.p.lookup_method(typ, meth, after=after)
            if r is None:
                res.unresolved = f"{typ}.{meth} (not found in MRO)"
            elif r[0] == "project":
                ctx = typ if typ in self.p.classes else None
                res.targets.append((r[1], ctx))
            else:
                res.library = r[1]
                res.library_candidates = self._library_expansions(r[1])
        else:
            res.library = f"{typ}.{meth}"
            res.library_candidates = self._library_expansions(res.library)

    def resolve(self, site: CallSite, ctx: str | None) -> Resolution:
        key = (id(site.node), ctx)
        cached = self._resolved.get(key)
        if cached is None:
            cached = self._resolve(site, ctx)
            self._resolved[key] = cached
        return cached

    def _resolve(self, site: CallSite, ctx: str | None) -> Resolution:
        info = self.p.functions[site.func]
        cls_ctx = ctx or info.cls
        res = Resolution()
        node = site.node
        if site.is_property:
            types = self.var_types(site.func, ctx)
            res.receiver_var = node.value.id
            res.receiver_type = types.get(node.value.id)
            if res.receiver_type:
                res.library = f"{res.receiver_type}.{node.attr}"
            res.via = "property"
            return res
        f = node.func
        # super().m(...)
        if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call) and isinstance(f.value.func, ast.Name)
                and f.value.func.id == "super"):
            if info.cls:
                res.via = "super"
                self._method_on_type(cls_ctx, f.attr, res, after=info.cls)
            else:
                res.unresolved = site.text
            return res
        # self.m(...) / cls.m(...)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and info.cls and \
                info.params and f.value.id == info.params[0] and f.value.id in ("self", "cls"):
            res.via = "self"
            res.receiver_type = cls_ctx
            r = self.p.lookup_method(cls_ctx, f.attr)
            if r is None:
                res.unresolved = site.text
            elif r[0] == "project":
                res.targets.append((r[1], cls_ctx))
            else:
                res.library = r[1]
                res.library_candidates = self._library_expansions(r[1])
            return res
        # statically resolvable name / attribute chain
        q = self.p.resolve_expr_static(info.module, f, info) if isinstance(f, (ast.Name, ast.Attribute)) else None
        if q:
            q = self.p.canonical(q)
            res.via = "static"
            if q in self.p.functions:
                fi = self.p.functions[q]
                res.targets.append((q, fi.cls))
                return res
            if q in self.p.classes:
                res.instantiates = q
                r = self.p.lookup_method(q, "__init__")
                if r and r[0] == "project":
                    res.targets.append((r[1], q))
                return res
            mod, rest = self.p.module_prefix(q)
            if mod is not None and rest:
                m = self.p.modules[mod]
                head = f"{mod}.{rest[0]}"
                if len(rest) >= 2 and head in self.p.classes:
                    self._method_on_type(head, rest[-1], res)
                    return res
                if len(rest) >= 2 and rest[0] in m.instances:
                    res.receiver_type = m.instances[rest[0]]
                    self._method_on_type(m.instances[rest[0]], rest[-1], res)
                    return res
                res.unresolved = site.text
                return res
            # library symbol
            if _is_class_like(self.p, q, self.known_classes) and not q.endswith(".objects"):
                res.instantiates = q
            res.library = q
            res.library_candidates = self._library_expansions(q)
            return res
        # method call on a typed local / chained call
        if isinstance(f, ast.Attribute):
            types = self.var_types(site.func, ctx)
            typ = None
            if isinstance(f.value, ast.Name):
                res.receiver_var = f.value.id
                typ = types.get(f.value.id)
            elif isinstance(f.value, (ast.Call, ast.Await)):
                typ = self.expr_type(f.value, info, cls_ctx, types)
            elif (isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name) and info.cls
                  and info.params and f.value.value.id == info.params[0] and f.value.value.id in ("self", "cls")):
                typ = self.attr_type(cls_ctx, f.value.attr)   # self.<attr>.method()
            if typ:
                res.receiver_type = typ
                res.via = "typed"
                self._method_on_type(typ, f.attr, res)
                return res
        res.unresolved = site.text
        return res


def _is_none(e) -> bool:
    return isinstance(e, ast.Constant) and e.value is None


def _u(node) -> str:
    try:
        return stable_unparse(node)
    except Exception:  # pragma: no cover - defensive
        return "?"


def _safe_unparse(node) -> str:
    try:
        s = stable_unparse(node)
    except Exception:  # pragma: no cover - defensive
        s = type(node).__name__
    return s if len(s) <= 120 else s[:117] + "..."

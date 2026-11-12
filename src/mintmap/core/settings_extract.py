"""Find Django settings modules and evaluate the literal parts of auth-relevant settings."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .fingerprint import stable_dump, stable_unparse
from .project import Project, Gap

KEY_SETTINGS = ("ROOT_URLCONF", "MIDDLEWARE", "AUTHENTICATION_BACKENDS", "REST_FRAMEWORK", "INSTALLED_APPS")
SETTINGS_MARKERS = {"ROOT_URLCONF", "MIDDLEWARE", "INSTALLED_APPS", "MIDDLEWARE_CLASSES"}
# settings whose differing values under `if` are kept as a list of alternatives (every one is analysed)
ALTERNATIVE_SETTINGS = {"ROOT_URLCONF"}


class Dynamic:
    """A value MintMap could not evaluate statically."""

    def __init__(self, text: str):
        self.text = text

    def __repr__(self):
        return f"<dynamic {self.text}>"

    def __eq__(self, other):
        return isinstance(other, Dynamic) and other.text == self.text

    def __hash__(self):
        return hash(self.text)


class PartialUnknown(Dynamic):
    """(v5, R4) Marker element: the setting holds the known items around it plus values MintMap cannot evaluate
    (e.g. `MIDDLEWARE.extend(plugin_middleware)`).  The known items are kept; a `setting_partially_unknown` gap
    names the statement."""

    def __repr__(self):
        return f"<partially_unknown {self.text}>"


class Alternatives:
    """(v5 review fix) A setting whose value depends on which branch / settings module applies: every option is
    one possible value (each is analysed, e.g. every hook class an alternative names is bound).  Used for
    relevant settings whose alternatives are not both lists or both dicts (those are merged item by item).
    Deliberately not a list subclass, so list-merging code never mistakes the options for list items."""

    def __init__(self, options=()):
        self.options = list(options)

    def __iter__(self):
        return iter(self.options)

    def __len__(self):
        return len(self.options)

    def __eq__(self, other):
        return isinstance(other, Alternatives) and other.options == self.options

    def __hash__(self):
        return hash(tuple(repr(x) for x in self.options))

    def __repr__(self):
        return f"Alternatives({self.options!r})"


def alternatives_of(*values) -> "Alternatives":
    out = []
    for v in values:
        for x in (v.options if isinstance(v, Alternatives) else [v]):
            if x not in out:
                out.append(x)
    return Alternatives(out)


def flat_values(v) -> list:
    """The possible values of a setting (one element unless it is `Alternatives`)."""
    return list(v.options) if isinstance(v, Alternatives) else [v]


def _unparse(n) -> str:
    try:
        s = stable_unparse(n)
    except Exception:
        s = type(n).__name__
    return s if len(s) <= 100 else s[:97] + "..."


@dataclass
class SettingsInfo:
    modules: list = field(default_factory=list)
    values: dict = field(default_factory=dict)
    stmts: dict = field(default_factory=dict)        # setting name -> [normalized statement dumps]
    gaps: list = field(default_factory=list)
    defaulted: list = field(default_factory=list)    # settings absent -> Django default assumed
    # (v5, R7) for EVERY upper-case setting: the statements that assign or change it (AST nodes), the conditions
    # that decide it ("cond:" dumps) and the last assignment of each name its statements read ("ref:" dumps)
    nodes: dict = field(default_factory=dict)
    deps: dict = field(default_factory=dict)
    # (v5, R7) (setting, item) -> {"cond:..." dumps}: the conditions under which a list item (a middleware, a
    # backend) is present in only some branches
    item_deps: dict = field(default_factory=dict)

    def digest_parts(self, name, key_filter=None) -> list:
        """(v5, R7) Stable text parts for one setting: its evaluated value (canonical form), the statements that
        assign / change it, the conditions that decide it and the assignments of the names those statements
        read.  `key_filter` (a set of dict keys) restricts a dict setting such as REST_FRAMEWORK to those keys:
        statements that only touch other keys are left out."""
        out = []
        v = self.values.get(name, _UNSET)
        if key_filter is not None and isinstance(v, dict):
            v = {k: x for k, x in v.items() if k in key_filter or isinstance(x, Dynamic) or not isinstance(k, str)
                 or k.startswith("<partially_unknown")}
        out.append("value:" + canonical_value(v))
        for st in self.nodes.get(name, []):
            d = statement_dump(st, name, key_filter)
            if d is not None:
                out.append("stmt:" + d)
        out += sorted(set(self.deps.get(name, [])))
        return out

    def str_list(self, name) -> list:
        out = []
        for v in flat_values(self.values.get(name)):
            if isinstance(v, (list, tuple)):
                out += [x for x in v if isinstance(x, str) and x not in out]
        return out

    def dynamic_items(self, name) -> list:
        out = []
        for v in flat_values(self.values.get(name)):
            if isinstance(v, Dynamic):
                out.append(v)
            elif isinstance(v, (list, tuple)):
                out += [x for x in v if isinstance(x, Dynamic)]
        return out

    def partially_unknown(self, name) -> bool:
        """(v5, R4) the setting is a list/dict with known items plus a value MintMap could not evaluate."""
        v = self.values.get(name)
        if isinstance(v, (list, tuple)):
            return any(isinstance(x, Dynamic) for x in v)
        if isinstance(v, dict):
            return any(isinstance(x, PartialUnknown) for x in v.values())
        return False


_NAMESPACE_CALLS = ("globals", "vars", "locals")
_NAMESPACE_WRITERS = ("update", "setdefault", "__setitem__", "pop", "clear")


def _namespace_writes(tree) -> list:
    """(v6c) [(line, text, update argument or None)] for statements that write a module's namespace dynamically: `globals().update(...)`,
    `globals()[k] = v` (anywhere in the module: globals() is the module namespace inside functions too),
    `vars()` / `locals()` writes at module level, and setattr / item stores / `__dict__` updates on
    `sys.modules[...]`."""
    out = []
    top = set()
    stack = list(tree.body)
    while stack:          # module-level statements (not inside a def or a class body)
        n = stack.pop()
        top.add(id(n))
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack.extend(x for x in ast.iter_child_nodes(n) if isinstance(x, ast.stmt))

    def namespace(e, at_top):
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and not e.args and not e.keywords:
            return e.func.id == "globals" or (at_top and e.func.id in ("vars", "locals"))
        if isinstance(e, ast.Attribute) and e.attr == "__dict__":
            return namespace(e.value, at_top) or _mentions_sys_modules(e.value)
        return _mentions_sys_modules(e)

    def visit(st, at_top):
        for n in ast.walk(st):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Subscript) and namespace(t.value, at_top):
                        out.append((n.lineno, _unparse(n)[:120], None))
            elif isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Attribute) and f.attr in _NAMESPACE_WRITERS and namespace(f.value, at_top):
                    arg = n.args[0] if f.attr == "update" and len(n.args) == 1 and not n.keywords else None
                    out.append((n.lineno, _unparse(n)[:120], arg))
                elif isinstance(f, ast.Name) and f.id in ("setattr", "delattr") and n.args and \
                        _mentions_sys_modules(n.args[0]):
                    out.append((n.lineno, _unparse(n)[:120], None))

    for st in ast.walk(tree):
        if isinstance(st, ast.stmt) and not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                                               ast.If, ast.For, ast.While, ast.With, ast.Try)):
            visit(st, id(st) in top)
    seen, uniq = set(), []
    for x in out:
        if x[:2] not in seen:
            seen.add(x[:2])
            uniq.append(x)
    return uniq


def _mentions_sys_modules(e) -> bool:
    return any(isinstance(x, ast.Attribute) and x.attr == "modules" and isinstance(x.value, ast.Name) and
               x.value.id == "sys" for x in ast.walk(e))


def _relevant(name: str, prefixes) -> bool:
    return name in KEY_SETTINGS or any(name.startswith(p) for p in prefixes)


class _Unset:
    def __repr__(self):
        return "<unset>"


_UNSET = _Unset()


def canonical_value(v) -> str:
    """(v5, R7) Order-stable text of an evaluated setting value (dict keys sorted, unknown parts by their text)."""
    if isinstance(v, PartialUnknown):
        return f"<partially_unknown {v.text}>"
    if isinstance(v, Dynamic):
        return f"<dynamic {v.text}>"
    if isinstance(v, Alternatives):
        return "alts[" + ",".join(canonical_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(f"{canonical_value(k)}:{canonical_value(x)}"
                              for k, x in sorted(v.items(), key=lambda kv: repr(kv[0]))) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_value(x) for x in v) + "]"
    return repr(v)


def _dict_key(k):
    return k.value if isinstance(k, ast.Constant) else None


def statement_dump(st, name, key_filter=None) -> str | None:
    """Dump of a statement that touches setting `name`; with `key_filter`, dict displays assigned to the setting
    keep only the listed keys (plus `**x` and computed keys), and a statement that only touches other keys of
    the setting (`NAME["OTHER"] = ...`, `NAME["OTHER"].append(...)`) is left out (None)."""
    if key_filter is None:
        return stable_dump(st)
    st = _copy_ast(st)

    def filt(d):
        if isinstance(d, ast.Dict):
            keep = [(k, v) for k, v in zip(d.keys, d.values)
                    if k is None or _dict_key(k) is None or _dict_key(k) in key_filter]
            d.keys, d.values = [k for k, _ in keep], [v for _, v in keep]
    if isinstance(st, (ast.Assign, ast.AnnAssign)):
        targets = st.targets if isinstance(st, ast.Assign) else [st.target]
        for t in targets:
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == name:
                k = _dict_key(t.slice)
                if k is not None and k not in key_filter:
                    return None
        filt(st.value)
    elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute):
        recv = st.value.func.value
        if isinstance(recv, ast.Subscript):
            while isinstance(recv.value, ast.Subscript):
                recv = recv.value
            k = _dict_key(recv.slice)
            if k is not None and k not in key_filter:
                return None
        for a in st.value.args:
            filt(a)
    return stable_dump(st)


def _copy_ast(n):
    import copy
    return copy.deepcopy(n)


def _root_name(e):
    """The Name at the root of a receiver chain (`X["a"].get("b").append` -> X), or None."""
    while True:
        if isinstance(e, ast.Subscript):
            e = e.value
        elif isinstance(e, ast.Attribute):
            e = e.value
        elif isinstance(e, ast.Call):
            e = e.func
        else:
            break
    return e.id if isinstance(e, ast.Name) else None


def _receiver_chain(e):
    """(v5 review fix) (root name, ops) for a receiver made of item accesses on a setting: `X["k"]`,
    `X.get("k"[, d])`, `X.setdefault("k", d)` (in any nesting).  ops = [("sub", key node) | ("get", call) |
    ("setdefault", call)], outermost last.  ops is None when a link is something else (the root is still
    returned so that the caller can mark the setting partially unknown)."""
    ops = []
    while True:
        if isinstance(e, ast.Subscript):
            ops.insert(0, ("sub", e.slice))
            e = e.value
        elif isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr in ("get", "setdefault") \
                and 1 <= len(e.args) <= 2 and not e.keywords and not any(isinstance(a, ast.Starred) for a in e.args):
            ops.insert(0, (e.func.attr, e))
            e = e.func.value
        else:
            break
    if isinstance(e, ast.Name):
        return e.id, ops
    return _root_name(e), None


class _Evaluator:
    def __init__(self, project: Project, prefixes):
        self.p = project
        self.prefixes = prefixes
        self.stmts: dict = {}
        self.gaps: list = []
        self._cache: dict = {}
        self.last_assign: dict = {}    # (v5) name -> the last statement that assigned it (any scope)
        self.nodes: dict = {}          # (v5, R7) upper-case name -> [statements that assign / change it]
        self.deps: dict = {}           # (v5, R7) upper-case name -> ["cond:..." / "ref:..." dumps]
        self.item_deps: dict = {}      # (v5, R7) (name, item) -> {"cond:..."}: items present in some branches only
        self.fdefs: dict = {}          # (v5, R4) module -> {function name: def node} (module-level defs)
        self.evaluated: set = set()    # (module, function) evaluated because module-level code calls it
        self._fstack: tuple = ()

    def ev(self, e, env):
        if isinstance(e, ast.Constant):
            return e.value
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            out = []
            for x in e.elts:
                if isinstance(x, ast.Starred):
                    v = self.ev(x.value, env)
                    out.extend(v if isinstance(v, (list, tuple)) else [Dynamic(_unparse(x))])
                else:
                    out.append(self.ev(x, env))
            return out
        if isinstance(e, ast.Dict):
            d = {}
            for k, v in zip(e.keys, e.values):
                if k is None:
                    inner = self.ev(v, env)
                    if isinstance(inner, dict):
                        d.update(inner)
                    continue
                kv = self.ev(k, env)
                d[kv if not isinstance(kv, Dynamic) else _unparse(k)] = self.ev(v, env)
            return d
        if isinstance(e, ast.Name):
            return env.get(e.id, Dynamic(e.id))
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
            a, b = self.ev(e.left, env), self.ev(e.right, env)
            if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
                return list(a) + list(b)
            if isinstance(a, str) and isinstance(b, str):
                return a + b
            # (v5, R4) a known list plus an unknown one: keep the known items, mark the rest
            if isinstance(a, (list, tuple)) and isinstance(b, Dynamic):
                return list(a) + [PartialUnknown(f"+ {_unparse(e.right)}")]
            if isinstance(b, (list, tuple)) and isinstance(a, Dynamic):
                return [PartialUnknown(f"{_unparse(e.left)} +")] + list(b)
            return Dynamic(_unparse(e))
        if isinstance(e, ast.Call):
            return self.ev_call(e, env)
        if isinstance(e, ast.IfExp):
            # (v6) `a if cond else b` with list values: every item of either branch (MintMap keeps every branch)
            a, b = self.ev(e.body, env), self.ev(e.orelse, env)
            if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
                return list(a) + [x for x in b if x not in a]
            if isinstance(a, (list, tuple)) and isinstance(b, Dynamic):
                return list(a) + [PartialUnknown(f"else {_unparse(e.orelse)}")]
            if isinstance(b, (list, tuple)) and isinstance(a, Dynamic):
                return list(b) + [PartialUnknown(f"{_unparse(e.body)} if ...")]
        if isinstance(e, ast.ListComp) and len(e.generators) == 1 and isinstance(e.elt, ast.Name) and \
                isinstance(e.generators[0].target, ast.Name) and e.generators[0].target.id == e.elt.id and \
                not e.generators[0].is_async:
            # (v6) `[m for m in X if m != "a"]`: a filtered copy of a known list
            g = e.generators[0]
            src = self.ev(g.iter, env)
            if isinstance(src, (list, tuple)):
                out = list(src)
                for cond in g.ifs:
                    out = _filter_items(out, cond, e.elt.id)
                return out
        return Dynamic(_unparse(e))

    def _returned_literal(self, e, env):
        """(v6) A call to a project function whose body is one `return {...}` / `return [...]` (a settings
        factory such as `REST_FRAMEWORK = api_settings(require_login=X)`): the returned literal, evaluated with
        the parameters bound to the call's arguments (parameters without an argument are unknown)."""
        mod = getattr(self, "_cur_mod", None)
        if mod is None or len(getattr(self, "_ret_stack", ())) > 3:
            return None
        q = self.p.resolve_expr_static(mod.name, e.func, getattr(self, "_cur_func", None))
        q = self.p.canonical(q) if q else None
        info = self.p.functions.get(q or "")
        if info is None or info.cls or not isinstance(info.node, ast.FunctionDef):
            return None
        lit = _single_return(info.node)
        if lit is None:
            return None
        a = info.node.args
        params = [x.arg for x in a.posonlyargs + a.args]
        local = {x.arg: Dynamic(x.arg) for x in a.posonlyargs + a.args + a.kwonlyargs}
        for i, arg in enumerate(e.args):
            if isinstance(arg, ast.Starred) or i >= len(params):
                break
            local[params[i]] = self.ev(arg, env)
        for k in e.keywords:
            if k.arg and k.arg in local:
                local[k.arg] = self.ev(k.value, env)
        self._ret_stack = getattr(self, "_ret_stack", ()) + (q,)
        try:
            return self.ev(lit, local)
        finally:
            self._ret_stack = self._ret_stack[:-1]

    def ev_call(self, e, env):
        """(v6) Settings computed by calls (`X = CONFIG.get("x", [defaults])`, `X = ensure_present(X, "a")`): the
        literal default of a getter, or the known list passed through an unknown function, is kept, plus a
        PartialUnknown marker naming the call (`setting_partially_unknown` gap).  Anything else stays Dynamic."""
        text = _unparse(e)
        f = e.func
        leaf = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
        if leaf in ("list", "tuple") and len(e.args) == 1 and not e.keywords:
            v = self.ev(e.args[0], env)
            if isinstance(v, (list, tuple)):
                return list(v)
        ret = self._returned_literal(e, env)
        if ret is not None:
            return ret
        default = next((k.value for k in e.keywords if k.arg in ("default", "fallback")), None)
        if default is None and leaf.lower().startswith("get") and len(e.args) >= 2:
            default = e.args[1]
        if default is not None:
            dv = self.ev(default, env)
            if isinstance(dv, (list, tuple)):
                return list(dv) + [PartialUnknown(f"{text}: configuration may replace the default")]
        if e.args and not isinstance(e.args[0], ast.Starred):
            first = self.ev(e.args[0], env)
            if isinstance(first, (list, tuple)) and any(isinstance(x, str) for x in first):
                known = [x for x in first if not (isinstance(x, PartialUnknown) and x.text.endswith("(passed through)"))]
                return known + [PartialUnknown(f"{text}: the list is passed through {leaf}() (passed through)")]
        return Dynamic(text)

    def record(self, name, st):
        if _relevant(name, self.prefixes):
            self.stmts.setdefault(name, []).append(stable_dump(st))
        if name.isupper() and not self._fstack_local(name):
            lst = self.nodes.setdefault(name, [])
            if all(x is not st for x in lst):
                lst.append(st)
            # (v5, R7) the last assignment of every other name this statement reads (one level): a setting
            # computed from a module constant changes when the constant does
            for n in ast.walk(st):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id != name and \
                        n.id in self.last_assign and self.last_assign[n.id] is not st:
                    d = "ref:" + stable_dump(self.last_assign[n.id])
                    if d not in self.deps.setdefault(name, []):
                        self.deps[name].append(d)

    def _fstack_local(self, name) -> bool:
        return False

    def run_module(self, modname, env=None, _stack=()):
        env = {} if env is None else env
        mod = self.p.modules.get(modname)
        if mod is None or modname in _stack:
            return env
        known_writes = []
        for line, text, arg in _namespace_writes(mod.tree):
            # (v6c) the module's namespace written through globals() / vars() / locals() / sys.modules: any setting
            # may be assigned (`globals().update(load_env())`, `for k, v in ...: globals()[k] = v`), unless the
            # update's keys are known (a dict literal, or the dict a project function builds and returns)
            keys = self._dict_keys(arg, mod.name) if arg is not None else None
            if keys is not None:
                known_writes.append((line, text, keys))
                continue
            self.gaps.append(Gap("dynamic_setting", mod.path, "<settings>",
                                 f"{text}: writes the settings module's namespace at run time; it may assign any "
                                 f"setting", line))
        self.run_block(mod, mod.tree.body, env, _stack + (modname,))
        for line, text, keys in known_writes:
            for k in sorted(keys):
                if k.isupper():
                    d = Dynamic(f"{text} (line {line})")
                    env[k] = merge_alternative_values(env[k], d) if k in env else d
        # (v5, R4) a module-level function that changes auth settings but that MintMap did not see being called
        # at module level (called through a variable, from another module, from a loop over functions ...)
        for fname, fdef in sorted(self.fdefs.get(modname, {}).items()):
            touched = self._touched(fdef)
            if touched and (modname, fname) not in self.evaluated:
                self.gaps.append(Gap("settings_function_not_evaluated", mod.path, fname,
                                     "changes " + ", ".join(sorted(touched)) + "; no module-level call found"))
        return env

    def _dict_keys(self, e, modname, depth=0):
        """(v6c) The constant string keys of a dict expression: a literal (with `**` of such dicts), or a call
        to a project function whose returns are names assigned only dict literals / constant-key item stores /
        updates with such dicts.  None when any key is not a constant."""
        if depth > 3:
            return None
        if isinstance(e, ast.Dict):
            out = set()
            for k, v in zip(e.keys, e.values):
                if k is None:
                    sub = self._dict_keys(v, modname, depth + 1)
                    if sub is None:
                        return None
                    out |= sub
                elif isinstance(k, ast.Constant) and isinstance(k.value, str):
                    out.add(k.value)
                else:
                    return None
            return out
        if isinstance(e, ast.Name):
            # a module-level name: every value assigned to it (`conf = get_conf(); globals().update(conf)`)
            mod = self.p.modules.get(modname)
            vals = (mod.assigns.get(e.id) if mod is not None else None) or []
            if not vals:
                return None
            out = set()
            for v in vals:
                sub = self._dict_keys(v, modname, depth + 1)
                if sub is None:
                    return None
                out |= sub
            return out
        if isinstance(e, ast.Call) and isinstance(e.func, (ast.Name, ast.Attribute)):
            q = self.p.resolve_expr_static(modname, e.func)
            q = self.p.canonical(q) if q else None
            info = self.p.functions.get(q or "")
            if info is None or info.cls:
                return None
            out = set()
            rets = [n for n in self.p.walk_function_body(info.node) if isinstance(n, ast.Return)]
            if not rets:
                return None
            for r in rets:
                v = r.value
                if isinstance(v, ast.Dict):
                    sub = self._dict_keys(v, info.module, depth + 1)
                elif isinstance(v, ast.Name):
                    sub = self._local_dict_keys(info, v.id, depth)
                else:
                    sub = None
                if sub is None:
                    return None
                out |= sub
            return out
        return None

    def _local_dict_keys(self, info, name, depth):
        out = set()
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    if isinstance(t, ast.Name) and t.id == name:
                        sub = self._dict_keys(n.value, info.module, depth + 1) if n.value is not None else None
                        if sub is None:
                            return None
                        out |= sub
                    elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == name:
                        if not (isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str)):
                            return None
                        out.add(t.slice.value)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                    isinstance(n.func.value, ast.Name) and n.func.value.id == name and \
                    n.func.attr in ("update", "setdefault", "__setitem__"):
                if n.func.attr == "update":
                    sub = self._dict_keys(n.args[0], info.module, depth + 1) if n.args else set()
                    if sub is None or n.keywords:
                        return None
                    out |= sub
                elif n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                    out.add(n.args[0].value)
                else:
                    return None
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name:
                return None
        return out

    def run_block(self, mod, body, env, stack):
        for st in body:
            self.run_stmt(mod, st, env, stack)

    # ------------------------------------------------------------------ (v5, R4) functions called at module level
    def _touched(self, fdef) -> set:
        """Relevant setting names a function rebinds (global) or changes in place (method call, item store)."""
        glob = {n for g in ast.walk(fdef) if isinstance(g, ast.Global) for n in g.names}
        out = {n for n in glob if _relevant(n, self.prefixes)}
        for n in ast.walk(fdef):
            roots = []
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                roots.append(_root_name(n.func.value))
            elif isinstance(n, (ast.Assign, ast.AugAssign)):
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if isinstance(t, (ast.Subscript, ast.Attribute)):
                        roots.append(_root_name(t))
            for r in roots:
                if r and _relevant(r, self.prefixes):
                    out.add(r)
        return out

    def _calls_to_module_functions(self, mod, node) -> list:
        defs = self.fdefs.get(mod.name, {})
        return [c for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                and c.func.id in defs]

    def call_function(self, mod, call, env, stack):
        """Run a module-level function that module-level code calls, with Python's scoping: names declared
        `global` (and lists/dicts changed in place) act on the module namespace; other names are locals that are
        dropped afterwards.  Parameters are unknown values.  Conditions inside are not decided (both branches,
        `conditional_setting` gaps as for module-level `if`)."""
        fdef = self.fdefs[mod.name][call.func.id]
        key = (mod.name, fdef.name)
        if key in self._fstack or len(self._fstack) >= 4:
            self.gaps.append(Gap("settings_function_not_evaluated", mod.path, fdef.name,
                                 "recursive or nested more than 4 deep"))
            return
        self.evaluated.add(key)
        glob = {n for g in ast.walk(fdef) if isinstance(g, ast.Global) for n in g.names}
        params = [a.arg for a in fdef.args.posonlyargs + fdef.args.args + fdef.args.kwonlyargs]
        params += [a.arg for a in (fdef.args.vararg, fdef.args.kwarg) if a]
        local = set(params) | {n.id for n in ast.walk(fdef) if isinstance(n, ast.Name)
                               and isinstance(n.ctx, ast.Store)}
        local -= glob
        saved = {n: env[n] for n in local if n in env}
        for n in params:
            env[n] = Dynamic(n)
        self._fstack += (key,)
        try:
            self.run_block(mod, fdef.body, env, stack)
        finally:
            self._fstack = self._fstack[:-1]
            for n in local:
                if n in saved:
                    env[n] = saved[n]
                else:
                    env.pop(n, None)

    def run_stmt(self, mod, st, env, stack):
        self._cur_mod = mod
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.fdefs.setdefault(mod.name, {})[st.name] = st
            return
        if isinstance(st, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign)) and st.value is not None:
            for c in self._calls_to_module_functions(mod, st.value):
                self.call_function(mod, c, env, stack)
        if isinstance(st, ast.Return):
            return
        if isinstance(st, ast.ImportFrom):
            src = self.p._resolve_relative(mod, st.level, st.module) if st.level else (st.module or "")
            for a in st.names:
                if a.name == "*":
                    if src in self.p.modules:
                        sub = self.run_module(src, {}, stack)
                        env.update(sub)
                    else:
                        self.gaps.append(Gap("settings_star_import_unresolved", mod.path, mod.name, f"from {src} import *"))
                elif src in self.p.modules and (a.name.isupper()):
                    sub = self.run_module(src, {}, stack)
                    if a.name in sub:
                        env[a.asname or a.name] = sub[a.name]
            return
        if isinstance(st, (ast.Assign, ast.AnnAssign)):
            targets = st.targets if isinstance(st, ast.Assign) else [st.target]
            if st.value is None:
                return
            for t in targets:
                if isinstance(t, ast.Name):
                    env[t.id] = self.ev(st.value, env)
                    self.last_assign[t.id] = st
                    self.record(t.id, st)
                elif isinstance(t, (ast.Tuple, ast.List)):
                    # (v5) unpacking: every bound name becomes unknown (was silently ignored)
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                            env[n.id] = Dynamic(_unparse(st))
                            self.record(n.id, st)
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                    base = env.get(t.value.id)
                    key = self.ev(t.slice, env)
                    if isinstance(base, dict) and not isinstance(key, Dynamic):
                        base[key] = self.ev(st.value, env)
                    elif _relevant(t.value.id, self.prefixes):
                        env[t.value.id] = Dynamic(_unparse(st))
                    self.record(t.value.id, st)
                elif isinstance(t, (ast.Subscript, ast.Attribute)):
                    # (v5 review fix) nested item store (`X["A"]["B"] = v`, `X.setdefault("A", {})["B"] = v`)
                    root, ops = _receiver_chain(t.value) if isinstance(t, ast.Subscript) else (_root_name(t), None)
                    if root is None or not root.isupper():
                        continue
                    container = self.navigate(env, root, ops) if ops is not None else None
                    key = self.ev(t.slice, env) if isinstance(t, ast.Subscript) else Dynamic("attr")
                    if isinstance(container, dict) and not isinstance(key, Dynamic):
                        container[key] = self.ev(st.value, env)
                    elif _relevant(root, self.prefixes):
                        self.mark_partial(mod, root, env, st, "item store MintMap does not follow")
                    self.record(root, st)
            return
        if isinstance(st, ast.AugAssign) and isinstance(st.target, (ast.Subscript, ast.Attribute)):
            # (v5 review fix) `X["K"] += (...)` (was ignored: neither evaluated nor recorded)
            t = st.target
            root, ops = _receiver_chain(t.value) if isinstance(t, ast.Subscript) else (_root_name(t), None)
            if root is None or not root.isupper():
                return
            container = self.navigate(env, root, ops) if ops is not None else None
            key = self.ev(t.slice, env) if isinstance(t, ast.Subscript) else Dynamic("attr")
            if isinstance(container, dict) and not isinstance(key, Dynamic) and key in container:
                cur, add = container[key], self.ev(st.value, env)
                if isinstance(cur, (list, tuple)) and isinstance(add, (list, tuple)) and isinstance(st.op, ast.Add):
                    container[key] = list(cur) + list(add)
                elif isinstance(cur, (list, tuple)) and isinstance(st.op, ast.Add):
                    container[key] = list(cur) + [PartialUnknown(f"{_unparse(t)} += {_unparse(st.value)}")]
                else:
                    container[key] = Dynamic(_unparse(st))
            elif _relevant(root, self.prefixes):
                self.mark_partial(mod, root, env, st, "augmented item assignment MintMap does not follow")
            self.record(root, st)
            return
        if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
            name = st.target.id
            cur, add = env.get(name), self.ev(st.value, env)
            if isinstance(cur, (list, tuple)) and isinstance(add, (list, tuple)):
                env[name] = list(cur) + list(add)
            elif isinstance(cur, (list, tuple)) and isinstance(st.op, ast.Add):
                # (v5, R4) `X += <unknown>`: keep the known items, mark the unknown part
                env[name] = list(cur) + [PartialUnknown(f"+= {_unparse(st.value)}")]
            else:
                env[name] = Dynamic(_unparse(st))
            self.record(name, st)
            return
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute):
            root, ops = _receiver_chain(st.value.func.value)
            if root is not None and ops is not None:
                self.method_call(mod, st, root, ops, env)
                return
            if root is not None and root.isupper() and _relevant(root, self.prefixes):
                # (v5 review fix) a method called on something computed from the setting that MintMap does not
                # follow (`X.copy().update(...)`, `X["k"].y.append(...)`): the setting may have changed
                self.mark_partial(mod, root, env, st, f"{_unparse(st.value.func)}() not evaluated")
                return
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Name) \
                and st.value.func.id in ("exec", "execfile", "include"):
            # (v5) exec(open(...).read()) / django-split-settings include(...): may assign any setting
            self.gaps.append(Gap("dynamic_setting", mod.path, "<settings>",
                                 f"{_unparse(st.value)}: code MintMap does not evaluate may change any setting",
                                 st.lineno))
            return
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
            # (v5) a relevant setting passed to a call MintMap does not follow may be changed in place
            evaluated = {id(c) for c in self._calls_to_module_functions(mod, st.value)}
            if id(st.value) not in evaluated:
                for a in list(st.value.args) + [k.value for k in st.value.keywords]:
                    if isinstance(a, ast.Name) and _relevant(a.id, self.prefixes) and a.id.isupper():
                        self.mark_partial(mod, a.id, env, st, f"passed to {_unparse(st.value.func)}()")
            return
        if isinstance(st, ast.Match):
            # (v5) each case is an alternative (merged like if/else); `match` was ignored before v5
            text = f"match {_unparse(st.subject)}"
            alts = []
            for case in st.cases:
                b = _copy(env)
                self.run_block(mod, case.body, b, stack)
                alts.append(b)
            if not any(isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None for c in st.cases):
                alts.append(_copy(env))       # no catch-all case: the unchanged environment is an alternative
            acc = alts[0]
            for b in alts[1:]:
                merged = {}
                self._merge(mod, st, acc, b, merged, text, st.subject)
                acc = merged
            env.clear()
            env.update(acc)
            return
        if isinstance(st, ast.If):
            a, b = _copy(env), _copy(env)
            self.run_block(mod, st.body, a, stack)
            self.run_block(mod, st.orelse, b, stack)
            self._merge(mod, st, a, b, env, f"if {_unparse(st.test)}", st.test)
            return
        if isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            self.run_block(mod, st.body, env, stack)
            for h in st.handlers:
                self.run_block(mod, h.body, env, stack)
            self.run_block(mod, st.orelse, env, stack)
            self.run_block(mod, st.finalbody, env, stack)
            return
        if isinstance(st, (ast.With, ast.For, ast.AsyncFor, ast.AsyncWith, ast.While)):
            # loop / with bodies run once (loop variables are unknown values); `while` was ignored before v5
            self.run_block(mod, st.body, env, stack)
            if isinstance(st, (ast.For, ast.While)):
                self.run_block(mod, st.orelse, env, stack)

    def mark_partial(self, mod, name, env, st, why):
        """(v5, R4) keep the known items of a list/dict setting and add a partially-unknown marker + gap."""
        cur = env.get(name)
        marker = PartialUnknown(f"{name}: {why} ({_unparse(st)})")
        if isinstance(cur, list):
            cur.append(marker)
        elif isinstance(cur, dict):
            cur[f"<partially_unknown:{_unparse(st)}>"] = marker
        elif name in env:
            env[name] = Dynamic(_unparse(st))
        self.record(name, st)

    def navigate(self, env, name, ops):
        """(v5 review fix) The (mutable) value reached from setting `name` through item accesses `ops`
        (`_receiver_chain`), creating a key for `setdefault` like Python does; None when not known."""
        cur = env.get(name)
        for op, node in ops:
            if op == "sub":
                k = self.ev(node, env)
                default = None
            else:
                k = self.ev(node.args[0], env)
                default = node.args[1] if len(node.args) > 1 else None
            if not isinstance(cur, dict) or isinstance(k, Dynamic):
                return None
            if k not in cur:
                if op != "setdefault":
                    return None
                dv = self.ev(default, env) if default is not None else None
                cur[k] = list(dv) if isinstance(dv, (list, tuple)) else (dict(dv) if isinstance(dv, dict) else dv)
            cur = cur[k]
            if isinstance(cur, tuple):
                return None
        return cur

    def method_call(self, mod, st, name, path, env):
        """`X.append(v)`, `X["K"].insert(0, v)`, `X.update({...})` ... on a (nested) list/dict setting."""
        call = st.value
        meth, args = call.func.attr, call.args
        cur = self.navigate(env, name, path)
        relevant = _relevant(name, self.prefixes)
        if isinstance(cur, list):
            vals = [self.ev(a, env) for a in args]
            if call.keywords:
                vals = None
            if vals is not None and meth == "append" and len(vals) == 1:
                cur.append(vals[0])
            elif vals is not None and meth == "insert" and len(vals) == 2:
                idx = vals[0] if isinstance(vals[0], int) else len(cur)
                cur.insert(idx, vals[1])
            elif vals is not None and meth == "extend" and len(vals) == 1 and isinstance(vals[0], (list, tuple)):
                cur.extend(vals[0])
            elif vals is not None and meth == "extend" and len(vals) == 1:
                cur.append(PartialUnknown(f"{name}.extend({_unparse(args[0])})"))
            elif vals is not None and meth == "remove" and len(vals) == 1 and vals[0] in cur:
                cur.remove(vals[0])
            elif meth in ("index", "count", "copy"):
                pass   # no change
            elif relevant:
                if path:
                    cur.append(PartialUnknown(f"{_unparse(call)}"))
                else:
                    self.mark_partial(mod, name, env, st, f".{meth}() not evaluated")
        elif isinstance(cur, dict) and meth == "update" and len(args) == 1 and not call.keywords:
            v = self.ev(args[0], env)
            if isinstance(v, dict):
                cur.update(v)
            elif relevant:
                cur[f"<partially_unknown:{_unparse(call)}>"] = PartialUnknown(f"{name}.update({_unparse(args[0])})")
        elif isinstance(cur, dict) and meth in ("get", "keys", "items", "values", "copy"):
            pass
        elif isinstance(cur, dict) and meth == "setdefault" and len(args) == 2:
            k = self.ev(args[0], env)
            if not isinstance(k, Dynamic):
                cur.setdefault(k, self.ev(args[1], env))
            elif relevant:
                cur[f"<partially_unknown:{_unparse(call)}>"] = PartialUnknown(_unparse(call))
        elif relevant and name in env and not isinstance(env.get(name), Dynamic):
            # receiver not understood (a nested value MintMap does not know): the setting is partially unknown
            top = env.get(name)
            if isinstance(top, (list, dict)):
                self.mark_partial(mod, name, env, st, f"{_unparse(call.func)}() on a value MintMap does not know")
        self.record(name, st)

    def _merge(self, mod, st, a, b, env, cond_text, cond=None):
        """Merge two alternative environments (if/else, match cases) into `env`."""
        for name in set(a) | set(b):
            va, vb = a.get(name), b.get(name)
            if va == vb:
                env[name] = va
                continue
            if name.isupper() and cond is not None:
                # (v5, R7) for every setting: the condition that decides it and the assignments it reads
                deps = [stable_dump(cond)]
                for n in ast.walk(cond):
                    if isinstance(n, ast.Name) and n.id in self.last_assign:
                        deps.append(stable_dump(self.last_assign[n.id]))
                for d in deps:
                    if "cond:" + d not in self.deps.setdefault(name, []):
                        self.deps[name].append("cond:" + d)
                if isinstance(va, list) and isinstance(vb, list):
                    for x in [y for y in va if y not in vb] + [y for y in vb if y not in va]:
                        if isinstance(x, str):
                            self.item_deps.setdefault((name, x), set()).update("cond:" + d for d in deps)
            if _relevant(name, self.prefixes):
                self.gaps.append(Gap("conditional_setting", mod.path, name, f"differs under `{cond_text}`",
                                     st.lineno))
                if cond is not None:
                    # (v5) the condition that decides the setting, and the assignments of the names it reads, are
                    # part of the setting's statements (settings fingerprint): changing an env default that
                    # switches a middleware on is a change of the setting
                    deps = [stable_dump(cond)]
                    for n in ast.walk(cond):
                        if isinstance(n, ast.Name) and n.id in self.last_assign:
                            deps.append(stable_dump(self.last_assign[n.id]))
                    for d in deps:
                        if "cond:" + d not in self.stmts.setdefault(name, []):
                            self.stmts[name].append("cond:" + d)
            if isinstance(va, list) and isinstance(vb, list):
                env[name] = va + [x for x in vb if x not in va]   # union: over-approximate
            elif isinstance(va, dict) and isinstance(vb, dict):
                env[name] = _union_dict(va, vb)                   # (v5) nested lists, e.g. REST_FRAMEWORK
            elif name in ALTERNATIVE_SETTINGS and name in a and name in b:
                # (v3, P4) a URLconf root chosen by a runtime condition: keep every alternative
                # (else/unchanged value first) instead of silently picking the `if` branch
                alts = _alternatives(vb) + [x for x in _alternatives(va) if x not in _alternatives(vb)]
                env[name] = alts[0] if len(alts) == 1 else alts
            elif name in a and name in b and name.isupper() and _relevant(name, self.prefixes):
                # (v5 review fix) a relevant scalar (a hook class path, a flag) that differs between branches:
                # keep both (was: the `if` branch only)
                env[name] = alternatives_of(va, vb)
            else:
                env[name] = va if name in a else vb


def _single_return(fdef):
    """The literal a factory function ends with (`... return {...}`, only one return statement); statements
    before it only bind locals, which stay unknown."""
    returns = [n for n in ast.walk(fdef) if isinstance(n, ast.Return)]
    last = fdef.body[-1] if fdef.body else None
    if len(returns) == 1 and returns[0] is last and isinstance(last.value, (ast.Dict, ast.List, ast.Tuple)):
        return last.value
    return None


def _filter_items(items, cond, var):
    """Apply a simple comprehension filter (`var != "x"`, `var not in ("x", ...)`) to known items; any other
    condition keeps every item and marks the list partially unknown."""
    if isinstance(cond, ast.Compare) and isinstance(cond.left, ast.Name) and cond.left.id == var and \
            len(cond.ops) == 1 and isinstance(cond.ops[0], (ast.NotEq, ast.NotIn, ast.IsNot)):
        c = cond.comparators[0]
        drop = None
        if isinstance(c, ast.Constant):
            drop = {c.value}
        elif isinstance(c, (ast.List, ast.Tuple, ast.Set)) and all(isinstance(x, ast.Constant) for x in c.elts):
            drop = {x.value for x in c.elts}
        if drop is not None:
            return [x for x in items if isinstance(x, Dynamic) or x not in drop]
    return list(items) + [PartialUnknown(f"filtered by {_unparse(cond)}")]


def _union_dict(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, vb in b.items():
        va = out.get(k)
        if k not in out:
            out[k] = vb
        elif isinstance(va, list) and isinstance(vb, list):
            out[k] = va + [x for x in vb if x not in va]
        elif isinstance(va, dict) and isinstance(vb, dict):
            out[k] = _union_dict(va, vb)
        elif va != vb:
            # (v5 review fix) differing scalars (e.g. REST_AUTH["LOGIN_SERIALIZER"]): keep both (was: the first)
            out[k] = alternatives_of(va, vb)
    return out


def merge_alternative_values(va, vb):
    """(v5 review fix) Value of a setting that is `va` in one settings module / branch and `vb` in another:
    lists are united, dicts merged key by key, a known list and an unknown value keep the list plus a
    partially-unknown marker, anything else becomes `Alternatives`."""
    if va == vb:
        return va
    if isinstance(va, list) and isinstance(vb, list):
        return va + [x for x in vb if x not in va]
    if isinstance(va, dict) and isinstance(vb, dict):
        return _union_dict(va, vb)
    if isinstance(va, list) and isinstance(vb, Dynamic):
        return va + [PartialUnknown(f"another settings module: {vb.text}")]
    if isinstance(vb, list) and isinstance(va, Dynamic):
        return vb + [PartialUnknown(f"another settings module: {va.text}")]
    return alternatives_of(va, vb)


def _alternatives(v) -> list:
    return list(v) if isinstance(v, list) else [v]


def _copy(env):
    out = {}
    for k, v in env.items():
        out[k] = list(v) if isinstance(v, list) else (dict(v) if isinstance(v, dict) else v)
    return out


def _dsm_literals(project: Project) -> list:
    found = []
    for mod in project.modules.values():
        for n in ast.walk(mod.tree):
            if isinstance(n, ast.Call) and len(n.args) >= 2 and isinstance(n.args[0], ast.Constant) \
                    and n.args[0].value == "DJANGO_SETTINGS_MODULE" and isinstance(n.args[1], ast.Constant) \
                    and isinstance(n.args[1].value, str):
                found.append((n.args[1].value, mod.path))
            elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Subscript):
                sl = n.targets[0].slice
                if isinstance(sl, ast.Constant) and sl.value == "DJANGO_SETTINGS_MODULE" and \
                        isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                    found.append((n.value.value, mod.path))
    return found


_TEST_SETTINGS = re.compile(r"(^|_)(test|tests|testing)($|_)")


def _settings_family(project: Project, candidates) -> tuple[list, set]:
    """(v5 review fix) Settings-like modules: the candidates (they assign ROOT_URLCONF/MIDDLEWARE/INSTALLED_APPS)
    plus every module that star-imports one of the family (`local.py`, `production.py` doing
    `from .base import *`).  Returns (leaves = family modules no other family module star-imports, family)."""
    family = set(candidates)
    changed = True
    while changed:
        changed = False
        for name, mod in project.modules.items():
            if name not in family and any(src in family for src in mod.star_imports):
                family.add(name)
                changed = True
    starred = {src for m in family for src in project.modules[m].star_imports}
    return sorted(m for m in family if m not in starred), family


def extract_settings(project: Project, prefixes) -> SettingsInfo:
    info = SettingsInfo()
    candidates = []
    for mod in project.modules.values():
        names = set()
        for st in project._top_level_statements(mod.tree.body):
            if isinstance(st, ast.Assign):
                names |= {t.id for t in st.targets if isinstance(t, ast.Name)}
        if names & SETTINGS_MARKERS:
            candidates.append(mod.name)
    leaves, family = _settings_family(project, candidates)
    dsm = _dsm_literals(project)
    chosen = sorted({v for v, _ in dsm if v in project.modules})
    missing = sorted({v for v, _ in dsm if v not in project.modules})
    for m in missing:
        info.gaps.append(Gap("settings_module_missing", "-", "DJANGO_SETTINGS_MODULE", m))
    if not chosen:
        starred = set()
        for c in candidates:
            for src in project.modules[c].star_imports:
                starred.add(src)
        chosen = sorted(c for c in candidates if c not in starred) or sorted(candidates)
        if len(chosen) > 1:
            info.gaps.append(Gap("settings_module_ambiguous", "-", "settings", ",".join(chosen)))
    else:
        # (v5 review fix) the deployment may select another settings module through the environment (a
        # Dockerfile, compose file, .env): every other leaf settings module of the project is analysed too, as
        # an alternative (lists united, dicts merged key by key, differing values kept as alternatives), except
        # modules named as test settings, which are listed in a gap
        tests = [m for m in leaves if m not in chosen and _TEST_SETTINGS.search(m.rsplit(".", 1)[-1])]
        extra = [m for m in leaves if m not in chosen and m not in tests]
        if tests:
            info.gaps.append(Gap("settings_module_not_analyzed", "-", "settings",
                                 "test settings modules (not deployed): " + ",".join(tests)))
        if extra:
            info.gaps.append(Gap("settings_module_ambiguous", "-", "DJANGO_SETTINGS_MODULE",
                                 ",".join(chosen) + "; also analysed as alternatives: " + ",".join(extra)))
            chosen = chosen + extra
        elif len(chosen) > 1:
            info.gaps.append(Gap("settings_module_ambiguous", "-", "DJANGO_SETTINGS_MODULE", ",".join(chosen)))
    if not chosen:
        info.gaps.append(Gap("no_settings_module", "-", "settings", "no module assigns ROOT_URLCONF/MIDDLEWARE/INSTALLED_APPS"))
        return info
    info.modules = chosen
    ev = _Evaluator(project, prefixes)
    merged: dict = {}
    for m in chosen:
        env = ev.run_module(m, {})
        for k, v in env.items():
            if not k.isupper():
                continue
            if k not in merged:
                merged[k] = v
            elif merged[k] != v:
                if k in ALTERNATIVE_SETTINGS:
                    merged[k] = _alternatives(merged[k]) + [x for x in _alternatives(v)
                                                            if x not in _alternatives(merged[k])]
                elif _relevant(k, prefixes):
                    # (v5 review fix) was: the first module's value (alphabetical order) silently won
                    merged[k] = merge_alternative_values(merged[k], v)
                elif isinstance(merged[k], list) and isinstance(v, list):
                    merged[k] = merged[k] + [x for x in v if x not in merged[k]]
                if _relevant(k, prefixes):
                    info.gaps.append(Gap("conflicting_setting", "-", k, "differs between settings modules"))
    # (v6) settings changed at run time by project code outside the settings modules (`settings.X = ...` in
    # AppConfig.ready() or a helper): the value is one more alternative, its statement is part of the setting's
    # fingerprint, and a gap names it
    fam = set(family) | set(chosen)
    sites = []
    for qn, finfo in sorted(project.functions.items()):
        if finfo.module not in fam:
            sites += [(project.modules[finfo.module], finfo, n) for n in project.walk_function_body(finfo.node)]
    for mname in sorted(project.modules):
        if mname not in fam:
            sites += [(project.modules[mname], None, st)
                      for st in project._top_level_statements(project.modules[mname].tree.body)]
    for mod, finfo, n in sites:
        if True:
            mname = mod.name
            target, value = None, None
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Attribute):
                target, name, value = n.targets[0].value, n.targets[0].attr, n.value
            elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) \
                    and n.value.func.id == "setattr" and len(n.value.args) == 3:
                # (v6c) setattr(settings, "NAME", value): the same as `settings.NAME = value`; a computed name
                # may assign any setting
                target, key, value = n.value.args
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    q = project.resolve_expr_static(mname, target, finfo)
                    if q and project.canonical(q) == "django.conf.settings":
                        info.gaps.append(Gap("dynamic_setting", mod.path, "<settings>",
                                             f"line {n.lineno}: {_unparse(n)[:120]}: a setting chosen at run "
                                             f"time may be assigned"))
                    continue
                name = key.value
            if target is None:
                continue
            if not (name.isupper() and _relevant(name, prefixes)):
                continue
            q = project.resolve_expr_static(mname, target, finfo)
            if not q or project.canonical(q) != "django.conf.settings":
                continue
            t = ast.Attribute(value=target, attr=name, ctx=ast.Store())
            ev._cur_mod, ev._cur_func = mod, finfo
            v = ev.ev(value, dict(merged))
            ev._cur_func = None
            merged[t.attr] = merge_alternative_values(merged[t.attr], v) if t.attr in merged else v
            ev.record(t.attr, n)
            ev.nodes.setdefault(t.attr, []).append(n)
            info.gaps.append(Gap("setting_changed_at_run_time", mod.path, t.attr,
                                 f"line {n.lineno}: {_unparse(n)[:120]}"))
    info.values = merged
    info.stmts = ev.stmts
    info.nodes = ev.nodes
    info.deps = ev.deps
    info.item_deps = ev.item_deps
    info.gaps.extend(ev.gaps)
    first = project.modules[chosen[0]].path
    for name in ("MIDDLEWARE", "AUTHENTICATION_BACKENDS", "ROOT_URLCONF", "INSTALLED_APPS"):
        for d in info.dynamic_items(name):
            # (v5, R4) a list with known items plus an unknown part keeps the known items
            typ = "setting_partially_unknown" if isinstance(d, PartialUnknown) else "dynamic_setting"
            info.gaps.append(Gap(typ, first, name, d.text))
    rf = merged.get("REST_FRAMEWORK")
    if isinstance(rf, Dynamic):
        info.gaps.append(Gap("dynamic_setting", first, "REST_FRAMEWORK", rf.text))
    elif isinstance(rf, dict):
        dac = rf.get("DEFAULT_AUTHENTICATION_CLASSES")
        if isinstance(dac, Dynamic):
            info.gaps.append(Gap("dynamic_setting", first, "REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES", dac.text))
        elif isinstance(dac, (list, tuple)):
            for d in dac:
                if isinstance(d, Dynamic):
                    info.gaps.append(Gap("setting_partially_unknown" if isinstance(d, PartialUnknown)
                                         else "dynamic_setting", first,
                                         "REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES", d.text))
        for k, v in rf.items():
            if isinstance(v, PartialUnknown):
                info.gaps.append(Gap("setting_partially_unknown", first, "REST_FRAMEWORK", v.text))
    if "AUTHENTICATION_BACKENDS" not in merged:
        info.defaulted.append("AUTHENTICATION_BACKENDS")
    if "MIDDLEWARE" not in merged and "MIDDLEWARE_CLASSES" not in merged:
        info.gaps.append(Gap("missing_setting", project.modules[chosen[0]].path, "MIDDLEWARE", "not assigned"))
    if "ROOT_URLCONF" not in merged:
        info.gaps.append(Gap("missing_setting", project.modules[chosen[0]].path, "ROOT_URLCONF", "not assigned"))
    return info


def drf_auth_classes(info: SettingsInfo) -> list:
    rf = info.values.get("REST_FRAMEWORK")
    if isinstance(rf, dict):
        v = rf.get("DEFAULT_AUTHENTICATION_CLASSES")
        if isinstance(v, (list, tuple)):
            return [x for x in v if isinstance(x, str)]
    return []

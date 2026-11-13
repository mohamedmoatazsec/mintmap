"""Formatting-insensitive, semantics-sensitive fingerprints.

normalize(node) = stable_dump(alpha_rename(copy_without_docstrings))

stable_dump() gives the same text on every supported Python version (see its docstring), so a lock written
with one Python version can be checked with another.

* comments, whitespace, quote style, parenthesisation and line numbers do not
  appear in the AST dump, so they cannot change a fingerprint;
* docstrings are removed explicitly;
* (v5, R8) function-local variables are alpha-renamed: every name a function (or lambda) binds itself
  (assignment and loop targets, `with ... as`, `except ... as`, walrus, `match` captures) is replaced by a
  canonical name chosen by the order of its first binding.  (v5 review fix) Comprehensions are their own scope,
  as in Python 3: their targets are renamed inside the comprehension only (the first iterable is evaluated in
  the enclosing scope), so a comprehension variable that has the same name as a global the function also calls
  does not turn that call into a "local" one; a walrus inside a comprehension binds in the enclosing function.  Parameters (part of
  the call signature), attribute names, keyword-argument names, string constants, globals, builtins, names
  declared `global`/`nonlocal` (nonlocal ones follow the enclosing function's renaming), imported names and
  the names of nested `def`/`class` statements are kept.  Scoping is followed: a nested function or lambda
  that binds a name of the enclosing function shadows it, so only the variable each occurrence refers to is
  renamed.  A function that calls `locals()`, `vars()`, `eval()`, `exec()` or `dir()` (which can observe
  local names) is not renamed.  Renaming a local variable therefore no longer changes a fingerprint;
* every other syntactic change (a constant, an operator, a call argument, a decorator, a type annotation,
  an attribute name, a parameter name) changes the dump.
"""
from __future__ import annotations

import ast
import copy
import hashlib

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
# calls that can observe local variable names (renaming would change what they see)
DYNAMIC_NAME_CALLS = {"locals", "vars", "eval", "exec", "dir"}
CANON_PREFIX = "%"     # cannot occur in a Python identifier, so canonical names never collide with real ones


def _strip_docstrings(tree):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = n.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                n.body = body[1:] or [ast.Pass()]
    return tree


# ------------------------------------------------------------------------------------------- alpha renaming
def _params(fn) -> set:
    a = fn.args
    out = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
    out |= {x.arg for x in (a.vararg, a.kwarg) if x is not None}
    return out


def comprehension_targets(nodes) -> set:
    """ids of the Name nodes bound as comprehension targets (they belong to the comprehension's own scope)."""
    out = set()
    for n in nodes:
        if isinstance(n, ast.comprehension):
            for t in ast.walk(n.target):
                if isinstance(t, ast.Name):
                    out.add(id(t))
    return out


def own_nodes(fn):
    """Nodes of a function's (or lambda's) own scope, in source order: nested def/class/lambda nodes are
    yielded but not entered.  Comprehensions are entered (a walrus inside one binds in the function); their
    targets are told apart with `comprehension_targets`."""
    body = fn.body if isinstance(fn.body, list) else [fn.body]
    stack = list(reversed(body))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, _SCOPES + (ast.ClassDef,)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def local_bindings(fn) -> tuple[list, set, set, set]:
    """(renamable locals in order of first binding, names kept as they are (imports, nested def/class names),
    names declared global, names declared nonlocal)."""
    order, seen, kept, glob, nonloc = [], set(), set(), set(), set()

    def bind(name, keep=False):
        if keep:
            kept.add(name)
        if name not in seen:
            seen.add(name)
            order.append(name)
    nodes = list(own_nodes(fn))
    comp_targets = comprehension_targets(nodes)
    for n in nodes:
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            if id(n) in comp_targets:
                continue          # comprehension scope (renamed by _AlphaRenamer._comprehension)
            bind(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bind(n.name)
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            bind(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            bind(n.rest)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                bind((a.asname or a.name).split(".")[0], keep=True)
        elif isinstance(n, _DEFS):
            bind(n.name, keep=True)
        elif isinstance(n, ast.Global):
            glob |= set(n.names)
        elif isinstance(n, ast.Nonlocal):
            nonloc |= set(n.names)
    params = _params(fn)
    ren = [x for x in order if x not in kept and x not in glob and x not in nonloc and x not in params]
    return ren, kept | params, glob, nonloc


def _dynamic(fn) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in DYNAMIC_NAME_CALLS
               for n in own_nodes(fn))


class _AlphaRenamer:
    def __init__(self):
        self.depth = 0
        self.dynamic = [False]

    def _comprehension(self, node, m: dict):
        """A comprehension is a scope of its own: the first iterable is evaluated outside it; its targets are
        renamed inside it only (not inside a function that can observe local names)."""
        gens = node.generators
        self.visit(gens[0].iter, m)
        targets = []
        for g in gens:
            for t in ast.walk(g.target):
                if isinstance(t, ast.Name) and t.id not in targets:
                    targets.append(t.id)
        m2 = {k: v for k, v in m.items() if k not in targets}
        if not self.dynamic[-1]:
            self.depth += 1
            m2.update({name: f"{CANON_PREFIX}{self.depth}.c{i}" for i, name in enumerate(targets)})
        for i, g in enumerate(gens):
            self.visit(g.target, m2)
            if i:
                self.visit(g.iter, m2)
            for c in g.ifs:
                self.visit(c, m2)
        if isinstance(node, ast.DictComp):
            self.visit(node.key, m2)
            self.visit(node.value, m2)
        else:
            self.visit(node.elt, m2)

    def visit(self, node, m: dict):
        if isinstance(node, _COMPS):
            self._comprehension(node, m)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                self.visit(d, m)
            self._outer_args(node.args, m)
            if node.returns is not None:
                self.visit(node.returns, m)
            self._scope(node, m)
            return
        if isinstance(node, ast.Lambda):
            self._outer_args(node.args, m)
            self._scope(node, m)
            return
        if isinstance(node, ast.ClassDef):
            for x in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                self.visit(x, m)
            bound = {n.id for st in node.body for n in ast.walk(st)
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            bound |= {st.name for st in node.body if isinstance(st, _DEFS)}
            mc = {k: v for k, v in m.items() if k not in bound}
            for st in node.body:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # decorators/defaults run in the class body; the method's free names skip the class scope
                    for d in st.decorator_list:
                        self.visit(d, mc)
                    self._outer_args(st.args, mc)
                    if st.returns is not None:
                        self.visit(st.returns, mc)
                    self._scope(st, m)
                else:
                    self.visit(st, mc)
            return
        if isinstance(node, ast.Name):
            node.id = m.get(node.id, node.id)
            return
        if isinstance(node, ast.ExceptHandler) and node.name:
            node.name = m.get(node.name, node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            node.name = m.get(node.name, node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            node.rest = m.get(node.rest, node.rest)
        elif isinstance(node, ast.Nonlocal):
            node.names = [m.get(n, n) for n in node.names]
        for child in list(ast.iter_child_nodes(node)):
            self.visit(child, m)

    def _outer_args(self, args, m):
        """Defaults and annotations of a function's parameters are evaluated in the enclosing scope."""
        for d in args.defaults + [d for d in args.kw_defaults if d is not None]:
            self.visit(d, m)
        for a in args.posonlyargs + args.args + args.kwonlyargs + [x for x in (args.vararg, args.kwarg) if x]:
            if a.annotation is not None:
                self.visit(a.annotation, m)

    def _scope(self, fn, outer: dict):
        ren, kept, glob, _nonloc = local_bindings(fn)
        # names this scope binds itself (or declares global) shadow the enclosing function's variables;
        # nonlocal names keep the enclosing renaming
        local = set(ren) | kept | glob
        m = {k: v for k, v in outer.items() if k not in local}
        dyn = _dynamic(fn)
        if not dyn:
            self.depth += 1
            m.update({name: f"{CANON_PREFIX}{self.depth}.{i}" for i, name in enumerate(ren)})
        self.dynamic.append(dyn)
        body = fn.body if isinstance(fn.body, list) else [fn.body]
        for st in body:
            self.visit(st, m)
        self.dynamic.pop()
        if isinstance(fn.body, list):
            return
        # lambda body is an expression (visited in place above)


def alpha_rename(tree):
    """Rename function-local variables of every function/lambda in `tree` (in place) to canonical names.
    Canonical names depend only on the structure, so alpha-equivalent code gives the same tree."""
    r = _AlphaRenamer()
    r.visit(tree, {})
    return tree


# ------------------------------------------------------------------------------------------------ dumps
_CACHE: dict = {}   # id(node) -> (node, dump); the node is kept so that its id cannot be reused


def stable_dump(node) -> str:
    """`ast.dump(node)` in a form that does not depend on the Python version (release 0.5.0a1 fix).

    `ast.dump` differs between versions for the same source: 3.12 adds `type_params=[]`, 3.13 omits empty lists
    and None fields, `repr()` of a string depends on the Unicode database of the running Python, and some 3.12
    releases end an f-string format spec that ends with a replacement field (`f"{x:>{w}}"`) with an extra
    `Constant('')`. This function always omits empty lists and unset optional fields (like `ast.dump` on 3.13),
    leaves out empty string constants inside f-strings (3.11 and 3.13 never produce them), and writes strings
    with `ascii()` (identical to `repr()` for ASCII text). On Python 3.13 its output is therefore identical to
    `ast.dump(node, include_attributes=False)` for every tree whose strings are ASCII, and two trees parsed by
    the same Python get equal dumps exactly when `ast.dump` would give them equal dumps."""
    if isinstance(node, ast.AST):
        cls = type(node)
        args = []
        for name in node._fields:
            try:
                value = getattr(node, name)
            except AttributeError:
                continue
            if value is None and getattr(cls, name, ...) is None:   # optional field left unset
                continue
            if name == "values" and isinstance(node, ast.JoinedStr) and isinstance(value, list):
                value = [v for v in value if not (isinstance(v, ast.Constant) and v.value == "")]
            if isinstance(value, list) and not value:
                continue
            args.append(f"{name}={stable_dump(value)}")
        return f"{cls.__name__}({', '.join(args)})"
    if isinstance(node, list):
        return "[" + ", ".join(stable_dump(x) for x in node) + "]"
    if isinstance(node, str):
        return ascii(node)
    return repr(node)


try:  # the unparser is private; Python 3.14 moved it from ast to _ast_unparse
    from ast import _Unparser as _BaseUnparser, _ALL_QUOTES, _MULTI_QUOTES, _Precedence
except ImportError:
    from _ast_unparse import Unparser as _BaseUnparser, _ALL_QUOTES, _MULTI_QUOTES, _Precedence


class _StableUnparser(_BaseUnparser):
    """`ast.unparse` with Python 3.13's rendering of f-strings on every supported version (release 0.5.0a1 fix).

    Unparsed text ends up in gap keys and in settings values, which the lock compares. Python 3.11 and 3.12 render
    f-strings differently from 3.13 (outer quote choice, backslash avoidance, escapes in format specs), so a lock
    written with one version reported changes under another. The three methods below follow 3.13's
    implementation; on 3.13 the output is identical to `ast.unparse`."""

    def visit_JoinedStr(self, node):
        self.write("f")
        parts = []
        for value in node.values:
            with self.buffered() as buffer:
                self._write_fstring_inner(value)
            parts.append(("".join(buffer), isinstance(value, ast.Constant)))
        out = []
        quote_types = list(_ALL_QUOTES)
        fallback_to_repr = False
        for value, is_constant in parts:
            if is_constant:
                value, new_quote_types = self._str_literal_helper(value, quote_types=quote_types,
                                                                  escape_special_whitespace=True)
                if set(new_quote_types).isdisjoint(quote_types):
                    fallback_to_repr = True
                    break
                quote_types = new_quote_types
            else:
                if "\n" in value:
                    quote_types = [q for q in quote_types if q in _MULTI_QUOTES]
                    assert quote_types
                narrowed = [q for q in quote_types if q not in value]
                if narrowed:
                    quote_types = narrowed
            out.append(value)
        if fallback_to_repr:
            quote_types = ["'''"]
            out = []
            for value, is_constant in parts:
                if is_constant:
                    value = repr('"' + value)       # forces repr() to use single quotes
                    assert value.startswith("'\""), value
                    value = value[2:-1]
                out.append(value)
        self.write(f"{quote_types[0]}{''.join(out)}{quote_types[0]}")

    def _write_fstring_inner(self, node, is_format_spec=False):
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                self._write_fstring_inner(value, is_format_spec=is_format_spec)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.replace("{", "{{").replace("}", "}}")
            if is_format_spec:
                value = value.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n")
            self.write(value)
        elif isinstance(node, ast.FormattedValue):
            self.visit_FormattedValue(node)
        else:
            raise ValueError(f"Unexpected node inside JoinedStr, {node!r}")

    def visit_FormattedValue(self, node):
        inner = type(self)()
        inner.set_precedence(_Precedence.TEST.next(), node.value)
        with self.delimit("{", "}"):
            expr = inner.visit(node.value)
            if expr.startswith("{"):
                self.write(" ")                      # "{ {" for a dict/set display
            self.write(expr)
            if node.conversion != -1:
                self.write(f"!{chr(node.conversion)}")
            if node.format_spec:
                self.write(":")
                self._write_fstring_inner(node.format_spec, is_format_spec=True)


def stable_unparse(node) -> str:
    """`ast.unparse(node)` with the same text on Python 3.11, 3.12 and 3.13 (see _StableUnparser). Falls back to
    `ast.unparse` if the private unparser of a future Python version is incompatible."""
    try:
        return _StableUnparser().visit(node)
    except (AttributeError, TypeError):
        return ast.unparse(node)


def dump_normalized(tree) -> str:
    """Dump of an already copied tree (docstrings stripped, alpha-renamed)."""
    return stable_dump(alpha_rename(_strip_docstrings(tree)))


def normalize(node) -> str:
    """Memoised per AST node: project trees are never mutated (normalisation works on a copy)."""
    if node is None:
        return "<none>"
    hit = _CACHE.get(id(node))
    if hit is not None and hit[0] is node:
        return hit[1]
    out = dump_normalized(copy.deepcopy(node))
    if len(_CACHE) > 200_000:
        _CACHE.clear()
    _CACHE[id(node)] = (node, out)
    return out


def class_shell(cls_node: ast.ClassDef) -> str:
    """Class header + non-method statements (attributes such as form_class,
    authentication_classes, post_reset_login), without method bodies."""
    shell = copy.deepcopy(cls_node)
    shell.body = [st for st in shell.body if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef))] or [ast.Pass()]
    return normalize(shell)


_CANON_MAPS: dict = {}


def canonical_text(func_node, expr) -> str:
    """(v5, R8) `ast.unparse(expr)` with the local variables of `func_node` replaced by their canonical names
    (for stable keys of gaps that quote a call, e.g. `form['username'].value`)."""
    if func_node is None or not isinstance(func_node, _SCOPES):
        return _unparse(expr)
    hit = _CANON_MAPS.get(id(func_node))
    if hit is None or hit[0] is not func_node:
        m = {} if _dynamic(func_node) else {
            name: f"{CANON_PREFIX}1.{i}" for i, name in enumerate(local_bindings(func_node)[0])}
        if m or not _dynamic(func_node):
            # (v5 review) comprehension variables (their own scope) get canonical names too, so renaming one does not
            # change a gap key that quotes a call on it; a name that is also a function local keeps that mapping
            nodes = list(own_nodes(func_node))
            ct = comprehension_targets(nodes)
            inner = {id(x) for n in nodes if isinstance(n, _COMPS) for x in ast.walk(n)}
            outside = {n.id for n in nodes if isinstance(n, ast.Name) and id(n) not in inner}
            k = 0
            for n in nodes:
                if isinstance(n, ast.Name) and id(n) in ct and n.id not in m and n.id not in outside:
                    m[n.id] = f"{CANON_PREFIX}c.{k}"
                    k += 1
        hit = (func_node, m)
        _CANON_MAPS[id(func_node)] = hit
    m = hit[1]
    if not m:
        return _unparse(expr)
    e = copy.deepcopy(expr)
    for n in ast.walk(e):
        if isinstance(n, ast.Name) and n.id in m:
            n.id = m[n.id]
    return _unparse(e)


def _unparse(n) -> str:
    try:
        s = stable_unparse(n)
    except Exception:  # pragma: no cover - defensive
        s = type(n).__name__
    return s if len(s) <= 120 else s[:117] + "..."


def digest(parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()[:24]

"""(v5, R2) Read-only access to installed / unpacked library source (``--library-path``).

Library modules are located on the given directories the way a ``site-packages`` directory is searched
(``<dir>/<pkg>/<mod>.py``); a directory whose sub-directories each hold one unpacked distribution
(``<dir>/<dist>/<pkg>/...``) is searched one level down as well.  Files are parsed with ``ast``; nothing is
imported or executed.  Used to resolve module-level view aliases (``login = LoginView.as_view()``), re-exports
(``from .views import LoginView``) and library class bases, so that a route or class that targets an unmapped
library symbol can be tied to a catalogued one, or reported as a gap that says what was found.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field

from .fingerprint import stable_unparse

MAX_DEPTH = 8


@dataclass
class LibResolution:
    symbol: str                 # canonical dotted name (module where it is defined + name)
    kind: str                   # class | function | as_view | value
    as_view_kwargs: dict = field(default_factory=dict)   # for as_view aliases: keyword -> ast expr
    trail: list = field(default_factory=list)            # ["allauth/mfa/base/views.py:127 authenticate = ..."]
    node: object = None         # the ClassDef / FunctionDef for class / function


class LibrarySource:
    def __init__(self, paths=None):
        self.roots: list[str] = []
        for p in paths or []:
            for part in str(p).split(os.pathsep):
                if part and os.path.isdir(part):
                    self.roots.append(os.path.abspath(part))
        self._bases: list[str] | None = None
        self._modules: dict = {}     # module -> (abs file, display path, tree) | None
        self._resolved: dict = {}

    @property
    def available(self) -> bool:
        return bool(self.roots)

    def _search_dirs(self) -> list[str]:
        if self._bases is None:
            out = []
            for r in self.roots:
                out.append(r)
                try:
                    subs = sorted(os.listdir(r))
                except OSError:
                    subs = []
                for s in subs:
                    d = os.path.join(r, s)
                    if os.path.isdir(d) and not s.startswith(".") and not s.endswith((".dist-info", ".egg-info")) \
                            and s != "__pycache__" and not os.path.isfile(os.path.join(d, "__init__.py")):
                        out.append(d)
            self._bases = out
        return self._bases

    def module(self, modname: str):
        """(abs file, display path, ast.Module) of a library module, or None."""
        if modname in self._modules:
            return self._modules[modname]
        found = None
        parts = modname.split(".")
        for base in self._search_dirs():
            p = os.path.join(base, *parts)
            for f in (p + ".py", os.path.join(p, "__init__.py")):
                if os.path.isfile(f):
                    try:
                        with open(f, "rb") as fh:
                            tree = ast.parse(fh.read(), filename=f)
                    except (SyntaxError, ValueError, OSError):
                        tree = None
                    found = (f, os.path.relpath(f, base), tree)
                    break
            if found:
                break
        self._modules[modname] = found
        return found

    @staticmethod
    def _top(body):
        for st in body:
            yield st
            if isinstance(st, ast.If):
                yield from LibrarySource._top(st.body)
                yield from LibrarySource._top(st.orelse)
            elif isinstance(st, ast.Try):
                yield from LibrarySource._top(st.body)
                for h in st.handlers:
                    yield from LibrarySource._top(h.body)
                yield from LibrarySource._top(st.orelse)

    @staticmethod
    def _package(modname: str, file: str) -> str:
        return modname if file.endswith("__init__.py") else modname.rpartition(".")[0]

    def _from_src(self, modname, file, st) -> str:
        if not st.level:
            return st.module or ""
        base = self._package(modname, file).split(".")
        base = base[: len(base) - (st.level - 1)] if st.level > 1 else base
        return ".".join(base + ([st.module] if st.module else []))

    def _imports(self, modname, file, tree) -> dict:
        table = {}
        for st in self._top(tree.body):
            if isinstance(st, ast.Import):
                for a in st.names:
                    table[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(st, ast.ImportFrom):
                src = self._from_src(modname, file, st)
                for a in st.names:
                    if a.name != "*":
                        table[a.asname or a.name] = f"{src}.{a.name}"
        return table

    def expr_name(self, modname, file, tree, expr) -> str | None:
        """Dotted name of a Name/Attribute expression in a library module (module scope)."""
        if isinstance(expr, ast.Subscript):
            expr = expr.value
        if isinstance(expr, ast.Name):
            for st in self._top(tree.body):
                if isinstance(st, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == expr.id:
                    return f"{modname}.{expr.id}"
            imp = self._imports(modname, file, tree)
            if expr.id in imp:
                return imp[expr.id]
            for st in self._top(tree.body):
                if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == expr.id for t in st.targets):
                    return f"{modname}.{expr.id}"
            return None
        if isinstance(expr, ast.Attribute):
            b = self.expr_name(modname, file, tree, expr.value)
            return f"{b}.{expr.attr}" if b else None
        return None

    def resolve(self, dotted: str, _depth: int = 0) -> LibResolution | None:
        """Follow re-exports and module-level aliases to the definition of a library symbol."""
        if not self.available or _depth > MAX_DEPTH:
            return None
        if _depth == 0 and dotted in self._resolved:
            return self._resolved[dotted]
        parts = dotted.split(".")
        res = None
        for i in range(len(parts) - 1, 0, -1):
            mod = ".".join(parts[:i])
            m = self.module(mod)
            if not m:
                continue
            rest = parts[i:]
            if len(rest) != 1 or m[2] is None:
                break
            res = self._binding(mod, m, rest[0], _depth)
            break
        if _depth == 0:
            self._resolved[dotted] = res
        return res

    def _binding(self, mod, m, name, depth) -> LibResolution | None:
        file, disp, tree = m
        binding = None
        for st in self._top(tree.body):
            if isinstance(st, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and st.name == name:
                binding = ("def", st)
            elif isinstance(st, (ast.Assign, ast.AnnAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                if any(isinstance(t, ast.Name) and t.id == name for t in targets) and st.value is not None:
                    binding = ("assign", st)
            elif isinstance(st, ast.ImportFrom) and any((a.asname or a.name) == name for a in st.names):
                binding = ("import", st)
            elif isinstance(st, ast.Import) and any(a.asname == name for a in st.names):
                binding = ("import", st)
        where = f"{disp}:{getattr(binding[1], 'lineno', 0)}" if binding else disp
        if binding is None:
            for st in self._top(tree.body):
                if isinstance(st, ast.ImportFrom) and any(a.name == "*" for a in st.names):
                    src = self._from_src(mod, file, st)
                    r = self.resolve(f"{src}.{name}", depth + 1) if src else None
                    if r:
                        r.trail.insert(0, f"{disp}:{st.lineno} from {src} import *")
                        return r
            return None
        kind, st = binding
        if kind == "def":
            return LibResolution(symbol=f"{mod}.{name}",
                                 kind="class" if isinstance(st, ast.ClassDef) else "function",
                                 trail=[f"{where} {'class' if isinstance(st, ast.ClassDef) else 'def'} {name}"],
                                 node=st)
        if kind == "import":
            target = self._imports(mod, file, ast.Module(body=[st], type_ignores=[])).get(name)
            if not target:
                return None
            r = self.resolve(target, depth + 1)
            if r:
                r.trail.insert(0, f"{where} import {target}")
                return r
            # the imported module is not on the library path: the re-export target is still known
            return LibResolution(symbol=target, kind="reexport", trail=[f"{where} import {target}"])
        value = st.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "as_view":
            cq = self.expr_name(mod, file, tree, value.func.value)
            if not cq:
                return None
            r = self.resolve(cq, depth + 1)
            sym = r.symbol if r else cq
            kw = {k.arg: k.value for k in value.keywords if k.arg}
            return LibResolution(symbol=sym, kind="as_view", as_view_kwargs=kw,
                                 trail=[f"{where} {name} = {stable_unparse(value)[:80]}"] + (r.trail if r else []),
                                 node=r.node if r else None)
        if isinstance(value, (ast.Name, ast.Attribute)):
            q = self.expr_name(mod, file, tree, value)
            r = self.resolve(q, depth + 1) if q else None
            if r:
                r.trail.insert(0, f"{where} {name} = {stable_unparse(value)[:80]}")
                return r
            return LibResolution(symbol=q, kind="reexport", trail=[f"{where} {name} = {stable_unparse(value)[:80]}"]) \
                if q else None
        return LibResolution(symbol=f"{mod}.{name}", kind="value", trail=[f"{where} {name} = <expression>"])

    def class_bases(self, symbol: str) -> list[str] | None:
        """Dotted names of the bases of a library class (None if the class is not found)."""
        r = self.resolve(symbol)
        if not r or r.kind != "class" or not isinstance(r.node, ast.ClassDef):
            return None
        mod = r.symbol.rpartition(".")[0]
        m = self.module(mod)
        if not m or m[2] is None:
            return None
        out = []
        for b in r.node.bases:
            q = self.expr_name(mod, m[0], m[2], b)
            if q:
                rb = self.resolve(q)
                out.append(rb.symbol if rb else q)
        return out

    def ancestors(self, symbol: str, limit: int = 12) -> list[str]:
        """Library base classes of `symbol`, breadth first (the class itself excluded)."""
        out, todo, seen = [], [symbol], {symbol}
        while todo and len(out) < limit:
            c = todo.pop(0)
            for b in self.class_bases(c) or []:
                if b not in seen:
                    seen.add(b)
                    out.append(b)
                    todo.append(b)
        return out

    def defines(self, symbol: str, method: str) -> bool:
        r = self.resolve(symbol)
        if not r or not isinstance(r.node, ast.ClassDef):
            return False
        return any(isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name == method for s in r.node.body)

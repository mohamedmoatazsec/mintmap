"""Parse a project tree: modules, import/alias symbol tables, classes, functions.

Only the standard library `ast` module is used; project code is never imported
or executed.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field

from .fingerprint import stable_unparse

DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
                         ".tox", ".nox", "site-packages", "build", "dist", ".mypy_cache", ".pytest_cache"}

# ---- test code (excluded by default; --include-tests keeps it) ----
TEST_DIR_NAMES = {"tests", "test"}
TEST_FILE_RE = re.compile(r"^(test_.*|.*_test|.*_tests|tests|conftest)\.py$")
# modules with these names are test code only if they define TestCase subclasses (e.g. a BaseTestCase)
TEST_SUPPORT_FILES = {"test.py", "testing.py"}


def test_path_reason(rel: str) -> str | None:
    """Why a file (path relative to the project root) is test code by its path, or None."""
    parts = rel.split(os.sep)
    if any(d in TEST_DIR_NAMES for d in parts[:-1]):
        return "in a tests/ or test/ directory"
    if TEST_FILE_RE.match(parts[-1]):
        return "test file name"
    return None


def unsubscript(expr):
    """(v5, R6) `Base[Any]`, `Generic[T]`, `Mixin[int, str]` -> the unsubscripted base expression (PEP 585 /
    typing generics: the subscript does not change the class that is inherited)."""
    while isinstance(expr, ast.Subscript):
        expr = expr.value
    return expr


def defines_testcase(tree) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef):
            for b in n.bases:
                name = b.attr if isinstance(b, ast.Attribute) else (b.id if isinstance(b, ast.Name) else "")
                if name.endswith("TestCase"):
                    return True
    return False

import builtins

BUILTIN_NAMES = set(dir(builtins))

# ---- (v5, R1) module naming with PEP 420 namespace packages ----
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DOTTED_REF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
# files whose dotted string constants name modules (DJANGO_SETTINGS_MODULE, ROOT_URLCONF, INSTALLED_APPS,
# include("x.urls"), AppConfig.name ...): used only as evidence for source roots and module names
_DOTTED_STRING_FILES = re.compile(r"(^|/)(manage|wsgi|asgi|urls|apps|settings\w*|celery)\.py$|(^|/)settings/")


@dataclass
class Gap:
    type: str
    file: str
    where: str
    detail: str
    line: int = 0
    # (v5, R8) stable form of `detail` used in the key, e.g. a quoted call with the function's local variables
    # replaced by canonical names, so renaming a local does not look like a new gap
    key_detail: str | None = None

    @property
    def key(self) -> str:
        # Line numbers are deliberately excluded so that moving code does not
        # look like a new gap.
        return f"{self.type}|{self.file}|{self.where}|{self.key_detail if self.key_detail is not None else self.detail}"

    def as_dict(self):
        return dict(type=self.type, file=self.file, where=self.where, detail=self.detail, line=self.line,
                    key=self.key)


@dataclass
class Module:
    name: str
    path: str                # path relative to project root
    tree: ast.Module
    is_package: bool
    symbols: dict = field(default_factory=dict)       # local name -> qualified name
    defs: dict = field(default_factory=dict)          # local name -> qualname (functions/classes)
    assigns: dict = field(default_factory=dict)       # local name -> [ast.expr] (module-level values)
    instances: dict = field(default_factory=dict)     # local name -> class qualname (x = Cls())
    view_aliases: dict = field(default_factory=dict)  # local name -> (class qualname, as_view Call)
    star_imports: list = field(default_factory=list)

    @property
    def package(self) -> str:
        return self.name if self.is_package else self.name.rpartition(".")[0]


@dataclass
class FunctionInfo:
    qualname: str
    module: str
    node: ast.AST
    cls: str | None
    params: list
    is_async: bool
    local_imports: dict = field(default_factory=dict)
    local_vars: set = field(default_factory=set)
    nested: dict = field(default_factory=dict)        # nested def name -> qualname
    parent: str | None = None

    @property
    def short(self) -> str:
        return self.qualname[len(self.module) + 1:]


@dataclass
class ClassInfo:
    qualname: str
    module: str
    node: ast.ClassDef
    bases: list               # resolved qualnames (project or library), None for unresolvable
    methods: dict             # name -> function qualname
    attrs: dict               # name -> ast.expr (class-level assignments)
    decorated_actions: set = field(default_factory=set)  # DRF @action methods
    unresolved_bases: list = field(default_factory=list)  # (v5, R6) base expressions MintMap cannot resolve


class Project:
    def __init__(self, root: str, excluded_dirs=None, library_bases=None, library_instances=None,
                 library_returns=None, library_lacks=None, include_tests: bool = False):
        self.root = os.path.abspath(root)
        self.include_tests = include_tests
        self.test_files_excluded: list[dict] = []     # [{file, reason}]
        self.test_files_reincluded: list[dict] = []   # [{file, reason, imported_by}]
        self.excluded_dirs = set(DEFAULT_EXCLUDED_DIRS if excluded_dirs is None else excluded_dirs)
        self.library_bases = library_bases or {}
        self.library_instances = library_instances or {}
        self.library_returns = library_returns or {}
        self.library_lacks = library_lacks or {}
        self.files_seen: list[str] = []
        self.parse_failures: list[dict] = []
        self.modules: dict[str, Module] = {}
        self.module_by_path: dict[str, Module] = {}
        self.functions: dict[str, FunctionInfo] = {}
        self.classes: dict[str, ClassInfo] = {}
        self.gaps: list[Gap] = []
        # (v5, R1) sys.path-like source roots: abs dir -> sorted reasons ("project_dir", "manage.py",
        # "import evidence"); module names of files in namespace-package directories (no __init__.py) are
        # computed relative to them.  module_aliases: other evidenced names of the same module.
        self.source_roots: dict[str, list] = {}
        self._strong_roots: set = set()
        self._ref_names: set = set()
        self._name_cache: dict = {}
        self._ambiguous: dict = {}
        self.module_aliases: dict[str, str] = {}
        self.namespace_modules: list[str] = []      # modules named through a source root (not __init__.py)
        self._load()

    # ------------------------------------------------------------------ loading
    def _iter_py_files(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self.excluded_dirs and not d.endswith(".egg-info"))
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    yield os.path.join(dirpath, fn)

    def _regular_name(self, abspath: str) -> tuple[list, bool, str]:
        """v1-v4 naming: climb through directories that contain __init__.py.  Returns (name parts,
        is_package, the directory the name is relative to)."""
        d, fn = os.path.split(abspath)
        stem = fn[:-3]
        is_pkg = stem == "__init__"
        parts = [] if is_pkg else [stem]
        base = d
        while os.path.isfile(os.path.join(d, "__init__.py")) and os.path.abspath(d) != os.path.dirname(self.root):
            parts.insert(0, os.path.basename(d))
            if os.path.abspath(d) == self.root:
                d = os.path.dirname(d)
                break
            d = os.path.dirname(d)
        base = os.path.abspath(d)
        if not parts:  # __init__.py directly in a non-package dir (root)
            parts = [os.path.basename(os.path.dirname(abspath))]
        return parts, is_pkg, base

    def _module_name(self, abspath: str) -> tuple[str, bool]:
        """(v5, R1) Dotted module name.  Regular packages (__init__.py) keep the v4 name when the directory the
        name is relative to is a source root.  Otherwise (a PEP 420 namespace-package directory, or a package
        below one) the name is taken relative to the nearest source root above it: the project directory, a
        directory holding manage.py, or a directory that absolute imports / settings dotted paths resolve from.
        Several candidate names: the one that project code imports wins (the others become aliases); if none is
        imported and the roots disagree, the nearest root wins and a `module_name_ambiguous` gap is recorded."""
        if abspath in self._name_cache:
            return self._name_cache[abspath]
        parts, is_pkg, base = self._regular_name(abspath)
        res = (".".join(parts), is_pkg)
        if base in self.source_roots or not base.startswith(self.root + os.sep):
            # (v5 review fix) a regular package below a directory that is ALSO put on sys.path (an `apps/` package
            # directory that settings add with sys.path.insert): project code imports its modules by the shorter
            # name (`from users.forms import F`, `include("users.urls")`); that name becomes an alias of the v4 name
            here = os.path.dirname(abspath)
            for r in self._strong_roots:
                if r != base and r.startswith(base + os.sep) and (here == r or here.startswith(r + os.sep)):
                    rel = os.path.relpath(here, r).split(os.sep) if here != r else []
                    alt = ".".join([x for x in rel if x != "."] + ([] if is_pkg else [parts[-1]]))
                    if alt and alt != res[0] and alt in self._ref_names and all(IDENT_RE.match(x) for x in
                                                                                alt.split(".")):
                        self.module_aliases.setdefault(alt, res[0])
            self._name_cache[abspath] = res
            return res
        cands = []
        for r in self.source_roots:
            if base.startswith(r + os.sep):
                rel = os.path.relpath(base, r).split(os.sep)
                if all(IDENT_RE.match(x) for x in rel):
                    cands.append((r, ".".join(rel + parts), r in self._strong_roots))
        if not cands:
            self._name_cache[abspath] = res
            return res
        pool = [c for c in cands if c[2]] or cands
        ev = [c for c in pool if c[1] in self._ref_names]
        chosen = max(ev or pool, key=lambda c: len(c[0]))
        if len(ev) > 1:
            for c in ev:
                if c[1] != chosen[1]:
                    self.module_aliases[c[1]] = chosen[1]
        elif not ev and len({c[1] for c in pool}) > 1:
            # reported when the module is analysed (_add_module), not for excluded test files
            rel = os.path.relpath(abspath, self.root)
            self._ambiguous[abspath] = Gap("module_name_ambiguous", rel, chosen[1], "candidate names " + ", ".join(
                f"{c[1]} (root {os.path.relpath(c[0], self.root)})" for c in sorted(pool)) +
                "; none is imported by project code")
        res = (chosen[1], is_pkg)
        self._name_cache[abspath] = res
        return res

    def _compute_source_roots(self, pre: dict):
        """(v5, R1) sys.path-like roots.  `pre`: abspath -> (rel, test_reason, tree, exc)."""
        roots: dict = {self.root: {"project_dir"}}
        index: dict = {}           # last component -> {tuple of rel parts} (module files, packages, dirs)
        for ap, (rel, reason, _t, _e) in pre.items():
            comps = rel[:-3].split(os.sep)
            if comps[-1] == "__init__":
                comps = comps[:-1]
            if comps:
                index.setdefault(comps[-1], set()).add(tuple(comps))
            dparts = rel.split(os.sep)[:-1]
            for k in range(1, len(dparts) + 1):
                index.setdefault(dparts[k - 1], set()).add(tuple(dparts[:k]))
            if os.path.basename(rel) == "manage.py" and not reason:
                roots.setdefault(os.path.dirname(ap), set()).add("manage.py")
        for ap, (rel, reason, tree, _e) in pre.items():
            if tree is None or reason:
                continue
            here = tuple(rel.split(os.sep)[:-1])
            refs = []
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    refs += [a.name for a in n.names]
                elif isinstance(n, ast.ImportFrom) and not n.level and n.module:
                    refs.append(n.module)
                    refs += [f"{n.module}.{a.name}" for a in n.names if a.name != "*"]
            if _DOTTED_STRING_FILES.search(rel.replace(os.sep, "/")):
                for n in ast.walk(tree):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and DOTTED_REF_RE.match(n.value):
                        refs.append(n.value)
            for ref in refs:
                parts = tuple(ref.split("."))
                for k in range(len(parts), 1, -1):   # single-component refs (`import utils`) are not evidence
                    sub = parts[:k]
                    hit = None
                    for c in index.get(sub[-1], ()):
                        if len(c) >= k and c[len(c) - k:] == sub and here[:len(c) - k] == c[:len(c) - k]:
                            if hit is None or len(c) > len(hit):
                                hit = c
                    if hit is not None:
                        d = os.path.join(self.root, *hit[:len(hit) - k]) if len(hit) > k else self.root
                        roots.setdefault(os.path.abspath(d), set()).add("import evidence")
                        for j in range(1, k + 1):
                            self._ref_names.add(".".join(sub[:j]))
                        break
        self.source_roots = {r: sorted(v) for r, v in sorted(roots.items())}
        self._strong_roots = {r for r, v in roots.items() if v - {"project_dir"}}

    def _parse(self, ap, rel):
        try:
            with open(ap, "rb") as fh:
                src = fh.read()
            return ast.parse(src, filename=rel), None
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            return None, exc

    def _add_module(self, ap, rel, tree):
        name, is_pkg = self._module_name(ap)
        if ap in self._ambiguous:
            self.gaps.append(self._ambiguous[ap])
        if self._regular_name(ap)[2] not in self.source_roots and ".".join(self._regular_name(ap)[0]) != name:
            self.namespace_modules.append(name)
        if name in self.modules:
            # Two files map to the same dotted name (separate source roots).  Keep
            # the first, address the second by its path-derived name, record a gap.
            alt = rel[:-3].replace(os.sep, ".")
            self.gaps.append(Gap("module_name_collision", rel, name, f"also defined by {self.modules[name].path}"))
            name = alt
        mod = Module(name=name, path=rel, tree=tree, is_package=is_pkg)
        self.modules[name] = mod
        self.module_by_path[rel] = mod
        return mod

    def _load(self):
        excluded: dict = {}   # module name -> [(abspath, rel, reason, tree|None)]
        pre: dict = {}        # abspath -> (rel, test reason, tree, exc); parsed first so roots can be computed
        for ap in self._iter_py_files():
            rel = os.path.relpath(ap, self.root)
            reason = None if self.include_tests else test_path_reason(rel)
            tree = exc = None
            if not reason:
                tree, exc = self._parse(ap, rel)
                if tree is not None and not self.include_tests and os.path.basename(rel) in TEST_SUPPORT_FILES \
                        and defines_testcase(tree):
                    reason = "test support module (TestCase subclass)"
            pre[ap] = (rel, reason, tree, exc)
        self._compute_source_roots(pre)
        for ap, (rel, reason, tree, exc) in pre.items():
            if reason:
                excluded.setdefault(self._module_name(ap)[0], []).append((ap, rel, reason, tree))
                continue
            self.files_seen.append(rel)
            if tree is None:
                err = f"{type(exc).__name__}: {exc}".splitlines()[0]
                self.parse_failures.append(dict(file=rel, error=err))
                self.gaps.append(Gap("parse_failure", rel, "<module>", type(exc).__name__))
                continue
            self._add_module(ap, rel, tree)
        if excluded:
            self._reinclude_imported_tests(excluded)
        self.test_files_excluded = sorted((dict(file=rel, reason=reason) for group in excluded.values()
                                           for ap, rel, reason, _ in group), key=lambda d: d["file"])
        for mod in self.modules.values():
            self._index_module(mod)
        for mod in self.modules.values():
            self._index_module_values(mod)
        for cls in self.classes.values():
            cls.bases, cls.unresolved_bases = [], []
            for b in cls.node.bases:
                q = self.canonical(self.resolve_expr_static(cls.module, unsubscript(b)))
                cls.bases.append(q)
                if q is None:
                    cls.unresolved_bases.append(stable_unparse(b))
        self.__dict__.pop("_mro_memo", None)    # bases are final now: MRO memo starts here

    def _imported_names(self, mod: Module) -> set:
        """Dotted names a module may import (module-level and function-local imports)."""
        out = set()
        for n in ast.walk(mod.tree):
            if isinstance(n, ast.Import):
                out |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                src = self._resolve_relative(mod, n.level, n.module) if n.level else (n.module or "")
                out.add(src)
                out |= {f"{src}.{a.name}" if src else a.name for a in n.names if a.name != "*"}
        return out

    def _reinclude_imported_tests(self, excluded: dict):
        """A file that matches the test-code patterns but is imported by analysed (non-test) code is
        analysed anyway: naming a production module `test_*.py` must not hide it."""
        pending = list(self.modules.values())
        while pending:
            nxt = []
            for mod in pending:
                for name in sorted(self._imported_names(mod)):
                    for ap, rel, reason, tree in excluded.pop(name, []):
                        self.files_seen.append(rel)
                        if tree is None:
                            tree, exc = self._parse(ap, rel)
                            if tree is None:
                                self.parse_failures.append(dict(file=rel, error=f"{type(exc).__name__}: {exc}"
                                                                .splitlines()[0]))
                                self.gaps.append(Gap("parse_failure", rel, "<module>", type(exc).__name__))
                                continue
                        self.test_files_reincluded.append(dict(file=rel, reason=reason, imported_by=mod.path))
                        nxt.append(self._add_module(ap, rel, tree))
            pending = nxt

    # ------------------------------------------------------------ module index
    def _resolve_relative(self, mod: Module, level: int, modname: str | None) -> str:
        pkg = mod.package.split(".") if mod.package else []
        if level > 1:
            pkg = pkg[: len(pkg) - (level - 1)]
        base = ".".join(pkg)
        if modname:
            return f"{base}.{modname}" if base else modname
        return base

    def unalias(self, dotted: str) -> str:
        """(v5, R1) Rewrite a dotted name that starts with an alias module name to the canonical module name."""
        if not self.module_aliases or not dotted:
            return dotted
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            m = ".".join(parts[:i])
            if m in self.module_aliases:
                return ".".join([self.module_aliases[m]] + parts[i:])
        return dotted

    def _import_bindings(self, mod: Module, node, table: dict, where: str):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    table[a.asname] = self.unalias(a.name)
                else:
                    top = a.name.split(".")[0]
                    table[top] = top
        elif isinstance(node, ast.ImportFrom):
            src = self._resolve_relative(mod, node.level, node.module) if node.level else (node.module or "")
            src = self.unalias(src)
            for a in node.names:
                if a.name == "*":
                    mod.star_imports.append(src)
                    continue
                table[a.asname or a.name] = f"{src}.{a.name}" if src else a.name

    def _top_level_statements(self, body):
        """Yield module-level statements, descending into if/try/with blocks."""
        for st in body:
            yield st
            if isinstance(st, ast.If):
                yield from self._top_level_statements(st.body)
                yield from self._top_level_statements(st.orelse)
            elif isinstance(st, ast.Try) or (hasattr(ast, "TryStar") and isinstance(st, ast.TryStar)):
                yield from self._top_level_statements(st.body)
                for h in st.handlers:
                    yield from self._top_level_statements(h.body)
                yield from self._top_level_statements(st.orelse)
                yield from self._top_level_statements(st.finalbody)
            elif isinstance(st, ast.With):
                yield from self._top_level_statements(st.body)

    def _index_module(self, mod: Module):
        for st in self._top_level_statements(mod.tree.body):
            if isinstance(st, (ast.Import, ast.ImportFrom)):
                self._import_bindings(mod, st, mod.symbols, mod.name)
            elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qn = f"{mod.name}.{st.name}"
                mod.defs[st.name] = qn
                self._index_function(mod, st, qn, cls=None)
            elif isinstance(st, ast.ClassDef):
                qn = f"{mod.name}.{st.name}"
                mod.defs[st.name] = qn
                self._index_class(mod, st, qn)
        # star imports of project modules are expanded lazily in lookup_symbol
        for src in mod.star_imports:
            if src not in self.modules and not any(src == m for m in self.modules):
                self.gaps.append(Gap("star_import_unresolved", mod.path, mod.name, f"from {src} import *"))

    def _index_module_values(self, mod: Module):
        for st in self._top_level_statements(mod.tree.body):
            targets, value = [], None
            if isinstance(st, ast.Assign):
                targets, value = st.targets, st.value
            elif isinstance(st, ast.AnnAssign) and st.value is not None:
                targets, value = [st.target], st.value
            elif isinstance(st, ast.AugAssign):
                targets, value = [st.target], st.value
            for t in targets:
                if not isinstance(t, ast.Name):
                    continue
                mod.assigns.setdefault(t.id, []).append(value)
                if isinstance(st, ast.AugAssign):
                    continue
                if isinstance(value, (ast.Name, ast.Attribute)):
                    q = self.resolve_expr_static(mod.name, value)
                    if q and t.id not in mod.defs:
                        mod.symbols[t.id] = q
                elif isinstance(value, ast.Call):
                    fq = self.resolve_expr_static(mod.name, value.func)
                    if isinstance(value.func, ast.Attribute) and value.func.attr == "as_view":
                        cq = self.resolve_expr_static(mod.name, value.func.value)
                        if cq:
                            mod.view_aliases[t.id] = (self.canonical(cq), value)
                    elif fq:
                        fq = self.canonical(fq)
                        if fq in self.classes or fq in self.library_bases or fq.split(".")[-1][:1].isupper():
                            mod.instances[t.id] = fq

    def _function_locals(self, mod: Module, node, info: FunctionInfo):
        args = node.args
        for a in args.posonlyargs + args.args + args.kwonlyargs:
            info.local_vars.add(a.arg)
        if args.vararg:
            info.local_vars.add(args.vararg.arg)
        if args.kwarg:
            info.local_vars.add(args.kwarg.arg)
        body_nodes = list(self.walk_function_body(node))
        # (v5 review fix) comprehension targets are local to the comprehension (Python 3): a name bound only
        # there and also used outside every comprehension refers, outside, to the enclosing/global binding
        comp_targets, comp_inner = set(), set()
        for sub in body_nodes:
            if isinstance(sub, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                for g in sub.generators:
                    comp_targets |= {id(t) for t in ast.walk(g.target) if isinstance(t, ast.Name)}
                comp_inner |= {id(x) for x in ast.walk(sub)}
        outside_loads = {sub.id for sub in body_nodes if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)
                         and id(sub) not in comp_inner}
        comp_only = []
        for sub in body_nodes:
            if isinstance(sub, (ast.Import, ast.ImportFrom)):
                self._import_bindings(mod, sub, info.local_imports, info.qualname)
            elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store) and id(sub) in comp_targets:
                comp_only.append(sub.id)
            elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                info.local_vars.add(sub.id)
            elif isinstance(sub, ast.ExceptHandler) and sub.name:
                info.local_vars.add(sub.name)
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not node:
                qn = f"{info.qualname}.{sub.name}"
                info.nested[sub.name] = qn
        for name in comp_only:
            if name not in outside_loads:
                info.local_vars.add(name)
        for name in info.local_imports:
            info.local_vars.discard(name)

    @staticmethod
    def walk_function_body(node):
        """Walk a function body without descending into nested defs/classes (but
        yielding the nested def nodes themselves)."""
        stack = list(reversed(node.body)) if hasattr(node, "body") else []
        while stack:
            n = stack.pop()
            yield n
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(n))))

    def _index_function(self, mod: Module, node, qn: str, cls: str | None, parent: str | None = None):
        params = [a.arg for a in node.args.posonlyargs + node.args.args]
        info = FunctionInfo(qualname=qn, module=mod.name, node=node, cls=cls, params=params,
                            is_async=isinstance(node, ast.AsyncFunctionDef), parent=parent)
        self.functions[qn] = info
        self._function_locals(mod, node, info)
        for sub in self.walk_function_body(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not node:
                self._index_function(mod, sub, f"{qn}.{sub.name}", cls=None, parent=qn)
        return info

    def _index_class(self, mod: Module, node: ast.ClassDef, qn: str):
        methods, attrs, actions = {}, {}, set()
        for st in node.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                mq = f"{qn}.{st.name}"
                methods[st.name] = mq
                self._index_function(mod, st, mq, cls=qn)
                for d in st.decorator_list:
                    dn = d.func if isinstance(d, ast.Call) else d
                    if (isinstance(dn, ast.Name) and dn.id == "action") or (
                            isinstance(dn, ast.Attribute) and dn.attr == "action"):
                        actions.add(st.name)
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        attrs[t.id] = st.value
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                attrs[st.target.id] = st.value
            elif isinstance(st, ast.ClassDef):
                self._index_class(mod, st, f"{qn}.{st.name}")
        self.classes[qn] = ClassInfo(qualname=qn, module=mod.name, node=node, bases=[], methods=methods,
                                     attrs=attrs, decorated_actions=actions)

    # -------------------------------------------------------------- resolution
    def lookup_symbol(self, modname: str, name: str, _seen=None) -> str | None:
        mod = self.modules.get(modname)
        if mod is None:
            return None
        if name in mod.defs:
            return mod.defs[name]
        if name in mod.symbols:
            return mod.symbols[name]
        if name in mod.assigns or name in mod.instances or name in mod.view_aliases:
            return f"{mod.name}.{name}"
        _seen = _seen or set()
        for src in mod.star_imports:
            if src in self.modules and src not in _seen:
                _seen.add(src)
                r = self.lookup_symbol(src, name, _seen)
                if r:
                    return r
        if name in BUILTIN_NAMES:
            return f"builtins.{name}"
        return None

    def resolve_expr_static(self, modname: str, expr, func: FunctionInfo | None = None) -> str | None:
        """Resolve a Name/Attribute chain to a dotted qualified name (not canonicalized)."""
        if isinstance(expr, ast.Name):
            if func is not None:
                f = func
                while f is not None:
                    if expr.id in f.local_imports:
                        return f.local_imports[expr.id]
                    if expr.id in f.nested:
                        return f.nested[expr.id]
                    if expr.id in f.local_vars:
                        return None
                    f = self.functions.get(f.parent) if f.parent else None
            return self.lookup_symbol(modname, expr.id)
        if isinstance(expr, ast.Attribute):
            base = self.resolve_expr_static(modname, expr.value, func)
            return f"{base}.{expr.attr}" if base else None
        return None

    def module_prefix(self, qn: str):
        parts = qn.split(".")
        for i in range(len(parts), 0, -1):
            m = ".".join(parts[:i])
            if m in self.modules:
                return m, parts[i:]
        if self.module_aliases:
            un = self.unalias(qn)
            if un != qn:
                return self.module_prefix(un)
        return None, parts

    def canonical(self, qn: str | None, _depth: int = 0) -> str | None:
        """Follow project re-exports / aliases and library instance aliases."""
        if qn is None or _depth > 20:
            return qn
        for inst, cls in self.library_instances.items():
            if qn == inst or qn.startswith(inst + "."):
                return cls + qn[len(inst):]
        mod, rest = self.module_prefix(qn)
        if mod is None or not rest:
            return qn
        m = self.modules[mod]
        first = rest[0]
        if first in m.defs:
            return qn
        if first in m.symbols:
            target = m.symbols[first]
            if target == qn:
                return qn
            return self.canonical(".".join([target] + rest[1:]), _depth + 1)
        for src in m.star_imports:
            if src in self.modules:
                r = self.lookup_symbol(src, first)
                if r:
                    return self.canonical(".".join([r] + rest[1:]), _depth + 1)
        return qn

    def is_project(self, qn: str | None) -> bool:
        if not qn:
            return False
        return qn in self.functions or qn in self.classes or self.module_prefix(qn)[0] is not None

    # ------------------------------------------------------------------ classes
    def mro(self, cls_qn: str, _seen=None) -> list[str]:
        """Approximate C3 linearisation; library classes appear as opaque names
        (expanded with overlay LIBRARY_BASES when known).  Memoised for top-level calls (the class table does not
        change once the project is loaded)."""
        if _seen is None:
            memo = self.__dict__.setdefault("_mro_memo", {})
            hit = memo.get(cls_qn)
            if hit is None:
                hit = self._mro(cls_qn, None)
                memo[cls_qn] = hit
            return list(hit)
        return self._mro(cls_qn, _seen)

    def _mro(self, cls_qn: str, _seen=None) -> list[str]:
        _seen = _seen or set()
        if cls_qn in _seen:
            return []
        _seen = _seen | {cls_qn}
        if cls_qn in self.classes:
            bases = [b for b in self.classes[cls_qn].bases if b]
        else:
            bases = list(self.library_bases.get(cls_qn, []))
        seqs = [self.mro(b, _seen) for b in bases] + [list(bases)]
        out = [cls_qn]
        seqs = [s for s in seqs if s]
        while seqs:
            for s in seqs:
                head = s[0]
                if not any(head in t[1:] for t in seqs):
                    break
            else:
                head = seqs[0][0]  # inconsistent hierarchy: fall back to depth-first
            out.append(head)
            seqs = [[x for x in s if x != head] for s in seqs]
            seqs = [s for s in seqs if s]
        return out

    def lookup_method(self, cls_qn: str, name: str, after: str | None = None):
        """Return ('project', func_qn) | ('library', 'lib.Cls.name') | None.
        `after` implements super(): start the search after that class in the MRO."""
        order = self.mro(cls_qn)
        if after is not None:
            if after in order:
                order = order[order.index(after) + 1:]
            else:
                order = []
        for c in order:
            if c in self.classes:
                if name in self.classes[c].methods:
                    return ("project", self.classes[c].methods[name])
            elif name in self.library_lacks.get(c, ()):
                continue  # known library base that does not define `name`
            else:
                return ("library", f"{c}.{name}")
        return None

    def unresolved_bases_in_mro(self, cls_qn: str) -> list:
        """(v5, R6) [(project class, base expression)] for every base in the project part of the MRO that MintMap
        cannot resolve: methods, attributes and gates inherited through it are invisible."""
        out = []
        for c in self.mro(cls_qn):
            if c in self.classes:
                out += [(c, b) for b in self.classes[c].unresolved_bases]
        return out

    def class_attr(self, cls_qn: str, name: str):
        for c in self.mro(cls_qn):
            if c in self.classes and name in self.classes[c].attrs:
                return c, self.classes[c].attrs[name]
        return None, None

    def subclasses_library(self, cls_qn: str, lib_qn_set) -> str | None:
        for c in self.mro(cls_qn):
            if c in lib_qn_set:
                return c
        return None

    def module_for_function(self, func_qn: str) -> Module:
        return self.modules[self.functions[func_qn].module]

    def file_of(self, qn: str) -> str:
        if qn in self.functions:
            return self.modules[self.functions[qn].module].path
        if qn in self.classes:
            return self.modules[self.classes[qn].module].path
        m, _ = self.module_prefix(qn)
        return self.modules[m].path if m else "?"

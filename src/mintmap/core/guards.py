"""Intraprocedural "is the sink control-dependent on check success?" analysis.

Vocabulary
----------
atom key      ('call', id(ast.Call)) or ('var', name)
RT(e)         atoms that are necessarily truthy/successful when expression e is truthy
RF(e)         atoms that are necessarily truthy/successful when e is falsy
guarantees    atoms that are necessarily successful whenever execution reaches the
              sink statement, derived from: enclosing `if` branches, preceding
              `if <cond>: return/raise` early exits, preceding raising checks
              (unless an exception handler swallows them), `assert` (tracked
              separately because `python -O` removes asserts).

This is deliberately simple and syntactic.  It does not model loops, exceptions
raised by arbitrary calls, aliasing, or values flowing through containers.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

_FALSY_CONSTS = (None, False, 0, "", b"")


def call_key(node) -> tuple:
    return ("call", id(node))


def atoms(e) -> set:
    if isinstance(e, ast.Await):
        return atoms(e.value)
    if isinstance(e, ast.NamedExpr):
        out = atoms(e.value)
        if isinstance(e.target, ast.Name):
            out.add(("var", e.target.id))
        return out
    if isinstance(e, ast.Call):
        if isinstance(e.func, ast.Name) and e.func.id == "bool" and len(e.args) == 1:
            return atoms(e.args[0]) | {call_key(e)}
        return {call_key(e)}
    if isinstance(e, ast.Name):
        return {("var", e.id)}
    return set()


def all_atoms(e) -> set:
    """Every call/variable atom occurring anywhere in an expression."""
    out = set()
    for n in ast.walk(e):
        if isinstance(n, ast.Call):
            out.add(call_key(n))
        elif isinstance(n, ast.Name):
            out.add(("var", n.id))
    return out


def _is_none(e) -> bool:
    return isinstance(e, ast.Constant) and e.value is None


def _const(e, val) -> bool:
    return isinstance(e, ast.Constant) and e.value is val


def RT(e) -> set:
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return RF(e.operand)
    if isinstance(e, ast.BoolOp):
        parts = [RT(v) for v in e.values]
        if isinstance(e.op, ast.And):
            return set().union(*parts)
        return set.intersection(*parts) if parts else set()
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, left, right = e.ops[0], e.left, e.comparators[0]
        if _is_none(left):
            left, right = right, left
        if isinstance(op, (ast.IsNot, ast.NotEq)) and _is_none(right):
            return atoms(left)
        if isinstance(op, (ast.Is, ast.Eq)) and _const(right, True):
            return atoms(left)
        return set()
    return atoms(e)


def RF(e) -> set:
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return RT(e.operand)
    if isinstance(e, ast.BoolOp):
        parts = [RF(v) for v in e.values]
        if isinstance(e.op, ast.Or):
            return set().union(*parts)
        return set.intersection(*parts) if parts else set()
    if isinstance(e, ast.Compare) and len(e.ops) == 1:
        op, left, right = e.ops[0], e.left, e.comparators[0]
        if _is_none(left):
            left, right = right, left
        if isinstance(op, (ast.Is, ast.Eq)) and _is_none(right):
            return atoms(left)
        if isinstance(op, (ast.Is, ast.Eq)) and _const(right, False):
            return atoms(left)
        return set()
    return set()


def _blocks(st):
    """(field, block) pairs of a compound statement."""
    if isinstance(st, ast.If):
        return [("body", st.body), ("orelse", st.orelse)]
    if isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
        return [("body", st.body), ("orelse", st.orelse)]
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return [("body", st.body)]
    if isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
        out = [("body", st.body), ("orelse", st.orelse), ("finalbody", st.finalbody)]
        for i, h in enumerate(st.handlers):
            out.append((f"handler{i}", h.body))
        return out
    if isinstance(st, ast.Match):
        return [(f"case{i}", c.body) for i, c in enumerate(st.cases)]
    return []


_DESC: dict = {}   # id(node) -> (node, frozenset of descendant ids); project trees are never mutated


def _contains(node, target) -> bool:
    if node is target:
        return True
    hit = _DESC.get(id(node))
    if hit is None or hit[0] is not node:
        if len(_DESC) > 400_000:
            _DESC.clear()
        hit = (node, frozenset(id(n) for n in ast.walk(node)))
        _DESC[id(node)] = hit
    return id(target) in hit[1]


def stmt_path(func_node, target):
    """[(parent, field, index), ...] from the function body down to the statement
    that contains `target` (an expression or statement node)."""
    def search(parent, fieldname, block):
        for i, st in enumerate(block):
            if not _contains(st, target):
                continue
            for f, b in _blocks(st):
                sub = search(st, f, b)
                if sub is not None:
                    return [(parent, fieldname, i)] + sub
            return [(parent, fieldname, i)]
        return None
    return search(func_node, "body", func_node.body)


def get_block(parent, fieldname):
    if fieldname.startswith("handler"):
        return parent.handlers[int(fieldname[7:])].body
    if fieldname.startswith("case"):
        return parent.cases[int(fieldname[4:])].body
    return getattr(parent, fieldname)


def always_exits(block) -> bool:
    for st in block:
        if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(st, ast.If) and st.orelse and always_exits(st.body) and always_exits(st.orelse):
            return True
        if isinstance(st, (ast.With, ast.AsyncWith)) and always_exits(st.body):
            return True
        if isinstance(st, ast.Try):
            if st.finalbody and always_exits(st.finalbody):
                return True
            if always_exits(st.body) and all(always_exits(h.body) for h in st.handlers):
                return True
    return False


@dataclass
class Guarantees:
    strong: set = field(default_factory=set)
    assert_only: set = field(default_factory=set)
    swallowed: set = field(default_factory=set)   # raising checks whose exception is caught
    tested: set = field(default_factory=set)      # every atom that appears in an enclosing/preceding test


class GuardAnalyzer:
    """Analyse one function.  `is_raising(call_node) -> bool` tells which calls
    are checks that raise on failure."""

    def __init__(self, func_node, is_raising):
        self.func = func_node
        self.is_raising = is_raising
        self._assigns = None
        self._expect_raise = None

    def expected_to_raise(self, call) -> bool:
        """The project code treats `call` as raising on failure: it is the value of a statement
        directly inside a `try:` body whose every handler exits (return/raise).  Used only for
        unrecognized checks, whose failure semantics MintMap does not know."""
        if self._expect_raise is None:
            ids = set()
            for n in ast.walk(self.func):
                if isinstance(n, (ast.Try, getattr(ast, "TryStar", ast.Try))) and n.handlers and \
                        all(always_exits(h.body) for h in n.handlers):
                    for st in n.body:
                        v = getattr(st, "value", None) if isinstance(st, (ast.Expr, ast.Assign, ast.AnnAssign)) \
                            else None
                        v = v.value if isinstance(v, ast.Await) else v
                        if isinstance(v, ast.Call):
                            ids.add(id(v))
            self._expect_raise = ids
        return id(call) in self._expect_raise

    # ------------------------------------------------------------ guarantees
    def _raising_in(self, node) -> set:
        out = set()
        for n in ast.walk(node):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(n, ast.Call) and self.is_raising(n):
                out.add(call_key(n))
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            tgt = node.targets[0] if isinstance(node, ast.Assign) else node.target
            val = node.value.value if isinstance(node.value, ast.Await) else node.value
            if isinstance(tgt, ast.Name) and isinstance(val, ast.Call) and self.is_raising(val):
                out.add(("var", tgt.id))
        return out

    def after(self, st, g: Guarantees) -> set:
        """Atoms guaranteed successful after `st` completes normally."""
        if isinstance(st, ast.If):
            g.tested |= all_atoms(st.test)
            b_exit = always_exits(st.body)
            o_exit = always_exits(st.orelse) if st.orelse else False
            if b_exit and not o_exit:
                return RF(st.test) | self.after_block(st.orelse, g)
            if o_exit and not b_exit:
                return RT(st.test) | self.after_block(st.body, g)
            if not b_exit and not o_exit:
                return (RT(st.test) | self.after_block(st.body, g)) & (RF(st.test) | self.after_block(st.orelse, g))
            return set()
        if isinstance(st, ast.Assert):
            g.assert_only |= RT(st.test)
            g.tested |= all_atoms(st.test)
            return set()
        if isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            inner = self.after_block(st.body, g) | self.after_block(st.orelse, g)
            if all(always_exits(h.body) for h in st.handlers):
                return inner | self.after_block(st.finalbody, g)
            g.swallowed |= {k for k in inner if k[0] == "call"}
            return self.after_block(st.finalbody, g)
        if isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                ce = item.context_expr
                fn = ce.func if isinstance(ce, ast.Call) else ce
                if (isinstance(fn, ast.Name) and fn.id == "suppress") or (
                        isinstance(fn, ast.Attribute) and fn.attr == "suppress"):
                    return set()
            return self._raising_in_header(st) | self.after_block(st.body, g)
        if isinstance(st, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return)):
            return self._raising_in(st)
        return set()

    def _raising_in_header(self, st) -> set:
        out = set()
        for item in st.items:
            for n in ast.walk(item.context_expr):
                if isinstance(n, ast.Call) and self.is_raising(n):
                    out.add(call_key(n))
        return out

    def after_block(self, block, g) -> set:
        out = set()
        for st in block:
            out |= self.after(st, g)
        return out

    def guarantees(self, sink) -> Guarantees:
        """sink: an AST node inside the function, or None for 'normal end of body'."""
        g = Guarantees()
        if sink is None:
            path = [(self.func, "body", len(self.func.body))]
        else:
            path = stmt_path(self.func, sink)
            if path is None:
                return g
        for parent, fieldname, idx in path:
            block = get_block(parent, fieldname)
            if isinstance(parent, (ast.If, ast.While)):
                g.tested |= all_atoms(parent.test)
                if fieldname == "body":
                    g.strong |= RT(parent.test)
                elif fieldname == "orelse" and isinstance(parent, ast.If):
                    g.strong |= RF(parent.test)
            if isinstance(parent, ast.Try) and fieldname == "orelse":
                g.strong |= self.after_block(parent.body, g)
            for st in block[:idx]:
                g.strong |= self.after(st, g)
        # expression-level ancestors inside the sink's statement
        if sink is not None and path:
            parent, fieldname, idx = path[-1]
            st = get_block(parent, fieldname)[idx]
            self._expr_guards(st, sink, g)
            # `x = check() ...; login(...)` on the same line: nothing extra
        return g

    def _expr_guards(self, st, sink, g: Guarantees):
        parents = {}
        for n in ast.walk(st):
            for c in ast.iter_child_nodes(n):
                parents[id(c)] = n
        cur = sink
        while id(cur) in parents:
            par = parents[id(cur)]
            if isinstance(par, ast.IfExp):
                if cur is par.body:
                    g.strong |= RT(par.test)
                elif cur is par.orelse:
                    g.strong |= RF(par.test)
            elif isinstance(par, ast.BoolOp):
                idx = next((i for i, v in enumerate(par.values) if v is cur), None)
                if idx:
                    prev = par.values[:idx]
                    if isinstance(par.op, ast.And):
                        for v in prev:
                            g.strong |= RT(v)
                    else:
                        for v in prev:
                            g.strong |= RF(v)
            if par is st:
                break
            cur = par

    # ------------------------------------------------------------ bindings
    def assigns(self):
        """var -> [(lineno, value_expr)] for single-Name assignments, in order;
        plus all store line numbers per var."""
        if self._assigns is None:
            binds, stores = {}, {}
            for n in ast.walk(self.func):
                if isinstance(n, ast.Assign):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            binds.setdefault(t.id, []).append((n.lineno, n.value))
                        elif isinstance(t, (ast.Tuple, ast.List)) and t.elts and isinstance(t.elts[0], ast.Name):
                            # `ok, info = check()` -> first element carries success
                            binds.setdefault(t.elts[0].id, []).append((n.lineno, ("tuple_first", n.value)))
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                    binds.setdefault(n.target.id, []).append((n.lineno, n.value))
                elif isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                    binds.setdefault(n.target.id, []).append((n.lineno, n.value))
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    stores.setdefault(n.id, []).append(n.lineno)
            self._assigns = (binds, stores)
        return self._assigns

    def implied(self, var: str, before_line: int, _depth=0) -> set:
        """Atoms implied successful when `var` is truthy at `before_line`."""
        binds, stores = self.assigns()
        if _depth > 8 or var not in binds:
            return set()
        cands = [(ln, v) for ln, v in binds[var] if ln <= before_line]
        if not cands:
            return set()
        ln, val = cands[-1]
        # reassigned between binding and use (any other store) -> nothing implied
        if any(ln < s < before_line for s in stores.get(var, [])):
            return set()
        if isinstance(val, tuple) and val[0] == "tuple_first":
            inner = val[1].value if isinstance(val[1], ast.Await) else val[1]
            return {call_key(inner)} if isinstance(inner, ast.Call) else set()
        out = set(RT(val))
        for k in list(out):
            if k[0] == "var" and k[1] != var:
                out |= self.implied(k[1], ln, _depth + 1)
        return out

    def closure(self, keys: set, line: int) -> set:
        out = set(keys)
        for k in keys:
            if k[0] == "var":
                out |= self.implied(k[1], line)
        return out

    def binding(self, call) -> tuple[str, str | None]:
        """How the result of `call` is consumed: bare | assign | tuple_first | condition | return | other."""
        path = stmt_path(self.func, call)
        if not path:
            return "other", None
        parent, fieldname, idx = path[-1]
        st = get_block(parent, fieldname)[idx]
        for n in ast.walk(st):  # walrus: `(user := authenticate(...))`
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
                v = n.value.value if isinstance(n.value, ast.Await) else n.value
                if v is call:
                    return "assign", n.target.id
        val = st.value if isinstance(st, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Return)) else None
        if isinstance(val, ast.Await):
            val = val.value
        if isinstance(st, ast.Expr) and val is call:
            return "bare", None
        if isinstance(st, ast.Assign) and val is call:
            t = st.targets[0]
            if isinstance(t, ast.Name):
                return "assign", t.id
            if isinstance(t, (ast.Tuple, ast.List)) and t.elts and isinstance(t.elts[0], ast.Name):
                return "tuple_first", t.elts[0].id
        if isinstance(st, ast.AnnAssign) and val is call and isinstance(st.target, ast.Name):
            return "assign", st.target.id
        if isinstance(st, (ast.If, ast.While)) and _contains(st.test, call):
            return "condition", None
        if isinstance(st, ast.Return):
            return "return", None
        if isinstance(st, ast.Assign) and isinstance(st.targets[0], ast.Name):
            return "assign_expr", st.targets[0].id
        return "other", None

    def classify(self, call, ret: str, sink) -> tuple[str, str]:
        """Relation of check `call` to `sink` (None = end of function).
        ret: bool | subject_or_none | raises | tuple | unknown (unrecognized check)."""
        if ret == "unknown" and self.expected_to_raise(call):
            ret = "raises"
        g = self.guarantees(sink)
        sink_line = getattr(sink, "lineno", 10 ** 9) if sink is not None else 10 ** 9
        strong = self.closure(g.strong, sink_line)
        weak = self.closure(g.assert_only, sink_line)
        key = call_key(call)
        kind, var = self.binding(call)
        if call.lineno > sink_line:
            return "present_unproven", "check executes after the mint on this path"
        if key in strong:
            if ret == "tuple" and kind not in ("tuple_first",):
                return "condition_always_truthy", "check returns a (bool, info) tuple, which is always truthy"
            return "guards_mint", _how(kind, var)
        if key in weak:
            return "guards_mint_assert_only", "guarded only by `assert` (removed under python -O)"
        if key in g.swallowed:
            return "present_unproven", "check raises on failure but an exception handler swallows it"
        if kind == "bare" and ret == "unknown":
            return "present_unproven", ("called as a statement; MintMap does not know whether this unrecognized "
                                        "check raises on failure or returns a result that is being ignored")
        if kind == "bare" and ret != "raises":
            return "result_ignored", "check result is discarded (bare expression statement)"
        tested = self.closure(g.tested, sink_line)
        if key in tested:
            return "present_unproven", "check appears in a condition that does not constrain the mint (e.g. `or`)"
        if kind in ("assign", "tuple_first", "assign_expr"):
            return "present_unproven", f"check result stored in `{var}` but `{var}` does not constrain the mint"
        return "present_unproven", "relationship between check and mint not established"


def _how(kind, var):
    if kind in ("assign", "tuple_first", "assign_expr"):
        return f"mint only reachable when `{var}` (check result) is successful"
    if kind == "bare":
        return "check raises on failure before the mint"
    if kind == "condition":
        return "check is in a condition whose success is required to reach the mint (branch or early exit)"
    return "mint only reachable after check success"

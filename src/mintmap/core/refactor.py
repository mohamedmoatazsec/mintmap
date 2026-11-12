"""(v5, R8) Refactoring-insensitive function dumps for fingerprints: conservative inlining of extracted helpers.

An "extract function" refactor moves statements of a function `f` into a new module-level helper `h` and
replaces them with a call `h(a, b)`.  Before hashing `f`, MintMap inlines such calls back, but only where the
inlined text is exactly equivalent to running the call:

* `h` is a plain module-level project function in the SAME module as `f` (so every free name of `h` means the
  same thing in `f`), not async, not a generator, no decorators, no default / `*args` / `**kwargs` /
  keyword-only parameters, no `global` / `nonlocal`, no nested `def` / `class` / `lambda`, no imports, no
  `locals()` / `eval()` / `exec()`, never rebinds a parameter, and none of its free names is a local variable of
  `f` (which would capture it);
* `h`'s body is straight-line with respect to `return`: either it has no `return` at all, or its only `return`
  is its last statement (`S1 ... Sn; return E`);
* every argument of the call is a plain name or a constant (no `*`/`**`), and every parameter is given exactly
  once; a name argument cannot be rebound while `h` runs (a module-level function cannot rebind `f`'s locals),
  so substituting the name for the parameter is exact;
* a helper with statements is inlined only where its call is the FIRST thing a statement evaluates: the whole
  expression statement `h(...)`, the value of an assignment / `return`, or the test of an `if` (also through
  `not`, the left operand of `and`/`or`, of a comparison or of a binary operator).  `S1 ... Sn` are inserted
  before that statement and the call is replaced by `E`.  A helper that is a single `return E` is inlined at any
  position (an expression replaced by an expression evaluated at the same point).  A loop condition is never
  inlined (it is evaluated again on every iteration);
* the helper's own local variables get fresh names (no capture of `f`'s variables); the alpha-renaming of
  `fingerprint.normalize` then makes the result independent of the names chosen.

In a truth-testing position (`if`/`while`/`assert` tests, `not`, comprehension filters, conditional
expressions) `bool(x)` is replaced by `x` when `bool` is the builtin (same truth value, `__bool__`/`__len__` is
called once either way).

The helper's body becomes part of every inlining caller's dump, so a later change of the helper changes the
caller's fingerprint; a helper whose body is instantiated in the dump of a function that IS hashed is not hashed
again on its own (see `Analysis.project_closure`, v5 review fix: coverage is decided from the bodies actually
present in hashed dumps at any inlining depth, not from each function's own transformation; a helper that the
outermost dump does not inline, because of that caller's locals or the depth budget `MAX_INLINE_DEPTH`, is hashed
on its own).  Anything that does not meet these conditions is hashed as before (a possible
false alarm, never a missed change).

(v6b) Also inlined: "extract method", a call `self.h(...)` made by a method of class `C` where `h` is a plain
method of the same class `C` (see `method_shape`: no decorator, not rebound in the class body, not overridden by
any project subclass of `C`, the caller never rebinds its receiver); and arguments that are attribute chains on
a name (`request.META`, `self.request.headers`) when the helper assigns or deletes none of the chain's
attributes (the chain is then read where the parameter is used rather than once at the call: the same object
unless reading the attribute has side effects).  A private method (`_h`) whose every reference in the project is
such an inlined call from a kept method of its class is left out of `class_dump` and is not a callee root of a
library flow (its body is in the callers' dumps); a public method stays (a library may call it by name).

Not handled (documented): extracting the mint call itself into the helper (the mint site moves to another
function, so the path id changes), helpers in another module or another class, helpers with control flow around
`return`, other expression arguments (`f(x)`, `a or b`: evaluated once at the call, but several times if
substituted), and check evidence (it is computed on the code as written, so a check moved into a helper can
read weaker).
"""
from __future__ import annotations

import ast
import copy

from .fingerprint import own_nodes, local_bindings, DYNAMIC_NAME_CALLS, dump_normalized, normalize

MAX_INLINE_DEPTH = 3
_FORBIDDEN = (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal, ast.FunctionDef, ast.AsyncFunctionDef,
              ast.ClassDef, ast.Lambda, ast.Import, ast.ImportFrom)
_STMT_LIST_FIELDS = ("body", "orelse", "finalbody")


class _Shape:
    __slots__ = ("qn", "module", "params", "stmts", "ret", "locals", "free", "stored_attrs", "cls")

    def __init__(self, qn, module, params, stmts, ret, locals_, free, stored_attrs=frozenset(), cls=None):
        self.qn, self.module, self.params, self.stmts, self.ret, self.locals, self.free = \
            qn, module, params, stmts, ret, locals_, free
        # (v6b) attribute names the helper assigns or deletes (an attribute-chain argument through one of them
        # could read a different object after the assignment); `cls`: the class of a method helper
        self.stored_attrs, self.cls = stored_attrs, cls


class Inliner:
    def __init__(self, project):
        self.p = project
        self._shapes: dict = {}
        self._fn: dict = {}        # qualname -> (dump, inlined original call ids, transformed tree, inlined bodies)
        self._cls: dict = {}
        self._counter = 0
        self._subclasses: dict = {}
        self._omit: dict = {}
        self._attr_refs = None     # (v6b) project-wide counts of attribute names / string constants

    # ------------------------------------------------------------------ helper eligibility
    def shape(self, qn: str):
        """Eligibility of a module-level function as an inlinable helper (None: not eligible)."""
        if qn in self._shapes:
            return self._shapes[qn]
        self._shapes[qn] = None
        info = self.p.functions.get(qn)
        if info is None or info.cls or info.parent or isinstance(info.node, ast.AsyncFunctionDef):
            return None
        s = self._body_shape(info, info.node)
        self._shapes[qn] = s
        return s

    def method_shape(self, qn: str):
        """(v6b) Eligibility of a method `C.h` as an inlinable helper of `self.h(...)` calls made by other methods
        of the same class `C` ("extract method").  Besides the conditions of `shape` (the receiver is its first
        parameter, which the body never rebinds): `h` is a plain method (no decorator, so no staticmethod /
        classmethod / property), the class body does not rebind the name `h`, and no project subclass of `C`
        overrides `h` (so `self.h` means `C.h` for every receiver the project creates)."""
        key = ("m", qn)
        if key in self._shapes:
            return self._shapes[key]
        self._shapes[key] = None
        info = self.p.functions.get(qn)
        if info is None or not info.cls or info.parent or isinstance(info.node, ast.AsyncFunctionDef):
            return None
        ci = self.p.classes.get(info.cls)
        name = info.node.name
        if ci is None or ci.methods.get(name) != qn or name in ci.attrs or \
                (name.startswith("__") and name.endswith("__")):
            return None
        if not (info.node.args.posonlyargs + info.node.args.args):
            return None
        if self._overridden_below(info.cls, name):
            return None
        s = self._body_shape(info, info.node)
        if s is not None:
            s.cls = info.cls
        self._shapes[key] = s
        return s

    def _overridden_below(self, cls_qn: str, name: str) -> bool:
        subs = self._subclasses.get(cls_qn)
        if subs is None:
            subs = [c for c in self.p.classes if c != cls_qn and cls_qn in self.p.mro(c)]
            self._subclasses[cls_qn] = subs
        return any(name in self.p.classes[c].methods or name in self.p.classes[c].attrs for c in subs)

    def _body_shape(self, info, node):
        a = node.args
        if node.decorator_list or a.vararg or a.kwarg or a.kwonlyargs or a.defaults or \
                any(d is not None for d in a.kw_defaults):
            return None
        params = [x.arg for x in a.posonlyargs + a.args]
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and \
                isinstance(body[0].value.value, str):
            body = body[1:]
        if not body:
            return None
        own = list(own_nodes(node))
        if any(isinstance(n, _FORBIDDEN) for n in own):
            return None
        if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in DYNAMIC_NAME_CALLS
               for n in own):
            return None
        if any(isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id in params for n in own):
            return None
        returns = [n for n in own if isinstance(n, ast.Return)]
        ret = None
        stmts = body
        if returns:
            last = body[-1]
            if len(returns) != 1 or returns[0] is not last or last.value is None:
                return None
            stmts, ret = body[:-1], last.value
        ren, _kept, _g, _nl = local_bindings(node)
        free = {n.id for n in own if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                and n.id not in params and n.id not in ren}
        stored = frozenset(n.attr for n in own if isinstance(n, ast.Attribute)
                           and isinstance(n.ctx, (ast.Store, ast.Del)))
        return _Shape(info.qualname, info.module, params, stmts, ret, ren, free, stored)

    # ------------------------------------------------------------------ public
    def function_dump(self, qn: str) -> str:
        return self._transform(qn)[0]

    def inlined_calls(self, qn: str) -> set:
        """ids of the ORIGINAL call nodes of `qn` that were inlined (their callee's body is in qn's dump)."""
        return self._transform(qn)[1]

    def transformed_node(self, qn: str):
        return self._transform(qn)[2]

    def inlined_bodies(self, qn: str) -> frozenset:
        """(v5 review) qualnames of every helper whose body was instantiated in qn's dump, at ANY inlining depth.
        `Analysis.project_closure` treats a function as covered only when its body is in one of these sets for
        a function it hashes; whether a nested call is inlined depends on the outermost caller's context
        (its locals, the depth budget), so the per-function `inlined_calls` alone does not prove coverage."""
        return self._transform(qn)[3]

    def class_dump(self, cls_qn: str) -> str:
        """Whole class, with every method replaced by its inlined form.  (v6b) A private method (`_name`, not a
        dunder) whose every reference in the project is a `self._name(...)` call that a kept method of this
        class inlines is left out: its body is in those methods' dumps ("extract method" leaves the class dump
        unchanged)."""
        hit = self._cls.get(cls_qn)
        if hit is not None:
            return hit
        ci = self.p.classes[cls_qn]
        omit = self.omitted_methods(cls_qn)
        node = copy.deepcopy(ci.node)
        new_body = []
        for st in node.body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) and f"{cls_qn}.{st.name}" in self.p.functions:
                if st.name in omit:
                    continue
                new_body.append(copy.deepcopy(self.transformed_node(f"{cls_qn}.{st.name}")))
            else:
                new_body.append(st)
        node.body = new_body or [ast.Pass()]
        out = dump_normalized(node)
        self._cls[cls_qn] = out
        return out

    def _references(self):
        """(v6b) Project-wide counts of attribute names (`x.name`) and the set of string constants."""
        if self._attr_refs is None:
            attrs, strings = {}, set()
            for mod in self.p.modules.values():
                for n in ast.walk(mod.tree):
                    if isinstance(n, ast.Attribute):
                        attrs[n.attr] = attrs.get(n.attr, 0) + 1
                    elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.isidentifier():
                        strings.add(n.value)
            self._attr_refs = (attrs, strings)
        return self._attr_refs

    def omitted_methods(self, cls_qn: str) -> set:
        """(v6b) Names of the private methods of `cls_qn` that `class_dump` leaves out (inlined everywhere)."""
        hit = self._omit.get(cls_qn)
        if hit is None:
            hit = self._omit[cls_qn] = frozenset(self._omitted_methods(cls_qn)) if cls_qn in self.p.classes \
                else frozenset()
        return hit

    def _omitted_methods(self, cls_qn: str) -> set:
        ci = self.p.classes[cls_qn]
        own = {name: qn for name, qn in ci.methods.items() if qn == f"{cls_qn}.{name}" and qn in self.p.functions}
        cand = {name for name, qn in own.items()
                if name.startswith("_") and not name.startswith("__") and self.method_shape(qn) is not None}
        if not cand:
            return set()
        attrs, strings = self._references()
        inlined_in = {}           # helper name -> methods whose own dump inlines a `self.name(...)` call
        counts = {}
        for name, qn in own.items():
            inl = self.inlined_calls(qn)
            if not inl:
                continue
            for n in ast.walk(self.p.functions[qn].node):
                if id(n) in inl and isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                        n.func.attr in cand:
                    counts[n.func.attr] = counts.get(n.func.attr, 0) + 1
                    inlined_in.setdefault(n.func.attr, set()).add(name)
        omit = {h for h in cand if counts.get(h) and counts[h] == attrs.get(h, 0) and h not in strings}
        # a helper is omitted only where the methods that inline it are kept (their dumps carry its body)
        changed = True
        while changed:
            changed = False
            for h in sorted(omit):
                if inlined_in.get(h, set()) & omit:
                    omit.discard(h)
                    changed = True
        return omit

    def _may_inline(self, info) -> bool:
        caller_locals = set(info.local_vars) | set(info.local_imports)
        recv = self._receiver(info)
        for n in ast.walk(info.node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id == "bool":
                    return True
                if n.func.id in caller_locals:
                    continue
                q = self.p.lookup_symbol(info.module, n.func.id)
                q = self.p.canonical(q) if q else None
                if q and q != info.qualname and self.shape(q) is not None:
                    return True
            elif recv and isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                    isinstance(n.func.value, ast.Name) and n.func.value.id == recv:
                q = self.p.classes[info.cls].methods.get(n.func.attr)
                if q and q != info.qualname and self.method_shape(q) is not None:
                    return True
        return False

    def _receiver(self, info):
        """(v6b) The name of the receiver parameter (`self`) of a plain method, when the method never rebinds it;
        None for functions, static / class methods and nested functions."""
        if not info.cls or info.parent or info.cls not in self.p.classes:
            return None
        node = info.node
        if any(isinstance(d, ast.Name) and d.id in ("staticmethod", "classmethod") for d in node.decorator_list):
            return None
        params = node.args.posonlyargs + node.args.args
        if not params:
            return None
        name = params[0].arg
        for n in own_nodes(node):
            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)):
                return None
        return name

    # ------------------------------------------------------------------ transformation
    def _transform(self, qn):
        hit = self._fn.get(qn)
        if hit is not None:
            return hit
        info = self.p.functions[qn]
        if not self._may_inline(info):
            # fast path: no call of an eligible helper and no bool() to simplify: the plain normalised dump
            out = (normalize(info.node), frozenset(), info.node, frozenset())
            self._fn[qn] = out
            return out
        memo: dict = {}
        tree = copy.deepcopy(info.node, memo)
        orig_of = {id(v): k for k, v in memo.items() if isinstance(v, ast.AST)}
        st = dict(info=info, caller_locals=set(info.local_vars) | set(info.local_imports), inlined=set(),
                  orig_of=orig_of, bodies=set(), receiver=self._receiver(info))
        self._rewrite_lists(tree, st, depth=0, stack=(qn,))
        self._peephole_bool(tree, info)
        # keep the transformed tree before dumping (dump_normalized renames in place: dump a copy)
        keep = copy.deepcopy(tree)
        out = (dump_normalized(tree), frozenset(st["inlined"]), keep, frozenset(st["bodies"]))
        self._fn[qn] = out
        return out

    def _rewrite_lists(self, node, st, depth, stack):
        """Rewrite every statement list of `node` (not entering nested def/class/lambda)."""
        for field in _STMT_LIST_FIELDS:
            lst = getattr(node, field, None)
            if isinstance(lst, list) and lst and isinstance(lst[0], ast.stmt):
                setattr(node, field, self._rewrite_stmts(lst, st, depth, stack))
        for h in getattr(node, "handlers", None) or []:
            h.body = self._rewrite_stmts(h.body, st, depth, stack)
        for c in getattr(node, "cases", None) or []:
            c.body = self._rewrite_stmts(c.body, st, depth, stack)

    def _rewrite_stmts(self, stmts, st, depth, stack):
        out = []
        for s in stmts:
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._rewrite_lists(s, st, depth, stack)
            pre, s2 = self._inline_stmt(s, st, depth, stack)
            out.extend(pre)
            if s2 is not None:
                out.append(s2)
        return out or [ast.Pass()]

    def _resolve_helper(self, call, st, stack):
        if not isinstance(call, ast.Call):
            return None
        info = st["info"]
        receiver = None
        if isinstance(call.func, ast.Name):
            name = call.func.id
            if name in st["caller_locals"]:
                return None
            q = self.p.lookup_symbol(info.module, name)
            q = self.p.canonical(q) if q else None
            if not q or q in stack:
                return None
            s = self.shape(q)
        elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and \
                st.get("receiver") and call.func.value.id == st["receiver"]:
            # (v6b) extract method: `self.h(...)` with `h` a plain method of the caller's own class
            q = self.p.classes[info.cls].methods.get(call.func.attr)
            if not q or q in stack:
                return None
            s = self.method_shape(q)
            if s is None or s.cls != info.cls:
                return None
            receiver = ast.Name(id=st["receiver"], ctx=ast.Load())
        else:
            return None
        if s is None or s.module != info.module or (s.free & st["caller_locals"]):
            return None
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            return None
        params = s.params[1:] if receiver is not None else s.params
        if len(call.args) > len(params):
            return None
        binding = dict(zip(params, call.args))
        for k in call.keywords:
            if k.arg not in params or k.arg in binding:
                return None
            binding[k.arg] = k.value
        if set(binding) != set(params):
            return None
        if not all(_stable_argument(v, s.stored_attrs) for v in binding.values()):
            return None
        if receiver is not None:
            binding[s.params[0]] = receiver
        return s, binding

    def _instantiate(self, s: _Shape, binding: dict):
        """Copies of the helper's statements and return expression: parameters replaced by the arguments,
        locals renamed fresh."""
        self._counter += 1
        fresh = {n: f"%inl{self._counter}.{n}" for n in s.locals}
        stmts = copy.deepcopy(s.stmts)
        ret = copy.deepcopy(s.ret)

        def subst(tree):
            for n in ast.walk(tree):
                for field, val in ast.iter_fields(n):
                    if isinstance(val, ast.Name) and isinstance(val.ctx, ast.Load) and val.id in binding:
                        setattr(n, field, copy.deepcopy(binding[val.id]))
                    elif isinstance(val, list):
                        for i, x in enumerate(val):
                            if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load) and x.id in binding:
                                val[i] = copy.deepcopy(binding[x.id])
            for n in ast.walk(tree):
                if isinstance(n, ast.Name) and n.id in fresh:
                    n.id = fresh[n.id]
                elif isinstance(n, ast.ExceptHandler) and n.name in fresh:
                    n.name = fresh[n.name]
                elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name in fresh:
                    n.name = fresh[n.name]
            return tree
        wrapper = ast.Module(body=stmts, type_ignores=[])
        subst(wrapper)
        if ret is not None:
            holder = ast.Expr(value=ret)
            subst(holder)
            ret = holder.value
        return wrapper.body, ret

    def _record(self, call, st, depth, qn=None):
        if qn is not None:
            st["bodies"].add(qn)
        if depth == 0:
            o = st["orig_of"].get(id(call))
            if o is not None:
                st["inlined"].add(o)

    def _inline_stmt(self, s, st, depth, stack):
        if depth > MAX_INLINE_DEPTH:
            return [], s
        pre = []
        slot = _leading_slot(s)
        if slot is not None:
            parent, field, call = slot
            hit = self._resolve_helper(call, st, stack)
            if hit is not None:
                shape, binding = hit
                if shape.ret is None and not (isinstance(s, ast.Expr) and s.value is call):
                    hit = None      # a helper without a return value used as a value: not inlined
            if hit is not None:
                shape, binding = hit
                stmts, ret = self._instantiate(shape, binding)
                self._record(call, st, depth, shape.qn)
                stmts = self._rewrite_stmts(stmts, st, depth + 1, stack + (shape.qn,)) if stmts else []
                if shape.ret is None:
                    return [x for x in stmts if not isinstance(x, ast.Pass)] or [ast.Pass()], None
                pre = [x for x in stmts if not isinstance(x, ast.Pass)]
                setattr(parent, field, ret)
        # single-expression helpers anywhere in the statement's own expressions
        self._inline_expressions(s, st, depth, stack)
        return pre, s

    def _inline_expressions(self, s, st, depth, stack):
        if depth > MAX_INLINE_DEPTH:
            return
        for field, val in ast.iter_fields(s):
            if field in _STMT_LIST_FIELDS or field in ("handlers", "cases"):
                continue
            if isinstance(s, (ast.While,)) and field == "test":
                continue      # re-evaluated on every iteration: inlining a pure expression is still exact,
                # but keep loop conditions as written (conservative)
            items = val if isinstance(val, list) else [val]
            for i, x in enumerate(items):
                if not isinstance(x, ast.AST) or isinstance(x, (ast.stmt, ast.Lambda)):
                    continue
                new = self._inline_expr(x, st, depth, stack)
                if new is not x:
                    if isinstance(val, list):
                        val[i] = new
                    else:
                        setattr(s, field, new)

    def _inline_expr(self, e, st, depth, stack):
        if isinstance(e, ast.Lambda):
            return e
        hit = self._resolve_helper(e, st, stack) if isinstance(e, ast.Call) else None
        if hit is not None and not hit[0].stmts and hit[0].ret is not None:
            shape, binding = hit
            _stmts, ret = self._instantiate(shape, binding)
            self._record(e, st, depth, shape.qn)
            holder = ast.Expr(value=ret)
            self._inline_expressions(holder, st, depth + 1, stack + (shape.qn,))
            return holder.value
        for field, val in ast.iter_fields(e):
            items = val if isinstance(val, list) else [val]
            for i, x in enumerate(items):
                if isinstance(x, ast.AST) and not isinstance(x, (ast.stmt, ast.Lambda, ast.expr_context)):
                    new = self._inline_expr(x, st, depth, stack)
                    if new is not x:
                        if isinstance(val, list):
                            val[i] = new
                        else:
                            setattr(e, field, new)
        return e

    # ------------------------------------------------------------------ bool() in truth tests
    def _peephole_bool(self, tree, info):
        mod = self.p.modules.get(info.module)
        if "bool" in info.local_vars or "bool" in info.local_imports or \
                (mod is not None and ("bool" in mod.defs or "bool" in mod.symbols or "bool" in mod.assigns)):
            return

        def strip(e):
            while isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "bool" and \
                    len(e.args) == 1 and not e.keywords and not isinstance(e.args[0], ast.Starred):
                e = e.args[0]
            if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
                e.operand = strip(e.operand)
            elif isinstance(e, ast.BoolOp):
                e.values = [strip(v) for v in e.values]
            return e
        for n in ast.walk(tree):
            if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)):
                n.test = strip(n.test)
            elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
                n.operand = strip(n.operand)
            elif isinstance(n, ast.comprehension):
                n.ifs = [strip(x) for x in n.ifs]


def _stable_argument(v, stored_attrs) -> bool:
    """(v6b) An argument that may be substituted for a parameter: a name, a constant, or an attribute chain on a
    name (`request.headers`, `self.request.META`) none of whose attributes the helper assigns or deletes.  A chain
    is then read where the helper uses the parameter instead of once at the call: the same object, unless reading
    the attribute has side effects (documented)."""
    if isinstance(v, (ast.Name, ast.Constant)):
        return True
    n = v
    while isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
        if n.attr in stored_attrs:
            return False
        n = n.value
    return n is not v and isinstance(n, ast.Name)


def _leading_slot(s):
    """(parent, field, call) for the call a statement evaluates first, or None."""
    if isinstance(s, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Return)):
        parent, field = s, "value"
    elif isinstance(s, ast.If):
        parent, field = s, "test"
    else:
        return None
    node = getattr(parent, field, None)
    while node is not None:
        if isinstance(node, ast.Call):
            return parent, field, node
        if isinstance(node, ast.UnaryOp):
            parent, field = node, "operand"
        elif isinstance(node, ast.Compare):
            parent, field = node, "left"
        elif isinstance(node, ast.BinOp):
            parent, field = node, "left"
        elif isinstance(node, ast.BoolOp):
            return _first_of_boolop(node)
        else:
            return None
        node = getattr(parent, field)
    return None


def _first_of_boolop(b):
    first = b.values[0]
    if isinstance(first, ast.Call):
        return _ListSlot(b.values, 0), "item", first
    return None


class _ListSlot:
    """setattr(slot, 'item', x) replaces lst[i]."""

    def __init__(self, lst, i):
        self.lst, self.i = lst, i

    def __setattr__(self, k, v):
        if k == "item":
            self.lst[self.i] = v
        else:
            object.__setattr__(self, k, v)

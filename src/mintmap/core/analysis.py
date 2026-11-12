"""MintMap analysis: entries -> traversal -> mint sites -> evidence -> fingerprints."""
from __future__ import annotations

import ast
import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field

from . import overlay
from .callgraph import CallGraph, CallSite, Resolution, GENERIC_LEAVES
from .catalog import Catalog, MintAPI
from .fingerprint import normalize, class_shell, digest, canonical_text, stable_unparse
from .guards import GuardAnalyzer, RT, call_key, always_exits
from .libsource import LibrarySource
from .lockfile import SHADOWED_STATUS
from .project import Project, Gap
from .refactor import Inliner
from .credentials import CredentialHeuristics, heuristic_api, HEURISTIC_KIND, MANAGER_ATTRS, CREATE_METHODS
from .candidates import CandidateFinder, CANDIDATE_KIND, GROUPS as CANDIDATE_GROUPS, RANK_ORDER, candidate_api
from .settings_extract import extract_settings, drf_auth_classes, canonical_value, Dynamic, flat_values, \
    Alternatives
from .urlconf import UrlConfParser, find_root_urlconfs, Route, mark_shadowing, ENDPOINT_KINDS

TOOL_VERSION = "0.6.0.dev0"

HTTP_VERBS = ["get", "post", "put", "patch", "delete", "head", "options"]
ALWAYS_DISPATCHED = ["dispatch", "setup"]
_ALL = HTTP_VERBS + ["create", "update", "partial_update", "destroy", "list", "retrieve"]
# hook -> the methods (in a library base) that invoke it
HOOK_DISPATCHERS = {
    "form_valid": ["post", "put"], "form_invalid": ["post", "put"], "get_form": ["get", "post", "put"],
    "get_form_kwargs": ["get", "post", "put"], "get_form_class": ["get", "post", "put"],
    "get_success_url": ["post", "put"], "get_context_data": ["get", "post"], "done": ["post"],
    "render_done": ["post"], "perform_create": ["create"], "perform_update": ["update", "partial_update"],
    "perform_destroy": ["destroy"], "get_serializer": _ALL, "get_serializer_class": _ALL,
    "get_serializer_context": _ALL, "get_object": _ALL, "get_queryset": _ALL, "login": ["post"],
    "process_login": ["post"], "get_response": ["post"], "create": ["post"], "update": ["put"],
    "partial_update": ["patch"], "destroy": ["delete"], "list": ["get"], "retrieve": ["get"],
    "initial": _ALL, "perform_authentication": _ALL, "check_permissions": _ALL,
}
VERB_TO_HOOKS: dict = {}
for _h, _ds in HOOK_DISPATCHERS.items():
    for _d in _ds:
        VERB_TO_HOOKS.setdefault(_d, []).append(_h)
VIEWSET_ACTIONS = ["list", "create", "retrieve", "update", "partial_update", "destroy"]
# hooks the framework calls only after validation of a form / serializer
FRAMEWORK_GATES = {"form_valid": ("form_class", "django.views.generic.edit.ProcessFormView.post calls form_valid "
                                                "only when form.is_valid()"),
                   "perform_create": ("serializer_class", "rest_framework CreateModelMixin.create calls "
                                                          "serializer.is_valid(raise_exception=True) first"),
                   "perform_update": ("serializer_class", "rest_framework UpdateModelMixin.update calls "
                                                          "serializer.is_valid(raise_exception=True) first")}
MIDDLEWARE_METHODS = ["__call__", "__acall__", "process_request", "process_view", "process_response",
                      "process_exception", "process_template_response"]
# (v5 review fix) + Django's AuthenticationForm.confirm_login_allowed (called by its clean())
FORM_VALIDATION_METHODS_PREFIX = ("clean", "validate", "confirm_login_allowed")
# calls on a form/serializer instance that make the framework run its clean*/validate* methods
VALIDATION_TRIGGERS = ("is_valid", "full_clean", "errors")

LIBRARY_BACKEND_FACTORS = {
    "django.contrib.auth.backends.ModelBackend": "password",
    "django.contrib.auth.backends.AllowAllUsersModelBackend": "password",
    "django.contrib.auth.backends.RemoteUserBackend": "remote_user_external",
    "django.contrib.auth.backends.AllowAllUsersRemoteUserBackend": "remote_user_external",
    "allauth.account.auth_backends.AuthenticationBackend": "password",
    "sesame.backends.ModelBackend": "magic_link_possession",
    "oauth2_provider.backends.OAuth2Backend": "oauth_bearer_token",
    "mozilla_django_oidc.auth.OIDCAuthenticationBackend": "idp_assertion",
    "guardian.backends.ObjectPermissionBackend": None,  # never authenticates (catalog note)
}

# (v5, R7) settings groups (one lock entry each) and per-path setting dependencies
RF_AUTH_KEYS = {"DEFAULT_AUTHENTICATION_CLASSES", "DEFAULT_PERMISSION_CLASSES", "UNAUTHENTICATED_USER",
                "UNAUTHENTICATED_TOKEN", "DEFAULT_THROTTLE_CLASSES", "DEFAULT_THROTTLE_RATES"}
CORE_AUTH_SETTINGS = ["AUTH_USER_MODEL", "SESSION_ENGINE", "SECRET_KEY_FALLBACKS",
                      # (v5 review fix) Django's own session-credential and password-hashing settings (lifetimes,
                      # serializer, cookie flags; the project classes they name are sources of the group)
                      "PASSWORD_HASHERS", "SESSION_SERIALIZER", "SESSION_COOKIE_AGE", "SESSION_EXPIRE_AT_BROWSER_CLOSE",
                      "SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SAMESITE",
                      "SESSION_COOKIE_DOMAIN", "SESSION_COOKIE_NAME", "SESSION_COOKIE_PATH", "SESSION_SAVE_EVERY_REQUEST",
                      "SESSION_CACHE_ALIAS", "SESSION_FILE_PATH"]
# settings of CORE_AUTH_SETTINGS that name project code (dotted class paths or a module)
CORE_AUTH_CODE_SETTINGS = ["PASSWORD_HASHERS", "SESSION_ENGINE", "SESSION_SERIALIZER"]
AUTHENTICATE_CALLS = {"django.contrib.auth.authenticate", "django.contrib.auth.aauthenticate"}
# catalog form / serializer checks whose validation calls authenticate() (overlay FORM_CHECKS with factor password)
AUTHENTICATING_FORM_REFS = {d["ref"] for d in overlay.FORM_CHECKS if d["factor"] == "password"}

# Mint leaf names that are too common to flag when the receiver is unknown
# (observed collisions: admin ChangeList.get_query_string, smtplib login, signer.sign_object).
AMBIGUOUS_MINT_LEAVES = {"login", "alogin", "get_query_string", "get_parameters", "get_token", "get_user", "create",
                         "sign", "sign_object", "dumps", "encode", "save", "generate_key", "access_token"}

RELATION_RANK = {"guards_mint": 4, "guards_mint_assert_only": 3, "present_unproven": 2,
                 "condition_always_truthy": 1, "result_ignored": 1, "absent": 0}

# ---- verification-looking calls that are not recognised checks ("unrecognized checks") ----
# A call whose last name component (leading underscores stripped, lower-cased) matches this
# pattern looks like a verification step.  When it is not a catalog check, MintMap treats it as a
# *provisional* check (factor `unrecognized:<callee>`, return semantics unknown), so that it is
# traced through project wrappers and forms like a real check, reported as an
# `unrecognized_check_call` gap on every path where it appears, and fingerprinted.
VERIFY_LIKE_RE = re.compile(r"^(verify|check_|validate|authenticate|confirm(_|$))|_verify$|"
                            r"^(compare_digest|constant_time_compare|bytes_eq|strings_equal)$")
# framework validation plumbing (not verification of a credential); is_valid is modelled separately
NOT_VERIFY_LEAVES = {"validate_unique", "validate_constraints", "full_clean", "clean_fields", "run_validators",
                     "is_valid"}
UNRECOGNIZED_PREFIX = "unrecognized:"
# how many project wrapper levels an unrecognized leaf is propagated through (0 = only direct calls)
UNRECOGNIZED_WRAPPER_DEPTH = 2


import sys as _sys

STDLIB_TOP = set(getattr(_sys, "stdlib_module_names", ())) | {"builtins", "object"}


# (v5) decorators that only wrap transactions / caching / HTTP-method checks / sensitivity markers (Django's
# django/views/decorators/*, django/utils/decorators.py method_decorator, django/db/transaction.py atomic)
KNOWN_DECORATOR_PREFIXES = ("django.views.decorators.", "django.utils.decorators.", "django.db.transaction.",
                            "django.contrib.auth.decorators.", "django.contrib.admin.views.decorators.")


def app_module(app: str) -> str:
    """INSTALLED_APPS entry -> app module (`x.apps.XConfig` -> `x`, `django.contrib.auth` unchanged)."""
    parts = app.split(".")
    if len(parts) > 1 and parts[-1][:1].isupper():
        parts = parts[:-1]
        if len(parts) > 1 and parts[-1] == "apps":
            parts = parts[:-1]
    return ".".join(parts)


def verification_like(leaf: str) -> bool:
    n = leaf.lstrip("_").lower()
    return bool(n) and n not in NOT_VERIFY_LEAVES and bool(VERIFY_LIKE_RE.search(n))


def is_unrecognized_factor(f: str) -> bool:
    return f.startswith(UNRECOGNIZED_PREFIX)


def all_unrecognized(factor: str) -> bool:
    parts = [x for x in factor.split("+") if x]
    return bool(parts) and all(is_unrecognized_factor(x) for x in parts)


@dataclass
class CheckDesc:
    symbol: str
    ref: str | None
    factor: str
    ret: str                     # bool | subject_or_none | raises | tuple
    subject: object              # 'return' | 'arg0' | 'arg1' | 'receiver' | 'form' | ('param', i, name) | None
    via: str                     # catalog | method_name | constructor | form | wrapper | framework
    faithful: bool = True
    detail: str = ""
    form_var: str | None = None
    project_funcs: list = field(default_factory=list)   # project code implementing the check (fingerprint)
    unrecognized: list = field(default_factory=list)    # [leaf dict] verification-looking calls behind it
    urec_depth: int = 0                                 # project wrapper levels above the unrecognized leaf
    config_src: list = field(default_factory=list)      # (v4) statements that configure the check (fingerprint)
    arg_gaps: list = field(default_factory=list)        # (v4) [Gap] arguments MintMap could not evaluate

    @property
    def urec_only(self) -> bool:
        return all_unrecognized(self.factor)


@dataclass
class WrapperSummary:
    func: str
    kind: str                    # bool | raises | unfaithful
    factors: list
    checks: list                 # [CheckDesc]
    subject: object
    detail: str = ""
    unrecognized: list = field(default_factory=list)
    urec_depth: int = 0
    config_src: list = field(default_factory=list)
    arg_gaps: list = field(default_factory=list)


@dataclass
class Entry:
    id: str
    kind: str                    # route | middleware | drf_auth_class | unrouted
    view: str
    route: Route | None = None
    funcs: list = field(default_factory=list)          # [(func_qn, ctx, role)]
    library_mints: list = field(default_factory=list)  # [(MintAPI, note)]
    notes: list = field(default_factory=list)
    gates: list = field(default_factory=list)
    ctx_class: str | None = None
    variants: list = field(default_factory=list)       # (v4) other occurrences of the route that run other code
    gaps: list = field(default_factory=list)           # (v5) gaps about this entry itself (every path of it)
    extra_code: list = field(default_factory=list)     # (v5 review fix) more code text hashed into `code`


class Analysis:
    def __init__(self, root: str, catalog: Catalog, excluded_dirs=None, fp_depth: int = 4, chain_limit: int = 16,
                 include_tests: bool = False, library_paths=None):
        self.catalog = catalog
        # (v5, R2) read-only library source (--library-path): resolves library aliases / re-exports / bases
        self.lib = LibrarySource(library_paths)
        self._admin_info = None
        self._settings_groups = None     # (v5, R7)
        self._hooks = None               # (v5, R5)
        self._settings_reads: dict = {}
        self.fp_depth = fp_depth
        self.chain_limit = chain_limit
        self.p = Project(root, excluded_dirs, library_bases=overlay.LIBRARY_BASES,
                         library_instances=overlay.LIBRARY_INSTANCES, library_returns=overlay.LIBRARY_RETURNS,
                         library_lacks=overlay.LIBRARY_CLASS_LACKS, include_tests=include_tests)
        self.cg = CallGraph(self.p, catalog)
        # (v5, R8) extract-function-insensitive function dumps (conservative inlining of extracted helpers)
        self.inliner = Inliner(self.p)
        # (v5, R3) custom credential generators (heuristic mints)
        self.cred = CredentialHeuristics(self)
        # (v6) candidate tier (candidates.py)
        self.candf = CandidateFinder(self)
        self._heur_memo: dict = {}
        self._heur_models: dict = {}     # (v5 review) heuristic mint symbol -> model with a credential default
        self.gaps: list[Gap] = list(self.p.gaps)
        prefixes = sorted({p for ps in overlay.PACKAGE_SETTING_PREFIXES.values() for p in ps})
        self.settings = extract_settings(self.p, prefixes)
        self.gaps += self.settings.gaps
        self._wrappers: dict = {}
        self._forms: dict = {}
        self._in_progress: set = set()
        self.lib_view_methods = {}
        for sym, d in catalog.library_views.items():
            for m in d.get("mint_methods", []):
                self.lib_view_methods[f"{sym}.{m}"] = d["refs"]
        self.distinctive_mint_leaves = {s.rsplit(".", 1)[-1] for s in catalog.mint_calls} - GENERIC_LEAVES \
            - AMBIGUOUS_MINT_LEAVES
        self.check_leaves = set(catalog.check_method_names) | {s.rsplit(".", 1)[-1] for s in catalog.check_calls}
        self.project_callable_names = {qn.rsplit(".", 1)[-1] for qn in self.p.functions} - GENERIC_LEAVES
        self._checks_memo: dict = {}
        self._derived = None
        self._as_view_memo: dict = {}        # id(call node) -> (class qualname, as_view Call) | None
        self._as_view_assigns: dict = {}     # function qualname -> {local name: as_view Call}
        self.dep_files, self.dep_specs = read_dependency_specs(self.p.root, self.p.excluded_dirs)
        self.backend_factor, self.backend_classes, self.backend_unrecognized = "pending", [], []
        self.backend_config, self.backend_arg_gaps = [], []
        self.backend_factor, self.backend_classes = self._backend_factor()
        self._wrappers.clear()
        self._forms.clear()
        self._checks_memo.clear()

    # ================================================================ oracles
    def mint_of(self, site: CallSite, res: Resolution) -> list:
        """[(MintAPI, purpose_note)] for a call site."""
        if site.is_property:
            if res.receiver_type:
                for c in self.p.mro(res.receiver_type):
                    api = self.catalog.property_mints.get((c, site.leaf))
                    if api:
                        return [(api, "")]
            return []
        out = []
        cands = res.library_candidates or ([res.library] if res.library else [])
        cands = cands + [fq for fq, _ in res.targets if fq in self.catalog.mint_calls]  # vendored copies
        note = ""
        if res.receiver_type and res.receiver_type in self.p.classes:
            note = (f"receiver is project class {res.receiver_type}; catalog purpose describes the library API, "
                    f"the project may use it for a different purpose")
        for c in cands:
            if c in self.catalog.mint_calls:
                api = self.catalog.mint_calls[c]
                if api.heuristic and api.ref is None and isinstance(site.node, ast.Call):
                    # (v6) a generic signing / JWT primitive: a mint only where its value is kept as a credential
                    # or it signs a principal identifier (credentials.signed_value_decision)
                    purpose, why = self.cred.signed_value_decision(site)
                    if purpose is None:
                        break
                    api = MintAPI(symbol=api.symbol, ref=None, purpose=api.purpose, purpose_basis=(
                        api.purpose_basis + f"; {why}"), kind=api.kind, user_arg=api.user_arg, heuristic=True)
                out.append((api, note))
                break
            if c in self.lib_view_methods:
                for ref in self.lib_view_methods[c]:
                    out.append((self.catalog.mint_for_ref(ref, "library_view_method", c), note))
                break
        if not out and res.library and self.lib.available and site.leaf in self.distinctive_mint_leaves:
            # (v5, R2) a library re-export / alias of a catalog mint (read in the library source)
            r = self.lib.resolve(res.library)
            if r and r.symbol != res.library and r.symbol in self.catalog.mint_calls:
                out.append((self.catalog.mint_calls[r.symbol], "; ".join(
                    x for x in (note, f"{res.library} resolves to {r.symbol} (library source: {r.trail[0]})") if x)))
        if not out:
            out = self.heuristic_mint(site, res)
        return out

    def heuristic_mint(self, site, res) -> list:
        """(v5, R3) a custom credential created without a catalog API (credentials.py): the randomness source call
        whose value is kept as a credential, or the creation of a model whose field default generates one."""
        key = id(site.node)
        if key in self._heur_memo:
            return self._heur_memo[key]
        out = []
        if isinstance(site.node, ast.Call):
            self.cred.run()
            c = self.cred.candidates.get(key)
            if c is not None:
                kept = "; ".join(sorted({x.detail for x in c.sinks}))[:400]
                out.append((heuristic_api(c.symbol, c.purpose,
                                          "heuristic: value of a randomness source kept as a credential (not a "
                                          "catalog API)"),
                            f"custom credential candidate ({c.symbol}): {kept}; names {', '.join(c.names)}"))
            else:
                hit = self.cred.creation_candidate(site, res, None)
                if hit is not None:
                    model, how, fields = hit
                    sym = f"{model}.objects.{how}" if how in CREATE_METHODS else (
                        model if how == "constructor" else f"{model} via {how}")
                    purpose = fields[0][2]
                    self._heur_models[sym] = model
                    out.append((heuristic_api(sym, purpose, "heuristic: creates a model whose field default "
                                                            "generates a credential (not a catalog API)"),
                                "creates " + model + ": " + ", ".join(f"{f} = default {g}()" for f, g, _ in fields)))
                else:
                    lib = self.library_credential_creation(site, res)
                    if lib is not None:
                        out.append(lib)
        self._heur_memo[key] = out
        return out

    def extra_mint_sites(self, fq) -> list:
        """(v5 review) Mint sites that are statements, not calls: `request.session[K] = v` where K is a session key
        that project code (or Django: `_auth_user_id`) uses to load a principal (CredentialHeuristics
        .auth_session_keys).  [(pseudo call site, MintAPI, note)]"""
        memo = self.__dict__.setdefault("_extra_sites", {})
        if fq in memo:
            return memo[fq]
        out = []
        if fq in self.p.functions:
            for st, key, consumers in self.cred.session_login_stores(fq):
                site = CallSite(func=fq, node=st, line=st.lineno, text=f"session[{key!r}] = ...",
                                leaf="session_store")
                api = heuristic_api(f"session[{key}]", "custom_session_login_candidate",
                                    "heuristic: writes a session key that project code (or Django) uses to "
                                    "authenticate a principal (not a catalog API)")
                out.append((site, api, f"hand-rolled session login: {key!r} is read back by "
                                       f"{', '.join(consumers[:3])} to load the principal"))
        memo[fq] = out
        return out

    def library_credential_creation(self, site, res):
        """(v5 review) A call into a package the catalog does not describe that creates a credential record or
        issues a key: `<Model>.objects.create/get_or_create/create_key/...` on a library model named after a
        credential (APIKey, AccessToken, ...; head noun of the class name), or a library function named
        create_*/issue_*/new_*/make_*/mint_* + a credential word.  Heuristic mint (`custom_library_credential_
        candidate`); catalogued packages are covered by the catalog (and library_call_may_mint)."""
        lib = res.library or ""
        top = lib.split(".")[0]
        if not lib or top in overlay.CATALOG_PACKAGES or top in STDLIB_TOP or \
                (res.receiver_type and res.receiver_type in self.p.classes):
            return None
        parts = lib.split(".")
        leaf = parts[-1]
        from .credentials import words as _w, POSITIVE as _POS, _head as _hd
        if len(parts) >= 3 and parts[-2] in MANAGER_ATTRS:
            cls = parts[-3]
            if (leaf in CREATE_METHODS or leaf.startswith("create")) and _hd(cls) in _POS:
                return (heuristic_api(lib, "custom_library_credential_candidate",
                                      "heuristic: creates a record of a library credential model the catalog does "
                                      "not describe"), f"library model {'.'.join(parts[:-2])} (credential-named)")
            return None
        lw = _w(leaf)
        if lw & {"create", "issue", "new", "make", "mint", "generate", "obtain", "rotate", "regenerate"} and \
                _hd(leaf) in _POS and not lw & {"id", "uuid", "name", "slug"}:
            return (heuristic_api(lib, "custom_library_credential_candidate",
                                  "heuristic: a library function the catalog does not describe that creates a "
                                  "credential"), f"library call {lib}")
        return None

    def possible_library_mint(self, site, res) -> bool:
        """(v5, R2) a resolved call into a catalogued package whose name is a catalog mint name but whose symbol
        the catalog does not map (e.g. a library wrapper of a mint): it may mint; reported as a gap."""
        if res.receiver_type and res.receiver_type in self.p.classes:
            return False   # a method on a project object: not a library call
        if (res.library or "").startswith("django.db.") or site.leaf in self.project_callable_names:
            # an ORM model/manager guess (`Profile.objects.for_user(...)` with a project manager) or a name the
            # project defines itself: the unresolved-project-call gaps cover these
            return False
        return bool(res.library) and site.leaf in self.distinctive_mint_leaves and \
            res.library.split(".")[0] in overlay.CATALOG_PACKAGES and res.library not in self.catalog.mint_calls

    def check_of(self, site: CallSite, res: Resolution, ctx) -> CheckDesc | None:
        if site.is_property:
            return None
        node = site.node
        cands = res.library_candidates or ([res.library] if res.library else [])
        cands = cands + [fq for fq, _ in res.targets if fq in self.catalog.check_calls]  # vendored copies
        for c in cands:
            api = self.catalog.check_calls.get(c)
            if api:
                factor = api.factor
                is_auth = c in ("django.contrib.auth.authenticate", "django.contrib.auth.aauthenticate")
                if is_auth:
                    factor = self.backend_factor
                off, unknown, config, gaps = "", [], [], []
                if api.disabled_if:
                    off, unknown, config = check_switches(self.p, site, api.disabled_if, site.func)
                    if unknown and not off:
                        off = (f"verification options not statically known ({'; '.join(unknown)}): the call may "
                               f"switch verification off")
                        gaps = [Gap("check_argument_not_static", self.p.file_of(site.func), site.func,
                                    f"{api.symbol}: {'; '.join(unknown)}", site.line)]
                if is_auth:
                    config, gaps = config + list(self.backend_config), gaps + list(self.backend_arg_gaps)
                return CheckDesc(api.symbol, api.ref, factor, api.ret, api.subject, "catalog",
                                 faithful=not off, detail=off,
                                 project_funcs=list(self.backend_classes) if is_auth else [],
                                 unrecognized=list(self.backend_unrecognized) if is_auth else [],
                                 config_src=config, arg_gaps=gaps)
        if res.instantiates and res.instantiates in self.catalog.check_constructors and (node.args or node.keywords):
            api = self.catalog.check_constructors[res.instantiates]
            return CheckDesc(api.symbol, api.ref, api.factor, api.ret, api.subject, "constructor")
        form_type = res.receiver_type
        if site.leaf == "is_valid" and not form_type:
            cands = self.form_types_for(site, res, ctx)
            form_type = cands[0] if len(cands) == 1 else None
        if site.leaf == "is_valid" and form_type:
            fc = self.form_check(form_type)
            if fc:
                raises = any(k.arg == "raise_exception" and isinstance(k.value, ast.Constant) and k.value.value
                             for k in node.keywords)
                return CheckDesc(form_type + ".is_valid", fc.ref, "+".join(fc.factors),
                                 "raises" if raises else "bool", "form", "form", fc.faithful, fc.detail,
                                 form_var=res.receiver_var, project_funcs=fc.project_funcs,
                                 unrecognized=fc.unrecognized, urec_depth=fc.urec_depth,
                                 config_src=fc.config_src, arg_gaps=fc.arg_gaps)
        for fq, fctx in res.targets:
            s = self.wrapper_summary(fq, fctx)
            if s:
                ret = "raises" if s.kind == "raises" else "bool"
                return CheckDesc(fq, None, "+".join(s.factors) or "unknown", ret, s.subject, "wrapper",
                                 s.kind != "unfaithful", s.detail, project_funcs=[fq],
                                 unrecognized=s.unrecognized, urec_depth=s.urec_depth,
                                 config_src=s.config_src, arg_gaps=s.arg_gaps)
        if not res.targets and site.leaf in self.catalog.check_method_names:
            api = self.catalog.check_method_names[site.leaf]
            return CheckDesc(api.symbol, api.ref, api.factor, api.ret, api.subject, "method_name",
                             detail="matched by method name only (receiver type unknown)")
        return self.unrecognized_check(site, res, cands)

    def unrecognized_check(self, site, res, cands) -> CheckDesc | None:
        """A verification-looking call that is not a recognised check: a library or unresolved
        callee, or a project function that contains no check MintMap can see."""
        if not verification_like(site.leaf) or site.leaf[:1].isupper() or res.instantiates:
            return None
        if any(c.startswith(p) for c in cands for p in self.catalog.non_check_prefixes):
            return None   # catalog v2 non_check_apis (format validators, password-strength policy)
        if res.via == "super" and site.func.rsplit(".", 1)[-1] == site.leaf:
            return None   # super().validate(...) inside validate(): delegation to the library default
        if self.mint_of(site, res):
            return None
        if any(t in self.mint_reaching() for t, _ in res.targets):
            return None   # a project function that leads to a mint is a mint wrapper (traced as such), not a check
        if res.targets:
            callee = res.targets[0][0]
            target, kind = callee, "project function containing no check MintMap recognises"
            funcs = [t for t, _ in res.targets]
        elif res.library:
            target, kind, funcs = res.library, "library callable not in the catalog", []
        else:
            target, kind, funcs = "?." + site.leaf, "callee could not be resolved", []
        leaf = dict(function=site.func, line=site.line, call=site.text, target=target, reason=kind)
        return CheckDesc(site.text, None, UNRECOGNIZED_PREFIX + target, "unknown", None, "unrecognized",
                         detail=f"verification-looking call `{site.text}` ({kind}: {target}); MintMap does not "
                                f"know what it verifies or how it reports failure",
                         project_funcs=funcs, unrecognized=[leaf], urec_depth=0)

    def function_checks(self, func_qn, ctx) -> list:
        key = (func_qn, ctx)
        if key in self._checks_memo:
            return self._checks_memo[key]
        out = []
        for site in self.cg.sites(func_qn):
            res = self.cg.resolve(site, ctx)
            d = self.check_of(site, res, ctx)
            if d:
                out.append((site, d))
        if not self._in_progress:  # results computed under a recursion guard may be partial
            self._checks_memo[key] = out
        return out

    def analyzer(self, func_qn, checks) -> GuardAnalyzer:
        by_id = {id(s.node): d for s, d in checks}

        def is_raising(call):
            d = by_id.get(id(call))
            if d is None or not d.faithful:
                return False
            return d.ret == "raises" or (d.ret == "unknown" and an.expected_to_raise(call))
        an = GuardAnalyzer(self.p.functions[func_qn].node, is_raising)
        return an

    def wrapper_summary(self, func_qn, ctx) -> WrapperSummary | None:
        key = (func_qn, ctx)
        if key in self._wrappers:
            return self._wrappers[key]
        if key in self._in_progress:
            return None
        self._in_progress.add(key)
        try:
            summary = self._compute_wrapper(func_qn, ctx)
        finally:
            self._in_progress.discard(key)
        self._wrappers[key] = summary
        return summary

    def _compute_wrapper(self, func_qn, ctx, recognised_only=False) -> WrapperSummary | None:
        """Classify a project function as a check wrapper.  `recognised_only` (v4): ignore unrecognized
        verification-looking calls, i.e. ask whether the function's success depends on RECOGNISED checks."""
        checks = [(s, d) for s, d in self.function_checks(func_qn, ctx)
                  if not (d.urec_only and d.urec_depth >= UNRECOGNIZED_WRAPPER_DEPTH)
                  and not (recognised_only and d.urec_only)]
        if not checks:
            return None
        info = self.p.functions[func_qn]
        an = self.analyzer(func_qn, checks)
        returns = [n for n in self.p.walk_function_body(info.node) if isinstance(n, ast.Return)]
        used: dict = {}
        unguarded, guarded_exits, falsy_exits = [], 0, 0
        for r in returns:
            v = r.value
            if v is None or (isinstance(v, ast.Constant) and not v.value):
                falsy_exits += 1
                ok = [d for s, d in checks if an.classify(s.node, d.ret, r)[0] == "guards_mint" and d.faithful]
                if ok:
                    guarded_exits += 1
                continue
            keys = an.closure(RT(v), r.lineno)
            prop = [(s, d) for s, d in checks if call_key(s.node) in keys and d.faithful]
            if prop:
                for s, d in prop:
                    used[id(s.node)] = (s, d)
                guarded_exits += 1
                continue
            ok = [(s, d) for s, d in checks if an.classify(s.node, d.ret, r)[0] == "guards_mint" and d.faithful]
            if ok:
                for s, d in ok:
                    used[id(s.node)] = (s, d)
                guarded_exits += 1
            else:
                unguarded.append(r)
        end_reachable = not always_exits(info.node.body)
        end_guarded = False
        if end_reachable:
            ok = [(s, d) for s, d in checks if an.classify(s.node, d.ret, None)[0] == "guards_mint" and d.faithful]
            end_guarded = bool(ok)
            for s, d in ok:
                used[id(s.node)] = (s, d)
        all_exits_guarded = guarded_exits == len(returns) and (not end_reachable or end_guarded)
        if all_exits_guarded and used:
            kind = "raises"
        elif not unguarded and used:
            kind = "bool"
        else:
            kind = "unfaithful"
        used_list = list(used.values())
        factors = sorted({d.factor for _, d in used_list}) if used_list else sorted({d.factor for _, d in checks})
        subject = None
        params = [a for a in info.params]
        if info.cls and params and params[0] in ("self", "cls"):
            params = params[1:]
        for s, d in used_list:
            name = subject_name(s.node, d, an)
            if name and name.split(".")[0] in params:
                root = name.split(".")[0]
                subject = ("param", params.index(root), root)
                break
            if d.subject == "return" and name and any(isinstance(r.value, ast.Name) and r.value.id == name
                                                      for r in returns):
                subject = "return"
                break
        detail = ""
        if kind == "unfaithful":
            detail = (f"project wrapper {func_qn} calls {', '.join(sorted({d.symbol for _, d in checks}))} "
                      f"but can return success without the check succeeding")
            inner = sorted({d.detail for _, d in checks if not d.faithful and d.detail})
            if inner:
                detail += " (" + "; ".join(inner) + ")"
        depth = 0
        if all(d.urec_only for _, d in checks):
            if kind == "unfaithful":
                # the function's outcome does not depend on the verification-looking call(s): with no
                # recognised check involved, the name alone is too weak to call this a wrapper
                return None
            depth = 1 + min((d.urec_depth for _, d in checks if d.urec_only), default=0)
        leaves = _merge_leaves(d.unrecognized for _, d in checks)
        return WrapperSummary(func_qn, kind, factors, [d for _, d in checks], subject, detail, leaves, depth,
                              config_src=sorted({c for _, d in checks for c in d.config_src}),
                              arg_gaps=_merge_gaps(d.arg_gaps for _, d in checks))

    @dataclass
    class FormCheck:
        factors: list
        ref: str | None
        faithful: bool
        detail: str
        project_funcs: list
        unrecognized: list = field(default_factory=list)
        urec_depth: int = 0
        config_src: list = field(default_factory=list)
        arg_gaps: list = field(default_factory=list)

    def form_check(self, cls_qn) -> "Analysis.FormCheck | None":
        if cls_qn in self._forms:
            return self._forms[cls_qn]
        self._forms[cls_qn] = None  # recursion guard
        factors, refs, details, funcs, weak, leaves, depths = [], [], [], [], [], [], []
        config, arg_gaps = set(), []
        mro = self.p.mro(cls_qn)
        for c in mro:
            if c in self.catalog.form_checks:
                fc = self.catalog.form_checks[c]
                r = self.p.lookup_method(cls_qn, fc["method"])
                if r is None or r[0] == "library":
                    factors.append(fc["factor"])
                    refs.append(fc["ref"])
                elif self._calls_super(r[1], fc["method"]):
                    factors.append(fc["factor"])
                    refs.append(fc["ref"])
                    funcs.append(r[1])
                else:
                    details.append(f"{r[1]} overrides {c}.{fc['method']} without super(): library check lost")
        for c in mro:
            if c not in self.p.classes:
                continue
            for name, mq in sorted(self.p.classes[c].methods.items()):
                if name.startswith(FORM_VALIDATION_METHODS_PREFIX):
                    s = self.wrapper_summary(mq, cls_qn)
                    if s:
                        leaves.append(s.unrecognized)
                        config |= set(s.config_src)
                        arg_gaps.append(s.arg_gaps)
                        if all(all_unrecognized(f) for f in s.factors):
                            depths.append(s.urec_depth)
                    if s and s.kind == "raises":
                        factors.extend(s.factors)
                        funcs.append(mq)
                    elif s:
                        details.append(f"{mq}: check present but does not raise on failure ({s.kind})")
                        weak.extend(s.factors)
                        funcs.append(mq)
        result = None
        if factors or details:
            # a form whose only checks do not raise keeps their factor names (e.g. unrecognized:...) so the
            # evidence still says which check is involved; it is not faithful
            result = Analysis.FormCheck(sorted(set(factors)) or sorted(set(weak)) or ["none"],
                                        refs[0] if refs else None, bool(factors), "; ".join(details),
                                        sorted(set(funcs)), _merge_leaves(leaves),
                                        min(depths) if depths and not refs else 0, sorted(config),
                                        _merge_gaps(arg_gaps))
        self._forms[cls_qn] = result
        return result

    def _calls_super(self, func_qn, method) -> bool:
        for n in self.p.walk_function_body(self.p.functions[func_qn].node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == method and \
                    isinstance(n.func.value, ast.Call) and isinstance(n.func.value.func, ast.Name) and \
                    n.func.value.func.id == "super":
                return True
        return False

    def _backend_factor(self):
        backends = self.settings.str_list("AUTHENTICATION_BACKENDS")
        if "AUTHENTICATION_BACKENDS" in self.settings.defaulted or not self.settings.modules:
            backends = ["django.contrib.auth.backends.ModelBackend"]
        factors, classes = set(), []
        for b in backends:
            q = self.p.canonical(b)
            if q in self.p.classes:
                classes.append(q)
                r = self.p.lookup_method(q, "authenticate")
                s = self.wrapper_summary(r[1], q) if r and r[0] == "project" else None
                if s:
                    self.backend_unrecognized = _merge_leaves([self.backend_unrecognized, s.unrecognized])
                    self.backend_config = sorted(set(self.backend_config) | set(s.config_src))
                    self.backend_arg_gaps = _merge_gaps([self.backend_arg_gaps, s.arg_gaps])
                if r and r[0] == "library":
                    factors.add(LIBRARY_BACKEND_FACTORS.get(r[1].rsplit(".", 1)[0], f"library_backend:{r[1]}") or
                                "none")
                else:
                    # (v4) judged on RECOGNISED checks only: verified when every success exit depends on a
                    # recognised check (extra unrecognized calls, e.g. an IP allow-list helper, are reported
                    # as unrecognized_check_call gaps but do not hide the password check); unverified when
                    # some success exit relies only on unrecognized calls or on nothing
                    rs = self._compute_wrapper(r[1], q, recognised_only=True) if s else None
                    if rs and rs.kind != "unfaithful":
                        for f in rs.factors:
                            parts = [x for x in f.split("+") if not is_unrecognized_factor(x)]
                            factors.add("+".join(parts) or f"unverified_project_backend:{q}")
                    else:
                        factors.add(f"unverified_project_backend:{q}")
            elif q in LIBRARY_BACKEND_FACTORS:
                if LIBRARY_BACKEND_FACTORS[q]:
                    factors.add(LIBRARY_BACKEND_FACTORS[q])
            elif q.split(".")[0] in ("social_core",):
                factors.add("idp_assertion")
            else:
                factors.add(f"unknown_backend:{q}")
        if self.settings.dynamic_items("AUTHENTICATION_BACKENDS"):
            factors.add("dynamic_backend")
        return "|".join(sorted(factors)) or "none", classes

    # ================================================================ entries
    def resolve_dotted(self, dotted: str) -> str:
        return self.p.canonical(dotted)

    def _decorator_names(self, func_qn) -> list:
        info = self.p.functions[func_qn]
        out = []
        for d in info.node.decorator_list:
            dn = d.func if isinstance(d, ast.Call) else d
            q = self.p.resolve_expr_static(info.module, dn)
            out.append(self.p.canonical(q) if q else stable_unparse(dn))
        return out

    def class_entry_funcs(self, cls_qn, actions=None, viewset=False) -> list:
        funcs = []
        seen = set()

        def add(name, role):
            r = self.p.lookup_method(cls_qn, name)
            if r and r[0] == "project" and r[1] not in seen:
                seen.add(r[1])
                funcs.append((r[1], cls_qn, role))

        verbs = list(HTTP_VERBS)
        if viewset:
            acts = list(actions.values()) if actions else VIEWSET_ACTIONS + sorted(
                a for c in self.p.mro(cls_qn) if c in self.p.classes for a in self.p.classes[c].decorated_actions)
            verbs = acts + ([] if actions else [])
        for v in verbs:
            add(v, "http_handler")
        for v in ALWAYS_DISPATCHED:
            add(v, "http_handler")
        for hook, dispatchers in HOOK_DISPATCHERS.items():
            for d in dispatchers:
                r = self.p.lookup_method(cls_qn, d)
                if r and r[0] == "library" and (not viewset or d in verbs or d in HTTP_VERBS):
                    add(hook, "framework_hook")
                    break
        # (v5, R3) DRF CreateModelMixin.create / UpdateModelMixin.update (library) -> perform_create/update
        # (library unless the project overrides it, then it is a hook above) -> serializer.save() -> the project
        # serializer's create/update/save -> the model's save
        if any(c.startswith("rest_framework.") for c in self.p.mro(cls_qn)):
            ser = self.cg.class_attr_type(cls_qn, "serializer_class")
            for verb, perform in (("create", "perform_create"), ("update", "perform_update")):
                r = self.p.lookup_method(cls_qn, verb)
                pr = self.p.lookup_method(cls_qn, perform)
                if not (r and r[0] == "library") or (viewset and actions and verb not in actions.values()):
                    continue
                if pr and pr[0] == "project":
                    continue
                if ser in self.p.classes:
                    for m in ("save", verb):
                        rr = self.p.lookup_method(ser, m)
                        if rr and rr[0] == "project" and rr[1] not in seen:
                            seen.add(rr[1])
                            funcs.append((rr[1], ser, "framework_hook"))
                    rr = self.p.lookup_method(ser, verb)
                    model = self.cred.model_meta(ser)
                    if not (rr and rr[0] == "project") and model:
                        ms = self.p.lookup_method(model, "save")
                        if ms and ms[0] == "project" and ms[1] not in seen:
                            seen.add(ms[1])
                            funcs.append((ms[1], model, "framework_hook"))
        return funcs

    def drf_library_creation_mints(self, cls_qn, actions=None, viewset=False) -> list:
        """(v5, R3) the DRF create flow of a view creates its serializer's Meta.model in library code (no project
        create/perform_create): a model whose field default generates a credential is a library-provided mint."""
        if not any(c.startswith("rest_framework.") for c in self.p.mro(cls_qn)):
            return []
        r = self.p.lookup_method(cls_qn, "create")
        pr = self.p.lookup_method(cls_qn, "perform_create")
        if not (r and r[0] == "library") or (pr and pr[0] == "project") or \
                (viewset and actions and "create" not in actions.values()):
            return []
        ser = self.cg.class_attr_type(cls_qn, "serializer_class")
        if ser not in self.p.classes:
            return []
        sc = self.p.lookup_method(ser, "create")
        if sc and sc[0] == "project":
            return []
        self.cred.run()
        model = self.cred.model_meta(ser)
        if model not in self.cred.default_models:
            return []
        fields = self.cred.default_models[model]
        self._heur_models[f"{model} via rest_framework create"] = model
        api = heuristic_api(f"{model} via rest_framework create", fields[0][2],
                            "heuristic: the DRF create flow creates a model whose field default generates a "
                            "credential (not a catalog API)")
        return [(api, f"{cls_qn}.create (library) saves {ser} -> creates {model}: " +
                 ", ".join(f"{f} = default {g}()" for f, g, _ in fields))]

    DJANGO_CREATE_VIEWS = ("django.views.generic.CreateView", "django.views.generic.edit.CreateView",
                           "django.views.generic.edit.BaseCreateView")

    def django_create_view_mints(self, cls_qn) -> list:
        """(v6) Django's generic CreateView saves its ModelForm in library code (ModelFormMixin.form_valid:
        `self.object = form.save()`): when the created model (the view's `model`, or the form's Meta.model) has a
        field default that generates a credential, the route mints it, unless the project replaces form_valid
        without calling super() (then the project code is analysed instead)."""
        mro = self.p.mro(cls_qn)
        if not any(c in self.DJANGO_CREATE_VIEWS for c in mro):
            return []
        r = self.p.lookup_method(cls_qn, "form_valid")
        if r and r[0] == "project" and not self._calls_super(r[1], "form_valid"):
            return []
        self.cred.run()
        model = None
        _c, mv = self.p.class_attr(cls_qn, "model")
        if mv is not None and isinstance(mv, (ast.Name, ast.Attribute)):
            q = self.p.resolve_expr_static(self.p.classes[_c].module, mv)
            model = self.p.canonical(q) if q else None
        if model not in self.cred.default_models:
            form = self.cg.class_attr_type(cls_qn, "form_class")
            model = self.cred.model_meta(form) if form in self.p.classes else model
        if model not in self.cred.default_models:
            return []
        fields = self.cred.default_models[model]
        sym = f"{model} via django CreateView"
        self._heur_models[sym] = model
        api = heuristic_api(sym, fields[0][2], "heuristic: Django's CreateView saves a model whose field default "
                                               "generates a credential (not a catalog API)")
        return [(api, f"{cls_qn} (CreateView) saves its form -> creates {model}: " +
                 ", ".join(f"{f} = default {g}()" for f, g, _ in fields))]

    def inherited_library_mints(self, cls_qn, as_view_kwargs) -> tuple[list, list]:
        mints, notes = [], []
        for c in self.p.mro(cls_qn):
            d = self.catalog.library_views.get(c)
            if not d:
                continue
            ok, note = self._requires_attr(d, cls_qn, as_view_kwargs)
            if note:
                notes.append(note)
            if not ok:
                break
            methods = d.get("mint_methods") or []
            overridden = [m for m in methods if (self.p.lookup_method(cls_qn, m) or ("", ""))[0] == "project"]
            if methods and len(overridden) == len(methods):
                calls_super = [m for m in overridden if self._calls_super(self.p.lookup_method(cls_qn, m)[1], m)]
                if not calls_super:
                    notes.append(f"{cls_qn} overrides {c} mint method(s) {overridden} without super(): "
                                 f"library mint not assumed")
                # if super() is called, the mint is found as a project call site
                break
            for ref in d["refs"]:
                mints.append((self.catalog.mint_for_ref(ref, "library_view", c),
                              f"inherited from {c}" if c != cls_qn else ""))
            break
        return mints, notes

    def _requires_attr(self, d, cls_qn, as_view_kwargs):
        req = d.get("requires_attr")
        if not req:
            return True, ""
        attr, want = req
        expr = as_view_kwargs.get(attr)
        if expr is None and cls_qn:
            _, expr = self.p.class_attr(cls_qn, attr)
        if expr is None:
            return False, f"{d['symbol']}: {attr} not set (library default) -> no mint"
        if isinstance(expr, ast.Constant):
            return expr.value == want, f"{d['symbol']}: {attr}={expr.value!r}"
        self.gaps.append(Gap("dynamic_view_attribute", "-", d["symbol"], f"{attr}={stable_unparse(expr)}"))
        return True, f"{d['symbol']}: {attr} is not a literal; mint assumed"

    def build_entries(self, routes) -> list:
        entries = []
        # one entry per id (the same pattern+view can be reached through two roots, two includes or two
        # branches of an if/else).  (v4) Occurrences that differ in what they run (URLconf wrappers such as a
        # project decorator, as_view() arguments, ViewSet actions, a dispatcher) are all kept as VARIANTS of
        # the entry: their functions and library mints are combined, a gate counts only if every variant
        # has it, every variant's gaps are reported and every variant's route code is fingerprinted.  The
        # displayed route (and its shadowing) is the occurrence that is not shadowed and not conditional
        # if there is one.
        groups: dict = {}
        for r in routes:
            groups.setdefault(f"route:{r.pattern}|{r.target}", []).append(r)
        for eid, rs in groups.items():
            chosen = min(rs, key=lambda r: (bool(r.shadowed_by), bool(r.may_be_shadowed_by), r.conditional))
            variants, seen = [], {self._variant_key(chosen)}
            for r in rs:
                k = self._variant_key(r)
                if k not in seen:
                    seen.add(k)
                    variants.append(r)
            e = Entry(id=eid, kind="route", view=chosen.target, route=chosen, variants=variants)
            r = chosen
            if r.shadowed_by:
                sb = r.shadowed_by
                e.notes.append(f"shadowed: the earlier pattern {sb['pattern']!r} -> {sb['target']} "
                               f"({sb['file']}:{sb['line']}) matches the same literal path first; Django never "
                               f"dispatches this route (first match wins)")
            elif r.may_be_shadowed_by:
                sb = r.may_be_shadowed_by
                e.notes.append(f"may be shadowed: the earlier conditional pattern {sb['pattern']!r} -> "
                               f"{sb['target']} ({sb['file']}:{sb['line']}) matches the same literal path first "
                               f"when its condition holds")
            gate_sets = []
            for v in [chosen] + variants:
                part = self._route_parts(v)
                for f in part.funcs:
                    if f not in e.funcs:
                        e.funcs.append(f)
                for m in part.library_mints:
                    if all((m[0].symbol, m[0].ref) != (x[0].symbol, x[0].ref) for x in e.library_mints):
                        e.library_mints.append(m)
                for n in part.notes:
                    if n not in e.notes:
                        e.notes.append(n)
                e.ctx_class = e.ctx_class or part.ctx_class
                for g in part.gaps:
                    if all(g.key != x.key for x in e.gaps):
                        e.gaps.append(g)
                for c in part.extra_code:
                    if c not in e.extra_code:
                        e.extra_code.append(c)
                gate_sets.append(part.gates)
            e.gates = [g for g in gate_sets[0] if all(g in gs for gs in gate_sets[1:])]
            if variants:
                dropped = sorted({g for gs in gate_sets for g in gs} - set(e.gates))
                e.notes.append(f"{len(variants) + 1} route definitions with this pattern and view run different "
                               f"code (URLconf wrappers, as_view() arguments, actions or dispatchers): the entry "
                               f"combines them" + (f"; gate(s) {dropped} are not on every definition and are not "
                                                   f"counted" if dropped else ""))
            if e.library_mints and e.route is not None and e.route.kind in ("library_view", "library_include",
                                                                             "admin_site"):
                # (v5, R5) a library flow runs the project hooks its settings name (adapters, token strategies,
                # pipeline functions ...): a mint inside a hook is linked to the library routes that call it
                for f in self.hook_entry_funcs({m.symbol.split(".")[0] for m, _ in e.library_mints}):
                    if f not in e.funcs:
                        e.funcs.append(f)
            if e.funcs or e.library_mints:
                entries.append(e)
        # middleware
        for mw in self.settings.str_list("MIDDLEWARE") + self.settings.str_list("MIDDLEWARE_CLASSES"):
            q = self.resolve_dotted(mw)
            e = Entry(id=f"middleware:{mw}", kind="middleware", view=q)
            if q in self.catalog.library_middleware:
                e.library_mints += [(m, "runs on every request") for m in self.catalog.library_middleware[q]]
            elif q in self.p.classes:
                e.ctx_class = q
                e.gaps += self.class_base_gaps([q])
                for m in MIDDLEWARE_METHODS:
                    r = self.p.lookup_method(q, m)
                    if r and r[0] == "project":
                        e.funcs.append((r[1], q, "middleware"))
                for c in self.p.mro(q):
                    if c in self.catalog.library_middleware:
                        e.library_mints += [(m, f"inherited from {c}") for m in self.catalog.library_middleware[c]]
                        break
                else:
                    e.gaps += self.library_base_gaps(q)
            elif q in self.p.functions:
                e.funcs.append((q, None, "middleware"))
                for nested in self.p.functions[q].nested.values():
                    e.funcs.append((nested, None, "middleware"))
            elif q in self.catalog.middleware_no_mint:
                pass
            else:
                # (v5, R2d) a library middleware the catalog does not declare (also from catalogued packages):
                # inherited catalog middleware is found through the library source, anything else is a gap
                anc = [c for c in self.lib.ancestors(q) if c in self.catalog.library_middleware] \
                    if self.lib.available else []
                if anc:
                    e.library_mints += [(m, f"{q} derives from {anc[0]} (library source)")
                                        for m in self.catalog.library_middleware[anc[0]]]
                    e.notes.append(f"{q}: library subclass of {anc[0]}; its own overrides are not analysed")
                    g = Gap("middleware_not_in_catalog", "-", "MIDDLEWARE", f"{mw} (subclass of {anc[0]})")
                    self.gaps.append(g)
                    e.gaps.append(g)
                else:
                    self.gaps.append(Gap("middleware_not_in_catalog", "-", "MIDDLEWARE", mw))
            if e.funcs or e.library_mints:
                entries.append(e)
        for ac in drf_auth_classes(self.settings):
            q = self.resolve_dotted(ac)
            if q in self.p.classes:
                e = Entry(id=f"drf_auth_class:{ac}", kind="drf_auth_class", view=q, ctx_class=q)
                e.gaps += self.class_base_gaps([q])
                for m in ("authenticate", "authenticate_credentials"):
                    r = self.p.lookup_method(q, m)
                    if r and r[0] == "project":
                        e.funcs.append((r[1], q, "drf_authentication"))
                for c in self.p.mro(q):
                    if c in self.catalog.library_drf_auth:
                        e.library_mints += [(m, f"inherited from {c}") for m in self.catalog.library_drf_auth[c]]
                        break
                else:
                    e.gaps += self.library_base_gaps(q)
                if e.funcs or e.library_mints:
                    entries.append(e)
            elif q in self.catalog.library_drf_auth:
                # (v5) a catalogued DRF authentication class that mints (knox token renewal) runs per API request
                e = Entry(id=f"drf_auth_class:{ac}", kind="drf_auth_class", view=q)
                e.library_mints += [(m, "runs on every API request that authenticates with it")
                                    for m in self.catalog.library_drf_auth[q]]
                entries.append(e)
            elif q in self.catalog.drf_auth_no_mint:
                pass
            else:
                # (v5, R2d) also for catalogued packages
                self.gaps.append(Gap("drf_auth_class_not_in_catalog", "-", "DEFAULT_AUTHENTICATION_CLASSES", ac))
        return entries

    @staticmethod
    def _variant_key(r: Route) -> tuple:
        """What a route occurrence runs, beyond its pattern and view (see build_entries)."""
        return (r.kind, tuple(r.decorators), tuple(r.wrapper_funcs), tuple(sorted(
            (k, _u(v)) for k, v in (r.as_view_kwargs or {}).items())), tuple(sorted((r.actions or {}).items())),
                r.dispatcher, r.dispatch_key)

    ASGI_ROUTERS = {"channels.routing.URLRouter"}
    ASGI_CONSUMER_METHODS = ("connect", "websocket_connect", "receive", "receive_json", "websocket_receive",
                             "disconnect", "websocket_disconnect", "http_request", "handle", "__call__")

    def asgi_entries(self) -> list:
        """(v5 review) Django Channels routes: `URLRouter([path(pattern, Consumer.as_asgi()), ...])` in project code
        (a list display, or a name / imported name bound to one).  Each consumer class is an entry
        (`asgi:<pattern>|<class>`) whose project methods are its functions; a URLRouter argument MintMap cannot
        enumerate is an `asgi_routing_not_analyzed` gap (mints in consumers then appear as unrouted paths)."""
        out, seen = [], set()
        for mname in sorted(self.p.modules):
            mod = self.p.modules[mname]
            for n in ast.walk(mod.tree):
                if not (isinstance(n, ast.Call) and n.args and
                        self.p.canonical(self.p.resolve_expr_static(mname, n.func) or "") in self.ASGI_ROUTERS):
                    continue
                lst, lmod = n.args[0], mname
                for _ in range(3):
                    if isinstance(lst, (ast.Name, ast.Attribute)):
                        q = self.p.canonical(self.p.resolve_expr_static(lmod, lst) or "")
                        m2, rest = self.p.module_prefix(q) if q else (None, [])
                        if m2 and len(rest) == 1 and self.p.modules[m2].assigns.get(rest[0]):
                            lst, lmod = self.p.modules[m2].assigns[rest[0]][-1], m2
                            continue
                    break
                if not isinstance(lst, (ast.List, ast.Tuple)):
                    self.gaps.append(Gap("asgi_routing_not_analyzed", mod.path, "URLRouter", _u(n.args[0]), n.lineno))
                    continue
                for el in lst.elts:
                    cls = None
                    if isinstance(el, ast.Call) and len(el.args) >= 2:
                        v = el.args[1]
                        if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and \
                                v.func.attr in ("as_asgi", "as_view"):
                            v = v.func.value
                        cls = self.p.canonical(self.p.resolve_expr_static(lmod, v) or "")
                    pat = el.args[0].value if isinstance(el, ast.Call) and el.args and \
                        isinstance(el.args[0], ast.Constant) else _u(el)
                    if cls in self.p.classes:
                        eid = f"asgi:{pat}|{cls}"
                        if eid in seen:
                            continue
                        seen.add(eid)
                        e = Entry(id=eid, kind="asgi_route", view=cls, ctx_class=cls,
                                  notes=[f"Django Channels route in {self.p.modules[lmod].path}"])
                        for c in self.p.mro(cls):
                            if c in self.p.classes:
                                for name, mq in sorted(self.p.classes[c].methods.items()):
                                    if (mq, cls, "asgi_consumer") not in e.funcs:
                                        e.funcs.append((mq, cls, "asgi_consumer"))
                        e.gaps += self.class_base_gaps([cls])
                        out.append(e)
                    elif isinstance(el, ast.Call):
                        self.gaps.append(Gap("asgi_routing_not_analyzed", self.p.modules[lmod].path, str(pat),
                                             _u(el), getattr(el, "lineno", 0)))
        return out

    def find_runtime_urlconfs(self) -> dict:
        """(v5 review fix) {project URLconf module: reason} for URLconfs selected at run time: dotted strings (or
        settings read) assigned to an attribute named `urlconf` (`request.urlconf = ...` in a middleware),
        passed to `set_urlconf(...)`, or held by a setting whose name ends in URLCONF (other than ROOT_URLCONF)."""
        out = {}

        def urlconf_module(x):
            if isinstance(x, str):
                x = self.p.unalias(x)
                if x in self.p.modules and "urlpatterns" in self.p.modules[x].assigns:
                    return x
            return None
        for name, v in sorted(self.settings.values.items()):
            if name.endswith("URLCONF") and name != "ROOT_URLCONF":
                for x in flat_values(v):
                    for y in (x if isinstance(x, (list, tuple)) else [x]):
                        m = urlconf_module(y)
                        if m:
                            out.setdefault(m, f"setting {name}")
        for mname in sorted(self.p.modules):
            mod = self.p.modules[mname]
            for n in ast.walk(mod.tree):
                exprs = []
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                    tg = n.targets if isinstance(n, ast.Assign) else [n.target]
                    if any(isinstance(t, ast.Attribute) and t.attr == "urlconf" for t in tg):
                        exprs.append(n.value)
                elif isinstance(n, ast.Call) and n.args and (
                        (isinstance(n.func, ast.Name) and n.func.id == "set_urlconf") or
                        (isinstance(n.func, ast.Attribute) and n.func.attr == "set_urlconf")):
                    exprs.append(n.args[0])
                for e in exprs:
                    for x in ast.walk(e):
                        if isinstance(x, ast.Constant):
                            m = urlconf_module(x.value)
                            if m:
                                out.setdefault(m, f"{mod.path}:{n.lineno} selects it per request")
                        elif isinstance(x, ast.Attribute) and x.attr.isupper():
                            q = self.p.resolve_expr_static(mname, x.value)
                            if q and self.p.canonical(q) == "django.conf.settings":
                                for y in flat_values(self.settings.values.get(x.attr)):
                                    m = urlconf_module(y)
                                    if m:
                                        out.setdefault(m, f"{mod.path}:{n.lineno} selects it per request "
                                                          f"(settings.{x.attr})")
        return out

    def _route_parts(self, r: Route) -> Entry:
        """Functions, library mints, notes and gates contributed by one route occurrence (a scratch Entry)."""
        e = Entry(id="", kind="route", view=r.target, route=r)
        if r.root in getattr(self, "unreached_roots", {}):
            # (v5 review fix) MintMap cannot tell whether this URLconf is served at all
            e.gaps.append(self.unreached_roots[r.root])
            e.notes.append(f"URLconf {r.root} is not reached from ROOT_URLCONF or a per-request URLconf")
        elif r.root in getattr(self, "runtime_urlconfs", {}):
            e.notes.append(f"URLconf {r.root} is selected at run time ({self.runtime_urlconfs[r.root]})")
        if r.dispatcher:
            e.notes.append(f"dispatched at runtime by {r.dispatcher} (route kwargs[{r.dispatch_key!r}]); checks "
                           f"the dispatcher makes before calling this view are not linked to the evidence")
        if r.helpers:
            e.notes.append("route built by project URL helper(s) " + ", ".join(r.helpers))
        for w in r.wrapper_funcs:
            info = self.p.functions[w]
            for nested in info.nested.values():
                e.funcs.append((nested, None, "view_wrapper"))
        if r.kind == "project_function":
            e.funcs.append((r.target, None, "http_handler"))
            for dq in self._decorator_names(r.target) + r.decorators:
                self._apply_decorator(e, dq)
                if dq in self.p.functions:
                    self.gaps.append(Gap("project_view_decorator_not_analyzed", r.file, r.target, dq, r.line))
        elif r.kind in ("project_class", "viewset"):
            e.ctx_class = r.target
            e.gaps += self.class_base_gaps([r.target], r.line)
            e.gaps += self.library_base_gaps(r.target, r.line)
            for c in self.p.mro(r.target):
                if c in self.p.classes:
                    for d in self.p.classes[c].node.decorator_list:
                        self.gaps.append(Gap("class_decorator_not_analyzed", r.file, c, _u(d), r.line))
            e.funcs += self.class_entry_funcs(r.target, r.actions, viewset=(r.kind == "viewset"))
            e.library_mints += self.drf_library_creation_mints(r.target, r.actions, viewset=(r.kind == "viewset"))
            e.library_mints += self.django_create_view_mints(r.target)
            mints, notes = self.inherited_library_mints(r.target, r.as_view_kwargs)
            e.library_mints += mints
            e.notes += notes
            for dq in r.decorators:
                self._apply_decorator(e, dq)
        elif r.kind == "library_view":
            status, sym, akw, trail = self.library_view_info(r.target)
            kwargs = {**akw, **(r.as_view_kwargs or {})}
            if trail:
                e.notes.append(f"{r.target}: " + "; ".join(trail))
            # (v5 review fix) project code handed to the library view through as_view(**kwargs) (a serializer
            # class, a form class, a model): the library flow runs it, so its methods are entry functions of
            # the route (a mint inside them is linked to it), also when the catalog declares the view non-minting
            injected = self.injected_code(e)
            for mq, cls in self.injected_methods(e):
                e.funcs.append((mq, cls, "library_view_kwarg"))
            if injected:
                e.notes.append(f"{r.target} runs project code passed to as_view(): " +
                               ", ".join(f"{q} ({how})" for q, how in injected))
            if status in ("mapped", "subclass"):
                d = self.catalog.library_views[sym]
                ok, note = self._requires_attr(d, None, kwargs)
                if note:
                    e.notes.append(note)
                if ok:
                    e.library_mints += [(self.catalog.mint_for_ref(ref, "library_view", sym),
                                         "" if sym == r.target else f"{r.target} resolves to {sym}")
                                        for ref in d["refs"]]
            elif status == "unknown":
                # (v5, R2a) also for catalogued packages: an unmapped symbol is a gap, not "covered, no mint"
                detail = r.target if sym == r.target else f"{r.target} -> {sym}"
                if r.target.split(".")[0] in overlay.CATALOG_PACKAGES:
                    detail += " (catalogued package; symbol not mapped)"
                self.gaps.append(Gap("library_view_not_in_catalog", r.file, r.pattern, detail, r.line))
            for dq in r.decorators:
                self._apply_decorator(e, dq)
        elif r.kind == "library_include":
            mints = self.catalog.library_includes.get(r.target)
            dropped, bnote = self._url_builder_narrowing(r)
            if bnote:
                e.notes.append(bnote)
            if mints and dropped:
                mints = [m for m in mints if m.ref not in dropped]
            if mints:
                e.library_mints += [(m, "settings-dependent library URLconf: not every listed flow is "
                                        "necessarily enabled") for m in mints]
                if r.target not in self.catalog.includes_complete:
                    # (v5, R2b) the catalog lists some flows of this URLconf but does not declare the list complete
                    g = Gap("library_include_mints_incomplete", r.file, r.pattern,
                            f"{r.target}: the catalog lists {len(mints)} mint flow(s) but does not declare this "
                            f"URLconf's mint list complete; other routes it exposes are not analysed", r.line)
                    self.gaps.append(g)
                    e.gaps.append(g)
            elif r.target in self.catalog.includes_complete:
                e.notes.append(f"{r.target}: the catalog declares that this URLconf mints nothing")
            else:
                self.gaps.append(Gap("library_include_not_in_catalog", r.file, r.pattern, r.target, r.line))
        elif r.kind == "admin_site":
            sfuncs, replaced, snotes = self.admin_site_parts()
            e.library_mints += [(m, "") for m in self.catalog.admin_site_urls[r.target] if m.ref not in replaced]
            for f in sfuncs:
                if f not in e.funcs:
                    e.funcs.append(f)
            e.notes += snotes
            mints, gap, notes = self.admin_registration_info()
            e.library_mints += mints
            e.notes += notes
            if gap is not None:
                e.gaps.append(gap)
            code, notes, gaps = self.admin_site_customisation()
            e.extra_code += code
            e.notes += notes
            e.gaps += gaps
        return e

    def _url_builder_narrowing(self, r: Route):
        """(v6) For a route that includes the result of a catalogued URL builder (`build_urlpatterns(Client.X)`):
        (refs the builder's argument disables, note)."""
        call = r.node
        if not isinstance(call, ast.Call):
            return set(), ""
        mod = self._module_of_file(r.file)
        q = self.p.resolve_expr_static(mod, call.func) if mod else None
        q = self.p.canonical(q) if q else None
        row = self.catalog.url_builders.get(q or "")
        if not row:
            return set(), ""
        note = f"routes built by {q}(...) ({row['source_location']}): the flows of {row['same_flows_as']}"
        cond = row.get("refs_only_for_client")
        if not cond:
            return set(), note
        i = cond.get("arg", 0)
        arg = call.args[i] if len(call.args) > i else None
        name = arg.attr if isinstance(arg, ast.Attribute) else (arg.id if isinstance(arg, ast.Name) else None)
        if name is None or name in cond["client_names"]:
            return set(), note + ("" if name else "; the builder argument is not static: every flow is listed")
        return set(cond["refs"]), note + (f"; argument {name}: {len(cond['refs'])} flow(s) that need "
                                          f"{'/'.join(cond['client_names'])} are not routed "
                                          f"({cond['source_location']})")

    # ------------------------------------------------------------- (v5 review fix) project code given to a library flow
    def _module_of_file(self, rel: str) -> str | None:
        if not hasattr(self, "_file_mods"):
            self._file_mods = {m.path: name for name, m in self.p.modules.items()}
        return self._file_mods.get(rel)

    def _project_code_refs(self, modname, expr, func=None) -> list:
        """Project classes / functions an expression names (a name, a dotted attribute, a list/tuple of them)."""
        if modname is None or expr is None:
            return []
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return [q for e in expr.elts for q in self._project_code_refs(modname, e, func)]
        if isinstance(expr, (ast.Name, ast.Attribute)):
            q = self.p.resolve_expr_static(modname, expr, func)
            q = self.p.canonical(q) if q else None
            if q and (q in self.p.classes or q in self.p.functions):
                return [q]
        return []

    def injected_code(self, entry) -> list:
        """(v5 review fix) Project classes / functions that a library flow of this entry runs because the route
        or the view class hands them over: values of `as_view(**kwargs)` of every route occurrence (a
        serializer_class, form_class, authentication_form, permission_classes ...; any keyword) and the class
        attributes of a project view class that inherits library code (any attribute name, not only form_class /
        serializer_class).  [(qualname, how)]"""
        key = entry.id
        memo = self.__dict__.setdefault("_injected", {})
        if key and key in memo:
            return memo[key]
        out = []
        for r in ([entry.route] + list(entry.variants)) if entry.route is not None else []:
            mod = self._module_of_file(r.file)
            for k, expr in sorted((r.as_view_kwargs or {}).items()):
                for q in self._project_code_refs(mod, expr):
                    if (q, f"as_view({k}=...)") not in out:
                        out.append((q, f"as_view({k}=...)"))
        ctx = entry.ctx_class
        if ctx in self.p.classes and any(c not in self.p.classes for c in self.p.mro(ctx)):
            for c in self.p.mro(ctx):
                if c not in self.p.classes:
                    continue
                for attr, expr in sorted(self.p.classes[c].attrs.items()):
                    if self.p.class_attr(ctx, attr)[0] != c:
                        continue      # overridden by a subclass
                    for q in self._project_code_refs(self.p.classes[c].module, expr):
                        if q != ctx and (q, f"{attr} = ...") not in out:
                            out.append((q, f"{attr} = ..."))
        if key:
            memo[key] = out
        return out

    def injected_methods(self, entry) -> list:
        """[(function, receiver class)] of the injected project code (every project method of an injected class,
        with its project bases)."""
        out = []
        for q, _how in self.injected_code(entry):
            if q in self.p.classes:
                for c in self.p.mro(q):
                    if c in self.p.classes:
                        for mq in sorted(self.p.classes[c].methods.values()):
                            if (mq, q) not in out:
                                out.append((mq, q))
            elif q in self.p.functions and (q, None) not in out:
                out.append((q, None))
        return out

    # ------------------------------------------------------------- (v5, R2) library knowledge, never silent
    def library_view_info(self, target: str):
        """Classify a library view symbol: ('mapped', catalog symbol, as_view kwargs, trail) | ('no_mint', ...) |
        ('subclass', catalog symbol, ...) | ('unknown', resolved symbol, ...).  Catalog aliases (catalog v3) and,
        with --library-path, the library source are followed (module-level `x = Cls.as_view(...)` aliases,
        re-exports).  A symbol of a catalogued package is NOT assumed to mint nothing: 'unknown' is a gap."""
        trail, kwargs, sym = [], {}, target
        for _ in range(6):
            if sym in self.catalog.library_views:
                return "mapped", sym, kwargs, trail
            src = self.catalog.view_no_mint(sym)
            if src:
                return "no_mint", sym, kwargs, trail + [f"catalog: no mint ({src})"]
            if sym in self.catalog.view_aliases:
                t, src = self.catalog.view_aliases[sym]
                trail.append(f"catalog alias {sym} = {t}.as_view() ({src})")
                sym = t
                continue
            if self.lib.available:
                r = self.lib.resolve(sym)
                if r and r.symbol != sym:
                    trail += [f"library source {t}" for t in r.trail]
                    kwargs = {**r.as_view_kwargs, **kwargs}
                    sym = r.symbol
                    continue
            break
        if self.lib.available:
            between = [sym]
            for anc in self.lib.ancestors(sym):
                if anc in self.catalog.library_views:
                    d = self.catalog.library_views[anc]
                    over = [m for m in d.get("mint_methods", []) for c in between if self.lib.defines(c, m)]
                    if over:
                        return "unknown", sym, kwargs, trail + [
                            f"library class {sym} derives from catalog view {anc} but overrides {sorted(set(over))}"]
                    return "subclass", anc, kwargs, trail + [f"library class {sym} derives from catalog view {anc} "
                                                             f"(library source) without overriding its mint method"]
                between.append(anc)
        return "unknown", sym, kwargs, trail

    def library_class_known(self, c: str) -> bool:
        """A library class in a project class's MRO whose methods the catalog accounts for."""
        top = c.split(".")[0]
        return (c in self.catalog.library_views or bool(self.catalog.view_no_mint(c)) or top in STDLIB_TOP
                or c in self.catalog.library_middleware or c in self.catalog.middleware_no_mint
                or c in self.catalog.library_drf_auth or c in self.catalog.drf_auth_no_mint
                or c in self.catalog.form_checks or c in overlay.LIBRARY_CLASS_LACKS)

    def library_base_gaps(self, cls_qn: str, line=0) -> list:
        """(v5, R2) a project class (view, middleware, DRF auth class) inherits a library class the catalog does
        not account for: an inherited method may mint.  One gap per library base (stable key)."""
        out = []
        for c in self.p.mro(cls_qn):
            if c in self.catalog.library_views or c in self.catalog.library_middleware or \
                    c in self.catalog.library_drf_auth:
                break     # the catalog accounts for this library class and the bases it brings
            if c in self.p.classes or self.library_class_known(c):
                continue
            g = Gap("library_base_not_in_catalog", self.p.file_of(cls_qn), c, "inherited by project classes", line)
            self.gaps.append(g)
            out.append(g)
        return out

    def admin_registration_info(self):
        """(v5, R2c) mints and gap for library apps' admin registrations under admin.site.urls (catalog v3
        `library_admin_registrations`).  Apps the catalog does not declare are listed in one gap."""
        if self._admin_info is not None:
            return self._admin_info
        mints, unknown, notes = [], [], []
        for a in self.settings.str_list("INSTALLED_APPS"):
            mod = app_module(a)
            if self.p.module_prefix(mod)[0] is not None:
                continue   # project app: its ModelAdmins are project code
            if mod in self.catalog.admin_registrations:
                for model, madmin, api, src in self.catalog.admin_registrations[mod]:
                    if api is not None:
                        mints.append((api, f"admin add/change view of {model} ({madmin}, {src}); registered when "
                                           f"{a!r} is in INSTALLED_APPS"))
                continue
            if self.lib.available and self.lib.module(mod) and not self.lib.module(mod + ".admin"):
                notes.append(f"{mod}: no admin module in the library source")
                continue
            unknown.append(mod)
        mints += self._project_admin_registrations()
        if self.settings.dynamic_items("INSTALLED_APPS"):
            unknown.append("<INSTALLED_APPS items MintMap cannot evaluate>")
        gap = None
        if unknown:
            gap = Gap("library_admin_not_in_catalog", "-", "admin.site.urls",
                      "admin registrations of installed apps are not in the catalog: " + ", ".join(sorted(set(unknown))))
            self.gaps.append(gap)
        self._admin_info = (mints, gap, notes)
        return self._admin_info

    ADMIN_SITE_OBJECTS = ("django.contrib.admin.site", "django.contrib.admin.sites.site")

    def admin_site_customisation(self):
        """(v5 review fix) Module-level project statements that change the default admin site object
        (`admin.site.__class__ = OTPAdminSite`, `admin.site.login_form = F`, `admin.site.login = f`,
        `admin.sites.site = S()`): the admin login runs what they install.  Their text, and the source of any
        project class / function they name, is hashed into the admin paths' `code`; a library class of a
        package the catalog does not describe is a gap.  -> (code parts, notes, gaps)"""
        hit = self.__dict__.get("_admin_custom")
        if hit is not None:
            return hit
        code, notes, gaps = [], [], []
        classes = []
        # (v6) also inside functions (`def patch_site(): admin.site = MySite()` called from AppConfig.ready()):
        # MintMap does not decide whether the function runs, so the swap is treated as possible
        fn_stmts: dict = {}
        for qn, info in self.p.functions.items():
            if info.parent is None and "site" in self.cred.mentions(info):
                fn_stmts.setdefault(info.module, []).extend(
                    (st, info) for st in self.p.walk_function_body(info.node)
                    if isinstance(st, (ast.Assign, ast.AugAssign, ast.AnnAssign)))
        for mname in sorted(self.p.modules):
            mod = self.p.modules[mname]
            stmts = [(st, None) for st in self.p._top_level_statements(mod.tree.body)] + fn_stmts.get(mname, [])
            for st, finfo in stmts:
                if not isinstance(st, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    continue
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                hitst = False
                for t in targets:
                    node = t
                    while isinstance(node, (ast.Attribute, ast.Subscript)):
                        q = self.p.resolve_expr_static(mname, node, finfo)
                        if q and self.p.canonical(q) in self.ADMIN_SITE_OBJECTS:
                            hitst = True
                            break
                        node = node.value
                if not hitst or st.value is None:
                    continue
                code.append(f"admin_site:{mname}:" + normalize(st))
                for q in self._project_code_refs(mname, st.value):
                    code.append("admin_site_code:" + self.source_dump(q))
                vq = self.p.resolve_expr_static(mname, st.value) if isinstance(st.value, (ast.Name, ast.Attribute)) \
                    else None
                vq = self.p.canonical(vq) if vq else None
                site_cls = self._admin_site_class(mname, st.value, finfo)
                if site_cls and site_cls not in classes:
                    classes.append(site_cls)
                where = f" (in {finfo.qualname})" if finfo else ""
                notes.append(f"{mod.path}:{st.lineno}{where} changes the admin site: "
                             f"{_short(stable_unparse(st), 120)}")
                if vq and vq not in self.p.classes and vq not in self.p.functions and \
                        vq.split(".")[0] not in overlay.CATALOG_PACKAGES and vq.split(".")[0] not in STDLIB_TOP:
                    g = Gap("admin_site_customised", mod.path, "admin.site", f"{vq}: library code of a package the "
                            f"catalog does not describe replaces part of the admin site", st.lineno)
                    self.gaps.append(g)
                    gaps.append(g)
        # (v6) `class X(AdminConfig): default_site = "pkg.sites.MySite"` listed in INSTALLED_APPS
        for a in self.settings.str_list("INSTALLED_APPS"):
            cq = self.resolve_dotted(a)
            if cq in self.p.classes and any(c.startswith("django.contrib.admin.apps.") for c in self.p.mro(cq)):
                _c, v = self.p.class_attr(cq, "default_site")
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    sq = self.resolve_dotted(v.value)
                    if sq in self.p.classes and sq not in classes:
                        classes.append(sq)
                        code.append("admin_site_default:" + self.source_dump(sq))
                        notes.append(f"{a} sets default_site = {v.value!r}")
        self._admin_custom = (code, notes, gaps)
        self._admin_site_classes = classes
        return self._admin_custom

    def _admin_site_class(self, mname, value, finfo):
        """The project AdminSite subclass an assigned value installs: `MySite()`, or a module constant bound to
        `MySite()` (`SITE = MySite()` ... `admin.site = SITE`)."""
        v = value
        for _ in range(3):
            if isinstance(v, ast.Call):
                q = self.p.resolve_expr_static(mname, v.func, finfo)
                q = self.p.canonical(q) if q else None
                return q if q in self.p.classes and any(c.rsplit(".", 1)[-1].endswith("AdminSite")
                                                         for c in self.p.mro(q)[1:]) else None
            if isinstance(v, (ast.Name, ast.Attribute)):
                q = self.p.resolve_expr_static(mname, v, finfo)
                q = self.p.canonical(q) if q else None
                m, rest = self.p.module_prefix(q) if q else (None, [])
                if not m or len(rest) != 1:
                    return None
                vals = [st.value for st in self.p._top_level_statements(self.p.modules[m].tree.body)
                        if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == rest[0]
                                                              for t in st.targets)]
                if len(vals) != 1:
                    return None
                mname, v, finfo = m, vals[0], None
                continue
            return None
        return None

    ADMIN_SITE_METHODS = ("login", "logout", "password_change", "password_change_done", "admin_view",
                          "has_permission", "index", "app_index", "each_context", "get_urls")

    def admin_site_parts(self):
        """(v6) [(func, ctx, role)] project methods of installed AdminSite subclasses, and the library admin-site
        mint refs their overrides replace (an override that never calls super() replaces the library flow)."""
        self.admin_site_customisation()
        funcs, replaced, notes = [], set(), []
        for cq in self.__dict__.get("_admin_site_classes", []):
            for m in self.ADMIN_SITE_METHODS:
                r = self.p.lookup_method(cq, m)
                if r and r[0] == "project":
                    funcs.append((r[1], cq, "admin_site"))
                    if m == "login" and not self._calls_super(r[1], "login"):
                        replaced.add("django.contrib.admin.sites.AdminSite.login")
                        notes.append(f"{cq}.login replaces AdminSite.login (no super() call): the project method is "
                                     f"analysed instead of the library flow")
        return funcs, replaced, notes

    def _project_admin_registrations(self) -> list:
        """(v5, R2c) `admin.site.register(Model, ...)` / `@admin.register(Model)` in project code where the model's
        `save` is a catalog mint (e.g. a DRF Token or a project subclass of it): the admin add view mints."""
        out, seen = [], set()
        for mod in self.p.modules.values():
            for n in ast.walk(mod.tree):
                calls = []
                if isinstance(n, ast.Call):
                    calls.append(n)
                for call in calls:
                    fq = self.p.resolve_expr_static(mod.name, call.func)
                    fq = self.p.canonical(fq) if fq else ""
                    if not (fq.endswith("admin.site.register") or fq in ("django.contrib.admin.register",
                                                                           "django.contrib.admin.decorators.register")):
                        continue
                    models = call.args[:1] if fq.endswith("site.register") else call.args
                    for a in models:
                        for e in (a.elts if isinstance(a, (ast.List, ast.Tuple)) else [a]):
                            q = self.p.resolve_expr_static(mod.name, e)
                            q = self.p.canonical(q) if q else None
                            if not q:
                                continue
                            for c in (self.p.mro(q) if q in self.p.classes else [q] + list(
                                    overlay.LIBRARY_BASES.get(q, []))):
                                api = self.catalog.mint_calls.get(f"{c}.save")
                                if api and (q, api.ref) not in seen:
                                    seen.add((q, api.ref))
                                    out.append((api, f"admin add/change view of {q} registered at {mod.path}:"
                                                     f"{call.lineno} (saving it runs {c}.save)"))
                                    break
        return out

    def class_base_gaps(self, classes, line=0) -> list:
        """(v5, R6) A `class_base_unresolved` gap for every base in the project MRO of these classes that MintMap
        cannot resolve (a call, an unknown name, a computed expression): inherited methods, permission classes
        and gates behind it are invisible, so the paths that use the class are incomplete.  Recorded globally
        too."""
        out, seen = [], set()
        for cq in classes:
            if not cq or cq not in self.p.classes:
                continue
            for c, b in self.p.unresolved_bases_in_mro(cq):
                if (c, b) in seen:
                    continue
                seen.add((c, b))
                g = Gap("class_base_unresolved", self.p.file_of(c), c, b, line)
                self.gaps.append(g)
                out.append(g)
        return out

    def _apply_decorator(self, e: Entry, dq: str):
        """Route/view decorators: some mint (sesame), some gate access (otp_required)."""
        for api in self.catalog.mint_decorators.get(dq, []):
            e.library_mints.append((api, "view decorator"))
        if dq in overlay.VIEW_GATE_DECORATORS or dq.startswith(("django.contrib.auth.decorators",
                                                                 "django.views.decorators")):
            e.gates.append(dq)
        elif dq not in self.catalog.mint_decorators and dq not in self.p.functions and \
                not dq.startswith(KNOWN_DECORATOR_PREFIXES) and dq.split(".")[0] not in STDLIB_TOP:
            # (v5, R2) a library (or unresolved) view decorator the catalog does not know: it wraps the view and
            # may check or mint; its effect is not analysed (before v5 it was ignored without a gap)
            r = e.route
            g = Gap("view_decorator_not_in_catalog", r.file if r else "-", e.view or "-", dq, r.line if r else 0)
            self.gaps.append(g)
            e.gaps.append(g)

    # ============================================================== traversal
    def implied_edges(self, site, res, ctx) -> list:
        """Framework-implied calls: form/serializer validation and save hooks,
        and super().post() dispatching to project hooks."""
        out = []
        t = res.receiver_type
        if site.leaf in VALIDATION_TRIGGERS:
            # every project form/serializer class the receiver may hold, recognised as a check or not
            for ft in self.form_types_for(site, res, ctx):
                out += [(mq, ft) for mq in self.validation_methods(ft)]
        elif t and t in self.p.classes and site.leaf == "save":
            for c in self.p.mro(t):
                if c not in self.p.classes:
                    continue
                for name, mq in self.p.classes[c].methods.items():
                    if name in ("save", "create", "update"):
                        out.append((mq, t))
            # (v5 review) pre_save / post_save receivers of a model run on its save(); (v6) an instance save()
            # that is not a creation does not reach a receiver whose whole body is guarded by `if created:`
            out += [(f, None) for f in self.cred.signal_receivers().get(t, [])
                    if not self._creation_only_receiver(f)]
        out += self.model_save_edges(site, res, ctx)
        if res.library and ctx and res.via in ("super", "self"):
            meth = res.library.rsplit(".", 1)[-1]
            for hook in VERB_TO_HOOKS.get(meth, []):
                r = self.p.lookup_method(ctx, hook)
                if r and r[0] == "project":
                    out.append((r[1], ctx))
        inv = self.as_view_invocation(site)
        if inv and inv[0] in self.p.classes:
            # (v3) a project CBV run from code: Cls.as_view(**kw)(request) -> its handlers and hooks
            out += [(f, c) for f, c, _ in self.class_entry_funcs(inv[0])]
        return out

    def _creation_only_receiver(self, fq) -> bool:
        """A post_save receiver `def f(sender, instance, created, **kw)` whose body (docstring aside) is one
        `if created:` block without else, or starts with `if not created: return`."""
        info = self.p.functions.get(fq)
        if not info or "created" not in info.params and not any(
                a.arg == "created" for a in info.node.args.kwonlyargs):
            return False
        body = [st for st in info.node.body if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
        if not body:
            return False
        first = body[0]
        if not isinstance(first, ast.If):
            return False
        t = first.test
        if len(body) == 1 and isinstance(t, ast.Name) and t.id == "created" and not first.orelse:
            return True
        return isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not) and isinstance(t.operand, ast.Name) and \
            t.operand.id == "created" and len(first.body) == 1 and isinstance(first.body[0], ast.Return)

    def model_save_edges(self, site, res, ctx) -> list:
        """(v5, R3) creating a project model runs its project `save()`: `M.objects.create/get_or_create/...`, the
        library ModelSerializer / ModelForm `save()`/`create()` of a serializer or form whose Meta.model is M
        (`serializer.save()` without a project create(), `super().create(...)` inside one)."""
        if not isinstance(site.node, ast.Call):
            return []
        info = self.p.functions[site.func]
        model, how = self.cred._creation_model(site.node, info, ctx or info.cls)
        if model and model.startswith("param:"):
            return []
        if model is None:
            owner = None
            if site.leaf == "save" and res.receiver_type in self.p.classes:
                r = self.p.lookup_method(res.receiver_type, "create")
                if not (r and r[0] == "project"):
                    owner = res.receiver_type
            elif site.leaf in ("create", "update", "save") and res.via == "super" and res.library and info.cls:
                owner = ctx or info.cls
            if owner:
                model = self.cred.model_meta(owner)
        if model is None or how == "constructor":
            return []
        r = self.p.lookup_method(model, "save")
        out = [(r[1], model)] if r and r[0] == "project" else []
        # (v5 review) pre_save / post_save receivers of the model run on every creation
        out += [(f, None) for f in self.cred.signal_receivers().get(model, [])]
        return out

    def as_view_invocation(self, site):
        """(class qualname, as_view Call) when the call site runs a class-based view from code:
        `Cls.as_view(**kw)(request, ...)` or `view = Cls.as_view(**kw)` ... `view(request, ...)`.
        Memoised per call node (it is asked for every site of every traversal)."""
        call = site.node
        if site.is_property or not isinstance(call, ast.Call):
            return None
        key = id(call)
        if key in self._as_view_memo:
            return self._as_view_memo[key]
        av = None
        if isinstance(call.func, ast.Call) and isinstance(call.func.func, ast.Attribute) and \
                call.func.func.attr == "as_view":
            av = call.func
        elif isinstance(call.func, ast.Name):
            av = self._as_view_assignments(site.func).get(call.func.id)
        out = None
        if av is not None:
            info = self.p.functions[site.func]
            q = self.p.resolve_expr_static(info.module, av.func.value, info)
            out = (self.p.canonical(q), av) if q else None
        self._as_view_memo[key] = out
        return out

    def _as_view_assignments(self, func_qn) -> dict:
        """{local name: as_view Call} for `name = Cls.as_view(...)` in a function body (first one wins)."""
        hit = self._as_view_assigns.get(func_qn)
        if hit is None:
            hit = {}
            for n in self.p.walk_function_body(self.p.functions[func_qn].node):
                if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and \
                        isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) and \
                        n.value.func.attr == "as_view":
                    hit.setdefault(n.targets[0].id, n.value)
            self._as_view_assigns[func_qn] = hit
        return hit

    def invoked_library_views(self, graph) -> list:
        """(v3) catalog library views (and project subclasses' inherited library mints) run from project
        code on this entry's call graph via as_view(...)(request): [(MintAPI, note)]."""
        out, seen = [], set()
        for fq, _ctx in sorted(graph, key=str):
            for site in self.cg.sites(fq):
                inv = self.as_view_invocation(site)
                if not inv:
                    # (v6) a catalogued FUNCTION view called directly with the request (`return complete(request,
                    # backend)` in a project view): the library flow runs exactly as if the route pointed at it
                    for api, note in self.function_view_invocation(site, _ctx):
                        if (api.symbol, api.ref) not in seen:
                            seen.add((api.symbol, api.ref))
                            out.append((api, note))
                    continue
                cq, av = inv
                kwargs = {k.arg: k.value for k in av.keywords if k.arg}
                how = f"invoked from {fq} via {_u(av)}(...)"
                if cq in self.p.classes:
                    mints, _notes = self.inherited_library_mints(cq, kwargs)
                    for api, note in mints:
                        if (api.symbol, api.ref) not in seen:
                            seen.add((api.symbol, api.ref))
                            out.append((api, "; ".join(x for x in (note, how) if x)))
                    continue
                status, sym, akw, _trail = self.library_view_info(cq)
                if status == "no_mint":
                    continue
                if status == "unknown":
                    # (v5, R2) a library view run from project code that the catalog does not map: a gap
                    self.gaps.append(Gap("library_view_not_in_catalog", self.p.file_of(fq), fq,
                                         cq if sym == cq else f"{cq} -> {sym}", site.line))
                    continue
                d = self.catalog.library_views[sym]
                kwargs = {**akw, **kwargs}
                ok, note = self._requires_attr(d, None, kwargs)
                if not ok:
                    continue
                for ref in d["refs"]:
                    api = self.catalog.mint_for_ref(ref, "library_view", sym)
                    if (api.symbol, api.ref) not in seen:
                        seen.add((api.symbol, api.ref))
                        out.append((api, "; ".join(x for x in (note, how) if x)))
        return out

    def function_view_invocation(self, site, ctx) -> list:
        """(v6) [(MintAPI, note)] when the call site runs a catalogued library function view (catalog
        `function_alias`) with the HTTP request as an argument."""
        call = site.node
        if site.is_property or not isinstance(call, ast.Call):
            return []
        if not any((isinstance(a, ast.Name) and a.id == "request") or (isinstance(a, ast.Attribute) and
                                                                         a.attr == "request")
                   for a in list(call.args) + [k.value for k in call.keywords]):
            return []
        res = self.cg.resolve(site, ctx)
        if not res.library or res.targets:
            return []
        status, sym, _akw, trail = self.library_view_info(res.library)
        if status != "mapped" or not self.catalog.library_views[sym].get("function_alias"):
            return []
        how = f"library view {sym} called directly from {site.func} (line {site.line})" + (
            f" ({'; '.join(trail)})" if trail else "")
        return [(self.catalog.mint_for_ref(ref, "library_view", sym), how)
                for ref in self.catalog.library_views[sym]["refs"]]

    def form_types_for(self, site, res, ctx) -> list:
        """Project classes the receiver of `x.is_valid()` may be (typed local, or every class
        instantiated into that variable in the function)."""
        types = set()
        if res.receiver_type:
            types.add(res.receiver_type)
        if res.receiver_var:
            types |= self.cg.var_type_candidates(site.func, ctx).get(res.receiver_var, set())
        return sorted(t for t in types if t in self.p.classes)

    def validation_methods(self, cls_qn) -> list:
        out = []
        for c in self.p.mro(cls_qn):
            if c in self.p.classes:
                out += [mq for name, mq in sorted(self.p.classes[c].methods.items())
                        if name.startswith(FORM_VALIDATION_METHODS_PREFIX)]
        return out

    def path_validation_methods(self, entry, chains, slice_nodes) -> list:
        """Project form/serializer clean*/validate* methods used on a path: reached from a path
        function through is_valid()/full_clean(), or run by the framework before a gated hook
        (form_valid / perform_create ...).  [(method, form class)]"""
        out = set()
        for fq, ctx in slice_nodes:
            for site in self.cg.sites(fq):
                if site.leaf in VALIDATION_TRIGGERS:
                    res = self.cg.resolve(site, ctx)
                    for ft in self.form_types_for(site, res, ctx):
                        out |= {(mq, ft) for mq in self.validation_methods(ft)}
        if not chains:
            # (v5) a library flow inherited by a project class (e.g. a project subclass of a catalog view with
            # its own serializer_class / form_class): the library runs the project form's / serializer's
            # validation, so those methods are part of what the path depends on (checks fingerprint, gaps).
            # (v5 review fix) any class the route or the view class hands to the library flow (any attribute
            # name, e.g. LoginView.authentication_form, and as_view(**kwargs) of a library view)
            for fcls, _how in self.injected_code(entry):
                if fcls in self.p.classes:
                    out |= {(mq, fcls) for mq in self.validation_methods(fcls)}
        roles = {(f, c): role for f, c, role in entry.funcs}
        for chain, _ in chains:
            first, ctx = chain[0]
            hook = first.rsplit(".", 1)[-1]
            if roles.get(chain[0]) == "framework_hook" and hook in FRAMEWORK_GATES and ctx:
                fcls = self.cg.class_attr_type(ctx, FRAMEWORK_GATES[hook][0])
                if fcls in self.p.classes:
                    out |= {(mq, fcls) for mq in self.validation_methods(fcls)}
        return sorted(out)

    def traverse(self, starts) -> dict:
        """BFS from start nodes. Returns graph: node -> [(child, site)]."""
        graph: dict = {}
        queue = list(starts)
        seen = set(starts)
        while queue:
            node = queue.pop(0)
            fq, ctx = node
            edges = []
            for site in self.cg.sites(fq):
                res = self.cg.resolve(site, ctx)
                for t in res.targets + self.implied_edges(site, res, ctx):
                    edges.append((t, site))
                    if t not in seen:
                        seen.add(t)
                        queue.append(t)
            graph[node] = edges
        return graph

    def chains(self, graph, starts, target) -> tuple[list, bool]:
        """Simple paths from any start to target (bounded)."""
        out, truncated = [], False
        rev: dict = {}
        for n, es in graph.items():
            for (c, site) in es:
                rev.setdefault(c, []).append((n, site))
        # nodes that can reach target
        can = {target}
        stack = [target]
        while stack:
            n = stack.pop()
            for (pn, _) in rev.get(n, []):
                if pn not in can:
                    can.add(pn)
                    stack.append(pn)

        def dfs(node, path, sites):
            nonlocal truncated
            if len(out) >= self.chain_limit:
                truncated = True
                return
            if node == target:
                out.append((list(path), list(sites)))
                return
            for child in sorted({c for c, _ in graph.get(node, []) if c in can and c not in path}, key=str):
                csites = [s for c2, s in graph[node] if c2 == child]
                path.append(child)
                sites.append(csites)
                dfs(child, path, sites)
                path.pop()
                sites.pop()
        for s in starts:
            if s in can:
                dfs(s, [s], [])
        return out, truncated

    # =============================================================== evidence
    def chain_evidence(self, chain, link_sites, mint_site, mint_api, entry: Entry, entry_role) -> list:
        """Check records for one chain: [(record dict)]."""
        records = []
        self._current_mint_line = mint_site.line
        mint_names = mint_user_names(mint_site, mint_api)
        if mint_names:
            mint_names |= self._alias_names(chain[-1][0], mint_names, mint_site.line)
        for i, (fq, ctx) in enumerate(chain):
            sinks = [mint_site.node] if i == len(chain) - 1 else [s.node for s in link_sites[i]]
            checks = self.function_checks(fq, ctx)
            an = self.analyzer(fq, checks)
            for s, d in checks:
                rels = [an.classify(s.node, d.ret, sink) for sink in sinks]
                rel, why = min(rels, key=lambda x: RELATION_RANK[x[0]])
                if not d.faithful and rel in ("guards_mint", "guards_mint_assert_only"):
                    rel, why = "present_unproven", d.detail or "check implementation not faithful"
                elif not d.faithful and d.via in ("catalog", "wrapper") and d.detail:
                    why = f"{d.detail}; {why}"   # e.g. jwt.decode(..., options={"verify_signature": False})
                same = "not_applicable"
                if d.subject is not None and mint_names is not None and rel.startswith("guards"):
                    same = self.same_user(chain, link_sites, i, s, d, an, mint_names)
                records.append(dict(function=fq, line=s.line, check=d.symbol, catalog_ref=d.ref, factor=d.factor,
                                    via=d.via, relation=rel, detail=why, same_user=same,
                                    project_funcs=d.project_funcs, unrecognized=d.unrecognized,
                                    config_src=d.config_src, arg_gaps=d.arg_gaps))
        # framework gate for hooks invoked by library code after validation
        first, ctx = chain[0]
        hook = first.rsplit(".", 1)[-1]
        if entry_role == "framework_hook" and hook in FRAMEWORK_GATES and ctx:
            attr, mech = FRAMEWORK_GATES[hook]
            fcls = self.cg.class_attr_type(ctx, attr)
            fc = self.form_check(fcls) if fcls else None
            if fc and fc.faithful:
                params = self.p.functions[first].params
                form_param = params[1] if len(params) > 1 else None
                same = "not_applicable"
                if mint_names is not None and form_param:
                    same = self.propagate_subject(chain, link_sites, 0, "form:" + form_param, mint_names)
                records.append(dict(function=first, line=self.p.functions[first].node.lineno,
                                    check=f"{fcls}.is_valid", catalog_ref=fc.ref, factor="+".join(fc.factors),
                                    via="framework", relation="guards_mint", detail=mech, same_user=same,
                                    project_funcs=fc.project_funcs, unrecognized=fc.unrecognized,
                                    config_src=fc.config_src, arg_gaps=fc.arg_gaps))
            elif fcls:
                records.append(dict(function=first, line=self.p.functions[first].node.lineno,
                                    check=f"{fcls}.is_valid", catalog_ref=None,
                                    factor="+".join(fc.factors) if fc else "none", via="framework",
                                    relation="present_unproven",
                                    detail=f"{mech}; but {fcls} has no recognised check that raises on failure"
                                           + (f" ({fc.detail})" if fc and fc.detail else ""),
                                    same_user="not_applicable", project_funcs=fc.project_funcs if fc else [],
                                    unrecognized=fc.unrecognized if fc else [],
                                    config_src=fc.config_src if fc else [], arg_gaps=fc.arg_gaps if fc else []))
            else:
                self.gaps.append(Gap("form_class_unresolved", self.p.file_of(first), first, attr))
        gate = self.prior_auth_gate(entry, chain, mint_names)
        if gate:
            records.append(gate)
        return records

    def _alias_names(self, func_qn, names, line) -> set:
        """`user = serializer.validated_data["user"]` -> also accept the right-hand side."""
        an = GuardAnalyzer(self.p.functions[func_qn].node, lambda c: False)
        binds, _ = an.assigns()
        out = set()
        for n in list(names):
            cands = [(ln, v) for ln, v in binds.get(n, []) if ln <= line and not isinstance(v, tuple)]
            if not cands:
                continue
            v = cands[-1][1]
            v = v.value if isinstance(v, ast.Await) else v
            out.add(_u(v))
            base = v.func if isinstance(v, ast.Call) else v
            while isinstance(base, (ast.Attribute, ast.Subscript, ast.Call)):
                base = base.func if isinstance(base, ast.Call) else base.value
            if isinstance(base, ast.Name) and base.id != n:
                out.add("form:" + base.id)
        return out

    def drf_list(self, ctx, attr, setting, default) -> list:
        owner, expr = self.p.class_attr(ctx, attr)
        if expr is not None:
            if isinstance(expr, (ast.List, ast.Tuple)):
                out = []
                for e in expr.elts:
                    q = self.p.resolve_expr_static(self.p.classes[owner].module, e)
                    out.append(self.p.canonical(q) if q else "<dynamic>")
                return out
            return ["<dynamic>"]
        rf = self.settings.values.get("REST_FRAMEWORK")
        if isinstance(rf, dict) and isinstance(rf.get(setting), (list, tuple)):
            return [x if isinstance(x, str) else "<dynamic>" for x in rf[setting]]
        return list(default)

    def prior_auth_gate(self, entry, chain, mint_names):
        """A mint for request.user behind an authentication requirement re-issues
        a credential for an already-authenticated principal (refresh/exchange)."""
        if not mint_names or not ({"request.user", "self.request.user"} & mint_names):
            return None
        first = chain[0][0]
        line = self.p.functions[first].node.lineno
        for g in entry.gates:
            if g.endswith("login_required") or g in overlay.VIEW_GATE_DECORATORS:
                factor = "prior_authentication:session" + ("+session_mfa_state" if g.endswith("otp_required") else "")
                return dict(function=first, line=line, check=g, catalog_ref=overlay.VIEW_GATE_DECORATORS.get(g),
                            factor=factor, via="framework", relation="guards_mint",
                            detail=f"{g} rejects requests without an authenticated session before the view runs",
                            same_user="shown", project_funcs=[])
        ctx = entry.ctx_class
        if ctx and any(c.startswith("rest_framework.") for c in self.p.mro(ctx)):
            perms = self.drf_list(ctx, "permission_classes", "DEFAULT_PERMISSION_CLASSES",
                                  ["rest_framework.permissions.AllowAny"])
            auths = self.drf_list(ctx, "authentication_classes", "DEFAULT_AUTHENTICATION_CLASSES",
                                  ["rest_framework.authentication.SessionAuthentication",
                                   "rest_framework.authentication.BasicAuthentication"])
            req = [p for p in perms if p.rsplit(".", 1)[-1] in ("IsAuthenticated", "IsAdminUser")]
            if req:
                return dict(function=first, line=line, check=req[0], catalog_ref=None,
                            factor="prior_authentication:" + "|".join(sorted(a.rsplit(".", 1)[-1] for a in auths)),
                            via="framework", relation="guards_mint",
                            detail=f"DRF {req[0].rsplit('.', 1)[-1]} runs before the handler; request.user was "
                                   f"authenticated by {', '.join(a.rsplit('.', 1)[-1] for a in auths)}",
                            same_user="shown", project_funcs=[])
        return None

    def context_notes(self, entry, chain_funcs, mint_api, site) -> list:
        notes = []
        if entry.kind == "middleware":
            notes.append("runs on every request that reaches this middleware")
        if site is not None:
            names = mint_user_names(site, mint_api) or set()
            if site_func_q := site.func:
                names |= self._alias_names(site_func_q, names, site.line) if names else set()
            if {"request.user", "self.request.user"} & names:
                notes.append("mint subject is request.user: re-issues/exchanges a credential for an already "
                             "authenticated principal; how that principal was authenticated is outside this path")
        for fq in chain_funcs:
            for n in self.p.walk_function_body(self.p.functions[fq].node):
                if isinstance(n, ast.Attribute) and n.attr == "session" and isinstance(n.value, (ast.Name,
                                                                                                ast.Attribute)):
                    notes.append(f"{fq} reads request.session: state from an earlier request (e.g. a stashed "
                                 f"login or MFA challenge) may decide this mint; per-request analysis cannot see "
                                 f"checks made in that earlier request")
                    break
        return notes

    def same_user(self, chain, link_sites, i, site, d, an, mint_names) -> str:
        name = subject_name(site.node, d, an)
        if not name:
            return "unproven"
        if d.subject == "form":
            name = "form:" + name
        # reassigned between check and the sink in this function?
        root = name.split(":")[-1].split(".")[0]
        _, stores = an.assigns()
        if i < len(chain) - 1:
            sink_line = link_sites[i][0].line if link_sites[i] else 10 ** 9
        else:
            sink_line = self._current_mint_line
        if any(site.line < ln < sink_line for ln in stores.get(root, [])) and d.subject != "return":
            return "unproven"
        return self.propagate_subject(chain, link_sites, i, name, mint_names)

    def propagate_subject(self, chain, link_sites, i, name, mint_names) -> str:
        prefix = "form:" if name.startswith("form:") else ""
        expr = name[len(prefix):]
        for j in range(i, len(chain) - 1):
            calls = link_sites[j]
            if not calls:
                return "unproven"
            call = calls[0].node
            callee = self.p.functions[chain[j + 1][0]]
            params = list(callee.params)
            if callee.cls and params and params[0] in ("self", "cls") and isinstance(call.func, ast.Attribute):
                params = params[1:]
            root, _, rest = expr.partition(".")
            new = None
            for pos, a in enumerate(call.args):
                if _u(a) == root and pos < len(params):
                    new = params[pos]
            for k in call.keywords:
                if k.arg and _u(k.value) == root:
                    new = k.arg
            if new is None:
                return "unproven"
            expr = new + ("." + rest if rest else "")
        return "shown" if (prefix + expr) in mint_names else "unproven"

    # =========================================================== fingerprints
    def project_closure(self, roots, depth) -> tuple[set, bool]:
        """Project functions transitively called from roots, depth-limited.  (v5) Context-sensitive: a root may
        be (function, receiver class); `self.m()` inside an inherited method then resolves against the
        receiver class, so a subclass override called from a base-class method (template method pattern) is
        part of the closure (v4 resolved it against the defining class and missed the override)."""
        nodes = [r if isinstance(r, tuple) else (r, self.p.functions[r].cls if r in self.p.functions else None)
                 for r in roots]
        # (v5, R8) `hashed`: functions whose own dump is part of the fingerprint.  A helper reached only through
        # calls that the caller's dump inlines (refactor.Inliner) is traversed (its callees count) at the
        # caller's depth but not hashed again: its body is already in the caller's dump.
        hashed = {f for f, _ in nodes}
        seen = set(hashed)
        seen_nodes, frontier, truncated = set(nodes), list(nodes), False
        order = [f for f, _ in nodes]
        for _level in range(depth):
            nxt = []
            queue = list(frontier)
            while queue:
                fq, ctx = queue.pop(0)
                if fq not in self.p.functions:
                    continue
                inl = self.inliner.inlined_calls(fq)
                for site in self.cg.sites(fq):
                    inline_edge = id(site.node) in inl
                    for t, tctx in self.cg.resolve(site, ctx).targets:
                        node = (t, tctx if tctx else (self.p.functions[t].cls if t in self.p.functions else None))
                        if not inline_edge:
                            hashed.add(t)
                        if t not in seen:
                            order.append(t)
                        seen.add(t)
                        if node not in seen_nodes:
                            seen_nodes.add(node)
                            (queue if inline_edge else nxt).append(node)
            frontier = nxt
        for fq, ctx in frontier:
            if fq in self.p.functions:
                for site in self.cg.sites(fq):
                    if any(t not in seen for t, _ in self.cg.resolve(site, ctx).targets):
                        truncated = True
        # (v5 review fix) an edge counts as inline only from the point of view of the caller's OWN transformation;
        # the dump that is hashed is the outermost one, which may not inline a nested helper (its locals shadow a
        # free name of the helper, or the inlining depth budget is used up).  A reached function is covered only
        # when its body is instantiated in the dump of a hashed function; every other one is hashed itself, in
        # discovery order (callers first, so a hashed caller can cover the helpers its own dump inlines).
        covered = set()
        for f in hashed:
            if f in self.p.functions:
                covered |= self.inliner.inlined_bodies(f)
        for f in order:
            if f in hashed or f in covered or f not in self.p.functions:
                continue
            hashed.add(f)
            covered |= self.inliner.inlined_bodies(f)
        self.last_closure_reached = seen
        return hashed, truncated

    # ------------------------------------------------------------------ (v5 review) dependency versions
    def version_gaps(self) -> dict:
        """(v5 review) {package: Gap} for catalogued packages whose declared version (requirements*.txt /
        pyproject.toml) excludes every version the catalog was read in (catalog v3 `verified_package_versions`):
        the catalog's mint lists, hook settings and flow mappings may not describe that version (e.g. dj-rest-auth
        before 3.0 reads REST_AUTH_SERIALIZERS instead of REST_AUTH).  The gap is attached to every path whose
        mint or hook belongs to the package."""
        hit = self.__dict__.get("_version_gaps")
        if hit is not None:
            return hit
        out = {}
        pkg_to_dist = {v: k for k, v in DIST_TO_PACKAGE.items()}
        for pkg, spec in sorted(self.dep_specs.items()):
            dist = pkg_to_dist.get(pkg)
            verified = self.catalog.verified_versions.get(dist or "")
            if not verified:
                continue
            bad = [item for item in spec.split() if version_spec_unverified(item.rsplit("@", 1)[0], verified)]
            if bad:
                g = Gap("dependency_version_not_verified", "-", dist, f"{dist} {' '.join(bad)}: the catalog was read "
                        f"in {', '.join(verified)}; this version's flows, hook settings and mint lists may differ")
                self.gaps.append(g)
                out[pkg] = g
        self._version_gaps = out
        return out

    # ------------------------------------------------------------------ (v5, R5) project hooks
    def hook_bindings(self) -> list:
        """(v5, R5) Project code that a library calls during an auth flow because a setting names it (catalog v3
        `library_hook_settings`: allauth adapters / token strategy / forms, DRF default authentication and
        permission classes, simplejwt / dj-rest-auth / djoser serializers, the social-auth pipeline, the hijack
        permission check, the OAuth2 validator, AUTHENTICATION_BACKENDS for library login flows).
        [dict(row, label, targets=[project qualnames], library=[library symbols], digest, functions, gaps)]"""
        if self._hooks is not None:
            return self._hooks
        out = []
        for row in self.catalog.hook_settings:
            label = row["setting"] + (f"[{row['key']}]" if row.get("key") else "")
            v = self.settings.values.get(row["setting"], _ABSENT)
            if v is not _ABSENT and row.get("key"):
                v = v.get(row["key"], _ABSENT) if isinstance(v, dict) else v
            if v is _ABSENT:
                continue      # library default: library code only
            kind = row["kind"]
            items, gaps = [], []
            # (v5 review fix) a setting that differs between settings modules / branches: every alternative
            for v in flat_values(v):
                if isinstance(v, Dynamic):
                    gaps.append(Gap("hook_setting_not_static", "-", label, f"{v.text}: the project code a library "
                                    f"calls through this setting is not known", 0))
                elif kind in ("class", "function"):
                    items.append(v)
                elif kind in ("class_list", "function_list"):
                    items += list(v) if isinstance(v, (list, tuple)) else [v]
                elif kind == "class_map":
                    items += [x for vv in (v.values() if isinstance(v, dict) else [v]) for x in flat_values(vv)]
                elif kind == "class_list_map":
                    items += [x for vv in (v.values() if isinstance(v, dict) else [v])
                              for vvv in flat_values(vv)
                              for x in (vvv if isinstance(vvv, (list, tuple)) else [vvv])]
            v = self.settings.values.get(row["setting"], _ABSENT)
            if row.get("key") and isinstance(v, dict):
                v = v.get(row["key"], _ABSENT)
            targets, library = [], []
            for x in items:
                if isinstance(x, Dynamic):
                    gaps.append(Gap("hook_setting_not_static", "-", label, f"{x.text}: an item MintMap cannot "
                                    f"evaluate", 0))
                    continue
                if not isinstance(x, str):
                    if x is not None:
                        gaps.append(Gap("hook_setting_not_static", "-", label, f"{x!r} is not a dotted path", 0))
                    continue
                q = self.resolve_dotted(x)
                if q in self.p.classes or q in self.p.functions:
                    targets.append(q)
                elif self.p.module_prefix(q)[0] is not None:
                    gaps.append(Gap("hook_target_unresolved", "-", label, f"{x}: names project code MintMap "
                                    f"cannot find", 0))
                else:
                    library.append(q)
                    top = q.split(".")[0]
                    if q != row.get("default") and top not in overlay.CATALOG_PACKAGES and top not in STDLIB_TOP:
                        # (v5 review fix) code of a package the catalog does not describe runs inside these
                        # library flows (was: treated as known library code, no gap)
                        gaps.append(Gap("hook_target_not_in_catalog", "-", label, f"{x}: library code of a package "
                                        f"the catalog does not describe; the {row['package']} flows run it", 0))
            if not targets and not gaps:
                out.append(dict(row, label=label, targets=[], library=library, digest="", functions=[], gaps=[]))
                continue
            funcs, roots = [], []
            for q in targets:
                if q in self.p.classes:
                    for c in self.p.mro(q):
                        if c in self.p.classes:
                            for mq in sorted(self.p.classes[c].methods.values()):
                                if mq not in funcs:
                                    funcs.append(mq)
                                    roots.append((mq, q))
                else:
                    funcs.append(q)
                    roots.append((q, None))
            closure, trunc = self.project_closure(roots, self.fp_depth)
            reached = sorted(f for f in self.last_closure_reached if f in self.p.functions)
            if trunc:
                gaps.append(Gap("fingerprint_depth_limit", "-", label, f"hook code beyond depth {self.fp_depth}"))
            parts = [f"value={canonical_value(v)}"] + [self.source_dump(q) for q in targets] + \
                ["fn:" + f + ":" + self.inliner.function_dump(f) for f in sorted(closure) if f in self.p.functions]
            for g in gaps:
                self.gaps.append(g)
            out.append(dict(row, label=label, targets=targets, library=library, digest=digest(parts),
                            functions=reached, roots=roots, gaps=gaps))
        self._hooks = out
        return out

    def path_hooks(self, entry, mint_api, site) -> list:
        """(v5, R5) hook bindings that apply to this path: the mint flow's package is in the row's `applies_to`
        (for a library flow, or a project call of a library mint API of that package), or the path's entry is a
        project DRF view that takes the setting's classes from REST_FRAMEWORK (`drf_views`)."""
        pkg = (mint_api.symbol or "").split(".")[0]
        ctx = entry.ctx_class
        drf_view = bool(ctx) and any(c.startswith("rest_framework.") for c in self.p.mro(ctx))
        out = []
        for h in self.hook_bindings():
            if not h["targets"] and not h["gaps"]:
                continue
            if h.get("purposes") and mint_api.purpose not in h["purposes"]:
                continue
            # a project-code call of a mint API runs the hook only where the catalog says so (`project_calls`)
            applies = pkg in h["applies_to"] and (site is None or bool(h.get("project_calls")))
            if not applies and "drf_views" in h["applies_to"] and drf_view and h.get("key"):
                attr = {"DEFAULT_AUTHENTICATION_CLASSES": "authentication_classes",
                        "DEFAULT_PERMISSION_CLASSES": "permission_classes"}.get(h["key"])
                applies = bool(attr) and self.p.class_attr(ctx, attr)[0] is None
            if applies:
                out.append(h)
        return out

    def hook_entry_funcs(self, packages) -> list:
        """(v5, R5) project hook code a library flow of these packages runs (its methods become functions of the
        library-provided entry, so a mint inside a hook, e.g. a token strategy, is linked to the library routes)."""
        out = []
        for h in self.hook_bindings():
            if not h["targets"] or not (set(h["applies_to"]) & packages) or h.get("library_flows_only") or \
                    "drf_views" in h["applies_to"]:
                continue
            for f, c in h.get("roots", []):
                if (f, c, "library_hook") not in out:
                    out.append((f, c, "library_hook"))
        return out

    # ------------------------------------------------------------------ (v5, R7) settings
    def source_dump(self, q: str) -> str:
        """Project class (with its project base classes) or function source, refactor-insensitive."""
        if q in self.p.classes:
            return "|".join(c + ":" + self.inliner.class_dump(c) for c in self.p.mro(q) if c in self.p.classes)
        if q in self.p.functions:
            return q + ":" + self.inliner.function_dump(q)
        return q + ":<not project code>"

    def _project_refs(self, dotted_items, modules=False) -> list:
        """Project classes / functions named by dotted strings; with `modules`, a dotted string naming a project
        module (SESSION_ENGINE) stands for the classes that module defines."""
        out = []
        for x in dotted_items:
            if isinstance(x, str):
                q = self.resolve_dotted(x)
                if q in self.p.classes or q in self.p.functions:
                    out.append(q)
                elif modules and x in self.p.modules:
                    out += [c for c in self.p.classes if c.rsplit(".", 1)[0] == x]
        return sorted(set(out))

    def _rf_value(self, key):
        rf = self.settings.values.get("REST_FRAMEWORK")
        return rf.get(key) if isinstance(rf, dict) else None

    def settings_groups(self) -> list:
        """(v5, R7) One reviewable lock entry per group of global auth settings (instead of hashing them into
        every path).  Each group hashes, per setting, its evaluated value, the statements that assign or change
        it, the conditions that decide it and the assignments those read (SettingsInfo.digest_parts), plus the
        source of the project classes the setting names (middleware, backends, DRF authentication/permission
        classes).  REST_FRAMEWORK counts only its authentication keys (RF_AUTH_KEYS)."""
        if self._settings_groups is not None:
            return self._settings_groups
        sv = self.settings
        all_names = set(sv.values) | set(sv.nodes)
        groups = []

        def mk(gid, names, key_filter=None, sources=(), extra=()):
            names = [n for n in names if n in all_names]
            if not names and not sources and not extra:
                return
            nd = {n: digest(sv.digest_parts(n, key_filter)) for n in names}
            sd = {q: digest([self.source_dump(q)]) for q in sources}
            vals, items = {}, {}
            for n in names:
                v = sv.values.get(n)
                if key_filter is not None and isinstance(v, dict):
                    v = {k: x for k, x in v.items() if k in key_filter}
                vals[n] = _short(canonical_value(v), 400)
                if isinstance(v, (list, tuple)):
                    items[n] = [canonical_value(x) for x in v]
                elif isinstance(v, dict):
                    items[n] = [f"{canonical_value(k)}: {canonical_value(x)}" for k, x in
                                sorted(v.items(), key=lambda kv: repr(kv[0]))]
            for i, e in enumerate(extra):
                nd[f"<{gid}:{i}>"] = digest([e])
            overall = digest([f"{k}={v}" for k, v in sorted(nd.items())] + [f"src:{k}={v}" for k, v in sorted(sd.items())])
            groups.append(dict(id="settings:" + gid, names=names, values=vals, items=items,
                               fingerprint=dict(overall=overall, settings=nd, sources=sd)))
        mw_items = sv.str_list("MIDDLEWARE") + sv.str_list("MIDDLEWARE_CLASSES")
        mk("MIDDLEWARE", ["MIDDLEWARE", "MIDDLEWARE_CLASSES"], sources=self._project_refs(mw_items))
        mk("AUTHENTICATION_BACKENDS", ["AUTHENTICATION_BACKENDS"],
           sources=self._project_refs(sv.str_list("AUTHENTICATION_BACKENDS")),
           extra=() if "AUTHENTICATION_BACKENDS" in all_names else ["<django default ModelBackend>"])
        rf_refs = [x for k in ("DEFAULT_AUTHENTICATION_CLASSES", "DEFAULT_PERMISSION_CLASSES")
                   for x in (self._rf_value(k) or []) if isinstance(self._rf_value(k), (list, tuple))]
        mk("REST_FRAMEWORK", ["REST_FRAMEWORK"], key_filter=RF_AUTH_KEYS, sources=self._project_refs(rf_refs))
        core_refs = []
        for n in CORE_AUTH_CODE_SETTINGS:
            for v in flat_values(sv.values.get(n)):
                core_refs += list(v) if isinstance(v, (list, tuple)) else [v]
        mk("AUTH_CORE", CORE_AUTH_SETTINGS, sources=self._project_refs(core_refs, modules=True))
        apps = [a for a in sv.str_list("INSTALLED_APPS") if a.split(".")[0] in overlay.CATALOG_PACKAGES
                and a.split(".")[0] != "django" or a.startswith("django.contrib.auth")]
        if "INSTALLED_APPS" in all_names:
            mk("INSTALLED_APPS(auth)", [], extra=["apps=" + ",".join(sorted(apps)) +
                                                  ";dynamic=" + ",".join(sorted(d.text for d in
                                                                                sv.dynamic_items("INSTALLED_APPS")))])
        taken = {"MIDDLEWARE", "MIDDLEWARE_CLASSES", "AUTHENTICATION_BACKENDS", "REST_FRAMEWORK", "INSTALLED_APPS"} \
            | set(CORE_AUTH_SETTINGS)
        by_prefixes: dict = {}
        for pkg, prefixes in sorted(overlay.PACKAGE_SETTING_PREFIXES.items()):
            by_prefixes.setdefault(tuple(sorted(prefixes)), []).append(pkg)
        for prefixes, pkgs in sorted(by_prefixes.items(), key=lambda kv: kv[1]):
            names = sorted(n for n in all_names if n not in taken and any(n.startswith(p) for p in prefixes))
            if names:
                mk("package:" + "+".join(sorted(pkgs)), names)
        self._settings_groups = groups
        return groups

    def settings_reads(self, fq: str) -> set:
        """(v5, R7) Settings a project function reads at run time: `settings.X`, `getattr(settings, "X"[, d])`
        with `settings` = django.conf.settings."""
        hit = self._settings_reads.get(fq)
        if hit is not None:
            return hit
        info = self.p.functions[fq]
        out = set()

        def is_settings(e):
            if not isinstance(e, (ast.Name, ast.Attribute)):
                return False
            q = self.p.resolve_expr_static(info.module, e, info)
            return bool(q) and self.p.canonical(q) == "django.conf.settings"
        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Attribute) and n.attr.isupper() and is_settings(n.value):
                out.add(n.attr)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "hasattr") \
                    and len(n.args) >= 2 and is_settings(n.args[0]) and isinstance(n.args[1], ast.Constant) \
                    and isinstance(n.args[1].value, str):
                out.add(n.args[1].value)
        self._settings_reads[fq] = out
        return out

    # ------------------------------------------------------------------ (v5 review) module-level values
    def module_globals_read(self, fq: str) -> list:
        """(v5 review fix) Module-level names (assigned values, not defs/imports of code) that a project function
        reads: its own module's globals, names imported from a project module, `mod.NAME` of an imported project
        module.  [(module, name)]"""
        memo = self.__dict__.setdefault("_globals_read", {})
        if fq in memo:
            return memo[fq]
        info = self.p.functions[fq]
        mod = self.p.modules[info.module]
        out = set()

        def module_value(m2, name):
            mm = self.p.modules.get(m2)
            return mm is not None and name in mm.assigns and name not in mm.defs

        for n in self.p.walk_function_body(info.node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in info.local_vars or n.id in info.local_imports:
                    continue
                if module_value(info.module, n.id):
                    out.add((info.module, n.id))
                elif n.id in mod.symbols:
                    q = self.p.canonical(mod.symbols[n.id])
                    m2, rest = self.p.module_prefix(q) if q else (None, [])
                    if m2 and len(rest) == 1 and module_value(m2, rest[0]):
                        out.add((m2, rest[0]))
            elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load) and isinstance(n.value, ast.Name) \
                    and n.value.id not in info.local_vars:
                q = self.p.resolve_expr_static(info.module, n.value, info)
                q = self.p.unalias(q) if q else None
                if q in self.p.modules and module_value(q, n.attr):
                    out.add((q, n.attr))
        memo[fq] = sorted(out)
        return memo[fq]

    def module_value_statements(self, modname: str, name: str) -> tuple:
        """(v5 review fix) (statement dumps, settings read) for a module-level name: every module-level
        statement that assigns or changes it (with the tests of the `if` blocks around it), and the settings
        those statements read (`settings.X`, `getattr(settings, "X", d)`)."""
        memo = self.__dict__.setdefault("_global_stmts", {})
        key = (modname, name)
        if key in memo:
            return memo[key]
        mod = self.p.modules[modname]
        dumps, reads = [], set()

        def is_settings(e):
            if not isinstance(e, (ast.Name, ast.Attribute)):
                return False
            q = self.p.resolve_expr_static(modname, e)
            return bool(q) and self.p.canonical(q) == "django.conf.settings"

        def touches(st):
            if isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                for t in targets:
                    for x in ast.walk(t):
                        if isinstance(x, ast.Name) and x.id == name and isinstance(x.ctx, ast.Store):
                            return True
                    root = t
                    while isinstance(root, (ast.Subscript, ast.Attribute)):
                        root = root.value
                    if isinstance(root, ast.Name) and root.id == name:
                        return True
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and \
                    isinstance(st.value.func, ast.Attribute):
                root = st.value.func.value
                while isinstance(root, (ast.Subscript, ast.Attribute, ast.Call)):
                    root = root.func if isinstance(root, ast.Call) else root.value
                return isinstance(root, ast.Name) and root.id == name
            return False

        def walk(body, tests):
            for st in body:
                if touches(st):
                    dumps.append(normalize(st) + "".join("|if:" + normalize(t) for t in tests))
                    for x in [st] + list(tests):
                        for n in ast.walk(x):
                            if isinstance(n, ast.Attribute) and n.attr.isupper() and is_settings(n.value):
                                reads.add(n.attr)
                            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and \
                                    n.func.id in ("getattr", "hasattr") and len(n.args) >= 2 and \
                                    is_settings(n.args[0]) and isinstance(n.args[1], ast.Constant) and \
                                    isinstance(n.args[1].value, str):
                                reads.add(n.args[1].value)
                if isinstance(st, ast.If):
                    walk(st.body, tests + (st.test,))
                    walk(st.orelse, tests + (st.test,))
                elif isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                    walk(st.body, tests)
                    for h in st.handlers:
                        walk(h.body, tests)
                    walk(st.orelse, tests)
                    walk(st.finalbody, tests)
                elif isinstance(st, (ast.With, ast.For, ast.While)):
                    walk(st.body, tests)
        walk(mod.tree.body, ())
        memo[key] = (dumps, reads)
        return memo[key]

    def path_settings_deps(self, entry, mint_api, checks, funcs, site) -> set:
        """(v5, R7) The settings this path's behaviour depends on SPECIFICALLY (hashed into its `settings`
        component; everything else is in the settings group entries):
        * `group:AUTHENTICATION_BACKENDS` when a check on the path calls authenticate() (directly or through a
          catalog form / serializer that does);
        * `rf:DEFAULT_PERMISSION_CLASSES` / `rf:DEFAULT_AUTHENTICATION_CLASSES` for a DRF view that takes its
          permission / authentication classes from REST_FRAMEWORK (authentication classes only when a
          permission requires an authenticated user or the mint is for request.user);
        * `setting:X` for every `settings.X` read by project code on the path (path functions, callees, check
          code, hooks) and for settings the catalog names for the mint's flow (catalog v3
          `mint_setting_dependencies`)."""
        deps = set()
        for r in checks:
            if r["check"] in AUTHENTICATE_CALLS or r.get("catalog_ref") in AUTHENTICATING_FORM_REFS:
                deps.add("group:AUTHENTICATION_BACKENDS")
        ctx = entry.ctx_class
        if ctx and any(c.startswith("rest_framework.") for c in self.p.mro(ctx)):
            perm_owner, _ = self.p.class_attr(ctx, "permission_classes")
            auth_owner, _ = self.p.class_attr(ctx, "authentication_classes")
            perms = self.drf_list(ctx, "permission_classes", "DEFAULT_PERMISSION_CLASSES",
                                  ["rest_framework.permissions.AllowAny"])
            if perm_owner is None:
                deps.add("rf:DEFAULT_PERMISSION_CLASSES")
            needs_auth = any(p.rsplit(".", 1)[-1] != "AllowAny" for p in perms) or \
                any(r.get("factor", "").startswith("prior_authentication") for r in checks)
            if auth_owner is None and needs_auth:
                deps.add("rf:DEFAULT_AUTHENTICATION_CLASSES")
        for fq in funcs:
            if fq in self.p.functions:
                deps |= {"setting:" + x for x in self.settings_reads(fq)}
        for name in self.catalog.mint_setting_deps.get(mint_api.ref or "", []):
            deps.add("setting:" + name)
        if entry.kind == "middleware":
            # the conditions under which this middleware is in MIDDLEWARE (e.g. an env-var default) decide
            # whether the path exists at run time
            mw = entry.id.split(":", 1)[1]
            for name in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
                if (name, mw) in self.settings.item_deps:
                    deps.add(f"item:{name}:{mw}")
        return deps

    def settings_component(self, deps) -> str:
        parts = []
        for d in sorted(deps):
            kind, _, name = d.partition(":")
            if kind == "group":
                g = next((g for g in self.settings_groups() if g["id"] == "settings:" + name), None)
                parts.append(d + "=" + (g["fingerprint"]["overall"] if g else "<absent>"))
            elif kind == "item":
                sname, _, item = name.partition(":")
                parts.append(d + "=" + digest(sorted(self.settings.item_deps.get((sname, item), ()))))
            elif kind == "rf":
                v = self._rf_value(name)
                parts.append(d + "=" + digest(self.settings.digest_parts("REST_FRAMEWORK", {name}) + [
                    self.source_dump(q) for q in self._project_refs(v if isinstance(v, (list, tuple)) else [])]))
            else:
                parts.append(d + "=" + digest(self.settings.digest_parts(name)))
        return digest(parts)

    def fingerprint(self, entry: Entry, slice_funcs, check_records, mint_ref, packages, extra_code=(), label="",
                    slice_nodes=None,
                    extra_check_roots=(), check_config=(), mint_api=None, site=None):
        gaps = []
        code = []
        if entry.route is not None and entry.route.node is not None:
            code.append("route:" + entry.route.pattern + ":" + normalize(entry.route.node))
        if entry.route is not None:
            # (v4) other definitions of the same pattern and view that run other code
            main = normalize(entry.route.node) if entry.route.node is not None else ""
            code += sorted({"route-variant:" + v.pattern + ":" + normalize(v.node) for v in entry.variants
                            if v.node is not None and normalize(v.node) != main})
            # (v3) project URL helpers that built the route and the view that dispatches to it
            hqs = []
            for r in [entry.route] + entry.variants:
                for hq in list(r.helpers) + ([r.dispatcher] if r.dispatcher else []):
                    if hq not in hqs:
                        hqs.append(hq)
            for hq in hqs:
                if hq in self.p.functions:
                    code.append("urlfn:" + hq + ":" + normalize(self.p.functions[hq].node))
            sb = entry.route.shadowed_by or entry.route.library_shadowed.get(mint_ref)
            if sb:
                code.append(f"shadowed_by:{sb['pattern']}|{sb['target']}")
        code += entry.extra_code
        library_flow = any(x.startswith("library_mint:") for x in extra_code)
        if entry.ctx_class:
            for c in self.p.mro(entry.ctx_class):
                if c in self.p.classes:
                    # a library-provided flow can be altered by ANY project override
                    # (get_form_class, get_success_url, process_request ...), so hash
                    # whole classes there; project mint paths hash attributes only and
                    # get their methods through the path slice.
                    node = self.p.classes[c].node
                    code.append("class:" + c + ":" + (self.inliner.class_dump(c) if library_flow
                                                       else class_shell(node)))
                else:
                    code.append("libbase:" + c)
        for fq in sorted(slice_funcs):
            code.append("fn:" + fq + ":" + self.inliner.function_dump(fq))
        code.extend(extra_code)
        # project functions called from the path (they may compute the user, the
        # token or a condition) even when they do not lead to the mint
        callee_roots = sorted(slice_nodes, key=str) if slice_nodes else sorted(slice_funcs)
        if library_flow and entry.ctx_class:
            # (v5) a library flow inherited by a project class runs the class's project methods (overrides and
            # hooks): their callees are part of what the path depends on
            callee_roots = callee_roots + [(mq, entry.ctx_class) for c in self.p.mro(entry.ctx_class)
                                           if c in self.p.classes
                                           for mq in sorted(self.p.classes[c].methods.values())]
        # (v5 review fix) project classes / functions handed to the library flow (as_view kwargs, class
        # attributes of a view inheriting library code): the library may call any of their methods
        callee_roots = callee_roots + [n for n in self.injected_methods(entry) if n not in callee_roots]
        callee_set, callee_trunc = self.project_closure(callee_roots, self.fp_depth)
        callee_listed = {f for f in self.last_closure_reached if f in self.p.functions}  # incl. inlined helpers
        callees = ["fn:" + f + ":" + self.inliner.function_dump(f)
                   for f in sorted(callee_set - set(slice_funcs)) if f in self.p.functions]
        if callee_trunc:
            gaps.append(Gap("fingerprint_depth_limit", "-", label, f"callees beyond depth {self.fp_depth}"))
        # project code implementing recognised checks, PLUS every project form/serializer validation
        # method used on the path and every project function behind an unrecognized check (P2), whether
        # or not it is recognised as a check
        roots = sorted({f for r in check_records for f in r.get("project_funcs", []) if f in self.p.functions}
                       | {f for f in extra_check_roots if f in self.p.functions})
        cls_roots = sorted({f for r in check_records for f in r.get("project_funcs", []) if f in self.p.classes})
        closure, truncated = self.project_closure(roots, self.fp_depth)
        check_listed = {f for f in self.last_closure_reached if f in self.p.functions}
        checks = ["fn:" + f + ":" + self.inliner.function_dump(f) for f in sorted(closure)]
        for c in cls_roots:
            checks.append("cls:" + c + ":" + self.inliner.class_dump(c))
        # (v4) module constants / local values that configure a check (e.g. the options dict of jwt.decode)
        checks += ["config:" + c for c in check_config]
        if truncated:
            gaps.append(Gap("fingerprint_depth_limit", "-", label, f"check code beyond depth {self.fp_depth}"))
        cat = [mint_ref or "none", self.catalog.entry_digest(mint_ref)]
        for r in check_records:
            if r["catalog_ref"]:
                cat.append(f"{r['catalog_ref']}:{self.catalog.entry_digest(r['catalog_ref'])}")
        deps = sorted(f"{pkg}={self.dep_specs[pkg]}" for pkg in packages if pkg in self.dep_specs)
        hooks = self.path_hooks(entry, mint_api, site) if mint_api is not None else []
        hook_funcs = {f for h in hooks for f in h["functions"]}
        sdeps = self.path_settings_deps(entry, mint_api, check_records,
                                        set(slice_funcs) | callee_listed | check_listed | hook_funcs, site) \
            if mint_api is not None else set()
        for h in hooks:
            sdeps.add("setting:" + h["setting"])
            gaps += h["gaps"]
        # (v5 review fix) module-level values the path's code reads (a flag computed from a setting at import
        # time, a module constant that gates a mint): their statements are part of `code`, the settings they read
        # are dependencies of the path
        gl = set()
        for f in set(slice_funcs) | callee_listed | check_listed | hook_funcs:
            if f in self.p.functions:
                gl |= set(self.module_globals_read(f))
        for m, n in sorted(gl):
            dumps, reads = self.module_value_statements(m, n)
            code.append(f"global:{m}.{n}:" + digest(dumps))
            if mint_api is not None:
                sdeps |= {"setting:" + x for x in reads}
        comps = dict(code=digest(code), callees=digest(callees), checks=digest(checks),
                     settings=self.settings_component(sdeps), catalog=digest(sorted(set(cat))),
                     deps=digest(deps),
                     # (v5, R5) project code that the library flow calls through a setting (adapters, strategies,
                     # serializers, pipeline functions, permission/authentication classes, backends)
                     hooks=digest(sorted(f"{h['label']}={h['digest']}" for h in hooks)))
        overall = digest([f"{k}={v}" for k, v in sorted(comps.items())])
        return dict(overall=overall, components=comps, fingerprint_depth=self.fp_depth,
                    settings_dependencies=sorted(sdeps),
                    hooks=[dict(setting=h["label"], project_code=h["targets"], functions=h["functions"])
                           for h in hooks],
                    path_functions=sorted(slice_funcs), callee_functions=sorted(callee_listed - set(slice_funcs)),
                    check_functions=sorted(check_listed)), gaps

    # ================================================================== paths
    def possible_mint(self, site) -> bool:
        """Unresolved call that may be a mint: distinctive name, or login/alogin
        called as a bare (parameter/local) name or with `request` first."""
        if site.is_property:
            return False
        if site.leaf in self.distinctive_mint_leaves:
            return True
        if site.leaf in ("login", "alogin"):
            call = site.node
            if isinstance(call.func, ast.Name):
                return True
            return bool(call.args) and _u(call.args[0]) in ("request", "self.request")
        return False

    def call_key_text(self, site) -> str:
        """(v5, R8) the callee text of a call site with the function's local variables canonicalised (gap keys)."""
        node = site.node.func if isinstance(site.node, ast.Call) else site.node
        return canonical_text(self.p.functions[site.func].node, node)

    def path_gaps(self, slice_nodes) -> list:
        out = []
        relevant = self.project_callable_names | self.check_leaves | self.distinctive_mint_leaves
        for fq, ctx in sorted(slice_nodes, key=str):
            for site in self.cg.sites(fq):
                res = self.cg.resolve(site, ctx)
                if res.unresolved and site.leaf in relevant and site.leaf not in GENERIC_LEAVES and \
                        site.leaf not in self.catalog.check_method_names:
                    out.append(Gap("unresolved_call_on_path", self.p.file_of(fq), fq, site.text, site.line,
                                   key_detail=self.call_key_text(site)))
        return out

    def make_path(self, entry: Entry, mint_api: MintAPI, purpose_note, site=None, site_func=None, chains=(),
                  truncated=False, graph=None, candidate=None):
        if site is not None:
            ordinal = sum(1 for s in self.cg.sites(site_func[0])
                          if s.line < site.line and self._mint_symbol(s, site_func[1]) == mint_api.symbol)
            mint_site_id = f"{site_func[0]}:{mint_api.symbol}:{mint_api.ref}#{ordinal}"
        else:
            mint_site_id = f"library:{mint_api.symbol}:{mint_api.ref}"
        pid = hashlib.sha256(f"{entry.id}||{mint_site_id}".encode()).hexdigest()[:16]
        path_gaps = []
        roles = {(f, c): role for f, c, role in entry.funcs}
        all_records, per_chain_best = [], []
        slice_nodes = set()
        for chain, link_sites in chains:
            slice_nodes |= set(chain)
            recs = self.chain_evidence(chain, link_sites, site, mint_api, entry, roles.get(chain[0], "http_handler"))
            all_records.append(recs)
            best = {}
            for r in recs:
                for f in r["factor"].split("+"):
                    rank = RELATION_RANK[r["relation"]] + (0.5 if r["same_user"] == "shown" else 0)
                    best[f] = max(best.get(f, 0), rank)
            per_chain_best.append(best)
        if truncated:
            path_gaps.append(Gap("chain_enumeration_truncated", self.p.file_of(site_func[0]) if site_func else "-",
                                 entry.id, f">{self.chain_limit} call chains"))
        factors = {}
        if per_chain_best:
            all_f = set().union(*[set(b) for b in per_chain_best])
            for f in sorted(all_f):
                factors[f] = min(b.get(f, 0) for b in per_chain_best)
        merged = {}
        for recs in all_records:
            for r in recs:
                k = (r["function"], r["line"], r["check"])
                if k not in merged or RELATION_RANK[r["relation"]] < RELATION_RANK[merged[k]["relation"]]:
                    merged[k] = r
        checks = sorted(merged.values(), key=lambda r: (r["function"], r["line"], r["check"]))
        path_gaps += self.path_gaps(slice_nodes)
        # (v5) gaps about the entry itself (e.g. an unresolved base of the routed class) and (R6) unresolved
        # bases of every class whose methods run on this path
        path_gaps += entry.gaps
        path_gaps += self.class_base_gaps(sorted({c for _, c in slice_nodes if c} |
                                                 {self.p.functions[f].cls for f, _ in slice_nodes
                                                  if f in self.p.functions and self.p.functions[f].cls}))
        for dq in sorted({r.dispatcher for r in ([entry.route] + entry.variants if entry.route else [])
                          if r.dispatcher}):
            # (v3) the view is called by a dispatcher view that received it in the route kwargs
            path_gaps.append(Gap("view_dispatcher_not_analyzed", self.p.file_of(dq) if dq in self.p.functions
                                 else "-", dq, "calls views passed in its routes' extra kwargs; checks it makes "
                                               "before the call are not linked to the paths of those views"))
        vmethods = self.path_validation_methods(entry, chains, slice_nodes)
        path_gaps += self.class_base_gaps(sorted({ft for _, ft in vmethods if ft}))
        leaf_groups = [r.get("unrecognized", []) for r in checks]
        config = {c for r in checks for c in r.get("config_src", [])}
        arg_gaps = [r.get("arg_gaps", []) for r in checks]
        for mq, ft in vmethods:
            leaf_groups += [d.unrecognized for _, d in self.function_checks(mq, ft)]
            for _, d in self.function_checks(mq, ft):
                config |= set(d.config_src)
                arg_gaps.append(d.arg_gaps)
        # (v4) a check argument MintMap could not evaluate (e.g. jwt.decode(options=<runtime value>))
        path_gaps += _merge_gaps(arg_gaps)
        leaves = _merge_leaves(leaf_groups)
        for leaf in leaves:
            path_gaps.append(Gap("unrecognized_check_call", self.p.file_of(leaf["function"]), leaf["function"],
                                 f"{leaf['target']} ({leaf['reason']})", leaf["line"]))
        extra_roots = [mq for mq, _ in vmethods] + [leaf["target"] for leaf in leaves]
        packages = {mint_api.symbol.split(".")[0], "django"} | {r["check"].split(".")[0] for r in checks}
        slice_funcs = sorted({f for f, _ in slice_nodes})
        extra = []
        if site is None:
            extra.append("library_mint:" + mint_api.symbol + ":" + (mint_api.ref or ""))
        if mint_api.kind == HEURISTIC_KIND and mint_api.symbol in self._heur_models:
            # (v5 review) the field default and its generator decide the credential: part of the path's code
            extra += self.cred.default_field_code(self._heur_models[mint_api.symbol])
        fp, fgaps = self.fingerprint(entry, slice_funcs, checks, mint_api.ref, packages, extra,
                                     label=f"{entry.id} -> {mint_site_id}", extra_check_roots=extra_roots,
                                     check_config=sorted(config), slice_nodes=slice_nodes, mint_api=mint_api,
                                     site=site)
        path_gaps += fgaps
        vg = self.version_gaps()
        if vg:
            pk = {mint_api.symbol.split(".")[0]} | {h["package"] for h in self.path_hooks(entry, mint_api, site)}
            path_gaps += [vg[x] for x in sorted(pk) if x in vg]
        status = self._status(entry, site, factors, checks, bool(leaves))
        context = self.context_notes(entry, slice_funcs, mint_api, site)
        for h in fp.get("hooks", []):
            if h["project_code"]:
                context.append(f"the library flow calls project code named by {h['setting']}: "
                               f"{', '.join(h['project_code'])} (fingerprinted in the `hooks` component)")
        # (v3, P5) first-match URL resolution: a literal-equal earlier route makes this path unreachable
        shadow, maybe_shadow, library_route = None, None, None
        if entry.route is not None:
            r = entry.route
            if site is None and mint_api.ref in r.library_routes:
                library_route = r.library_routes[mint_api.ref][0]
            if r.kind in ENDPOINT_KINDS or site is not None:
                shadow, maybe_shadow = r.shadowed_by, r.may_be_shadowed_by
            if site is None and not shadow:
                shadow = r.library_shadowed.get(mint_api.ref)
        status_if_reachable = None
        if shadow:
            status_if_reachable, status = status, SHADOWED_STATUS
            context.append(f"route shadowed by the earlier pattern {shadow['pattern']!r} -> {shadow['target']} "
                           f"({shadow['file']}:{shadow['line']}): not reachable through this route")
        elif maybe_shadow:
            context.append(f"may be shadowed by the earlier conditional pattern {maybe_shadow['pattern']!r} -> "
                           f"{maybe_shadow['target']} ({maybe_shadow['file']}:{maybe_shadow['line']})")
        shortest = min((c for c, _ in chains), key=len) if chains else []
        site_info = None
        if site is not None:
            site_info = dict(file=self.p.file_of(site_func[0]), function=site_func[0], line=site.line, call=site.text)
        return dict(
            id=pid,
            entry=dict(kind=entry.kind, id=entry.id, view=entry.view,
                       route=entry.route.describe() if entry.route else None,
                       **({"route_variants": [v.describe() for v in entry.variants]} if entry.variants else {}),
                       functions=[f"{f}" + (f" [ctx {c}]" if c and not f.startswith(c + ".") else "") + f" ({role})"
                                  for f, c, role in entry.funcs], gates=entry.gates, notes=entry.notes),
            mint=dict(api=mint_api.symbol if site is not None else (mint_api.ref or mint_api.symbol),
                      kind=mint_api.kind,
                      provided_via=None if site is not None else mint_api.symbol,
                      catalog_ref=mint_api.ref, purpose=mint_api.purpose,
                      purpose_basis=mint_api.purpose_basis, purpose_note=purpose_note,
                      provided_by="library" if site is None else "project_code",
                      library_source=mint_api.source_location if site is None else None, site=site_info,
                      library_route=library_route),
            chain=[f for f, _ in shortest], chains_analyzed=len(chains),
            shadowed=bool(shadow),
            evidence=dict(status=status, context=context, status_if_reachable=status_if_reachable,
                          shadowed_by=shadow,
                          factors={f: _rank_name(v) for f, v in factors.items()}, checks=[
                {k: v for k, v in r.items() if k not in ("project_funcs", "unrecognized", "config_src", "arg_gaps")}
                for r in checks],
                          unrecognized_checks=leaves,
                          validation_methods=sorted({mq for mq, _ in vmethods}),
                          hooks=fp.get("hooks", [])),
            gaps=sorted({g.key for g in path_gaps}),
            # (v5 review) two flags: the evidence/inventory analysis (every gap except the callee-closure depth
            # limit) and the fingerprint (callees beyond the depth limit are not hashed).  One flag for both was
            # false on 287 of 294 Zulip paths, almost always only because of the depth limit
            analysis_complete=not [g for g in path_gaps if g.type != "fingerprint_depth_limit"],
            fingerprint_complete=not [g for g in path_gaps if g.type == "fingerprint_depth_limit"],
            fingerprint=fp,
            # (v6) confirmed: catalog API / library flow / R3 heuristic / principal session key; candidate: see
            # candidates.py (kept out of `paths`, one review entry per site)
            tier="candidate" if candidate is not None else "confirmed",
            **({"candidate": candidate} if candidate is not None else {}),
        ), path_gaps

    def _mint_symbol(self, s, ctx):
        res = self.cg.resolve(s, ctx)
        m = self.mint_of(s, res)
        return m[0][0].symbol if m else None

    @staticmethod
    def _status(entry, site, factors, checks, unrecognized=False):
        """Status from RECOGNISED checks; unrecognized verification-looking calls never make a path
        'guarded', but they replace the 'no check found' label."""
        if site is None:
            return "library_flow_checks_not_analyzed"
        guarding = [f for f, v in factors.items()
                    if v >= RELATION_RANK["guards_mint"] and not is_unrecognized_factor(f)]
        if any(_verified_factor(f) for f in guarding):
            return "check_guards_mint"
        if guarding:
            return "guard_relies_on_unverified_check"
        rels = {r["relation"] for r in checks if not all_unrecognized(r["factor"])}
        if rels & {"result_ignored", "condition_always_truthy"}:
            return "check_result_not_enforced"
        if rels:
            return "check_present_relationship_unproven"
        if unrecognized or any(all_unrecognized(r["factor"]) for r in checks):
            return "unrecognized_check_present"
        return "no_check_found_in_analyzed_code"

    # ==================================================================== run
    def run(self) -> dict:
        roots, rgaps = find_root_urlconfs(self.p, self.settings.values)
        self.gaps += rgaps
        # (v5 review fix) URLconfs chosen per request (`request.urlconf = "x.urls"`, `set_urlconf(...)`, settings
        # such as PUBLIC_SCHEMA_URLCONF) are roots too
        self.runtime_urlconfs = self.find_runtime_urlconfs()
        for m in sorted(self.runtime_urlconfs):
            if m not in roots:
                roots.append(m)
        up = UrlConfParser(self.p, self.settings.values, url_builders=self.catalog.url_builders)
        for r in roots:
            up.parse_root(r)
        # (v5 review fix) a URLconf no root reaches is still parsed (as a root of its own) so that its routes and
        # library mints are in the inventory; every path of it carries the urlconf_not_reached_from_root gap
        self.unreached_roots = {}
        while True:
            todo = [m for m in sorted(self.p.modules) if m not in up.reached and up.has_urlpatterns(m)]
            if not todo:
                break
            m = todo[0]
            g = Gap("urlconf_not_reached_from_root", self.p.modules[m].path, m, "urlpatterns")
            self.unreached_roots[m] = g
            up.parse_root(m)
        mark_shadowing(up.routes, self.catalog.library_url_routes)
        self.gaps += up.gaps
        for dq in sorted(up.dispatchers):
            self.gaps.append(Gap("view_dispatcher_not_analyzed", self.p.file_of(dq) if dq in self.p.functions else "-",
                                 dq, "calls views passed in its routes' extra kwargs; checks it makes before the "
                                     "call are not linked to the paths of those views"))
        self.gaps += list(self.unreached_roots.values())
        if not roots:
            self.gaps.append(Gap("no_urlconf", "-", "ROOT_URLCONF", "no root URLconf found"))
        entries = self.build_entries(up.routes)
        entries += self.asgi_entries()
        paths, all_path_gaps = [], []
        reached_mints = set()
        reachable_funcs = set()
        for e in entries:
            for api, note in e.library_mints:
                p, g = self.make_path(e, api, note, chains=[])
                paths.append(p)
                all_path_gaps += g
            if not e.funcs:
                continue
            starts = [(f, c) for f, c, _ in e.funcs]
            graph = self.traverse(starts)
            known = {(api.symbol, api.ref) for api, _ in e.library_mints}
            invoked = [(api, note) for api, note in self.invoked_library_views(graph)
                       if (api.symbol, api.ref) not in known]
            extra = []
            if invoked:
                # (v6) a library flow run from project code runs the project hooks its settings name, as when the
                # route points at the library view (R5): the hooks are entry functions of this entry too
                extra += [f for f in self.hook_entry_funcs({a.symbol.split(".")[0] for a, _ in invoked})
                          if f not in e.funcs]
            if extra:
                e.funcs += extra
                starts = [(f, c) for f, c, _ in e.funcs]
                graph = self.traverse(starts)
            reachable_funcs |= set(graph)
            for api, note in invoked:
                p, g = self.make_path(e, api, note, chains=[])
                paths.append(p)
                all_path_gaps += g
            for node in sorted(graph, key=str):
                fq, ctx = node
                for site in self.cg.sites(fq):
                    res = self.cg.resolve(site, ctx)
                    mints = self.mint_of(site, res)
                    if not mints and self.possible_library_mint(site, res):
                        self.gaps.append(Gap("library_call_may_mint", self.p.file_of(fq), fq,
                                             f"{res.library} (catalog mint name, symbol not mapped)", site.line))
                    for api, note in mints:
                        reached_mints.add((fq, site.line, api.symbol))
                        chains, trunc = self.chains(graph, starts, node)
                        p, g = self.make_path(e, api, note, site=site, site_func=node, chains=chains,
                                              truncated=trunc, graph=graph)
                        paths.append(p)
                        all_path_gaps += g
                for site, api, note in self.extra_mint_sites(fq):
                    reached_mints.add((fq, site.line, api.symbol))
                    chains, trunc = self.chains(graph, starts, node)
                    p, g = self.make_path(e, api, note, site=site, site_func=node, chains=chains,
                                          truncated=trunc, graph=graph)
                    paths.append(p)
                    all_path_gaps += g
                # (v6) candidate tier: statement sites of this function, and calls handing the request to an
                # uncatalogued authentication-package function
                for site, api, note, cinfo in self.candidate_sites(fq, ctx):
                    reached_mints.add((fq, site.line, api.symbol))
                    chains, trunc = self.chains(graph, starts, node)
                    p, _g = self.make_path(e, api, note, site=site, site_func=node, chains=chains,
                                           truncated=trunc, graph=graph, candidate=cinfo)
                    paths.append(p)     # (v6) a candidate's gaps stay on its own entry, not in the global list
        paths += self.unrouted_paths(reached_mints, all_path_gaps)
        paths += self.minting_subclass_paths(entries, [])
        paths = self.group_shared_heuristic_sites(paths)
        cand_paths = [p for p in paths if p.get("tier") == "candidate"]
        paths = [p for p in paths if p.get("tier") != "candidate"]
        candidates = self.group_candidate_sites(cand_paths)
        self.global_unresolved(reachable_funcs)
        # dedupe identical path ids (same route listed twice)
        uniq = {}
        for p in paths:
            uniq.setdefault(p["id"], p)
        paths = sorted(uniq.values(), key=lambda p: (p["entry"]["id"], p["mint"]["api"], p["id"]))
        gaps = {g.key: g for g in self.gaps + all_path_gaps}
        gap_list = sorted(gaps.values(), key=lambda g: g.key)
        by_type = {}
        for g in gap_list:
            by_type[g.type] = by_type.get(g.type, 0) + 1
        routes_by_kind = {}
        for r in up.routes:
            routes_by_kind[r.kind] = routes_by_kind.get(r.kind, 0) + 1
        coverage = dict(
            files_seen=len(self.p.files_seen), files_parsed=len(self.p.files_seen) - len(self.p.parse_failures),
            parse_failures=self.p.parse_failures, excluded_dirs=sorted(self.p.excluded_dirs),
            test_code=dict(included=self.p.include_tests, excluded_files=len(self.p.test_files_excluded),
                           excluded_by_reason=_count_by(self.p.test_files_excluded, "reason"),
                           excluded_dirs=sorted({os.path.dirname(t["file"]) for t in self.p.test_files_excluded
                                                 if t["reason"].startswith("in a tests/")}),
                           reincluded=self.p.test_files_reincluded),
            functions_indexed=len(self.p.functions), classes_indexed=len(self.p.classes),
            # (v5, R1) sys.path-like roots used for module names; modules named through them (no __init__.py chain)
            source_roots={(os.path.relpath(r, self.p.root) if r != self.p.root else "."): why
                          for r, why in self.p.source_roots.items()},
            namespace_modules=len(self.p.namespace_modules), module_aliases=dict(sorted(self.p.module_aliases.items())),
            settings_modules=self.settings.modules, root_urlconfs=roots, routes_total=len(up.routes),
            routes_by_kind=routes_by_kind, entries_total=len(entries),
            routes_shadowed=sum(1 for r in up.routes if r.shadowed_by),
            routes_may_be_shadowed=sum(1 for r in up.routes if r.may_be_shadowed_by),
            library_subroutes_shadowed=sum(len(r.library_shadowed) for r in up.routes),
            paths_total=len(paths), paths_shadowed=sum(1 for p in paths if p["shadowed"]),
            paths_unrouted=sum(1 for p in paths if p["entry"]["kind"] == "unrouted"),
            authentication_backends_factor=self.backend_factor,
            dependency_files=self.dep_files, dependency_specs=self.dep_specs,
            gaps_by_type=by_type, gaps=[g.as_dict() for g in gap_list],
            limits=dict(chain_limit=self.chain_limit, fingerprint_depth=self.fp_depth),
            custom_credentials=self.custom_credential_summary(),
            candidates=self.candidate_summary(candidates),
        )
        return dict(
            tool=dict(name="mintmap", version=TOOL_VERSION, catalog_path=os.path.basename(self.catalog.path),
                      library_paths=self.lib.roots,
                      catalog_sha256=self.catalog.sha256, overlay_sha256=_file_sha(overlay.__file__),
                      catalog_entries_unmapped=self.catalog.unmapped_refs,
                      overlay_entries_skipped=self.catalog.skipped_overlay),
            project=os.path.basename(self.p.root),
            routes=[r.describe() for r in sorted(up.routes, key=lambda r: (r.pattern, r.target))],
            derived_mint_wrappers=self.derived_wrappers(),
            settings_groups=self.settings_groups(),
            paths=paths, candidates=candidates, coverage=coverage)

    HEURISTIC_GROUP_MIN = 6

    def group_shared_heuristic_sites(self, paths) -> list:
        """(v5 review) Review cost of R3 on large projects: a heuristic credential site (a model creation with a
        credential default, a token generator) that MORE than HEURISTIC_GROUP_MIN - 1 routed entry points reach is
        shared infrastructure; one path per entry repeated the same evidence and turned every edit of a shared
        helper into dozens of findings.  Such a site becomes ONE lock entry (`entry.kind = heuristic_site`) whose
        fingerprint combines every member path's components keyed by entry id (a new or lost entry point, or a
        change on any member path, changes it: one finding), whose factors are the weakest over the members, and
        whose gaps are their union.  Catalog mints and sites reached from fewer entry points keep one path per
        entry."""
        groups: dict = {}
        for p in paths:
            if p["mint"]["kind"] != HEURISTIC_KIND or p["entry"]["kind"] == "unrouted" or p.get("tier") == "candidate":
                continue
            site = p["mint"].get("site") or {}
            # (v6) line-independent: a line inserted above the site must not replace the entry
            groups.setdefault((p["mint"]["api"], site.get("function"), None), []).append(p)
        drop, add = set(), []
        for key, ps in sorted(groups.items(), key=lambda kv: str(kv[0])):
            ids = sorted({p["entry"]["id"] for p in ps})
            if len(ids) < self.HEURISTIC_GROUP_MIN:
                continue
            drop |= {id(p) for p in ps}
            add.append(self._grouped_path(key, ps, ids))
        if not drop:
            return paths
        return [p for p in paths if id(p) not in drop] + add

    def _grouped_path(self, key, ps, ids) -> dict:
        from .lockfile import STATUS_RANK, FACTOR_RANK
        api, func, line = key
        ps = sorted(ps, key=lambda p: (p["entry"]["id"], p["id"]))
        comps = {}
        for name in ps[0]["fingerprint"]["components"]:
            comps[name] = digest(sorted(f"{p['entry']['id']}={p['fingerprint']['components'].get(name, '')}"
                                        for p in ps))
        comps["code"] = digest([comps["code"], "entries:" + ",".join(ids)])
        fp = dict(overall=digest([f"{k}={v}" for k, v in sorted(comps.items())]), components=comps,
                  fingerprint_depth=self.fp_depth,
                  settings_dependencies=sorted({d for p in ps for d in p["fingerprint"]["settings_dependencies"]}),
                  hooks=[], path_functions=sorted({f for p in ps for f in p["fingerprint"]["path_functions"]}),
                  callee_functions=sorted({f for p in ps for f in p["fingerprint"]["callee_functions"]}),
                  check_functions=sorted({f for p in ps for f in p["fingerprint"]["check_functions"]}))
        worst = min(ps, key=lambda p: STATUS_RANK.get(p["evidence"]["status"]) or 0)
        factors = {}
        for f in sorted({f for p in ps for f in p["evidence"]["factors"]}):
            vals = [p["evidence"]["factors"].get(f, "absent") for p in ps]
            factors[f] = min(vals, key=lambda v: FACTOR_RANK.get(v, 0))
        checks, seen = [], set()
        for p in ps:
            for c in p["evidence"]["checks"]:
                k = (c.get("function"), c.get("line"), c.get("check"))
                if k not in seen:
                    seen.add(k)
                    checks.append(c)
        gaps = sorted({g for p in ps for g in p["gaps"]})
        note = (f"one lock entry for a heuristic credential site reached from {len(ids)} entry points (more than "
                f"{self.HEURISTIC_GROUP_MIN - 1}): a new or lost entry point, or a change on any of their paths, "
                f"changes this entry")
        evidence = dict(worst["evidence"], factors=factors, checks=checks,
                        context=[note] + list(worst["evidence"].get("context", []))[:3],
                        unrecognized_checks=[u for p in ps for u in p["evidence"].get("unrecognized_checks", [])][:50],
                        validation_methods=sorted({m for p in ps for m in p["evidence"].get("validation_methods", [])}),
                        hooks=[])
        where = func or api
        return dict(
            id=hashlib.sha256(f"heuristic_site||{api}|{func}".encode()).hexdigest()[:16],
            entry=dict(kind="heuristic_site", id=f"heuristic_site:{where}", view=where, route=None,
                       functions=[], gates=[], notes=[note], reached_from=ids),
            mint=ps[0]["mint"], chain=min((p["chain"] for p in ps), key=len),
            chains_analyzed=sum(p["chains_analyzed"] for p in ps), shadowed=all(p["shadowed"] for p in ps),
            evidence=evidence, gaps=gaps, analysis_complete=all(p["analysis_complete"] for p in ps),
            fingerprint_complete=all(p.get("fingerprint_complete", True) for p in ps), fingerprint=fp)

    # ------------------------------------------------------------------------------------ (v6) candidate tier
    def candidate_sites(self, fq, ctx) -> list:
        """[(site, MintAPI, note, candidate info)] candidate mint sites of one function (see candidates.py)."""
        out = list(self.candf.function_sites(fq))
        for site in self.cg.sites(fq):
            if site.is_property:
                continue
            res = self.cg.resolve(site, ctx)
            if res.targets or self.mint_of(site, res):
                continue
            for api, note, cinfo in self.candf.call_candidate(site, res):
                out.append((site, api, note, cinfo))
        return out

    def minting_subclass_paths(self, entries, all_path_gaps) -> list:
        """(v6) Candidate entries for project subclasses of a catalogued MINTING middleware or library view that
        no MIDDLEWARE item, route or as_view() invocation MintMap saw uses (a settings list computed at run time,
        a URLconf built dynamically): their own code and the library mint are traced as if they were registered,
        so the code is fingerprinted and visible."""
        used = {e.view for e in entries} | {e.ctx_class for e in entries if e.ctx_class}
        for e in entries:
            for f, c, _role in e.funcs:
                if c:
                    used.add(c)
        # a class run from code (`Cls.as_view(...)(request)`) or referenced by name in project code outside the
        # settings modules (registered at run time, passed to a factory) is not reported as unregistered; a dotted
        # string in a settings list MintMap could not evaluate does not count as a use
        named = set()
        settings_mods = set(self.settings.modules or [])
        for fq, info in self.p.functions.items():
            if info.module not in settings_mods:
                named |= self.cred.mentions(info)
        for mname, mod in self.p.modules.items():
            if mname in settings_mods:
                continue
            for st in self.p._top_level_statements(mod.tree.body):
                if not isinstance(st, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Import,
                                       ast.ImportFrom)):
                    for n in ast.walk(st):
                        if isinstance(n, ast.Name):
                            named.add(n.id)
                        elif isinstance(n, ast.Attribute):
                            named.add(n.attr)
        for v in list(used):
            if v in self.p.classes:
                used |= set(self.p.mro(v))
        out = []
        for cq in sorted(self.p.classes):
            if cq in used or cq.rsplit(".", 1)[-1] in named:
                continue
            mro = self.p.mro(cq)
            kind, base, mints = None, None, []
            for c in mro[1:]:
                if c in self.catalog.library_middleware:
                    kind, base, mints = "middleware", c, self.catalog.library_middleware[c]
                    break
                if c in self.catalog.library_views and self.catalog.library_views[c].get("mint_methods"):
                    d = self.catalog.library_views[c]
                    kind, base = "view", c
                    mints = [self.catalog.mint_for_ref(ref, "library_view", c) for ref in d["refs"]]
                    break
            if not kind:
                continue
            # a subclass of it that IS used covers it; an abstract helper base used by a registered class is in mro
            if any(cq in self.p.mro(o) for o in used if o in self.p.classes):
                continue
            e = Entry(id=f"unregistered_{kind}:{cq}", kind="candidate_entry", view=cq, ctx_class=cq)
            e.notes.append(f"project subclass of the catalogued minting {kind} {base}; MintMap did not see it in "
                           f"MIDDLEWARE, a route or an as_view() call (a value computed at run time?)")
            methods = MIDDLEWARE_METHODS if kind == "middleware" else HTTP_VERBS + list(HOOK_DISPATCHERS)
            for m in methods:
                r = self.p.lookup_method(cq, m)
                if r and r[0] == "project" and (r[1], cq, kind) not in e.funcs:
                    e.funcs.append((r[1], cq, kind))
            reason = f"subclass of {base} ({kind} that mints) not seen registered or routed"
            cinfo = dict(group="minting_subclass", rank="high", reason=reason, signals=[f"{kind}_subclass"],
                         keys=[base])
            for api, _ in [(m, "") for m in mints]:
                p, g = self.make_path(e, api, f"inherited from {base}; {reason}", chains=[], candidate=cinfo)
                p["mint"]["site"] = None
                out.append(p)
                all_path_gaps += g
            if e.funcs:
                starts = [(f, c) for f, c, _ in e.funcs]
                graph = self.traverse(starts)
                for node in sorted(graph, key=str):
                    fq, ctx = node
                    for site in self.cg.sites(fq):
                        for api, note in self.mint_of(site, self.cg.resolve(site, ctx)):
                            chains, trunc = self.chains(graph, starts, node)
                            p, g = self.make_path(e, api, note, site=site, site_func=node, chains=chains,
                                                  truncated=trunc, graph=graph, candidate=cinfo)
                            out.append(p)
                            all_path_gaps += g
        return out

    def group_candidate_sites(self, cand_paths) -> list:
        """(v6) One review entry per candidate site (mint symbol, function, line) whatever the number of entry
        points that reach it (all listed in `reached_from`; a new or lost one, or a change on any of their paths,
        changes the entry), sorted by group and rank."""
        groups: dict = {}
        for p in cand_paths:
            # line-independent identity (a line inserted above the site must not turn it into a new candidate)
            site = p["mint"].get("site") or {}
            key = (p["mint"]["api"], site.get("function") or p["entry"]["view"], None)
            groups.setdefault(key, []).append(p)
        out = []
        for key, ps in sorted(groups.items(), key=lambda kv: str(kv[0])):
            ids = sorted({p["entry"]["id"] for p in ps})
            g = self._grouped_path(key, ps, ids)
            cinfo = dict(ps[0]["candidate"])
            cinfo["rank"] = min((p["candidate"]["rank"] for p in ps), key=lambda r: RANK_ORDER.get(r, 9))
            routed = [i for i in ids if not i.startswith("unrouted:")]
            api, func, line = key
            where = func or api
            g["id"] = hashlib.sha256(f"candidate_site||{api}|{func}".encode()).hexdigest()[:16]
            note = (f"candidate ({cinfo['group']}, {cinfo['rank']}): {cinfo['reason']}; reached from "
                    f"{len(routed)} routed entry point(s)" + (f" and {len(ids) - len(routed)} unrouted root(s)"
                                                              if len(ids) > len(routed) else ""))
            g["entry"] = dict(kind="candidate_site", id=f"candidate_site:{where}", view=where, route=None,
                              functions=[], gates=[], notes=[note], reached_from=ids)
            g["evidence"]["context"] = [note] + [c for c in g["evidence"].get("context", [])[1:]]
            g["tier"] = "candidate"
            g["candidate"] = cinfo
            g["mint"] = dict(ps[0]["mint"])
            out.append(g)
        out.sort(key=lambda c: (c["candidate"]["group"], RANK_ORDER.get(c["candidate"]["rank"], 9), c["entry"]["id"]))
        return out

    def candidate_summary(self, candidates) -> dict:
        by = {}
        for c in candidates:
            row = by.setdefault(c["candidate"]["group"], dict(sites=0, high=0, medium=0))
            row["sites"] += 1
            row[c["candidate"]["rank"]] = row.get(c["candidate"]["rank"], 0) + 1
        return dict(groups={g: dict(by.get(g, dict(sites=0, high=0, medium=0)), description=d)
                            for g, d in CANDIDATE_GROUPS.items()},
                    sites=len(candidates),
                    set_aside_count=len(self.candf.set_aside),
                    set_aside=sorted(self.candf.set_aside, key=lambda r: (r["function"], r["line"]))[:200])

    def custom_credential_summary(self) -> dict:
        """(v5, R3) what the custom-credential heuristic found and what it set aside (not part of the lock)."""
        self.cred.run()
        return dict(
            candidates=[dict(function=c.func, line=c.line, source=c.symbol, purpose=c.purpose, kept_as=c.names,
                             file=self.p.file_of(c.func)) for c in sorted(self.cred.candidates.values(),
                                                                          key=lambda c: (c.func, c.line))],
            models_with_credential_defaults={m: [dict(field=f, generator=g, purpose=pp) for f, g, pp in v]
                                             for m, v in sorted(self.cred.default_models.items())},
            set_aside=sorted(self.cred.rejected, key=lambda r: (r["function"], r["line"])))

    def unrouted_paths(self, reached, all_path_gaps) -> list:
        out = []
        callers: dict = {}
        mint_nodes = []
        for fq, info in sorted(self.p.functions.items()):
            ctx = info.cls
            for site in self.cg.sites(fq):
                res = self.cg.resolve(site, ctx)
                for t, _ in res.targets:
                    callers.setdefault(t, set()).add(fq)
                for api, note in self.mint_of(site, res):
                    if (fq, site.line, api.symbol) not in reached:
                        mint_nodes.append((fq, ctx, site, api, note))
            for site, api, note in self.extra_mint_sites(fq):
                if (fq, site.line, api.symbol) not in reached:
                    mint_nodes.append((fq, ctx, site, api, note))
            for site, api, note, cinfo in self.candidate_sites(fq, ctx):
                if (fq, site.line, api.symbol) not in reached and self.candf.unrouted_allowed(fq, cinfo):
                    mint_nodes.append((fq, ctx, site, api, note, cinfo))
        for node in mint_nodes:
            fq, ctx, site, api, note = node[:5]
            cinfo = node[5] if len(node) > 5 else None
            roots, seen, stack = set(), {fq}, [fq]
            while stack:
                n = stack.pop()
                ps = callers.get(n, set()) - {n}
                if not ps:
                    roots.add(n)
                for c in ps:
                    if c not in seen:
                        seen.add(c)
                        stack.append(c)
            if not roots:
                roots = {fq}  # recursion-only cycle
            # (v6) Django data migrations run under `manage.py migrate`, never in a request
            roots = {r for r in roots if ".migrations." not in f".{r}."}
            for root in sorted(roots)[:10]:
                rinfo = self.p.functions[root]
                e = Entry(id=f"unrouted:{root}", kind="unrouted", view=root, funcs=[(root, rinfo.cls, "unrouted")],
                          notes=["no URL route, middleware or DRF authentication class reaches this code; it may run "
                                 "from signals, tasks, management commands, tests, or unresolved dynamic dispatch"],
                          ctx_class=rinfo.cls)
                graph = self.traverse([(root, rinfo.cls)])
                target = (fq, ctx)
                if target not in graph:
                    target = next((n for n in sorted(graph, key=str) if n[0] == fq), target)
                chains, trunc = self.chains(graph, [(root, rinfo.cls)], target) if target in graph else ([], False)
                if not chains:
                    chains = [([target], [])] if root == fq else []
                p, g = self.make_path(e, api, note, site=site, site_func=target, chains=chains, truncated=trunc,
                                      candidate=cinfo)
                out.append(p)
                if cinfo is None:
                    all_path_gaps += g
            if len(roots) > 10:
                self.gaps.append(Gap("unrouted_roots_truncated", self.p.file_of(fq), fq, f"{len(roots)} roots"))
        return out

    def _derived_mints(self) -> tuple[dict, dict]:
        """(function -> mint symbols it reaches, function -> direct mint symbols); cached."""
        if self._derived is not None:
            return self._derived
        direct: dict = {}
        callers: dict = {}
        for fq, info in self.p.functions.items():
            for site in self.cg.sites(fq):
                res = self.cg.resolve(site, info.cls)
                for api, _ in self.mint_of(site, res):
                    direct.setdefault(fq, set()).add(api.symbol)
                for t, _ in res.targets:
                    callers.setdefault(t, set()).add(fq)
        mints = {k: set(v) for k, v in direct.items()}
        stack = list(direct)
        while stack:
            n = stack.pop()
            for c in callers.get(n, ()):
                before = len(mints.get(c, ()))
                mints.setdefault(c, set()).update(mints[n])
                if len(mints[c]) != before:
                    stack.append(c)
        self._derived = (mints, direct)
        return self._derived

    def mint_reaching(self) -> dict:
        return self._derived_mints()[0]

    def derived_wrappers(self) -> list:
        """Project functions that call a mint API directly or through other project functions."""
        mints, direct = self._derived_mints()
        return [dict(function=f, file=self.p.file_of(f), direct=f in direct, mints=sorted(m))
                for f, m in sorted(mints.items())]

    def global_unresolved(self, reachable):
        wrapper_names = set()
        # project functions that (transitively) reach a mint -> their names
        mint_funcs = set()
        for fq, info in self.p.functions.items():
            for site in self.cg.sites(fq):
                if self.mint_of(site, self.cg.resolve(site, info.cls)):
                    mint_funcs.add(fq)
        callers: dict = {}
        for fq, info in self.p.functions.items():
            for site in self.cg.sites(fq):
                for t, _ in self.cg.resolve(site, info.cls).targets:
                    callers.setdefault(t, set()).add(fq)
        stack, seen = list(mint_funcs), set(mint_funcs)
        while stack:
            n = stack.pop()
            for c in callers.get(n, ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        wrapper_names = {q.rsplit(".", 1)[-1] for q in seen} - GENERIC_LEAVES
        reachable_names = {n[0] for n in reachable}
        for fq, info in sorted(self.p.functions.items()):
            for site in self.cg.sites(fq):
                res = self.cg.resolve(site, info.cls)
                if not res.unresolved:
                    continue
                if self.possible_mint(site):
                    self.gaps.append(Gap("possible_mint_call_unresolved", self.p.file_of(fq), fq, site.text, site.line,
                                         key_detail=self.call_key_text(site)))
                elif site.leaf in wrapper_names and fq in reachable_names:
                    self.gaps.append(Gap("unresolved_call_may_reach_mint", self.p.file_of(fq), fq, site.text,
                                         site.line, key_detail=self.call_key_text(site)))


# ---------------------------------------------------------------- helpers
DIST_TO_PACKAGE = {
    "django": "django", "djangorestframework": "rest_framework",
    "djangorestframework-simplejwt": "rest_framework_simplejwt", "django-allauth": "allauth",
    "django-otp": "django_otp", "django-two-factor-auth": "two_factor", "django-formtools": "formtools",
    "django-rest-knox": "knox", "django-sesame": "sesame", "social-auth-app-django": "social_django",
    "social-auth-core": "social_core", "dj-rest-auth": "dj_rest_auth", "djoser": "djoser",
    "django-hijack": "hijack", "django-oauth-toolkit": "oauth2_provider", "mozilla-django-oidc": "mozilla_django_oidc",
    "webauthn": "webauthn", "channels": "channels",
}
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;#]*)")


_CMP_RE = re.compile(r"(===|==|~=|>=|<=|!=|<|>|\^|~)\s*v?([0-9][0-9A-Za-z.*+-]*)")


def _vtuple(v: str) -> tuple:
    out = []
    for part in v.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group(0)))
    return tuple(out) or (0,)


def version_spec_unverified(spec: str, verified: list) -> bool:
    """(v5 review) True when a requirement specifier excludes every catalog-verified version's major line:
    a pin (`==2.2.8`, `~=2.2`, poetry `^2.2`) of another major version, or bounds that exclude all verified
    versions (`<3.0` when 7.2.0 was read)."""
    vs = [_vtuple(v) for v in verified]
    majors = {v[0] for v in vs}
    for op, ver in _CMP_RE.findall(spec or ""):
        t = _vtuple(ver.replace("*", "0"))
        if op in ("==", "===", "~=", "^", "~") and t[0] not in majors:
            return True
        if op == "<" and all(v >= t for v in vs):
            return True
        if op == "<=" and all(v > t for v in vs):
            return True
        if op in (">=", ">") and all(v < t for v in vs):
            return True
    return False


def read_dependency_specs(root, excluded) -> tuple[list, dict]:
    """Version specifiers of catalog packages from requirements*.txt / pyproject.toml.
    Lock files (poetry.lock, uv.lock, Pipfile.lock) are NOT read."""
    files, specs = [], {}

    def note(dist, spec, rel):
        pkg = DIST_TO_PACKAGE.get(dist.lower().replace("_", "-"))
        if pkg:
            specs[pkg] = (specs.get(pkg, "") + " " + f"{spec.strip() or '(unpinned)'}@{rel}").strip()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excluded)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if fn.startswith("requirements") and fn.endswith((".txt", ".in")):
                files.append(rel)
                with open(full, errors="replace") as fh:
                    for line in fh:
                        m = _REQ_RE.match(line)
                        if m and not line.lstrip().startswith(("-", "#")):
                            note(m.group(1), m.group(3), rel)
            elif fn == "pyproject.toml":
                files.append(rel)
                try:
                    with open(full, "rb") as fh:
                        data = tomllib.load(fh)
                except (tomllib.TOMLDecodeError, OSError):
                    continue
                for dep in data.get("project", {}).get("dependencies", []) or []:
                    m = _REQ_RE.match(dep)
                    if m:
                        note(m.group(1), m.group(3), rel)
                poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
                for name, val in poetry.items():
                    note(name, val if isinstance(val, str) else str(val.get("version", "")), rel)
    return files, specs


def _u(n) -> str:
    try:
        return stable_unparse(n)
    except Exception:
        return "?"


_ABSENT = object()


def _short(s: str, n: int = 200) -> str:
    return s if len(s) <= n else s[:n - 3] + "..."


UNVERIFIED_FACTOR_PREFIXES = ("unverified_", "unknown", "dynamic_backend", "none", "library_backend:",
                              UNRECOGNIZED_PREFIX)


def _verified_factor(f: str) -> bool:
    """A factor string like 'password|unverified_project_backend:x' is only as strong
    as its weakest alternative (authenticate() accepts if ANY backend accepts)."""
    return all(not part.startswith(UNVERIFIED_FACTOR_PREFIXES) for part in f.split("|"))


def _count_by(items, key) -> dict:
    out: dict = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return out


class _Unknown:
    def __repr__(self):
        return "UNKNOWN"


UNKNOWN = _Unknown()
ABSENT = object()
MUTATING_METHODS = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"}


class _SDict(dict):
    """A statically evaluated dict; `incomplete` when part of it (a `**x` MintMap cannot evaluate) is unknown."""
    incomplete = False


class ArgEvaluator:
    """(v4) Static values of the arguments a catalog check's `disabled_if` patterns inspect
    (e.g. `jwt.decode(..., options=...)`): literals, dict displays (with `**`), `dict(...)`, `a | b`, local
    variables assigned once (or always to the same value), and module constants of project modules
    (also imported ones).  Everything else (parameters, call results, settings, a dict that is changed
    in place, ...) is UNKNOWN.  `sources` collects the statements consulted (for the fingerprint)."""

    def __init__(self, project: Project):
        self.p = project
        self.sources: list = []

    def value(self, e, module, func, depth=0):
        if depth > 12:
            return UNKNOWN
        if isinstance(e, ast.Constant):
            return e.value
        if isinstance(e, (ast.List, ast.Tuple)):
            vals = [self.value(x, module, func, depth + 1) for x in e.elts]
            return UNKNOWN if any(v is UNKNOWN for v in vals) else vals
        if isinstance(e, ast.Dict):
            d = _SDict()
            for k, v in zip(e.keys, e.values):
                if k is None:
                    self._merge(d, self.value(v, module, func, depth + 1))
                    continue
                kv = self.value(k, module, func, depth + 1)
                if isinstance(kv, (str, int, bool)) or kv is None:
                    d[kv] = self.value(v, module, func, depth + 1)
                else:
                    d.incomplete = True
            return d
        if isinstance(e, ast.Call):
            q = self.p.resolve_expr_static(module, e.func, func) if isinstance(e.func, (ast.Name, ast.Attribute)) \
                else None
            if q and self.p.canonical(q) == "builtins.dict" and len(e.args) <= 1:
                d = _SDict()
                if e.args:
                    self._merge(d, self.value(e.args[0], module, func, depth + 1))
                for k in e.keywords:
                    if k.arg is None:
                        self._merge(d, self.value(k.value, module, func, depth + 1))
                    else:
                        d[k.arg] = self.value(k.value, module, func, depth + 1)
                return d
            return UNKNOWN
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.BitOr):
            a, b = self.value(e.left, module, func, depth + 1), self.value(e.right, module, func, depth + 1)
            if isinstance(a, dict) and isinstance(b, dict):
                d = _SDict()
                self._merge(d, a)
                self._merge(d, b)
                return d
            return UNKNOWN
        if isinstance(e, ast.Name) and func is not None and self._is_local(e.id, func):
            return self._local(e.id, func, depth)
        if isinstance(e, (ast.Name, ast.Attribute)):
            q = self.p.resolve_expr_static(module, e, func)
            q = self.p.canonical(q) if q else None
            if not q:
                return UNKNOWN
            m2, rest = self.p.module_prefix(q)
            if m2 and len(rest) == 1:
                return self._module_constant(m2, rest[0], depth)
        return UNKNOWN

    @staticmethod
    def _merge(d, sub):
        if isinstance(sub, dict):
            d.update(sub)
            d.incomplete = d.incomplete or getattr(sub, "incomplete", False)
        else:
            d.incomplete = True

    def _is_local(self, name, func):
        f = func
        while f is not None:
            if name in f.local_vars or name in f.local_imports:
                return name in f.local_vars and f is func
            f = self.p.functions.get(f.parent) if f.parent else None
        return False

    def _local(self, name, func, depth):
        """A local variable: every store must be a plain `name = <value>` of the same value, and the
        variable must not be changed in place."""
        if name in func.params or name in (func.node.args.vararg.arg if func.node.args.vararg else "",
                                           func.node.args.kwarg.arg if func.node.args.kwarg else "") or \
                name in [a.arg for a in func.node.args.kwonlyargs]:
            return UNKNOWN                       # chosen by the caller
        stores, values = 0, []
        for n in self.p.walk_function_body(func.node):
            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store):
                stores += 1
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) \
                    and n.targets[0].id == name:
                values.append(n)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name \
                    and n.value is not None:
                values.append(n)
            elif self._mutates(n, name):
                return UNKNOWN
        if not values or stores != len(values):
            return UNKNOWN
        return self._same(values, func.module, func, depth)

    def _module_constant(self, modname, name, depth):
        mod = self.p.modules[modname]
        values = []
        for st in self.p._top_level_statements(mod.tree.body):
            if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in st.targets):
                if len(st.targets) != 1:
                    return UNKNOWN
                values.append(st)
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.target.id == name:
                if st.value is None:
                    continue
                values.append(st)
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name) and st.target.id == name:
                return UNKNOWN
            elif isinstance(st, (ast.Assign, ast.AugAssign, ast.Expr, ast.Delete)) and \
                    any(self._mutates(n, name) for n in ast.walk(st)):
                return UNKNOWN
            elif isinstance(st, (ast.Import, ast.ImportFrom)) and any((a.asname or a.name) == name
                                                                       for a in st.names):
                q = self.p.lookup_symbol(modname, name)
                m2, rest = self.p.module_prefix(self.p.canonical(q)) if q else (None, [])
                if m2 and len(rest) == 1 and m2 != modname:
                    return self._module_constant(m2, rest[0], depth + 1)
                return UNKNOWN
        if not values:
            return UNKNOWN
        return self._same(values, modname, None, depth)

    def _same(self, stmts, module, func, depth):
        vals = [self.value(s.value, module, func, depth + 1) for s in stmts]
        if any(v is UNKNOWN for v in vals) or any(v != vals[0] for v in vals[1:]):
            return UNKNOWN
        self.sources += [f"{module}:{normalize(s)}" for s in stmts]
        return vals[0]

    @staticmethod
    def _mutates(n, name) -> bool:
        """`name[k] = v`, `del name[k]`, `name.update(...)` ..."""
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id == name and \
                isinstance(n.ctx, (ast.Store, ast.Del)):
            return True
        return isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in MUTATING_METHODS \
            and isinstance(n.func.value, ast.Name) and n.func.value.id == name


def check_switches(project: Project, site, patterns, func_qn) -> tuple:
    """(v4) For a catalog check with `disabled_if` patterns (e.g. jwt.decode(..., options={"verify_signature":
    False})): (disabled reason, [arguments MintMap cannot evaluate], [source statements consulted]).
    A pattern matches a keyword argument, the positional argument at `pos`, or a key of a `**kwargs`
    dict; a falsy value equal to the pattern's value switches verification off."""
    call = site.node
    func = project.functions.get(func_qn)
    module = func.module if func else ""
    ev = ArgEvaluator(project)
    disabled, unknown = [], []
    for pat in patterns or ():
        kw, key = pat["kw"], pat.get("key")
        shown, val = "", ABSENT
        for k in call.keywords:
            if k.arg == kw:
                shown, val = f"{kw}={_u(k.value)}", ev.value(k.value, module, func)
        pos = pat.get("pos")
        if val is ABSENT and pos is not None:
            star = next((i for i, a in enumerate(call.args) if isinstance(a, ast.Starred)), None)
            if star is not None and star <= pos:
                shown, val = f"{_u(call.args[star])} (may pass {kw})", UNKNOWN
            elif len(call.args) > pos:
                shown, val = f"{kw}={_u(call.args[pos])} (positional)", ev.value(call.args[pos], module, func)
        if val is ABSENT:
            for k in call.keywords:
                if k.arg is None:
                    d = ev.value(k.value, module, func)
                    if isinstance(d, dict) and kw in d:
                        shown, val = f"**{_u(k.value)} sets {kw}", d[kw]
                    elif not isinstance(d, dict) or d.incomplete:
                        shown, val = f"**{_u(k.value)} (may set {kw})", UNKNOWN
        if val is ABSENT:
            continue
        if key is None:
            if val is UNKNOWN:
                unknown.append(shown)
            elif val == pat["value"] or (pat["value"] is False and not val and val is not None):
                disabled.append(f"{kw}={val!r}")
            continue
        if val is None:
            continue                               # options=None: library defaults (verification on)
        if not isinstance(val, dict):
            unknown.append(shown)
            continue
        inner = val.get(key, ABSENT)
        if inner is UNKNOWN or (inner is ABSENT and val.incomplete):
            unknown.append(shown)
        elif inner is not ABSENT and (inner == pat["value"] or (pat["value"] is False and not inner)):
            disabled.append(f"{kw}[{key!r}]={inner!r}" + (f" ({shown})" if not shown.startswith(f"{kw}={{")
                                                           else ""))
    reason = ("verification disabled: " + ", ".join(disabled)) if disabled else ""
    return reason, unknown, sorted(set(ev.sources))


def _merge_gaps(groups) -> list:
    out, seen = [], set()
    for g in groups:
        for gap in g or ():
            if gap.key not in seen:
                seen.add(gap.key)
                out.append(gap)
    return out


def _merge_leaves(groups) -> list:
    """Union of unrecognized-check leaves (dicts), deduplicated by (function, line, call)."""
    out, seen = [], set()
    for g in groups:
        for leaf in g or ():
            k = (leaf["function"], leaf["line"], leaf["call"])
            if k not in seen:
                seen.add(k)
                out.append(leaf)
    return sorted(out, key=lambda x: (x["function"], x["line"], x["call"]))


def _rank_name(v):
    base = int(v)
    names = {4: "guards_mint", 3: "guards_mint_assert_only", 2: "present_unproven", 1: "not_enforced", 0: "absent"}
    s = names.get(base, "absent")
    if v - base >= 0.5:
        s += "+same_user_shown"
    return s


def subject_name(call, d, an) -> str | None:
    subj = d.subject
    if subj == "return":
        kind, var = an.binding(call)
        return var if kind in ("assign", "tuple_first") else None
    if subj in ("arg0", "arg1"):
        i = int(subj[3:])
        if len(call.args) > i:
            return _u(call.args[i])
        for k in call.keywords:
            if k.arg == "user":
                return _u(k.value)
        return None
    if subj == "receiver" and isinstance(call.func, ast.Attribute):
        return _u(call.func.value)
    if subj == "form" and isinstance(call.func, ast.Attribute):
        return _u(call.func.value)
    if isinstance(subj, tuple) and subj[0] == "param":
        i = subj[1]
        if len(call.args) > i:
            return _u(call.args[i])
        for k in call.keywords:
            if k.arg == subj[2]:
                return _u(k.value)
    return None


def mint_user_names(site, api) -> set | None:
    if site is None or site.is_property or api.user_arg is None:
        return None
    pos, kw = api.user_arg
    call = site.node
    expr = None
    if pos is not None and len(call.args) > pos:
        expr = call.args[pos]
    for k in call.keywords:
        if k.arg == kw:
            expr = k.value
    if expr is None:
        return set()
    names = {_u(expr)}
    # form.get_user(), form.user, form.cleaned_data['user'], serializer.validated_data['user']
    base = expr
    if isinstance(base, ast.Call):
        base = base.func
    while isinstance(base, (ast.Attribute, ast.Subscript, ast.Call)):
        base = base.value if not isinstance(base, ast.Call) else base.func
    if isinstance(base, ast.Name):
        names.add("form:" + base.id)
    return names


def _file_sha(path) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()[:16]

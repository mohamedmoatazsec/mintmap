"""Load the library catalog (default: the packaged mintmap/data/django_catalog.json) and join it with the machine-readable overlay."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from . import overlay

DEFAULT_CATALOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "django_catalog.json")


class CatalogError(Exception):
    pass


@dataclass
class MintAPI:
    symbol: str
    ref: str | None           # catalog qualname, None for heuristic entries
    purpose: str
    purpose_basis: str
    kind: str                 # call | property | library_view | include | middleware | admin_urls
    user_arg: tuple | None = None
    returns: str | None = None
    heuristic: bool = False
    source_location: str | None = None


@dataclass
class CheckAPI:
    symbol: str
    ref: str
    factor: str
    ret: str                  # bool | subject_or_none | raises | tuple
    subject: str | None
    match: str = "qualname"   # qualname | method_name
    source_location: str | None = None
    disabled_if: list = field(default_factory=list)   # keyword patterns that switch verification off


@dataclass
class Catalog:
    path: str
    sha256: str
    entries_by_ref: dict            # catalog qualname -> raw entry (mint or check)
    mint_calls: dict                # symbol -> MintAPI
    property_mints: dict            # (receiver, attr) -> MintAPI
    check_calls: dict               # symbol -> CheckAPI (qualname match)
    check_method_names: dict        # method name -> CheckAPI (name-only match)
    check_constructors: dict        # class symbol -> CheckAPI
    form_checks: dict               # class symbol -> dict(method, factor, ref, subject_via)
    library_views: dict             # symbol -> dict(refs, mint_methods, ...)
    library_includes: dict          # module -> [MintAPI]
    admin_site_urls: dict           # symbol -> [MintAPI]
    library_middleware: dict        # symbol -> [MintAPI]
    mint_decorators: dict           # decorator symbol -> [MintAPI]
    unmapped_refs: list = field(default_factory=list)
    non_check_prefixes: list = field(default_factory=list)   # library symbol prefixes that are not checks
    skipped_overlay: list = field(default_factory=list)      # optional overlay entries whose ref is missing
    # (v3, P5) include symbol -> {mint ref: [sub-route]} from the catalog section `library_url_routes`
    library_url_routes: dict = field(default_factory=dict)
    # (v5, catalog v3) what the catalog declares KNOWN beyond the mint lists; everything else a library exposes
    # is a gap.  Empty with the v1/v2 catalogs (then every unmapped library construct is a gap).
    includes_complete: set = field(default_factory=set)       # include modules whose mint list is complete
    views_no_mint: dict = field(default_factory=dict)         # symbol -> source_location
    views_no_mint_prefixes: list = field(default_factory=list)  # [(prefix, source_location)]
    view_aliases: dict = field(default_factory=dict)          # alias symbol -> (class symbol, source_location)
    middleware_no_mint: dict = field(default_factory=dict)    # symbol -> source_location
    drf_auth_no_mint: dict = field(default_factory=dict)      # symbol -> source_location
    library_drf_auth: dict = field(default_factory=dict)      # DRF auth class symbol -> [MintAPI]
    admin_registrations: dict = field(default_factory=dict)   # app -> [(model, model_admin, MintAPI|None, src)]
    # (v5 part B) mint ref -> [setting names the library flow reads] (catalog v3 `mint_setting_dependencies`)
    mint_setting_deps: dict = field(default_factory=dict)
    # (v5 part B) project hooks: [row] from catalog v3 `library_hook_settings` (see analysis.hook_bindings)
    hook_settings: list = field(default_factory=list)
    # (v5 review) dist name -> [versions whose source the catalog was read in] (catalog v3 verified_package_versions)
    verified_versions: dict = field(default_factory=dict)
    # (v5 review) library model qualname -> MintAPI: creating it creates a credential (library_credential_models)
    credential_models: dict = field(default_factory=dict)
    catalog_version: int = 1

    def view_no_mint(self, symbol: str) -> str | None:
        """source_location if the catalog declares this library view (or its prefix) non-minting."""
        if symbol in self.views_no_mint:
            return self.views_no_mint[symbol]
        for pre, src in self.views_no_mint_prefixes:
            if symbol.startswith(pre):
                return src
        return None

    def mint_for_ref(self, ref: str, kind: str, symbol: str) -> MintAPI:
        e = self.entries_by_ref[ref]
        return MintAPI(symbol=symbol, ref=ref, purpose=e["purpose"],
                       purpose_basis="catalog:" + ref, kind=kind,
                       source_location=e.get("source_location"))

    def entry_digest(self, ref: str | None) -> str:
        """Stable digest of a catalog entry (used in fingerprints)."""
        if ref is None:
            return "heuristic"
        e = self.entries_by_ref.get(ref)
        return hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()[:16]


def load_catalog(path: str = DEFAULT_CATALOG) -> Catalog:
    with open(path, "rb") as fh:
        raw = fh.read()
    data = json.loads(raw)
    entries = {}
    for e in data.get("mint_apis", []):
        entries[e["qualname"]] = dict(e, _type="mint")
    # (v5 review, catalog v3) mint APIs added outside the unchanged v2 `mint_apis` list
    for e in data.get("library_mint_calls", []):
        entries[e["qualname"]] = dict(e, _type="mint")
    for e in data.get("library_credential_models", []):
        entries[e["model"]] = dict(e, qualname=e["model"], _type="mint")
    for e in data.get("check_apis", []):
        entries[e["qualname"]] = dict(e, _type="check")
    for e in data.get("non_check_apis", []):
        entries[e["qualname"]] = dict(e, _type="non_check")
    used_refs: set[str] = set()
    skipped: list = []

    def missing_optional(d) -> bool:
        """Entries marked optional (catalog v2 additions) are skipped, not fatal, when the
        catalog in use lacks their ref; they are listed in tool.overlay_entries_skipped."""
        if d.get("optional") and d.get("ref") not in entries:
            skipped.append(d.get("symbol") or d.get("prefix") or d.get("cls"))
            return True
        return False

    def need(ref, expect_type=None):
        if ref not in entries:
            raise CatalogError(f"overlay references unknown catalog entry: {ref!r}")
        if expect_type and entries[ref]["_type"] != expect_type:
            raise CatalogError(f"overlay entry {ref!r} is a {entries[ref]['_type']}, expected {expect_type}")
        used_refs.add(ref)
        return entries[ref]

    mint_calls = {}
    for d in overlay.MINT_CALLS:
        if d.get("heuristic"):
            mint_calls[d["symbol"]] = MintAPI(
                symbol=d["symbol"], ref=None, purpose="unknown",
                purpose_basis="heuristic: generic signing/JWT primitive (not in catalog)",
                kind="call", user_arg=d.get("user_arg"), heuristic=True)
            continue
        e = need(d["ref"], "mint")
        purpose, basis = e["purpose"], "catalog:" + d["ref"]
        if d.get("purpose_override"):
            purpose, basis = d["purpose_override"], "overlay override; " + d["basis"]
        mint_calls[d["symbol"]] = MintAPI(
            symbol=d["symbol"], ref=d["ref"], purpose=purpose, purpose_basis=basis, kind="call",
            user_arg=d.get("user_arg"), returns=d.get("returns"), source_location=e.get("source_location"))

    property_mints = {}
    for d in overlay.PROPERTY_MINTS:
        e = need(d["ref"], "mint")
        property_mints[(d["receiver"], d["attr"])] = MintAPI(
            symbol=d["receiver"] + "." + d["attr"], ref=d["ref"], purpose=e["purpose"],
            purpose_basis="catalog:" + d["ref"], kind="property", source_location=e.get("source_location"))

    def mk_check(d):
        e = need(d["ref"], "check")
        return CheckAPI(symbol=d["symbol"], ref=d["ref"], factor=d["factor"], ret=d["ret"],
                        subject=d.get("subject"), match=d.get("match", "qualname"),
                        source_location=e.get("source_location"), disabled_if=list(d.get("disabled_if", [])))

    check_calls, check_method_names = {}, {}
    for d in overlay.CHECK_CALLS:
        if missing_optional(d):
            continue
        c = mk_check(d)
        (check_method_names if c.match == "method_name" else check_calls)[c.symbol] = c
    check_constructors = {d["symbol"]: mk_check(d) for d in overlay.CHECK_CONSTRUCTORS}

    form_checks = {}
    for d in overlay.FORM_CHECKS:
        need(d["ref"], "check")
        form_checks[d["cls"]] = dict(d)

    library_views = {}
    for d in overlay.LIBRARY_VIEWS:
        for r in d["refs"]:
            need(r, "mint")
        library_views[d["symbol"]] = dict(d)

    def mints_for(refs, kind, symbol):
        out = []
        for r in refs:
            need(r, "mint")
            e = entries[r]
            out.append(MintAPI(symbol=symbol, ref=r, purpose=e["purpose"], purpose_basis="catalog:" + r,
                               kind=kind, source_location=e.get("source_location")))
        return out

    library_includes = {m: mints_for(refs, "include", m) for m, refs in overlay.LIBRARY_INCLUDES.items()}
    admin_site_urls = {s: mints_for(refs, "admin_urls", s) for s, refs in overlay.ADMIN_SITE_URLS.items()}
    library_middleware = {s: mints_for(refs, "middleware", s) for s, refs in overlay.LIBRARY_MIDDLEWARE.items()}
    mint_decorators = {s: mints_for(refs, "decorator", s) for s, refs in overlay.MINT_DECORATORS.items()}
    for ref in overlay.VIEW_GATE_DECORATORS.values():
        need(ref, "check")
    non_check_prefixes = []
    for d in getattr(overlay, "NON_CHECK_PREFIXES", []):
        if missing_optional(d):
            continue
        need(d["ref"], "non_check")
        non_check_prefixes.append(d["prefix"])

    # (v3, P5) where a library URLconf exposes a mint flow (absent from the v1 catalog: then no
    # library route takes part in first-match shadowing)
    library_url_routes: dict = {}
    for row in data.get("library_url_routes", []):
        inc, ref = row["include"], row["mint_ref"]
        if ref not in entries or entries[ref]["_type"] != "mint":
            raise CatalogError(f"library_url_routes references unknown mint entry: {ref!r}")
        known = {m.ref for m in library_includes.get(inc, []) + admin_site_urls.get(inc, [])}
        if ref not in known:
            raise CatalogError(f"library_url_routes: {ref!r} is not a mint of include {inc!r} in the overlay")
        if row.get("route_kind", "path") != "path":
            continue
        library_url_routes.setdefault(inc, {}).setdefault(ref, []).append(row["route"])

    # ---- (v5) catalog v3 sections ----
    def mint_entry(ref, where):
        if ref not in entries or entries[ref]["_type"] != "mint":
            raise CatalogError(f"{where} references unknown mint entry: {ref!r}")
        used_refs.add(ref)
        e = entries[ref]
        return e

    includes_complete = {r["include"] for r in data.get("library_includes_complete", []) if r.get("complete")}
    views_no_mint, views_no_mint_prefixes = {}, []
    for r in data.get("library_views_no_mint", []) + data.get("library_classes_no_mint", []):
        if r.get("prefix"):
            views_no_mint_prefixes.append((r["symbol"].rstrip("*"), r["source_location"]))
        else:
            views_no_mint[r["symbol"]] = r["source_location"]
    view_aliases = {r["symbol"]: (r["target"], r["source_location"]) for r in data.get("library_view_aliases", [])}
    middleware_no_mint = {r["symbol"]: r["source_location"] for r in data.get("library_middleware_no_mint", [])}
    drf_auth_no_mint = {r["symbol"]: r["source_location"] for r in data.get("library_drf_auth_no_mint", [])}
    library_drf_auth = {}
    for r in data.get("library_view_flows", []):
        e = mint_entry(r["mint_ref"], "library_view_flows")
        api = MintAPI(symbol=r["symbol"], ref=r["mint_ref"], purpose=e["purpose"],
                      purpose_basis="catalog:" + r["mint_ref"],
                      kind="library_view" if r.get("kind") == "view" else "drf_auth",
                      source_location=e.get("source_location"))
        if r.get("kind") == "view":
            if r["symbol"] in library_views:
                raise CatalogError(f"library_view_flows: {r['symbol']} already mapped by the overlay")
            library_views[r["symbol"]] = dict(symbol=r["symbol"], refs=[r["mint_ref"]],
                                              mint_methods=list(r.get("mint_methods", [])),
                                              verified=r.get("source_location"))
        else:
            library_drf_auth.setdefault(r["symbol"], []).append(api)
    for r in data.get("library_admin_site_extra_mints", []):
        e = mint_entry(r["mint_ref"], "library_admin_site_extra_mints")
        admin_site_urls.setdefault(r["include"], []).append(MintAPI(
            symbol=r["include"], ref=r["mint_ref"], purpose=e["purpose"], purpose_basis="catalog:" + r["mint_ref"],
            kind="admin_urls", source_location=e.get("source_location")))
    admin_registrations = {}
    for r in data.get("library_admin_registrations", []):
        regs = []
        for g in r.get("registrations", []):
            api = None
            if g.get("mint_ref"):
                e = mint_entry(g["mint_ref"], "library_admin_registrations")
                api = MintAPI(symbol=f"admin:{g['model']}", ref=g["mint_ref"], purpose=e["purpose"],
                              purpose_basis="catalog:" + g["mint_ref"], kind="admin_registration",
                              source_location=r["source_location"])
            regs.append((g["model"], g.get("model_admin"), api, r["source_location"]))
        admin_registrations[r["app"]] = regs

    mint_setting_deps: dict = {}
    for r in data.get("mint_setting_dependencies", []):
        mint_entry(r["mint_ref"], "mint_setting_dependencies")
        mint_setting_deps.setdefault(r["mint_ref"], [])
        mint_setting_deps[r["mint_ref"]] += [x for x in r["settings"] if x not in mint_setting_deps[r["mint_ref"]]]
    for r in data.get("library_mint_calls", []):
        e = mint_entry(r["qualname"], "library_mint_calls")
        for sym in r["symbols"]:
            mint_calls[sym] = MintAPI(symbol=sym, ref=r["qualname"], purpose=e["purpose"],
                                      purpose_basis="catalog:" + r["qualname"], kind="call",
                                      source_location=e.get("source_location"))
    credential_models = {}
    for r in data.get("library_credential_models", []):
        e = mint_entry(r["model"], "library_credential_models")
        credential_models[r["model"]] = MintAPI(symbol=r["model"], ref=r["model"], purpose=e["purpose"],
                                                purpose_basis="catalog:" + r["model"], kind="call",
                                                source_location=e.get("source_location"))
        for m in ("create", "get_or_create", "update_or_create", "bulk_create", "acreate", "aget_or_create",
                  "aupdate_or_create"):
            sym = f"{r['model']}.objects.{m}"
            mint_calls[sym] = MintAPI(symbol=sym, ref=r["model"], purpose=e["purpose"],
                                      purpose_basis="catalog:" + r["model"], kind="call",
                                      source_location=e.get("source_location"))
    verified_versions = {r["dist"]: list(r["versions"]) for r in data.get("verified_package_versions", [])}
    hook_settings = []
    for r in data.get("library_hook_settings", []):
        for k in ("setting", "package", "kind", "applies_to", "source_location"):
            if k not in r:
                raise CatalogError(f"library_hook_settings row without {k!r}: {r}")
        hook_settings.append(dict(r))

    unmapped = sorted(r for r in entries if r not in used_refs)
    return Catalog(
        path=path, sha256=hashlib.sha256(raw).hexdigest(), entries_by_ref=entries,
        mint_calls=mint_calls, property_mints=property_mints, check_calls=check_calls,
        check_method_names=check_method_names, check_constructors=check_constructors,
        form_checks=form_checks, library_views=library_views, library_includes=library_includes,
        admin_site_urls=admin_site_urls, library_middleware=library_middleware, mint_decorators=mint_decorators,
        unmapped_refs=unmapped, non_check_prefixes=non_check_prefixes, skipped_overlay=sorted(set(skipped)),
        library_url_routes=library_url_routes, includes_complete=includes_complete, views_no_mint=views_no_mint,
        views_no_mint_prefixes=views_no_mint_prefixes, view_aliases=view_aliases,
        middleware_no_mint=middleware_no_mint, drf_auth_no_mint=drf_auth_no_mint, library_drf_auth=library_drf_auth,
        admin_registrations=admin_registrations, mint_setting_deps=mint_setting_deps, hook_settings=hook_settings,
        verified_versions=verified_versions, credential_models=credential_models,
        catalog_version=int(data.get("catalog_version", 1)))

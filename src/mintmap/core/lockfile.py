"""mintmap.lock: build, merge (update) and diff.

Exit-code bits returned by diff():
    1  NEW_PATH              a mint path not in the lock
    2  REMOVED_PATH          a locked path no longer found (code removed OR analysis lost it)
    4  FINGERPRINT_CHANGED   code/settings/catalog evidence behind a path changed -> review invalid
    8  EVIDENCE_DOWNGRADED   a factor's relation to the mint got weaker (or disappeared)
   16  PURPOSE_CHANGED       catalog purpose of the minted credential changed
   32  COVERAGE_REGRESSION   fewer parsed files, more parse failures, new gaps, new exclusions,
                             or a path that was complete is now incomplete
   64  UNREVIEWED            lock entries whose review_status is not 'accepted'
  (v5, R7) a settings group entry (`settings:<group>`) that is new, removed or changed sets bit 4 once, with the
  changed settings named in the finding; an unaccepted unchanged group sets bit 64
  128  (CLI) usage / input error
  (v6) candidate groups (`candidates:<kind>`, one lock entry per kind listing its member SITES): a new member sets
  bit 1, a member no longer found bit 2, a member whose fingerprint (code, checks, settings, entry points that reach
  it ...) changed bit 4; an unaccepted unchanged group sets bit 64.  Findings name the member and carry
  `tier: "candidate"`.
  (v6c) watched groups (`watched:<kind>`): sites a precision rule set aside as not credentials (signed / random
  values, session lookups of non-principal objects, generators nothing references), with the same bits per member
  and `tier: "watched"`; their fingerprint is the site function's code, the symbol and the entry points.

(v6b) Path entries carry an informational `review` block (credential-kind group such as `kind:session`, risk,
why); diff never compares it, so a lock written before v6b (without it) stays valid, and `mintmap update` adds it.
`mintmap accept --group <group>` accepts every entry of a review group (`kind:<k>`, `candidates:<kind>`,
`settings`); for an older lock the group of a path is derived from its purpose.
"""
from __future__ import annotations

import json
import sys

LOCK_VERSION = 1
NEW_PATH, REMOVED_PATH, FINGERPRINT_CHANGED, EVIDENCE_DOWNGRADED, PURPOSE_CHANGED, COVERAGE_REGRESSION, UNREVIEWED = \
    1, 2, 4, 8, 16, 32, 64
BIT_NAMES = {NEW_PATH: "new_path", REMOVED_PATH: "removed_path", FINGERPRINT_CHANGED: "fingerprint_changed",
             EVIDENCE_DOWNGRADED: "evidence_downgraded", PURPOSE_CHANGED: "purpose_changed",
             COVERAGE_REGRESSION: "coverage_regression", UNREVIEWED: "unreviewed"}

FACTOR_RANK = {"guards_mint+same_user_shown": 5, "guards_mint": 4, "guards_mint_assert_only+same_user_shown": 3.5,
               "guards_mint_assert_only": 3, "present_unproven": 2, "not_enforced": 1, "absent": 0}
SHADOWED_STATUS = "shadowed_by_earlier_route"
# (v3) a shadowed path is not reachable through its route, so it ranks above every reachable status:
# a path that stops being shadowed (the earlier route was removed or changed) is reported as a downgrade,
# whatever its new status, including library_flow_checks_not_analyzed (which otherwise has no rank).
STATUS_RANK = {SHADOWED_STATUS: 4, "check_guards_mint": 3, "check_present_relationship_unproven": 2,
               "guard_relies_on_unverified_check": 2, "check_result_not_enforced": 1,
               "unrecognized_check_present": 1,
               "no_check_found_in_analyzed_code": 0, "library_flow_checks_not_analyzed": None}
REVIEW_FIELDS = ("review_status", "policy_note", "reviewer")


def _lock_coverage(cov: dict) -> dict:
    return dict(files_seen=cov["files_seen"], files_parsed=cov["files_parsed"],
                parse_failures=cov["parse_failures"], excluded_dirs=cov["excluded_dirs"],
                settings_modules=cov["settings_modules"], root_urlconfs=cov["root_urlconfs"],
                routes_total=cov["routes_total"], entries_total=cov["entries_total"],
                gaps_by_type=cov["gaps_by_type"], gap_keys=sorted(g["key"] for g in cov["gaps"]),
                dependency_files=cov.get("dependency_files", []), dependency_specs=cov.get("dependency_specs", {}),
                limits=cov["limits"],
                test_code={k: cov["test_code"][k] for k in ("included", "excluded_files", "reincluded")}
                if "test_code" in cov else None)


def _lock_path(p: dict) -> dict:
    return dict(
        id=p["id"],
        entry_point=p["entry"],
        mint_site=p["mint"],
        purpose=p["mint"]["purpose"],
        evidence=p["evidence"],
        chain=p["chain"],
        analysis_complete=p["analysis_complete"],
        fingerprint_complete=p.get("fingerprint_complete", True),     # (v5 review)
        gaps=p["gaps"],
        fingerprint=p["fingerprint"],
        # (v6b) informational: review group (credential kind), risk and why (not compared by diff)
        **({"review": p["review"]} if "review" in p else {}),
        review_status="unreviewed",
        policy_note="",
        reviewer="",
    )


def _lock_settings(g: dict) -> dict:
    return dict(g, review_status="unreviewed", policy_note="", reviewer="")


def running_python() -> str:
    return "%d.%d" % sys.version_info[:2]


def _lock_tool(tool: dict) -> dict:
    """The report's tool section, as stored in the lock (release 0.5.0a1): absolute --library-path directories
    are replaced by their number (they would put the reviewer's home directory into a committed file, and diff
    does not read them), and the Python version that wrote the lock is recorded."""
    out = {k: v for k, v in tool.items() if k != "library_paths"}
    out["library_paths_count"] = len(tool.get("library_paths") or [])
    out["python"] = running_python()
    return out


def _candidate_member(c: dict) -> dict:
    site = c["mint"].get("site") or {}
    return dict(site=f"{site.get('function') or c['entry']['view']}",
                line=site.get("line"),
                file=site.get("file"), mint=c["mint"]["api"], purpose=c["mint"]["purpose"],
                rank=c["candidate"]["rank"], reason=c["candidate"]["reason"],
                reached_from=list(c["entry"].get("reached_from") or []), status=c["evidence"]["status"],
                fingerprint=c["fingerprint"]["overall"], components=c["fingerprint"]["components"],
                gaps=c["gaps"], analysis_complete=c["analysis_complete"])


def _lock_candidates(report: dict) -> list:
    """(v6) One lock entry per candidate kind; each member is one candidate site (see candidates.py)."""
    from .fingerprint import digest
    groups: dict = {}
    for c in report.get("candidates", []):
        grp = c["candidate"]["group"]
        g = groups.setdefault(grp, dict(id=f"candidates:{grp}", kind="candidate_group", group=grp, members={}))
        g["members"][c["id"]] = _candidate_member(c)
    out = []
    for grp, g in sorted(groups.items()):
        g["fingerprint"] = dict(overall=digest(sorted(f"{mid}={m['fingerprint']}" for mid, m in g["members"].items())))
        out.append(dict(g, review_status="unreviewed", policy_note="", reviewer=""))
    return out


def _watched_member(w: dict) -> dict:
    site = w["mint"].get("site") or {}
    return dict(site=site.get("function"), line=site.get("line"), file=site.get("file"), mint=w["mint"]["api"],
                purpose=w["mint"]["purpose"], rank=w["watch"]["rank"], reason=w["watch"]["reason"],
                reached_from=list(w["entry"].get("reached_from") or []), status=w["evidence"]["status"],
                fingerprint=w["fingerprint"]["overall"], components=w["fingerprint"]["components"],
                gaps=w.get("gaps", []), analysis_complete=w.get("analysis_complete", True))


def _lock_watched(report: dict) -> list:
    """(v6c) One lock entry per watched kind (`watched:<kind>`); each member is one site a precision rule set aside."""
    from .fingerprint import digest
    groups: dict = {}
    for w in report.get("watched", []):
        grp = w["watch"]["group"]
        g = groups.setdefault(grp, dict(id=f"watched:{grp}", kind="watched_group", group=grp, members={}))
        g["members"][w["id"]] = _watched_member(w)
    out = []
    for grp, g in sorted(groups.items()):
        g["fingerprint"] = dict(overall=digest(sorted(f"{mid}={m['fingerprint']}" for mid, m in g["members"].items())))
        out.append(dict(g, review_status="unreviewed", policy_note="", reviewer=""))
    return out


def build_lock(report: dict) -> dict:
    return dict(mintmap_lock_version=LOCK_VERSION, tool=_lock_tool(report["tool"]), project=report["project"],
                coverage=_lock_coverage(report["coverage"]),
                # (v5, R7) global auth settings: one reviewable entry per group (not hashed into every path)
                settings=[_lock_settings(g) for g in report.get("settings_groups", [])],
                paths=[_lock_path(p) for p in report["paths"]],
                # (v6) candidate tier: one entry per kind, members = candidate sites
                candidates=_lock_candidates(report),
                # (v6c) watched tier: sites set aside by a precision rule, one entry per kind
                watched=_lock_watched(report))


def _cut(v, n=160) -> str:
    v = str(v)
    return v if len(v) <= n else v[:n - 3] + "..."


def _settings_change(o: dict, n: dict) -> str:
    """Which settings / project sources of a settings group changed, with old -> new values."""
    of, nf = o.get("fingerprint", {}), n.get("fingerprint", {})
    out = []
    for name in sorted(set(of.get("settings", {})) | set(nf.get("settings", {}))):
        a, b = of.get("settings", {}).get(name), nf.get("settings", {}).get(name)
        if a == b:
            continue
        ov, nv = o.get("values", {}).get(name), n.get("values", {}).get(name)
        oi, ni = o.get("items", {}).get(name), n.get("items", {}).get(name)
        if a is None:
            out.append(f"{name} added" + (f" ({_cut(nv)})" if nv is not None else ""))
        elif b is None:
            out.append(f"{name} removed")
        elif oi is not None and ni is not None and oi != ni:
            plus = [x for x in ni if x not in oi]
            minus = [x for x in oi if x not in ni]
            moved = "" if plus or minus else " (order changed)"
            out.append(f"{name}:" + "".join(f" +{x}" for x in plus) + "".join(f" -{x}" for x in minus) + moved)
        elif ov != nv:
            out.append(f"{name}: {_cut(ov)} -> {_cut(nv)}")
        else:
            out.append(f"{name}: statements or the conditions deciding it changed (value as evaluated unchanged; "
                       f"MintMap keeps every branch)")
    for src in sorted(set(of.get("sources", {})) | set(nf.get("sources", {}))):
        a, b = of.get("sources", {}).get(src), nf.get("sources", {}).get(src)
        if a != b:
            out.append(f"project code {src} " + ("added" if a is None else "removed" if b is None else "changed"))
    return "; ".join(out) or "fingerprint changed"


def merge_lock(old: dict, report: dict) -> tuple[dict, list]:
    """New lock from report; keep human review fields only where the entry is
    unchanged (same id, same overall fingerprint, same purpose, no downgrade)."""
    new = build_lock(report)
    old_by_id = {p["id"]: p for p in old.get("paths", [])}
    notes = []
    old_settings = {g["id"]: g for g in old.get("settings", [])}
    for g in new["settings"]:
        o = old_settings.get(g["id"])
        if o and o["fingerprint"]["overall"] == g["fingerprint"]["overall"]:
            for f in REVIEW_FIELDS:
                g[f] = o.get(f, g[f])
        elif o:
            g["previous_review"] = {f: o.get(f) for f in REVIEW_FIELDS}
            notes.append(f"{g['id']} changed: review reset to unreviewed")
        else:
            notes.append(f"new {g['id']} (unreviewed)")
    old_c = {g["id"]: g for g in old.get("candidates", []) + old.get("watched", [])}
    for g in new["candidates"] + new["watched"]:
        o = old_c.get(g["id"])
        if o and o["fingerprint"]["overall"] == g["fingerprint"]["overall"]:
            for f in REVIEW_FIELDS:
                g[f] = o.get(f, g[f])
        elif o:
            g["previous_review"] = {f: o.get(f) for f in REVIEW_FIELDS}
            notes.append(f"{g['id']} changed: review reset to unreviewed")
        else:
            notes.append(f"new {g['id']} with {len(g['members'])} site(s) (unreviewed)")
    for p in new["paths"]:
        o = old_by_id.get(p["id"])
        if not o:
            notes.append(f"new path {p['id']} (unreviewed)")
            continue
        unchanged = (o["fingerprint"]["overall"] == p["fingerprint"]["overall"] and o["purpose"] == p["purpose"]
                     and not _downgrades(o, p))
        if unchanged:
            for f in REVIEW_FIELDS:
                p[f] = o.get(f, p[f])
        else:
            p["previous_review"] = {f: o.get(f) for f in REVIEW_FIELDS}
            p["previous_review"]["fingerprint"] = o["fingerprint"]["overall"]
            notes.append(f"path {p['id']} changed: review reset to unreviewed")
    return new, notes


def _downgrades(old_p: dict, new_p: dict) -> list:
    out = []
    of, nf = old_p["evidence"].get("factors", {}), new_p["evidence"].get("factors", {})
    for f, rel in of.items():
        n = nf.get(f, "absent")
        if FACTOR_RANK.get(n, 0) < FACTOR_RANK.get(rel, 0):
            out.append(f"factor {f}: {rel} -> {n}")
    os_, ns = old_p["evidence"].get("status"), new_p["evidence"].get("status")
    if os_ == SHADOWED_STATUS and ns != SHADOWED_STATUS:
        out.append(f"status: {os_} -> {ns} (the route is no longer shadowed by an earlier pattern: the mint is "
                   f"reachable through it)")
    elif STATUS_RANK.get(os_) is not None and STATUS_RANK.get(ns) is not None and STATUS_RANK[ns] < STATUS_RANK[os_]:
        out.append(f"status: {os_} -> {ns}")
    return out


def diff(lock: dict, report: dict) -> tuple[list, int]:
    findings = []
    code = 0

    def add(bit, path_id, msg, **extra):
        nonlocal code
        code |= bit
        findings.append(dict(kind=BIT_NAMES[bit], path_id=path_id, message=msg, **extra))

    cur = {p["id"]: p for p in build_lock(report)["paths"]}
    old = {p["id"]: p for p in lock.get("paths", [])}
    for pid in sorted(set(cur) - set(old)):
        p = cur[pid]
        add(NEW_PATH, pid, f"new mint path: {p['entry_point']['id']} -> {p['mint_site']['api']} "
                           f"[{p['purpose']}] evidence={p['evidence']['status']}")
    for pid in sorted(set(old) - set(cur)):
        p = old[pid]
        add(REMOVED_PATH, pid, f"locked path no longer found: {p['entry_point']['id']} -> {p['mint_site']['api']} "
                               f"(code removed, or the analysis can no longer see it)")
    for pid in sorted(set(cur) & set(old)):
        o, n = old[pid], cur[pid]
        changed = False
        ogot = set((o.get("entry_point") or {}).get("reached_from") or [])
        ngot = set((n.get("entry_point") or {}).get("reached_from") or [])
        if ngot - ogot and (n.get("entry_point") or {}).get("kind") == "heuristic_site":
            # (v6c) a grouped heuristic site reached from a new entry point is a new way to obtain the credential
            add(NEW_PATH, pid, f"new entry point(s) reach the grouped site {n['mint_site']['api']} at "
                               f"{(n['mint_site'].get('site') or {}).get('function')}: "
                               f"{_cut(', '.join(sorted(ngot - ogot)), 300)}")
            changed = True
        if o["fingerprint"]["overall"] != n["fingerprint"]["overall"]:
            comps = sorted(k for k in n["fingerprint"]["components"]
                           if o["fingerprint"]["components"].get(k) != n["fingerprint"]["components"][k])
            add(FINGERPRINT_CHANGED, pid, f"evidence inputs changed ({', '.join(comps)}); "
                                          f"previous review ({o.get('review_status')}) no longer applies",
                components=comps)
            changed = True
        dg = _downgrades(o, n)
        if dg:
            add(EVIDENCE_DOWNGRADED, pid, "; ".join(dg))
            changed = True
        if o["purpose"] != n["purpose"]:
            add(PURPOSE_CHANGED, pid, f"purpose {o['purpose']} -> {n['purpose']}")
            changed = True
        if o.get("analysis_complete") and not n.get("analysis_complete"):
            add(COVERAGE_REGRESSION, pid, "path analysis became incomplete: " + ", ".join(
                sorted(set(n["gaps"]) - set(o.get("gaps", [])))[:5]))
            changed = True
        elif o.get("fingerprint_complete", True) and not n.get("fingerprint_complete", True):
            # (v5 review) the callee closure is now truncated by the depth limit
            add(COVERAGE_REGRESSION, pid, "path fingerprint became incomplete: " + ", ".join(
                sorted(set(n["gaps"]) - set(o.get("gaps", [])))[:5]))
            changed = True
        if not changed and o.get("review_status") != "accepted":
            add(UNREVIEWED, pid, f"lock entry not accepted (review_status={o.get('review_status')!r})")
    # (v5, R7) settings groups: one finding per changed group, whatever the number of paths
    old_s = {g["id"]: g for g in lock.get("settings", [])}
    cur_s = {g["id"]: g for g in build_lock(report)["settings"]}
    for gid in sorted(set(cur_s) | set(old_s)):
        o, n = old_s.get(gid), cur_s.get(gid)
        if o is None:
            add(FINGERPRINT_CHANGED, gid, f"new settings group {gid}: " + "; ".join(
                f"{k}={v}" for k, v in sorted(n.get("values", {}).items()))[:600], components=["settings"])
        elif n is None:
            add(FINGERPRINT_CHANGED, gid, f"settings group {gid} no longer present (its settings were removed)",
                components=["settings"])
        elif o["fingerprint"]["overall"] != n["fingerprint"]["overall"]:
            add(FINGERPRINT_CHANGED, gid, f"settings group {gid} changed: {_settings_change(o, n)}; previous "
                                          f"review ({o.get('review_status')}) no longer applies",
                components=["settings"])
        elif o.get("review_status") != "accepted":
            add(UNREVIEWED, gid, f"settings group not accepted (review_status={o.get('review_status')!r})")
    # (v6) candidate groups and (v6c) watched groups: findings per member site
    built = build_lock(report)
    for tier, key in (("candidate", "candidates"), ("watched", "watched")):
        _diff_groups(lock.get(key, []), built[key], tier, add, findings)
    # coverage
    _diff_coverage(lock, report, add, findings)
    return findings, code


def _diff_groups(old_groups, cur_groups, tier, add, findings):
    old_c = {g["id"]: g for g in old_groups}
    cur_c = {g["id"]: g for g in cur_groups}
    what = "candidate" if tier == "candidate" else "watched site (set aside by a rule as not a credential)"
    for gid in sorted(set(cur_c) | set(old_c)):
        o, n = old_c.get(gid), cur_c.get(gid)
        om, nm = (o or {}).get("members", {}), (n or {}).get("members", {})
        before = len(findings)
        for mid in sorted(set(nm) - set(om)):
            m = nm[mid]
            add(NEW_PATH, mid, f"new {what} ({gid}, {m['rank']}): {m['site']} -> {m['mint']}; reached from "
                               f"{len(m['reached_from'])} entry point(s) {_cut(', '.join(m['reached_from']), 200)}; "
                               f"{_cut(m['reason'], 300)}", tier=tier, group=gid)
        for mid in sorted(set(om) - set(nm)):
            m = om[mid]
            add(REMOVED_PATH, mid, f"{what} no longer found ({gid}): {m['site']} -> {m['mint']} (code removed, "
                                   f"or the analysis can no longer see it, or it is now reported elsewhere)",
                tier=tier, group=gid)
        for mid in sorted(set(om) & set(nm)):
            a, b = om[mid], nm[mid]
            if a["fingerprint"] == b["fingerprint"]:
                continue
            comps = sorted(k for k in b["components"] if a["components"].get(k) != b["components"][k])
            gained = sorted(set(b["reached_from"]) - set(a["reached_from"]))
            lost = sorted(set(a["reached_from"]) - set(b["reached_from"]))
            extra = "".join([f"; now also reached from {_cut(', '.join(gained), 300)}" if gained else "",
                             f"; no longer reached from {_cut(', '.join(lost), 300)}" if lost else ""])
            add(FINGERPRINT_CHANGED, mid, f"{tier} {m_site(b)} ({gid}) changed ({', '.join(comps)}){extra}; "
                                          f"previous review of {gid} ({(o or {}).get('review_status')}) no longer "
                                          f"applies", components=comps, tier=tier, group=gid)
        if len(findings) == before and o is not None and nm and o.get("review_status") != "accepted":
            add(UNREVIEWED, gid, f"{tier} group not accepted (review_status={o.get('review_status')!r}, "
                                 f"{len(nm)} site(s))", tier=tier, group=gid)


def _diff_coverage(lock, report, add, findings):
    oc, nc = lock.get("coverage", {}), _lock_coverage(report["coverage"])
    if nc["files_parsed"] < oc.get("files_parsed", 0):
        add(COVERAGE_REGRESSION, None, f"parsed files decreased {oc.get('files_parsed')} -> {nc['files_parsed']}")
    old_pf = {f["file"] for f in oc.get("parse_failures", [])}
    new_pf = {f["file"] for f in nc["parse_failures"]}
    if new_pf - old_pf or len(nc["parse_failures"]) > len(oc.get("parse_failures", [])):
        add(COVERAGE_REGRESSION, None, f"new parse failures: {sorted(new_pf - old_pf)}")
    new_gaps = sorted(set(nc["gap_keys"]) - set(oc.get("gap_keys", [])))
    if new_gaps:
        add(COVERAGE_REGRESSION, None, f"{len(new_gaps)} new analysis gap(s): " + "; ".join(new_gaps[:8]),
            gaps=new_gaps)
    for t, c in nc["gaps_by_type"].items():
        if c > oc.get("gaps_by_type", {}).get(t, 0) and not new_gaps:
            add(COVERAGE_REGRESSION, None, f"gap count for {t} increased")
    added_excl = sorted(set(nc["excluded_dirs"]) - set(oc.get("excluded_dirs", [])))
    if added_excl:
        add(COVERAGE_REGRESSION, None, f"new excluded directories: {added_excl}")
    otc, ntc = oc.get("test_code") or {}, nc.get("test_code") or {}
    if otc.get("included") and not ntc.get("included", False):
        add(COVERAGE_REGRESSION, None, "test code was analysed when the lock was written and is now excluded "
                                       "(--include-tests not given)")
    if ntc.get("excluded_files", 0) > otc.get("excluded_files", 0) and otc:
        findings.append(dict(kind="info", path_id=None,
                             message=f"excluded test files {otc.get('excluded_files', 0)} -> "
                                     f"{ntc.get('excluded_files', 0)}"))
    if nc["settings_modules"] != oc.get("settings_modules") or nc["root_urlconfs"] != oc.get("root_urlconfs"):
        add(COVERAGE_REGRESSION, None, f"settings/URLconf roots changed: {oc.get('settings_modules')}/"
                                       f"{oc.get('root_urlconfs')} -> {nc['settings_modules']}/{nc['root_urlconfs']}")
    fixed = sorted(set(oc.get("gap_keys", [])) - set(nc["gap_keys"]))
    if fixed:
        findings.append(dict(kind="info", path_id=None, message=f"{len(fixed)} gap(s) resolved; run `update` to "
                                                                  f"record improved coverage"))
    if lock.get("tool", {}).get("catalog_sha256") != report["tool"]["catalog_sha256"] or \
            lock.get("tool", {}).get("overlay_sha256") != report["tool"]["overlay_sha256"]:
        findings.append(dict(kind="info", path_id=None, message="catalog/overlay changed since the lock was written"))
    lock_py = lock.get("tool", {}).get("python")
    if lock_py and lock_py != running_python():
        findings.append(dict(kind="info", path_id=None, message=(
            f"lock written with Python {lock_py}, running Python {running_python()}. Fingerprints are designed "
            f"to be the same on every supported version (tested on 3.11-3.13); if most paths report "
            f"fingerprint_changed without a code change, run MintMap with Python {lock_py}")))


def m_site(m: dict) -> str:
    return f"{m['site']} -> {m['mint']}"


def dump(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"

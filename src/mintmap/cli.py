"""MintMap CLI (Django only, standard library only).

  mintmap scan   <project_dir> [--json out.json] [--include-tests] [--library-path DIR]
  mintmap init   <project_dir> [--lock mintmap.lock] [--force]
  mintmap update <project_dir> [--lock mintmap.lock]
  mintmap diff   <project_dir> [--lock mintmap.lock] [--json findings.json]
  mintmap accept <project_dir> (ID... | --group GROUP | --all) --reviewer NAME [--note TEXT] [--lock mintmap.lock]
  mintmap --version

Project code is parsed with `ast`; it is never imported or executed.
Exit code 128 means MintMap could not run (bad arguments, lock or catalog, or an internal error).
"""
from __future__ import annotations

import argparse
import json
import os
import sys


from .core.analysis import Analysis, TOOL_VERSION
from .core.catalog import load_catalog, DEFAULT_CATALOG, CatalogError
from .core.lockfile import build_lock, merge_lock, diff, dump, BIT_NAMES
from .core.project import DEFAULT_EXCLUDED_DIRS
from .core import review

EXIT_ERROR = 128


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse would exit 2, which collides with REMOVED_PATH
        self.print_usage(sys.stderr)
        sys.stderr.write(f"mintmap: error: {message}\n")
        sys.exit(EXIT_ERROR)


def run_scan(args) -> dict:
    catalog = load_catalog(args.catalog)
    excluded = set(DEFAULT_EXCLUDED_DIRS) | set(args.exclude or [])
    lib = [p for v in (args.library_path or []) for p in v.split(os.pathsep) if p]
    return Analysis(args.project_dir, catalog, excluded_dirs=excluded, fp_depth=args.fingerprint_depth,
                    chain_limit=args.chain_limit, include_tests=args.include_tests, library_paths=lib).run()


def _where(m: dict, entry: dict) -> str:
    if m.get("site"):
        return f"{m['site']['function']}:{m['site']['line']}"
    return f"library, via {m.get('provided_via')}" if m.get("provided_via") else entry.get("view") or "library"


def review_queue(report: dict) -> list:
    """(v6b) The day-one review queue: confirmed paths grouped by credential kind and entry point, candidate sites by
    kind, each ranked by risk with the reason it was reported."""
    paths = [p for p in report["paths"]]
    cands = report.get("candidates", [])
    settings = report.get("settings_groups", [])
    for p in paths:
        p.setdefault("review", review.path_review(p))
    for c in cands:
        c.setdefault("review", review.candidate_review(c))
    groups: dict = {}
    for p in paths:
        groups.setdefault(p["review"]["group"], []).append(p)
    cgroups: dict = {}
    for c in cands:
        cgroups.setdefault(c["review"]["group"], []).append(c)
    watched = report.get("watched", [])
    n_wgroups = len({w["watch"]["group"] for w in watched})
    n_entries = len(paths) + len(cgroups) + len(settings) + n_wgroups
    lines = [f"REVIEW QUEUE: {n_entries} lock entr{'y' if n_entries == 1 else 'ies'}: {len(paths)} path(s) in "
             f"{len(groups)} credential kind(s), {len(cands)} candidate site(s) in {len(cgroups)} group entr"
             f"{'y' if len(cgroups) == 1 else 'ies'}, {len(settings)} settings group(s), {len(watched)} watched "
             f"site(s) in {n_wgroups} group entr{'y' if n_wgroups == 1 else 'ies'}. Highest risk first; "
             f"'why' says why each entry was reported."]

    def rkey(x):
        return (review.RISK_ORDER.get(x["review"]["risk"], 9), -x["review"]["score"], x["entry"]["id"], x["id"])
    for g in sorted(groups, key=review.group_key):
        ps = groups[g]
        cnt = {r: sum(1 for p in ps if p["review"]["risk"] == r) for r in ("high", "medium", "low")}
        by_entry: dict = {}
        for p in ps:
            by_entry.setdefault(p["entry"]["id"], []).append(p)
        lines.append(f"  {g}  {review.KINDS.get(g[5:], '')}: {len(ps)} path(s) from {len(by_entry)} entry point(s); "
                     f"{cnt['high']} high, {cnt['medium']} medium, {cnt['low']} low")
        for eid, eps in sorted(by_entry.items(), key=lambda kv: min(rkey(p) for p in kv[1])):
            eps = sorted(eps, key=rkey)
            lines.append(f"    {eid}" + (f"  ({len(eps)} paths)" if len(eps) > 1 else ""))
            for p in eps:
                m = p["mint"]
                lines.append(f"      [{p['id']}] {p['review']['risk']:<6} {m['api']} at {_where(m, p['entry'])}")
                lines.append(f"          why: {'; '.join(p['review']['why'])}")
    for g in sorted(cgroups):
        cs = sorted(cgroups[g], key=rkey)
        cnt = {r: sum(1 for c in cs if c["review"]["risk"] == r) for r in ("high", "medium", "low")}
        desc = ((report["coverage"].get("candidates") or {}).get("groups") or {}).get(g.split(":", 1)[1], {})
        lines.append(f"  {g}  (one lock entry; lower confidence) {desc.get('description', '')}: {len(cs)} site(s); "
                     f"{cnt['high']} high, {cnt['medium']} medium, {cnt['low']} low")
        for c in cs:
            reached = c["entry"].get("reached_from") or []
            lines.append(f"      [{c['id']}] {c['review']['risk']:<6} {_where(c['mint'], c['entry'])}  reached from "
                         f"{len(reached)} entry point(s): {', '.join(reached[:3])}{' ...' if len(reached) > 3 else ''}")
            lines.append(f"          why: {c['candidate']['reason']}")
    if settings:
        lines.append(f"  settings  authentication settings, one lock entry per group: "
                     f"{', '.join(g['id'] for g in settings)}")
    wgroups: dict = {}
    for w in report.get("watched", []):
        wgroups.setdefault(f"watched:{w['watch']['group']}", []).append(w)
    descs = (report["coverage"].get("watched") or {}).get("groups") or {}
    for g in sorted(wgroups):
        ws = wgroups[g]
        lines.append(f"  {g}  (one lock entry; set aside as NOT credentials by a rule, watched so that a change is "
                     f"a finding) {descs.get(g.split(':', 1)[1], {}).get('description', '')}: {len(ws)} site(s)")
        for w in ws[:WATCHED_SHOWN]:
            reached = w["entry"].get("reached_from") or []
            lines.append(f"      [{w['id']}] {w['mint']['api']} at {_where(w['mint'], w['entry'])}  reached from "
                         f"{len(reached)}: {', '.join(reached[:2])}{' ...' if len(reached) > 2 else ''}")
            lines.append(f"          set aside: {w['watch']['reason'][:200]}")
        if len(ws) > WATCHED_SHOWN:
            lines.append(f"      ... {len(ws) - WATCHED_SHOWN} more (see --json `watched`)")
    lines.append("  after reviewing a group: mintmap accept <dir> --group <group> --reviewer NAME "
                 "(groups: " + ", ".join(sorted(groups, key=review.group_key) + sorted(cgroups) +
                                         (["settings"] if settings else []) + sorted(wgroups)) + ")")
    return lines


WATCHED_SHOWN = 15


def summarize(report: dict) -> str:
    cov = report["coverage"]
    lines = [f"MintMap {report['tool']['version']}  project={report['project']}",
             f"files parsed {cov['files_parsed']}/{cov['files_seen']}  parse failures {len(cov['parse_failures'])}  "
             f"settings {cov['settings_modules']}  root URLconf {cov['root_urlconfs']}",
             f"test code {'included' if cov['test_code']['included'] else 'excluded'}: "
             f"{cov['test_code']['excluded_files']} file(s) excluded {cov['test_code']['excluded_by_reason']}, "
             f"{len(cov['test_code']['reincluded'])} re-included because non-test code imports them",
             f"source roots {cov.get('source_roots')}  modules named through a source root (namespace packages): "
             f"{cov.get('namespace_modules', 0)}",
             f"routes {cov['routes_total']} {cov['routes_by_kind']}  entries {cov['entries_total']}  "
             f"authenticate() factor: {cov['authentication_backends_factor']}",
             f"mint paths: {len(report['paths'])} ({cov.get('paths_unrouted', 0)} unrouted, "
             f"{cov.get('paths_shadowed', 0)} shadowed by an earlier route; shadowed routes: "
             f"{cov.get('routes_shadowed', 0)}, library sub-routes: {cov.get('library_subroutes_shadowed', 0)}, "
             f"possibly shadowed (conditional earlier route): {cov.get('routes_may_be_shadowed', 0)})"]
    lines += review_queue(report)
    lines.append("PATH DETAILS (check evidence), in review-queue order")
    order = sorted(report["paths"], key=lambda p: (review.group_key(p["review"]["group"]),
                                                    review.RISK_ORDER.get(p["review"]["risk"], 9),
                                                    -p["review"]["score"], p["entry"]["id"], p["id"]))
    for p in order:
        m = p["mint"]
        lines.append(f"  [{p['id']}] {p['entry']['id']}")
        lines.append(f"      mints {m['api']} purpose={m['purpose']} at {_where(m, p['entry'])}")
        ev = p["evidence"]
        lines.append(f"      evidence={ev['status']} factors={ev['factors']} complete={p['analysis_complete']} "
                     f"fingerprint_complete={p.get('fingerprint_complete', True)}")
        if ev.get("shadowed_by"):
            sb = ev["shadowed_by"]
            lines.append(f"      shadowed by {sb['pattern']!r} -> {sb['target']} ({sb['file']}:{sb['line']}); "
                         f"status if reachable: {ev.get('status_if_reachable')}")
        for c in ev["checks"]:
            lines.append(f"        - {c['check']} ({c['factor']}, via {c['via']}) {c['relation']}; "
                         f"same_user={c['same_user']}: {c['detail']}")
        for u in ev.get("unrecognized_checks", []):
            lines.append(f"        ? unrecognized check {u['call']} in {u['function']}:{u['line']} -> {u['target']} "
                         f"({u['reason']})")
    cs = cov.get("candidates") or {}
    lines.append(f"candidates: {len(report.get('candidates', []))} site(s) (listed in the review queue); "
                 f"{cs.get('set_aside_count', 0)} session write(s) set aside")
    cc = cov.get("custom_credentials") or {}
    aside = len(cc.get("set_aside") or []) + len(cc.get("session_lookups_set_aside") or [])
    if aside:
        lines.append(f"custom-credential heuristic: {aside} random value(s) / session lookup(s) set aside as not "
                     f"credentials; {len(report.get('watched', []))} watched site(s) are in the lock (the others "
                     f"are named as identifiers, files, cache keys ...; see --json coverage.custom_credentials)")
    off = cov.get("library_flows_disabled_by_settings") or []
    if off:
        lines.append(f"library flows switched off by settings (not paths; enabling one is a new path): {len(off)}")
        for d in off[:20]:
            lines.append(f"  {d['entry']} -> {d['mint']}: {d['why']}")
        if len(off) > 20:
            lines.append(f"  ... {len(off) - 20} more (see --json)")
    lines.append(f"gaps by type: {cov['gaps_by_type'] or '{}'}")
    for g in cov["gaps"][:40]:
        lines.append(f"  gap {g['type']}: {g['file']} {g['where']} :: {g['detail']}")
    if len(cov["gaps"]) > 40:
        lines.append(f"  ... {len(cov['gaps']) - 40} more (see --json)")
    lines.append(f"catalog entries not mapped to symbols: {len(report['tool']['catalog_entries_unmapped'])}")
    return "\n".join(lines)


def _load_lock(lock_path: str):
    """The lock as a dict, or None after printing why it cannot be used."""
    try:
        with open(lock_path) as fh:
            lock = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"mintmap: cannot read lock {lock_path}: {exc}", file=sys.stderr)
        return None
    ok = isinstance(lock, dict) and all(
        isinstance(lock.get(k, []), list) and all(isinstance(e, dict) and isinstance(e.get("id"), str)
                                                  for e in lock.get(k, []))
        for k in ("paths", "settings", "candidates", "watched"))
    if not ok or "paths" not in lock:
        print(f"mintmap: {lock_path} is not a MintMap lock (expected a JSON object with a 'paths' list of entries)",
              file=sys.stderr)
        return None
    return lock


def run_accept(args, lock_path: str) -> int:
    """Mark lock entries accepted. This records a review decision; it does not re-scan the code."""
    if not args.ids and not args.all and not args.group:
        print("mintmap: give entry ids to accept, --group GROUP, or --all", file=sys.stderr)
        return EXIT_ERROR
    lock = _load_lock(lock_path)
    if lock is None:
        return EXIT_ERROR
    entries = list(lock.get("settings", [])) + list(lock.get("candidates", [])) + list(lock.get("watched", [])) + \
        list(lock.get("paths", []))
    chosen = []
    if args.all:
        chosen = [e for e in entries if e.get("review_status") != "accepted"]
    # (v6b) a review group of the report's review queue: kind:<credential kind>, candidates:<kind>, settings
    groups: dict = {}
    for e in entries:
        groups.setdefault(review.lock_entry_group(e), []).append(e)
    for g in args.group or []:
        if g not in groups:
            print(f"mintmap: no lock entries in group {g!r} (groups in this lock: {', '.join(sorted(groups))})",
                  file=sys.stderr)
            return EXIT_ERROR
        for e in groups[g]:
            if e not in chosen:
                chosen.append(e)
    for want in args.ids:
        hits = [e for e in entries if e["id"] == want]
        if not hits and len(want) >= 8:
            hits = [e for e in entries if e["id"].startswith(want)]
        if len(hits) != 1:
            why = "no lock entry" if not hits else f"{len(hits)} lock entries"
            print(f"mintmap: {why} matches {want!r}", file=sys.stderr)
            return EXIT_ERROR
        if hits[0] not in chosen:
            chosen.append(hits[0])
    for e in chosen:
        e["review_status"] = "accepted"
        e["reviewer"] = args.reviewer
        e["policy_note"] = args.note
        print(f"accepted {e['id']}")
    with open(lock_path, "w") as fh:
        fh.write(dump(lock))
    left = sum(1 for e in entries if e.get("review_status") != "accepted")
    print(f"{len(chosen)} entr{'y' if len(chosen) == 1 else 'ies'} accepted; {left} not accepted")
    print("accept records a decision on the lock as written; it does not re-scan. After a code change run "
          "`mintmap update` first, and run `mintmap diff` to confirm the lock matches the code.")
    return 0


def main(argv=None) -> int:
    ap = _Parser(prog="mintmap", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"mintmap {TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    for name in ("scan", "init", "update", "diff"):
        sp = sub.add_parser(name)
        sp.add_argument("project_dir")
        sp.add_argument("--catalog", default=DEFAULT_CATALOG)
        sp.add_argument("--exclude", action="append", help="directory name to skip (recorded in coverage)")
        sp.add_argument("--fingerprint-depth", type=int, default=4)
        sp.add_argument("--chain-limit", type=int, default=16)
        sp.add_argument("--include-tests", action="store_true",
                        help="also analyse test code (tests/ and test/ dirs, test_*.py, *_test(s).py, tests.py, "
                             "conftest.py, test.py/testing.py defining TestCase subclasses); excluded by default")
        sp.add_argument("--library-path", action="append",
                        help="(v5) directory with library source, read only (site-packages, or a directory of "
                             "unpacked wheels); repeatable or os.pathsep-separated. Used to resolve library view "
                             "aliases, re-exports and class bases. Nothing is imported.")
        sp.add_argument("--json", help="write the full report / findings as JSON")
        if name != "scan":
            sp.add_argument("--lock", help="lock file (default: <project_dir>/mintmap.lock)")
        if name == "init":
            sp.add_argument("--force", action="store_true")
    sp = sub.add_parser("accept", help="record a human review: mark lock entries accepted (no scan)")
    sp.add_argument("project_dir")
    sp.add_argument("ids", nargs="*", help="path ids (or unique prefixes of 8+ characters) and settings ids")
    sp.add_argument("--all", action="store_true", help="accept every entry that is not accepted yet")
    sp.add_argument("--group", action="append",
                    help="(v6b) accept every entry of a review group shown by `scan`: kind:session, kind:token, "
                         "kind:precursor, kind:custom, kind:other, candidates:<kind>, watched:<kind> or settings; "
                         "repeatable")
    sp.add_argument("--reviewer", required=True, help="who reviewed the entries (stored in the lock)")
    sp.add_argument("--note", default="", help="policy note stored with each accepted entry")
    sp.add_argument("--lock", help="lock file (default: <project_dir>/mintmap.lock)")
    # argparse before Python 3.13 does not give positionals that follow an option to an nargs='*' positional
    # (`accept DIR --lock L ID` fails with 'unrecognized arguments'): collect them here instead.
    args, extra = ap.parse_known_args(argv)
    if extra:
        if args.cmd != "accept" or any(x.startswith("-") for x in extra):
            ap.error("unrecognized arguments: " + " ".join(extra))
        args.ids = list(args.ids) + extra
    if not os.path.isdir(args.project_dir):
        print(f"mintmap: not a directory: {args.project_dir}", file=sys.stderr)
        return EXIT_ERROR
    lock_path = getattr(args, "lock", None) or os.path.join(args.project_dir, "mintmap.lock")
    if args.cmd == "accept":
        return run_accept(args, lock_path)
    try:
        report = run_scan(args)
    except CatalogError as exc:
        print(f"mintmap: catalog error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.cmd == "scan":
        if args.json:
            with open(args.json, "w") as fh:
                fh.write(dump(report))
        print(summarize(report))
        return 0
    if args.cmd == "init":
        if os.path.exists(lock_path) and not args.force:
            print(f"mintmap: {lock_path} exists (use update, or --force to discard reviews)", file=sys.stderr)
            return EXIT_ERROR
        with open(lock_path, "w") as fh:
            fh.write(dump(build_lock(report)))
        print(f"wrote {lock_path}: {len(report['paths'])} path(s), all review_status=unreviewed")
        return 0
    lock = _load_lock(lock_path)
    if lock is None:
        return EXIT_ERROR
    if args.cmd == "update":
        new, notes = merge_lock(lock, report)
        with open(lock_path, "w") as fh:
            fh.write(dump(new))
        for n in notes:
            print(n)
        print(f"updated {lock_path}: {len(new['paths'])} path(s)")
        return 0
    findings, code = diff(lock, report)
    if args.json:
        with open(args.json, "w") as fh:
            fh.write(dump(dict(exit_code=code, findings=findings)))
    for f in findings:
        print(f"{f['kind'].upper():22} {f['path_id'] or '-':17} {f['message']}")
    names = [n for b, n in sorted(BIT_NAMES.items()) if code & b]
    print(f"exit {code} ({', '.join(names) or 'ok'})")
    return code


def entry(argv=None) -> int:
    """Console entry point. An unexpected exception must not exit 1, which is the new_path bit: it prints the
    traceback and exits 128 (MintMap could not run), so a crash never passes as an ordinary finding."""
    try:
        code = main(argv)
        sys.stdout.flush()      # inside the try: a closed pipe must not surface later as exit 120 at shutdown
        return code
    except BrokenPipeError:
        # stdout was closed early (`mintmap diff | head`): the result was not shown in full, so it is not a pass
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        print("mintmap: output closed before MintMap finished writing it", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # RecursionError, OSError from a dangling symlink, malformed lock, ...
        import traceback
        traceback.print_exc()
        print(f"mintmap: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(entry())

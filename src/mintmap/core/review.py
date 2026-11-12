"""(v6b) Review cost: group, rank and explain every lock entry so that a day-one review is cheap.

Nothing here changes what is found or fingerprinted: path ids, fingerprints and diff findings do not depend on it.
Each confirmed path gets a `review` block

    review = {group: "kind:<k>", risk: "high" | "medium" | "low", score: int, why: [short reasons]}

and each candidate site gets the same block with group `candidates:<kind>` and its candidate rank as risk.

Credential kinds (`kind:<k>`), from the minted credential's purpose:
    session      a full login session (login(), library login flows, impersonation, an administrator choosing a
                 password, hand-rolled session logins)
    token        a bearer / long-lived credential (API tokens, JWT, OAuth tokens and client secrets)
    precursor    something that leads to a session or token later (reset / magic / invitation tokens, MFA
                 challenge state, one-time codes, session continuation after a password change)
    custom       a project-made credential found by the custom-credential heuristic whose kind is unclear
    other        anything else (purpose unknown or not credential-specific)

Risk is a transparent score (shown in `why`): the credential kind (session 3, token 2, precursor / custom 1), the
check evidence (no check found or a check whose result is not enforced +3, an unrecognized or unverified check +2,
a check whose relation to the mint is unproven or a library flow whose checks are not analysed +1, a route shadowed
by an earlier pattern -3), reachability (a route, middleware or authentication class +1; unrouted 0) and confidence
(a heuristic credential -1; incomplete analysis of project code +1).  high >= 6, medium >= 4, low otherwise.
"""
from __future__ import annotations

KINDS = {
    "session": "full login sessions (login(), library login flows, impersonation, admin-chosen passwords, "
               "hand-rolled session logins)",
    "token": "bearer / long-lived credentials (API tokens, JWT, OAuth tokens and client secrets)",
    "precursor": "credentials that lead to a session or token later (reset / magic / invitation tokens, MFA "
                 "challenge state, one-time codes, session continuation)",
    "custom": "project-made credentials found by the custom-credential heuristic (kind unclear)",
    "other": "other mint paths (purpose unknown or not credential-specific)",
}
KIND_ORDER = {k: i for i, k in enumerate(KINDS)}
KIND_SCORE = {"session": 3, "token": 2, "precursor": 1, "custom": 1, "other": 1}
RISK_ORDER = {"high": 0, "medium": 1, "low": 2}

_SESSION = {"full_session", "impersonation_session", "admin_chosen_password", "custom_session_login_candidate"}
_TOKEN_PREFIXES = ("api_token", "jwt_", "oauth_", "custom_api_token", "custom_library_credential")
_PRECURSOR = {"password_reset_token", "magic_link_token", "invitation_or_signup_token", "mfa_challenge_state",
              "session_rotation_keep_auth", "custom_password_reset_token_candidate",
              "custom_invitation_token_candidate", "custom_recovery_code_candidate",
              "custom_one_time_code_candidate", "custom_password_candidate", "custom_session_token_candidate"}
STATUS_SCORE = {
    "no_check_found_in_analyzed_code": (3, "no check found on the path"),
    "check_result_not_enforced": (3, "a check runs but its result is not enforced"),
    "unrecognized_check_present": (2, "only checks MintMap does not recognise"),
    "guard_relies_on_unverified_check": (2, "the guard relies on a check MintMap could not verify"),
    "check_present_relationship_unproven": (1, "a check is present but its relation to the mint is unproven"),
    "library_flow_checks_not_analyzed": (1, "library flow: its own checks are not analysed"),
    "check_guards_mint": (0, "a recognised check guards the mint"),
    "shadowed_by_earlier_route": (-3, "the route is shadowed by an earlier pattern (not reachable through it)"),
}


def credential_kind(purpose: str) -> str:
    purpose = purpose or ""
    if purpose in _SESSION:
        return "session"
    if purpose.startswith(_TOKEN_PREFIXES):
        return "token"
    if purpose in _PRECURSOR:
        return "precursor"
    if purpose.startswith("custom_"):
        return "custom"
    return "other"


def risk_of(score: int) -> str:
    return "high" if score >= 6 else "medium" if score >= 4 else "low"


def path_review(p: dict) -> dict:
    """The review block of a confirmed path (report path dict)."""
    kind = credential_kind(p["mint"].get("purpose"))
    score = KIND_SCORE[kind]
    why = [f"{kind} credential ({p['mint'].get('purpose')})"]
    st = p["evidence"].get("status")
    s, text = STATUS_SCORE.get(st, (1, st or "evidence unknown"))
    score += s
    why.append(text)
    ek = p["entry"].get("kind")
    if ek == "unrouted":
        why.append("no route, middleware or authentication class reaches it (unrouted)")
    else:
        score += 1
        n = len(p["entry"].get("reached_from") or []) if ek == "heuristic_site" else 1
        why.append(f"reachable from {n} entry point(s)" if ek == "heuristic_site" else f"reachable ({ek})")
    if p["mint"].get("kind") == "heuristic_custom_credential":
        score -= 1
        why.append("found by the custom-credential heuristic (lower confidence)")
    if not p.get("analysis_complete", True):
        if st != "library_flow_checks_not_analyzed":
            score += 1
        why.append("analysis incomplete (see the path's gaps)")
    return dict(group=f"kind:{kind}", risk=risk_of(score), score=score, why=why)


def candidate_review(c: dict) -> dict:
    cinfo = c.get("candidate") or {}
    rank = cinfo.get("rank", "medium")
    return dict(group=f"candidates:{cinfo.get('group')}", risk=rank, score={"high": 6, "medium": 4}.get(rank, 2),
                why=[cinfo.get("reason", "")])


def annotate(report: dict) -> dict:
    for p in report.get("paths", []):
        p["review"] = path_review(p)
    for c in report.get("candidates", []):
        c["review"] = candidate_review(c)
    report.setdefault("coverage", {})["review_summary"] = summary(report)
    return report


def summary(report: dict) -> dict:
    """{group: {entries, high, medium, low, entry_points}} over the confirmed paths and candidate sites."""
    out: dict = {}
    for p in list(report.get("paths", [])) + list(report.get("candidates", [])):
        r = p.get("review") or (candidate_review(p) if p.get("tier") == "candidate" else path_review(p))
        row = out.setdefault(r["group"], dict(entries=0, high=0, medium=0, low=0, entry_points=set()))
        row["entries"] += 1
        row[r["risk"]] += 1
        row["entry_points"].add(p["entry"]["id"])
    return {g: dict(v, entry_points=len(v["entry_points"])) for g, v in sorted(out.items(), key=lambda kv: group_key(kv[0]))}


def group_key(group: str):
    if group.startswith("kind:"):
        return (0, KIND_ORDER.get(group[5:], 9), group)
    return (1, 0, group)


def lock_entry_group(entry: dict) -> str:
    """The review group of a lock entry (also for locks written before v6b, which have no review block)."""
    if entry.get("kind") == "candidate_group" or str(entry.get("id", "")).startswith("candidates:"):
        return entry["id"]
    if str(entry.get("id", "")).startswith("settings:"):
        return "settings"
    r = entry.get("review")
    if isinstance(r, dict) and r.get("group"):
        return r["group"]
    return f"kind:{credential_kind(entry.get('purpose') or (entry.get('mint_site') or {}).get('purpose'))}"

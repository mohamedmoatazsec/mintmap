"""Render `mintmap diff --json` findings as Markdown (used by the GitHub Action for the job summary).

    python -I -m mintmap.ci_summary findings.json [exit_code]

Finding messages quote text from the pull request (route patterns, file names, setting values). Every value is
therefore written as a Markdown code span, with control and bidirectional-formatting characters removed and a
length limit, so that the pull request cannot inject headings, links, images, HTML or @mentions into the summary
a reviewer reads, or push it past GitHub's 1 MiB step-summary limit.
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata

from .core.lockfile import BIT_NAMES

ERROR_BIT = 128
MAX_ROWS = 200
MAX_CELL = 400
MAX_TOTAL = 512 * 1024   # well below GitHub's 1 MiB limit for a step summary

_ADVICE = {
    "new_path": "A new way to obtain a session or credential. Review the route, the checks on the way, and the credential's purpose.",
    "removed_path": "A previously reviewed path is gone. Confirm this was intended.",
    "fingerprint_changed": "Code, checks, hooks or settings on a reviewed path changed. Re-review the path.",
    "evidence_downgraded": "A check on the path got weaker (for example a verified factor is now absent or unproven).",
    "purpose_changed": "The credential issued on this path now has a different purpose.",
    "coverage_regression": "The tool can now analyse less of the code (new gaps, unparsed files, changed roots).",
    "unreviewed": "Lock entries have not been accepted by a reviewer yet.",
    "error": "MintMap could not run (missing or invalid lock, bad project directory, catalog or arguments, or an "
             "internal error). The findings below, if any, are incomplete. See the step log.",
}


def _plain(text: object, limit: int = MAX_CELL) -> str:
    """One line of printable text: whitespace collapsed, control/format (incl. bidi) characters dropped, cut."""
    s = " ".join(str(text).split())
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    if len(s) > limit:
        s = s[:limit - 1] + "…"
    return s


def _cell(text: object, limit: int = MAX_CELL) -> str:
    """A table cell holding `text` as a code span: no Markdown, HTML, link, mention or autolink is interpreted."""
    s = _plain(text, limit)
    if not s:
        return ""
    s = s.replace("|", "\\|")            # GitHub splits table cells on '|' even inside code spans
    longest = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def render(data: dict, code: int | None = None) -> str:
    code = data.get("exit_code", code) if code is None else code
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    bits = [name for bit, name in sorted(BIT_NAMES.items()) if code and code & bit]
    if code and code & ERROR_BIT:
        bits.append("error")
    lines = ["## MintMap: login and credential paths", ""]
    if not code:
        lines.append("No changes to reviewed login/credential paths, and no coverage regression.")
        return "\n".join(lines) + "\n"
    lines.append(f"**Exit {code}**: {', '.join(bits) or 'unknown'}. A security reviewer should look at this pull request.")
    lines.append("")
    for b in bits:
        if b in _ADVICE:
            lines.append(f"- **{b}**: {_ADVICE[b]}")
    lines += ["", "| finding | lock entry | detail |", "|---|---|---|"]
    size = sum(len(x) + 1 for x in lines)
    shown = 0
    for f in findings[:MAX_ROWS]:
        if not isinstance(f, dict):
            continue
        row = f"| {_cell(f.get('kind', ''), 40)} | {_cell(f.get('path_id') or '-', 80)} | {_cell(f.get('message', ''))} |"
        if size + len(row) > MAX_TOTAL:
            break
        lines.append(row)
        size += len(row) + 1
        shown += 1
    if len(findings) > shown:
        lines.append(f"| … | | {len(findings) - shown} more findings in the JSON report |")
    lines.append("")
    if code & ERROR_BIT:
        lines.append("Fix the error shown in the step log. If the project has no lock yet, create one with "
                     "`mintmap init <project_dir>`, review it, record the review with "
                     "`mintmap accept <project_dir> --all --reviewer <name>`, and commit `mintmap.lock`.")
    else:
        lines.append("After review, record the decision: if the code change is intended, run "
                     "`mintmap update <project_dir>`, then `mintmap accept <project_dir> <ids...> --reviewer <name>`, "
                     "and commit `mintmap.lock`.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        with open(argv[0]) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        data = {"findings": []}
    if not isinstance(data, dict):
        data = {"findings": []}
    try:
        code = int(argv[1]) if len(argv) > 1 else None
    except ValueError:
        code = ERROR_BIT
    sys.stdout.write(render(data, code))
    return 0


if __name__ == "__main__":
    sys.exit(main())

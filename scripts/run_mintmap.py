"""Run MintMap from this checkout without installing it. Used by action.yml.

    python -I scripts/run_mintmap.py <mintmap arguments>                  (for example: diff . --json out.json)
    python -I scripts/run_mintmap.py --summary <findings.json> <exit_code>  (Markdown job summary)

Always run it with `python -I`. In a GitHub Actions job the working directory is the pull request's checkout;
`-I` keeps that directory (and PYTHON* environment variables and the user site directory) off sys.path, so files
added by a pull request (for example a top-level `mintmap/` or `json.py`) cannot replace MintMap or the
standard-library modules it imports. Nothing is built, downloaded or installed.
"""
import os
import sys

if not sys.flags.isolated:
    sys.stderr.write("mintmap: scripts/run_mintmap.py must be run with `python -I`\n")
    sys.exit(128)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

if sys.argv[1:2] == ["--summary"]:
    from mintmap.ci_summary import main as summary_main
    sys.exit(summary_main(sys.argv[2:]))

from mintmap.cli import entry  # noqa: E402

sys.exit(entry(sys.argv[1:]))

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
if sys.version_info < (3, 11):
    sys.stderr.write("mintmap: could not start on Python %s: MintMap needs Python 3.11 or newer\n"
                     % sys.version.split()[0])
    sys.exit(128)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

# Exit 128 ("MintMap could not run") if MintMap cannot even be imported, for example on an unsupported Python.
# An uncaught import error would exit 1, which the action and CI read as new_path, not as a failure to run.
try:
    if sys.argv[1:2] == ["--summary"]:
        from mintmap.ci_summary import main as summary_main
    else:
        from mintmap.cli import entry
except Exception as exc:  # noqa: BLE001
    sys.stderr.write(f"mintmap: could not start on Python {sys.version.split()[0]}: {exc!r}\n")
    sys.exit(128)

if sys.argv[1:2] == ["--summary"]:
    sys.exit(summary_main(sys.argv[2:]))
sys.exit(entry(sys.argv[1:]))

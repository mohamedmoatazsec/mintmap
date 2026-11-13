# Changelog

## Unreleased

No change to the analysis, the catalog, fingerprints or the lock format.

- `action.yml`: the description no longer contains an apostrophe, which the GitHub Marketplace page dropped
  ("MintMap s own coverage"). It now ends "or what MintMap can analyse changes."
- The author shown on PyPI (`pyproject.toml`) and in `CITATION.cff` is `mohamedmoatazsec`.
- README and `examples/mintmap.yml`: the Action snippet is pinned to the full commit SHA of the `v0.6.0a2` release,
  with the tag as a comment, and the README has a PyPI version badge.

## 0.6.0a2 (experimental)

The analysis and the catalog are those evaluated as 0.6.0a1. On Python 3.11 to 3.13, analysis results and
fingerprints are unchanged from 0.6.0a1 for projects without symbolic links, a lock written by 0.6.0a1 stays valid,
and the published accuracy numbers still describe this code. (Checked: `scan --json` of the demo, Healthchecks,
Tandoor, CVAT and Label Studio gives the same paths, candidates, watched sites, settings groups, fingerprints and
gaps as 0.6.0a1's frozen tree on 3.11 and 3.13; on 3.14 the result is the same as on 3.13.)

This is the first release on PyPI: `pip install mintmap`.

Fixes:

- **Python 3.14.** MintMap failed on import there (the private unparser it extends moved to `_ast_unparse`). 3.14
  is now tested in CI and listed in the classifiers.
- **Exit 128 when MintMap cannot start.** An import error (an unsupported Python, a broken install) exited 1, the
  `new_path` bit, so the action could report it as a finding or, with a `fail-on` without bit 1, pass. The
  `mintmap` command, `python -m mintmap` and the action's launcher now print
  `mintmap: could not start on Python X: ...` and exit 128; on Python older than 3.11 they say that 3.11 or newer
  is needed.
- **Security: links that leave the project and special files are not read.** A symbolic link to a file outside the
  project directory, and a special file (a FIFO, a device), was read: a pull request could make MintMap print another
  file's strings in the CI log, run it out of memory or hang it. Such a Python file is now a parse failure with a
  `parse_failure` gap, so `diff` reports `coverage_regression`; such a `requirements*.txt` or `pyproject.toml` is
  listed in `coverage.dependency_files_not_read` and in the `scan` report. A lock file (`mintmap.lock` or `--lock`)
  that is a symbolic link or not a regular file is neither read nor written: `diff`, `update`, `init` and `accept`
  exit 128. A dangling link still exits 128. No evaluation project contains such a link, so the published numbers
  still describe this code.
- **Security: no workflow commands from the pull request.** `scan`, `diff`, `update` and `accept` print text from
  the analysed code (route strings, file names, gap details) on one line, with control, format and line-separator
  characters escaped, and the action pauses workflow commands (`::stop-commands::` with a random token) while
  MintMap runs. A pull request can no longer write `::error::` or `::add-mask::` lines into the step log.
- The Action's name is `MintMap for Django`: GitHub Marketplace names must be unique, and `MintMap` is another
  account's name. Workflows keep using `mohamedmoatazsec/mintmap@...`; only the Marketplace listing name changes.
- `action.yml` and the workflows use actions/checkout v7.0.1 and actions/setup-python v7.1.0 (Node 24; Node 20
  is deprecated on GitHub). Self-hosted runners need Actions Runner v2.327.1 or later.
- `scripts/demo.sh` names the Python it needs instead of printing tracebacks on Python older than 3.11.

Added:

- `mintmap --version`.
- A demo project in `examples/demo` (password login, TOTP step, password-reset auto-login, API token endpoint) with
  a reviewed lock and a bad pull request, `scripts/demo.sh` to run it, and a CI job that asserts the failing exit
  code and that the README image matches the real output.
- README rewritten around the demo, with a diagram, an FAQ, measured scan times, Windows notes and first-use
  steps that end with a passing `mintmap diff`. The long explanation of candidates and watched sites moved to the
  new `docs/CONCEPTS.md`.
- `docs/ROADMAP.md`: the known blind spots as open work, linked to issues.
- `docs/EVALUATION.md` restructured for reading. No measured result changed; the positions of the four JSON-only
  gap units are now counted one way (75 to 231; 0.6.0a1 said 75–230).
- `docs/DEVELOPMENT_HISTORY.md` moved to `docs/history/`.
- Community files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue and pull-request templates,
  `CITATION.cff`, Dependabot for the pinned GitHub Actions and the release build tools.
- `.github/workflows/release.yml`: builds the sdist and wheel with hash-pinned tools and publishes to PyPI with
  Trusted Publishing when a GitHub release is published. The sdist includes what the tests need.
- `scripts/render_social_preview.py` for `docs/assets/social-preview.png`.

Changed:

- The tagline, the package description and the docs no longer say that MintMap finds "every" path: they say it
  looks for the paths that create a session or credential, as the published miss rates require.
- Arithmetic on number literals in a settings value (`PASSWORD_RESET_TIMEOUT = 60 * 60`, `-3600`) is folded to its
  value before the settings group is fingerprinted. Rewriting it as its value (`3600`), or as another expression with
  the same value, no longer reports `fingerprint_changed`; a different number still does. Only literal arithmetic is
  folded: names, calls, attributes and strings are not evaluated.
- Upgrade note: a settings group that contains such an expression, or a negative number literal, reports
  `fingerprint_changed` once after upgrading, because its fingerprint text changes. Run `mintmap update` and accept
  the entry again.

## 0.6.0a1 (experimental)

First public release.

- `scan`, `init`, `update`, `diff` and `accept` commands, a composite GitHub Action, and a review queue grouped by
  credential kind and entry point.
- Lower-confidence **candidate** sites and **watched** sites (precision-rule set-asides), both fingerprinted and
  diffed.
- Evaluated frozen on three Django projects it had never seen (CVAT, Label Studio, Tandoor), with the previous
  internal version as a control: 8 of 66 credential paths missed with no warning, 25 of 58 reported paths were
  false alarms, and 42 of 65 harmful test changes were caught. See [docs/EVALUATION.md](docs/EVALUATION.md).

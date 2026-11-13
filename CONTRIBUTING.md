# Contributing to MintMap

Thank you for looking. MintMap is experimental and has one maintainer, so small, focused contributions are the
easiest to review. By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

| I want to... | Go to |
|---|---|
| report a path MintMap missed, or a false alarm | [Report a silent miss](#report-a-silent-miss-or-a-false-alarm) |
| add a library to the catalog | [Add a catalog entry](#add-a-catalog-entry) |
| fix something | [Development setup](#development-setup), then [Pull requests](#pull-requests) |
| report a vulnerability in MintMap itself | [SECURITY.md](SECURITY.md), not a public issue |

Open work is listed in [docs/ROADMAP.md](docs/ROADMAP.md).

## Development setup

MintMap has no dependencies. You need Python 3.11, 3.12 or 3.13 and git.

```bash
git clone https://github.com/mohamedmoatazsec/mintmap
cd mintmap
python -I scripts/run_mintmap.py scan examples/demo     # run from the checkout, nothing installed
```

To get the `mintmap` command while you work:

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e .
mintmap --version
```

Layout:

| Path | What |
|---|---|
| `src/mintmap/cli.py`, `ci_summary.py` | Command line and the job summary of the action |
| `src/mintmap/core/` | The analysis: project model, URLconf, call graph, checks, fingerprints, lock |
| `src/mintmap/data/django_catalog.json` | What MintMap knows about Django and auth libraries |
| `tests/` | `unittest` tests; `tests/fixtures/` holds synthetic Django projects |
| `examples/demo/` | The demo project of the README |
| `action.yml`, `scripts/run_mintmap.py` | The GitHub Action |

## Tests

```bash
python -I -m unittest discover -s tests -t tests
bash scripts/demo.sh
```

CI runs both on Python 3.11, 3.12 and 3.13. `-I` keeps the current directory off `sys.path`, as the action does.

If you change `examples/demo` or the output format of `scan` or `diff`, refresh the demo lock and the README
image (see [examples/demo/README.md](examples/demo/README.md)). CI fails if `docs/assets/demo.svg` no longer
matches the real output.

Rules for test code and examples:

- **Write fixtures yourself.** Many Django projects are GPL or AGPL licensed. Do not copy code from them into
  tests, examples or issues. A few lines that show the shape of the problem are enough.
- Standard library only, in the package and in the tests.

## Report a silent miss or a false alarm

A *silent miss* is a way to get a session or credential that `mintmap scan` neither reports nor lists as a gap.
These reports are the most useful thing you can send.

1. Reduce it to the smallest Django code that still shows the problem: usually one view, its URL pattern and
   the relevant settings. Write it fresh; do not paste code from your project or from a GPL project.
2. Put the files in an empty directory with a `manage.py` that names the settings module, and run:

   ```bash
   mintmap --version
   mintmap scan <dir> --json report.json
   ```

3. Open an issue with the "Missed path or false alarm" template. Include the snippet, what you expected, and the
   relevant lines of the output. Say whether the path appears as a candidate, as a watched site or in the gap
   list of `report.json` (then it is not silent, but still worth reporting).

For a false alarm, the same applies: the smallest code that produces the wrong path or finding, and why it is
not a credential path (or why the change is harmless).

## Add a catalog entry

`src/mintmap/data/django_catalog.json` lists, per library, the functions that mint a credential (`mint_apis`), the
functions that check one (`check_apis`), library views and routes, the settings that name hooks, and more. Every
entry cites where the fact was read.

1. **Read the library source without installing it.** Download the wheel for one exact release and unpack it:

   ```bash
   python -m pip download --no-deps --only-binary :all: -d wheels "django-example-auth==1.2.3"
   python -m zipfile -e wheels/django_example_auth-1.2.3-py3-none-any.whl src-read/
   ```

   Do not `pip install` it and do not import it. MintMap's own rule is that nothing is executed.
2. **Find the facts.** Which functions create a session, token or other credential? Which functions verify one,
   and what do they return or raise when the check fails? Which views and URL includes does the library ship?
   Which settings name project code that the library calls?
3. **Add entries next to similar ones**, copying their field names. Look at an existing entry of the same kind
   first, for example the `rest_framework.authtoken` entries in `mint_apis` and `check_apis`.
4. **Cite the source in every entry** in its `source_location`: the file inside the distribution, and a line
   number where the fact is line-specific (for example `djangorestframework/rest_framework/authtoken/views.py:26`).
   Add the package, version and wheel hash to `package_versions`, and the version to `verified_package_versions`.
5. **Add a test** with a small synthetic project that uses the library the way a real project would
   (`tests/test_v6.py` shows the pattern: the test writes the project into a temporary directory).
6. Say in the pull request which release you read, and anything you were unsure about. An honest "not verified"
   is better than a guess: unverified notes do not go into the catalog.

Catalog and analysis changes alter what MintMap reports, so they are released together with a new evaluation run
(see [docs/ROADMAP.md](docs/ROADMAP.md)). Your pull request may therefore wait on a development branch for a
while. That is not a sign that it is unwelcome.

## Pull requests

- One topic per pull request, with small commits that each do one thing.
- Tests pass on 3.11, 3.12 and 3.13, and `bash scripts/demo.sh` prints `demo ok`.
- No new runtime dependencies.
- **Honesty rules for docs.** The accuracy numbers in `README.md` and `docs/EVALUATION.md` come from a held-out
  evaluation. Do not change them, and do not add claims nobody measured (accuracy, comparisons with other tools,
  user counts). Tool output shown in docs or images must be real output; never write or edit it by hand.
- **The action stays hardened.** `action.yml` runs MintMap from its own checkout with `python -I`, pins actions
  to full commit SHAs, and never installs or runs code from the pull request. See
  [docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).
- Add a line to `CHANGELOG.md` under "Unreleased".

## Releasing

For the maintainer.

1. Set the version in `pyproject.toml` and `TOOL_VERSION` in `src/mintmap/core/analysis.py` (a test checks that
   they match). Move the "Unreleased" notes in `CHANGELOG.md` under the new version.
2. Tag `v<version>` and publish a GitHub release for the tag.
3. `.github/workflows/release.yml` then checks that the tag matches the version, runs the tests and the demo,
   builds the sdist and wheel and uploads them to PyPI with Trusted Publishing. No API token is involved.

The PyPI project trusts this publisher: owner `mohamedmoatazsec`, repository `mintmap`, workflow `release.yml`,
environment `pypi`.

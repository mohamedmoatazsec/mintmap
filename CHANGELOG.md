# Changelog

## Unreleased

No change to the analysis, the catalog, fingerprints or the lock format: a lock written by 0.6.0a1 stays valid, and
the published accuracy numbers still describe this code.

- `mintmap --version`.
- A demo project in `examples/demo` (password login, TOTP step, password-reset auto-login, API token endpoint) with
  a reviewed lock and a bad pull request, `scripts/demo.sh` to run it, and a CI job that asserts the failing exit
  code and that the README image matches the real output.
- README rewritten around the demo, with a diagram, an FAQ and measured scan times. The long explanation of
  candidates and watched sites moved to the new `docs/CONCEPTS.md`.
- `docs/ROADMAP.md`: the known blind spots as open work, linked to issues.
- `docs/EVALUATION.md` restructured for reading. No number changed.
- `docs/DEVELOPMENT_HISTORY.md` moved to `docs/history/`.
- Community files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue and pull-request templates,
  `CITATION.cff`, Dependabot for the pinned GitHub Actions.
- `.github/workflows/release.yml`: builds the sdist and wheel and publishes to PyPI with Trusted Publishing when a
  GitHub release is published.

## 0.6.0a1 (experimental)

First public release.

- `scan`, `init`, `update`, `diff` and `accept` commands, a composite GitHub Action, and a review queue grouped by
  credential kind and entry point.
- Lower-confidence **candidate** sites and **watched** sites (precision-rule set-asides), both fingerprinted and
  diffed.
- Evaluated frozen on three Django projects it had never seen (CVAT, Label Studio, Tandoor), with the previous
  internal version as a control: 8 of 66 credential paths missed with no warning, 25 of 58 reported paths were
  false alarms, and 42 of 65 harmful test changes were caught. See [docs/EVALUATION.md](docs/EVALUATION.md).

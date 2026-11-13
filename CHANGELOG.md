# Changelog

## 0.6.0a1 (experimental)

First public release.

- `scan`, `init`, `update`, `diff` and `accept` commands, a composite GitHub Action, and a review queue grouped by
  credential kind and entry point.
- Lower-confidence **candidate** sites and **watched** sites (precision-rule set-asides), both fingerprinted and
  diffed.
- Evaluated frozen on three Django projects it had never seen (CVAT, Label Studio, Tandoor), with the previous
  internal version as a control: 8 of 66 credential paths missed with no warning, 25 of 58 reported paths were
  false alarms, and 42 of 65 harmful test changes were caught. See [docs/EVALUATION.md](docs/EVALUATION.md).

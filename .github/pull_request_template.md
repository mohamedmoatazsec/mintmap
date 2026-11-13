## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `python -I -m unittest discover -s tests -t tests` passes
- [ ] `bash scripts/demo.sh` prints `demo ok`
- [ ] No new runtime dependency
- [ ] `CHANGELOG.md` has a line under "Unreleased"

If this touches the analysis (`src/mintmap/core/`) or the catalog:

- [ ] There is a test with a synthetic project written for it (no code copied from other projects)
- [ ] Catalog entries cite the library source file, and a line number where the fact is line-specific
- [ ] I did not change the accuracy numbers in `README.md` or `docs/EVALUATION.md`

If this touches docs or images:

- [ ] Every tool output shown is real output, not written or edited by hand
- [ ] No claim that was not measured

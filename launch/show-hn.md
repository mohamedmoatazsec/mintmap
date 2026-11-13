# Show HN

**Title** (80 characters maximum):

```
Show HN: MintMap – every login path in a Django app, reviewed and checked in CI
```

**URL:** https://github.com/mohamedmoatazsec/mintmap

**First comment** (post it yourself right after submitting):

```
Author here. MintMap is a static-analysis tool for Django. It finds the code paths that create a login session
or a credential (login views, password-reset auto-login, API tokens, 2FA steps, SSO callbacks), writes them to a
lock file that a person reviews once, and then fails CI when a pull request adds a path, removes one, or changes
the code or the checks on one. It parses the code with Python's ast module and never imports or runs it. It has
no dependencies.

It is experimental, and I measured how wrong it is. I froze the tool and ran it on three Django projects I had
not looked at while building it (CVAT, Label Studio, Tandoor):

- 8 of 66 credential paths were missed with no warning (12%). On an earlier set of unseen projects the previous
  version missed 30%.
- 25 of 58 reported paths were false alarms (43%).
- 42 of 65 deliberately harmful changes were caught by the CI diff (65%). 23 passed.
- 7 of 22 harmless refactors raised a finding.

The reference inventories were written by AI agents that never saw the tool's output, not by people, and they
contain errors. That is a real limit of the evaluation and it is stated in the write-up.

The gains I made on the projects I developed against mostly did not transfer: silent misses went from 51 to 4 of
213 there, and from 11 to 8 of 66 on unseen code.

To try it: clone the repo and run `bash scripts/demo.sh`. It scans a small demo project, applies a patch that
makes a TOTP check ignore its result, and shows the diff failing.

Methodology and per-project numbers: docs/EVALUATION.md in the repo. I would like to hear where it breaks on
your code.
```

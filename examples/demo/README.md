# Teahouse: the MintMap demo project

A tiny Django project written for this repository, with four ways to get signed in:

| Route | View | What it creates | Check on the way |
|---|---|---|---|
| `members/sign-in/` | `members.views.sign_in` | a session (or the pending-member marker for two-step sign-in) | password |
| `members/sign-in/code/` | `members.views.sign_in_code` | a session | TOTP code (`CodeForm`) |
| `members/reset/<uidb64>/<token>/` | `members.views.finish_reset` | a new password, then a session | password-reset token |
| `members/api/token/` | `members.views.ApiTokenView` | a DRF API token | password |

**Two of these ways in deliberately skip the TOTP step.** A member who switched on two-step sign-in still gets a
session from the password-reset link (`finish_reset` checks only the reset token) and an API token from
`ApiTokenView` (it checks only the password). Real projects often have exactly this shape, and it is the kind of
thing a reviewer should spot. MintMap does not judge whether a path is safe, but the scan shows it: `otp` appears
only in the factors of `sign_in_code`, while the reset path has `factors={'reset_token_possession': ...}` and the
API token path `factors={'password': ...}`.

MintMap only parses this code, so neither Django nor the other imports need to be installed. The project has no
templates or migrations and is not meant to be run.

- `mintmap.lock` is the reviewed baseline: every entry was accepted with `mintmap accept --all`.
- `bad-pr.patch` is the "pull request": it makes `sign_in_code` call `form.is_valid()` without using the result,
  so any code passes the TOTP step.

Run the whole demo from the repository root:

```bash
bash scripts/demo.sh
```

On Python 3.11, 3.12 or 3.14, `mintmap diff` also prints an `INFO` line, because the demo lock was written with
Python 3.13. It is informational: the demo's fingerprints and exit codes are the same on all four versions (CI runs
the demo on each).

After changing anything in this directory, refresh the baseline and the README image, all with Python 3.13 (the
lock records the Python version, and any other version adds that `INFO` line to the image):

```bash
python3.13 -I scripts/run_mintmap.py update examples/demo
python3.13 -I scripts/run_mintmap.py accept examples/demo --all --reviewer demo-reviewer --note "Baseline of the demo project"
python3.13 scripts/render_demo.py
```

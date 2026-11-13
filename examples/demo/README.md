# Teahouse: the MintMap demo project

A tiny Django project written for this repository, with four ways to get signed in:

| Route | View | What it creates | Check on the way |
|---|---|---|---|
| `members/sign-in/` | `members.views.sign_in` | a session (or the pending-member marker for two-step sign-in) | password |
| `members/sign-in/code/` | `members.views.sign_in_code` | a session | TOTP code (`CodeForm`) |
| `members/reset/<uidb64>/<token>/` | `members.views.finish_reset` | a new password, then a session | password-reset token |
| `members/api/token/` | `members.views.ApiTokenView` | a DRF API token | password |

MintMap only parses this code, so neither Django nor the other imports need to be installed. The project has no
templates or migrations and is not meant to be run.

- `mintmap.lock` is the reviewed baseline: every entry was accepted with `mintmap accept --all`.
- `bad-pr.patch` is the "pull request": it makes `sign_in_code` call `form.is_valid()` without using the result,
  so any six characters pass the TOTP step.

Run the whole demo from the repository root:

```bash
bash scripts/demo.sh
```

After changing anything in this directory, refresh the baseline and the README image:

```bash
python -I scripts/run_mintmap.py update examples/demo
python -I scripts/run_mintmap.py accept examples/demo --all --reviewer demo-reviewer --note "Baseline of the demo project"
python scripts/render_demo.py        # with Python 3.13
```

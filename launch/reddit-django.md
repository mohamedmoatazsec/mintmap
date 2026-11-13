# r/django

Read the sidebar rules first (self-promotion, flair).

**Title:**

```
I built a tool that maps the ways to get logged in to a Django app and fails CI when that map changes (experimental, with measured miss rates)
```

**Body:**

```
In a Django project the "ways in" are scattered: the login view, auto-login after sign-up or password reset,
SSO callbacks, magic links, 2FA steps, DRF tokens, admin impersonation. A pull request can add one or weaken one
and the reviewer may not notice it touched authentication.

MintMap is my attempt at a guard for that:

- `mintmap scan` looks for the calls that create a session or credential (django.contrib.auth.login, DRF and JWT
  tokens, allauth flows and so on), traces the ones it finds to URL routes and middleware, and records the checks
  it can see on the way.
- You review the result once and commit it as `mintmap.lock`.
- `mintmap diff` (there is a GitHub Action) fails the pull request when a path is added or removed, or when the
  code or a check on a reviewed path changes.

It only parses your code with `ast`. It does not import Django or your project, needs no database, and has no
dependencies.

It is experimental and it misses things. Frozen and run on three projects it had never seen (CVAT, Label Studio,
Tandoor):

- 28 of 66 credential paths found and linked to the right route
- 8 of 66 missed with no warning (12%); on an earlier set of unseen projects the previous version missed 30%
- 25 of 58 reported paths were false alarms (43%)
- 42 of 65 harmful test changes caught by diff; 23 passed
- 7 of 22 harmless changes raised a finding (all 7 were refactors)

The reference inventories for those numbers were written by AI agents, not by people, and the adversarial
verifier that re-checked the scoring was an AI agent too. The details and the limits are in docs/EVALUATION.md.

There is a demo project in the repo: `bash scripts/demo.sh` (Python 3.11 or newer) shows a bad pull request (a
TOTP check whose result is ignored) failing the diff. To try it on your project: `pip install mintmap`.

Repo: https://github.com/mohamedmoatazsec/mintmap

What I would like to know: which auth libraries do you use that it should understand? The catalog covers Django
auth, DRF, SimpleJWT, allauth, django-otp and a few more. And if it misses a login path in your project, a
minimal snippet in an issue would help a lot.
```

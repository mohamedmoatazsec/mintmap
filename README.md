# MintMap

**A reviewed map of every code path that creates a login session or credential in a Django app, enforced in CI.**

> **Status: experimental (0.6.0a1).** MintMap was built on eight open-source Django projects and then frozen and
> tested on three it had never seen (CVAT, Label Studio, Tandoor). There it missed 12% of credential paths with no
> warning (an earlier set of unseen projects: 30%). 43% of the paths it reported were false alarms, and `diff` let
> 23 of 65 harmful test changes through. It is a review aid, not a guarantee. Read [Accuracy](#accuracy) first.

## The problem

In a real Django app, "ways to get logged in" are scattered: the login view, auto-login after sign-up or password
reset, SSO callbacks, magic links, two-factor steps, API tokens, admin impersonation, remote-user middleware.
Any pull request can add one or weaken one, and most reviewers will not notice that a change touched
authentication. A classic bug: the two-factor check still runs, but its result is ignored.

Security teams rarely have an up-to-date list of these paths, and code scanners look for known bug patterns rather
than telling you *that the set of ways in has changed*.

## What MintMap does

1. **Finds mint sites**: calls that create a session or credential (`django.contrib.auth.login`, DRF and JWT
   tokens, django-allauth flows, OAuth2 provider tokens, project-made tokens built from `secrets`/`uuid4`, ...).
2. **Traces them to entry points**: URL routes (including `include()`, routers, helper functions, i18n
   patterns), middleware, admin registrations and library views.
   *Since 0.6.0a1* it also lists lower-confidence **candidates**:
   hand-written session state (logins, MFA / step-up / impersonation state, session hand-offs, any session write
   right after a password or PIN re-check), passwords set from a value the code does not generate, calls into an
   authentication library the catalog does not describe (also packages the catalog does not cover at all, when the
   function's name says it logs in or issues a token and it receives the request or a user), unregistered
   subclasses of minting middleware or views, project code that authenticates requests itself (DRF authentication
   classes, another framework's `authenticate(self, request, ...)`, every `request.user = ...` /
   `scope["user"] = ...` that is not an anonymous user, ranked high when no credential check is visible), and mint
   sites that only start-up, deploy or command-line code reaches (`AppConfig.ready()`, settings, management
   commands, data migrations).  Candidates are traced, fingerprinted and diffed like paths, but reviewed as one
   lock entry per kind (`candidates:<kind>`) whose sites are ranked and carry the reason they were reported.
   *Also new:* sites that a precision rule **set aside** as not being credentials (random values kept under a
   name without a credential word, signed values no reader uses to log anyone in, session ids that load a
   non-principal object, generators nothing references) are **watched**: one low-ranked lock entry per rule
   (`watched:<kind>`), fingerprinted by the site's own code and the entry points reaching it, so a wrong
   judgement on unfamiliar code still shows up in `diff`.  Values set aside because their name says they are an
   identifier, a file, a cache key and so on are only listed in the JSON report.
3. **Records the checks it can see on the way**: password, TOTP, WebAuthn, token signature, permission gates, and
   a best-effort judgement of whether each check's result decides the outcome. This evidence is often weaker than
   the truth and sometimes wrong (see [Accuracy](#accuracy)).
4. **Writes `mintmap.lock`**, which a security reviewer approves once.
5. **Fails CI** when a pull request adds or removes a path, changes the code or checks on a reviewed path,
   weakens a check, or reduces what MintMap can analyse. Many constructs it cannot analyse are listed as
   **gaps**, but not all: on projects it was not developed against, 12% to 30% of credential paths were missed
   with no gap at all, depending on the project set (see [Accuracy](#accuracy)).

Real output, after a one-line change that makes the Healthchecks TOTP form accept every code:

```
$ mintmap diff .
FINGERPRINT_CHANGED    e06b237f9895851e  evidence inputs changed (checks); previous review (accepted) no longer applies
EVIDENCE_DOWNGRADED    e06b237f9895851e  factor otp: guards_mint -> present_unproven; status: check_guards_mint -> check_present_relationship_unproven
exit 12 (fingerprint_changed, evidence_downgraded)
```

MintMap reads source code with Python's `ast` module. It **never imports or runs** the project or its libraries,
needs no database or settings, and has no dependencies beyond the Python standard library (3.11+). It must run on
a Python that can parse the project's code: a project that uses Python 3.12 syntax (for example the same quotes
nested inside an f-string) needs MintMap on 3.12 or newer, otherwise those files are reported as parse failures.
Lock fingerprints are the same on Python 3.11, 3.12 and 3.13 (tested on eight projects), so a lock written with one
of these versions can be checked with another; with any other version, write the lock with the Python minor
version CI uses.

## Quick start

```bash
pip install "git+https://github.com/mohamedmoatazsec/mintmap@v0.6.0a1"   # PyPI release pending

mintmap scan  path/to/django/project                    # the review queue, path evidence and the gaps
mintmap init  path/to/django/project                    # write mintmap.lock (all entries unreviewed)
# review the entries, then record the decision (one group at a time, or --all):
mintmap accept path/to/django/project --group kind:session --reviewer "alice" --note "initial review"
git add path/to/django/project/mintmap.lock && git commit -m "Add reviewed MintMap lock"
```

The text report of `scan` starts with a **review queue** (since 0.6.0a1): confirmed paths grouped by credential kind
(`kind:session`, `kind:token`, `kind:precursor`, `kind:custom`, `kind:other`) and entry point, candidate sites by
kind, the settings groups and the watched groups; inside a group the entries are ranked by a transparent risk
score (credential kind, check evidence, reachability, confidence; an unrouted path is scored like a reachable one,
because on unfamiliar code a route MintMap did not see is the common case), each with a `why` line. The ranking is
a hint, not a verdict: in the evaluation, false alarms were sometimes ranked high and an administrator setting any
user's password was ranked low.
`mintmap accept --group <group>` accepts one such group. Lock entries carry the same information in an informational `review` block that `diff` ignores (locks
written by 0.5.0a1 stay valid; `mintmap update` adds it).

After an intended change: `mintmap update <dir>` refreshes the lock (changed entries become unreviewed again),
then `mintmap accept <dir> <ids...> --reviewer <name>`.

Optional: `--library-path <dir>` lets MintMap read library source (still without importing it), which can resolve
library view aliases in some layouts. In our evaluation it changed no result.

## GitHub Action

```yaml
# .github/workflows/mintmap.yml
on: pull_request
permissions:
  contents: read
jobs:
  mintmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false
      - uses: mohamedmoatazsec/mintmap@<full-commit-sha>   # pin to the full commit SHA of a release tag
        with:
          project-dir: .
```

The job fails on any finding (configurable with `fail-on`; exit 128, "MintMap could not run", always fails) and
writes a summary table to the job page. The action runs MintMap from its own checkout with `python -I`, so files
added by a pull request cannot replace it; no package is built or installed. See [`examples/mintmap.yml`](examples/mintmap.yml).

**The check is only as strong as the review rules around `mintmap.lock`.** Without code-owner review, a pull
request can accept its own change. Do not run code from the pull request (installing its dependencies, running
its tests) in the same job before MintMap: anything that runs in the job can replace the check. Follow
[docs/ENFORCEMENT.md](docs/ENFORCEMENT.md).

## `mintmap diff` exit codes (bitmask)

| bit | name | meaning |
|---|---|---|
| 1 | `new_path` | a new way to obtain a session/credential |
| 2 | `removed_path` | a reviewed path disappeared |
| 4 | `fingerprint_changed` | code, checks, hooks or settings on a reviewed path changed |
| 8 | `evidence_downgraded` | a check on a path got weaker |
| 16 | `purpose_changed` | the credential issued on a path changed kind |
| 32 | `coverage_regression` | MintMap can analyse less than before (new gaps, parse failures, changed roots) |
| 64 | `unreviewed` | lock entries not yet accepted |
| 128 | `error` | MintMap could not run (bad arguments, missing or invalid lock, catalog error, or an internal error) |

A candidate group (`candidates:<kind>`) uses the same bits for its sites (a new site sets 1, a vanished one 2, a
changed one 4, naming new or lost entry points); its findings carry `"tier": "candidate"`. A watched group
(`watched:<kind>`) does the same with `"tier": "watched"`. A mint site shared by many entry points (one lock entry
listing them) sets bit 1 when a new entry point reaches it, and the finding names that entry point.

Formatting, comments, docstrings and renamed local variables are normalised and do not change fingerprints. Simple
extractions of a helper function in the same module are normalised too, but extracting a method, extracting a
helper that takes expressions as arguments, or moving code to another module still changes the fingerprint (a
false alarm). Since 0.6.0a1, extracting a method of the same class that no subclass overrides, and helpers called
with attribute arguments such as `request.META`, are normalised as well, unless a call in the helper could rebind
the attribute (for example the helper calls `load_account(self, ...)` and the argument is `self.account`); so are
moving the mint call itself into such a helper, and extracting a method in a class that a hook setting names.
Moving code to another module or class still is not. Even so, 7 of 22 harmless changes raised a finding in the
latest evaluation: four extracted helper functions or methods (one named `_check_*`, which reads as a new
unrecognised check), a value first held in a new local variable, a hook's local import moved to module level, and a
settings expression rewritten without changing its value.

## Accuracy

MintMap 0.6.0a1 (frozen before the test) was measured on three open-source Django projects that nobody looked at
while it was built: CVAT, Label Studio and Tandoor. The previous release, 0.5.0a1, was run on the same projects as a
control. The reference inventories were written by separate AI agents (not humans) that never saw the tool's
output, and every result was re-checked by an adversarial AI verifier that re-ran both versions:

| | 0.6.0a1 | 0.5.0a1 (control) |
|---|---|---|
| credential paths found and linked to the right route | 28 of 66 (42%) | 26 of 66 (39%) |
| found, but only as an unlinked mint, a candidate or a named gap (1) | 30 of 66 (45%) | 29 of 66 (44%) |
| **missed with no warning** (2) | **8 of 66 (12%)** | **11 of 66 (17%)** |
| reported paths that are not real credential paths | 25 of 58 (43%) | 30 of 61 (49%) |
| lock entries to review on day one / of which false alarms | 88 / 33 | 82 / 33 |
| check evidence on matched paths: agrees / weaker than the truth / wrong (3) | 2 / 38 / 2 of 42 | – |
| harmful code changes caught by `diff` (required categories) | 13 of 18 | 13 of 18 |
| harmful code changes caught (all, incl. project-specific and verifier probes) | 42 of 65 (65%) | 36 of 65 (55%) |
| harmless changes that raised a finding | 7 of 22 | 8 of 22 |

(1) 4 of the 11 "named gap" units are visible only in `--json` output (the text report lists the first 40 gaps).
Label Studio's personal access tokens, its main API credential, are among them and do not appear in the review
queue. (2) By class: full login sessions 0 of 28, tokens 4 of 26, precursors (reset, invitation, MFA state) 4 of
12. Scoring judgement calls move the 0.6.0a1 count between 4 and 12. (3) "Weaker" means the tool claimed less than
was true, typically "no check found" on a login whose password check runs in a serializer or form named by a
library setting. "Wrong" means it claimed something false.

**In short:** 0.6.0a1 is somewhat better than 0.5.0a1 on code neither had seen: 3 fewer silent misses, 6 more
harmful changes caught, fewer false-alarm paths. But most of the large gains it made on its development projects
(silent misses 51 → 4 of 213, harmful changes caught 98 of 98) did not transfer. The project set matters too: on an
earlier set of unseen projects (InvenTree, Weblate, pretix) 0.5.0a1 missed 30% silently, against 17% here. Expect
to miss some tokens and precursors in an unfamiliar codebase, to dismiss many false alarms on day one, and to see
about a third of harmful changes to auth code pass `diff`, mostly where the changed check is reached through
settings-named serializers, library-called hooks or admin code.

Full methodology, per-project numbers and the earlier rounds: [docs/EVALUATION.md](docs/EVALUATION.md).

## Known blind spots

General causes of the misses found in the latest evaluation (0.6.0a1 on CVAT, Label Studio and Tandoor):

- A library's mint function called through the library's settings object (dj-rest-auth
  `api_settings.TOKEN_CREATOR(...)`): neither a path nor a gap.
- Credentials created or edited through the Django admin for project models (`ModelAdmin` saves, admin actions, a
  token field in an admin form). Admin registrations are linked only when the model's `save()` is a known mint.
- A settings module that star-imports its base module through a source-root alias: the base module's
  `INSTALLED_APPS`, `MIDDLEWARE`, `AUTHENTICATION_BACKENDS` and `REST_FRAMEWORK` are not read (one generic gap).
- Hooks named in settings and loaded by a project helper (`load_func(settings.X)`), and adapter classes re-exported
  from a package `__init__`: such code is in no fingerprint, so weakening it can pass `diff`.
- DRF routers extended at run time (one global gap), tokens created by `ModelSerializer.create()` through `super()`,
  and credentials written from request data by an update serializer.
- Values whose field name has no credential word (`InviteLink.uuid`) and session writes without a principal-like
  signal are set aside in the JSON report only, not watched.
- Libraries outside the catalog (for example django-auth-ldap) and project code that only such a library calls.
- Not modelled: session lifetime and token revocation checks, project view decorators, admin actions as entry
  points, signed cookies (`set_signed_cookie`) as credentials, multi-request flows. There is no option to choose the
  settings module: MintMap follows `DJANGO_SETTINGS_MODULE` in `manage.py`.
- Django only. Library knowledge covers Django auth, DRF, SimpleJWT, knox, djoser, dj-rest-auth, django-allauth,
  social-auth, django-otp, two-factor-auth, sesame, oauth-toolkit and a few more (about 15 packages). Other
  libraries usually show up as gaps, but not always.

0.6.0a1 added general mechanisms for the blind spots of 0.5.0a1:
- hand-written sessions with run-time keys
- credentials created through related managers and `CreateView`
- library flows called directly
- settings computed by function calls
- library URL builders
- admin-chosen passwords and step-up state (as candidates)

The evaluation above is the measure of how far that went.

## How is this different from Semgrep or CodeQL?

Semgrep and CodeQL find code that matches a query. You *can* write a CodeQL query that traces `login()` calls back
to request handlers (we did, while evaluating MintMap), but you then still need: knowledge of what Django auth
libraries mint and check (MintMap's catalog covers about 15), a reviewed baseline, fingerprints that ignore harmless refactors,
a diff that fails CI only when the reviewed set changes, and an explicit list of what the analysis could not see.
MintMap is that package for one framework. It is a combination of established techniques (call-graph tracing,
library models, baselines), not a new kind of analysis.

## Contributing

The library catalog (`src/mintmap/data/django_catalog.json`) is the most valuable place to help: entries cite the
library source file they were read from, with a line number where the fact is line-specific. Bug reports with a minimal Django snippet that MintMap
misses silently are especially welcome. Tests: `python -I -m unittest discover -s tests -t tests`.

The internal development log of the prototype (design notes, rounds 1 and 2 in detail including their failures;
rounds 3 and 4 are summarised in [docs/EVALUATION.md](docs/EVALUATION.md)) is in
[docs/DEVELOPMENT_HISTORY.md](docs/DEVELOPMENT_HISTORY.md). Its commands and paths refer to the prototype, not to
this package.

## License

Apache License 2.0. See [LICENSE](LICENSE).

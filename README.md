# MintMap

**A reviewed map of every code path that creates a login session or credential in a Django app, enforced in CI.**

> **Status: experimental (0.5.0a1 was evaluated; this tree is 0.6.0.dev0, not yet evaluated).** MintMap has been
> evaluated on eight open-source Django projects. On projects it was not developed against, it missed about 30% of
> credential paths without warning, and about half of what it reported were false alarms. It is a review aid, not a guarantee. Read [Accuracy](#accuracy) first.

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
   *Since 0.6.0.dev0 (not yet evaluated on fresh projects):* it also lists lower-confidence **candidates**:
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
   **gaps**, but not all: on projects it was not developed against, about 30% of credential paths were missed
   with no gap at all (see [Accuracy](#accuracy)).

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
pip install "git+https://github.com/OWNER/mintmap"      # replace OWNER; PyPI release pending

mintmap scan  path/to/django/project                    # the review queue, path evidence and the gaps
mintmap init  path/to/django/project                    # write mintmap.lock (all entries unreviewed)
# review the entries, then record the decision (one group at a time, or --all):
mintmap accept path/to/django/project --group kind:session --reviewer "alice" --note "initial review"
git add path/to/django/project/mintmap.lock && git commit -m "Add reviewed MintMap lock"
```

The text report of `scan` starts with a **review queue** (0.6.0.dev0): confirmed paths grouped by credential kind
(`kind:session`, `kind:token`, `kind:precursor`, `kind:custom`, `kind:other`) and entry point, candidate sites by
kind, the settings groups and the watched groups; inside a group the entries are ranked by a transparent risk
score (credential kind, check evidence, reachability, confidence; an unrouted path is scored like a reachable one,
because on unfamiliar code a route MintMap did not see is the common case), each with a `why` line.
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
      - uses: OWNER/mintmap@<full-commit-sha>   # replace OWNER; pin to a full commit SHA of a release
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
false alarm): in the evaluation, 3 of 8 extract-function refactors raised a finding. (0.6.0.dev0, not yet
evaluated: extracting a method of the same class that no subclass overrides, and helpers called with attribute
arguments such as `request.META`, are normalised as well, unless a call in the helper could rebind the attribute
(for example the helper calls `load_account(self, ...)` and the argument is `self.account`); so are moving the
mint call itself into such a helper, and extracting a method in a class that a hook setting names; moving code to
another module or class still is not.)

## Accuracy

Measured on three open-source Django projects (InvenTree, Weblate, pretix) that nobody looked at while the tool
was built. The reference inventories were written by separate AI agents (not humans) that never saw the tool's
output, and every result was re-checked by an adversarial AI verifier that re-ran the tool:

| | result |
|---|---|
| credential paths found and linked to the right route | 56 of 149 (38%) |
| found, but only as an unlinked mint or a named gap (1) | 48 of 149 (32%) |
| **missed with no warning** | **45 of 149 (30%)** |
| reported paths that are not real credential paths | 127 of 230 (55%) |
| check evidence on matched paths: agrees / weaker than the truth / wrong (2) | 5 / 43 / 12 of 60 |
| harmful code changes caught by `diff` (required categories) | 14 of 18 |
| harmful code changes caught (all mutations incl. project-specific and verifier probes) | 40 of 58 |
| harmless changes that raised a finding | 4 of 20 (refactors only: 3 of 16) |

(1) 24 of the 31 units counted as "named gap" (InvenTree's allauth headless API) are visible only through global
`unsupported_url_construct` gaps that are not attached to any path and appear only in `--json` output (the text
report lists the first 40 gaps). (2) "Weaker" means the tool claimed less than was true (for example
"relationship unproven" or "library flow checks not analysed"); "wrong" means it claimed something false, for
example that a check guards a mint when it does not.

**In short:** `diff` catches most changes to the code it fingerprints and ignores most harmless refactors. But
checks reached through runtime-built backends, forms or settings helpers can sit outside every fingerprint: 18 of
58 harmful changes passed with exit 0, 8 of them on paths MintMap had already reported (including disabling
Weblate's main TOTP check and pretix's central password check). The inventory is not complete either: in an
unfamiliar codebase, expect around a third of credential paths (especially custom session handling and custom
token models) to be missing without a gap, and expect to dismiss many false alarms on day one.

Full methodology and per-project numbers: [docs/EVALUATION.md](docs/EVALUATION.md).

## Known blind spots

These are the blind spots of the evaluated release (0.5.0a1). 0.6.0.dev0 adds general mechanisms for the first
five and for admin-chosen passwords and step-up grants (as candidates or confirmed paths); they have not been
measured on projects the tool was not developed against yet.

- Sessions written by hand with keys built at runtime (`request.session[f"..."]`).
- Credentials created through related managers (`team.tokens.create(...)`) or Django `CreateView` saves.
- Project code that calls a library's login flow directly (for example `social_django.views.complete()`).
- Settings computed by function calls (`MIDDLEWARE = CONFIG.get(...)`): middleware logins become invisible.
- Library URL builder functions (allauth headless `build_urlpatterns()`): reported as gaps, not linked.
- Checks reached through runtime-built backends, forms or settings helpers: they may sit outside every
  fingerprint, so weakening them can pass `diff`.
- Session step-up grants, admin-chosen passwords, multi-request flows, and token *consumers* are not modelled
  (0.6.0.dev0: step-up state, admin-chosen passwords and project request authenticators are candidates).
- Django only. Library knowledge covers Django auth, DRF, SimpleJWT, knox, djoser, dj-rest-auth, django-allauth,
  social-auth, django-otp, two-factor-auth, sesame, oauth-toolkit and a few more (15 packages). Other libraries
  usually show up as gaps, but not always (see [Accuracy](#accuracy)).

Shapes found silent by a review of 0.6.0.dev0 on 31 synthetic projects, and how the current tree handles them
(not yet measured on fresh projects): custom model managers and querysets (`objects = KeyManager()`,
`QS.as_manager()`: now resolved), uncatalogued authentication libraries called directly (now candidates when the
function name says it logs in or issues a token), non-DRF request authenticators (Channels `scope["user"]`,
django-ninja `authenticate()`, `request.user = SimpleLazyObject(...)`: now candidates), class-based settings
(django-configurations: now read), project code that libraries call through settings, signals or permission
registries (`CAN_LOGIN_AS = "..."`, `@receiver(populate_user)`, `rules.add_perm(...)`: now hashed in a
`settings:AUTH_HOOKS(project code)` entry), and URL lists filled at run time by a decorator (now a gap; the
views stay unrouted).  Still not modelled: a signed cookie (`set_signed_cookie`) is not a credential of its own
(its reader is a candidate when it sets `request.user`), and checks reached through code MintMap cannot resolve can
still sit outside every fingerprint.

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
round 3 is summarised in [docs/EVALUATION.md](docs/EVALUATION.md)) is in
[docs/DEVELOPMENT_HISTORY.md](docs/DEVELOPMENT_HISTORY.md). Its commands and paths refer to the prototype, not to
this package.

## License

Apache License 2.0. See [LICENSE](LICENSE).

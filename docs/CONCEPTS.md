# Concepts

The words MintMap uses in its reports, its lock file and its findings. Every example on this page is real output
from the demo project in [`examples/demo`](../examples/demo); run `mintmap scan examples/demo` to see the rest.

**In the demo**, four routes sign someone in, and `mintmap scan` reports five paths and one candidate: the three
logins and the API token, the pending-member value that `sign_in` writes to the session before the TOTP step (a
hand-written session value, found by a heuristic), and, as a candidate, the `set_password` call in `finish_reset`
(a password set from a value the code does not generate).

| Word | In one line |
|---|---|
| [Mint site](#mint-sites) | A call that creates a session or credential |
| [Entry point](#entry-points) | Where a request (or other trigger) comes in: a route, middleware, an admin registration |
| [Path](#paths) | One entry point reaching one mint site, with the checks seen on the way |
| [Check evidence](#check-evidence) | What MintMap could see about the checks on a path |
| [Factor](#check-evidence) | What a check verifies: `password`, `otp`, `reset_token_possession`, ... |
| [Candidate](#candidates) | A lower-confidence site that has a structural reason to be reviewed |
| [Watched site](#watched-sites) | A site a rule decided is *not* a credential, kept under watch in case the rule is wrong |
| [Gap](#gaps) | Something MintMap could not analyse, listed explicitly |
| [Settings group](#settings-groups) | The authentication settings, reviewed as a few lock entries |
| [Review queue](#the-review-queue) | The grouped, ranked list a reviewer works through on day one |
| [Lock](#the-lock) | `mintmap.lock`: the reviewed baseline that `mintmap diff` compares against |
| [Fingerprint](#fingerprints) | A hash of the code, checks and settings behind an entry; a change invalidates the review |

MintMap reads source code with Python's `ast` module. It never imports or runs the project or its libraries.

## Mint sites

A mint site is a call that creates a session or a credential. MintMap knows them from three sources:

- **The library catalog** ([`src/mintmap/data/django_catalog.json`](../src/mintmap/data/django_catalog.json)):
  `django.contrib.auth.login`, DRF and JWT tokens, django-allauth flows, OAuth2 provider tokens and so on, for
  about 15 packages. Each entry cites the library source file it was read from.
- **Library flows**: views and middleware of those libraries that mint without any project code calling a mint
  function (for example a library's login view included in the URLconf).
- **Heuristics for project-made credentials**: tokens built from `secrets` or `uuid4`, and hand-written session
  logins whose session key is read back as a user.

Each mint site has a **purpose**, for example `full_session`, `api_token` or `password_reset_token`. Purposes are
grouped into five **credential kinds**:

| Kind | Meaning |
|---|---|
| `session` | A full login session: `login()`, library login flows, impersonation, an administrator choosing a password, hand-rolled session logins |
| `token` | A bearer or long-lived credential: API tokens, JWT, OAuth tokens and client secrets |
| `precursor` | Something that leads to a session or token later: reset, magic-link and invitation tokens, MFA challenge state, one-time codes |
| `custom` | A project-made credential found by a heuristic, kind unclear |
| `other` | Anything else |

## Entry points

MintMap traces each mint site it finds back to the places it can see that trigger it: URL routes (including
`include()`, DRF routers, helper functions and i18n patterns), middleware, admin registrations and library views.
An entry point has an id such as:

```
route:members/sign-in/code/|members.views.sign_in_code
```

A mint site that no route, middleware or authentication class reaches is reported as **unrouted**. It is scored
like a reachable one, because on unfamiliar code a route MintMap did not see is the common case.

## Paths

A path is one entry point reaching one mint site. It has a 16-character id, and the report shows it like this:

```
  [033339f757191ebb] route:members/sign-in/code/|members.views.sign_in_code
      mints django.contrib.auth.login purpose=full_session at members.views.sign_in_code:52
      evidence=check_guards_mint factors={'otp': 'guards_mint'} complete=True fingerprint_complete=True
        - members.forms.CodeForm.is_valid (otp, via form) guards_mint; same_user=unproven: check is in a condition whose success is required to reach the mint (branch or early exit)
```

A mint site shared by many entry points becomes one lock entry that lists them; a new entry point reaching it is a
`new_path` finding that names the entry point.

## Check evidence

On the way from the entry point to the mint site, MintMap records the checks it can see: password, TOTP, WebAuthn,
token signature, permission gates. Each check is labelled with the authentication **factor** it verifies, for
example `password`, `otp` or `reset_token_possession`; a path's `factors` maps each factor to its relation. For
each check MintMap makes a best-effort judgement of whether the result decides the outcome:

| Relation | Meaning |
|---|---|
| `guards_mint` | The mint is only reached when the check succeeds (a branch or an early exit) |
| `guards_mint_assert_only` | The check guards the mint only through an `assert` |
| `present_unproven` | The check runs, but MintMap cannot show that its result decides the outcome |
| `not_enforced` | The check runs and its result is ignored |
| `absent` | No check of that factor was found |

`+same_user_shown` is added when MintMap can also see that the checked user is the user who gets the credential.
Each path then gets one overall **status**, from `check_guards_mint` down to `no_check_found_in_analyzed_code`.
A status or relation that gets weaker is an `evidence_downgraded` finding.

> **This evidence is often weaker than the truth and sometimes wrong.** On unseen projects it agreed with the
> truth on 2 of 42 matched paths, claimed less than was true on 38 and was wrong on 2. A common case is a login
> reported with "no check found" whose password check runs in a serializer or form that a library setting names.
> See [EVALUATION.md](EVALUATION.md).

## Candidates

*Since 0.6.0a1.* A candidate is a site that has a general, structural reason to be reviewed, without enough
evidence to be called a mint. Candidates exist so that shapes MintMap does not model are at least visible.

| Candidate kind | What it is |
|---|---|
| `session_state` | Hand-written session state: logins, MFA / step-up / impersonation state, session hand-offs, and any session write right after a password or PIN re-check |
| `password_set` | A password set from a value the code does not generate (sign-up, password change, an administrator choosing a password) |
| `auth_library_call` | A call into an authentication library that the catalog does not describe. Also packages the catalog does not cover at all, when the function's name says it logs in or issues a token and it receives the request or a user |
| `minting_subclass` | A subclass of a catalogued minting middleware or view that MintMap did not see registered or routed |
| `request_authenticator` | Project code that authenticates requests itself: DRF authentication classes, another framework's `authenticate(self, request, ...)`, and every `request.user = ...` / `scope["user"] = ...` that is not an anonymous user (ranked high when no credential check is visible) |
| `startup_only` | A mint site that only start-up, deploy or command-line code reaches: `AppConfig.ready()`, settings, management commands, data migrations |

Candidates are traced, fingerprinted and diffed like paths, but they are reviewed as **one lock entry per kind**
(`candidates:<kind>`). The sites in an entry are ranked and each carries the reason it was reported:

```
  candidates:password_set  (one lock entry; lower confidence) a password set from a value that is not generated (user- or administrator-chosen): 1 site(s); 0 high, 1 medium, 0 low
      [cd678fdb9fe16dfa] medium members.views.finish_reset:66  reached from 1 entry point(s): route:members/reset/<uidb64>/<token>/|members.views.finish_reset
          why: sets a password from a value it does not generate: member.set_password(form.cleaned_data['password'])
```

In `diff`, a candidate group uses the same exit-code bits for its sites: a new site sets 1, a vanished one 2, a
changed one 4 (naming new or lost entry points). Its findings carry `"tier": "candidate"`.

## Watched sites

*Since 0.6.0a1.* Some sites look like mint sites but a precision rule **sets them aside** as not being
credentials. Those rules are judgements, and a judgement can be wrong on unfamiliar code. So the sites are
**watched**: one low-ranked lock entry per rule (`watched:<kind>`), fingerprinted by the site's own code and the
entry points reaching it. A wrong judgement then still shows up in `diff`.

| Watched kind | What was set aside |
|---|---|
| `random_value` | Random values kept under a name without a credential word |
| `signed_value` | Signed values no reader uses to log anyone in |
| `session_lookup` | Session ids that load a non-principal object |
| `unreferenced` | Generators nothing references |

Values set aside because their name says they are an identifier, a file, a cache key and so on are **not** watched.
They are only listed in the JSON report (`coverage.custom_credentials`).

In `diff`, a watched group behaves like a candidate group, with `"tier": "watched"`.

## Gaps

A gap is a construct MintMap could not analyse: a view it could not resolve, a URL built in a way it does not
model, a setting computed at run time. Files it could not parse are counted separately, as parse failures. Gaps
are listed at the end of the report, by type:

```
gaps by type: {}
```

(The demo project has none.) The text report lists the first 40 gaps; `--json` has all of them. A pull request
that adds a gap or a parse failure, loses a parsed file or changes the analysed roots raises `coverage_regression`, so MintMap cannot
quietly start seeing less.

> **Not everything MintMap misses is a gap.** On projects it was not developed against, 0.6.0a1 missed 12% of
> credential paths with no gap at all (0.5.0a1 missed 30% on an earlier, harder project set). See
> [Known blind spots](../README.md#known-blind-spots) and [EVALUATION.md](EVALUATION.md).

The report also lists library flows that the project's settings switch off. They are not paths, but switching one
on is a new path.

## Settings groups

Authentication settings affect every path, so they are not hashed into each one. They are reviewed as a few lock
entries, one per group:

```
  settings  authentication settings, one lock entry per group: settings:MIDDLEWARE, settings:AUTHENTICATION_BACKENDS, settings:REST_FRAMEWORK, settings:AUTH_CORE, settings:INSTALLED_APPS(auth), settings:package:django
```

A group that is new, removed or changed sets `fingerprint_changed` once, and the finding names the settings that
changed. MintMap analyses the settings modules that `DJANGO_SETTINGS_MODULE` literals in the code name and, as
alternatives, every other leaf settings module except test settings. There is no option to choose one settings
module.

## The review queue

The text report of `scan` starts with the review queue (since 0.6.0a1). It contains:

- confirmed paths, grouped by credential kind (`kind:session`, `kind:token`, `kind:precursor`, `kind:custom`,
  `kind:other`) and by entry point;
- candidate sites, by kind;
- the settings groups;
- the watched groups.

Inside a group, entries are ranked by a transparent risk score and each has a `why` line:

```
    route:members/sign-in/code/|members.views.sign_in_code
      [033339f757191ebb] medium django.contrib.auth.login at members.views.sign_in_code:52
          why: session credential (full_session); a recognised check guards the mint; reachable (route)
```

The score adds up the credential kind, the check evidence, reachability and confidence. An unrouted path is scored
like a reachable one.

> **The ranking is a hint, not a verdict.** In the evaluation, false alarms were sometimes ranked high and an
> administrator setting any user's password was ranked low.

`mintmap accept <dir> --group <group> --reviewer NAME` accepts one group; `--all` accepts everything that is not
accepted yet; ids (or unique prefixes of 8 or more characters) accept single entries.

## The lock

`mintmap.lock` is a JSON file with one entry per path, per candidate group, per watched group and per settings
group, plus a record of coverage (files parsed, gaps, roots) and of the tool, catalog and Python version that
wrote it. Every entry has a `review_status` (`unreviewed` or `accepted`), a `reviewer` and a `policy_note`.

| Command | What it does to the lock |
|---|---|
| `mintmap init <dir>` | Writes a new lock. Every entry is unreviewed |
| `mintmap accept <dir> ...` | Records a review decision. It does not re-scan the code |
| `mintmap update <dir>` | Re-scans and refreshes the lock after an intended change. Changed entries become unreviewed again |
| `mintmap diff <dir>` | Compares the code with the lock and exits with a [bitmask](../README.md#exit-codes) |

Lock entries carry the review-queue information in an informational `review` block that `diff` ignores. Locks
written by 0.5.0a1 stay valid, and `mintmap update` adds the block.

The lock is only as strong as the review rules around it: without code-owner review, a pull request can accept its
own change. See [ENFORCEMENT.md](ENFORCEMENT.md).

## Fingerprints

Each entry stores a fingerprint of what the review was based on: the code on the path, the checks, the hooks and
the settings involved. If any of it changes, `diff` reports `fingerprint_changed` and the previous review no
longer applies.

Fingerprints are the same on Python 3.11, 3.12 and 3.13 (tested on eight projects), so a lock written with one of
these versions can be checked with another. With any other version, write the lock with the Python minor version
CI uses.

**What does not change a fingerprint:** formatting, comments, docstrings and renamed local variables. Simple
extractions of a helper function in the same module are normalised too, except a helper whose name looks like a
check (for example `check_*`, `verify*`, `validate*`, `confirm_*`, after leading underscores) and a helper that
returns the result of a recognised check ([#9](https://github.com/mohamedmoatazsec/mintmap/issues/9)). Since 0.6.0a1
the following are normalised as well:

- extracting a method of the same class that no subclass overrides;
- helpers called with attribute arguments such as `request.META`, unless a call in the helper could rebind the
  attribute (for example the helper calls `load_account(self, ...)` and the argument is `self.account`);
- moving the mint call itself into such a helper;
- extracting a method in a class that a hook setting names.

**What still does (a false alarm):** extracting a helper that takes other expressions as arguments, and moving
code to another module or class.

Even so, 7 of 22 harmless changes raised a finding in the latest evaluation: four extracted helper functions or
methods (one named `_check_*`, which reads as a new unrecognised check), a value first held in a new local
variable, a hook's local import moved to module level, and a settings expression rewritten without changing its
value.

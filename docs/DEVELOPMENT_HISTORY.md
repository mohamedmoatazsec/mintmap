# MintMap development log (internal)

> **This is the internal development log of the MintMap prototype**, published as a record of how the tool was
> built and evaluated, including the failures. It is not user documentation. It was the prototype's working
> README; its commands, file names and version numbers refer to the prototype (`mintmap.py`, `mintmap_core/`,
> version `0.5.0-proto`), whose analysis code became the `mintmap` package (`src/mintmap/`, version 0.5.0a1).
> Names of harness runs (`v4`, `v5a`, `v5b`, `mut-hc-v2`, ...), reviewer fixtures (`e1..e11`, `mp1..mp11`) and
> result files refer to a private evaluation workspace that is not published. Rounds 1 and 2 are described here in
> detail; round 3 (the fresh held-out evaluation on InvenTree, Weblate and pretix) is only in
> [EVALUATION.md](EVALUATION.md).
>
> Current usage: [README.md](../README.md). Current results: [EVALUATION.md](EVALUATION.md). Review enforcement
> and the GitHub Action: [ENFORCEMENT.md](ENFORCEMENT.md).
>
> v6 (0.6.0.dev0) was developed in the release package (`src/mintmap/`) and is summarised in the first section
> below, in three parts (v6a, v6b, v6c); it has not been evaluated on fresh projects.
>
> Changes in release 0.5.0a1 after this log: fingerprints, gap keys and settings values use a
> Python-version-independent AST dump and unparser (identical to the evaluated ones on Python 3.13, except that
> non-ASCII string literals are escaped in the dump); the lock records the Python version
> and no longer stores absolute `--library-path` directories; the CLI has an `accept` command and exits 128 on
> internal errors; the catalog text was edited to remove local paths and unverified notes.

A small static-analysis prototype. It inventories the places where a Django
application creates a session or credential ("mint sites"), links each one to its
HTTP entry points, records which authentication checks constrain the mint, and stores
human-reviewed results in `mintmap.lock`. A CI `diff` then fails on new or removed
paths, changed evidence, or reduced analysis coverage.

* Python 3.11-3.13, **standard library only** (`ast`, `json`, `hashlib`, `tomllib`, `argparse`, `unittest`).
* Project code is **parsed, never imported or executed**. Library source given with `--library-path` (v5) is
  parsed the same way, read only.
* Mint and check knowledge comes from catalog v3 (the default since v5, shipped as
  `src/mintmap/data/django_catalog.json`; a strict superset of the unchanged v2, itself a superset of the unchanged
  v1; v1 and v2 are kept in `tests/data/` for the regression tests), through a hand-written machine-readable
  overlay (`core/overlay.py`). The overlay is described below.
* Prototype version `0.5.0-proto`. The v5 changes (part A: regression harness, fixes for root causes R1, R2, R4, R6 of the
  held-out evaluation of v4; part B: R3 custom credential generators, R5 project hooks called by library flows,
  R7 settings as their own lock entries, R8 refactor-insensitive fingerprints; **review round**: fixes for the 22
  findings of two adversarial reviews of part B), the v4 changes (fixes for eight findings of an adversarial review
  of v3), the v3 changes (P4 URL-list construction / routing, P5 first-match URL shadowing) and the v2 changes (P1,
  P2, P3) are summarised in the next sections and marked **(v5 review)** / **(v5)** / **(v4)** / **(v3)** / **(v2)**
  further down. Frozen copies of v1 and v4 were kept for comparison.

This is a prototype for evaluating an idea. It is **not** a vulnerability scanner. Its
labels describe *what the analysed code shows*. They are not security verdicts.

## What changed in v6 (0.6.0.dev0; developed in the release package, not yet evaluated on fresh projects)

Round 3 (frozen v5 on InvenTree, Weblate, pretix; see [EVALUATION.md](EVALUATION.md)) missed 45 of 149 units with
no visible gap and 18 of 58 harmful mutations passed `diff`; v4 had the same silent rate on its own held-out set, so
fixes tuned on development projects did not transfer. v6 therefore adds broad structural rules, above all a
**candidate tier** that makes new shapes visible and diffable at low review cost, plus false-alarm reductions. Those
three projects are now development projects; the evaluation of v6 needs fresh ones. Every rule has a synthetic
fixture test (`tests/test_v6.py`, 30 tests; `tests/test_v6b.py`, 19 tests; `tests/test_v6c.py`, 22 tests for the second
part, v6b, below; `tests/test_v6d.py`, 67 tests for the third part, v6c; no project code copied).

**Harness (A0).** `run_all.py` / `units.json` cover all eight development projects: the saved mutations of InvenTree,
Weblate and pretix with their labels, the verifiers' own probes (InvenTree v1-v6, Weblate v1, pretix y1-y3) and 149
recall units with the verifier-corrected verdicts. The unit scorer reproduces every verified v5 verdict on the frozen
v5 scans (44/44, 36/36, 69/69: tolerance 0), and a false-alarm classifier (adjudicated FALSE_ALARM paths matched by
path id or by entry + mint + mint-site function; grouped entries by member keys) reproduces the adjudicated counts
(17, 61, 49) with no unadjudicated path. Paths a run reports that nobody adjudicated are counted separately as an
upper bound on new false alarms. Baseline: label `v5r` (the release copy of v5).

**Candidate tier** (`core/candidates.py`). A candidate is a site with a general structural reason to be reviewed but
not enough evidence to be called a mint. Candidates are traced to entry points, fingerprinted and diffed like paths,
but each SITE is one review entry (all entry points listed in `reached_from`), grouped per kind in the lock
(`candidates:<kind>`), ranked (high / medium) and carrying its reason. Kinds:
`session_state` (session writes that re-key the session with an identifier / hash, copy a session key or a value of
another session, hand out a new SessionStore, or keep an identifier / hash / timestamp / flag / signed marker under an
auth-named key; ordinary UI state is set aside and counted), `password_set` (a password set from a value the code does
not generate, not the signed-in user's own), `auth_library_call` (the request handed to an authentication-package
function the catalog does not describe; accessors and `did_*` / `was_*` predicates excluded), `minting_subclass` (an
unregistered project subclass of a catalogued minting middleware / view), and `request_authenticator` (the
`authenticate` / `authenticate_credentials` method of a project DRF authentication class; a routed function that sets
`request.user` after verifying or reading a credential). A new, vanished or changed member sets the usual bits.

**Recall rules (confirmed tier).**
* Session keys are compared as patterns (f-strings, `str.format`, `%`, `+`, locals, module constants) and read
  through session aliases and SessionStore objects (hand-rolled logins with run-time keys).
* Creation through a reverse relation (`team.tokens.create(...)`) and Django CreateView saves of credential models;
  a `post_save` receiver whose body is `if created:` is not reached by an update save.
* A catalogued library function view called directly (`return complete(request, backend)`) mints at the calling
  route, with the project hooks its settings name.
* Settings computed by calls keep the items they can read (getter defaults, pass-through functions, comprehension
  filters, conditional expressions) and mark the rest (`setting_partially_unknown`); settings returned by a project
  factory function are evaluated; settings assigned at run time in project code (`AppConfig.ready()`) are one more
  alternative (`setting_changed_at_run_time`).
* An admin site swapped inside a function or through `AdminConfig.default_site`; catalogued URL builders
  (`allauth.headless.urls.build_urlpatterns`, narrowed by its client argument); unknown library helpers that wrap
  `path()` are read as conditional routes with a gap; admin-chosen passwords (`UserAdmin.add_view`).
* URLconf: `api_urls = router.urls` referenced from another module is the router's routes (InvenTree's whole admin
  API was a global gap); an instance of a project class with `__call__` used as a view is routed to `__call__`.
* Module names: a reference that resolves from the project directory is not evidence for a deeper source root
  (`plugin/machine/` next to `machine/` had made `plugin` an alias of `plugin.plugin`), and an alias never rewrites a
  real module name.

**Change detection.** Reading a project `@property` / `@cached_property` on `self` is an edge to its getter; the
values of a class-level dict a view picks from (`forms = {"totp": TotpForm, ...}`) are injected code; for
`x.m(...)` with an untyped receiver, the project methods named `m` (non-generic name, at most 3 definitions) join the
callee closure (fingerprint only).

**False-alarm reductions.**
* URL-prefix twins (`if not PREFIX: urlpatterns = x else: [path(PREFIX, include(x))]`) are one entry.
* Catalog `library_flow_conditions` (django-allauth 65.20.0, cited): a library flow is not a path when every enabling
  condition is statically false (HEADLESS_ONLY for the headed flows of `allauth.urls`, `allauth.mfa` /
  `allauth.socialaccount` not installed, ACCOUNT_LOGIN_ON_PASSWORD_RESET / LOGIN_ON_EMAIL_CONFIRMATION left at their
  default, ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE, MFA_PASSKEY_LOGIN_ENABLED, MFA_TRUST_ENABLED); such flows are listed in
  `coverage.library_flows_disabled_by_settings`, unknown values keep the flow, and enabling one later is a new path.
* Generic signing / JWT primitives are mints only for credential-like values (kept under a credential name, or
  signing a principal identifier); updates are not creations (perform_update / UpdateView form saves,
  `perform_destroy(instance)`, read-only DRF viewsets have no create flow, from the DRF class method lists);
  heuristic generators that no project code calls or names are set aside; heuristic sites reached from 3 or more
  entry points (was 6) are one lock entry; heuristic-site entries are line-independent.

Changed earlier expectations: `test_v5b.SettingsGroupTests.test_catalog_flow_setting_is_a_dependency_of_that_flow_only`
uses ACCOUNT_LOGIN_TIMEOUT (a False ACCOUNT_LOGIN_ON_PASSWORD_RESET now switches its flow off);
`test_v5c.ReviewNoiseTests.test_few_entry_points_keep_one_path_each` uses 2 entry points; the `testcode_project`
fixture signs a principal id (an unkeyed signed order id is no longer a mint); `mm_testutil.accept_all` also accepts
candidate groups.

### Before / after (regression harness: `v5r` = release copy of v5, `v6a` = this tree)

Same harness, same saved mutations and units; `--library-path` not used. "Recall" is the automatic unit scorer;
"FA" counts reported paths and candidate sites that verifiers adjudicated FALSE_ALARM (v5) still reported / reported
items nobody adjudicated (an upper bound on new false alarms; candidate sites in brackets). Lock entries: path entries
+ settings entries + candidate groups (candidate sites).

| project | run | lock entries | recall exact / mint only / gap / **silent** | harmful caught / **silent** | harmless flagged | FA known / unadjudicated | scan s |
|---|---|---|---|---|---|---|---|
| Healthchecks | v5r | 32 + 6 | - | 6/6 / **0** | 0/3 | - | 2.7 |
| | v6a | 27 + 6 + 1 (2) | - | 6/6 / **0** | 0/3 | - | 2.3 |
| paperless-ngx | v5r | 33 + 7 | 18 / 0 / 6 / **0** of 24 | 12/12 / **0** | 0/3 | 4 / 9 | 5.5 |
| | v6a | 34 + 7 + 3 (8) | 18 / 0 / 6 / **0** of 24 | 12/12 / **0** | 0/3 | 4 / 18 (8) | 4.0 |
| netbox | v5r | 9 + 9 | 10 / 1 / 2 / **2** of 15 | 11/11 / **0** | 0/3 | 0 / 3 | 23.0 |
| | v6a | 9 + 9 + 3 (8) | 12 / 2 / 1 / **0** of 15 | 11/11 / **0** | 0/3 | 0 / 8 (5) | 17.2 |
| plane | v5r | 35 + 7 | 25 / 0 / 0 / **0** of 25 | 11/11 / **0** | 0/6 | 3 / 6 | 10.4 |
| | v6a | 35 + 7 + 2 (8) | 25 / 0 / 0 / **0** of 25 | 11/11 / **0** | 0/6 | 3 / 14 (8) | 8.1 |
| InvenTree | v5r | 36 + 10 | 9 / 3 / 27 / **5** of 44 | 14/19 / **5** | 2/10 | 17 / 0 | 11.4 |
| | v6a | 30 + 10 + 2 (7) | 26 / 3 / 15 / **0** of 44 | 19/19 / **0** | 2/10 | 5 / 8 (5) | 9.4 |
| Weblate | v5r | 103 + 11 | 14 / 7 / 3 / **12** of 36 | 13/21 / **8** | 1/5 | 61 / 0 | 37.6 |
| | v6a | 50 + 11 + 3 (13) | 26 / 6 / 2 / **2** of 36 | 21/21 / **0** | 1/5 | 19 / 16 (8) | 31.4 |
| pretix | v5r | 91 + 9 | 33 / 7 / 1 / **28** of 69 | 13/18 / **5** | 1/5 | 49 / 0 | 32.3 |
| | v6a | 88 + 9 + 3 (17) | 55 / 12 / 0 / **2** of 69 | 18/18 / **0** | 1/5 | 28 / 17 (9) | 30.8 |
| Zulip (scan only) | v5r | 121 + 10 | - | - | - | - | 40.1 |
| | v6a | 103 + 10 + 1 (2) | - | - | - | - | 37.0 |

Totals: harmful mutations caught 80/98 -> **98/98** (round-3 projects 40/58 -> 58/58, including all 9 verifier
probes); harmless changes flagged 4/35 -> 4/35 (the same four: three extract-method refactors and a log edit in a
check closure). Recall on the round-3 projects (149 units, v5r reproduces the verified v5 numbers exactly): exact
56 -> 107, mint only 17 -> 21, gap 31 -> 17, **silent 45 -> 4** (S 17 -> 0, T 12 -> 0, P 16 -> 4; 20 units are
found only by candidates). Reported items on those projects 230 -> 205 (paths 168, candidate sites 37):
adjudicated false alarms still reported 127 -> 52, unadjudicated 0 -> 41 (22 of them candidate sites). Every
unmodified diff exits 0; locks written with Python 3.11 and 3.13 are identical (Healthchecks, paperless-ngx,
InvenTree, pretix). These recall and mutation gains were obtained on the projects the fixes were built against.

### v6 limits

* All numbers above are on the development projects; InvenTree, Weblate and pretix were used to find the root
  causes, so their recall says little about unseen code. Only a fresh evaluation can show whether the candidate
  tier generalises.
* Still silent on the development set: two e-mail validation links run by the social-auth pipeline (library code)
  and an OAuth authorization code kept under the weak word `code` on a model linked to a non-user principal.
* The candidate tier trades silence for review work: every site is listed with its reason, but day-one review now
  includes the candidate groups.
* Not done: completing the catalog for allauth headless and django-oauth-toolkit URLconfs (several units are still
  `library_include_mints_incomplete` gaps); a signed value carrying only the signed-in user's id is still a confirmed
  mint (it can be a session hand-off or an OAuth-like state).

### v6, second part (v6b): precision, change detection and review cost

Same development set and harness; synthetic fixture tests in `tests/test_v6c.py` (22 tests, no project code).

**Change detection (refactor false alarms).** The four harmless changes that still raised a finding in `v6a`
were three extract-method / extract-helper refactors and a log-call edit in the check closure of a false-alarm path.
* `refactor.Inliner` also inlines *extract method*: `self.h(...)` called by a method of class `C`, where `h` is a
  plain method of the same class (no decorator, not rebound in the class body, not overridden by any project
  subclass, the caller never rebinds its receiver). A private method inlined at every reference in the project is
  left out of the class dump and of a library flow's callee roots; a public one stays (a library may call it by name).
* Arguments that are attribute chains on a name (`request.META`, `self.request.headers`) are substituted when the
  helper assigns or deletes none of the chain's attributes.
* The log-call edit sat in the check closure of an audit correlation id reported as a custom credential; that path
  is gone (below), and with it the finding.

**False alarms (general rules).**
* *Start-up-only mints* are a candidate kind `startup_only` (rank low): a mint site that only `AppConfig.ready()`,
  import-time calls (a settings module calling a key generator), a management command's `handle()` or a function
  that only migrations name reaches is not a request path. Still traced, fingerprinted and diffed.
* *Session values that load something other than a principal*: a key read back as `pk=` / `id=` of a project model
  that is not principal-like (not the user model, not named after a user / customer / member / account, keeps no
  password) and is not attached to the request (`request.x = ...`) is flow state (an event, a payment, a workspace);
  `get_object_or_404(M, pk=...)` is read too. Listed in `coverage.custom_credentials.session_lookups_set_aside`.
* *Signed values read back*: a `signing.dumps` / `Signer.sign` value that looked like a credential is set aside when
  every project function that reads it back with the same salt (`signing.loads` / `unsign`), its callers, and what
  they call two levels down neither log anyone in, set a password nor call a catalogued mint (confirmation payloads,
  OAuth-like state, redirect proofs). A hand-off link whose reader logs the user in stays a mint; making a reader
  log in is a new path.
* *Custom-credential heuristic*: a callable keeps a credential only when its name has a credential noun (an action
  word such as `reset()`, e.g. `ContextVar.reset(token)`, does not); a predicate (`check_*`, `verify_*`,
  `validate_*`, `is_*` ...) consumes a value rather than keeps it; an integration word (`webhook`, `callback`,
  `integration` ...) in the kept name vetoes even a strong head noun (`webhook_token`); `session` no longer
  qualifies itself as a weak word (`_session_wizard_prefix`).
* `testutils/` and `test_utils/` packages are test code (re-included when non-test code imports them).

**Review cost.** Every confirmed path carries a `review` block: its group (credential kind `kind:session`,
`kind:token`, `kind:precursor`, `kind:custom`, `kind:other`), a risk (high / medium / low from a transparent score:
kind, check evidence, reachability, confidence) and the reasons; candidate sites carry their kind and rank. The text
report starts with this review queue (kinds, then entry points, highest risk first, one `why` line per entry,
candidate groups, settings groups) and lists the path evidence in the same order. `mintmap accept --group <group>`
accepts one group. Lock format: path entries gain the informational `review` block, which `diff` ignores; locks
written by 0.5.0a1 / v6a stay valid (for them `accept --group` derives the group from the purpose) and
`mintmap update` adds the block.

**Before / after** (regression harness `v5r` -> `v6a` -> `v6b` = this tree, snapshot 553190a, 1270.9 s). Lock
entries = path entries + settings entries + candidate groups (candidate sites). FA = adjudicated false alarms still
reported (any tier) / reported items nobody adjudicated; precision = share of reported items (paths + candidate
sites) that are not adjudicated false alarms, as a range (unadjudicated items counted as false alarms ... as real).

| project | run | lock entries | harmful caught | harmless flagged | FA known / unadj. | precision, all items | precision, confirmed paths |
|---|---|---|---|---|---|---|---|
| InvenTree | v5r | 36 + 10 | 14/19 | 2/10 | 17 / 0 | 53% | 53% |
| | v6a | 30 + 10 + 2 (7) | 19/19 | 2/10 | 5 / 8 | 65-86% | 73-83% |
| | v6b | 25 + 10 + 3 (10) | 19/19 | **0/10** | 4 / 7 (3 of the 4 are low-ranked `startup_only` candidates) | 69-89% | 88-96% |
| Weblate | v5r | 103 + 11 | 13/21 | 1/5 | 61 / 0 | 41% | 41% |
| | v6a | 50 + 11 + 3 (13) | 21/21 | 1/5 | 19 / 16 | 44-70% | 46-62% |
| | v6b | 37 + 11 + 4 (15) | 21/21 | **0/5** | 8 / 16 | 54-85% | 59-78% |
| pretix | v5r | 91 + 9 | 13/18 | 1/5 | 49 / 0 | 46% | 46% |
| | v6a | 88 + 9 + 3 (17) | 18/18 | 1/5 | 28 / 17 | 57-73% | 59-68% |
| | v6b | 81 + 9 + 3 (17) | 18/18 | **0/5** | 21 / 17 | 61-79% | 64-74% |
| paperless-ngx | v6a / v6b | 34 + 7 + 3 (8) | 12/12 | 0/3 | 4 / 18 | 48-90% | 59-88% |
| netbox | v6a | 9 + 9 + 3 (8) | 11/11 | 0/3 | 0 / 8 | 53-100% | 67-100% |
| | v6b | 8 + 9 + 4 (9) | 11/11 | 0/3 | 0 / 8 | 53-100% | 75-100% |
| plane | v6a / v6b | 35 + 7 + 2 (8) | 11/11 (+4 follow-ups) | 0/6 | 3 / 14 | 60-93% | 74-91% |
| Healthchecks | v6a / v6b | 27 + 6 + 1 (2) | 6/6 | 0/3 | - | - | - |
| Zulip (scan only) | v6a | 103 + 10 + 1 (2) | - | - | - | - | - |
| | v6b | 97 + 10 + 2 (8) | - | - | - | - | - |

Totals: harmful mutations caught 98/98 in `v6a` and `v6b` (v5r 80/98); harmless changes flagged 4/35 -> **0/35**.
Recall (213 units) unchanged from `v6a`: exact 162, mint only 23, gap 24, silent 4; no adjudicated real path was
lost (real paths still reported 15 / 20 / 42 on InvenTree / Weblate / pretix in both runs). On the round-3 projects
reported items 230 (v5r) -> 205 (v6a) -> 185 (v6b): adjudicated false alarms 127 -> 52 -> 33, unadjudicated
0 -> 41 -> 40; precision 45% -> 55-75% -> 61-82% (confirmed paths only: 45% -> 58-69% -> 67-79%). Day-one lock
entries 260 -> 206 -> 183. Scan times unchanged within noise (Weblate 31.4 -> 33.3 s, netbox 17.2 -> 20.1 s).
Every unmodified diff exits 0; locks written with Python 3.11 and 3.13 are identical apart from the `tool` block
(Healthchecks, pretix).

### v6b limits

* As for v6a: every number is on development projects; the rules were derived from the adjudications of InvenTree,
  Weblate and pretix, so only a fresh evaluation can show whether they generalise.
* Remaining adjudicated false alarms (33): pretix order / position capability secrets created at many sites (11),
  Weblate `django_otp.login` re-storing a device id through a social-auth completion (4), outbound-integration and
  server secrets whose names carry no integration word (backup passphrase, Stripe OAuth state, server key pairs),
  signed download tokens of a project signer class (no comparable salt), a random password nobody receives, and
  three low-ranked `startup_only` candidates.
* The candidate tier grew by 5 sites on the round-3 projects (37 -> 42, of them 3 adjudicated false alarms moved
  there from the confirmed tier); on Zulip 6 confirmed paths became `startup_only` candidates.
* Extract-method normalisation does not cover public methods of classes that inherit a library flow, helpers in
  another class or module, or expression arguments other than attribute chains; check evidence is still computed on
  the code as written (a check moved into a helper can read weaker).
* The signed-value rule trusts the project's readers: a value read back by a library, by code in another
  repository, or without a comparable salt keeps the earlier decision.

### v6, third part (v6c): two adversarial reviews of v6b; generalisation over development numbers

Frozen v5 missed 30% of the credential units of three unseen projects with no visible gap, and v4 had the same
rate on its own held-out set; v6a/v6b then reached near-perfect numbers on the projects they were built from. Two
adversarial reviews of v6b showed what that was worth: a soundness review found 11 changes that v6b let through
with exit 0 (most of them regressions introduced by the v6 precision rules), and a generalisation review wrote 31
new synthetic projects (31 auth shapes, 51 units, 36 should-flag and 9 harmless mutations) on which v6b caught
19/35 harmful changes, no more than the evaluated v5 (19) and fewer than v6a (21), with 11 units silent. The
precision rules had removed real paths into JSON-only `set_aside` lists, invisible to `diff`. This round therefore
changes structure more than vocabulary: every judgement that drops a site now leaves it visible and diffed.
Synthetic fixture tests: `tests/test_v6d.py` (67 tests, no project code). The reviewers' fixtures are part of the
development set from now on, so their numbers below are not a generalisation measure either.

**Watched tier** (the main change). A site that a precision rule sets aside as *not a credential* (a random value
kept under a name without a credential word, a weak word nobody checks, an integration-named secret; a signed value
without a credential name or principal payload, or whose readers issue nothing; a session write whose key loads a
non-principal object; a generator nothing references) is a report entry (`watched`) and a lock entry per rule
(`watched:<kind>`, rank low, with the reason). Its fingerprint is deliberately narrow: the site function's
normalised code, the symbol and the entry points reaching it, so a weakened generator, a check removed in the
writer, or a new route to the site is a finding (bits 1 / 2 / 4, `tier: "watched"`), while edits elsewhere on the
paths are not. Values set aside because their name says they are an identifier, a file, a cache key ... stay in the
JSON report only. Development projects carry 1-30 watched sites in 1-4 groups.

**Soundness (regressions of v6a/v6b).**
* Inliner: an attribute-chain argument (`request.team`, `self.account`) is substituted only when no call in the
  helper receives an object the chain goes through (`load_account(self, ...)`, `activate_team(request, ...)`,
  `self.reload()`): such a call may rebind the attribute, and the reviewed check would silently move onto the old
  object.
* `installed_app` flow conditions compare `AppConfig.name` (django/apps/registry.py:242-249): a project subclass of
  a library AppConfig installs that app; an AppConfig MintMap cannot read keeps the flow.
* Absent settings: `ALLAUTH_SETTING_GETTER` (catalog `settings_read_through`, allauth/utils.py:223-230),
  `setattr(settings, "X", v)` at run time, and `globals()` / `vars()` / `locals()` / `sys.modules` writes in a
  settings module keep the flows a library default would switch off (a computed key may assign any setting; a
  `globals().update(...)` whose dict has constant keys, also built by a project function, assigns only those).
* Signed values: readers with the same salt (or the same PyJWT key), also a bare `loads` import, are followed up to
  four levels of callers (codec -> service -> view); a value whose reader logs someone in or authenticates a
  request is a mint whatever it is called; a credential-looking value is set aside only when every reader is
  analysed and reaches no issuing code at any depth.
* Session lookups: `request.user = obj.owner` (anything derived from the looked-up object) attaches it; a session
  id written right after a secret check (`pin != POST["pin"]`, `compare_digest`, `check_password`) is a login
  whatever the model is called (kiosk / terminal / employee logins).
* An integration-named field that a project authenticator looks requests up by is a credential.
* Test-helper modules named by dotted strings (`include("x.test_utils.urls")`, MIDDLEWARE) are analysed.
* Functions of a module dispatched into with `getattr(module, <computed>)` are not dead code; dead-code generators
  are watched instead of dropped.
* A mint only a data migration reaches is a `startup_only` candidate (also through `apps.get_model(...)`).
* `request.user = ...` / `scope["user"] = ...` is a candidate without a visible credential check (rank high).

**Recall on new shapes.**
* Custom managers and querysets: `Model.objects.<m>()` resolves to the project manager / queryset method
  (`objects = M()`, `QS.as_manager()`, `Manager.from_queryset(QS)()`); `self.create(...)` / `self.model(...)` in a
  manager create its model; chained queryset calls keep the queryset type.
* Candidates: other frameworks' `authenticate(self, request, ...)` (django-ninja), Channels `scope["user"]`,
  `SimpleLazyObject(lambda: helper(request))` (the helper is in the candidate's callees); calls into packages the
  catalog does not cover at all when the function name says it logs in or issues a token (`sign_in_as`,
  `token_for`) and it receives the request or a user.
* `settings:AUTH_HOOKS(project code)`: callables named by auth-named settings of uncatalogued libraries
  (`CAN_LOGIN_AS`), receivers of authentication-library signals (`populate_user`, `user_logged_in`), predicates
  registered with permission registries (`rules.add_perm`), each hashed with its callee closure.
* A random nonce kept in a cache key that a view reads back to log the user in is a credential (cross-domain
  hand-off); Django's `SESSION_KEY` constants resolve to `_auth_user_id`.
* Class-based settings (django-configurations) are evaluated; a URL list filled at run time by a decorator is a
  `url_list_filled_at_run_time` gap; unrouted paths are scored like reachable ones in the review queue.

**False alarms and review cost.**
* Weak words (`code`, `key`, `pin`) on a user-linked model need a reader (a lookup or a comparison by that field):
  a booking reference or coupon code nobody checks is watched, not a path.
* `session_state`: principal nouns alone (`user_prefers_dark`) and UI hint words do not make a candidate; keys
  recording a failed check (`bad_link`) do not either.
* The `SECRET_KEY_FALLBACKS` re-hash branch of AuthenticationMiddleware is a path only when fallbacks are
  configured (catalog `library_flow_conditions`, django/contrib/auth/__init__.py:309-314); `DEBUG` is an allauth
  setting only in projects that use allauth, and package settings groups need the package.
* A catalogued mint reached through a signal receiver from six or more entry points is one grouped entry (better
  manager resolution had connected 23 Weblate views to the token a receiver creates for every new bot user); a new
  entry point reaching any grouped site is a NEW_PATH that names it.
* Extract refactors: a mint moved into an inlined helper keeps its path id and code; nested `and` / `or` are
  flattened; inlined private methods of hook classes are not hook roots.
* Name fallback: up to six project definitions are hashed; more set `fingerprint_complete` false
  (`fingerprint_name_fallback_limit`) instead of hashing nothing silently.

Changed earlier expectations: none of the existing tests changed; `mm_testutil.accept_all` also accepts watched
groups. Lock format: a `watched` list next to `candidates` (older locks: the watched groups are new entries on the
first diff; run `mintmap update`). Path ids of mints inside small helpers that their caller inlines changed (the
caller is now the identity), so the first `diff` after upgrading reports those paths as removed and new.

**Before / after** (regression harness `v5r` -> `v6b` -> `v6` = this tree; same saved mutations, units and
adjudications; `--library-path` not used). Lock entries = path entries + settings entries + candidate groups
(candidate sites) + watched groups [watched sites]. Recall = exact / mint only / gap / **silent** (automatic unit
scorer; watched sites do not count). FA = adjudicated false alarms still reported (any tier) / reported items nobody
adjudicated; precision as in the v6b table (paths + candidate sites; watched sites are not reported items).

| project | run | lock entries | recall exact / mint only / gap / **silent** | harmful caught | harmless flagged | FA known / unadj. | precision, all items | precision, confirmed paths | scan s |
|---|---|---|---|---|---|---|---|---|---|
| Healthchecks | v5r | 32 + 6 | - | 6/6 | 0/3 | - | - | - | 2.69 |
|  | v6b | 27 + 6 + 1 (2) | - | 6/6 | 0/3 | - | - | - | 2.19 |
|  | **v6** | 27 + 5 + 1 (2) + 2 [13] | - | 6/6 | 0/3 | - | - | - | 2.39 |
| paperless-ngx | v5r | 33 + 7 | 18 / 0 / 6 / **0** of 24 | 12/12 | 0/3 | 4 / 9 | 61%-88% | 61%-88% | 5.5 |
|  | v6b | 34 + 7 + 3 (8) | 18 / 0 / 6 / **0** of 24 | 12/12 | 0/3 | 4 / 18 | 48%-90% | 59%-88% | 3.91 |
|  | **v6** | 34 + 7 + 3 (8) + 1 [1] | 18 / 0 / 6 / **0** of 24 | 12/12 | 0/3 | 4 / 18 | 48%-90% | 59%-88% | 4.14 |
| netbox | v5r | 9 + 9 | 10 / 1 / 2 / **2** of 15 | 11/11 | 0/3 | 0 / 3 | 67%-100% | 67%-100% | 23.01 |
|  | v6b | 8 + 9 + 4 (9) | 12 / 2 / 1 / **0** of 15 | 11/11 | 0/3 | 0 / 8 | 53%-100% | 75%-100% | 20.05 |
|  | **v6** | 8 + 10 + 4 (9) + 1 [1] | 12 / 2 / 1 / **0** of 15 | 11/11 | 0/3 | 0 / 8 | 53%-100% | 75%-100% | 20.16 |
| plane | v5r | 35 + 7 | 25 / 0 / 0 / **0** of 25 | 11/11 | 0/6 | 3 / 6 | 74%-91% | 74%-91% | 10.44 |
|  | v6b | 35 + 7 + 2 (8) | 25 / 0 / 0 / **0** of 25 | 11/11 | 0/6 | 3 / 14 | 60%-93% | 74%-91% | 8.96 |
|  | **v6** | 34 + 6 + 2 (8) + 1 [2] | 25 / 0 / 0 / **0** of 25 | 11/11 | 0/6 | 2 / 14 | 62%-95% | 76%-94% | 9.54 |
| InvenTree | v5r | 36 + 10 | 9 / 3 / 27 / **5** of 44 | 14/19 | 2/10 | 17 / 0 | 53%-53% | 53%-53% | 11.42 |
|  | v6b | 25 + 10 + 3 (10) | 26 / 3 / 15 / **0** of 44 | 19/19 | 0/10 | 4 / 7 | 69%-89% | 88%-96% | 8.55 |
|  | **v6** | 24 + 11 + 3 (12) + 1 [1] | 26 / 3 / 15 / **0** of 44 | 19/19 | 0/10 | 4 / 8 | 67%-89% | 92%-96% | 8.56 |
| Weblate | v5r | 103 + 11 | 14 / 7 / 3 / **12** of 36 | 13/21 | 1/5 | 61 / 0 | 41%-41% | 41%-41% | 37.62 |
|  | v6b | 37 + 11 + 4 (15) | 26 / 6 / 2 / **2** of 36 | 21/21 | 0/5 | 8 / 16 | 54%-85% | 59%-78% | 33.28 |
|  | **v6** | 38 + 12 + 4 (16) + 3 [19] | 26 / 6 / 2 / **2** of 36 | 21/21 | 0/5 | 9 / 17 | 52%-83% | 58%-76% | 39.57 |
| pretix | v5r | 91 + 9 | 33 / 7 / 1 / **28** of 69 | 13/18 | 1/5 | 49 / 0 | 46%-46% | 46%-46% | 32.31 |
|  | v6b | 81 + 9 + 3 (17) | 55 / 12 / 0 / **2** of 69 | 18/18 | 0/5 | 21 / 17 | 61%-79% | 64%-74% | 30.58 |
|  | **v6** | 84 + 9 + 3 (18) + 4 [30] | 55 / 12 / 0 / **2** of 69 | 18/18 | 0/5 | 21 / 21 | 59%-79% | 62%-75% | 31.66 |
| Zulip (scan only) | v5r | 121 + 10 | - | 0/0 | 0/0 | - | - | - | 40.06 |
|  | v6b | 97 + 10 + 2 (8) | - | 0/0 | 0/0 | - | - | - | 38.43 |
|  | **v6** | 97 + 8 + 3 (10) + 2 [7] | - | 0/0 | 0/0 | - | - | - | 41.54 |

Totals: harmful mutations caught 80/98 (v5r) -> 98/98 (v6b) -> **98/98** (v6); harmless changes flagged 4/35 -> 0/35
-> **0/35**. Recall (213 units) unchanged from v6b: exact 162, mint only 23, gap 24, silent 4. Round-3 projects:
reported items (paths + candidate sites) 230 -> 185 -> 192, adjudicated false alarms still reported 127 -> 33 -> 34,
unadjudicated 0 -> 40 -> 46; precision 45% -> 61-82% -> 58-82% (confirmed paths only: 45% -> 67-79% -> 66-79%);
day-one lock entries 260 -> 183 -> 196 (of which 8 watched groups with 50 sites, accepted as groups). Harness wall
time 1271 s (v6b) -> 1454 s (v6). Every unmodified diff exits 0; locks written with Python 3.11 and 3.13 are
identical apart from the `tool` block (Healthchecks and two of the new fixture projects).

**The reviewers' fixtures (now development fixtures, not a generalisation measure).** Soundness cases: every one of
the 11 changes that v6b let through is a finding (c02, c02c, c04, c04b, c05 x5, c07 x2, c08b x3, c09 x2, c11, c14,
c16, c17b, c19, c19b, c20). Generalisation projects: should-flag mutations caught 19/35 (v6b; 20/36 with the
reviewers' control m36) -> 36/36; harmless mutations flagged 3/9 -> 0/9 (h03, a log line on a reviewed path, is a
code change and is excluded as in the review). Of the 11 units the review found silent, 10 are now visible: eight as
confirmed paths or a candidate (g09.1, g10.1, g17.1, g20.1, g20.2, g30.1, g31.1 confirmed; g21.1 a candidate), two
only as watched sites (g07.1 websocket ticket, g14.2 deploy key); the remember-me cookie (g16.2, `set_signed_cookie`)
is still not a credential of its own (its reader is a request-authenticator candidate).

### v6c limits

* Every number is on development projects; InvenTree, Weblate and pretix and the reviewers' 31 synthetic projects
  were used to find the problems. Only a fresh evaluation can tell whether the structural rules generalise.
* Review cost went up a little: the round-3 projects have 13 more (196) day-one lock entries (watched groups, the
  AUTH_HOOKS settings group) and 6 more (46) unadjudicated reported items (new request-authenticator and
  uncatalogued-library candidates, user creations that better manager resolution now links to routes); the
  adjudicated false alarms still reported are 34 (one more) (Weblate's password-reset scope token is a path again:
  its reader's view sets a password, which is what the reader rule looks for).
* The reader rules (signed values, cache keys, weak words, session keys) decide by reachability, not data flow: a
  reader whose caller logs someone in for an unrelated reason makes a value a credential.
* A watched site's fingerprint is its own function: an edit there for an unrelated reason is a finding (CI noise),
  and a change elsewhere on its paths (a caller dropping a check) is not.
* Path ids of mints inside small helpers that their caller inlines changed (the caller is the identity now): the
  first `diff` after upgrading from v6b reports those paths as removed and new; `mintmap update` re-baselines.
* Scan time: Weblate 33 -> 40 s, Zulip 38 -> 41 s, other projects within noise (new whole-project passes for
  hooks, readers and dynamic dispatch).
* Not done: signed cookies as credentials; routes registered by decorators at run time stay unrouted (gap only);
  a weak-word value is kept as a credential as soon as any project code looks it up by its field (a booking
  reference read back by a lookup stays a path); `globals().update(...)` with keys MintMap cannot read keeps
  every flow a default would switch off (InvenTree-style LDAP dicts with constant keys are read).

## What changed in v5 (review round: 22 findings of two adversarial reviews of part B)

Two reviewers attacked v5 part B with synthetic fixtures (soundness experiments `e1..e11` on
the part-B mechanisms; generalization projects `mp1..mp11` with mutation lists: fresh project
shapes). Every finding was reproduced; none was judged wrong. Each fix is general and has tests in `tests/test_v5c.py`
(see "Tests"). Where a full analysis was not possible the miss is made VISIBLE (a gap, `analysis_complete=false`).

| # | finding (review evidence) | change |
|---|---|---|
| F1 (high) | R8 inlining left a helper in no fingerprint: an edge counted as "inline" when the helper's OWN transformation inlined it, but the hashed dump is the outer caller's, which may not inline it (a caller-local `from m import X` shadows the helper's free name). e1: exit 0 (v4: 4) | `refactor.Inliner.inlined_bodies(f)` records every helper instantiated in `f`'s dump at any depth; `project_closure` hashes every reached function whose body is not instantiated in the dump of a hashed function (callers first). e1: exit 4 |
| F2 (high) | library views declared non-minting by prefix (`rest_framework.generics.*`, `django.views.generic.*`) ignored `as_view(**kwargs)`: `CreateAPIView.as_view(serializer_class=<token-minting serializer>, permission_classes=[AllowAny])` was a new unauthenticated token route with no path and no gap. e7: exit 0 | project classes / functions passed in `as_view(**kwargs)` of a library view are entry functions of the route (`library_view_kwarg`), also for non-minting views, and are fingerprinted (`callees`) and validated (`checks`). e7: exit 1 (`new_path`) |
| F3 (medium) | alpha-renaming treated comprehension targets as function locals: `[f for f in xs]` plus a call `f(...)` of a global renamed the call; two programs calling different global checks had equal dumps and gap keys. e3: exit 0 (v4: 36) | comprehensions are their own renaming scope (first iterable outside, targets inside, walrus binds in the function); the call graph's function locals no longer include names bound only in comprehensions. e3: exit 12 |
| F4 (medium) | `MAX_INLINE_DEPTH`: helpers deeper than the outer dump's budget were inlined in their own caller's transform only, hashed nowhere, and no `fingerprint_depth_limit` gap (v4 had one). e2: exit 0 | same fix as F1 (a body not instantiated in a hashed dump is hashed itself). e2: exit 4 |
| F5 (medium) | settings changes ignored silently: `REST_FRAMEWORK["K"] += (...)`, `REST_FRAMEWORK.setdefault("K", []).append(x)`, `REST_FRAMEWORK.get("K").append(x)`. e4/e5: exit 0 | receivers are followed through item access, `.get()` and `.setdefault()` (creating the key like Python); item `+=` is evaluated; a method call or item store on a computed receiver MintMap does not follow adds a `setting_partially_unknown` gap. e4, e5 (3 forms): exit 12 |
| F6 (medium) | module-level values read by path code were in no fingerprint: `ENABLED = getattr(settings, "X", False)` at import time gating a minting middleware; editing the constant itself. e10, e11: exit 0 | every module-level value (own module, imported, `mod.NAME`) a path's functions read: its statements (with the `if` tests around them) are part of `code` (`global:`), and the settings they read are path dependencies. e10, e11: exit 4 |
| F7 (low) | a hook setting naming code of an uncatalogued package (`ACCOUNT_ADAPTER = "vendorsso.Adapter"`) was treated as known library code. e6 | `hook_target_not_in_catalog` gap on every path the hook row applies to |
| F8 (high) | several settings modules: a differing non-list setting kept the alphabetically first module's value (`local` over `production`): production's adapter and auth classes were dropped; only a global `conflicting_setting` gap. mp5: production adapter mutations exit 0 | differing values of relevant settings across modules (and across `if` branches) are kept: lists united, dicts merged key by key (differing nested scalars too), other values become `Alternatives` (every option is analysed: every hook class bound). mp5: exit 4 |
| F9 (high) | with a `DJANGO_SETTINGS_MODULE` literal only that module was analysed; a production module selected through the environment was ignored with no gap. mp5b: exit 0 | every leaf settings module of the project (candidates plus modules that star-import them, not star-imported themselves) is analysed as an alternative; test settings modules are listed in `settings_module_not_analyzed`; the chosen set is named in `settings_module_ambiguous`. mp5b: exit 4 |
| F10 (high) | the inherited-flow form fix hard-coded `form_class`/`serializer_class` and `clean*`/`validate*`: `LoginView.authentication_form`, `LoginView.as_view(authentication_form=F)` and `confirm_login_allowed` were missed. mp11: exit 0 | any class attribute of a project view inheriting library code, and every `as_view` kwarg, naming project code is "injected code": its methods are fingerprinted and its validation methods (`confirm_login_allowed` added) are checks. mp11/mp11b: all exit 4 |
| F11 (high) | per-request URLconfs (`request.urlconf = "x.urls"`, `PUBLIC_SCHEMA_URLCONF`) were not modelled: their library mints were not inventoried. mp4: exit 0 | such URLconfs are roots; an unreached URLconf is parsed as a root too and its paths carry `urlconf_not_reached_from_root`. mp4: new routes exit 1 |
| F12 (high) | R3 missed common credential shapes with no gap (hashed key in a `digest` field, token stored by a helper parameter, `user.api_token = ...` on an untyped object, `pre_save` receiver, uuid4 `activation_key`, `random.choices` OTP), and an extract-store refactor lost the credential. mp6: 0 of 6 found | see C1 (parameter flow, untyped attribute stores, signal receivers, `random`/`oauthlib` sources, owner-name qualification, per-subject cache keys, `activation`/`confirmation`). mp6: all 7 flag mutations caught; mp2 `i_enroll_extract_store_helper` exit 0 |
| F13 (high) | the model-field default generator was in no fingerprint. mp2/mp2b: weakening it exit 0 | the field declaration and the generator's source (with callees) are part of `code` of every path that creates the model. exit 4 |
| F14 (medium) | dependency versions were never compared with the versions the catalog was read in (dj-rest-auth 2.x reads `REST_AUTH_SERIALIZERS`). mp1b: exit 0 | catalog v3 `verified_package_versions` (dist-info / PKG-INFO `Version:` lines); a specifier that excludes every verified major line is a `dependency_version_not_verified` gap on the package's paths; legacy dj-rest-auth hook rows (`REST_AUTH_SERIALIZERS[LOGIN_SERIALIZER]`, `REST_AUTH_TOKEN_CREATOR`, `REST_AUTH_REGISTER_SERIALIZERS`, read in the 2.2.8 sdist). mp1b: exit 4 |
| F15 (medium) | swapping the admin site class (`admin.site.__class__ = AdminSiteOTPRequired`) was not modelled. mp3: removing it exit 0 | project statements that change the default admin site, and the project code they name, are part of the admin paths' `code`; library code of an undescribed package there is an `admin_site_customised` gap. exit 4 |
| F16 (medium) | a hand-rolled session for a second principal (`request.session["customer_id"] = pk`, read back by a middleware) had no path. mp7: exit 0 | session keys that project code reads back to load a principal (and Django's `_auth_user_id`) make every store of them a heuristic mint (`custom_session_login_candidate`). mp7: exit 12 / 1 |
| F17 (medium) | credential-creating library APIs outside the catalog's mint calls (django-oauth-toolkit `AccessToken.objects.create`, `APIKey.objects.create_key`) were silent. mp9: exit 0 | catalog v3 `library_credential_models` (5 DOT models, cited) are catalog mints; uncatalogued packages: credential-named model creation / `create_*key/token` functions are heuristic mints. mp9: exit 4 |
| F18 (medium) | Channels websocket logins were invisible. mp8 | catalog v3 `library_mint_calls`: `channels.auth.login` (channels 4.3.2 `auth.py:58-110`); `URLRouter` routes are `asgi:` entries; unanalysable routers are `asgi_routing_not_analyzed` gaps. mp8: path `asgi:ws/lobby/` |
| F19 (medium) | a regular-package `apps/` directory put on `sys.path` kept the long module names: `include("users.urls")`, `from users.forms import F` unresolved. mp10: exit 0 | a package below another (strong) source root gets its short name as an alias when project code imports it; URLconf includes and imports are unaliased. mp10: exit 12 |
| F20 (medium) | R3 review noise on Zulip: 294 paths (205 heuristic), a harmless edit gave 97-127 findings, 287 of 294 paths `analysis_complete=false` | a heuristic site reached from 6 or more entry points is one lock entry (`heuristic_site`, see C6); `fingerprint_depth_limit` only clears the new `fingerprint_complete` flag. Zulip: see below |
| F21 (medium) | R3 word lists tuned to the dev set; weak words `code`/`pin` anywhere: coupon / gift-card / room / referral / short-link codes were candidates, real credentials missed | a weak word alone needs a principal link or a credential-named owner (C1); the owner name qualifies; NEGATIVE provenance documented ("Not implemented"). mp6: the 5 non-credential codes set aside, `i_coupon_length_change` exit 0 |
| F22 (low) | `SESSION_COOKIE_AGE`, `SESSION_SERIALIZER`, cookie flags untracked. mp3b: exit 0 | part of `settings:AUTH_CORE`. mp3b: exit 4 |
| L1 (low) | README said `PASSWORD_HASHERS` project classes were part of `settings:AUTH_CORE`; they were in no hash. e9: exit 0 | `PASSWORD_HASHERS` / `SESSION_ENGINE` / `SESSION_SERIALIZER` project classes are sources of `settings:AUTH_CORE`; README corrected. e9: exit 4 |
| L2 (low) | no test for nested / deep inlining or comprehension scope | `InlineCoverageTests`, `ComprehensionScopeTests` |
| L3 (low) | catalog v3 no-mint declarations mirrored the dev set (AccountMiddleware, simplejwt `JWTAuthentication`, knox logout views were permanent gaps); hooks attached per package | declared, read in the source: `allauth.account.middleware.AccountMiddleware`, simplejwt `JWTAuthentication` / `JWTStatelessUserAuthentication`, dj-rest-auth `JWTCookieAuthentication`, DOT `OAuth2Authentication`, knox `LogoutView` / `LogoutAllView`. Not fixed: hooks are still attached per package, not per flow (over-invalidation, documented in "Known limitations") |

Catalog v3 (rebuilt by a catalog build script; still a strict superset of the unchanged v2, sha256
`efbccdde...`) gains `library_mint_calls` (1), `library_credential_models` (5), `verified_package_versions`
(22 dists), 3 legacy dj-rest-auth `library_hook_settings` rows, 1 `library_middleware_no_mint`, 5
`library_drf_auth_no_mint` and 2 `library_views_no_mint` rows; every new row has `added_in: "v3"`,
`review_round: "v5-review"` and a `source_location` (relative to the directory of unpacked
library distributions, or to the pinned-wheel trees).

### Before / after (regression harness: runs `v4`, `v5b`, `v5`)

`v5` was run like v5b (`--library-path` = the pinned wheels + the unpacked library distributions). "init entries" = path entries +
settings-group entries. "incomplete" counts `analysis_complete=false`; `fingerprint_complete=false` (callee closure
truncated by the depth limit, a v5-review flag) is given after the semicolon.

| project | | init entries | should-flag caught (req) | on relevant path (req) | **silent (req)** | harmless false alarms (req) | all: caught / silent / false alarms | unrelated invalidations (all) | scan s | paths (unrouted, incomplete; fingerprint-incomplete) | gaps |
|---|---|---|---|---|---|---|---|---|---|---|---|
| healthchecks | v4 | 24 | 6/6 | 6/6 | **0/6** | 2/3 | 6/6 / 0 / 2/3 | 28 | 0.9 | 24 (12, 11) | 94 |
| | v5b | 32 + 5 | 6/6 | 6/6 | **0/6** | 0/3 | 6/6 / 0 / 0/3 | 4 | 1.5 | 32 (19, 14) | 98 |
| | **v5** | 32 + 6 | 6/6 | 6/6 | **0/6** | **0/3** | 6/6 / 0 / 0/3 | **4** | 1.9 | 32 (19, 12; 2) | 98 |
| paperless-ngx | v4 | 18 | 3/6 | 3/6 | **3/6** | 2/3 | 6/12 / 6 / 2/3 | 46 | 1.8 | 18 (1, 0) | 49 |
| | v5b | 33 + 7 | 6/6 | 6/6 | **0/6** | 0/3 | 12/12 / 0 / 0/3 | 32 | 2.6 | 33 (0, 10) | 55 |
| | **v5** | 33 + 7 | 6/6 | 6/6 | **0/6** | **0/3** | **12/12 / 0** / 0/3 | 32 | 3.5 | 33 (0, 10; 0) | 54 |
| netbox | v4 | 4 | 4/6 | 4/6 | **2/6** | 2/3 | 7/11 / 4 / 2/3 | 9 | 9.4 | 4 (1, 1) | 1119 |
| | v5b | 9 + 9 | 6/6 | 6/6 | **0/6** | 0/3 | 11/11 / 0 / 0/3 | 6 | 13.6 | 9 (1, 4) | 1132 |
| | **v5** | 9 + 9 | 6/6 | 6/6 | **0/6** | **0/3** | **11/11 / 0** / 0/3 | 6 | 17.0 | 9 (1, 4; 1) | 1132 |
| plane | v4 | 7 | 3/6 | 1/6 (+2 gap only) | **3/6** | 2/3 | 7/11 / 4 / 4/6 | 27 | 3.8 | 7 (3, 2) | 173 |
| | v5b | 35 + 7 | 6/6 | 6/6 | **0/6** | 0/3 | 11/11 / 0 / 0/6 | 6 | 6.1 | 35 (1, 19) | 87 |
| | **v5** | 35 + 7 | 6/6 | 6/6 | **0/6** | **0/3** | 11/11 / 0 / **0/6** | 6 | 7.1 | 35 (1, 19; 16) | 99 |
| **held-out three** | v4 | | 10/18 | 8/18 | **8/18** | 6/9 | | | | | |
| | v5b | | 18/18 | 18/18 | **0/18** | 0/9 | | | | | |
| | **v5** | | **18/18** | **18/18** | **0/18** | **0/9** | | | | | |

All 59 mutation and follow-up exit codes of `v5` equal those of `v5b` (plane follow-ups 12, 4, 4, 12; every step-1
diff 0); every unmodified diff exits 0. Recall per S/T/P unit is unchanged from v5b:

| class | v4 exact / mint-only / gap / **silent** | v5b | **v5** |
|---|---|---|---|
| S (41) | 13 / 21 / 1 / **6** | 38 / 0 / 3 / **0** | 38 / 0 / 3 / **0** |
| T (12) | 3 / 1 / 3 / **5** | 9 / 1 / 1 / **1** | 9 / 1 / 1 / **1** |
| P (11) | 2 / 1 / 2 / **6** | 6 / 0 / 4 / **1** | 6 / 0 / 4 / **1** |
| total (64) | 18 / 23 / 6 / **17** | 53 / 1 / 8 / **2** | **53 / 1 / 8 / 2** |

Still silent (unchanged since v5b, documented there): netbox L02 (`set_password` with a client-chosen password, not a
generated credential) and P01 (the OAuth `state` written inside `social_django.views.auth`, library code).

Dev-project deltas v5b -> v5 (base scans): Healthchecks `settings:AUTH_CORE` is a new settings entry (its
`PASSWORD_HASHERS` moved there), 2 paths are now `analysis_complete=true` with only `fingerprint_complete=false`;
paperless-ngx loses the `middleware_not_in_catalog` gap for `allauth.account.middleware.AccountMiddleware` (declared
in catalog v3); plane's `plane.settings.local` is now analysed as an alternative of `production` (12 new global gaps:
`settings_module_ambiguous`, `settings_module_not_analyzed` for `plane.settings.test`, three `conflicting_setting` and
three `conditional_setting` from its `if DEBUG:` block, `middleware_not_in_catalog` for the debug toolbar, and three
`library_view_not_in_catalog` for drf-spectacular views of the previously unreached `plane.api.urls.schema`, which is
now parsed). The R3 candidates of the four harness projects are unchanged (Healthchecks 4, paperless-ngx 0, netbox 2,
plane 4 + 2 defaults); Zulip has 11 + 3 defaults (v5b 10 + 3: the new one, a registration-transfer endpoint that gives
a remote server a new `api_key` on an object MintMap cannot type, is a credential). More is set aside, with a reason
(weak words without a principal link, objects of unknown type). Scan time grew by 20-35 % (module-level values,
injected code, plane's second settings module).

**Reviewer fixtures, before (part B) -> after.** Soundness experiments (`e1..e11`,
mutated diff exit codes): e1 0 -> 4, e2 0 -> 4, e3 0 -> 12, e4 0 -> 12, e5 (item `+=`, `setdefault().append`,
`get().append`) 0 -> 12, starred rebuild 44 -> 44, e6 no gap -> `hook_target_not_in_catalog` on the 17 allauth paths,
e7 0 -> 1, e8 4 -> 4, e9 0 -> 4, e10 0 -> 4, e11 0 -> 4. Generalization projects (the reviewers' mutation runner,
with and without `--library-path`, identical): 79 of the 81 applicable mutations behave as the reviewers expected
(every "flag" mutation exits non-zero, every "quiet" one 0, including mp2 `i_enroll_extract_store_helper` and mp6
`i_coupon_length_change`); the 2 others are `mp5`/`mp5b d_local_adapter_change` (a change to the development
settings module's adapter) which exit 4: MintMap cannot know that `local` is not deployed (see "Not implemented").
Two mp1 mutations do not apply to `mp1b` (their edit target is absent).

**Review noise on Zulip** (the reviewers' noise script; base = a copy of the Zulip checkout): the lock has 121 path entries instead of 294; 7 `heuristic_site` entries stand for the 181 entry/site pairs of 7 shared heuristic sites (confirmation keys: 84 entry points; user creation: 15-19; realm creation: 15; Redis-stored login tokens: 18). z1 (one more name in a skip list of `bulk_create_users`) 127 -> 33 findings, z2 (a log message in `send_email`) 97 -> 15, none of them on more than one entry per heuristic site. 91 of 121 paths are `analysis_complete=false` (v5b: 287 of 294) and 105 `fingerprint_complete=false`; the remaining incompleteness is `unrecognized_check_call`, `unresolved_call_on_path`, `view_dispatcher_not_analyzed` and incomplete library includes. Scan about 32 s (v5b about 27 s), 984 gaps, 10 settings groups.

**Smoke runs** (every unpacked library tree, `scan` with defaults): all 23 trees exit 0 (Django
904 files about 14.8 s, django-allauth 838 files about 5.5 s, every other tree under 1.3 s; the new trees `channels`
and `dj_rest_auth_legacy` included).

## What changed in v5 (part B: R3, R5, R7, R8)

Part B addresses the remaining root causes of the round-2 evaluation report (summarised in [EVALUATION.md](EVALUATION.md)). Same development set and rules as part
A (see "Development constraints"); every rule is general and has synthetic fixture tests in `tests/test_v5b.py`
(31 tests; 23 of them fail on frozen the frozen v4 copy, the other 8 are controls: changes that must stay
detected, such as swapping two variables or a helper that the inliner must not inline).

| # | defect (v4 / v5a) | v5 part B change | tests (`test_v5b.py`) |
|---|---|---|---|
| R3 | project credentials made without a catalog API were invisible: netbox's own `Token.save()` (secret from `secrets.choice`), plane's `APIToken` (`token = CharField(default=generate_token)`), plane's 6-digit magic code (`secrets.randbelow`, stored in Redis). netbox `c_helper_accepts_all`, `a2_new_token_route`, `f2_legit_api_token_rotation` passed CI (exit 0) | new `credentials.py` (see C1 "Heuristic custom credential mints"): values of randomness sources kept as credentials (model attribute, model creation field, cache / session store, credential-named call, return of a credential-named function) and model fields whose `default=` is a generator; mint paths with `mint.kind = heuristic_custom_credential` and a `custom_*_candidate` purpose. Reach: creating a project model runs its project `save()` (`M.objects.create(...)`, `serializer.save()` without a project `create()`, `super().create()` in a `ModelSerializer`); a DRF view whose `create`/`update` is library code runs its serializer's `save`/`create`/`update`; `perform_create(serializer)` is typed from `serializer_class`; an unannotated method parameter is typed when every `self.m(...)` call in the class passes the same project class (a view's `post` passing its serializer to `self.perform_create(serializer)`); a library-only DRF create flow of a model with a credential default is a library-provided heuristic mint. General filters (measured below) | `CustomCredentialTests` (5) |
| R5 | project code that a library calls because a setting names it was not fingerprinted: making paperless's `ACCOUNT_ADAPTER.pre_authenticate` accept everything gave exit 0 | catalog v3 section `library_hook_settings` (25 rows, each read where the library imports the dotted path): allauth `ACCOUNT_ADAPTER`, `SOCIALACCOUNT_ADAPTER`, `MFA_ADAPTER`, `HEADLESS_ADAPTER`, `HEADLESS_TOKEN_STRATEGY`, `ACCOUNT_FORMS`, `SOCIALACCOUNT_FORMS`, `MFA_FORMS`, `ACCOUNT_SIGNUP_FORM_CLASS`; DRF `DEFAULT_AUTHENTICATION_CLASSES` / `DEFAULT_PERMISSION_CLASSES`; simplejwt serializers and `USER_AUTHENTICATION_RULE`; dj-rest-auth `LOGIN_SERIALIZER`, `TOKEN_CREATOR`, `JWT_TOKEN_CLAIMS_SERIALIZER`, `REGISTER_SERIALIZER`; djoser `SERIALIZERS` / `PERMISSIONS`; `SOCIAL_AUTH_PIPELINE`; `HIJACK_PERMISSION_CHECK`; `OAUTH2_PROVIDER["OAUTH2_VALIDATOR_CLASS"]`; `AUTHENTICATION_BACKENDS` for library login flows. A setting that names project code binds it: the class (with its project bases) or function and its callees (depth-limited, context-sensitive) are the new **`hooks` fingerprint component** of every path of the packages the row applies to (library flows; project calls of the package's mint API only where the row says `project_calls`, e.g. the allauth adapters; project DRF views that take the class from `REST_FRAMEWORK`), and are listed in `evidence.hooks` with a context note. The hook methods are also functions of the library-provided entries of that package, so a mint inside a hook (a project token strategy) is linked to the library routes (paperless PNG-15 is now `exact`). A hook setting MintMap cannot evaluate is a `hook_setting_not_static` gap on those paths | `HookTests` (5) |
| R7 | one auth-setting change invalidated every path (unrelated invalidations: paperless 110, plane 89 in v5a); a setting read by project code at run time was not fingerprinted (netbox `d_remote_auth_enabled_by_default` exit 0) | global auth settings are **one lock entry per settings group** (`settings:MIDDLEWARE`, `settings:AUTHENTICATION_BACKENDS`, `settings:REST_FRAMEWORK` with its authentication keys only, `settings:AUTH_CORE`, `settings:INSTALLED_APPS(auth)`, `settings:package:<pkg>`), reviewed once; a change is one finding naming the changed settings (see "`diff` findings"). The path `settings` component keeps only what the path depends on specifically: `authenticate()` -> the backends group (list + project backend source); DRF defaults used by the view; every `settings.X` read by project code on the path (now recorded for every upper-case setting, with its deciding conditions and the assignments its statements read); catalog v3 `mint_setting_dependencies` (10 rows: e.g. `ACCOUNT_LOGIN_ON_PASSWORD_RESET` for `perform_password_reset_login`, `PASSWORD_RESET_TIMEOUT`, `HIJACK_PERMISSION_CHECK`); the conditions that put a middleware into `MIDDLEWARE`. New mint paths created by settings (middleware, backends) are still `new_path` | `SettingsGroupTests` (9) |
| R8 | harmless renames / extract-function refactors raised false alarms 6 of 9 times (held-out three) and 2 of 3 on Healthchecks | `fingerprint.normalize` alpha-renames function-local variables (scoping followed; parameters, attributes, keyword names, globals and imports kept; functions calling `locals()`/`eval()`/`exec()` are not renamed); gap keys that quote a call use the canonical names (`Gap.key_detail`), so `auth_form['username'].value` is not a new gap. `refactor.py` inlines extracted same-module helpers into the caller's dump under strict conditions (module docstring of `refactor.py`): plain-name or constant arguments, straight-line helper (`S1..Sn; return E` or no return), statements hoisted only where the call is the first thing a statement evaluates, no capture of caller locals; `bool(x)` in a truth test is `x`. A helper reached only through inlined calls is not hashed separately (its body is in the caller's dump), so a later change of the helper still changes the caller. **(v5 review)** That claim was wrong for nested helpers (see "review round", F1/F2): coverage is now decided from the bodies actually present in hashed dumps, and comprehension variables are their own scope (F3) | `AlphaRenamingTests` (5), `ExtractFunctionTests` (7) |
| also | library flows inherited by a project class did not fingerprint the callees of the class's overriding methods | the callee closure of such paths starts from every project method of the class's MRO | (covered by `HookTests`, `FingerprintReachTests`) |

Catalog v3 (`django_catalog_v3.json`, rebuilt by a catalog build script, still a strict superset
of the unchanged v2, sha256 `efbccdde...`) gains `mint_setting_dependencies` (10 rows) and `library_hook_settings`
(25 rows); every row has `added_in: "v3"` and a `source_location` in the unpacked library sources.

### R3: false-alarm cost on the five development projects (every candidate judged by reading its code)

Candidate sites = randomness calls reported as mints + models with a credential field default (scan with defaults).

| project | candidate sites | judged credential | judged not a credential | set aside by the general rules | heuristic mint paths (unrouted) |
|---|---|---|---|---|---|
| Healthchecks | 4 | 4: sudo-mode code, login / transfer / email-change token, API keys, ping key | 0 | 14 (OAuth `state` x6, `UUIDField` identifiers x6, uuid4 `code`/`badge_key`, WebAuthn user handle) | 7 (7) |
| Zulip | 13 (10 + 3 defaults) | 8: confirmation keys, missed-message email token, Redis-stored login tokens, server-transfer challenge, `generate_api_key`, defaults `UserProfile.api_key`, `ChannelEmailAddress.email_token`, `Realm.uuid_owner_secret` | 5: four deployment-secret generators in `scripts/setup/generate_secrets.py`, one dev-data management command | 7 (a cache-key prefix, a dev file path, 2 `UUIDField` identifiers, 2 migrations, 1 generator reported at its model's creation sites) | 205 (17) |
| paperless-ngx | 0 | 0 | 0 | 1 (cache generation key) | 0 |
| netbox | 2 | 1: API `Token` secret (`Token.generate`, reached from `tokens/provision/` and `TokenViewSet`) | 1: `SECRET_KEY` generator of the CLI | 2 (job id, primary key) | 3 (1) |
| plane | 6 (4 + 2 defaults) | 5: email-change verification code, magic sign-in code, custom session key generator, `APIToken.token`, export download token | 1: `User.token` (credential-shaped, no consumer found) | 42 (asset/file keys x12, OAuth `state` x8, primary keys x5, generators reported at creation sites x4, random unusable passwords x3, labels / usernames / anchors / names / ids x8, a `UUIDField`, the outbound `Webhook.secret_key`) | 8 (1) |
| **total** | **25** | **18** | **7** | **66** | **223** |

General rules (no project names): a credential word must name the place the value is kept (strong words `token`,
`secret`, `password`, `otp`, `invite`, `reset`, `verification`, ... anywhere; weak words `key`, `code`, `pin`, `session`
only in the name of the field / attribute / cache key, or next to a qualifier: `session_key`, `api_key`,
`login_code`); a non-credential word there vetoes unless the head noun is a strong word (`uuid_owner_secret` is kept,
`cache_key`, `job_id`, `filename`, OAuth `state`, `asset`, `label` are not); `uuid4` values need a strong word; a
`UUIDField` default without a strong word is an identifier; a primary key is not a credential; an owner named
`webhook`/`hook`/`callback`/`outbound`/`integration` marks an outbound secret; a random password that only
`set_password`/`make_password` ever receive disables login; an update `save()` (serializer built on an instance), an
unsaved instance and code in `migrations/` are not creations. The Zulip path count (89 -> 294) is the cost of
"every reachable creation of a model with a credential default is a candidate": 84 paths reach the confirmation-key
generator, 55 create a `UserProfile` (its `api_key` default) and 30 create a `Realm` (`uuid_owner_secret`). Remaining false alarms are server-configuration
secret generators, which no name rule separates from user credentials.

### Before / after (regression harness: runs `v4`, `v5a`, `v5b`)

v5b was run like v5a (`--library-path` = the pinned wheels + the unpacked library distributions); run `v5b-nolib` is the
same run with CLI defaults (see below). "init entries" counts path entries; v5b locks also hold the settings group
entries (hc 5, paperless 7, netbox 9, plane 7). The harness accepts settings entries like paths.

| project | | init entries | should-flag caught (req) | on relevant path (req) | **silent (req)** | harmless false alarms (req) | all: caught / silent / false alarms | unrelated invalidations (all) | scan s | paths (unrouted, incomplete) | gaps |
|---|---|---|---|---|---|---|---|---|---|---|---|
| healthchecks | v4 | 24 | 6/6 | 6/6 | **0/6** | 2/3 | 6/6 / 0 / 2/3 | 28 | 0.9 | 24 (12, 11) | 94 |
| | v5a | 25 | 6/6 | 6/6 | **0/6** | 2/3 | 6/6 / 0 / 2/3 | 29 | 1.2 | 25 (12, 14) | 95 |
| | v5b | 32 | 6/6 | 6/6 | **0/6** | **0/3** | 6/6 / 0 / 0/3 | **4** | 1.5 | 32 (19, 14) | 98 |
| paperless-ngx | v4 | 18 | 3/6 | 3/6 | **3/6** | 2/3 | 6/12 / 6 / 2/3 | 46 | 1.8 | 18 (1, 0) | 49 |
| | v5a | 25 | 6/6 | 6/6 | **0/6** | 2/3 | 11/12 / 1 / 2/3 | 110 | 2.3 | 25 (1, 9) | 55 |
| | v5b | 33 | 6/6 | 6/6 | **0/6** | **0/3** | **12/12 / 0** / 0/3 | **32** | 2.6 | 33 (0, 10) | 55 |
| netbox | v4 | 4 | 4/6 | 4/6 | **2/6** | 2/3 | 7/11 / 4 / 2/3 | 9 | 9.4 | 4 (1, 1) | 1119 |
| | v5a | 6 | 4/6 | 4/6 | **2/6** | 2/3 | 7/11 / 4 / 2/3 | 12 | 10.1 | 6 (0, 2) | 1126 |
| | v5b | 9 | **6/6** | **6/6** | **0/6** | **0/3** | **11/11 / 0** / 0/3 | **6** | 13.6 | 9 (1, 4) | 1132 |
| plane | v4 | 7 | 3/6 | 1/6 (+2 gap only) | **3/6** | 2/3 | 7/11 / 4 / 4/6 | 27 | 3.8 | 7 (3, 2) | 173 |
| | v5a | 27 | 6/6 | 6/6 | **0/6** | 2/3 | 11/11 / 0 / 4/6 | 89 | 5.0 | 27 (0, 16) | 83 |
| | v5b | 35 | 6/6 | 6/6 | **0/6** | **0/3** | 11/11 / 0 / **0/6** | **6** | 6.1 | 35 (1, 19) | 87 |
| **held-out three** | v4 | | 10/18 | 8/18 | **8/18** | 6/9 | | | | | |
| | v5a | | 16/18 | 16/18 | **2/18** | 6/9 | | | | | |
| | v5b | | **18/18** | **18/18** | **0/18** | **0/9** | | | | | |

**Without `--library-path`** (run `v5b-nolib`): all 59 mutation / follow-up exit codes, init entries,
path and gap counts and the recall table are identical to v5b.

plane second-order follow-ups: v4 0/4 caught (step 2), v5a 4/4, v5b 4/4 (12, 4, 4, 12; every step-1 diff after
`update` + accept exits 0, so `update` carries the settings-group reviews correctly).

Recall per S/T/P unit (automatic scorer):

| class | v4 exact / mint-only / gap / **silent** | v5a | **v5b** |
|---|---|---|---|
| S (41) | 13 / 21 / 1 / **6** | 38 / 0 / 3 / **0** | 38 / 0 / 3 / **0** |
| T (12) | 3 / 1 / 3 / **5** | 4 / 1 / 3 / **4** | 9 / 1 / 1 / **1** |
| P (11) | 2 / 1 / 2 / **6** | 4 / 0 / 4 / **3** | 6 / 0 / 4 / **1** |
| total (64) | 18 / 23 / 6 / **17** | 46 / 1 / 10 / **7** | **53 / 1 / 8 / 2** |

T/P changes: netbox K01 (`tokens/provision/`) and K02 (`TokenViewSet`) silent -> exact, K04 gap -> exact (through
`TokenViewSet`), K03 gap -> mint-only (the `Token` secret site is found; the netbox generic edit view that saves the
form is behind a `class_decorator_not_analyzed` gap); plane C01 (`APIToken.objects.create`, R3 default) and C03/C04
(magic code) silent -> exact; paperless PNG-15 (project `HEADLESS_TOKEN_STRATEGY` minting a DRF token) mint-only ->
exact (R5 hook entry functions). Still silent: netbox L02 (`UserViewSet` sets a password the client chose through the
serializer: `set_password` is not a catalog mint and the value is not generated) and P01 (the OAuth `state` written
inside `social_django.views.auth`, library code with no catalog mint).

**Every mutation that v4 left silent, after part B** (exit code v4 -> v5a -> v5b, and why):
* paperless `b_ignored_mfa_result`, `c_helper_accepts_all`, `e_mfa_pending_gets_token` (0 -> 4 -> 4): R6 + the
  inherited-library-flow serializer hole, fixed in part A; part B keeps them.
* paperless `c2_pre_authenticate_accepts_all` (0 -> 0 -> **4**): R5. `ACCOUNT_ADAPTER` binds the project adapter; its
  code is the `hooks` component of the 15 allauth library-flow paths (the harness counts 10 of them as unrelated
  because their route names differ, but each runs the adapter).
* paperless `d2_auto_login_default_user` (0 -> 4 -> 4): now on the auto-login middleware path itself (it reads
  `settings.AUTO_LOGIN_USERNAME`, and the condition that inserts it into `MIDDLEWARE` is an item dependency) plus the
  `settings:MIDDLEWARE` group, instead of every path.
* paperless `d3_remote_user_on_by_default` (0 -> 4 -> 4): the env-var default decides whether the remote-user
  middleware is in `MIDDLEWARE`: item dependency of that middleware's path + the MIDDLEWARE and backends groups.
* netbox `a2_new_token_route` (0 -> 0 -> **1**), `c_helper_accepts_all` (0 -> 0 -> **12**),
  `f2_legit_api_token_rotation` (0 -> 0 -> **12**): R3. The token secret generated in `Token.save()` is a heuristic
  mint reached from `tokens/provision/` (through `perform_create(serializer)` typed from the caller) and from
  `TokenViewSet` (library create flow -> serializer `create` -> `super().create()` -> `Token.save()`): the new route is
  a `new_path`, the serializer check change is `checks` + `evidence_downgraded`, the new `rotate` action is part of
  the viewset entry (`fingerprint_changed` + `evidence_downgraded`, not a new path id).
* netbox `d_remote_auth_enabled_by_default` (0 -> 0 -> **4**): R7. The project remote-user middleware reads
  `settings.REMOTE_AUTH_ENABLED`; that setting is now a dependency of its paths.
* plane `b_ignored_password_check`, `c_helper_accepts_all` (0 -> 4 -> 4), `f_legit_reset_autologin` (0 -> 1 -> 1),
  `b2_admin_password_check_not_enforced` (0 -> 12 -> 12) and the follow-ups `a_` (0 -> 12 -> 12), `a2_` (0 -> 4 -> 4),
  `e_` (0 -> 4 -> 4): R1 (namespace packages), fixed in part A; unchanged.

The harmless refactors: `h_rename_local` (hc, paperless, netbox, plane) and plane `h2_rename_local_user_login` are
alpha-renaming cases (netbox's also changed a gap key, now canonical); `i_extract_function` (hc: single-return
helper; paperless and netbox: statement helpers; plane: a helper whose value is tested with `if not h():` and returns
`bool(...)`) are inlined; plane `d4_control_schema_setting` (a non-authentication `REST_FRAMEWORK` key) is outside the
REST_FRAMEWORK group. All give exit 0; `g_formatting_only` and `z0_unmodified_copy` stay 0.

**Development projects (scan with defaults).** Zulip: 1084 routes / 1051 entries; 294 paths (17 unrouted): the 87
paths of v5a plus 2 linked through the social-auth pipeline hook (R5) and 205 heuristic custom-credential paths
(R3, table above); 982 gaps (621 in v5a: +361 `fingerprint_depth_limit` notes, one per new path whose callee closure
is truncated, and 2 for hook code); 10 settings groups; scan about 27 s (v5a about 15.5 s; most of the increase is
the evidence of the new paths). Healthchecks: 32 paths (7 new heuristic paths, all unrouted because the views call
`profile.send_*` on an untyped object), 98 gaps, mutation exit codes a 1, b 12, c 12, d 5, e 5, f 1, g 0, **h 0, i 0**.

### v5 limits (part B)
* R3 is a heuristic. It sees values from the listed sources only (not `random`, `hashlib` of a timestamp, a library
  token generator other than catalog ones), through local variables and project return values only (not attributes,
  containers, parameters or other requests), and it decides by names. (**v5 review:** `random.*` over characters and
  oauthlib generators are sources, parameters of storing helpers are followed, and weak words need a principal
  link; see "review round" F12/F21.) It cannot tell a server-configuration secret
  from a user credential (5 of the 7 judged false candidates). Every reachable creation of a model with a credential
  default is a path, which can make the lock large (Zulip +205 entries); the candidates and everything set aside are
  listed in `coverage.custom_credentials` so the decisions can be reviewed.
* R5 binds hooks only where a catalog row declares the setting; a project class reached through other library
  lookups (`get_user_model()` managers, signals, `AppConfig.ready`) is not a hook. A hook class is fingerprinted as a
  whole on every path of its package (no method-to-flow mapping): a change to any adapter method re-opens every flow
  of that package. `PASSWORD_HASHERS` and `SESSION_ENGINE` project classes are not hooks. (Part B said they were "part
  of the `settings:AUTH_CORE` group value"; that was inaccurate: `PASSWORD_HASHERS` was in `settings:package:django`
  and no project hasher source was hashed anywhere. **(v5 review)** Both settings, `SESSION_SERIALIZER` and the
  session cookie / lifetime settings are now in `settings:AUTH_CORE`, and the source of the project classes they
  name is a source of that group.)
* R7: a path depends on a setting only through the rules listed above; a setting read inside library code is a
  dependency only where catalog v3 `mint_setting_dependencies` lists it; anything else (e.g. `ACCOUNT_EMAIL_REQUIRED`)
  changes only its settings group entry.
* R8: see "Not implemented" for the extract-function shapes that are not normalised.

## What changed in v5 (part A: regression harness, held-out root causes R1, R2, R4, R6)

Frozen v4 was evaluated on held-out projects (the round-2 evaluation report (summarised in [EVALUATION.md](EVALUATION.md))). Only 13 of 41 full-session
paths were linked exactly, 17 of 64 S/T/P units were missed with no visible gap, 8 of 18 should-flag code
changes passed CI with exit 0, and harmless refactors raised false alarms 6 of 9 times. v5 part A fixes the
"never silent" and project-model causes R1, R2, R4 and R6 of that report. paperless-ngx, netbox and plane were
used to develop these fixes, so **they are no longer held-out**; the numbers below are development-set numbers.
Every fix is general (no project-specific names) and has synthetic fixture tests in `tests/test_v5.py`.

### A0: regression harness (`run_all.py`)

`python3 -I run_all.py <prototype dir> --label <label> [--tool-arg=--library-path=...]` (in the private evaluation workspace)
replays every saved mutation against a prototype: Healthchecks (the saved mutation diffs on a fresh copy of
the Healthchecks checkout without `.git`) and paperless-ngx, netbox, plane (the round-2 base copies
+ saved mutation diffs; labels `should_be_flagged`, category and required/extra from the round-2 mutation records),
plus plane's four second-order follow-ups (first mutation, `update`, accept, then the follow-up edit). Per
project it copies the base, runs a timed `scan`, `init`, accepts every entry, checks that the unmodified `diff`
exits 0, then applies each diff (GNU `patch --fuzz=0`, per file) to a fresh copy and runs `diff`. It records exit
code, bits, finding counts, whether a finding concerns the **relevant path** (a path-level finding on a path whose
entry/mint/chain/fingerprinted functions contain one of the mutation's tokens; tokens are listed in `run_all.py`)
or only a relevant gap (for a settings-group finding, part B, its message is matched), unrelated invalidations,
scan time, init entries, path statuses and gap counts. (Part B: the harness also accepts the `settings` group entries
of a lock and records `init_settings_entries`; older locks have none, so earlier labels are unaffected.) It also
scores **recall** per S/T/P unit with hand-derived unit specs (`units.json`, written by
`build_units.py` from the manual inventories and the v4 adjudication): `exact` (a non-shadowed routed path with the
unit's entry and mint), `mint_only` (a project-code mint site found but not linked to this entry), `gap` (a gap key
names the unit's view/route/include) or `silent`. Output: `<label>/summary.json` and `summary.md`.

**v4 baseline check** (run `v4`): all 59 mutation and follow-up exit codes reproduce the codes in the
eval files (no mismatch), the unmodified diffs exit 0, and the automatic unit scorer agrees with all 64 adjudicated
v4 unit verdicts (paperless 24/24, netbox 15/15, plane 25/25), reproducing RESULTS.md's recall table (S exact 13,
silent 6; T exact 3, gap 3, silent 5; P exact 2, silent 6). RESULTS.md's "caught on the relevant path" column counts path-specific detections only (paperless 2/6); the harness counts any finding on the relevant path, which includes paperless `d_drf_basic_auth_swap` (a `settings` fingerprint change on every path), giving 3/6; netbox 4/6 and plane 1/6 (+2 relevant gap only) match.

### Fixes

| # | v4 defect (held-out evidence) | v5 change | tests (`test_v5.py`) |
|---|---|---|---|
| R1 | PEP 420 namespace packages: module names climbed only through directories with `__init__.py`, so `plane/authentication/utils/login.py` was `login`; imports of it never resolved and all 20 plane session paths were one `unrouted` path; 111 project views were typed as library views | `project.py` first computes **source roots** (sys.path-like): the project directory, every directory holding `manage.py`, and every directory from which an absolute import (`from a.b.c import x`) or a dotted string in `manage.py`/`wsgi.py`/`asgi.py`/`urls.py`/`apps.py`/`settings*.py` (`DJANGO_SETTINGS_MODULE`, `ROOT_URLCONF`, `INSTALLED_APPS`, `include("x.urls")`) resolves to a file or directory of the tree; only roots that are ancestors of the importing file count, and single-component imports are not evidence. A file in a regular package keeps its v4 name when the directory the name is relative to is a root. Otherwise (namespace directory, or a package below one) the name is relative to the nearest root; if several roots give different names, the one project code imports wins (the others become aliases that imports are rewritten to); if none is imported and two non-default roots disagree, the nearest root wins and a `module_name_ambiguous` gap names every candidate. The roots are not reported as values, only through names and gaps | `NamespacePackageTests` (5) |
| R2a | library route targets in a **catalogued** package whose symbol is not mapped were treated as "covered, no mint" (`analysis.py` dropped the gap for `CATALOG_PACKAGES`): allauth module-level aliases (`authenticate = AuthenticateView.as_view()`, `password_reset`, social `signup`) produced no path and no gap | the suppression is removed everywhere (views, includes, middleware, DRF authentication classes, library views run from project code with `Cls.as_view()(request)`). A library view is resolved through catalog v3 alias rows (`library_view_aliases`, each citing the alias line) and, with `--library-path`, through the library source itself (`libsource.py`: module-level `x = Cls.as_view(**kw)` aliases with their keyword arguments, re-exports, star imports; a library subclass of a catalog view counts as that view when it overrides none of its mint methods). It is then a catalog view (paths), declared non-minting (catalog v3 `library_views_no_mint`, `library_classes_no_mint`, verified rows and prefixes such as `django.views.generic.*`, `rest_framework.generics.*`), or a `library_view_not_in_catalog` gap that says "catalogued package; symbol not mapped" and the resolution trail | `LibraryViewTests` (7) |
| R2b | `allauth.headless.urls` mapped to a fixed list of 5 mints and was treated as complete: headless signup, provider token, MFA-pending state, reauthentication, password change were silent | catalog v3 section `library_includes_complete` declares an include's mint list complete only where its URLconf was read route by route (`rest_framework.urls`, `knox.urls`, `hijack.urls`, `djoser.urls.jwt`, `djoser.urls.authtoken`). Every other mapped include adds a `library_include_mints_incomplete` gap to **each path** of that include (paths become `analysis_complete=false`); an unmapped include is `library_include_not_in_catalog`, also for catalogued packages | `LibraryIncludeTests` (3) |
| R2c | library admin registrations under `admin.site.urls` (DRF `TokenAdmin`: any staff user can mint a token for any user) were invisible; the admin site's own `password_change/` (`update_session_auth_hash`) was not listed | catalog v3 `library_admin_registrations` (per app, read in the app's `admin.py`; `rest_framework.authtoken` -> `TokenAdmin` -> `Token.save / generate_key`; `django.contrib.*` apps and others that register no credential model) and `library_admin_site_extra_mints` (`AdminSite.password_change` -> `PasswordChangeView.form_valid`, sites.py:279-282, 351-367). For each library app in `INSTALLED_APPS` the declared mints become paths of the `admin.site.urls` entry; the apps the catalog does not declare (and unknown `INSTALLED_APPS` items) are listed in **one** `library_admin_not_in_catalog` gap attached to the admin paths (with `--library-path`, an app without an `admin` module is not listed). Project `admin.site.register(Model, ...)` / `@admin.register(Model)` of a model whose `save` is a catalog mint (a DRF `Token` or a project subclass) is a mint path too | `AdminRegistrationTests` (4) |
| R2d | audit of other silent drops | (1) middleware and DRF authentication classes of catalogued packages: declared non-minting (catalog v3 `library_middleware_no_mint`, `library_drf_auth_no_mint`, each read in source) or a gap; a library middleware that subclasses a catalog middleware (found in the library source) gets that middleware's mint plus a gap; knox `TokenAuthentication` in `DEFAULT_AUTHENTICATION_CLASSES` is now a mint path (`renew_token`, catalog v2 entry that v4 never used). (2) project views / middleware / DRF auth classes inheriting a library class the catalog does not account for: `library_base_not_in_catalog` (path gap). (3) library or unresolved view decorators (other than `django.views.decorators.*`, `django.contrib.auth.decorators.*`, `django.utils.decorators.*`, `django.db.transaction.*`, the catalog gates and mint decorators) were ignored: `view_decorator_not_in_catalog` (path gap); a decorator factory `cache_page(60)(view)` is named by its factory. (4) a resolved call into a catalogued package whose leaf is a catalog mint name but whose symbol is not mapped: resolved through the library source when it is a re-export of a catalog mint (then a mint), otherwise `library_call_may_mint`. (5) DRF `router.register` inside a module-level loop or function: `unsupported_url_construct` (was ignored). (6) settings statements that were ignored (`while`, `match`, tuple unpacking, a relevant setting passed to an unknown call) are evaluated or give a gap (R4). (7) the gaps about an entry itself (unresolved bases, library bases, decorators, incomplete includes, admin registrations) are now attached to every path of the entry, so `analysis_complete` reflects them | `MiddlewareAuthClassTests` (3), `LibraryCallAndBaseTests` (3) |
| R4 | settings changed inside functions (`def _parse_remote_user_settings(): global MIDDLEWARE; MIDDLEWARE.append(...)`, called at module level) were not evaluated; `MIDDLEWARE.extend(plugin_list)` made the whole setting unknown, so netbox's own remote-user middleware was unrouted | `settings_extract.py`: a module-level function called at module level (statement, assignment value, nested) is evaluated with Python scoping (names declared `global` and lists/dicts changed in place act on the module namespace; locals are dropped; parameters are unknown values; at most 4 nested calls); conditions inside are not decided (both branches, `conditional_setting`). `X.extend(<unknown>)`, `X += <unknown>`, `X + <unknown>`, `X.update(<unknown>)` and unknown methods keep the known items and add a `PartialUnknown` marker plus a `setting_partially_unknown` gap; nested receivers (`REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"].insert(0, ...)`) are followed; `if`/`match` merge dicts key by key (list union). A function that changes auth settings but is not called at module level in a way MintMap follows is a `settings_function_not_evaluated` gap. The condition that decides an auth setting, and the last assignment of each name it reads, are added to that setting's statements, so changing `os.getenv("AUTO_LOGIN_USERNAME", "")` to `"admin"` changes the `settings` fingerprint | `SettingsFunctionTests` (8) |
| R6 | PEP 585 / typing subscripted bases (`GenericAPIView[Any]`, `Generic[T]`, `Base[int]`) resolved to nothing, so the DRF permission gate (and anything inherited) was lost without a gap (>= 20 paperless classes) | bases are resolved after removing the subscript; a base that still cannot be resolved (a call, an unknown name) is recorded on the class and becomes a `class_base_unresolved` gap on every path whose entry class, slice classes or form/serializer classes have it in their MRO | `SubscriptedBaseTests` (2) |
| also | two fingerprint holes that left held-out mutations silent once R1/R6 made the paths visible | (a) a project subclass of a catalog library view (inherited library flow) contributes the `clean*`/`validate*` methods of its `serializer_class`/`form_class` to the path (`evidence.validation_methods`, `checks` fingerprint, unrecognized-check gaps); (b) the callee closure of the fingerprint is context-sensitive: `self.m()` inside an inherited base-class method resolves against the receiver class, so a subclass override (template-method pattern) is fingerprinted | `FingerprintReachTests` (2) |

Catalog v3 (`django_catalog_v3.json`, built by a catalog build script from the unchanged v2):
every v2 key is kept verbatim (checked by the builder); new sections `library_includes_complete` (5),
`library_views_no_mint` (23 rows, 6 of them prefixes), `library_classes_no_mint` (2), `library_view_aliases` (7),
`library_middleware_no_mint` (11), `library_drf_auth_no_mint` (4), `library_admin_registrations` (12 apps),
`library_admin_site_extra_mints` (1) and `library_view_flows` (4: allauth `PasswordChangeView`/`PasswordSetView`
-> `logout_on_password_change`, socialaccount `SignupView` -> `complete_signup`, knox `TokenAuthentication` ->
`renew_token`, mapped to existing catalog mint entries). Every row has `added_in: "v3"` and a `source_location`
relative to the directory of unpacked library distributions, read in the unpacked wheel; nothing was installed or imported.
Catalog entries not mapped to symbols: 24 (v2: 25; knox `renew_token` is now used). The v2 and v1 catalogs still load and are never silent either: on paperless-ngx v5 finds 19 paths and 18 `library_view_not_in_catalog` gaps with the v2 catalog (the aliases and template views it cannot classify), and 25 paths with 2 such gaps (`drf_spectacular`) with v3.

### Before / after (regression harness, run `v4` vs run `v5a`)

v5a was run with `--library-path` pointing at the unpacked pinned wheels (Django 5.2.17,
django-allauth 65.16.1, DRF 3.18.1, then the unpacked library distributions);
run `v5a-nolib` is the same run without it (see below). Required = the 9 required mutation categories
per project (6 should flag, 3 harmless); "all" includes the extra mutations.

| project | | init entries | should-flag caught (req) | on relevant path (req) | **silent, exit 0 (req)** | harmless false alarms (req) | all: caught / silent / false alarms | unrelated invalidations (all) | scan s | paths (unrouted, incomplete) | gaps |
|---|---|---|---|---|---|---|---|---|---|---|---|
| healthchecks | v4 | 24 | 6/6 | 6/6 | **0/6** | 2/3 | 6/6 / 0 / 2/3 | 28 | 0.9 | 24 (12, 11) | 94 |
| | v5a | 25 | 6/6 | 6/6 | **0/6** | 2/3 | 6/6 / 0 / 2/3 | 29 | 1.2 | 25 (12, 14) | 95 |
| paperless-ngx | v4 | 18 | 3/6 | 3/6 | **3/6** | 2/3 | 6/12 / 6 / 2/3 | 46 | 1.8 | 18 (1, 0) | 49 |
| | v5a | 25 | 6/6 | 6/6 | **0/6** | 2/3 | 11/12 / 1 / 2/3 | 110 | 2.3 | 25 (1, 9) | 55 |
| netbox | v4 | 4 | 4/6 | 4/6 | **2/6** | 2/3 | 7/11 / 4 / 2/3 | 9 | 9.4 | 4 (1, 1) | 1119 |
| | v5a | 6 | 4/6 | 4/6 | **2/6** | 2/3 | 7/11 / 4 / 2/3 | 12 | 10.1 | 6 (0, 2) | 1126 |
| plane | v4 | 7 | 3/6 | 1/6 (+2 gap only) | **3/6** | 2/3 | 7/11 / 4 / 4/6 | 27 | 3.8 | 7 (3, 2) | 173 |
| | v5a | 27 | 6/6 | 6/6 | **0/6** | 2/3 | 11/11 / 0 / 4/6 | 89 | 5.0 | 27 (0, 16) | 83 |
| **held-out three** | v4 | | 10/18 | 8/18 | **8/18** | 6/9 | | | | | |
| | v5a | | 16/18 | 16/18 | **2/18** | 6/9 | | | | | |

plane second-order follow-ups (accept a mutation, then weaken the code it added): v4 caught 1/4 (only the positive
control), v5a 4/4 (`a_followup_code_check_dropped` 12, `a2_followup_permission_dropped` 4,
`e_followup_token_compare_dropped` 4, `f2_followup_old_password_check_dropped` 12).

Recall per S/T/P unit (automatic scorer; on v4 it reproduces all 64 adjudicated verdicts):

| class | v4 exact / mint-only / gap / **silent** | v5a exact / mint-only / gap / **silent** |
|---|---|---|
| S full session (41: paperless 14, netbox 7, plane 20) | 13 / 21 / 1 / **6** | 38 / 0 / 3 / **0** |
| T bearer token (12) | 3 / 1 / 3 / **5** | 4 / 1 / 3 / **4** |
| P precursor (11) | 2 / 1 / 2 / **6** | 4 / 0 / 4 / **3** |
| total (64) | 18 / 23 / 6 / **17** | 46 / 1 / 10 / **7** |

What is still silent, and why (none of it is R1/R2/R4/R6):
* mutations: netbox `c_helper_accepts_all` and `a2_new_token_route`, `f2_legit_api_token_rotation` (NetBox's own
  `Token` model generates the secret in `save()`: a custom credential generator, R3); netbox
  `d_remote_auth_enabled_by_default` (the project middleware reads `settings.REMOTE_AUTH_ENABLED` at run time;
  a setting read by project code is not fingerprinted, R5/R7); paperless `c2_pre_authenticate_accepts_all`
  (allauth calls the project's `ACCOUNT_ADAPTER.pre_authenticate`; hooks called by library flows, R5).
* units: T: netbox K01, K02, L02 and plane C01 (custom token models that generate the secret in `save()` or a
  model default, and `set_password`: R3); P: netbox P01 (OAuth `begin` state written by `social_django.views.auth`,
  not a catalog mint) and plane C03/C04 (a 6-digit code from `secrets.randbelow` stored in Redis: R3). plane C03
  was a `gap` in v4 only by accident: the gap was R1's misnamed view (`library_view_not_in_catalog`); with the
  right name the view is analysed and its custom code generator is not a catalog mint, so it is now silent.
  paperless PNG-18 (DRF `TokenAdmin`) is now exact (R2c). The three paperless S units that are `gap` (headless
  signup, headless provider token, the social callback) carry `library_include_mints_incomplete` for
  `allauth.headless.urls` or the `build_provider_urlpatterns()` construct gap.
* harmless refactors still raise false alarms 6 of 9 times (no alpha-renaming, extracted helpers change the
  `code` component: R8), and the coarse `settings` fingerprint (R7) now invalidates more paths per settings
  change because there are more paths (paperless 46 -> 110 unrelated invalidations, plane 27 -> 89).

**Without `--library-path`** (run `v5a-nolib`, the default CLI behaviour): hc: init 25, required caught 6/6, silent 0, false alarms 2/3; all caught 6/6; paths 25, gaps 95; paperless-ngx: init 25, required caught 6/6, silent 0, false alarms 2/3; all caught 11/12; paths 25, gaps 55; netbox: init 6, required caught 4/6, silent 2, false alarms 2/3; all caught 7/11; paths 6, gaps 1126; plane: init 27, required caught 6/6, silent 0, false alarms 2/3; all caught 11/11; paths 27, gaps 83. hc: 9/9 exit codes equal to v5a; paperless-ngx: 15/15 exit codes equal to v5a; netbox: 14/14 exit codes equal to v5a; plane: 21/21 exit codes equal to v5a. Recall (exact/mint-only/gap/silent): paperless-ngx S 11/0/3/0, T 4/1/0/0, P 2/0/3/0; netbox S 7/0/0/0, T 0/0/3/3, P 0/0/1/1; plane S 20/0/0/0, T 0/0/0/1, P 2/0/0/2. The catalog v3 alias rows cover every library alias these projects route; the library path matters for aliases, re-exports and library subclasses the catalog does not list (see `LibraryViewTests`).

**Development projects (scan with defaults, no library path).** Zulip: the same 1084 routes / 1051 entries, the
same 87 path ids with the same statuses as v4, scan about 15.5 s (v4 about 16 s). Gaps 605 -> 621: new
`library_include_mints_incomplete` for `social_django.urls` and `two_factor.urls`, a new
`library_include_not_in_catalog` for `two_factor.gateways.twilio.urls` (v4 dropped it silently because
`two_factor` is a catalogued package), 14 more `fingerprint_depth_limit` (the context-sensitive callee closure
reaches further), one `unresolved_call_on_path` resolved; 7 paths became `analysis_complete=false`. Healthchecks:
24 -> 25 paths (new: the admin site's `password_change/` -> `update_session_auth_hash`, R2c), gaps 94 -> 95 (one
`library_admin_not_in_catalog` naming `compressor`), mutation exit codes unchanged (a 1, b 12, c 12, d 5, e 5,
f 1, g 0, h 4, i 4). On every development project every fingerprint changes once (the `settings` component now
includes the conditions that decide auth settings; catalog v3), so **v4 locks must be re-initialised** (path ids
of projects with namespace packages change too).

### v5 limits (part A)
* Source roots come from `manage.py`, absolute imports and dotted strings in settings-like files. A project that
  adds roots only at run time (`sys.path.insert` in `manage.py` with a computed path) and imports nothing absolute
  from them gets the nearest-root name; two roots that disagree for an unimported module give a gap. Relative
  imports are not used as evidence.
* Library source is used for views, middleware, re-exports of catalog mints and admin modules only; library
  URLconfs (`include("lib.urls")`) are not walked (the `complete` flag and gaps stand in for that), and library
  code is still never analysed for checks.
* The no-mint and completeness declarations of catalog v3 were read in the unpacked wheel versions listed in
  the catalog; other versions may differ (the `deps` fingerprint component still flags pinned version
  changes only).
* A setting evaluated inside a function uses the function's parameters as unknown values; conditions are not
  decided. Functions called through variables, loops over functions, other modules' functions that receive a
  setting are gaps (`settings_function_not_evaluated`, `setting_partially_unknown`); `exec(...)` and
  django-split-settings `include(...)` in a settings module are a `dynamic_setting` gap (`<settings>`).
* `library_base_not_in_catalog` is reported per library base symbol; a base the catalog does not list, even an
  obviously harmless mixin of a non-catalogued package, makes the paths of every class that inherits it
  incomplete. Declaring it is a catalog change.
* Not addressed in part A: R3, R5, R7, R8 (addressed in part B, above), and the URL evaluator's triplication of
  routes when `urlpatterns` is rebound inside `if`/`try` (plane: every route is listed three times and marked
  conditional; it costs precision, not recall; still open).

## What changed in v4 (review findings on v3)

An adversarial review of v3 confirmed eight defects, each with a synthetic fixture under
the reviewers' fixtures. All eight were reproduced and fixed. None of them was judged wrong. Every fix is
general (no project-specific names). Each has regression tests in `tests/test_review_v4.py`, which builds
its own small synthetic projects and copies no development-project code. 26 of its 28 tests fail on v3. The
other two are positive controls, e.g. a strict `options` constant is still a guard.

| # | v3 defect | v4 change | tests (`test_review_v4.py`) |
|---|---|---|---|
| F1 (high) | `jwt.decode` counted as a faithful check unless `options` was a literal dict: `options=CONST`, `options=dict(verify_signature=False)` or `**kwargs` gave `check_guards_mint`. A change to the module constant alone changed no fingerprint (diff exit 0) | `disabled_if` arguments are evaluated statically: keyword, **positional** (`pos` in the overlay: `options` is argument 3, `verify` 4) or a key of `**kwargs`. Values can be literals, dict displays with `**`, `dict(...)`, `a \| b`, locals assigned once (or always to the same value) and **module constants of project modules, also imported ones**. A constant changed in place (`C["k"] = v`, `C.update(...)`) is not evaluated. A value that switches verification off makes the check unfaithful (`present_unproven`). A value MintMap **cannot evaluate** (a parameter, a call result, settings, `**settings.X`) also makes it unfaithful, and adds a new path gap `check_argument_not_static`. The statements consulted are hashed into the `checks` fingerprint (`config:` entries). Wrappers around such a check are unfaithful, and the evidence detail names the reason | `CheckArgumentTests` (6) |
| F2 (high) | `try: urlpatterns = [A] except ImportError: urlpatterns = [B]` ran the body and then the handler in one environment, so the handler replaced the body and A was dropped with no gap | the try body (+ `else`) and each handler are **alternatives** (`exec_branches`), and all their routes are kept, `conditional`. A handler that ends in `raise` is not an alternative, so the body is then unconditional | `TryExceptTests` (2) |
| F3 (high) | `import`/`from ... import` were ignored by the interpreter. In `if X: from lib.urls import urlpatterns as u` / `else: u = []`, the `[]` won the merge, and the library include (or project list) vanished with no route and no gap | imports bind a `Ref` (qualified name) in the current block. A name whose branches bind different kinds of value is now `Alts` (every alternative is evaluated, conditional) instead of an unknown value. This covers an imported list vs `[]`, and two different imported views | `ConditionalImportTests` (3) |
| F4 (medium) | `.append/.extend/.insert` on a URL list imported from another module were dropped silently. `+=` after `from m import *` recorded a gap and dropped the imported routes | these calls and `+=` on an imported name (explicit or star import) act on **that module's list object** (Python's in-place semantics). Its routes are kept. A module whose `urlpatterns` are used this way counts as reached (no `urlconf_not_reached_from_root`) | `ImportedListTests` (4) |
| F5 (medium) | `build_entries` kept one `Route` per entry id (`pattern\|view`) and dropped the others, including one that wraps the view in a project decorator that mints (if/else branches, or another `ROOT_URLCONF`). The decorator's mint became unrouted, with no gap | all occurrences that run different code (URLconf wrappers, `as_view()` arguments, actions, dispatcher) are **variants of one entry**. Their functions and library mints are combined, a gate counts only if every variant has it, every variant's gaps are reported, and every variant's route code is in the `code` fingerprint (`route-variant:`). The path shows them in `entry.route_variants`. Entry and path ids are unchanged | `RouteVariantTests` (4) |
| F6 (medium) | unrolled loops ignored `break`/`continue`, so v3 invented unconditional routes that then marked real later routes `shadowed_by_earlier_route` | statements report how they exit (`Flow`). After a possible `break`/`continue`/`return`, the rest of the block is conditional. After a certain `break`, unrolling stops. **Static conditions** are decided from code alone: literals, `not/and/or`, and `==`, `!=`, `in`, `not in` between strings MintMap knows exactly (literals, unrolled loop variables, module constants). A condition that reads a settings value is never decided. The same applies to `while False:` and to comprehension filters | `LoopControlTests` (3) |
| F7 (medium) | a project auth backend lost its `password` factor (`unverified_project_backend`) whenever it **also** called any unrecognized check (e.g. a `check_*` IP allow-list helper), contrary to this README | the backend is judged as a wrapper over its **recognised** checks only. It is verified when every success exit depends on a recognised check, and unverified when some success exit relies only on unrecognized calls (or on nothing). The unrecognized calls are still `unrecognized_check_call` gaps | `BackendFactorTests` (3) |
| F8 (medium) | `pyotp.TOTP(secret)` was not typed because the CapWords heuristic rejects all-caps names. `t = pyotp.TOTP(s); t.verify()`, `pyotp.TOTP(s).verify()`, `from pyotp import TOTP` and `self.totp = pyotp.TOTP(...)` gave `unrecognized:?.verify`. The only fixture used an annotated parameter | library classes named by the catalog and overlay count as classes: overlay bases and re-export aliases, declared return types, and the class part of catalog methods (`pyotp.totp.TOTP`, `django_otp.oath.TOTP`, `pyotp.hotp.HOTP`, ...) | `LibraryClassTypingTests` (3): local, chained, `from` import, HOTP, `django_otp.oath.TOTP`, a form `__init__` constructing `pyotp.TOTP`, the v1 catalog, a mutation |

The review fixtures (the reviewers' fixtures), v3 → v4 (catalog v2; `run.py`/`lockcycle.py` there):

| fixture | v3 | v4 |
|---|---|---|
| `jwt1` (`options=NO_VERIFY`, `dict(...)`, `**kw`) | 3 of 4 `check_guards_mint` | all 4 `check_present_relationship_unproven` ("verification disabled ...") |
| `jwt2` constant-only mutation (`STRICT` -> `{"verify_signature": False}`) | diff exit 0 | exit 12 (`fingerprint_changed` checks + `evidence_downgraded`) |
| `try1` | `signin/` lost, mint `unrouted` | `signin/` and `fallback/` routed (conditional) |
| `try2`, `if1` (optional `two_factor.urls`) | include lost, no gap | conditional `two_factor.urls` include, 4 library mint paths |
| `if2` (project list imported under `if`) | mint unrouted + `urlconf_not_reached_from_root` | routed, no gap |
| `imp1` (`from base import *` + `+=`) | base route lost + 2 gaps | both routes, no gap |
| `dd2` (decorated variant in `else`) | mint `unrouted:...kiosk_autologin.inner`, no gap | path `route:dash/` -> login + `project_view_decorator_not_analyzed` |
| `brk` (`break`/`continue` in loops) | 2 invented routes, 2 login paths `shadowed_by_earlier_route` | 4 real routes, both login paths `check_guards_mint` |
| `be1` (backend with `check_password` + `check_source_address`) | `guard_relies_on_unverified_check`; removing `check_password` gave exit 4 | `check_guards_mint` (`password`) + gap; the same mutation gives exit 12 (`evidence_downgraded password -> absent`) |
| `wa`, `otpf` (pyotp shapes) | 4 paths `unrecognized_check_present` (`?.verify`) | all `check_guards_mint` with `otp` |

**Development projects with v4** (scan with defaults): Healthchecks and Zulip results are **identical to v3**.
The two scans have the same routes, entries, paths, statuses, factors, gaps and fingerprint components.
Healthchecks has 179 routes / 182 entries, 24 paths (12 unrouted, 1 shadowed) and 94 gaps, in about
1.4 s. Zulip has 1084 routes / 1051 entries, 87 paths (0 unrouted, 2 shadowed) and 605 gaps, in about
16.7 s. Zulip's statuses are 36 `guard_relies_on_unverified_check`, 13
`library_flow_checks_not_analyzed`, 12 `no_check_found_in_analyzed_code`, 10
`check_present_relationship_unproven`, 9 `unrecognized_check_present`, 5 `check_guards_mint` and 2
`shadowed_by_earlier_route`. None of the eight defect patterns occurs on a mint path of these two projects.
Zulip's only `jwt.decode` passes a literal `{"verify_signature": True}` and stays a guard. Its conditional
`two_factor` imports have no `else` branch and were already routed (conditional) by v3. A lock written by
v3 for Healthchecks diffs clean with v4 (exit 0, one informational "catalog/overlay changed").

**Healthchecks mutation experiment re-run with v4** (run `mut-hc-v2`; the base
copy is recreated from the Healthchecks checkout without `.git`). The directory now holds the v4 outputs.
The v2 numbers are in the v2 table below, the v3 outputs are in run `mut-hc-v3`. Results: `init` 24
lock entries, unmodified diff exit 0. The 9 mutations give the same exit codes and finding counts as v2
and v3: a 1, b 12, c 12, d 5 (1 new_path + 24 fingerprint_changed), e 5, f 1, g 0, h 4, i 4. The
`--catalog-v1` run (run `mut-hc-v2/catalog_v1`) gives the same codes as well. The P5 check
(a P5 unshadowing script) gives exit 14, as in v3. The false alarms (h) and (i) are unchanged.

## What changed in v3 (P4, P5 from the Healthchecks/Zulip evaluation)

### P4: why Zulip's mint paths were unrouted (v2, development set)

Measured with the v2 code (snapshot before this change):

1. **Wrong root URLconf.** `zproject/computed_settings.py` sets `ROOT_URLCONF = "zproject.urls"` and later,
   under `if RUNNING_INSIDE_TORNADO:`, `ROOT_URLCONF = "zproject.tornado_urls"`. Settings evaluation kept the
   value of the `if` branch, so only the Tornado URLconf (3 routes) was analysed.
2. **URL lists built in steps.** Even with `zproject.urls` as root, v2 found 34 routes and 266
   `unsupported_url_construct` gaps: 259 calls of a project URL helper (`def rest_path(route, **handlers):
   return path(route, rest_dispatch, handlers)`, the views are passed in the extra-kwargs dict),
   `urls = list(i18n_urls)`, `i18n_patterns(*i18n_urls)` (starred argument), references to another module's
   lists (`dev_urls.urls`, `dev_urls.v1_api_mobile_patterns`), lists imported under an `if`, and a
   comprehension over runtime objects. The module-level `for app_name in settings.EXTRA_INSTALLED_APPS:` loop
   with `include(f"{app_name}.urls")` and `+= import_string(f"{app_name}.urls.i18n_urlpatterns")` was
   skipped **without a gap** (`for` statements were not walked), so the billing/remote-server URLconfs were
   only reported as `urlconf_not_reached_from_root`.
3. **Class-based views run from a function view.** The login page view runs `LoginView.as_view(...)(request)`
   (or a project `two_factor` LoginView subclass) from code; the library mint was only attributed when the
   class itself was routed.

### v3 changes

| problem | change | tests |
|---|---|---|
| P4 root | a setting listed in `ALTERNATIVE_SETTINGS` (`ROOT_URLCONF`) that differs between `if`/`else` (or between settings modules) keeps **every** alternative (else/unchanged value first) instead of the `if` value; each root is analysed (`conditional_setting` gap kept) | `test_urlconf` (root alternatives) |
| P4 lists | `urlconf.py` evaluates URLconf statements **in order** with a small abstract interpreter (see C2): list identity (`include(x)` sees later `x += / .append / .extend / .insert`; `list(x)`, `x + y`, `[*x]`, `i18n_patterns(*x)` are snapshots), `if`/`match`/`a if c else b` (all alternatives, `conditional`), loops and comprehensions over static string lists (module constants, literal settings values) are unrolled, f-string/`+` route and include strings, `import_string("<literal>")`, `(patterns, app_name)` tuples, `i18n_patterns` adds `{lang}/`. Everything else is an explicit gap (`unsupported_url_construct`, `dynamic_route_pattern`) | `test_urlconf.UrlListConstructionTests` |
| P4 helpers | **project URL helper functions** are expanded: parameters are bound to the call-site arguments (`*args`, `**kwargs`, defaults, keyword dicts), the body is evaluated by the same interpreter (loops, local lists, several returns), and the route/view resolve through the parameters. Callables in a route's extra-kwargs dict become **dispatch targets** of that route (`route.dispatched_by`), with a `view_dispatcher_not_analyzed` gap on those paths; the helper and dispatcher source are part of the `code` fingerprint. A project function called with a URL list (`add_routes(urlpatterns)`) is run on the same list object; any other callee receiving a URL list is a gap | same |
| P4 views | `Cls.as_view(**kw)(request)` (or `v = Cls.as_view(...)`, `v(request)`) inside project code: catalog library views (and project subclasses' inherited library mints) become library-provided paths of the calling route, and a project CBV's handlers/hooks become call-graph edges | `test_library_view_run_from_project_code` |
| P5 | `mark_shadowing()` models Django's first-match resolution per root URLconf. A later endpoint whose full pattern is **literally equal** (same text up to converter parameter names, same runtime placeholders, same path/regex kind) to an earlier unconditional endpoint from a different `path()` call is marked `shadowed_by`; its paths get status **`shadowed_by_earlier_route`** (the status it would have otherwise is kept in `evidence.status_if_reachable`), an entry note and a context note, and are counted in `coverage.paths_shadowed`, not as reachable. An earlier **conditional** route only adds `may_be_shadowed_by` and a note. Library includes take part through the new catalog section `library_url_routes` (13 rows, each citing the library's URLconf line): an earlier project route shadows a library mint flow only when **every** listed sub-route of that flow is shadowed, and a library sub-route shadows later project routes | `test_urlconf.ShadowingTests`, `LockAndFingerprintTests` |
| P5 lock | `shadowed_by_earlier_route` has the highest status rank (4): a locked shadowed path that becomes reachable (the earlier route is removed or changed) is `evidence_downgraded` ("no longer shadowed"), plus `fingerprint_changed` (`code` includes the shadowing route). A path that becomes shadowed is only `fingerprint_changed` | same |
| speed | `as_view` invocation lookup is memoised (it walked each function body for every call site of every traversal; Zulip went from 2 min 17 s to about 19 s with 1051 routed entries) | – |

### Results on the development projects (scan with defaults)

| | Zulip v1 (frozen) | Zulip v2 | **Zulip v3** | Healthchecks v2 | **Healthchecks v3** |
|---|---|---|---|---|---|
| root URLconfs | `tornado_urls` | `tornado_urls` | `urls`, `tornado_urls` | `hc.urls` | `hc.urls` |
| routes / entries | 3 / 13 | 3 / 13 | **1084 / 1051** | 179 / 182 | 179 / 182 |
| mint paths | 67 | 42 | 87 | 24 | 24 |
| unrouted paths | 66 | 41 | **0** | 12 | 12 (an admin action, project decorator wrappers, model and notification methods) |
| shadowed paths | – | – | 2 (`[{lang}/]accounts/login/` -> stock `LoginView`) | – | **1** (admin `AdminSite.login` under `admin/`) |
| `unsupported_url_construct` gaps | 2 | 2 | 6 | 0 | 0 |
| scan time | about 42 s | about 17-24 s | about 19 s | about 2 s | about 1.5 s |

Zulip S-class (full-session) entries of the Zulip manual inventory linked to the route the manual inventory
names (a MintMap path from that route and view to the expected mint, not shadowed): **v1 0/17, v2 0/17,
v3 14/17 fully + 1 partially** (28 of 31 expected route/view pairs). ZS01/ZS02 (`login/`,
`accounts/login/` -> `login_page` -> `LoginView` / two_factor `LoginView.done`), ZS03 (`two_factor.urls`),
ZS04, ZS06, ZS07, ZS08, ZS11, ZS12 (`do_login`), ZS05/ZS17 (`social_django.urls`), ZS09 (`realm/register/`;
the manual names a redis login token, MintMap reaches `do_login` through the same registration helper),
ZS15 (all 6 settings routes -> `update_session_auth_hash`), ZS16 (all 6 `django_otp.login` routes). ZS13 is
partial (2 of 3 dev routes). Not linked, because the mint is not a catalog API although the route is now
found: ZS10 and the third ZS13 route (a project redis login token, `ExternalAuthResult.store_data`) and ZS14
(`django.test.Client().login`, unmapped). `zerver.decorator.do_login` is reached from **10 distinct routed
views** (CodeQL: 10 route handlers). The manual inventory's note that the second `accounts/login/` entry
(stock `LoginView`) "is shadowed by the first match and unreachable" is reproduced (P5), as is the
Healthchecks manual entry HC-S09 (the admin login under `admin/` is shadowed by `admin/login/`).

Healthchecks regression check: the same 24 paths with the same statuses, except that the admin login flow is
now `shadowed_by_earlier_route` (`status_if_reachable: library_flow_checks_not_analyzed`). Route patterns
built from the runtime-chosen `prefix` now read `{prefix}accounts/login/` instead of `<dynamic>accounts/login/`
(path ids change: re-run `init`). The mutation experiment re-run with v3 (run `mut-hc-v3`)
gives the same exit codes as v2 for all 9 mutations (a 1, b 12, c 12, d 5, e 5, f 1, g 0, h 4, i 4; unmodified
diff 0; 24 lock entries). An extra P5 mutation (a P5 unshadowing script: delete the
`admin/login/` project route from `hc/urls.py`) gives exit 14: `removed_path` for that route and, for the
admin login flow, `fingerprint_changed` (`code`) plus `evidence_downgraded` "status: shadowed_by_earlier_route
-> library_flow_checks_not_analyzed (the route is no longer shadowed ...)".

## What changed in v2 (P1, P2, P3 from the Healthchecks/Zulip evaluation)

| problem (v1) | v2 change | tests |
|---|---|---|
| **P1** silent miss: a TOTP check (`pyotp` `self.totp.verify()` in a form's `clean_code`) or WebAuthn check (`fido2`) was not a known check, so the path said `no_check_found_in_analyzed_code`, had no gap, and a mutation that made `clean_code` accept every code gave `diff` exit 0 | (a) catalog v2 adds 8 verifier APIs read in library source (pyotp TOTP/HOTP `verify`, fido2 `Fido2Server.authenticate_complete`, PyJWT `decode`, Django `signing.loads`/`unsign`, `hashers.check_password`/`verify_password`, `django_otp.oath.TOTP.verify`) plus a py_webauthn re-export alias; `self.<attr>` receivers are typed from `__init__` assignments and annotations. (b) generic: a *verification-looking* call that is not a recognised check becomes a provisional check `unrecognized:<callee>`, is traced through forms and project wrappers, emits an `unrecognized_check_call` gap (path becomes incomplete) and gives the status `unrecognized_check_present` instead of `no_check_found_in_analyzed_code` | `test_unrecognized.py` |
| **P2** fingerprints left out form/serializer validation methods when the form was not a recognised check | the `checks` component always hashes every project `clean*`/`validate*` method of the forms/serializers used on the path (via `is_valid()`/`full_clean()` on a path function, or the framework-gated `form_class`/`serializer_class`), their project callees (depth-limited) and every project function behind an unrecognized check | `test_unrecognized.py` (`ValidationMethodFingerprintTests`, `MutationDetectionTests`) |
| **P3** 40 of 72 Healthchecks lock entries came from test files | test code is excluded by default (`--include-tests` keeps it); counts are in `coverage.test_code`; a test-named file that analysed code imports is re-included | `test_testcode.py` |

Healthchecks mutation experiment, before (frozen v1, run `mut-hc`) and after (v2,
run `mut-hc-v2`; the base copy is recreated from
the Healthchecks checkout without `.git`, `init`, every entry accepted, unmodified `diff` exit 0). The
v2 column is the v2 run. Run `mut-hc-v2` was re-run with v4 and now holds the v4 outputs, which have
the same exit codes and finding counts (see "What changed in v4"):

| id | mutation | should flag | v1 exit / findings | v2 exit / findings |
|---|---|---|---|---|
| – | `init` lock entries | – | 72 (40 from test files) | **24** (238 test files excluded) |
| a | new route to existing `_check_2fa` | yes | 1: 1 new_path | 1: 1 new_path |
| b | TOTP `form.is_valid()` result ignored | yes | 4: fingerprint_changed (code) | **12**: fingerprint_changed (code) + evidence_downgraded (`otp: guards_mint -> not_enforced`, status `check_guards_mint -> check_result_not_enforced`) |
| c | `TotpForm.clean_code` accepts every code | yes | **0: none (silent FN)** | **12**: fingerprint_changed (checks) + evidence_downgraded (`otp: guards_mint -> present_unproven`) |
| d | add `RemoteUserMiddleware` | yes | 5: 1 new_path + 72 fingerprint_changed | 5: 1 new_path + 24 fingerprint_changed |
| e | MFA-pending branch also calls `auth_login` | yes | 5: 4 new_path + 4 fingerprint_changed | 5: 4 new_path + 4 fingerprint_changed |
| f | `PasswordResetConfirmView(post_reset_login=True)` | yes | 1: 1 new_path | 1: 1 new_path |
| g | comments / blank lines only | no | 0 | 0 |
| h | rename local `totp` -> `otp_gen` | no | 4: 1 fingerprint_changed (FP) | 4: 1 fingerprint_changed (FP, unchanged: no alpha-renaming) |
| i | extract `_make_totp()` helper | no | 4: 1 fingerprint_changed (FP) | 4: 1 fingerprint_changed (FP, unchanged) |

The same experiment with the v2 prototype but the **v1 catalog** (run with `--catalog-v1`,
output in run `mut-hc-v2/catalog_v1`), i.e. with pyotp and fido2 unknown, gives the same exit codes:
(b) and (c) are caught by the generic mechanism alone (`unrecognized:pyotp.totp.TOTP.verify:
guards_mint -> not_enforced` / `-> absent`), and the TOTP and WebAuthn paths are labelled
`unrecognized_check_present` with an `unrecognized_check_call` gap instead of `no_check_found_in_analyzed_code`.

Development projects, `scan` with defaults, frozen v1 vs v2:

| | Healthchecks v1 | Healthchecks v2 | Zulip v1 | Zulip v2 |
|---|---|---|---|---|
| files analysed (test files excluded) | 655 (0) | 417 (238) | 2039 (0) | 1769 (270; 5 re-included) |
| paths (unrouted) | 72 (60) | 24 (12) | 67 (66) | 42 (41) |
| `check_guards_mint` | 1 | 5 | 0 | 3 |
| `guard_relies_on_unverified_check` | 3 | 2 | 18 | 18 |
| `check_present_relationship_unproven` | 2 | 3 | 0 | 1 |
| `unrecognized_check_present` | – | 0 | – | 6 |
| `no_check_found_in_analyzed_code` | 63 | 11 | 48 | 13 |
| `library_flow_checks_not_analyzed` | 3 | 3 | 1 | 1 |
| `unrecognized_check_call` gaps | – | 1 | – | 22 |

Healthchecks TOTP and WebAuthn login paths: v1 `no_check_found_in_analyzed_code`, no gap; v2
`check_guards_mint` with factor `otp` (`TotpForm.clean_code` in the `checks` fingerprint) and
`webauthn` (project helper around `Fido2Server.authenticate_complete`). With the v1 catalog both are
`unrecognized_check_present` with an `unrecognized_check_call` gap.

These are development-set results (Healthchecks and Zulip were used while building v2); they are not
a held-out evaluation. P4 (Zulip routing) and P5 (URL shadowing) are addressed by v3 (previous section).

## Commands (prototype)

The prototype was run as `python3 -I mintmap.py <command> ...`; the package is run as `mintmap <command> ...` with
the same commands and options (see [README.md](../README.md)). Tests: `python -I -m unittest discover -s tests -t tests`.

Common options: `--catalog PATH` (defaults to catalog v3; the v2 and v1 catalogs still
load: without the v3 sections every unmapped library construct is a gap, and the v2-only overlay entries are
skipped with the v1 catalog and listed in `tool.overlay_entries_skipped`), **(v5)** `--library-path DIR`
(repeatable or `os.pathsep`-separated; a `site-packages` directory or a directory of unpacked wheels, read only:
used to resolve library view aliases, re-exports and base classes; recorded in the scan report's
`tool.library_paths`),
`--fingerprint-depth N` (default 4), `--chain-limit N` (default 16) and `--include-tests` (analyse test
code too; see C1). The default lock path is `<project_dir>/mintmap.lock`.

Review workflow: `init` → a reviewer records the review (in the prototype by editing `review_status` to
`accepted` and filling in `reviewer` and `policy_note`; in the package with `mintmap accept`) → commit → CI runs
`diff`. When code changes, run `update` and re-review the entries it reset to `unreviewed`.

## Development constraints that were followed

* v1: the target projects and their manual inventories were
  **not** read, grepped or scanned.
* v2: the development set was the synthetic fixtures, the unpacked library
  sources, the Healthchecks checkout and the Zulip checkout (and their results files).
  The held-out projects (paperless-ngx, netbox, plane) and their manual inventories and scans were
  **not** read, grepped, scanned or run. No fix names a project-specific module, class or function;
  every fix has a synthetic fixture test that does not copy dev-project code.
* v3: same development set and rules as v2 (Healthchecks and Zulip, the Healthchecks and Zulip manual inventories and their scans, library sources, synthetic fixtures); the held-out projects were not
  read, grepped, scanned or run. The URL evaluator has no project-specific names; `tests/fixtures/urlbuild_project`
  was written for it.
* v4: same development set and rules. The inputs were the review fixtures in the reviewers' fixtures
  (synthetic), Healthchecks and Zulip (for regression comparison against v3 only), and the PyJWT source
  for the positions of `options`/`verify` (`jwt/api_jwt.py:305-312`). The held-out projects were not read,
  grepped, scanned or run. The tests in `tests/test_review_v4.py` build their own synthetic projects.
* v5 (part A): the development set was the synthetic fixtures, the library sources under the unpacked library
  distributions (and the pinned-wheel trees), Healthchecks, Zulip, paperless-ngx, netbox and plane and every result file
  including the round-2 evaluation (the v4 evaluation of paperless-ngx, netbox and plane, which therefore
  are **no longer held-out**). The projects reserved for evaluating v5 (InvenTree, Weblate, pretix) and their
  manual inventories were not read, grepped, scanned or run. No fix names a project-specific module, class or
  function; `tests/test_v5.py` builds its own synthetic projects and synthetic library directories.
* v5 (part B): the same development set and rules as part A. The unpacked library sources were read
  for the catalog v3 rows added in part B (`mint_setting_dependencies`, `library_hook_settings`); the five
  development projects were scanned to measure the custom-credential heuristic (R3) and every candidate was judged
  by reading its code. InvenTree, Weblate and pretix and their manual inventories were not read, grepped, scanned or
  run. No rule names a project-specific module, class, function or setting; `tests/test_v5b.py` builds its own
  synthetic projects.
* v5 (review round): the same development set and rules. Inputs were the two review reports (findings with
  synthetic fixtures under the reviewers' workspace: soundness experiments `e1..e11` and generalization projects `mp1..mp11`,
  written by the reviewers, not dev-project code), the unpacked library sources (catalog v3 rows of this
  round cite `channels` 4.3.2, unpacked from the existing pinned wheel, django-oauth-toolkit,
  simplejwt, dj-rest-auth 7.2.0, knox, allauth, and the dj-rest-auth 2.2.8 sdist downloaded with `pip download` and
  unpacked as `dj_rest_auth_legacy` (its `setup.py`, which pip ran to prepare metadata, was
  read afterwards: it only reads `README.md` and `__version__.py`)), and the five development projects (regression
  and noise measurements). InvenTree, Weblate and pretix and their manual inventories were not read, grepped, scanned
  or run. No rule names a project-specific module, class, function or setting; `tests/test_v5c.py` builds its own
  synthetic projects and copies neither dev-project nor reviewer fixture code.
* Behaviour was developed against synthetic fixtures (`tests/fixtures/basic_project`,
  `tests/fixtures/edge_project`, in v2 `tests/fixtures/verify_project` and
  `tests/fixtures/testcode_project`, in v3 `tests/fixtures/urlbuild_project`) written for this prototype.
* The unpacked library sources were read to verify overlay
  facts, such as re-exports and class bases (cited in `overlay.py`). They were also
  scanned as robustness smoke tests: crash and performance checks only, **not** an
  accuracy evaluation (see "Smoke runs" below).

## Layout

Prototype modules and their place in the package (`src/mintmap/`; the prototype's `mintmap_core/` is
`src/mintmap/core/`).

| file | role |
|---|---|
| `cli.py` (prototype: `mintmap.py`) | CLI (`scan`, `init`, `update`, `diff`; the package adds `accept`), exit codes |
| `ci_summary.py` | (package) Markdown job summary for the GitHub Action |
| `core/overlay.py` | machine-readable mapping from catalog qualnames to importable symbols (every entry cites its catalog `ref`) |
| `core/catalog.py` | loads the catalog and overlay; refuses unknown refs (except `optional` v2 entries, which are skipped and reported); reports catalog entries the overlay does not map |
| `core/project.py` | file discovery, test-code exclusion (v2), parse failures, module naming (v5: source roots, PEP 420 namespace packages), import/alias tables, class/function index, MRO (v5: subscripted bases) |
| `core/libsource.py` | (v5) read-only library source (`--library-path`): module lookup, re-exports, `x = Cls.as_view()` aliases, class bases |
| `core/callgraph.py` | call-site extraction and context-sensitive resolution (`self.`, `super()`, typed locals, `self.<attr>` (v2), instances, catalog-known library classes (v4)) |
| `core/settings_extract.py` | settings discovery and literal evaluation, with gaps for dynamic values; (v3) every alternative of a conditionally reassigned `ROOT_URLCONF`; (v5) module-level functions called at module level, partially unknown lists, `match`/`while`, conditions fingerprinted |
| `core/urlconf.py` | URLconf extraction: in-order evaluation of URL lists, URL helper expansion (v3), first-match shadowing (v3); imports, branch/handler alternatives, `break`/`continue`, static conditions (v4) |
| `core/guards.py` | intraprocedural "is the mint control-dependent on check success?" analysis |
| `core/analysis.py` | entries → traversal → mint sites → evidence → fingerprints → gaps |
| `core/fingerprint.py` | normalised-AST hashing; (v5 part B) alpha-renaming of function-local variables |
| `core/refactor.py` | (v5 part B) refactor-insensitive function dumps: conservative inlining of extracted same-module helpers |
| `core/credentials.py` | (v5 part B) heuristic custom credential mints (randomness sources kept as credentials, model field defaults); (v5 review) parameter flow into storing helpers, signal receivers, principal links, hand-rolled session logins |
| `core/lockfile.py` | lock build / merge / diff and exit-code bits |

## Implemented (each item is exercised by a test unless marked *untested*)

Capability numbers C1–C7 are the capabilities the prototype was built to provide: C1 inventory of mint sites,
C2 entry points and tracing, C3 purpose, C4 check evidence, C5 assurance labels, C6 baseline and change
detection, C7 analysis gaps.

### C1 – inventory of mint sites
* **Imports and aliases:** `import x`, `import x as y`, `from a import b as c`,
  relative imports, function-local imports, module attribute access (`auth.login`),
  module-level aliases (`x = auth.login`), project re-exports, and star imports of
  project modules. A star import from a library is recorded as a gap.
* **Mint APIs** (from the catalog via the overlay):
  * 40 call symbols, including `login`/`alogin` and `update_session_auth_hash`; manager
    methods (`Token.objects.get_or_create`, `AuthToken.objects.create`); the
    receiver-dependent `RefreshToken`/`AccessToken`/`SlidingToken.for_user`; library
    instances (`default_token_generator.make_token`); and chained calls
    (`get_adapter().login`).
  * 1 property mint (`refresh.access_token`, using a typed local).
  * 41 library views, 23 library URL includes, `admin.site.urls`, 6 middleware classes
    and 1 minting decorator (sesame).
  * 6 **heuristic, non-catalog** primitives (`django.core.signing.dumps`/`Signer.sign`/
    `sign_object`, `jwt.encode`), reported with purpose `unknown`.
  * **(v5 review)** catalog v3 `library_mint_calls` (`channels.auth.login`) and `library_credential_models` (the
    manager `create`/`get_or_create`/`update_or_create`/`bulk_create` calls of django-oauth-toolkit `AccessToken`,
    `RefreshToken`, `Grant`, `IDToken`, `Application`).
* **Method resolution through project classes into library classes:**
  `super().form_valid()`, `self.x()`, subclasses of library token generators, and
  module-level instances of project classes.
* **(v5 part B, R3) Heuristic custom credential mints** (`credentials.py`): project code that creates a credential
  without a catalog API. A value from `secrets.token_hex/token_urlsafe/token_bytes/choice/randbelow/randbits`,
  `secrets.SystemRandom`, `uuid.uuid4`, `os.urandom` or `django.utils.crypto.get_random_string` (and anything
  computed from it by string/bytes transforms, `"".join`, `hexlify`, digests) that is kept as a credential: an
  attribute of a project model instance, a field of a model creation (`M.objects.create/get_or_create/
  update_or_create/bulk_create`, `M(...)` that is saved, returned or collected, `serializer.save(field=...)`), a
  cache / session store, a credential-named call (`set_password`, `store_token`), or the return value of a
  credential-named function; or a model field `default=` generator, which makes every project creation of the model
  (constructor, manager create, `ModelSerializer`/`ModelForm` save, a DRF view whose library create flow saves that
  serializer) a mint. The mint site is the randomness call (or the creation call for defaults); the path has
  `mint.kind = heuristic_custom_credential`, a `custom_*_candidate` purpose (`custom_one_time_code_candidate`,
  `custom_api_token_candidate`, `custom_password_reset_token_candidate`, `custom_session_token_candidate`, ... or
  `custom_token_candidate`) and the evidence of the chain as for any mint, and it is a reviewable lock entry.
  General name rules set aside non-credential randomness (OAuth `state`, file / asset names, identifiers and
  `UUIDField`s, cache keys, primary keys, outbound webhook secrets, a random password nobody receives, an unsaved
  instance, an update save, migrations); `coverage.custom_credentials` lists the candidates, the models with
  credential defaults and everything set aside with the reason. Values flow through local variables and the
  return values of project functions, not through attributes or containers. **(v5 review)** Also: through the
  parameters of project helpers that store them (`_persist(owner, raw)`, also when the model class itself is passed
  in); stores on objects MintMap cannot type (`user = request.user; user.api_token = ...`); `pre_save`/`post_save`
  receivers (`@receiver(pre_save, sender=M)` / `sig.connect(f, sender=M)`: `instance` is an `M`, and the receivers
  run on every creation / `save()` of `M`); `random.choice/choices/sample` over characters, `random.randint/
  randrange/random/getrandbits/randbytes` and `oauthlib.common.generate_token/generate_client_id` as sources;
  per-subject cache keys (`f"login-otp:{user.pk}"`); `activation` / `confirmation` are strong words; the owner model's
  name qualifies like a field name (`AccessKey.digest`) and a model named after a credential (`ServiceKey`,
  `DeviceKey`) supplies the word for any of its fields. A WEAK word alone (`code`, `key`, `pin`, `session`, no
  qualifier) now needs a principal link (a session, a per-subject cache key, the user model or a model with a
  ForeignKey / OneToOne / ManyToMany to it) or a credential-named owner: coupon / gift-card / room / short-link codes
  are set aside. The field default and the source of its project generator (with callees) are part of the `code` of
  every path that creates the model. **(v5 review) hand-rolled session logins:** a session key that project code
  reads back to load a principal (`pk=` / `id=` / `*_id=` lookup with `x.session.get(K)` or `x.session[K]`), and
  Django's own `_auth_user_id`, make every `x.session[K] = v` a mint (`custom_session_login_candidate`; the mint site
  is the assignment statement). **(v5 review) library credentials:** creating a catalog v3 `library_credential_models`
  model (django-oauth-toolkit `AccessToken`, `RefreshToken`, `Grant`, `IDToken`, `Application`) through its manager
  is a catalog mint; in packages the catalog does not describe, `<CredentialNamedModel>.objects.create*/get_or_create`
  and `create_*/issue_*/generate_*...<credential word>` functions are heuristic mints
  (`custom_library_credential_candidate`). Channels `channels.auth.login` is a catalog mint (`library_mint_calls`).
* **Derived mint wrappers:** project functions that reach a mint directly or
  transitively are listed in `derived_mint_wrappers`, and paths are traced through them.
* **Vendored copies:** if a project contains a function whose qualified name is a
  catalog symbol, it is matched.
* **Unrouted mints:** mint sites that no entry reaches are kept as `unrouted:<root>`
  paths (roots are found by walking callers backwards). They are not dropped.
* **(v3) Library URL sub-routes:** catalog v2 gains a `library_url_routes` section (13 rows; `include` symbol,
  `mint_ref`, sub-route, `source_location` in the unpacked library URLconf, e.g. `django/contrib/admin/sites.py:277`
  `path("login/", self.login)`). It is only used for first-match shadowing; `catalog.py` checks that each row's
  mint is one the overlay maps to that include.
* **Coverage of the catalog:** with the v2 catalog (93 mint, 62 check and 3 non-check entries), 25
  catalog entries are not mapped to symbols, 8 of them mint entries (the same 25 as in v1; every v2
  addition is mapped). **(v5)** With catalog v3 (the same entries plus the v3 sections, see "What changed in v5")
  24 are unmapped: knox `TokenAuthentication.renew_token` is now used for `DEFAULT_AUTHENTICATION_CLASSES`. Every
  report lists them in `tool.catalog_entries_unmapped`.
* **(v5) Library knowledge is never assumed.** A library view, include, middleware, DRF authentication class,
  view decorator, base class or admin registration of an installed app is either mapped to catalog mints, declared
  non-minting (or, for includes, complete) by a catalog v3 row that cites the library source, or reported as a gap
  (also for catalogued packages). See "What changed in v5" (R2).
* **Test code (v2):** excluded by default. Excluded are files in a directory named `tests` or `test`,
  files named `test_*.py`, `*_test.py`, `*_tests.py`, `tests.py`, `conftest.py`, and modules named
  `test.py`/`testing.py` that define a class whose base name ends in `TestCase`. A `test.py` without
  such a class is production code. A test-named file that analysed (non-test) code imports
  (module-level or function-local import) is analysed anyway and listed in
  `coverage.test_code.reincluded`, so naming a production module `test_x.py` does not hide it.
  `coverage.test_code` records `included`, `excluded_files`, `excluded_by_reason`, `excluded_dirs` and
  `reincluded`; `files_seen` counts analysed files only. `--include-tests` restores v1 behaviour.

### C2 – entry points and tracing
* **(v5 review) More roots and entries:** URLconfs chosen per request (a dotted string or a `settings.X` value
  assigned to `<obj>.urlconf`, passed to `set_urlconf()`, or held by any `*_URLCONF` setting) are roots like
  `ROOT_URLCONF`; a URLconf no root reaches is parsed as a root of its own, and every path of it carries its
  `urlconf_not_reached_from_root` gap (v1-v5b: one global gap, routes not inventoried). Django Channels routes
  (`URLRouter([path(p, Consumer.as_asgi()), ...])`, also through a name bound to the list) are entries
  `asgi:<pattern>|<consumer>` whose functions are the consumer's project methods. Project code handed to a library
  view through `as_view(**kwargs)` (a serializer / form / model class, any keyword) is an entry function of the
  route, also when the catalog declares the view non-minting.
* **URLconf extraction:**
  * `path` / `re_path` / `url`.
  * `include()` of module strings, module objects, lists, `(patterns, app_name)` tuples,
    and `router.urls`.
  * `Class.as_view(**kwargs)`, including ViewSet action maps.
  * Function views and view aliases (`login = LoginView.as_view()`).
  * Wrapper calls in URLconfs (`csrf_exempt(view)`).
  * DRF `router.register` and `@action` methods.
  * Pass-through of `format_suffix_patterns`; **(v3)** `i18n_patterns` adds a `{lang}/` prefix
    (`{lang?}/` and no comparison when `prefix_default_language` is not `True`).
  * `if settings.DEBUG:` routes are kept and flagged `conditional`.
  * **(v5) Module names** follow Python's import system for PEP 420 namespace packages: names are relative to
    sys.path-like source roots (the project directory, `manage.py` directories, directories that absolute imports
    and settings dotted paths resolve from); ambiguity is a `module_name_ambiguous` gap.
  * The root comes from `ROOT_URLCONF`; otherwise it is inferred and a gap is recorded. **(v3)** When
    `ROOT_URLCONF` is reassigned under a runtime condition, every alternative is a root.
  * **(v3) in-order evaluation.** Module statements are evaluated in order: assignments, `+=`,
    `.append/.extend/.insert` (in place: an earlier `include(x)` sees them), copies (`list(x)`, `tuple(x)`,
    `sorted(x)`, `x + y`, `[*x]`, `i18n_patterns(*x)`), `del`/item assignment (gap), `if`/`elif`/`else`,
    `match`, `try`/`except`/`else`/`finally`, `with`, `while` (body once, gap), `for` loops and list/generator
    comprehensions (unrolled up to 64 iterations over a static list of strings: a literal, a module constant,
    a literal settings value; a loop over a settings value marks its routes `conditional`; anything else is
    evaluated once with the loop variable unknown and recorded as a gap), conditional expressions (both arms,
    `conditional`), `(patterns, app_name)` tuples, `import_string("<literal dotted path>")`, names imported
    from other modules (their final module-level value).
  * **(v4) alternatives, imports and control flow.** `import` / `from ... import` statements bind names in
    the block where they run (`Ref`), so an import inside an `if` or `try` branch is one alternative. A name
    that the branches bind to different kinds of value (an imported list vs `[]`, two imported views) keeps
    every alternative (`Alts`). Each alternative is evaluated where the name is used, and is `conditional`. A
    `try` body (+ `else`) and each `except` handler are alternatives, except a handler that ends in `raise`
    (the body is then unconditional). A branch that always raises is left out of the merge. After a
    statement that may `break`, `continue` or `return`, the rest of the block is conditional; a certain
    `break` stops loop unrolling. Conditions are **decided statically** only from literals, unrolled loop
    variables and module constants (`not`/`and`/`or`, `==`, `!=`, `in`, `not in` on strings). Anything that
    reads a settings value is never decided. This applies to `if`, `while` and comprehension filters.
    `.append/.extend/.insert` and `+=` on a list imported from another project module (explicit or star
    import) change **that module's list object**, and that module counts as reached.
  * **(v3) route strings** are evaluated symbolically (literals, f-strings, `+`, module constants, literal
    settings values). A value chosen at runtime (e.g. `prefix = ""` then `if ...: prefix = f"{x}/"`) becomes a
    named placeholder `{prefix}`; a value MintMap cannot evaluate at all is `<dynamic>` (plus a
    `dynamic_route_pattern` gap).
  * **(v3) project URL helper functions** (module-level, non-async) called where a pattern or a pattern
    list is expected are expanded (at most 4 nested): positional, keyword, default, `*args` and `**kwargs`
    parameters are bound to the call-site arguments; the body is interpreted; every `return` value is a
    pattern or pattern list (several returns are `conditional`). Routes record `url_helpers`; the helpers'
    source is part of the `code` fingerprint. A helper MintMap cannot expand gives an
    `unsupported_url_construct` gap that names the reason.
  * **(v3) dispatch targets.** Callables in a route's extra-kwargs dict (`path(r, dispatcher, {"POST": view})`,
    also through a helper's `**handlers`; a `(view, flags)` tuple uses its first element) become routes of the
    same pattern with `dispatched_by`; their paths carry a `view_dispatcher_not_analyzed` gap because checks
    the dispatcher makes before calling the view are not linked. The dispatcher's source is fingerprinted.
  * **(v3) URL lists passed to functions** as a statement (`add_routes(urlpatterns)`): a project function is
    run with its parameter bound to the same list; any other callee gives a gap.
  * **(v3) first-match shadowing (P5)**, see "Path status" and the v3 section above.
* **Entries:**
  * function views;
  * CBVs: HTTP verbs, plus framework hooks such as `form_valid` and `perform_create`,
    but only when the dispatching method (`post`, `create`, ...) resolves to library
    code;
  * ViewSet actions;
  * routed library views and includes, which become library-provided paths with
    catalog purposes;
  * project CBVs that inherit a catalog view's mint (unless the mint method is
    overridden without `super()`);
  * **(v3)** catalog library views (and project subclasses' inherited library mints) run from project code
    on the entry's call graph with `Cls.as_view(**kw)(request)` or `v = Cls.as_view(...)` ... `v(request)`;
    a project CBV run that way contributes its handlers and hooks as call-graph edges;
  * **(v4) one entry per `pattern|view`, with variants:** when the same pattern and view are routed more
    than once (two roots, two includes, if/else branches) and the occurrences run different code (URLconf
    wrappers such as a project decorator, `as_view()` arguments, ViewSet actions, a dispatcher), the entry
    combines them. It gets the union of functions and library mints, and a gate only if every variant has
    it. Every variant's gaps are reported and every variant's route call is fingerprinted. The displayed
    route (and its shadowing) is an occurrence that is not shadowed and not conditional if one exists; the
    others are listed in `entry.route_variants`;
  * catalog middleware;
  * project middleware, including subclasses of catalog middleware;
  * project classes in `REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']`.
* **Tracing:**
  * Context-sensitive forward reachability from entries: `(function, concrete class)`
    nodes, so `self.helper()` resolves against the routed class.
  * Implied framework edges: `form.is_valid()` / `full_clean()` → `clean*`/`validate*` of the
    project form or serializer class, whether or not it is a recognised check; `serializer.save()` →
    `create`/`update`; `super().post()` → project hooks.
  * **(v2) type inference used for this:** a `x = None` placeholder no longer hides the type of a later
    `x = SomeForm(...)`; when a variable is assigned several project classes (`if ...: form = A(...)
    else: form = B(...)`) the implied edges go to every candidate; parameter annotations accept
    `T | None`, `Optional[T]` and string annotations; `self.<attr>.m()` is resolved when every
    `self.<attr> = ...` in the class hierarchy (or a class-level annotation) gives the same class,
    e.g. `self.totp = totp` with `def __init__(self, totp: TOTP)`.
  * **(v4)** a call of a library class that the catalog or overlay names is a constructor (its result is
    typed) even when the class name is all upper case: `t = pyotp.TOTP(s)`, `pyotp.TOTP(s).verify(...)`,
    `from pyotp import TOTP`, `self.gen = pyotp.TOTP(...)`, `django_otp.oath.TOTP(key)`. The known classes are
    the overlay bases and re-export aliases, declared return types, and the class part of catalog
    method symbols. Other all-caps names are still not treated as classes.
  * Call chains are recovered backwards from each mint site, up to `--chain-limit`
    simple paths. Hitting the limit is recorded as a gap.

### C3 – purpose
* Purpose comes from the catalog entry of the mint API: `full_session`,
  `mfa_challenge_state`, `password_reset_token`, `jwt_refresh`, `jwt_access`,
  `jwt_refresh_exchange`, `api_token`, `session_rotation_keep_auth`, `impersonation_session`,
  `magic_link_token`, `oauth_authorization_code_or_token`, `invitation_or_signup_token`,
  `other`.
* Heuristic custom-token primitives get `unknown`.
* If the receiver is a **project subclass** of the catalog class (for example
  `InvitationTokenGenerator(PasswordResetTokenGenerator)`), the catalog purpose is kept
  and `purpose_note` says the project may use it differently. MintMap does not infer
  the intended purpose; reviewers record it in `policy_note`.

### C4 – check evidence
Check recognition:
* 25 catalog check functions, plus in v2 (catalog v2 `check_apis` with `added_in: "v2"`, each citing
  `file:line` in the unpacked wheel): `pyotp.totp.TOTP.verify` (totp.py:68) and `pyotp.hotp.HOTP.verify`
  (hotp.py:47) with the `pyotp.TOTP`/`HOTP`/`Steam` re-exports; `fido2.server.Fido2Server.authenticate_complete`
  (server.py:324, raises); PyJWT `jwt.decode`/`decode_complete` (api_jwt.py:305, raises; marked not
  faithful when `options` sets `verify_signature` to a false value or `verify=False`, and **(v4)** also when
  MintMap cannot evaluate those arguments, see "Check arguments" below);
  `django.core.signing.loads`, `Signer.unsign`/`unsign_object`, `TimestampSigner.unsign` (signing.py:195,
  raises); `django.contrib.auth.hashers.check_password`/`acheck_password` (hashers.py:75) and
  `verify_password` (hashers.py:39, returns an always-truthy tuple); `django_otp.oath.TOTP.verify`
  (oath.py:171); and the module path of `webauthn.verify_authentication_response` (`__init__.py:6-8`);
* 5 checks matched by method name only (receiver type unknown), such as
  `check_password`, `verify_token`, `verify_is_allowed` and `is_verified`;
* 4 raising JWT constructors;
* 11 catalog form or serializer classes (`is_valid`, with `raise_exception=True`
  treated as raising);
* project forms whose `clean*`/`validate*` methods raise when a check fails;
* project **wrappers**, classified as `bool`, `raises` or `unfaithful`. A wrapper is
  `unfaithful` when it can return success without the inner check succeeding.
* **(v2) unrecognized checks.** A call whose last name component (leading underscores removed,
  lower-cased) starts with `verify`, `check_`, `validate`, `authenticate` or `confirm`/`confirm_`, ends
  with `_verify`, or is `compare_digest`, `constant_time_compare`, `bytes_eq` or `strings_equal`, and
  that is not a recognised check, becomes a provisional check with factor `unrecognized:<callee>`
  (`<callee>` is the resolved library symbol, the project function, or `?.<name>` when unresolved) and
  unknown return semantics. Not counted: constructors, mint calls, project functions that lead to a
  mint (mint wrappers), `super().m()` inside `m` (delegation), framework plumbing (`full_clean`,
  `clean_fields`, `validate_unique`, `validate_constraints`, `run_validators`, `is_valid`), and library
  symbols in the catalog v2 `non_check_apis` list (Django `django.core.validators.*`, the password
  strength policy `validate_password`, fido2 `authenticate_begin`/`register_begin`). A project function
  with such a name is an unrecognized check only when it contains no check MintMap can see; otherwise
  it is analysed as a wrapper. Unrecognized checks are traced like real ones through form
  `clean*`/`validate*` methods and through up to **2** project wrapper levels, but only through
  wrappers whose outcome depends on them (`bool`/`raises`, not `unfaithful`). Their relation to the mint
  is computed as for other checks; a bare call is `present_unproven` (raising or ignored result cannot be
  told apart) unless it sits in a `try:` whose handlers all return/raise, which shows the code expects
  it to raise. They never make a path "guarded".
* **(v4) Check arguments.** For a catalog check whose overlay entry has `disabled_if` patterns (today the
  PyJWT decode functions), MintMap evaluates the relevant argument statically. It looks at the keyword
  argument, the positional argument at the pattern's `pos` (`options` = 3, `verify` = 4), or the key of a
  `**kwargs` dict. Understood values are literals, dict displays (with `**`), `dict(...)`, `a | b`, local
  variables that every store assigns the same value, and module constants of project modules (also
  imported ones). A constant changed in place (`C[k] = v`, `C.update(...)`, `+=`) is not understood.
  * The argument switches verification off: the check is not faithful, its relation is at most
    `present_unproven`, and the detail says "verification disabled: options['verify_signature']=False
    (options=NAME)".
  * The argument cannot be evaluated (a parameter, a call result, a settings value, `**settings.X`,
    `*args` before the position): the check is also not faithful ("verification options not statically
    known"), and the path gets a `check_argument_not_static` gap.
  * The statements consulted (the constant's assignment, the local's assignment) are hashed into the
    `checks` fingerprint component, so changing only the constant is a `fingerprint_changed` (and, if it
    disables verification, an `evidence_downgraded`).
  * A project wrapper around such a check is unfaithful, and its detail repeats the reason.
* Every unrecognized check on a path (in path functions, in the validation methods of forms used on the
  path, or behind a wrapper) gives an `unrecognized_check_call` gap (`where` = function containing the
  call, `detail` = callee and why it is unrecognized; no line numbers), so the path is
  `analysis_complete=false`, and is listed in `evidence.unrecognized_checks`.

Per check, the relation to the mint (or to the call that leads to it, for each function
on the chain) is one of:

| relation | meaning |
|---|---|
| `guards_mint` | the mint is reachable only if the check succeeded: inside `if check:` / `if x is not None:`, after an early exit `if not check: return/raise`, after a raising check that no handler swallows, in the `else:` of a `try`, via walrus or variable bindings, `and` conjunctions, or IfExp |
| `guards_mint_assert_only` | the only guard is `assert` (removed under `python -O`) |
| `present_unproven` | called, but the relationship is not established: a disjunction (`or`), a result stored in a variable that is reassigned or unused, the check running after the mint, a swallowed exception, an unfaithful wrapper, or anything else |
| `result_ignored` | a non-raising check used as a bare expression statement |
| `condition_always_truthy` | a check returning `(bool, info)` (`verify_is_allowed`) used directly as a condition |

* **Framework gates:**
  * `form_valid` reached through the library `post` (Django `ProcessFormView`) counts
    as guarded by the form class's checks.
  * `perform_create`/`perform_update` count as guarded by the serializer.
  * A mint for `request.user` behind `login_required`/`otp_required`, or behind DRF
    `IsAuthenticated`/`IsAdminUser`, records a `prior_authentication:<auth classes>`
    factor.
* **`same_user`** is `shown` when simple variable-name dataflow links the verified
  subject (the return value, an argument, the receiver, or the form or serializer) to
  the mint's user argument, mapping arguments to parameters along the chain.
  Otherwise it is `unproven`, or `not_applicable`. Wrong-user verification is detected
  only as `unproven`.
* **`authenticate()`**: its factor is derived from `AUTHENTICATION_BACKENDS` (Django's
  default `ModelBackend` when unset). Each project backend's `authenticate` is analysed as a wrapper
  **over its recognised checks only (v4)**. If a success exit (a return of a non-falsy value) is not
  guarded by a faithful recognised check, the factor becomes `unverified_project_backend:<cls>` and the
  path status becomes `guard_relies_on_unverified_check`. That includes an exit guarded only by
  unrecognized calls, and a backend whose only checks are unrecognized. Otherwise the factor is the
  recognised checks' factor (e.g. `password`), even when the backend also calls an unrecognized helper
  such as a `check_*` IP allow-list. (v2) Unrecognized checks inside a project backend are reported as
  `unrecognized_check_call` gaps on every path that calls `authenticate()`.
* Paths are combined across chains conservatively: for each factor, the weakest
  relation over all chains is kept.
* Context notes (not checks):
  * the mint subject is `request.user` (an exchange or re-issue, not a fresh login);
  * a function on the path reads `request.session`, so an earlier request may hold the
    real check;
  * the entry is middleware.

### Path status (machine label, not a verdict)

| status | meaning |
|---|---|
| `check_guards_mint` | at least one verified factor guards the mint |
| `guard_relies_on_unverified_check` | the only guards are unverified (for example an unfaithful project backend) |
| `check_present_relationship_unproven` | checks are present, none is shown to guard |
| `check_result_not_enforced` | a check result is ignored or always truthy, and nothing guards |
| `unrecognized_check_present` **(v2)** | no recognised check on the path, but at least one verification-looking call MintMap does not recognise (see C4). Its relation is in `evidence.factors` as `unrecognized:<callee>`; the path also has an `unrecognized_check_call` gap |
| `no_check_found_in_analyzed_code` | no recognised check in the analysed project code on this path. This is **not** "no checks at all": the check may be in an earlier request, a project decorator, a proxy or IdP, or it may be the possession of an invitation/reset token handled elsewhere |
| `library_flow_checks_not_analyzed` | the mint happens inside library code; see the catalog semantics for what the library checks |
| `shadowed_by_earlier_route` **(v3)** | Django's first-match resolution never dispatches this route for this mint: an earlier unconditional route with a literally equal pattern (or, for a library include, earlier routes equal to every catalog-listed sub-route of this flow) takes the request. `evidence.shadowed_by` names it and `evidence.status_if_reachable` keeps the status the path would otherwise have. Only literal equality is modelled (see "Not implemented") |

Human fields in the lock (`review_status: unreviewed|accepted`, `reviewer`,
`policy_note`) are the only place where an intended policy is expressed. MintMap does
not decide whether a path is acceptable.

### C5 – assurance labels
**Not implemented.** Factor names are descriptive (`password`, `otp`,
`prior_authentication:session`, ...). No NIST SP 800-63-4 AAL or phishing-resistance
label is assigned.

### C6 – baseline and change detection
* **Fingerprint** per path: seven components (v5 part B: `hooks`), each a SHA-256 prefix over
  `ast.dump(..., include_attributes=False)` with docstrings removed. Comments,
  whitespace, quoting, parentheses and line numbers do not change it. **(v5 part B, R8)** Function-local variables are
  alpha-renamed (canonical names in order of first binding; parameters, attributes, keyword-argument names, globals
  and imports are kept), and extracted same-module helpers are inlined back into their callers under the conditions
  listed in `refactor.py` (plain-name or constant arguments, straight-line helper, no capture), so renaming a local
  or extracting a helper does not change a fingerprint; any other syntactic change does.

| component | what it hashes |
|---|---|
| `code` | the route call (**v4**: and the route call of every other variant of the entry, `route-variant:`); class attributes of the project CBV MRO (whole classes for library-provided flows); every function on any entry→mint chain; (v3) URL helpers, dispatcher and the shadowing route; **(v5 review)** the module-level statements (with the `if` tests around them) of every module-level value the path's functions read (`global:`; a flag computed from a setting at import time also makes that setting a path dependency); for admin paths, project statements that change the default admin site (`admin.site.__class__ = ...`, `admin.site.login_form = ...`) and the project code they name; for heuristic model-default paths, the field declaration and the generator's source; for a grouped heuristic site, the list of entries that reach it |
| `callees` | project functions called from the path, transitively, up to `--fingerprint-depth` (default 4); **(v5)** context-sensitive: `self.m()` in an inherited method resolves against the receiver class, so a subclass override is included; **(v5 review)** every project method of the classes a library flow is handed (as_view kwargs, any class attribute of a view inheriting library code); a helper is left out only when its body is instantiated in the dump of a function that is hashed |
| `checks` | project check wrappers, forms and backends used as checks; **(v2)** every project `clean*`/`validate*` method of the forms/serializers used on the path (recognised as checks or not; reached by `is_valid()`/`full_clean()` from a path function, or the `form_class`/`serializer_class` of a framework-gated hook) and every project function behind an unrecognized check; plus their callees (same depth). The methods are listed in `evidence.validation_methods`. **(v4)** the statements that configure a check's `disabled_if` arguments (`config:` entries, e.g. the module constant passed as `options=` to `jwt.decode`); **(v5)** for a library flow inherited by a project class, the validation methods of its `serializer_class` / `form_class`; **(v5 review)** of every project class handed to the library flow (any attribute name, e.g. `authentication_form`, and `as_view(**kwargs)` of library views); `confirm_login_allowed` counts as a validation method |
| `settings` | **(v5 part B, R7)** only the settings THIS path depends on (`fingerprint.settings_dependencies`): the `AUTHENTICATION_BACKENDS` group when a check on the path calls `authenticate()` (directly or through a catalog form/serializer that does); `REST_FRAMEWORK` `DEFAULT_PERMISSION_CLASSES` / `DEFAULT_AUTHENTICATION_CLASSES` for a DRF view that takes them from the setting; every `settings.X` (or `getattr(settings, "X")`) read by project code on the path (path functions, callees, check code, hooks); the settings the catalog names for the mint's flow (catalog v3 `mint_setting_dependencies`); the conditions under which a middleware is in `MIDDLEWARE` (middleware paths); the hook settings of the path. Each dependency hashes the evaluated value, the statements that assign or change it, the conditions that decide it and the assignments those read. Global settings are separate lock entries (see "Lockfile"). Before part B: every auth setting of the project on every path |
| `hooks` | **(v5 part B, R5)** project code a library flow calls because a setting names it (catalog v3 `library_hook_settings`): the hook classes (whole class and project bases) / functions and their callees, for every path of the packages the row applies to |
| `catalog` | the catalog entries of the mint and check APIs on the path |
| `deps` | version specifiers for the path's packages from `requirements*.txt` / `.in` and `pyproject.toml`. Lock files (`poetry.lock`, `uv.lock`, `Pipfile.lock`) are **not** read |

  When a depth limit truncates the closure, that is recorded as a gap. **(v5 review)** That gap clears the path's
  `fingerprint_complete` flag only; `analysis_complete` reflects every other gap (one flag was false on 287 of 294
  Zulip paths, almost always only because of the depth limit). Both flipping from true to false are bit 32.
* **Path id:** `sha256(entry id || mint-site id)`. The entry id contains the route
  pattern and the view qualname. The mint-site id is the function, the API symbol, the
  catalog ref and the ordinal of that API in the function; no line numbers.
* **`update`:** carries `review_status`/`reviewer`/`policy_note` forward only when id,
  overall fingerprint and purpose are unchanged and evidence is not downgraded.
  Otherwise the entry is reset to `unreviewed` and the old fields are kept under
  `previous_review`.

### C7 – analysis gaps
Every gap has `type`, `file`, `where` and `detail`, and a stable key without line
numbers. It appears in `coverage.gaps` and, where it concerns one path, in the path's
`gaps` (which makes `analysis_complete=false`; **(v5 review)** a `fingerprint_depth_limit` gap makes
`fingerprint_complete=false` instead).

Implemented gap types:
* parsing and modules: `parse_failure`, `module_name_collision`,
  `star_import_unresolved`, `settings_star_import_unresolved`;
* settings: `dynamic_setting`, `conditional_setting`, `conflicting_setting`,
  `missing_setting`, `no_settings_module`, `settings_module_ambiguous`,
  `settings_module_missing`;
* URLconf: `root_urlconf_inferred`, `root_urlconf_not_found`, `no_urlconf`,
  `urlconf_not_reached_from_root`, `unsupported_url_construct`, `unsupported_view_expr`,
  `unresolved_view`, `dynamic_route_pattern`, `url_include_cycle`, **(v3)** `view_dispatcher_not_analyzed`;
* libraries outside the catalog: `library_view_not_in_catalog`,
  `library_include_not_in_catalog`, `middleware_not_in_catalog`,
  `drf_auth_class_not_in_catalog`;
* things MintMap cannot see into: `project_view_decorator_not_analyzed`,
  `class_decorator_not_analyzed`, `form_class_unresolved`, `dynamic_view_attribute`;
* call resolution: `possible_mint_call_unresolved` (a distinctive mint name, or
  `login`/`alogin` called as a bare parameter or with `request` first),
  `unresolved_call_on_path`, `unresolved_call_may_reach_mint`;
* analysis limits: `chain_enumeration_truncated`, `fingerprint_depth_limit`,
  `unrouted_roots_truncated`;
* **(v2)** checks: `unrecognized_check_call` (see C4);
* **(v4)** checks: `check_argument_not_static` (a `disabled_if` argument of a catalog check MintMap cannot
  evaluate; see C4 "Check arguments").
* **(v5)** modules: `module_name_ambiguous` (a file in a namespace-package directory has different valid names
  under two source roots and project code imports neither); classes: `class_base_unresolved` (a base of a class on
  the path MintMap cannot resolve, e.g. `class V(make_base()):`), `library_base_not_in_catalog` (a project view,
  middleware or DRF authentication class inherits a library class the catalog does not account for);
  libraries: `library_include_mints_incomplete` (catalog v3 does not declare the include's mint list complete),
  `library_admin_not_in_catalog` (installed apps whose admin registrations the catalog does not declare, one
  aggregated gap on the `admin.site.urls` paths), `library_call_may_mint` (a resolved call into a catalogued
  package whose name is a catalog mint name but whose symbol is not mapped), `view_decorator_not_in_catalog`
  (a library or unresolved view decorator); settings: `setting_partially_unknown` (known items kept, e.g.
  `MIDDLEWARE.extend(plugin_list)`), `settings_function_not_evaluated` (a settings function that changes auth
  settings but is not called at module level in a way MintMap follows).
* **(v5 part B)** hooks: `hook_setting_not_static` (a hook setting, e.g. `ACCOUNT_ADAPTER`, whose value MintMap cannot
  evaluate: the project code the library calls is unknown; attached to every path the hook applies to),
  `hook_target_unresolved` (it names project code MintMap cannot find); `fingerprint_depth_limit` also for hook
  code beyond the depth. `library_view_not_in_catalog`,
  `library_include_not_in_catalog`, `middleware_not_in_catalog` and `drf_auth_class_not_in_catalog` are now
  also reported for **catalogued** packages (v1-v4 suppressed them).
* **(v5 review)** `hook_target_not_in_catalog` (a hook setting names library code of a package the catalog does not
  describe; attached to every path the hook row applies to), `dependency_version_not_verified` (a pinned / bounded
  version of a catalogued package excludes every version the catalog was read in, catalog v3
  `verified_package_versions`; attached to every path whose mint or hook belongs to the package),
  `settings_module_not_analyzed` (test settings modules that are not analysed as alternatives), `admin_site_customised`
  (library code of an undescribed package replaces part of the admin site; admin paths), `asgi_routing_not_analyzed`
  (a Channels `URLRouter` argument or element MintMap cannot enumerate). `urlconf_not_reached_from_root` is now also
  attached to every path of the unreached URLconf (which is parsed). `setting_partially_unknown` now also covers item
  stores, item `+=` and method calls through computed receivers that MintMap does not follow.

## Lockfile (`mintmap.lock`, JSON, `mintmap_lock_version: 1`)

```
{ "mintmap_lock_version": 1,
  "tool":     {name, version, catalog_path, catalog_sha256, overlay_sha256, catalog_entries_unmapped,
               overlay_entries_skipped, library_paths_count, python},   (release 0.5.0a1: the last two)
  "project":  "<dir name>",
  "settings": [ {id: "settings:<group>", names[], values{}, items{}, fingerprint{overall, settings{}, sources{}},
                 review_status, reviewer, policy_note} ],          (v5 part B, R7)
  "coverage": {files_seen, files_parsed, parse_failures[], excluded_dirs[], settings_modules[], root_urlconfs[],
               routes_total, entries_total, gaps_by_type{}, gap_keys[], dependency_files[], dependency_specs{}, limits{},
               test_code{included, excluded_files, reincluded[]}},
  "paths": [ { "id", "entry_point": {kind (route | middleware | drf_auth_class | unrouted | (v5 review) asgi_route |
                                     heuristic_site), id, view, route{pattern,name,kind,target,file,line,decorators,
                                     conditional,urlconf_chain, url_helpers?, dispatched_by?{view,kwarg},
                                     shadowed_by?, may_be_shadowed_by?}, route_variants? (v4) [route{...}],
                                     functions[], gates[], notes[], reached_from? (v5 review, heuristic_site) []},
               "mint_site": {api, kind (v5 part B: call | library_view | ... | heuristic_custom_credential),
                             provided_by: project_code|library, provided_via, catalog_ref, purpose,
                             purpose_basis, purpose_note, library_source, site{file,function,line,call}},
               "purpose", "chain": [...],
               "evidence": {status, status_if_reachable (v3), shadowed_by (v3), context[], factors{factor: relation},
                            checks[{function,line,check,catalog_ref,
                            factor,via,relation,detail,same_user}], unrecognized_checks[{function,line,call,
                            target,reason}], validation_methods[]},
               "analysis_complete", "fingerprint_complete" (v5 review), "gaps": [gap keys],
               "fingerprint": {overall, components{code,callees,checks,settings,catalog,deps,hooks},
                               fingerprint_depth, settings_dependencies[], hooks[], path_functions[],
                               callee_functions[], check_functions[]},
               "review_status": "unreviewed|accepted", "policy_note": "", "reviewer": "",
               "previous_review"?: {...} } ] }
```

## `diff` findings and exit codes (bitmask; several can be set at once)

| bit | finding | when |
|---|---|---|
| 1 | `new_path` | an id in the scan that is not in the lock |
| 2 | `removed_path` | an id in the lock that the scan no longer finds. This includes the analysis losing sight of it, so a coverage drop cannot keep an approved path green |
| 4 | `fingerprint_changed` | overall fingerprint differs; the finding names the changed components |
| 8 | `evidence_downgraded` | a factor's relation weakened or disappeared, `same_user_shown` was lost, or the status rank dropped |
| 16 | `purpose_changed` | the catalog purpose differs |
| 32 | `coverage_regression` | fewer parsed files; new parse failures; any new gap key (v2: including a new `unrecognized_check_call`); newly excluded directories; test code analysed when the lock was written but excluded now (v2); changed settings or URLconf roots; or a path that was complete is now incomplete (**v5 review**: `analysis_complete` or `fingerprint_complete`) |
| 64 | `unreviewed` | an otherwise unchanged lock entry whose `review_status` is not `accepted` |
| 128 | – | usage, input or catalog errors (argparse is overridden so that its exit code 2 does not collide with bit 2) |

**(v5 part B, R7) Settings groups.** The global auth settings are one lock entry per group: `settings:MIDDLEWARE`,
`settings:AUTHENTICATION_BACKENDS`, `settings:REST_FRAMEWORK` (authentication keys only: `DEFAULT_AUTHENTICATION_CLASSES`,
`DEFAULT_PERMISSION_CLASSES`, `UNAUTHENTICATED_USER/TOKEN`, `DEFAULT_THROTTLE_CLASSES/RATES`), `settings:AUTH_CORE`
(`AUTH_USER_MODEL`, `SESSION_ENGINE`, `SECRET_KEY_FALLBACKS`; **v5 review**: `PASSWORD_HASHERS`, `SESSION_SERIALIZER`,
`SESSION_COOKIE_AGE/SECURE/HTTPONLY/SAMESITE/DOMAIN/NAME/PATH`, `SESSION_EXPIRE_AT_BROWSER_CLOSE`,
`SESSION_SAVE_EVERY_REQUEST`, `SESSION_CACHE_ALIAS`, `SESSION_FILE_PATH`, with the source of the project hasher /
session store / serializer classes they name), `settings:INSTALLED_APPS(auth)` and one
`settings:package:<pkg>` per package whose prefixed settings the project sets (`ACCOUNT_*`/`MFA_*`/... for allauth,
`SIMPLE_JWT`, `SOCIAL_AUTH_*`, ...). A group hashes, per setting, the evaluated value, the statements, the deciding
conditions and the assignments they read, plus the source of the project classes the setting names (middleware,
backends, DRF authentication/permission classes). A changed, new or removed group is ONE `fingerprint_changed`
finding (bit 4) whose `path_id` is the group id and whose message names the changed settings (`MIDDLEWARE:
+'x.Middleware'`, `ACCOUNT_LOGIN_ON_PASSWORD_RESET added (True)`, `project code x.Backend changed`); an unchanged
group that is not accepted is `unreviewed` (bit 64). `update` keeps the review of unchanged groups. A minting
middleware or backend that a settings change adds is still a `new_path`, and paths that depend on a changed setting
specifically still change (see the `settings` component).

`0` means every path and settings group matches an accepted lock entry and coverage did not regress.
Informational findings (gaps resolved, catalog or overlay changed, more excluded test files) do not set bits.
The status rank used for `evidence_downgraded` places `unrecognized_check_present` with
`check_result_not_enforced` (1), above `no_check_found_in_analyzed_code` (0). **(v3)**
`shadowed_by_earlier_route` ranks highest (4), and leaving it is always a downgrade, whatever the new status
(also `library_flow_checks_not_analyzed`, which otherwise has no rank): a locked path whose shadowing route
disappears is reported as reachable again.

The scan report (not the lock) also has `coverage.paths_unrouted`, `paths_shadowed`, `routes_shadowed`,
`routes_may_be_shadowed` and `library_subroutes_shadowed` (v3), printed in the `scan` summary.

A lock written by v5 part B (before the review round) should be re-initialised too: `code` / `callees` / `checks`
digests change where paths read module-level values, run classes handed to library flows, use comprehensions or create
models with credential defaults; `settings:AUTH_CORE` gains the session and hasher settings; projects with several
settings modules, per-request or unreached URLconfs, Channels routes or the new credential shapes get new entries;
widely shared heuristic sites become `heuristic_site` entries (new ids, the per-entry paths are removed); and paths gain
`fingerprint_complete`. Re-run `init` (or `update` and re-review).

A lock written by v5 part A should not be reused with part B unchanged either: the lock gains `settings` group
entries (a part-A lock has none, so every group is reported as new), every `code`/`callees`/`checks` digest changes
once (alpha-renamed, inlined dumps), the `settings` component holds only path-specific dependencies and the new
`hooks` component is added, and heuristic custom-credential paths appear. Re-run `init` (or `update` and re-review).

A v4 lock should **not** be reused with v5 unchanged: every fingerprint changes once (the `settings` component
hashes the conditions that decide auth settings; catalog v3), projects with namespace packages get new module
names and therefore new entry and path ids, the context-sensitive callee closure and the validation methods of
inherited library flows change `callees`/`checks`, new library paths appear (admin `password_change/`, library
admin registrations, resolved aliases) and many paths gain gaps that v4 suppressed. Re-run `init` (or `update`
and re-review).

A v3 lock can be reused with v4: entry and path ids are unchanged. Fingerprints change only for paths whose
entry now has route variants (`route-variant:` in `code`) or whose checks have `disabled_if` arguments
configured by a constant or local (`config:` in `checks`). Paths with a `jwt.decode` whose arguments MintMap
cannot evaluate gain a `check_argument_not_static` gap (`coverage_regression`) and may be `evidence_downgraded`.
The URLconf fixes can add routes and paths (`new_path`), and can turn routes that v3 wrongly reported as
unconditional into conditional ones. On Healthchecks a v3 lock diffs clean with v4 (exit 0).

A v2 lock should not be reused with v3 unchanged either: route patterns change (`{lang}/` for
`i18n_patterns`, `{placeholder}` instead of `<dynamic>` for runtime-chosen parts, routes found through
helpers), so entry and path ids change, root URLconfs can change, and helper/dispatcher source enters the
`code` fingerprint. Re-run `init` (or `update` and re-review).

A v1 lock should not be reused with v2 unchanged: the `checks` fingerprint component of paths that use
forms, the ids of unrouted paths whose root came from test code, and the coverage counts can change, so
the first `diff` against a v1 lock can report many findings. Re-run `init` (or `update` and re-review).

## Not implemented

* **C5 assurance labels** (NIST AAL / phishing-resistant), and any policy engine.
* **Multi-request state machines.** allauth login stages, the two-factor-auth formtools
  wizard, the dj-rest-auth ephemeral token, Django's password-reset session token and
  social-auth partial pipelines are not modelled. Library-internal flows are reported
  as `library_flow_checks_not_analyzed`. Project code that reads `request.session` only
  gets a context note, except **(v5 review)** a session key read back to load a principal (`pk=`/`id=` lookup),
  whose writes are hand-rolled session-login mints.
* **Library internals.** MintMap never analyses library code for checks. Settings
  conditions inside libraries (allauth `MFA_ENABLED`, dj-rest-auth `USE_JWT`, ...) are
  not evaluated; a library include lists every catalog mint it *can* expose.
* **Token consumers.** Mints are not linked to the places where the token is accepted.
  JWT claims are not analysed. A challenge token "gaining full-access privileges" is
  only caught indirectly, through fingerprint or evidence changes on the paths involved.
* **External MFA/SSO** (proxy, IdP `acr`/`amr`) cannot be seen. `RemoteUserMiddleware`
  and OIDC flows are reported as library flows.
* **Project decorators.** Their checks and mints are not analysed; they are reported as
  `project_view_decorator_not_analyzed` / `class_decorator_not_analyzed` gaps.
  `method_decorator(login_required, name="dispatch")` is not recognised as a gate.
* **Signals, Celery tasks and management commands** are not linked to triggers, except **(v5 review)** Django
  `pre_save`/`post_save` receivers registered for a project model (`@receiver(..., sender=M)`, `sig.connect(f,
  sender=M)`), which are called from every creation / `save()` of `M` on a path. Other mints there appear as
  `unrouted:` paths. Test code is excluded by default (v2); with
  `--include-tests` its mints appear as `unrouted:` paths. `django.test.Client.login` is unmapped.
* **Extract-function refactors that the conservative inliner does not cover (v5 part B, R8):** a helper in another
  module or class (`self.h()` may be overridden), a helper with a `return` inside control flow, a helper called with
  expressions as arguments (substituting them would evaluate them several times), extracting the mint call itself
  (the mint site moves to another function, so the path id changes: `new_path` + `removed_path`), and inlining into
  a `while` condition. These still change the fingerprint (a false alarm, never a miss).
* **v3 limits of URL evaluation (P4):**
  * settings conditions are not evaluated (`if settings.X:` keeps both branches, `conditional`); a loop over
    a settings value uses the value found in the settings files, which a deployment may override;
  * URL patterns produced by objects (`integration.url_objects`, properties, class methods, routers other
    than DRF `router.register`, custom `AdminSite` instances' `.urls`), by methods or async functions, by
    `functools.partial`, or by values computed at runtime are gaps, not routes;
  * a dispatcher view's own checks (e.g. authentication done by the dispatcher before it calls the view) are
    not linked to the dispatched view's evidence (`view_dispatcher_not_analyzed` gap);
  * mints that are not catalog APIs stay invisible even when their route is now found (Zulip: a project redis
    login token; `django.test.Client.login`).
* **v4 limits (review fixes):**
  * static conditions are decided only for strings that MintMap knows exactly (`==`, `!=`, `in`,
    `not in`, `not`, `and`, `or`, literal constants). Numbers, booleans held in module constants, function
    calls and every settings value are not decided, so both branches are kept and marked `conditional`;
  * alternatives are over-approximated: every branch, handler and imported alternative is kept,
    `conditional`, and a conditional route never hard-shadows a later one (it only "may shadow");
  * a list imported from another project module is modelled by that module's final value. Import order,
    circular imports and a list changed after it was imported elsewhere are not modelled;
  * check-argument evaluation covers only the `disabled_if` arguments of catalog checks (today the PyJWT
    decode functions). A value passed in through a project function's parameter is unknown, and so is a
    `check_argument_not_static` gap, even when every caller passes the same constant. A constant changed
    in place, or reassigned to different values, is unknown;
  * route variants are combined (union of code and mints, intersection of gates). The displayed route and
    its shadowing come from the least-shadowed variant, so a variant that is shadowed in its own root is
    not reported as shadowed;
  * the backend rule uses the usual wrapper classification: a falsy constant return is failure, anything
    else is success.
* **v3 limits of shadowing (P5):** only literal equality is modelled. Not modelled: a `re_path` that matches
  the same URL as a `path` (or two different regexes that overlap), converters that overlap (`<str:x>` vs a
  literal segment, `<path:p>` catch-alls), prefix-only regex includes, middleware or view-level dispatch that
  hides a route, and routes with a part MintMap cannot evaluate (`<dynamic>`). Library includes take part only
  through the 13 `library_url_routes` rows of catalog v2 (Django admin and `contrib.auth.urls`, DRF browsable
  API login, two_factor, knox, hijack, mozilla-django-oidc); allauth, dj-rest-auth, djoser and social-auth
  flows are reachable from several sub-routes or depend on settings and are not listed, so they are never
  marked shadowed. Shadowing is computed per root URLconf; a project-wide "reachable from some root" view is
  not computed.
* **v2 limits of the unrecognized-check heuristic:**
  * it is name-based: a verification step whose name does not match (e.g. `token == stored`, or a
    helper called `is_good_code`) is still invisible unless it is a catalog check. P2 makes such code
    part of the `checks` fingerprint when it sits in a form/serializer validation method used on the
    path, but not when it is in an arbitrary helper (only the callee closure covers it there);
  * names that match but are not authentication checks (`validate_email_not_already_in_realm`,
    `check_password_strength`, `verify_UTC` ...) are reported too (noise; see the dev numbers below);
  * unrecognized checks are propagated through at most 2 project wrapper levels, and only through
    wrappers whose result depends on them;
  * forms validated in a helper that is not on the entry→mint chain, and a variable that may hold
    several form classes, give implied edges and fingerprints but no form-level check record.
* **v2 limits of test-code exclusion:** only imports re-include a test-named module. A production
  module named like a test and referenced only by a string (URLconf `include("x.tests.urls")`, a
  settings dotted path) stays excluded; its mints are not inventoried (a locked path from it shows up
  as `removed_path`; the unresolved reference may show up as a URLconf or middleware gap).
* Guard analysis does not track a check result stored in an attribute (`self.user = authenticate(...)`
  then `if self.user is None: raise`), so such form `clean` methods are `present_unproven`.
* **Other resolution limits:**
  * `getattr`, `functools.partial`, functions passed as values (except the gap for
    `login` passed as a parameter), `sync_to_async`, and decorators that wrap views at
    runtime are not resolved;
  * `self.attr` types, containers and aliasing are not modelled;
  * no type stubs are used.
* **Dependency lock files**, and library versions that are not pinned in
  `requirements*.txt` or `pyproject.toml`.
* **GitHub enforcement** (CODEOWNERS, rulesets, required reviews, protected workflow). The prototype had none.
  Release 0.5.0a1 adds a composite GitHub Action and the guidance in [ENFORCEMENT.md](ENFORCEMENT.md); the GitHub
  settings there are derived from GitHub's documentation and have not been tested on a live repository.
* **v5 review-round limits (documented, not fixed):**
  * settings alternatives over-approximate: every leaf settings module that is not named as test settings is
    analysed, so a development-only module's hook classes are bound and fingerprinted too (a change to a dev-only
    adapter is a finding: reviewer mutation `mp5 d_local_adapter_change`, exit 4 where "quiet" was expected); test
    settings modules (name `test`/`tests`/`testing` part) are only listed in `settings_module_not_analyzed`;
    `DJANGO_SETTINGS_MODULE` values in Dockerfiles / compose / `.env` files are not read;
  * per-request URLconfs are found only from dotted string literals, `settings.X` values and `*_URLCONF` settings;
    a URLconf chosen through a computed value or a tenant library's own setting name not ending in `URLCONF` is
    parsed as an unreached URLconf (with its path gap) instead;
  * Channels: only `channels.routing.URLRouter` with a list display (directly or through a name); a consumer's
    every project method is an entry function; other ASGI routers / protocol servers are not modelled (mints there are
    `unrouted:` paths);
  * the dependency-version rule compares major lines (and bounds) of declared specifiers only; lock files are still not
    read; dj-rest-auth below 3.0 additionally has hook rows for its legacy settings (`REST_AUTH_SERIALIZERS`,
    `REST_AUTH_TOKEN_CREATOR`, `REST_AUTH_REGISTER_SERIALIZERS`), other old versions only get the gap;
  * the hand-rolled session rule needs a consumer that loads the principal with a `pk`/`id`/`*_id` lookup of the
    session value; a consumer that uses the value differently (a cache lookup, `get_user(session_id)`) is not seen;
  * R3 remains name-based (`STRONG`, `WEAK`, `QUALIFIERS`, `NEGATIVE` in `credentials.py`). The `NEGATIVE` list was
    collected while reading development-project candidates (asset, attachment, anchor, label, username, OAuth `state`,
    `public`, ...): general non-credential nouns, but chosen on the development set. A credential stored only under a
    weak word on a model that is neither credential-named nor related to the user model (a device `code` of a
    machine) is set aside (reason in `coverage.custom_credentials.set_aside`). The library-credential heuristic for
    uncatalogued packages is name-based too (class head noun / function name);
  * a heuristic site reached from 6 or more entry points is one lock entry: a new entry point reaching it is a
    `fingerprint_changed` (bit 4) on that entry, not a `new_path` (bit 1);
  * more code is hashed (module-level values read by path code, every method of classes handed to library flows),
    so harmless edits of a module constant or of an unrelated serializer method can now be findings.
* **No held-out evaluation of v5 at the time of writing.** Frozen v4 was evaluated on paperless-ngx, netbox and
  plane (round 2); v5 was developed with those projects in view, so its numbers on them are development-set
  numbers. Frozen v5 was later evaluated on a fresh held-out set (InvenTree, Weblate, pretix: round 3, see
  [EVALUATION.md](EVALUATION.md)); on those projects it missed 30% of credential units silently.

## Known limitations (expected sources of false alarms and misses)

* The overlay is hand-written and must be maintained per library release. It was
  checked against the latest release of each package; older versions (for example the
  pre-`internal.flows` allauth API) are covered only where an alias was added.
* Method-name matching (`verify_token`, `check_password`, `is_verified`,
  `verify_is_allowed`) can match unrelated objects. Such evidence is labelled
  `via: method_name`.
* Some unresolved calls are flagged as gaps when their name matches any project
  function name. On large code bases this is noisy.
* **CBV hook dispatch** assumes that an unknown library base defines `post`/`create`
  (only `View`, `APIView`, `GenericAPIView`, `ViewSet` and `TemplateView` are known not
  to). An over-approximated hook entry can make a guard look `present_unproven`.
* **Fingerprints** (v5 part B) alpha-rename function-local variables and inline extracted same-module helpers;
  other refactors (moving code between modules or classes, renaming parameters or attributes) invalidate the review.
  A global settings change is one settings-group finding (v5 part B), but a Django version change still invalidates
  every path (`deps`). The callee closure (depth 4) can pull in unrelated helpers and cause extra invalidations; a
  hook class (e.g. an allauth adapter) is fingerprinted as a whole on every path of its package, so a change to one
  adapter method invalidates every flow of that package (review finding L3, not fixed: e.g. a dj-rest-auth
  `LOGIN_SERIALIZER` edit also invalidates the registration and password-change paths, and simplejwt
  `TOKEN_OBTAIN_SERIALIZER` is attached to the refresh view too).
* **Same-user dataflow** compares variable names and parameter positions only.
  `same_user=shown` is evidence, not proof.
* **Guard analysis** is intraprocedural, per function on the chain. It ignores loops,
  exceptions raised by non-check calls, and `match` statements.
* **Wrapper classification** treats returning a falsy constant as failure and anything
  else as success.

## Tests

`python3 -I -m unittest discover -s tests -v` runs **268 tests, all passing**
(`Ran 268 tests ... OK` on the last run with Python 3.11, 3.12 and 3.13; 64 v1 tests + 29 v2 tests + 32 v3 tests +
28 v4 tests + 38 v5 part A tests + 31 v5 part B tests + 46 v5 review-round tests).

v5 review-round test file (`tests/test_v5c.py`; synthetic projects written into temporary directories with the helpers
of `test_v5.py`; neither development-project nor reviewer fixture code is copied). 39 of its 46 tests fail when run
against a copy of the part-B prototype (`0.5.0-proto` before this round, with the new catalog); the other 7 are 5
controls (one extracted helper still inlined, a walrus in a comprehension, a session key nobody reads back, a heuristic
site reached from 3 entries keeps one path each, an outbound webhook secret on a fetched or untyped object is set
aside) and 2 tests of catalog v3 rows added this round (legacy dj-rest-auth hook rows, the AccountMiddleware /
JWTAuthentication declarations), which pass on the old prototype once it reads the new catalog:
* `InlineCoverageTests` (3, F1/F4): a nested helper the outer caller cannot inline (caller-local import shadowing its
  free name) and a chain deeper than the inlining budget are hashed; one extracted helper still gives exit 0.
* `ComprehensionScopeTests` (4, F3): a comprehension variable named like a called global; renaming a comprehension
  variable (also inside a gap key: comprehension variables get canonical names there too); a walrus in a comprehension
  binds in the function.
* `SettingsInPlaceTests` (5, F5): item `+=`, `.setdefault(k, []).append`, `.get(k).append` (evaluated: the
  `settings:REST_FRAMEWORK` entry changes and names the added class); unfollowed changes are
  `setting_partially_unknown` gaps.
* `SplitSettingsTests` (3, F8/F9): a leaf settings module not named by `DJANGO_SETTINGS_MODULE` is analysed as an
  alternative (both adapters bound, its REST_FRAMEWORK item store kept), a change in it is detected, test settings are
  listed in a gap; differing scalars under `if` are `Alternatives`.
* `CoreSettingsTests` (2, F22/L1): `SESSION_COOKIE_AGE` is one `settings:AUTH_CORE` finding; a project password
  hasher's source is hashed.
* `InjectedCodeTests` (3, F2/F10): a project serializer handed to a non-minting library view (`CreateAPIView.as_view(
  serializer_class=...)`) gives a new path; `LoginView.as_view(authentication_form=F)` with `confirm_login_allowed`; a
  form set through the `authentication_form` attribute.
* `LibraryKnowledgeTests` (5, F7/F14/F15/L3): hook target in an uncatalogued package; `admin.site.__class__ = ...`
  (removing it, or changing the project site class); a version outside the catalog; the legacy dj-rest-auth serializer
  setting; catalog v3 declarations of common components.
* `ModuleValueTests` (2, F6): a setting read at import time into a module constant is a path dependency; changing the
  module constant itself is detected.
* `UrlconfRootTests` (3, F11/F19): `request.urlconf` and a `*_URLCONF` setting are roots; an unreached URLconf is
  inventoried with a path gap (a new minting route in it is `new_path`); a regular `apps/` package on `sys.path`.
* `CredentialShapeTests` (7, F12/F13/F21): seven shapes found, a voucher code set aside; weakening the hashed key, a
  helper-stored token, a signal-receiver key, a default generator; extracting the store into a helper keeps the path;
  an outbound secret on a fetched model (`x = M.objects.get(...)`, typed now) or an untyped `webhook` object is set
  aside (the receiver's name counts for the outbound-integration rule).
* `SessionLoginTests` (2, F16): a session key read back as a principal is a mint; without a consumer it is not.
* `LibraryTokenTests` (3, F17/F18): `AccessToken.objects.create` (catalog), an uncatalogued `create_key`, a Channels
  websocket login on an `asgi:` entry.
* `ReviewNoiseTests` (4, F20): a site reached from 7 entries is one entry and one finding; a new entry point changes
  it; 3 entries keep 3 paths; the depth limit only clears `fingerprint_complete`.

Changed earlier expectations in the v5 review round (3): `test_v5.MiddlewareAuthClassTests` used
`allauth.account.middleware.AccountMiddleware` and simplejwt `JWTAuthentication` as examples of undeclared
catalogued-package classes; catalog v3 now declares both (read in the source), so the two tests use
`allauth.usersessions.middleware.UserSessionsMiddleware` and `JWTTokenUserAuthentication` instead (same assertions);
`test_review_v4.CheckArgumentTests.test_changing_only_the_constant_is_detected` now expects the components
`["checks", "code"]` instead of `["checks"]`: the view reads the module constant itself, whose statement is now part
of `code`.

v5 part B test file (`tests/test_v5b.py`; synthetic projects written into temporary directories with the helpers of
`test_v5.py`; no development-project code is copied). 23 of its 31 tests fail when run against the frozen v4 copy
(checked in a scratch copy); the other 8 are controls that must keep detecting a change (swapped variables, renamed
attributes / keyword arguments / parameters, `locals()`, a later change of an inlined helper, helpers that must not be
inlined, a new minting middleware):
* `CustomCredentialTests` (5, R3): a secret generated in a model's `save()` reached through a DRF view's
  `perform_create(serializer)` (path at the `secrets.choice` call, chain through `save()`); a model field default ->
  `M.objects.create` site and the library create flow of a `ModelViewSet`; a one-time code stored in the cache and a
  random password that is e-mailed; set aside: OAuth `state`, a file name, a random unusable password, an outbound
  hook secret, an unsaved instance, an update save, a primary key, a `UUIDField` identifier; a new route to the token
  view is a `new_path` and shortening the generated secret is `fingerprint_changed`.
* `SettingsGroupTests` (9, R7): one lock entry per group (unreviewed -> 64, accepted -> 0); a global middleware change
  is one finding that names the added item; a new minting middleware is still a `new_path`; a project backend change
  reaches the `authenticate()` path and the backends group but not a DRF token path; DRF default permission classes
  are a dependency only of views that use them; a non-authentication REST_FRAMEWORK key is not a change; a setting
  read by a middleware and the condition that adds it to `MIDDLEWARE` are dependencies of that middleware's path only;
  a catalog flow setting (`ACCOUNT_LOGIN_ON_PASSWORD_RESET`) changes only that flow's path and the allauth group;
  `update` keeps the review of unchanged groups.
* `HookTests` (5, R5): a project `ACCOUNT_ADAPTER` is in the `hooks` component and evidence of every allauth library
  flow (not of DRF token views) and making its gate accept everything is exit 4 on exactly those paths; a mint inside
  a project `HEADLESS_TOKEN_STRATEGY` is linked to the `allauth.headless.urls` route; a project default permission
  class is fingerprinted on DRF views that use the default only; `SOCIAL_AUTH_PIPELINE` functions and a project
  backend are fingerprinted on social-auth and library `LoginView` paths; a dynamic `ACCOUNT_ADAPTER` is a
  `hook_setting_not_static` gap on the allauth paths.
* `AlphaRenamingTests` (5, R8) and `ExtractFunctionTests` (7, R8): see "What changed in v5 (part B)".

v5 test file (`tests/test_v5.py`; each test writes a small synthetic project, and where needed a synthetic
"site-packages" directory that MintMap only reads through `--library-path`; no development-project code is
copied). 32 of its 37 analysis tests fail on frozen v4 (checked by running the file against the frozen v4 copy;
the CLI test `LibraryPathCliTests` needs the v5 option and was not run there); the other 5 are controls (the same project with `__init__.py` files, a complete include, a declared no-mint view,
known generic bases, an app without an admin module):
* `NamespacePackageTests` (5): a mint helper in a directory without `__init__.py` is routed; same-stem modules in
  two namespace directories do not collide; two `manage.py` roots and an unimported namespace module give a
  `module_name_ambiguous` gap; a module imported under two names (two roots) is one module with an alias; a
  source root found from `DJANGO_SETTINGS_MODULE` in `wsgi.py` without `manage.py`.
* `LibraryViewTests` (7), `LibraryIncludeTests` (3), `AdminRegistrationTests` (4), `MiddlewareAuthClassTests`
  (3), `LibraryCallAndBaseTests` (3): R2 (see "What changed in v5").
* `FingerprintReachTests` (2): a project serializer run by an inherited library flow, and a subclass override
  called from a base-class method, are in the fingerprint (a change to either is `fingerprint_changed`).
* `SettingsFunctionTests` (8): R4.
* `SubscriptedBaseTests` (2): R6.
* `LibraryPathCliTests` (1): `scan --library-path` end to end (`tool.library_paths`, version `0.5.0-proto`).

Changed earlier expectations in v5 part B (2): `test_lock.LockTests.test_settings_change_invalidates_every_path` now
expects ONE `fingerprint_changed` finding on `settings:MIDDLEWARE` (naming the removed middleware) instead of one per
path (R7; the test name is kept); `test_cli.CliTests.test_init_diff_accept_change_cycle` also accepts the settings
group entries of the lock before expecting exit 0 (they are reviewed like paths).

Changed earlier expectations in v5 part A (2): `test_unrecognized.CatalogV2CheckTests.test_default_catalog_is_v2_superset`
now expects the default catalog to be `django_catalog_v3.json` (still checks the v2 entries); and
`test_inventory.BasicInventoryTests.test_clean_fixture_has_no_gaps` now expects exactly one gap,
`library_include_mints_incomplete` for `include('allauth.urls')`: catalog v3 does not declare that URLconf's mint
list complete, and v5 no longer treats an incomplete catalogued include as fully known. All other expectations are
unchanged. No earlier test expectation was changed in v4.

v4 test file (`tests/test_review_v4.py`; each test writes a small synthetic project into a temporary
directory; one class per review finding, see "What changed in v4"):
* `CheckArgumentTests` (6): `jwt.decode` verification switched off through a module constant, an imported
  constant, `dict(CONST, verify_signature=False)`, `**{"options": {...}}`, a positional `options`, and
  `CONST | {...: 0}`, all `present_unproven`; a strict constant is still a guard; a parameter, a call result,
  a constant changed in place and `**settings.X` are unproven with a `check_argument_not_static` gap; a
  wrapper around a disabled check is unfaithful; changing only the constant to disable verification gives
  `fingerprint_changed` (`checks`) + `evidence_downgraded`; a benign constant change gives only
  `fingerprint_changed`.
* `TryExceptTests` (2): try body and handler both routed (conditional); a re-raising handler is not an
  alternative.
* `ConditionalImportTests` (3): `two_factor.urls` imported under `if` vs `[]` (conditional include and its
  library paths); a project list imported in `try` vs `[]` (routed, no unreached-URLconf gap); a view imported
  differently in the branches (both routes).
* `ImportedListTests` (4): `.append`, `.extend`, `.insert` (under an alias) and `+=` after a star import on an
  imported list.
* `RouteVariantTests` (4): a minting project decorator in either branch of an if/else, and under an alternative
  `ROOT_URLCONF` (path routed, decorator gap, `route_variants`); a gate counts only if every variant has it; a
  change to the non-displayed variant's route call changes the `code` fingerprint.
* `LoopControlTests` (3): static `break`/`continue` (no invented routes, nothing shadowed); `break` on an
  unknown condition (later iterations conditional, later route only "may be shadowed"); a comprehension
  filter decided statically.
* `BackendFactorTests` (3): a backend with `check_password` plus a `check_*` helper keeps `password`; a success
  exit guarded only by an unrecognized call is unverified; removing `check_password` is an `evidence_downgraded`.
* `LibraryClassTypingTests` (3): `pyotp.TOTP` local, chained `pyotp.totp.TOTP(...).verify`, `from pyotp import
  HOTP`, `django_otp.oath.TOTP`, and a form whose `__init__` builds `pyotp.TOTP` all give `otp: guards_mint`;
  with the v1 catalog the gap names `pyotp.TOTP.verify` instead of `?.verify`; a form clean method that
  accepts every pin gives exit bits 4|8.

v3 test file (synthetic fixture `urlbuild_project`, which does not copy dev-project code):
* `test_urlconf.py` (32):
  * `UrlListConstructionTests` (18): no unrouted path; a `ROOT_URLCONF` reassigned under `if` keeps both
    roots; a helper's view resolved through its parameters; a helper returning a list built in a loop
    (unconditional); views passed to a dispatcher in the route kwargs (`dispatched_by`, path gap); `include(x)`
    sees a later `x.append()`; `list(x)` is a snapshot; `i18n_patterns` prefix; `.extend()` and `.insert(0, ...)`;
    a loop over a settings list with f-string `include()` and `import_string()` (conditional); a
    `(patterns, app_name)` tuple; settings-conditional block and conditional expressions (list and view);
    a comprehension over a literal tuple; comprehensions/loops over unknown values are gaps; a project function
    that appends to the list passed to it; a list passed to an unknown callable is a gap; a runtime-chosen
    prefix becomes `{prefix}`; `LoginView.as_view(...)(request)` run from a function view.
  * `ShadowingTests` (8): a later literal-equal route (also under `{lang}/`) is shadowed with
    `status_if_reachable`; an earlier project `admin/login/` shadows only the admin login flow of
    `admin.site.urls`; an earlier `include("django.contrib.auth.urls")` shadows a later project
    `accounts/login/`; an earlier conditional route only "may shadow"; the same `{prefix}` placeholder compares
    equal; converter parameter names are ignored; `x/signin` vs `x/signin/`, `re_path` vs `path` and other
    roots are not compared; coverage counters.
  * `LockAndFingerprintTests` (6): unchanged project diffs clean; removing the shadowing endpoint gives
    `removed_path` + (`fingerprint_changed`, `evidence_downgraded` "no longer shadowed") on the other path;
    the same for the route that shadows the admin login flow (only that flow changes); a newly shadowed path is
    `fingerprint_changed` (`code`) only; changes to the dispatcher or to a URL helper change exactly the `code`
    component of the paths built with it; the lock records the shadowing.

v2 test files (synthetic fixtures `verify_project` and `testcode_project`):
* `test_unrecognized.py` (21): catalog v2 is a superset with source citations; pyotp in a form clean
  method through a typed `self.<attr>`; fido2 assertion in a project helper class (challenge
  generation not reported); `jwt.decode` and `verify_signature: False`; `signing.loads`; the v1
  catalog skips the optional overlay entries and the same TOTP path becomes `unrecognized_check_present`;
  an unknown library verifier in a form clean method (status, factor, gap, fingerprint); the gap is a
  global coverage gap; an unresolved receiver in a serializer `validate_<field>` (and `super().validate`
  ignored); a verify-named project function without a check; a call in a `try` with exiting handlers;
  a helper that ignores the call is not a check; the wrapper depth limit (and its documented miss); a
  check-named mint wrapper is not a check; a catalog non-check validator is ignored; P2: forms that are
  not checks (two candidate classes) get implied edges and are fingerprinted; a `form = None`
  placeholder; mutations: a recognised clean method accepting every code (exit includes 4|8), the same
  with the check unrecognized (v1 catalog), a change in a plain-comparison clean method (`checks`
  component only), a new unrecognized check is a coverage regression.
* `test_testcode.py` (8): path patterns; default exclusion and its coverage counts; re-inclusion of an
  imported test-named production module; `test.py` without `TestCase` is kept; `--include-tests`;
  a lock written with tests then scanned without them is a coverage regression; a new test file does not
  change the outcome; the CLI flag.

Changed v1 expectations (2): `test_lock.test_helper_that_accepts_every_otp` and
`test_cli.test_init_diff_accept_change_cycle` turn the fixture helper `verify_otp` into `return True`.
v2 additionally reports that verify-named function, which now contains no check, as an
`unrecognized_check_call` gap, so the findings for that path gain `coverage_regression` and the CLI
exit code is 44 (4|8|32) instead of 12. All other v1 expectations are unchanged.

* `test_inventory.py` (24):
  * aliases, module attribute access, a wrapper in another module, CBV `form_valid`,
    async `alogin`;
  * RemoteUserMiddleware from settings, `include('allauth.urls')`;
  * project middleware, JWT purposes, DRF Token, `post_reset_login`, a project subclass
    purpose note, an unrouted mint, `login` passed as a parameter;
  * a DRF router `@action`, routed library views, inherited and `super()` library-view
    mints, an `unknown`-purpose custom token, derived wrappers, dependency pins;
  * gap reporting.
* `test_evidence.py` (19): early-return guard, ignored OTP result, cross-module wrapper
  with same-user, framework gate, wrong-user verification, disjunction, assert-only,
  tuple-truthy, check after mint, swallowed exception, reassigned result, unverified
  backend, walrus, serializer `raise_exception`, `request.user` exchange context,
  `login_required` and DRF `IsAuthenticated` gates, and that the "no check" label is
  scoped to analysed code.
* `test_lock.py` (18):
  * review state: unreviewed fails, accepted passes;
  * fingerprints: a **formatting-only change keeps every fingerprint**; a **helper that
    starts accepting every OTP** changes the fingerprint (`callees` + `checks`) and
    downgrades evidence, on that path only; a helper that ignores the check result; a
    MIDDLEWARE change invalidates all paths (`settings`); a backend swap downgrades the
    password factor; an override in a library-view subclass invalidates the inherited
    path; a library upgrade changes only that library's paths (`deps`);
  * new and removed paths: a **new route to an existing wrapper** adds a path; removing
    a route turns the mint unrouted instead of dropping it; removing the view and route
    gives `removed_path`;
  * coverage: a **new parse failure is a coverage regression**; a broken file holding
    an approved path cannot stay green; a new exclusion is a regression; a new
    unsupported URL construct is a regression;
  * purpose changes; `update` keeps reviews only for unchanged paths.
* `test_cli.py` (3): `scan --json`; the `init` → `diff`(64) → accept → `diff`(0) →
  helper change → `diff`(12) → `update` → `diff`(64) cycle; usage and input errors (128).

The fixtures were written by the same author as the analyser, so passing tests show
that the implemented behaviour works on the cases it was designed for. They are not
evidence of recall or precision on real projects.

## Smoke runs on library source (robustness only, not accuracy)

v5 review round (all 23 unpacked library trees, including the newly unpacked `channels` and
`dj_rest_auth_legacy`, exit 0): Django 904 files about 14.8 s (55 paths, 123 gaps), django-allauth 838 files about
5.5 s (176 paths, 633 gaps), social-auth-core about 1.2 s, DRF about 1.0 s, every other tree under 1 s.

v4 re-run (all 21 unpacked trees exit 0; Django about 11.1 s, django-allauth about 5.6 s, DRF about 1.1 s,
every other tree under 1.1 s). Django, django-allauth, DRF and two-factor-auth give the same routes, paths and
gaps as v3.

v3 re-run (all 21 unpacked trees exit 0): Django about 10.4 s, django-allauth about 4.8 s (the former
`url_include_cycle` gap in `openid_connect/urls.py` was a false cycle, the list is rebound in an `if`, and is
gone; the 120 `unsupported_url_construct` gaps from function-built provider URLs are now expanded helpers
whose routes start with `<dynamic>` from `provider.get_slug()`, i.e. 117 `dynamic_route_pattern` gaps, and
the headless URL builders are now expanded too, giving 68 `unsupported_view_expr` gaps for
`View.as_api_view(client=...)` views, a view factory MintMap does not model;
`two_factor/urls.py`'s `(patterns, app_name)` tuple is understood), DRF about 0.9 s, every other tree under
1 s. Healthchecks about 1.5 s, Zulip about 19 s.

v2 re-run (the development machine, after memoising `normalize()` and caching `self.<attr>` assignments): Django
904 files about 10.3 s (frozen v1 about 10.1 s here), django-allauth about 4.4 s (frozen v1 about 16 s
here), DRF about 0.9 s, dj-rest-auth, django-otp, two-factor-auth, djoser, fido2, pyotp and PyJWT under
1 s; all exit 0. Test code inside these trees is now excluded by default. Dev projects: Healthchecks
417 analysed files (238 test files excluded) about 2 s; Zulip 1769 files (270 excluded, 5 re-included
because non-test code imports them) about 17-24 s (v1: 2039 files, about 42 s).

Dev-set noise of the unrecognized-check heuristic: Healthchecks 1 `unrecognized_check_call` gap
(`profile.check_token` with an unresolved receiver in a project authentication backend); Zulip 22
distinct gaps, 6 paths labelled `unrecognized_check_present` (e.g. `check_prereg_key`, the registration
confirmation-key check, which is relevant; several are input or policy validators such as
`validate_email_not_already_in_realm` or `check_password_strength`).

v1 table (original runs). The unpacked library sources were scanned as if they were projects. All
runs completed (exit 0):

| tree | files parsed | time | notes |
|---|---|---|---|
| Django | 907 | about 7.4 s | – |
| django-allauth | 838 | about 2 s | before the fix, an include cycle caused a RecursionError; now reported as a `url_include_cycle` gap; 120 `unsupported_url_construct` gaps from function-built provider URLs |
| DRF | 73 | about 0.6 s | – |
| dj-rest-auth | 41 | about 0.7 s | – |

Ten smaller packages also completed. These runs found two crash or noise bugs that
were fixed: the include cycle, and name collisions such as admin
`ChangeList.get_query_string` versus sesame's `get_query_string` and SMTP `.login`.
No inventory numbers from these runs should be read as accuracy figures.

## Review enforcement (superseded)

The prototype only proposed review enforcement (CODEOWNERS for the lock, the MintMap code, the catalog and the
workflow; a ruleset requiring code-owner review and the MintMap check; a workflow the pull request cannot change).
Release 0.5.0a1 replaces that proposal with [ENFORCEMENT.md](ENFORCEMENT.md) and a GitHub Action. None of it has been
tested on a live repository.

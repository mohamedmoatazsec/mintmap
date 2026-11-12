# Evaluation

MintMap was developed and measured on eight open-source Django projects in three rounds. Round 1 was development.
In rounds 2 and 3 the tool was frozen first and then measured on projects it had not been tuned on (paperless-ngx
only weakly so: a v1 scan was run on it during round 1, but no fix targeted it). Ground truth for each project is an
inventory of every way to obtain a session or credential, compiled by reading the code by a separate AI agent
that never saw the tool or its output (not by humans; inventories have errors, and verifiers corrected some).
Every Round 3 number below was re-checked by an adversarial AI verifier that re-ran the tool and tried to refute the scoring. The
"Round 2 → 3" numbers come from an automatic regression harness and were not re-checked by a verifier.

## Method

- **Unit** = (entry point, mint site). Classes: **S** full session, **T** bearer/long-lived credential (API key,
  DRF/JWT token, OAuth token), **P** precursor (reset/magic/invite token, MFA challenge state, step-up).
- **Verdicts**: *exact* (same mint, same entry point), *mint only* (mint found but not linked to its route),
  *gap* (an explicit analysis gap names this unit), *silent* (nothing in the output points to it).
- **Mutation tests**: copy the project, create and accept a lock, apply one realistic change, run `mintmap diff`.
  Nine required categories per project (new login path, ignored MFA result, verifier accepts all, auth settings
  change, challenge state gains full access, legitimate recovery flow, and three harmless refactors), plus
  project-specific extras.

| round | tool | measured on | role |
|---|---|---|---|
| 1 | v1–v4 | healthchecks, zulip (plus one v1 scan of paperless-ngx) | development |
| 2 | v4 frozen | paperless-ngx (weakly held-out), netbox, plane | held-out, then used to develop v5 |
| 3 | **v5 frozen (released as 0.5.0a1)** | **InvenTree, Weblate, pretix** | **fresh held-out** |

Release 0.5.0a1 is frozen v5 plus packaging and the fixes of a release review: fingerprints, gap keys and settings
values that do not depend on the Python version (identical to v5's on Python 3.13, the version the evaluation ran
on, except that non-ASCII string literals are escaped in fingerprints), a CLI that exits 128 instead of crashing,
and a hardened GitHub Action. Replaying the 127 saved mutations of seven projects (all rounds; Zulip has none, and
the verifiers' own probes were not saved with them) without `--library-path` on Python 3.13 gives identical exit
codes and findings, including path ids, with v5 and with the release.

## Round 3: v5 on projects nobody looked at during development

### Inventory recall

| project | units | exact | mint only | visible as gap | **silent** |
|---|---|---|---|---|---|
| InvenTree | 44 | 9 | 3 | 27 | **5 (11%)** |
| Weblate | 36 | 14 | 7 | 3 | **12 (33%)** |
| pretix | 69 | 33 | 7 | 1 | **28 (41%)** |
| **total** | **149** | **56 (38%)** | 17 | 31 | **45 (30%)** |

By class: full sessions 17 of 51 silent (33%), tokens 12 of 54 (22%), precursors 16 of 44 (36%).
False alarms: 127 of 230 reported paths (55%); on day one a reviewer looks at 260 lock entries, 130 of them not
real credential paths. Reading installed library source (`--library-path`) did not change these numbers.

"Visible as gap" is weaker than it sounds for most of those 31 units: 24 of them (InvenTree's allauth headless API)
are visible only through global `unsupported_url_construct` gaps naming allauth's `build_urlpatterns()`. Those gaps
are not attached to any path entry and appear only in `--json` output (the text report lists the first 40 gaps;
InvenTree has 131).

**Check evidence.** On the matched units the verifiers judged, the recorded check evidence agreed with the
inventory on 5 of 60, was weaker than the truth but not false on 43 (for example "relationship unproven" or
"library flow checks not analysed"), and was wrong on 12 (InvenTree 2 of 11, Weblate 6 of 16, pretix 4 of 33), for
example claiming that a check guards a mint when it does not. On InvenTree, `evidence_downgraded` fired in none of
the 23 mutations.

### Change detection (lock + diff)

| set | harmful changes caught | missed (exit 0) | harmless changes flagged |
|---|---|---|---|
| 9 required categories × 3 projects | 14 / 18 | 4 / 18 | 0 / 9 |
| all mutations, incl. extras and verifier probes | 40 / 58 | 18 / 58 (31%) | 4 / 20 |

Of the 20 harmless changes, 16 were refactors and 3 of those raised a finding; all three were extract-function
refactors (3 of 8 extractions). The fourth false alarm was an edit to an error-logging call in an unrelated module
that sat in the check closure of a false-alarm path. Of the 18 harmful changes that passed with exit 0, 8 were on
paths that already had lock entries: the changed check sat outside every fingerprint (for example the verification
forms behind Weblate's main TOTP login, and pretix's central password backend).

Verifiers noted that some required targets sit in code the tool handles best. All four should-flag probes they
added themselves (a customer magic-link login, a customer password-recovery auto-login, an SSO completion route,
and a token action on the admin API router) passed with exit 0.

### Why it misses (fresh projects)

1. Hand-rolled sessions whose keys are built at runtime (f-strings, `str.format`, keys in variables).
2. Credentials created through related managers (`team.tokens.create(...)`) or Django `CreateView` saves.
3. Project code calling a library's auth flow directly (for example `social_django.views.complete()`).
4. Settings computed by function calls (`MIDDLEWARE = CONFIG.get(...)`), which hides middleware logins.
5. An admin site swapped inside a function.
6. Session step-up grants and admin-chosen passwords, which MintMap does not model as credentials.

Visible as gaps but not linked: library URL builder functions such as allauth headless `build_urlpatterns()`.
Main false-alarm sources: library flows that settings disable (e.g. `HEADLESS_ONLY`), heuristic custom-credential
candidates that are not credentials, duplicated URL-prefix routes.

## Round 2 → 3: what the v5 fixes changed on the projects they were built against

On paperless-ngx, netbox and plane (round-2 held-out, then used for development), an automatic regression harness
that replays the saved mutations shows v4 → v5: required harmful mutations missed 8/18 → 0/18 and required harmless
ones flagged 6/9 → 0/9; over all saved mutations, harmful missed 14/34 → 0/34 and harmless flagged 8/12 → 0/12. An
automatic unit scorer (it matched every adjudicated v4 verdict) counts units missed silently 17/64 → 2/64; the v5
verdicts that changed were not adjudicated. These are results on the projects the fixes were built against, and no
verifier re-checked them. Round 3 shows these gains do not transfer fully to new codebases: v4 missed 27% of units
silently on its held-out projects, v5 missed 30% on its fresh ones.

## What this means for you

- **Change detection on paths MintMap reports is the stronger part**: `diff` catches most changes to the code it
  fingerprints, and harmless refactors are mostly ignored. But checks reached through runtime-built backends, forms
  or settings helpers may sit outside every fingerprint: on fresh projects 18 of 58 harmful changes passed, 8 of
  them on reported paths.
- **The inventory is not complete.** Expect roughly a third of credential paths in an unfamiliar codebase to be
  missing without a gap, especially custom session handling and custom token models. Read the gap list (the text
  report shows the first 40 gaps; `--json` has all of them), and add your own review of custom auth code.
- Raw data, scoring files and verifier reports for every round are kept with the development history; ask in an
  issue if you want them.

# Evaluation

How often MintMap misses things, how much noise it makes, and how these numbers were measured.

## At a glance

Release 0.6.0a1, frozen and then run on three Django projects nobody had looked at while it was built (CVAT,
Label Studio, Tandoor):

| Question | Result |
|---|---|
| Credential paths found and linked to the right route | 28 of 66 (42%) |
| Found only as an unlinked mint, a candidate or a named gap (4 of the 11 gaps only in `--json`) | 30 of 66 (45%) |
| Credential paths **missed with no warning** (scoring judgement calls: 4 to 12) | **8 of 66 (12%)** |
| Reported paths that are not real credential paths | 25 of 58 (43%) |
| Lock entries to review on day one / of which false alarms | 88 / 33 |
| Harmful code changes caught by `diff` | 42 of 65 (65%) |
| Harmless changes that raised a finding | 7 of 22 |

On an earlier, harder set of unseen projects (InvenTree, Weblate, pretix), the previous version (0.5.0a1) missed
30% of credential paths with no warning. MintMap is a review aid, not a guarantee.

**On this page:** [How it was measured](#how-it-was-measured) · [Method](#method) ·
[Round 4](#round-4-v6-on-projects-nobody-looked-at-with-v5-as-a-control) ·
[Round 3](#round-3-v5-on-inventree-weblate-pretix) · [Round 2 → 3](#round-2--3) ·
[What this means for you](#what-this-means-for-you)

## How it was measured

MintMap was developed and measured on eleven open-source Django projects in four rounds. In every round after
the first, the tool was frozen first and then measured on projects nobody had looked at while building that
version.

- **Ground truth** for each project is an inventory of every way to obtain a session or credential. A separate AI
  agent compiled it by reading the code, without ever seeing the tool or its output.
- **The inventories were not written by humans.** They contain errors, and verifiers corrected some of them.
- **Every held-out number below was re-checked** by an adversarial AI verifier that re-ran the tool and tried to
  refute the scoring.
- **The "dev set" numbers** come from an automatic regression harness and were not re-checked by a verifier.

| round | tool | measured on | role |
|---|---|---|---|
| 1 | v1–v4 | healthchecks, zulip (plus one v1 scan of paperless-ngx) | development |
| 2 | v4 frozen | paperless-ngx (weakly held-out), netbox, plane | held-out, then used to develop v5 |
| 3 | v5 frozen (released as 0.5.0a1) | InvenTree, Weblate, pretix | held-out, then used to develop v6 |
| 4 | **v6 frozen (released as 0.6.0a1)**, with v5 as a control | **CVAT, Label Studio, Tandoor** | **held-out** |

Release 0.6.0a1 is the frozen v6 tree (tag `v0.6.0.dev0-frozen`, commit `fed05c8`) plus documentation and the
version string. No analysis code changed after freezing.

## Method

- **Unit** = (entry point, mint site). Classes: **S** full session, **T** bearer/long-lived credential (API key,
  DRF/JWT token, OAuth token), **P** precursor (reset/magic/invite token, MFA challenge state, step-up).
- **Verdicts**, strongest that applies: *exact* (a confirmed path with the same mint at the same entry point),
  *mint only* (the mint is a confirmed path but not linked to this entry point), *candidate* (only a candidate site
  names it), *watched* (only a watched site names it), *gap* (an explicit analysis gap names this unit's file,
  function, route or include), *silent* (nothing in the output points to it).
- **False alarms**: every reported item that matches no inventory unit was adjudicated by reading the code.
- **Mutation tests**: copy the project, create and accept a lock, apply one realistic change, run `mintmap diff`.
  There are nine required categories per project: new login path, ignored MFA result, verifier accepts all, auth
  settings change, challenge state gains full access, legitimate recovery flow, and three harmless refactors.
  Project-specific extras and the verifiers' own probes come on top.
- **Control** (round 4): frozen v5 was run on the same projects, with the same units and the same mutations.

## Round 4: v6 on projects nobody looked at, with v5 as a control

CVAT (commit `b090415c`), Label Studio (`3003ccaa`), Tandoor (`cbb96e15`). The agent transcripts were checked to
confirm that no agent that changed or reviewed the tool opened these projects or their inventories.

### Inventory recall

| project | units | v6 exact | v6 mint only | v6 candidate | v6 gap | **v6 silent** | **v5 silent** |
|---|---|---|---|---|---|---|---|
| CVAT | 15 | 9 | 1 | 0 | 2 | **3** | 4 |
| Label Studio | 21 | 8 | 8 | 0 | 2 | **3** | 4 |
| Tandoor | 30 | 11 | 9 | 1 | 7 | **2** | 3 |
| **total** | **66** | **28 (42%)** | 18 | 1 | 11 | **8 (12%)** | **11 (17%)** |

v5 on the same units: 26 exact, 18 mint only, 11 gap, 11 silent. No unit was found only through a watched site.

By class (v6 / v5 silent): full sessions 0 of 28 / 0, tokens 4 of 26 / 7, precursors 4 of 12 / 4. v6 is better
than v5 on 3 units and worse on none.

Notes on these numbers:

- **Scoring judgement calls** move the v6 silent count between 4 and 12. They are: how specific a gap must be,
  whether an invitation stored in the session is a credential, and whether a match through a false-alarm path
  counts.
- **`--library-path`** (wheels at the pinned versions) changed no verdict on any project.
- **Settings module.** For CVAT the tool analysed `cvat.settings.development` (the module `manage.py` names) and,
  as an alternative, `cvat.settings.email_settings`, which star-imports `cvat.settings.production`. MintMap has no
  option to choose one settings module. A verifier re-ran with production-only settings, and no unit changed.

"Gap" is weaker than it sounds for some units. 4 of the 11 are visible only in `--json` output: CVAT's
password-reset token and password change, and Label Studio's personal access token create and rotate (gaps at
positions 75 to 231 of the gap list: CVAT 75, 77 and 84 of 87, Label Studio 230 and 231 of 259; the text report
lists the first 40). Label Studio's personal access tokens, its main API
credential, do not appear in the review queue at all.

**Check evidence.** On the 42 matched units the verifiers judged, the recorded check evidence agreed with the truth
on 2, was weaker than the truth but not false on 38, and was wrong on 2. A common case is a login route reported
with "no check found" whose password check runs in a serializer or form that a library setting names.

### False alarms and review cost

| | v6 | v5 |
|---|---|---|
| confirmed paths that are not credential paths | 25 of 58 (43%) | 30 of 61 (49%) |
| candidate sites | 9: 1 real unit, 3 false alarms, 5 unclear (mostly code that checks a credential rather than issuing one) | – |
| watched sites | 4, all correctly set aside | – |
| lock entries a reviewer approves on day one | 88, of which 33 are false alarms | 82, of which 33 are false alarms |

Tandoor accounts for most v6 false alarms (16 of 25). A plugin loader edits settings at run time, so MintMap
cannot rule out the allauth flows that the static settings switch off. That `dynamic_setting` gap explains 10 of
the 16.

The verifiers also judged the review queue's ranking. It often points the wrong way:
- On CVAT and Tandoor, false alarms are among the few "high" entries.
- An administrator setting any user's password is filed as a low-risk precursor.
- On CVAT, a login that issues both a token and a session is labelled only as a token.

### Change detection (lock + diff)

| set | v6 caught | v5 caught | v6 harmless flagged | v5 harmless flagged |
|---|---|---|---|---|
| 9 required categories × 3 projects | 13 / 18 | 13 / 18 | 2 / 9 | 1 / 9 |
| all mutations, incl. extras and verifier probes | 42 / 65 (65%) | 36 / 65 (55%) | 7 / 22 | 8 / 22 |

23 of 65 harmful changes passed v6 with exit 0. Of v6's 42 catches, 9 name only the changed settings group, a
candidate group, a gap or a different path, not the login path whose behaviour changed.

The harmless changes that raised a finding were all realistic refactors:
- four extracted helper functions or methods, one of them named `_check_*`, which MintMap reads as a new
  unrecognised check;
- a value first held in a new local variable;
- a hook's local import moved to module level;
- a settings expression rewritten without changing its value (`365*60*24*60` → `60*60*24*365`).

### Why v6 still misses (general causes found by the verifiers)

1. A library's mint function called through the library's settings object (dj-rest-auth
   `api_settings.TOKEN_CREATOR(...)`): neither a mint nor a gap.
2. Credentials created or edited through the Django admin for project models (`ModelAdmin` save, actions, a token
   field in an admin form). MintMap links admin registrations only for models whose `save()` is a catalogued mint.
3. A settings module that star-imports its base module through a source-root alias (Label Studio). The star import
   is not resolved, so `INSTALLED_APPS`, `MIDDLEWARE`, `AUTHENTICATION_BACKENDS` and `REST_FRAMEWORK` are never
   read, and the scan reports only the unresolved import (`settings_star_import_unresolved`) and `missing_setting`
   gaps, not which settings the unread base module holds.
4. Hooks named in settings and loaded by a project helper (`load_func(settings.X)`). Also an adapter class
   re-exported from a package `__init__`, which MintMap resolves to the submodule.
5. DRF routers extended at run time (one global gap). Tokens created by `ModelSerializer.create()` through
   `super()`. Credentials written from request data by an update serializer.
6. Values whose field name carries no credential word (`InviteLink.uuid`), and session writes with no principal-like
   signal. These are set aside in the JSON report only, not watched.
7. Libraries outside the catalog (django-auth-ldap), and project code that only such a library calls (a key
   generator held by a manager, a model method the library calls to validate a key).
8. Not modelled at all: session lifetime and token revocation checks, project view decorators, and admin actions
   as entry points.

### Did the v6 development gains transfer?

Only partly. On the eight development projects, the units missed silently fell from 51 of 213 (v5) to 4 of 213, and
caught harmful changes rose from 80 of 98 to 98 of 98. Those are the projects the fixes were built against. On the
three unseen projects the gain over v5 is 3 units (11 → 8 silent) and 6 mutations (36 → 42 caught).

The round-4 projects were easier for both versions than round 3 was: v5 missed 30% silently on InvenTree, Weblate
and pretix, but 17% on CVAT, Label Studio and Tandoor. So compare v6 with v5 on the same projects, not across
rounds.

## Round 3: v5 on InvenTree, Weblate, pretix

This is the earlier held-out round. Its projects were then used to develop v6, so they are development data now.

| project | units | exact | mint only | visible as gap | **silent** |
|---|---|---|---|---|---|
| InvenTree | 44 | 9 | 3 | 27 | **5 (11%)** |
| Weblate | 36 | 14 | 7 | 3 | **12 (33%)** |
| pretix | 69 | 33 | 7 | 1 | **28 (41%)** |
| **total** | **149** | **56 (38%)** | 17 | 31 | **45 (30%)** |

- **By class:** full sessions 17 of 51 silent, tokens 12 of 54, precursors 16 of 44.
- **False alarms:** 127 of 230 reported paths (55%). On day one a reviewer looks at 260 lock entries, and 130 of
  them are not real credential paths.
- **Gaps:** 24 of the 31 gap units (InvenTree's allauth headless API) are visible only through global gaps in
  `--json` output.
- **Check evidence** agreed with the inventory on 5 of 60 matched units, was weaker on 43 and wrong on 12.

| set | harmful changes caught | missed (exit 0) | harmless changes flagged |
|---|---|---|---|
| 9 required categories × 3 projects | 14 / 18 | 4 / 18 | 0 / 9 |
| all mutations, incl. extras and verifier probes | 40 / 58 | 18 / 58 (31%) | 4 / 20 |

The root causes found in round 3 were the input of v6:

- hand-rolled sessions with run-time keys
- credentials created through related managers or `CreateView`
- library flows called directly
- settings computed by calls
- an admin site swapped in a function
- library URL builders

On the round-3 projects (now development data) v6 misses 4 of 149 units silently. That is the dev-set number
above, not a held-out result.

## Round 2 → 3

On paperless-ngx, netbox and plane (the round-2 held-out set, then used for development), an automatic regression
harness that replays the saved mutations showed v4 → v5:
- required harmful mutations missed: 8/18 → 0/18
- required harmless mutations flagged: 6/9 → 0/9
- units missed silently: 17/64 → 2/64

Round 3 then showed that these gains did not transfer fully to new codebases. v4 missed 27% of units silently on
its held-out projects, and v5 missed 30% on its own.

## What this means for you

- **The inventory is not complete.** On the latest unseen projects about 1 in 8 credential paths was missing with
  no warning, and on harder projects (round 3) it was closer to 1 in 3. Tokens and precursors (a registration token
  issued through a library setting, API keys created in the admin, invitation tokens) are missed far more often
  than login sessions. Read the gap list (the text report shows the first 40 gaps; `--json` has all of them), and
  add your own review of custom auth code.
- **Expect noise.** About 4 in 10 reported paths were false alarms. The ranking of the review queue is not reliable
  yet.
- **`diff` catches most, not all, harmful changes to the code it fingerprints.** On unseen projects about a third of
  harmful changes passed. Checks reached through settings-named serializers, library-called hooks and admin code
  are the usual reason.
- **Raw data.** Scoring files and verifier reports for every round are kept with the development history. Ask in
  an issue if you want them.

For the vocabulary used here (path, candidate, watched site, gap), see [CONCEPTS.md](CONCEPTS.md). The open
problems behind these numbers are tracked in [ROADMAP.md](ROADMAP.md).

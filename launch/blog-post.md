# We measured how often our auth-path scanner misses things

MintMap is a static-analysis tool for Django. It finds every code path that creates a login session or a
credential, writes the set to a lock file that a person reviews, and fails CI when a pull request changes that
set or the code on it. Whether that works is an empirical question, so we froze the tool and ran it on code
it had never seen. This post is about what came back.

## The set-up

MintMap was developed in four rounds on eleven open-source Django projects. In every round after the first, the
tool was frozen first and then measured on projects nobody had looked at while building that version. Those
projects then became development data for the next version.

For each project, a separate AI agent read the code and wrote an inventory of every way to obtain a session or
credential, without ever seeing the tool or its output. An adversarial verifier then re-ran the tool and tried
to refute the scoring.

We also wanted to know whether MintMap notices harmful changes. So we copied each project, accepted a lock,
applied one realistic change (a new login path, an MFA result that is ignored, a verifier that accepts
everything) and ran `mintmap diff`.

## The numbers

Release 0.6.0a1 on CVAT, Label Studio and Tandoor:

| | Result |
|---|---|
| Credential paths found and linked to the right route | 28 of 66 (42%) |
| Missed with no warning | 8 of 66 (12%) |
| Reported paths that are not credential paths | 25 of 58 (43%) |
| Lock entries to review on day one / of which false alarms | 88 / 33 |
| Harmful changes caught by `diff` | 42 of 65 (65%) |
| Harmless changes that raised a finding | 7 of 22 |

The remaining paths were visible only in a weaker form: as a mint not linked to its route, as a lower-confidence
candidate, or as an explicit analysis gap.

The misses are not spread evenly. No full login session was missed (0 of 28). Tokens (4 of 26) and precursors
such as reset and invitation tokens (4 of 12) were.

## What did not transfer

This is the result that changed how we work.

On the eight projects the tool was developed against, the newest version cut silent misses from 51 of 213 to 4
of 213, and caught 98 of 98 harmful changes, up from 80. Those numbers looked like a solved problem.

On the three unseen projects, the same version improved on its predecessor by 3 paths (11 silent misses down to
8) and 6 harmful changes (36 caught up to 42).

Every fix we made was real. It fixed a pattern in a project we had read. The next project had different
patterns. A development set, however large, only shows you the part of the long tail you have already walked.

The project set matters as much as the tool. The previous version missed 30% of paths silently on one set of
unseen projects (InvenTree, Weblate, pretix) and 17% on another. So we now only compare versions on the same
projects.

## Why it misses

The verifiers traced each miss to a cause. A few examples:

- A library's token function called through the library's settings object.
- Credentials created or edited through the Django admin for project models.
- Hooks named in settings and loaded by a project helper. That code is in no fingerprint, so weakening it passes
  the diff.
- Tokens created by a serializer through `super().create()`.

None of these is exotic. They are ordinary Django.

The check evidence is weaker still. On 42 matched paths, what MintMap said about the checks on the way agreed
with the truth on 2, claimed less than was true on 38, and was wrong on 2.

## The limits of the measurement

The inventories were written by AI agents, not by people. They contain errors, and verifiers corrected some of
them. Judgement calls in scoring move the silent-miss count between 4 and 12 of 66. Three projects is a small
sample.

## What we concluded

MintMap is a review aid, not a guarantee, and the README says so before anything else. On an unfamiliar
codebase, expect it to miss some tokens and precursors, to show you many false alarms on day one, and to let
about a third of harmful changes to auth code through.

We still think it is worth having. A reviewed list with known holes, and an explicit list of what the analysis
could not see, is better than no list. But that is only an honest claim because the miss rate is written next to
it.

If you build analysis tools: freeze, test on code you have not read, and publish the number you get.

The methodology and per-project results are in
[docs/EVALUATION.md](https://github.com/mohamedmoatazsec/mintmap/blob/main/docs/EVALUATION.md). MintMap is open
source and experimental: https://github.com/mohamedmoatazsec/mintmap

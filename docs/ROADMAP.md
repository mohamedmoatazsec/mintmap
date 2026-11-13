# Roadmap

MintMap is experimental. This page turns the known blind spots (from the [README](../README.md#known-blind-spots)
and [EVALUATION.md](EVALUATION.md)) into open work. Nothing here has a date. The order inside a section is a
rough priority, not a promise.

**How changes to the analysis are released.** The accuracy numbers describe one frozen version of the analysis.
A change to `src/mintmap/core/` or to the catalog makes them out of date, so such changes are collected and
released together with a new evaluation run on projects nobody has looked at.

## 1. Silent misses

These are paths MintMap does not report and does not list as a gap. They matter most, because nothing tells the
reviewer to look.

| Blind spot | Issue |
|---|---|
| A library's mint function called through the library's settings object (dj-rest-auth `api_settings.TOKEN_CREATOR(...)`) | [#1](https://github.com/mohamedmoatazsec/mintmap/issues/1) |
| Credentials created or edited through the Django admin for project models (`ModelAdmin` saves, admin actions, a token field in an admin form) | [#2](https://github.com/mohamedmoatazsec/mintmap/issues/2) |
| Tokens created by `ModelSerializer.create()` through `super()`, and credentials written from request data by an update serializer | [#5](https://github.com/mohamedmoatazsec/mintmap/issues/5) |
| Libraries outside the catalog (for example django-auth-ldap), and project code that only such a library calls | [#8](https://github.com/mohamedmoatazsec/mintmap/issues/8) |
| Values whose field name has no credential word (`InviteLink.uuid`) and session writes without a principal-like signal: set aside in the JSON report only, not watched | not filed yet |
| DRF routers extended at run time (one global gap today) | not filed yet |

## 2. Changes that pass `diff`

Code that is in no fingerprint can be weakened without a finding.

| Blind spot | Issue |
|---|---|
| Hooks named in settings and loaded by a project helper (`load_func(settings.X)`), and adapter classes re-exported from a package `__init__` | [#4](https://github.com/mohamedmoatazsec/mintmap/issues/4) |
| A settings module that star-imports its base module through a source-root alias: `INSTALLED_APPS`, `MIDDLEWARE`, `AUTHENTICATION_BACKENDS` and `REST_FRAMEWORK` are not read | [#3](https://github.com/mohamedmoatazsec/mintmap/issues/3) |
| No option to choose the settings module: MintMap follows `DJANGO_SETTINGS_MODULE` in `manage.py` | [#7](https://github.com/mohamedmoatazsec/mintmap/issues/7) |

## 3. False alarms

| Problem | Issue |
|---|---|
| An extracted helper named `_check_*` reads as a new unrecognised check | [#9](https://github.com/mohamedmoatazsec/mintmap/issues/9) |
| A settings expression rewritten without changing its value | [#10](https://github.com/mohamedmoatazsec/mintmap/issues/10) |
| A value first held in a new local variable; a hook's local import moved to module level | not filed yet |
| Moving code to another module or class changes the fingerprint | not filed yet |
| Library flows that static settings switch off but a run-time settings edit could switch on (Tandoor's plugin loader: 10 of its 16 false alarms) | not filed yet |

## 4. Reports and review cost

| Problem | Issue |
|---|---|
| The text report lists only the first 40 gaps; the rest are only in `--json` | [#6](https://github.com/mohamedmoatazsec/mintmap/issues/6) |
| No short form of the `scan` report | [#11](https://github.com/mohamedmoatazsec/mintmap/issues/11) |
| The review-queue ranking is not reliable: false alarms ranked high, an administrator setting any user's password ranked low, a login that issues both a token and a session labelled only as a token | not filed yet |
| Check evidence is usually weaker than the truth: password checks in serializers or forms named by a library setting are not seen | not filed yet |

## 5. Not modelled

No design exists for these yet. Ideas and examples are welcome in an issue.

- session lifetime and token revocation checks
- project view decorators
- admin actions as entry points
- signed cookies (`set_signed_cookie`) as credentials
- multi-request flows
- frameworks other than Django

## 6. Evaluation

- The reference inventories were written by AI agents, not by people, and contain errors. A human-written
  inventory for even one project would make the numbers more trustworthy.
- Three projects per round is a small sample, and the result depends on the project set (17% silent misses for
  0.5.0a1 on one set, 30% on another).
- Raw scoring files and verifier reports are not published yet.

## 7. Distribution

- First release on PyPI (the release workflow is in place; see [CONTRIBUTING.md](../CONTRIBUTING.md#releasing)).
- Listing the action on GitHub Marketplace.

## How to help

Pick an issue labelled
[`good first issue`](https://github.com/mohamedmoatazsec/mintmap/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22),
[`help wanted`](https://github.com/mohamedmoatazsec/mintmap/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) or
[`catalog`](https://github.com/mohamedmoatazsec/mintmap/issues?q=is%3Aissue+is%3Aopen+label%3Acatalog), or report a
path MintMap missed in your own project. [CONTRIBUTING.md](../CONTRIBUTING.md) explains how.

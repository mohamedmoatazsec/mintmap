# Making the MintMap check hard to bypass

`mintmap diff` compares the code in a pull request with `mintmap.lock`. The lock lives in the same repository, so
a pull request could also edit the lock (accepting its own change) or the workflow that runs MintMap. The check is
only as strong as the review rules around those files, and as the job that runs it. This page lists the GitHub
settings that narrow those gaps, strongest first. They come from GitHub's documentation (github/docs at commit
`dae83f7d`, October 2026) and **have not been tested on a live repository**; plan availability changes, so check
your plan.

## 1. Code owners for the lock, the workflow and CODEOWNERS itself (all paid plans; public repos on Free)

Add the lines from [`examples/CODEOWNERS`](../examples/CODEOWNERS) at the **end** of `.github/CODEOWNERS`.

- The last matching pattern wins, so these lines must come after broad patterns such as `*`.
- Own the whole `.github/workflows/` and `.github/actions/` directories, not just one file: a pull request can add
  a new workflow whose job has the same name as the required check.
- Own CODEOWNERS in all three locations GitHub reads (`.github/`, root, `docs/`).
- The owning team must be visible and have explicit write access. Give it at least two members: authors cannot
  approve their own pull requests, so a one-person team cannot approve that person's changes (an inference from
  GitHub's rules, not tested).
- CODEOWNERS fails open: invalid lines are skipped silently, unknown owners or owners without write access get no
  review request, and a pattern with no owner removes ownership. Check
  `GET /repos/{owner}/{repo}/codeowners/errors` after every edit.

CODEOWNERS alone only *requests* reviews. Step 2 turns it into a merge requirement.

## 2. Branch ruleset on the default branch

Settings → Rules → Rulesets → New branch ruleset, targeting the default branch (and release branches):

- **Require a pull request before merging**, with at least 1 approval, **Require review from Code Owners**,
  **Dismiss stale pull request approvals when new commits are pushed**, and **Require approval of the most recent
  reviewable push**. Without the last two, a pull request approved for harmless code can merge a lock edit pushed
  afterwards.
- **Require status checks to pass**: add the MintMap job, enable "Require branches to be up to date", and pin the
  expected source to the GitHub Actions app.
- **Bypass list**: empty, or bypass "for pull requests only". Never "exempt" (no audit entry is created).
  With classic branch protection, enable "Do not allow bypassing the above settings"; admins are otherwise exempt.
- Settings → Actions → General: turn **off** "Allow GitHub Actions to create and approve pull requests".

Optional on rulesets: the **Required reviewers** sub-rule (public preview; organization-owned repositories only,
because it maps paths to teams) can map `mintmap.lock` and `.github/workflows/**` to the security team inside the
ruleset itself, so it does not depend on CODEOWNERS parsing.

## 3. Strongest: run MintMap from a workflow the pull request cannot change (GitHub Enterprise Cloud)

With an in-repository `pull_request` workflow, the pull request's own copy of the workflow judges the pull request.
On Enterprise Cloud, an organization ruleset **Require workflows to pass before merging** can run a MintMap workflow
that lives in a separate policy repository, pinned to a commit SHA. Keep the MintMap version (and, if you customise
it, the catalog) in that pinned repository.

## 4. Keep the job that runs MintMap clean (all plans)

A pull request does not need to touch the workflow to tamper with the check if code from it runs in the job.

- The MintMap action runs MintMap from the action's own checkout with `python -I`, so the working directory (the
  pull request's checkout) is not on `sys.path`: a pull request that adds a top-level `mintmap/`, `pip/` or
  `json.py` cannot replace MintMap or the modules it imports. No package is built or installed (only the Python
  interpreter, by `actions/setup-python`), and the catalog is read from the action, not from the pull request. If
  you run MintMap yourself, do the same (`python -I`, MintMap installed or checked out outside the pull request's
  tree).
- MintMap's output quotes text from the pull request (route strings, file names). `scan` and `diff` print each
  item on one line with control characters escaped, and the action also pauses workflow commands
  (`::stop-commands::` with a random token) while MintMap runs, so that text cannot write `::error::` or
  `::add-mask::` lines into the log.
- Do not run code from the pull request in the MintMap job before MintMap runs: no `pip install -r
  requirements.txt` or `pip install -e .`, no tests, no setup scripts from the repository. Installing packages can
  run code the pull request controls, and that code can modify the Python installation or the action's files. Run
  MintMap in its own job.
- Pin `uses:` lines (MintMap and the actions it uses) to full commit SHAs.
- Use the `pull_request` event. Do not use `pull_request_target` with a checkout of the pull request's code: that
  event runs with the base repository's secrets and write token.

## What this does not cover

- Organization owners, repository admins and bypass actors can always change or disable these rules.
- Push rulesets that block edits to `mintmap.lock` entirely exist only for private and internal repositories.
- MintMap reports what it could not analyse (gaps), but it does not prove an application is secure. See
  [EVALUATION.md](EVALUATION.md) for measured misses and false alarms.

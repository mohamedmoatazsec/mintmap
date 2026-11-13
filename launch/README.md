# Launch kit

Drafts for announcing MintMap. **This branch is not meant to be merged.** Every number in these drafts is from
[docs/EVALUATION.md](../docs/EVALUATION.md). If you edit a draft, keep it that way: no "every path" or "catches
everything" in a title or anywhere else, no user counts, no comparisons nobody measured, say that the inventories
and the verifier were AI agents, label development-set numbers as such, and keep the word "experimental".

| File | For |
|---|---|
| [show-hn.md](show-hn.md) | Hacker News (Show HN) |
| [reddit-django.md](reddit-django.md) | r/django |
| [reddit-netsec.md](reddit-netsec.md) | r/netsec |
| [django-forum.md](django-forum.md) | The Django Forum |
| [social-thread.md](social-thread.md) | X and LinkedIn |
| [blog-post.md](blog-post.md) | Blog post, "We measured how often our auth-path scanner misses things" (about 900 words) |

## Before you post anything

0. **Publish 0.6.0a2 to PyPI, and confirm that `pip install mintmap` works, before posting anything.** Merge the
   launch-readiness pull request, then follow CONTRIBUTING.md, "Releasing" (first the pending trusted publisher
   on PyPI and the protected `pypi` environment on GitHub), tag `v0.6.0a2` and publish the GitHub release. In a
   fresh virtualenv, check that `pip install mintmap` installs 0.6.0a2 and that `mintmap --version` prints
   `mintmap 0.6.0a2`. Until a release exists, anyone can register the name `mintmap` on PyPI, and readers (and
   AI assistants) who type `pip install mintmap` would install their package. The drafts below tell people to run
   `pip install mintmap`.
1. Check that the launch-readiness pull request is merged, so the README, the demo and the issue links exist on
   `main`. Then pin the Action snippet to the release: in a docs commit, replace `@v0.6.0a2` in README.md and
   examples/mintmap.yml with the tag's full commit SHA (CONTRIBUTING.md, "Releasing", step 5).
2. Check that private vulnerability reporting is on: `gh api repos/mohamedmoatazsec/mintmap/private-vulnerability-reporting`
   prints `{"enabled":true}`. SECURITY.md, the issue chooser and CODE_OF_CONDUCT.md link to it.
3. Repository settings, because link cards on HN, Reddit and X show them: set the About description to the
   README tagline ("A reviewed map of the code paths that create a login session or credential in a Django app,
   enforced in CI."), upload `docs/assets/social-preview.png` under Settings, General, Social preview, and add
   topics (django, security, authentication, static-analysis, appsec, ci, github-actions, python).
4. Publish the blog post somewhere with a stable URL. Several places below take a write-up but not a bare
   repository link.
5. Be online for a few hours after each post. People will ask about the miss rate; answer with the numbers.
6. Spread the posts over a week or two. The same link in five places on one day reads as spam.

## Where to submit, and the rules

Rules were read on 2026-11-13. Read them again before posting: they change.

### Hacker News: Show HN

- Rules: https://news.ycombinator.com/showhn.html
- The title must begin with `Show HN:`. It has to be something people can try, which you built yourself, and you
  should be around to discuss it. No sign-up should be needed (none is).
- Blog posts are not Show HN material: link the repository in the Show HN, and submit the blog post separately as
  a normal link on another day if you want.
- Do not ask anyone to upvote or comment.

### r/netsec

- Rules: the subreddit's wiki page "guidelines".
- **Do not link the GitHub repository.** The moderators no longer accept direct links to tool code or READMEs;
  those go in the pinned "monthly discussion & tool thread". Posts are judged on technical merit, and titles must
  give context.
- So: post the **blog post** (a technical write-up of the evaluation) as a link, or put the repository in the
  monthly tool thread. `reddit-netsec.md` has both.
- If you are unsure whether it counts as self-promotion, the guidelines say to ask the moderators by modmail
  first.

### r/django

- I did not find a reliable copy of the current rules. Read the sidebar and the pinned posts before posting, in
  particular anything about self-promotion and post flair.
- A text post that explains the tool and its limits is the safer form.

### Django Forum

- https://forum.djangoproject.com. Use the category for sharing projects (it was called "Show & Tell" when I
  last knew it; check the category list).
- It is a discussion forum: ask a real question. The draft asks which auth libraries people want in the catalog.

### awesome-django

- https://github.com/wsvincent/awesome-django, rules in `contributing.md`.
- **MintMap does not qualify yet.** The list asks for at least six months of active maintenance, says projects
  with fewer than 100 GitHub stars are usually too early, and wants a stable release history and clear
  documentation.
- When it does: one pull request per suggestion, fill in the pull-request template completely (pull requests
  that skip it are closed automatically), add the entry at the end of its section unless the section is
  alphabetical.

### Python awesome lists

- `vinta/awesome-python` (rules in `CONTRIBUTING.md`): **does not qualify yet.** It requires a stable project,
  "not alpha, beta, or experimental", and a repository at least one month old. One project per pull request, and
  it rejects coordinated self-promotion.
- Python security lists (for example `guardrailsio/awesome-python-security`): I did not verify their rules. Read
  the contributing file of each list first, and expect a similar bar.

### Newsletters

- **PyCoder's Weekly**: https://pycoders.com/submit. They take links to projects and articles and do not promise
  to feature them. Submit the blog post, or the repository once it is on PyPI.
- **Django News**: I found no submission form on https://django-news.com. Look in the footer of a current issue
  for how they take suggestions. The curators (Jeff Triplett and Will Vincent) also maintain awesome-django.

### Conference talks

- **DjangoCon US 2027**: the ticket page lists talks on September 13 to 15, 2027. The organisers' plan says the
  call for proposals opens no later than mid-January 2027. The 2026 call ran on pretalx; watch
  https://2027.djangocon.us.
- **DjangoCon Europe 2027**: the DSF asked for hosts in April 2026, with possible dates between January 4 and
  April 26 or June 3 and June 27, 2027. I found no announced city or call for proposals. Watch the Django blog.
- A talk idea that fits the evaluation: "What a held-out evaluation taught us about our own static analysis",
  with the dev-set and unseen-project numbers side by side.

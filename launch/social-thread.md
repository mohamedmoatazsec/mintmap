# X / LinkedIn thread

Attach `docs/assets/demo.svg` (as a PNG) to the first post, or `docs/assets/social-preview.png`.

```
1/
In a Django app, how many ways are there to get logged in?

Login view, reset auto-login, API tokens, 2FA steps, SSO, admin... Most teams have no list, and any pull request can add one or weaken one.

I built MintMap to keep that list and check it in CI. It is experimental.

2/
How it works:
- mintmap scan finds every code path that creates a session or credential
- a person reviews it once and commits mintmap.lock
- mintmap diff fails the pull request when the set, or the code on it, changes

It parses code with ast and never runs it.

3/
I measured how often it is wrong.

Frozen, then run on 3 Django projects it had never seen:
- 8 of 66 credential paths missed with no warning (12%)
- 25 of 58 reported paths were false alarms (43%)
- 42 of 65 harmful changes caught by the diff (65%)

4/
What did not work: on the projects I developed against, silent misses went from 51 to 4 of 213.
On unseen projects, from 11 to 8 of 66.

Most of the gain did not transfer. Tuning on your dev set flatters you.

5/
Limits of the evaluation itself: the reference inventories were written by AI agents, not people, and contain
errors. Three projects is a small sample. An earlier set of unseen projects gave a 30% silent miss rate for the
previous version.

6/
Try it: clone the repo, run bash scripts/demo.sh, and watch a bad pull request (a TOTP check whose result is
ignored) fail the diff.

https://github.com/mohamedmoatazsec/mintmap

If it misses a login path in your project, I want the snippet.
```

For LinkedIn, join posts 1 to 6 into one text and drop the numbering.

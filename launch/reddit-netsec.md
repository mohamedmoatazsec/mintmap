# r/netsec

r/netsec does not accept direct links to tool repositories or READMEs. Use one of these two.

## Option A: link post to the blog post

Publish `blog-post.md` first, then submit its URL as a link post.

**Title** (must give context):

```
Measuring a Django auth-path static analyzer on unseen codebases: 12% of credential paths missed silently, 43% false alarms
```

## Option B: a comment in the pinned "monthly discussion & tool thread"

```
MintMap (open source, Apache-2.0, experimental): static analysis for Django that inventories every code path
that creates a session or credential, stores a reviewed baseline, and fails CI when the set or the code on it
changes. Parses with ast, never imports the project.

I measured it frozen on three codebases it had not seen: 8 of 66 credential paths missed with no warning, 25 of
58 reported paths false alarms, 42 of 65 harmful mutations caught by the CI diff. The inventories used as ground
truth were written by AI agents, not people. Methodology and failure analysis are in docs/EVALUATION.md.

https://github.com/mohamedmoatazsec/mintmap
```

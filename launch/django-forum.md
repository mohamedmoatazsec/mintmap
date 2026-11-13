# Django Forum

Post in the category for sharing projects.

**Title:**

```
MintMap: a reviewed list of a Django app's login and credential paths, checked in CI (experimental) – which auth libraries should it know?
```

**Body:**

```
Hello,

I have been working on a static-analysis tool for Django called MintMap and would like feedback from people who
maintain real projects.

What it does: it reads a project's code (with `ast`, nothing is imported or run), finds the places that create a
login session or credential, and traces each one it can back to a URL route, middleware or admin registration. The
result goes into a `mintmap.lock` file that someone reviews once. After that, `mintmap diff` fails CI when a pull
request adds or removes such a path, or changes the code or the checks on a reviewed one.

What it does not do: it is not a vulnerability scanner, and it is not complete. I froze it and ran it on three
projects it had never seen (CVAT, Label Studio, Tandoor). It missed 8 of 66 credential paths with no warning,
25 of 58 reported paths were false alarms, and the CI diff caught 42 of 65 harmful test changes. The reference
inventories were written by AI agents rather than people, and the adversarial verifier that re-checked the
scoring was an AI agent too, so the numbers have their own error. Everything is in docs/EVALUATION.md.

What it knows about libraries comes from a catalog in which every entry cites the library source it was read
from. Today that covers Django auth, DRF, SimpleJWT, knox, djoser, dj-rest-auth, django-allauth, social-auth,
django-otp, two-factor-auth, sesame, oauth-toolkit, django-hijack and mozilla-django-oidc (about 15 packages).

My questions:

1. Which authentication libraries do you rely on that are missing from that list?
2. Where do credentials get created in your project that a tool like this would never guess? In the evaluation
   the hard cases were tokens created in the Django admin, hooks named in settings, and serializers that create a
   token in `super().create()`.

Repository, with a demo you can run without installing anything (Python 3.11 or newer):
https://github.com/mohamedmoatazsec/mintmap

Thank you for reading.
```

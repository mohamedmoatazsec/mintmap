"""Named test.py but defines no TestCase: production code (kept)."""
from django.core import signing


def coupon(user):
    # (v6) a signed principal id: generic signing primitives are mints only for credential-like values
    return signing.dumps({"u": user.pk})

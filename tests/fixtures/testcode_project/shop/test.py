"""Named test.py but defines no TestCase: production code (kept)."""
from django.core import signing


def coupon(order_id):
    return signing.dumps({"order": order_id})

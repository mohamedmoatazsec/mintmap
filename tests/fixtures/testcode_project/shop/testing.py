from django.core import signing
from django.test import TestCase


class ShopTestCase(TestCase):
    def make_link(self):
        return signing.dumps({"u": self.user.pk})

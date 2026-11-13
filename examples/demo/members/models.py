from django.conf import settings
from django.db import models


class Authenticator(models.Model):
    """The TOTP seed of a member who switched on two-step sign-in."""

    member = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="authenticator")
    seed = models.CharField(max_length=64)
    confirmed = models.BooleanField(default=False)

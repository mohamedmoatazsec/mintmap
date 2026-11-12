from django.contrib.auth import login as _dj_login
from django_otp import match_token


def sign_in(request, user):
    """Project wrapper around django.contrib.auth.login."""
    _dj_login(request, user)


def verify_otp(user, token):
    device = match_token(user, token)
    return device is not None

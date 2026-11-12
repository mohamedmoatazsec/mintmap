from django.contrib.auth import login
from django.core import signing


def fixture_login(client_request, user):
    login(client_request, user)
    return signing.dumps({"u": user.pk})

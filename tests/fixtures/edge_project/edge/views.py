from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django_otp import match_token, verify_token

from .tokens import invitation_tokens


def wrong_user(request, target):
    # verifies the OTP of the *current* user, then logs in someone else
    if match_token(request.user, request.POST["otp"]) is None:
        return HttpResponse(status=401)
    login(request, target)
    return HttpResponse("ok")


def disjunction(request, user):
    if match_token(user, request.POST["otp"]) or settings.DEBUG:
        login(request, user)
    return HttpResponse("ok")


def assert_only(request, user):
    ok = match_token(user, request.POST["otp"])
    assert ok
    login(request, user)
    return HttpResponse("ok")


def tuple_truthy(request, user, device):
    if device.verify_is_allowed():
        login(request, user)
    return HttpResponse("ok")


def check_after_mint(request, user):
    login(request, user)
    if match_token(user, request.POST["otp"]) is None:
        return HttpResponse(status=401)
    return HttpResponse("ok")


def swallowed(request, user):
    from dj_rest_auth.mfa.utils import verify_ephemeral_token
    try:
        verify_ephemeral_token(request.POST["t"])
    except Exception:
        pass
    login(request, user)
    return HttpResponse("ok")


def backend_login(request):
    user = authenticate(request, email=request.POST["e"], password=request.POST["p"])
    if user is not None:
        login(request, user)
    return HttpResponse("ok")


def walrus_login(request):
    if (user := authenticate(request, email="e", password="p")) is not None:
        login(request, user)
    return HttpResponse("ok")


def invite(request, user):
    token = invitation_tokens.make_token(user)
    return HttpResponse(token)


def stale_result(request, user):
    ok = verify_token(user, request.POST["d"], request.POST["otp"])
    ok = True
    if ok:
        login(request, user)
    return HttpResponse("ok")

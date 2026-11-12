"""Synthetic second-factor / token views for MintMap tests."""
import jwt
import pyotp
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core import signing
from django.http import HttpResponse
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import NicknameForm, OneTimeCodeForm, PinForm, RecoveryCodeForm
from .helpers import check_and_login, confirm_link, deep_mid, deep_outer, load_book, stamp_audit
from .keys import KeyChecker, ledger_accepts
from .serializers import PinSerializer


def pending_user(request):
    return User.objects.get(pk=request.session["pending"])


def totp_step(request):
    user = pending_user(request)
    form = None
    if request.method == "POST":
        form = OneTimeCodeForm(pyotp.TOTP(user.profile.seed), request.POST)
        if form.is_valid():
            login(request, user)
            return HttpResponse("ok")
    return HttpResponse("form")


def recovery_step(request):
    user = pending_user(request)
    form = RecoveryCodeForm(load_book(user), request.POST)
    if form.is_valid():
        login(request, user)
    return HttpResponse("done")


def pin_step(request):
    user = pending_user(request)
    if request.POST.get("kind") == "short":
        form = PinForm(user.profile.pin, request.POST)
    else:
        form = NicknameForm(request.POST)
    if form.is_valid():
        login(request, user)
    return HttpResponse("done")


def key_step(request):
    user = pending_user(request)
    checker = KeyChecker("example.org")
    if request.method == "GET":
        options, request.session["state"] = checker.start(user.keys())
        return HttpResponse(str(options))
    if not checker.assertion_ok(request.session["state"], user.keys(), request.POST["response"]):
        return HttpResponse(status=400)
    login(request, user)
    return HttpResponse("ok")


def ledger_step(request, ledger):
    user = pending_user(request)
    if not ledger_accepts(ledger, request.POST["token"]):
        return HttpResponse(status=403)
    login(request, user)
    return HttpResponse("ok")


def link_step(request, token):
    user = pending_user(request)
    if not confirm_link(user, token):
        return HttpResponse(status=403)
    login(request, user)
    return HttpResponse("ok")


def remote_token_step(request):
    claims = jwt.decode(request.headers["X-Token"], "k", algorithms=["HS256"])
    user = User.objects.get(username=claims["sub"])
    login(request, user)
    return HttpResponse("ok")


def unsafe_token_step(request):
    claims = jwt.decode(request.headers["X-Token"], options={"verify_signature": False})
    user = User.objects.get(username=claims["sub"])
    login(request, user)
    return HttpResponse("ok")


def signed_link_step(request, blob):
    data = signing.loads(blob, max_age=600)
    user = User.objects.get(pk=data["uid"])
    login(request, user)
    return HttpResponse("ok")


def audited_step(request):
    user = pending_user(request)
    stamp_audit(user)
    login(request, user)
    return HttpResponse("ok")


def deep_step(request, blob):
    user = pending_user(request)
    if not deep_outer(blob):
        return HttpResponse(status=403)
    login(request, user)
    return HttpResponse("ok")


def mid_step(request, blob):
    user = pending_user(request)
    if not deep_mid(blob):
        return HttpResponse(status=403)
    login(request, user)
    return HttpResponse("ok")


def wrapped_step(request):
    check_and_login(request, pending_user(request))
    return HttpResponse("ok")


class PinTokenView(APIView):
    def post(self, request):
        serializer = PinSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token, _ = Token.objects.get_or_create(user=request.user)
        return Response({"t": token.key})

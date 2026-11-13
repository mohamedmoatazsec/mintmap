"""Every way to get signed in to Teahouse.

1. sign_in         password; members with two-step sign-in continue at sign_in_code
2. sign_in_code    TOTP code, then the session
3. finish_reset    password-reset link: sets the new password and signs the member in
4. ApiTokenView    password in, API token out
"""
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import CodeForm, NewPasswordForm, SignInForm
from .models import Authenticator

PENDING_KEY = "teahouse_pending_member"


def sign_in(request):
    form = SignInForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        member = authenticate(request, username=form.cleaned_data["username"],
                              password=form.cleaned_data["password"])
        if member is None:
            form.add_error(None, "Wrong username or password.")
        elif Authenticator.objects.filter(member=member, confirmed=True).exists():
            request.session[PENDING_KEY] = member.pk
            return redirect("sign-in-code")
        else:
            login(request, member)
            return redirect("/")
    return render(request, "members/sign_in.html", {"form": form})


def sign_in_code(request):
    member_id = request.session.get(PENDING_KEY)
    if member_id is None:
        return redirect("sign-in")
    member = get_user_model().objects.get(pk=member_id)
    form = CodeForm(member.authenticator.seed, request.POST or None)
    if request.method == "POST":
        if not form.is_valid():
            return render(request, "members/sign_in_code.html", {"form": form}, status=400)
        del request.session[PENDING_KEY]
        login(request, member, backend="django.contrib.auth.backends.ModelBackend")
        return redirect("/")
    return render(request, "members/sign_in_code.html", {"form": form})


def finish_reset(request, uidb64, token):
    try:
        member = get_user_model().objects.get(pk=force_str(urlsafe_base64_decode(uidb64)))
    except (ValueError, get_user_model().DoesNotExist):
        return HttpResponseForbidden()
    if not default_token_generator.check_token(member, token):
        return HttpResponseForbidden()
    form = NewPasswordForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        member.set_password(form.cleaned_data["password"])
        member.save()
        login(request, member, backend="django.contrib.auth.backends.ModelBackend")
        return redirect("/")
    return render(request, "members/new_password.html", {"form": form})


class ApiTokenView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        member = authenticate(request, username=request.data.get("username"),
                              password=request.data.get("password"))
        if member is None:
            return Response({"detail": "Wrong username or password."}, status=status.HTTP_400_BAD_REQUEST)
        token, _created = Token.objects.get_or_create(user=member)
        return Response({"token": token.key})

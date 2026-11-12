from django.contrib import auth
from django.contrib.auth import aauthenticate, alogin, authenticate
from django.contrib.auth import login as django_login
from django.http import HttpResponse
from django.views.generic import FormView
from django_otp import match_token

from .forms import EmailLoginForm
from .helpers import sign_in, verify_otp


def password_login(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    django_login(request, user)
    return HttpResponse("ok")


def otp_login_ignored(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    match_token(user, request.POST["otp"])
    django_login(request, user)
    return HttpResponse("ok")


def otp_login_wrapper(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    if not verify_otp(user, request.POST["otp"]):
        return HttpResponse(status=401)
    sign_in(request, user)
    return HttpResponse("ok")


class EmailLoginView(FormView):
    form_class = EmailLoginForm
    template_name = "login.html"

    def form_valid(self, form):
        auth.login(self.request, form.get_user())
        return super().form_valid(form)


async def async_login(request):
    user = await aauthenticate(request, username="u", password="p")
    if user is not None:
        await alogin(request, user)
    return HttpResponse("ok")

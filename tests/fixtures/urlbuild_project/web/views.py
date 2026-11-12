from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from django.http import HttpResponse


def _signin(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    login(request, user)
    return HttpResponse("ok")


def password_signin(request):
    return _signin(request)


def token_signin(request):
    return _signin(request)


def sso_signin(request):
    return _signin(request)


def late_signin(request):
    return _signin(request)


def magic_signin(request, key):
    return _signin(request)


def localized_only_signin(request):
    return _signin(request)


def custom_account_login(request):
    return _signin(request)


def legacy_signin_a(request):
    return _signin(request)


def legacy_signin_b(request):
    return _signin(request)


def beta_signin(request):
    return _signin(request)


def choice_a(request):
    return _signin(request)


def choice_b(request):
    return _signin(request)


def named_signin(request):
    return _signin(request)


def portal_signin(request):
    return _signin(request)


def second_portal_signin(request):
    return _signin(request)


def user_signin(request, pk):
    return _signin(request)


def user_signin_dup(request, uid):
    return _signin(request)


def slash_a(request):
    return _signin(request)


def slash_b(request):
    return _signin(request)


def regex_a(request):
    return _signin(request)


def regex_b(request):
    return _signin(request)


def stream_signin(request):
    return _signin(request)


def redirect_view(request):
    return HttpResponse("moved")


def page_with_library_login(request):
    # runs the stock Django login view from project code
    view = LoginView.as_view(template_name="web/login.html")
    return view(request)

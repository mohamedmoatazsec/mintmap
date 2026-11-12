from django.contrib.auth import authenticate, login
from django.http import HttpResponse


def billing_signin(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    if user is None:
        return HttpResponse(status=401)
    login(request, user)
    return HttpResponse("ok")


def welcome(request):
    return HttpResponse("welcome")

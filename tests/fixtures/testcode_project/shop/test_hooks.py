from django.contrib.auth import login
from django.contrib.auth.models import User


def admit(request):
    login(request, User.objects.get(username=request.GET["u"]))

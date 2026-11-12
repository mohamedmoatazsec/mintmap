from django.http import HttpResponse

from .test_hooks import admit


def enter(request):
    admit(request)
    return HttpResponse("ok")
